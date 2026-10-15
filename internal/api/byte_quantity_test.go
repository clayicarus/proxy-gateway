package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/clayicarus/proxy-gateway/internal/config"
	"github.com/clayicarus/proxy-gateway/internal/storage"
	"github.com/clayicarus/proxy-gateway/internal/traffic"
	"go.uber.org/zap"
	"golang.org/x/net/html"
)

func TestParseByteQuantity(t *testing.T) {
	for _, tt := range []struct {
		value, unit string
		want        uint64
		invalid     bool
	}{
		{"123", "", 123, false},
		{"", "", 0, false},
		{"0", "MB", 0, false},
		{"0", "GB", 0, false},
		{"0", "KB", 0, false},
		{"0", "B", 0, false},
		{"123", "B", 123, false},
		{"1.5", "KB", 1536, false},
		{"1.5", "MB", 1572864, false},
		{"1.5", "GB", 1610612736, false},
		{" .5 ", "MB", 524288, false},
		{"1.", "KB", 1024, false},
		{"0.1", "MB", 104858, false},
		{"0.0000001", "MB", 1, false},
		{"0.1", "B", 1, false},
		{"9223372036854775807", "B", 9223372036854775807, false},
		{"8796093022207.99999904632568359375", "MB", 9223372036854775807, false},
		{"9223372036854775807.1", "B", 0, true},
		{"8796093022208", "MB", 0, true},
		{"18446744073709551616", "GB", 0, true},
		{"-1", "MB", 0, true},
		{"NaN", "MB", 0, true},
		{"Inf", "MB", 0, true},
		{"1e9", "MB", 0, true},
		{"1/2", "MB", 0, true},
		{"0x10", "MB", 0, true},
		{"1,5", "MB", 0, true},
		{"1", "TB", 0, true},
		{"0", "invalid", 0, true},
		{"", "invalid", 0, true},
		{strings.Repeat("1", 65), "B", 0, true},
	} {
		t.Run(tt.value+"_"+tt.unit, func(t *testing.T) {
			got, err := parseByteQuantity(tt.value, tt.unit)
			if (err != nil) != tt.invalid || got != tt.want {
				t.Fatalf("got %d, %v; want %d, invalid=%v", got, err, tt.want, tt.invalid)
			}
		})
	}
}

func TestMegabytesPreservesEveryByte(t *testing.T) {
	for _, value := range []uint64{0, 1, 64, 1023, 1024, 1048575, 1048576, 1048577, 9007199254740993, 9223372036854775807} {
		formatted := formatMegabytes(value)
		got, err := parseByteQuantity(formatted, "MB")
		if err != nil || got != value {
			t.Fatalf("%d rendered as %q, parsed as %d, %v", value, formatted, got, err)
		}
	}
}

func TestManagerQuantityForms(t *testing.T) {
	store, err := storage.NewSQLiteStore(t.TempDir()+"/admin.db", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	manager, err := NewManager(&config.Config{Timezone: "UTC"}, store, traffic.NewTrafficLogger(nil, store, zap.NewNop()), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	post := func(path string, form url.Values, wantStatus int) {
		t.Helper()
		form.Set("csrf", manager.csrf)
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()
		manager.Handler().ServeHTTP(response, req)
		if response.Code != wantStatus {
			t.Fatalf("POST %s: %d: %s", path, response.Code, response.Body.String())
		}
	}
	check := func(monthly, speed uint64) {
		t.Helper()
		user, err := store.GetUser("alice")
		if err != nil || user == nil {
			t.Fatalf("get user: %v, %v", user, err)
		}
		if user.MonthlyBytes != monthly || user.DownloadSpeed != speed {
			t.Fatalf("stored quota/speed %d/%d, want %d/%d", user.MonthlyBytes, user.DownloadSpeed, monthly, speed)
		}
	}
	// Submit the actual rendered create form, including its default MB units.
	forms := quantityForms(t, manager)
	create := forms["/users"]
	create.Set("username", "alice")
	create.Set("routes", "direct")
	create.Set("monthly_bytes", "1.5")
	create.Set("download_speed", "0.5")
	post("/users", create, http.StatusOK)
	check(1572864, 524288)

	// Editing independently selected units must reach storage in bytes.
	edit := quantityForms(t, manager)["/users/alice/save"]
	edit.Set("routes", "direct")
	edit.Set("monthly_bytes", "2")
	edit.Set("monthly_bytes_unit", "GB")
	edit.Set("download_speed", "1.5")
	edit.Set("download_speed_unit", "KB")
	post("/users/alice/save", edit, http.StatusSeeOther)
	check(2147483648, 1536)

	// Old forms remain byte-based, including values beyond float64 precision.
	edit.Del("monthly_bytes_unit")
	edit.Del("download_speed_unit")
	edit.Set("monthly_bytes", "9007199254740993")
	edit.Set("download_speed", "1")
	post("/users/alice/save", edit, http.StatusSeeOther)
	check(9007199254740993, 1)

	// Resubmitting the displayed MB form preserves these exact values.
	edit = quantityForms(t, manager)["/users/alice/save"]
	edit.Set("routes", "direct")
	post("/users/alice/save", edit, http.StatusSeeOther)
	check(9007199254740993, 1)

	for _, field := range []string{"monthly_bytes", "download_speed"} {
		for _, invalid := range []string{"-1", "NaN", "8796093022208"} {
			form := quantityForms(t, manager)["/users/alice/save"]
			form.Set("routes", "direct")
			form.Set(field, invalid)
			post("/users/alice/save", form, http.StatusSeeOther)
			check(9007199254740993, 1)
		}
	}
	edit.Set("monthly_bytes", "0")
	edit.Set("download_speed", "0")
	post("/users/alice/save", edit, http.StatusSeeOther)
	check(0, 0)
}

// Read real HTML controls to verify defaults and the render/submit contract.
func quantityForms(t *testing.T, manager *Manager) map[string]url.Values {
	t.Helper()
	response := httptest.NewRecorder()
	manager.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("render dashboard: %d: %s", response.Code, response.Body.String())
	}
	root, err := html.Parse(strings.NewReader(response.Body.String()))
	if err != nil {
		t.Fatal(err)
	}
	attr := func(node *html.Node, name string) string {
		for _, a := range node.Attr {
			if a.Key == name {
				return a.Val
			}
		}
		return ""
	}
	forms := map[string]url.Values{}
	var visit func(*html.Node, url.Values)
	visit = func(node *html.Node, form url.Values) {
		if node.Type == html.ElementNode && node.Data == "form" {
			form = url.Values{}
			forms[attr(node, "action")] = form
		}
		if form != nil && node.Type == html.ElementNode {
			switch node.Data {
			case "input":
				if attr(node, "type") != "checkbox" {
					form.Set(attr(node, "name"), attr(node, "value"))
				}
			case "select":
				name := attr(node, "name")
				if strings.HasSuffix(name, "_unit") {
					var units []string
					for option := node.FirstChild; option != nil; option = option.NextSibling {
						if option.Data != "option" {
							continue
						}
						units = append(units, attr(option, "value"))
						for _, a := range option.Attr {
							if a.Key == "selected" {
								form.Set(name, attr(option, "value"))
							}
						}
					}
					if fmt.Sprint(units) != "[GB MB KB B]" || form.Get(name) != "MB" {
						t.Fatalf("%s options=%v default=%q", name, units, form.Get(name))
					}
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			visit(child, form)
		}
	}
	visit(root, nil)
	return forms
}
