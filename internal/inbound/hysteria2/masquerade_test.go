package hysteria2

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/clayicarus/proxy-gateway/internal/config"
	"go.uber.org/zap"
)

func TestNewMasqueradeForwardsToBackend(t *testing.T) {
	var seen *http.Request
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		seen = request.Clone(request.Context())
		writer.Header().Set("Server", "test-site")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("my website"))
	}))
	defer backend.Close()

	masq, err := newMasquerade(proxyConfig(backend.URL+"/site", false), "hy2", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer masq.Close()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "https://probe.example.com/page?q=1", nil)
	request.Host = "probe.example.com"
	masq.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK || recorder.Body.String() != "my website" {
		t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Server"); got != "test-site" {
		t.Fatalf("Server header = %q, want the backend value", got)
	}
	if seen == nil {
		t.Fatal("backend received no request")
	}
	if seen.URL.Path != "/site/page" || seen.URL.RawQuery != "q=1" {
		t.Fatalf("backend path = %q?%q", seen.URL.Path, seen.URL.RawQuery)
	}
	// Without rewriteHost the backend must observe the Host the probe used.
	if seen.Host != "probe.example.com" {
		t.Fatalf("backend Host = %q, want the probe Host", seen.Host)
	}
	// A plain web server would not advertise a proxy in front of it, and the
	// prober's address must not be handed to the backend.
	for _, header := range []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded"} {
		if value := seen.Header.Get(header); value != "" {
			t.Fatalf("backend saw %s = %q", header, value)
		}
	}
}

func TestNewMasqueradeRewritesHost(t *testing.T) {
	var seenHost string
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		seenHost = request.Host
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()

	masq, err := newMasquerade(proxyConfig(backend.URL, true), "hy2", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer masq.Close()

	request := httptest.NewRequest(http.MethodGet, "https://probe.example.com/", nil)
	request.Host = "probe.example.com"
	masq.Handler().ServeHTTP(httptest.NewRecorder(), request)

	backendHost, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	if seenHost != backendHost.Host {
		t.Fatalf("backend Host = %q, want %q", seenHost, backendHost.Host)
	}
}

func TestNewMasqueradeReturnsBadGatewayWithoutLeakingDetail(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	address := backend.URL
	backend.Close()

	masq, err := newMasquerade(proxyConfig(address, false), "hy2", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer masq.Close()

	recorder := httptest.NewRecorder()
	masq.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "https://probe.example.com/", nil))
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", recorder.Code)
	}
	body, err := io.ReadAll(recorder.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != 0 {
		t.Fatalf("error body = %q, want no proxy detail", body)
	}
	for key := range recorder.Header() {
		if strings.Contains(strings.ToLower(key), "hysteria") || strings.Contains(strings.ToLower(key), "gateway") {
			t.Fatalf("error response leaked header %q", key)
		}
	}
}

func TestNewMasqueradeNilConfigKeepsUpstreamDefault(t *testing.T) {
	masq, err := newMasquerade(nil, "hy2", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if masq != nil || masq.Handler() != nil {
		t.Fatalf("masquerade = %#v, want no handler", masq)
	}
	masq.Close()
}

func TestNewMasqueradeRejectsUnimplementedType(t *testing.T) {
	_, err := newMasquerade(&config.InboundMasqueradeConfig{Type: "file"}, "hy2", zap.NewNop())
	if err == nil {
		t.Fatal("unimplemented masquerade type was accepted")
	}
}

func proxyConfig(target string, rewriteHost bool) *config.InboundMasqueradeConfig {
	return &config.InboundMasqueradeConfig{
		Type:  config.MasqueradeProxyType,
		Proxy: &config.MasqueradeProxyConfig{URL: target, RewriteHost: rewriteHost},
	}
}
