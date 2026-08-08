package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hy2-gateway/internal/config"
	"github.com/hy2-gateway/internal/connection"
	"github.com/hy2-gateway/internal/storage"
	"github.com/hy2-gateway/internal/traffic"
	"go.uber.org/zap"
)

func TestManagerRejectsWriteWithoutCSRF(t *testing.T) {
	store, err := storage.NewSQLiteStore(t.TempDir()+"/admin.db", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	cfg := &config.Config{Timezone: "UTC"}
	manager, err := NewManager(cfg, store, traffic.NewTrafficLogger(nil, store, zap.NewNop()), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9090/users", strings.NewReader("username=alice&routes=direct"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	manager.Handler().ServeHTTP(response, req)
	if response.Code != http.StatusForbidden {
		t.Fatalf("expected request without CSRF token to fail, got %d", response.Code)
	}
}

func TestManagerRejectsGETForUserActions(t *testing.T) {
	store, err := storage.NewSQLiteStore(t.TempDir()+"/admin.db", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.CreateUser(storage.ManagedUserInput{Username: "alice", Password: "password", Routes: []string{"direct"}}, "token"); err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(&config.Config{Timezone: "UTC"}, store, traffic.NewTrafficLogger(nil, store, zap.NewNop()), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	manager.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9090/users/alice/delete", nil))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET user action status = %d, want %d", response.Code, http.StatusMethodNotAllowed)
	}
	user, err := store.GetUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	if user == nil || user.DeletedAt != nil {
		t.Fatal("GET user action changed managed user state")
	}
}

func TestManagerCreatesUserWithCSRFRegardlessOfOrigin(t *testing.T) {
	store, err := storage.NewSQLiteStore(t.TempDir()+"/admin.db", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	cfg := &config.Config{Timezone: "UTC"}
	manager, err := NewManager(cfg, store, traffic.NewTrafficLogger(nil, store, zap.NewNop()), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{
		"csrf":           {manager.csrf},
		"username":       {"alice"},
		"monthly_bytes":  {"1024"},
		"download_speed": {"64"},
		"routes":         {"direct"},
	}
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9090/users", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://ssh-forward.example.invalid")
	response := httptest.NewRecorder()
	manager.Handler().ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected user creation response, got %d: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "重启 Gateway 后可用") {
		t.Fatal("restart requirement missing from credential response")
	}
	user, err := store.GetUser("alice")
	if err != nil || user == nil {
		t.Fatalf("created user not persisted: user=%#v err=%v", user, err)
	}
}

func TestManagerRendersDashboard(t *testing.T) {
	store, err := storage.NewSQLiteStore(t.TempDir()+"/admin.db", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.CreateUser(storage.ManagedUserInput{Username: "alice", Password: "password", Routes: []string{"direct"}}, "token"); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Timezone: "UTC"}
	manager, err := NewManager(cfg, store, traffic.NewTrafficLogger(nil, store, zap.NewNop()), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9090/", nil)
	response := httptest.NewRecorder()
	manager.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("expected dashboard response, got %d: %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("dashboard cache control = %q, want no-store", response.Header().Get("Cache-Control"))
	}
	if !strings.Contains(response.Body.String(), "Hy2 Gateway") {
		t.Fatal("dashboard title missing")
	}
	for _, section := range []string{"基本信息", "用户管理", "活跃连接", "成本分析", "故障分析"} {
		if !strings.Contains(response.Body.String(), section) {
			t.Fatalf("dashboard section %q missing", section)
		}
	}
	if !strings.Contains(response.Body.String(), "/assets/admin.js?v=4") || !strings.Contains(response.Body.String(), "/assets/admin.css?v=4") {
		t.Fatal("dashboard live script missing")
	}
	for _, content := range []string{
		"操作确认",
		"重置 alice 的密码？",
		"停用用户 alice？",
		"已有会话会在下一笔流量时关闭整条 QUIC 连接",
	} {
		if !strings.Contains(response.Body.String(), content) {
			t.Fatalf("sensitive operation warning %q missing", content)
		}
	}
}

func TestManagerRendersEveryUserRow(t *testing.T) {
	store, err := storage.NewSQLiteStore(t.TempDir()+"/admin.db", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	now := time.Now().UTC()
	for i := 0; i < 11; i++ {
		username := fmt.Sprintf("user-%02d", i)
		input := storage.ManagedUserInput{
			Username:      username,
			Password:      "password",
			MonthlyBytes:  uint64(i) * 1024,
			DownloadSpeed: uint64(i) * 64,
			Routes:        []string{"direct"},
		}
		if i == 1 {
			expiresAt := now.Add(24 * time.Hour)
			input.ExpiresAt = &expiresAt
		}
		if i == 2 {
			expiresAt := now.Add(-24 * time.Hour)
			input.ExpiresAt = &expiresAt
		}
		if err := store.CreateUser(input, "token-"+username); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.SetUserDeleted("user-03", true); err != nil {
		t.Fatal(err)
	}

	manager, err := NewManager(&config.Config{Timezone: "UTC"}, store, traffic.NewTrafficLogger(nil, store, zap.NewNop()), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	manager.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9090/", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("dashboard response = %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if got := strings.Count(body, "data-user-row="); got != 11 {
		t.Fatalf("rendered user rows = %d, want 11", got)
	}
	for i := 0; i < 11; i++ {
		marker := fmt.Sprintf(`data-user-row="user-%02d"`, i)
		if !strings.Contains(body, marker) {
			t.Fatalf("user row %q missing", marker)
		}
	}
}

func TestManagerLiveIncludesConnectionDetails(t *testing.T) {
	store, err := storage.NewSQLiteStore(t.TempDir()+"/admin.db", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	tracker := connection.NewTracker()
	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.20"), Port: 4567}
	tracker.Connect(addr, "alice:node1")
	tracker.StartTCP(addr, "example.com:443")
	manager, err := NewManager(&config.Config{Timezone: "UTC"}, store, traffic.NewTrafficLogger(nil, store, zap.NewNop()), zap.NewNop(), tracker)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	manager.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://127.0.0.1/live", nil))
	var status liveStatus
	if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if len(status.Connections) != 1 || status.Connections[0].ClientIP != "192.0.2.20" || len(status.Connections[0].Requests) != 1 {
		t.Fatalf("unexpected live connections: %#v", status.Connections)
	}
}

func TestManagerTrafficRange(t *testing.T) {
	store, err := storage.NewSQLiteStore(t.TempDir()+"/admin.db", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	base := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	if err := store.FlushTraffic([]storage.TrafficRecord{
		{UserID: "alice", NodeID: "node1", TxBytes: 100, RxBytes: 200, Timestamp: base},
		{UserID: "bob", NodeID: "direct", TxBytes: 10, RxBytes: 20, Timestamp: base.Add(time.Hour)},
	}); err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(&config.Config{Timezone: "UTC"}, store, traffic.NewTrafficLogger(nil, store, zap.NewNop()), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/traffic-range?start=2026-08-08T09%3A00&end=2026-08-08T12%3A00", nil)
	manager.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("traffic range status = %d: %s", response.Code, response.Body.String())
	}
	var status trafficRangeStatus
	if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.Total.TxBytes != 110 || status.Total.RxBytes != 220 || status.NodeEgress != 300 || len(status.Hours) != 2 {
		t.Fatalf("unexpected traffic range: %#v", status)
	}
}

func TestManagerServesEmbeddedAssets(t *testing.T) {
	store, err := storage.NewSQLiteStore(t.TempDir()+"/admin.db", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	manager, err := NewManager(&config.Config{Timezone: "UTC"}, store, traffic.NewTrafficLogger(nil, store, zap.NewNop()), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	manager.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9090/assets/admin.css", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Header().Get("Content-Type"), "text/css") || !strings.Contains(response.Body.String(), ".sidebar") {
		t.Fatalf("embedded stylesheet response invalid: status=%d type=%q", response.Code, response.Header().Get("Content-Type"))
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("embedded asset cache control = %q, want no-store", response.Header().Get("Cache-Control"))
	}
	response = httptest.NewRecorder()
	manager.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9090/assets/admin.js", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "pendingConfirmForm") || !strings.Contains(response.Body.String(), "requestSubmit") {
		t.Fatalf("embedded confirmation script response invalid: status=%d", response.Code)
	}
}

func TestManagerLiveTrafficAggregatesByUserAndNode(t *testing.T) {
	store, err := storage.NewSQLiteStore(t.TempDir()+"/admin.db", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	users := map[string]config.UserConfig{
		"alice": {Routes: []string{"node1", "direct"}},
		"bob":   {Routes: []string{"node1"}},
	}
	trafficLogger := traffic.NewTrafficLogger(users, store, zap.NewNop())
	trafficLogger.LogTraffic("alice:node1", 100, 200)
	trafficLogger.LogTraffic("alice:direct", 10, 20)
	trafficLogger.LogTraffic("bob:node1", 40, 50)
	trafficLogger.LogOnlineState("alice:node1", true)
	trafficLogger.LogOnlineState("bob:node1", true)
	manager, err := NewManager(&config.Config{Timezone: "UTC"}, store, trafficLogger, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	manager.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9090/live", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("live status response = %d: %s", response.Code, response.Body.String())
	}
	var status liveStatus
	if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.Total.TxBytes != 150 || status.Total.RxBytes != 270 || status.Total.Online != 2 {
		t.Fatalf("unexpected total live traffic: %#v", status.Total)
	}
	if got := status.Users["alice"]; got.TxBytes != 110 || got.RxBytes != 220 || got.Online != 1 {
		t.Fatalf("unexpected alice live traffic: %#v", got)
	}
	if got := status.Nodes["node1"]; got.TxBytes != 140 || got.RxBytes != 250 || got.Online != 2 {
		t.Fatalf("unexpected node1 live traffic: %#v", got)
	}
}

func TestDirectRouteSetIncludesLegacyNamedDirectNodes(t *testing.T) {
	routes := directRouteSet([]storage.ManagedNode{
		{Name: "direct-v4", Config: config.NodeConfig{Type: "direct", Direct: &config.DirectConfig{}}},
		{Name: "node1", Config: config.NodeConfig{Type: "socks5", SOCKS5: &config.SOCKS5Config{Addr: "127.0.0.1:1080"}}},
	})
	if !routes["direct"] || !routes["direct-v4"] || routes["node1"] {
		t.Fatalf("unexpected direct route set: %#v", routes)
	}
}
