package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/clayicarus/proxy-gateway/internal/config"
	"github.com/clayicarus/proxy-gateway/internal/storage"
	"github.com/clayicarus/proxy-gateway/internal/traffic"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

func TestDatabaseSubscriptionUsesRestartAppliedRoutes(t *testing.T) {
	for _, protocol := range []string{config.Hysteria2InboundType, config.TrojanInboundType} {
		t.Run(protocol, func(t *testing.T) {
			testDatabaseSubscriptionUsesRestartAppliedRoutes(t, protocol)
		})
	}
}

func testDatabaseSubscriptionUsesRestartAppliedRoutes(t *testing.T, protocol string) {
	store, err := storage.NewSQLiteStore(t.TempDir()+"/managed.db", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	node1 := config.NodeConfig{Type: "hysteria2", Alias: "Node One", Hysteria2: &config.Hysteria2OutboundConfig{Addr: "node1.example:443", Auth: "node-password"}}
	if err := store.SaveNode("node1", node1, true); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateUser(storage.ManagedUserInput{Username: "alice", Password: "gateway-password", Routes: []string{"node1"}}, "subscription-token"); err != nil {
		t.Fatal(err)
	}
	users := map[string]config.UserConfig{"alice": {Password: "gateway-password", Routes: []string{"node1"}}}
	handler := NewDatabaseSubscriptionHandler(subscriptionTestConfig(protocol), store, users, map[string]config.NodeConfig{"node1": node1}, zap.NewNop()).Handler()

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://sub.example/sub/subscription-token", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("subscription status = %d: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "Node One") || !strings.Contains(response.Body.String(), "gateway-password") {
		t.Fatalf("subscription omitted applied node or live password: %s", response.Body.String())
	}
	proxies := decodeClientSubscription(t, response).Proxies
	if len(proxies) != 3 || proxies[0]["type"] != protocol || proxies[0]["password"] != "alice:node1:gateway-password" {
		t.Fatal("subscription did not publish the selected protocol and node credential")
	}
	for _, proxy := range proxies[1:] {
		proxy["name"] = proxies[0]["name"]
		if !reflect.DeepEqual(proxy, proxies[0]) {
			t.Fatal("information entry lost the authorized proxy transport or credentials")
		}
	}

	if err := store.SaveNode("node2", config.NodeConfig{Type: "hysteria2", Alias: "Node Two", Hysteria2: &config.Hysteria2OutboundConfig{Addr: "node2.example:443", Auth: "node-password"}}, true); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateUser(storage.ManagedUserInput{Username: "alice", Password: "new-password", Routes: []string{"node2"}}); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://sub.example/sub/subscription-token", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("subscription after pending change status = %d: %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "Node Two") || !strings.Contains(response.Body.String(), "Node One") || !strings.Contains(response.Body.String(), "new-password") {
		t.Fatalf("subscription did not retain applied routes with live password: %s", response.Body.String())
	}
}

func TestDatabaseSubscriptionRejectsInactiveUser(t *testing.T) {
	store, err := storage.NewSQLiteStore(t.TempDir()+"/managed.db", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.CreateUser(storage.ManagedUserInput{Username: "alice", Password: "password", Routes: []string{"direct"}}, "subscription-token"); err != nil {
		t.Fatal(err)
	}
	users := map[string]config.UserConfig{"alice": {Password: "password", Routes: []string{"direct"}}}
	handler := NewDatabaseSubscriptionHandler(subscriptionTestConfig(config.TrojanInboundType), store, users, nil, zap.NewNop()).Handler()
	if err := store.SetUserDeleted("alice", true); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://sub.example/sub/subscription-token", nil))
	if response.Code != http.StatusForbidden {
		t.Fatalf("deleted user status = %d", response.Code)
	}
	if err := store.SetUserDeleted("alice", false); err != nil {
		t.Fatal(err)
	}
	expired := time.Now().Add(-time.Hour).UTC()
	if err := store.UpdateUser(storage.ManagedUserInput{Username: "alice", Password: "password", ExpiresAt: &expired, Routes: []string{"direct"}}); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://sub.example/sub/subscription-token", nil))
	if response.Code != http.StatusForbidden {
		t.Fatalf("expired user status = %d", response.Code)
	}
}

func TestDatabaseSubscriptionRejectsTokenOutsideSubPath(t *testing.T) {
	store, err := storage.NewSQLiteStore(t.TempDir()+"/managed.db", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.CreateUser(storage.ManagedUserInput{Username: "alice", Password: "password", Routes: []string{"direct"}}, "subscription-token"); err != nil {
		t.Fatal(err)
	}
	users := map[string]config.UserConfig{"alice": {Password: "password", Routes: []string{"direct"}}}
	handler := NewDatabaseSubscriptionHandler(subscriptionTestConfig(config.TrojanInboundType), store, users, nil, zap.NewNop()).Handler()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://sub.example/subscription-token", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("token outside /sub/ status = %d, want 404", response.Code)
	}
}

func TestDatabaseSubscriptionEscapesYAMLSpecialCharacters(t *testing.T) {
	store, err := storage.NewSQLiteStore(t.TempDir()+"/managed.db", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	node := config.NodeConfig{
		Type:      "hysteria2",
		Alias:     "Node \"One\"\nPrimary",
		Hysteria2: &config.Hysteria2OutboundConfig{Addr: "node1.example:443", Auth: "node-password"},
	}
	password := "p\"ass\\word\nsecond-line"
	if err := store.SaveNode("node1", node, true); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateUser(storage.ManagedUserInput{Username: "alice", Password: password, Routes: []string{"node1"}}, "subscription-token"); err != nil {
		t.Fatal(err)
	}
	users := map[string]config.UserConfig{"alice": {Password: password, Routes: []string{"node1"}}}
	handler := NewDatabaseSubscriptionHandler(subscriptionTestConfig(config.Hysteria2InboundType), store, users, map[string]config.NodeConfig{"node1": node}, zap.NewNop()).Handler()

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://sub.example/sub/subscription-token", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("subscription status = %d: %s", response.Code, response.Body.String())
	}
	var decoded managedClashConfig
	if err := yaml.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("generated subscription is invalid YAML: %v\n%s", err, response.Body.String())
	}
	if len(decoded.Proxies) != 3 || decoded.Proxies[0].Name != node.Alias || decoded.Proxies[0].Auth != "alice:node1:"+password {
		t.Fatalf("special characters did not round trip: %#v", decoded.Proxies)
	}
	if decoded.Proxies[1].Name != "有效期剩余：长期有效" || decoded.Proxies[2].Name != "本月已用流量：0 B" {
		t.Fatalf("subscription information proxies = %#v", decoded.Proxies[1:])
	}
}

func TestDatabaseSubscriptionShowsExpiryAndNonDirectMonthlyUsage(t *testing.T) {
	store, err := storage.NewSQLiteStore(t.TempDir()+"/managed.db", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	node := config.NodeConfig{Type: "hysteria2", Alias: "Node One", Hysteria2: &config.Hysteria2OutboundConfig{Addr: "node1.example:443", Auth: "node-password"}}
	if err := store.SaveNode("node1", node, true); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	expiresAt := now.Add(49 * time.Hour)
	if err := store.CreateUser(storage.ManagedUserInput{
		Username: "alice", Password: "gateway-password", ExpiresAt: &expiresAt,
		MonthlyBytes: 10 * 1024, Routes: []string{"direct", "node1"},
	}, "subscription-token"); err != nil {
		t.Fatal(err)
	}
	users := map[string]config.UserConfig{"alice": {
		Password: "gateway-password", ExpiresAt: &expiresAt,
		MaxBytes: 10 * 1024, Routes: []string{"direct", "node1"},
	}}
	trafficLogger := traffic.NewTrafficLoggerWithLocation(users, store, zap.NewNop(), time.UTC)
	if !trafficLogger.LogTraffic("alice:node1", 3*1024, 1024) {
		t.Fatal("non-direct traffic rejected")
	}
	if !trafficLogger.LogTraffic("alice:direct", 10, 20) {
		t.Fatal("direct traffic rejected")
	}
	cfg := subscriptionTestConfig(config.Hysteria2InboundType)
	cfg.Timezone = "UTC"
	handler := NewDatabaseSubscriptionHandler(cfg, store, users, map[string]config.NodeConfig{"node1": node}, zap.NewNop(), trafficLogger)
	handler.now = func() time.Time { return now }

	response := httptest.NewRecorder()
	handler.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://sub.example/sub/subscription-token", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("subscription status = %d: %s", response.Code, response.Body.String())
	}
	var decoded managedClashConfig
	if err := yaml.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Proxies) != 4 {
		t.Fatalf("proxy count = %d, want 4", len(decoded.Proxies))
	}
	if decoded.Proxies[2].Name != "有效期剩余：3 天" || decoded.Proxies[3].Name != "本月已用流量：4.00 KB" {
		t.Fatalf("information proxies = %#v", decoded.Proxies[2:])
	}
	group := decoded.ProxyGroups[0].Proxies
	if group[2] != decoded.Proxies[2].Name || group[3] != decoded.Proxies[3].Name {
		t.Fatalf("information proxies missing from group: %#v", group)
	}
	wantUserinfo := "upload=3072; download=1024; total=10240; expire=" + strconv.FormatInt(expiresAt.Unix(), 10)
	if got := response.Header().Get("Subscription-Userinfo"); got != wantUserinfo {
		t.Fatalf("Subscription-Userinfo = %q, want %q", got, wantUserinfo)
	}
}

func TestSubscriptionMonthlyWindowAndUserIsolation(t *testing.T) {
	cfg := subscriptionTestConfig(config.Hysteria2InboundType)
	cfg.Timezone = "Asia/Shanghai"
	store, _ := newSubscriptionFixture(t, cfg, []string{"direct"}, nil)
	now := time.Date(2026, time.September, 15, 12, 0, 0, 0, time.UTC)
	// September in UTC+8 starts on August 31 at 16:00 UTC.
	start := time.Date(2026, time.August, 31, 16, 0, 0, 0, time.UTC)
	end := time.Date(2026, time.September, 30, 16, 0, 0, 0, time.UTC)
	if err := store.FlushTraffic([]storage.TrafficRecord{
		{UserID: "alice", NodeID: "old-node", TxBytes: 100, RxBytes: 200, Timestamp: start},
		{UserID: "alice", NodeID: "other-node", TxBytes: 10, RxBytes: 20, Timestamp: end.Add(-time.Second)},
		{UserID: "alice", NodeID: "old-node", TxBytes: 1000, Timestamp: start.Add(-time.Second)},
		{UserID: "alice", NodeID: "old-node", TxBytes: 2000, Timestamp: end},
		{UserID: "alice", NodeID: "direct", TxBytes: 4000, Timestamp: now},
		{UserID: "bob", NodeID: "old-node", TxBytes: 8000, Timestamp: now},
	}); err != nil {
		t.Fatal(err)
	}
	h := NewDatabaseSubscriptionHandler(cfg, store, map[string]config.UserConfig{"alice": {Routes: []string{"direct"}}}, nil, zap.NewNop())
	h.now = func() time.Time { return now }
	response := requestTestSubscription(h.Handler(), "subscription-token")
	decoded := decodeClientSubscription(t, response)
	if got := response.Header().Get("Subscription-Userinfo"); got != "upload=110; download=220" {
		t.Fatalf("current-month user usage = %q", got)
	}
	if decoded.Proxies[2]["name"] != "本月已用流量：330 B" {
		t.Fatal("card usage did not match header")
	}
	h.now = func() time.Time { return end }
	response = requestTestSubscription(h.Handler(), "subscription-token")
	decodeClientSubscription(t, response)
	if got := response.Header().Get("Subscription-Userinfo"); got != "upload=2000; download=0" {
		t.Fatalf("new-month user usage = %q", got)
	}
}

type failedSubscriptionFlush struct{}

func (failedSubscriptionFlush) FlushContext(context.Context) error {
	return errors.New("test flush failure")
}

func TestSubscriptionDoesNotPublishStaleUsageOnFlushFailure(t *testing.T) {
	cfg := subscriptionTestConfig(config.TrojanInboundType)
	store, _ := newSubscriptionFixture(t, cfg, []string{"direct"}, nil)
	h := NewDatabaseSubscriptionHandler(cfg, store, map[string]config.UserConfig{"alice": {Routes: []string{"direct"}}}, nil, zap.NewNop(), failedSubscriptionFlush{})
	response := requestTestSubscription(h.Handler(), "subscription-token")
	if response.Code != http.StatusServiceUnavailable || response.Header().Get("Subscription-Userinfo") != "" || strings.Contains(response.Body.String(), "test:password") {
		t.Fatal("failed flush published usage or credentials")
	}
}

func TestSubscriptionInformationNamesCannotCollide(t *testing.T) {
	for _, alias := range []string{"有效期剩余：长期有效", "本月已用流量：0 B"} {
		nodes := map[string]config.NodeConfig{"node": {
			Type: "hysteria2", Alias: alias,
			Hysteria2: &config.Hysteria2OutboundConfig{Addr: "node.example:443", Auth: "secret"},
		}}
		_, handler := newSubscriptionFixture(t, subscriptionTestConfig(config.Hysteria2InboundType), []string{"node"}, nodes)
		decoded := decodeClientSubscription(t, requestTestSubscription(handler, "subscription-token"))
		seen := map[any]bool{}
		for _, proxy := range decoded.Proxies {
			if seen[proxy["name"]] {
				t.Fatalf("duplicate proxy name: %s", proxy["name"])
			}
			seen[proxy["name"]] = true
		}
	}
}

func TestSubscriptionExpiryLabels(t *testing.T) {
	now := time.Date(2026, time.September, 18, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		remaining time.Duration
		want      string
	}{
		{time.Second, "有效期剩余：1 天"},
		{24 * time.Hour, "有效期剩余：1 天"},
		{24*time.Hour + time.Second, "有效期剩余：2 天"},
		{0, "有效期剩余：已到期"},
	} {
		expires := now.Add(test.remaining)
		if got := subscriptionExpiryLabel(&expires, now); got != test.want {
			t.Fatalf("expiry %s: got %q, want %q", test.remaining, got, test.want)
		}
	}
}

func subscriptionTestConfig(protocol string) *config.Config {
	return &config.Config{
		Inbounds: []config.Inbound{{Name: "public", Type: protocol, Listen: ":9443"}},
		Sub:      &config.SubConfig{Inbound: "public", ServerAddr: "gateway.example:8443", SNI: "gateway.example"},
	}
}

type clientSubscription struct {
	Proxies     []map[string]any `yaml:"proxies"`
	ProxyGroups []struct {
		Name    string   `yaml:"name"`
		Proxies []string `yaml:"proxies"`
	} `yaml:"proxy-groups"`
}

func decodeClientSubscription(t *testing.T, response *httptest.ResponseRecorder) clientSubscription {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("subscription status = %d, want 200", response.Code)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("credential-bearing subscription must disable caching")
	}
	var decoded clientSubscription
	if err := yaml.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid Clash YAML: %v", err)
	}
	return decoded
}

func newSubscriptionFixture(t *testing.T, cfg *config.Config, routes []string, nodes map[string]config.NodeConfig) (*storage.SQLiteStore, http.Handler) {
	t.Helper()
	store, err := storage.NewSQLiteStore(t.TempDir()+"/managed.db", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	for name, node := range nodes {
		if err := store.SaveNode(name, node, true); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.CreateUser(storage.ManagedUserInput{Username: "alice", Password: "test:password", Routes: routes}, "subscription-token"); err != nil {
		t.Fatal(err)
	}
	users := map[string]config.UserConfig{"alice": {Password: "test:password", Routes: routes}}
	return store, NewDatabaseSubscriptionHandler(cfg, store, users, nodes, zap.NewNop()).Handler()
}

func requestTestSubscription(handler http.Handler, token string) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/sub/"+token, nil))
	return response
}

func TestDatabaseSubscriptionMixedInbounds(t *testing.T) {
	cfg := &config.Config{
		Inbounds: []config.Inbound{
			{Name: "private", Type: config.Hysteria2InboundType, Listen: "127.0.0.1:7443"},
			{Name: "hy2", Type: config.Hysteria2InboundType, Listen: ":8443"},
			{Name: "trojan", Type: config.TrojanInboundType, Listen: ":9443"},
		},
		Sub: &config.SubConfig{Endpoints: []config.SubscriptionEndpoint{
			{Inbound: "hy2", ServerAddr: "hy2.example:443", SNI: "hy2-tls.example"},
			{Inbound: "trojan", ServerAddr: "[2001:db8::1]:10443", SNI: "trojan-tls.example", Insecure: true},
		}},
	}
	nodes := map[string]config.NodeConfig{
		"node1": {Type: "hysteria2", Alias: "Node One", Hysteria2: &config.Hysteria2OutboundConfig{Addr: "node1.example:443", Auth: "node-secret"}},
		"node2": {Type: "hysteria2", Alias: "Unassigned", Hysteria2: &config.Hysteria2OutboundConfig{Addr: "node2.example:443", Auth: "node-secret"}},
	}
	store, handler := newSubscriptionFixture(t, cfg, []string{"node1", "direct"}, nodes)
	response := requestTestSubscription(handler, "subscription-token")
	decoded := decodeClientSubscription(t, response)
	if len(decoded.Proxies) != 6 {
		t.Fatalf("proxy count = %d, want four route entries and two information entries", len(decoded.Proxies))
	}
	for i, proxy := range decoded.Proxies[:4] {
		route, alias := "node1", "Node One"
		if i >= 2 {
			route, alias = "direct", "direct"
		}
		if proxy["password"] != "alice:"+route+":test:password" {
			t.Fatal("proxy password is not the raw authorized user/node credential")
		}
		if i%2 == 0 {
			if proxy["type"] != "hysteria2" || proxy["name"] != alias+"-hysteria2" || proxy["server"] != "hy2.example" || proxy["port"] != 443 || proxy["sni"] != "hy2-tls.example" || proxy["skip-cert-verify"] != false {
				t.Fatal("Hysteria2 endpoint or TLS settings were not preserved")
			}
			if _, exists := proxy["udp"]; exists {
				t.Fatal("Hysteria2 output unexpectedly changed its UDP setting")
			}
		} else {
			if proxy["type"] != "trojan" || proxy["name"] != alias+"-trojan" || proxy["server"] != "2001:db8::1" || proxy["port"] != 10443 || proxy["sni"] != "trojan-tls.example" || proxy["skip-cert-verify"] != true || proxy["udp"] != true {
				t.Fatal("Trojan endpoint, TLS settings or UDP support were not preserved")
			}
		}
	}
	if len(decoded.ProxyGroups) != 1 || len(decoded.ProxyGroups[0].Proxies) != 7 {
		t.Fatal("selection group must include every proxy and local DIRECT")
	}
	for i, proxy := range decoded.Proxies {
		if decoded.ProxyGroups[0].Proxies[i] != proxy["name"] {
			t.Fatal("selection group references the wrong proxy")
		}
	}
	if decoded.ProxyGroups[0].Proxies[6] != "DIRECT" {
		t.Fatal("local DIRECT option was lost")
	}
	if err := store.ResetUserToken("alice", "rotated-token"); err != nil {
		t.Fatal(err)
	}
	if status := requestTestSubscription(handler, "subscription-token").Code; status != http.StatusForbidden {
		t.Fatalf("rotated token status = %d, want 403", status)
	}
	decodeClientSubscription(t, requestTestSubscription(handler, "rotated-token"))
}

func TestDatabaseSubscriptionUniqueNamesAndSnapshot(t *testing.T) {
	cfg := &config.Config{
		Inbounds: []config.Inbound{
			{Name: "one", Type: config.TrojanInboundType},
			{Name: "two", Type: config.TrojanInboundType},
		},
		Sub: &config.SubConfig{Endpoints: []config.SubscriptionEndpoint{
			{Inbound: "one", ServerAddr: "one.example:443"},
			{Inbound: "two", ServerAddr: "two.example:8443"},
		}},
	}
	nodes := map[string]config.NodeConfig{
		"node1": {Type: "hysteria2", Alias: "Same", Hysteria2: &config.Hysteria2OutboundConfig{Addr: "one.example:443", Auth: "secret"}},
		"node2": {Type: "hysteria2", Alias: "Same", Hysteria2: &config.Hysteria2OutboundConfig{Addr: "two.example:443", Auth: "secret"}},
	}
	_, handler := newSubscriptionFixture(t, cfg, []string{"node1", "node2"}, nodes)
	// Caller-owned node maps are not allowed to change the restart snapshot.
	delete(nodes, "node1")
	response := requestTestSubscription(handler, "subscription-token")
	decoded := decodeClientSubscription(t, response)
	if len(decoded.Proxies) != 6 {
		t.Fatal("node mutation changed the applied subscription snapshot")
	}
	seen := map[string]bool{}
	for i, proxy := range decoded.Proxies {
		name := proxy["name"].(string)
		if seen[name] || (i < 4 && !strings.Contains(name, "-trojan-")) {
			t.Fatalf("proxy name %q does not distinguish protocol and inbound", name)
		}
		seen[name] = true
		if decoded.ProxyGroups[0].Proxies[i] != name {
			t.Fatal("renamed proxy was not included in the selection group")
		}
	}
	if second := requestTestSubscription(handler, "subscription-token"); second.Body.String() != response.Body.String() {
		t.Fatal("unchanged subscription must have deterministic proxy names")
	}
}

func TestDatabaseSubscriptionReservedAliases(t *testing.T) {
	for _, alias := range []string{"DIRECT", "REJECT", "规则代理"} {
		t.Run(alias, func(t *testing.T) {
			nodes := map[string]config.NodeConfig{
				"node": {Type: "hysteria2", Alias: alias, Hysteria2: &config.Hysteria2OutboundConfig{Addr: "node.example:443", Auth: "secret"}},
			}
			_, handler := newSubscriptionFixture(t, subscriptionTestConfig(config.Hysteria2InboundType), []string{"node"}, nodes)
			decoded := decodeClientSubscription(t, requestTestSubscription(handler, "subscription-token"))
			if len(decoded.Proxies) != 3 || decoded.Proxies[0]["name"] == alias || decoded.ProxyGroups[0].Proxies[0] != decoded.Proxies[0]["name"] {
				t.Fatal("node alias shadows a built-in outbound or selection group")
			}
		})
	}
}

func TestDatabaseSubscriptionRejectsUnpublishableEndpoints(t *testing.T) {
	for _, name := range []string{"unknown inbound", "unsupported protocol", "missing address", "invalid port", "wildcard address", "no subscription"} {
		t.Run(name, func(t *testing.T) {
			cfg := subscriptionTestConfig(config.TrojanInboundType)
			switch name {
			case "unknown inbound":
				cfg.Sub.Inbound = "missing"
			case "unsupported protocol":
				cfg.Inbounds[0].Type = "unknown"
			case "missing address":
				cfg.Sub.ServerAddr = ""
			case "invalid port":
				cfg.Sub.ServerAddr = "gateway.example:0"
			case "wildcard address":
				cfg.Sub.ServerAddr = "[::]:443"
			case "no subscription":
				cfg.Sub = nil
			}
			_, handler := newSubscriptionFixture(t, cfg, []string{"direct"}, nil)
			response := requestTestSubscription(handler, "subscription-token")
			if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "test:password") {
				t.Fatalf("unpublishable endpoint returned status %d or exposed credentials", response.Code)
			}
		})
	}
}

func TestDatabaseSubscriptionMatchesWebsiteALPN(t *testing.T) {
	cfg := &config.Config{
		Inbounds: []config.Inbound{
			{Name: "hy2", Type: config.Hysteria2InboundType},
			{Name: "trojan", Type: config.TrojanInboundType},
			{Name: "website", Type: config.TrojanInboundType, Trojan: &config.TrojanInboundConfig{
				Fallback: &config.TrojanFallbackConfig{Addr: "127.0.0.1:8080"},
			}},
		},
		Sub: &config.SubConfig{Endpoints: []config.SubscriptionEndpoint{
			{Inbound: "hy2", ServerAddr: "gateway.example:443"},
			{Inbound: "trojan", ServerAddr: "gateway.example:8443"},
			{Inbound: "website", ServerAddr: "gateway.example:443"},
		}},
	}
	_, handler := newSubscriptionFixture(t, cfg, []string{"direct"}, nil)
	proxies := decodeClientSubscription(t, requestTestSubscription(handler, "subscription-token")).Proxies
	if len(proxies) != 5 {
		t.Fatal("subscription did not publish all configured endpoints")
	}
	for i, proxy := range proxies {
		alpn, present := proxy["alpn"]
		if i != 2 {
			if present {
				t.Fatal("website ALPN affected another inbound")
			}
			continue
		}
		protocols, ok := alpn.([]any)
		if !ok || len(protocols) != 1 || protocols[0] != "http/1.1" {
			t.Fatal("Trojan website subscription must advertise only http/1.1")
		}
	}
}
