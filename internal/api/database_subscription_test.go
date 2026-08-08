package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hy2-gateway/internal/config"
	"github.com/hy2-gateway/internal/storage"
	"go.uber.org/zap"
)

func TestDatabaseSubscriptionUsesRestartAppliedRoutes(t *testing.T) {
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
	handler := NewDatabaseSubscriptionHandler(&config.Config{Sub: &config.SubConfig{ServerAddr: "gateway.example:8443"}}, store, users, map[string]config.NodeConfig{"node1": node1}, zap.NewNop()).Handler()

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://sub.example/sub/subscription-token", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("subscription status = %d: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "Node One") || !strings.Contains(response.Body.String(), "gateway-password") {
		t.Fatalf("subscription omitted applied node or live password: %s", response.Body.String())
	}

	if err := store.SaveNode("node2", config.NodeConfig{Type: "socks5", Alias: "Node Two", SOCKS5: &config.SOCKS5Config{Addr: "127.0.0.1:1080"}}, true); err != nil {
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
	handler := NewDatabaseSubscriptionHandler(&config.Config{Listen: "gateway.example:8443"}, store, users, nil, zap.NewNop()).Handler()
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
	handler := NewDatabaseSubscriptionHandler(&config.Config{Listen: "gateway.example:8443"}, store, users, nil, zap.NewNop()).Handler()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://sub.example/subscription-token", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("token outside /sub/ status = %d, want 404", response.Code)
	}
}
