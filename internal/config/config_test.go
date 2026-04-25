package config

import (
	"os"
	"testing"
)

func TestLoad_ValidConfig(t *testing.T) {
	content := `
listen: ":8443"
tls:
  cert: test.crt
  key: test.key
users:
  alice:
    password: "pass123"
    route: "direct"
    maxBytes: 1000000
  bob:
    password: "secret"
    route: "node1"
nodes:
  node1:
    type: socks5
    socks5:
      addr: "proxy.example.com:1080"
api:
  listen: ":9090"
  secret: "test_secret"
dbPath: "test.db"
`
	path := writeTempFile(t, content)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}

	if cfg.Listen != ":8443" {
		t.Errorf("expected listen :8443, got %s", cfg.Listen)
	}
	if len(cfg.Users) != 2 {
		t.Errorf("expected 2 users, got %d", len(cfg.Users))
	}
	if cfg.Users["alice"].MaxBytes != 1000000 {
		t.Errorf("expected alice maxBytes=1000000, got %d", cfg.Users["alice"].MaxBytes)
	}
	if cfg.Users["bob"].Route != "node1" {
		t.Errorf("expected bob route=node1, got %s", cfg.Users["bob"].Route)
	}
	if cfg.DBPath != "test.db" {
		t.Errorf("expected dbPath=test.db, got %s", cfg.DBPath)
	}
}

func TestLoad_DefaultValues(t *testing.T) {
	content := `
tls:
  cert: test.crt
  key: test.key
users:
  alice:
    password: "pass123"
    route: "direct"
api:
  listen: ":9090"
`
	path := writeTempFile(t, content)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}

	if cfg.Listen != ":443" {
		t.Errorf("expected default listen :443, got %s", cfg.Listen)
	}
	if cfg.DBPath != "hy2-gateway.db" {
		t.Errorf("expected default dbPath, got %s", cfg.DBPath)
	}
}

func TestLoad_MissingTLS(t *testing.T) {
	content := `
users:
  alice:
    password: "pass123"
    route: "direct"
`
	path := writeTempFile(t, content)
	_, err := Load(path)
	if err == nil {
		t.Error("expected error for missing TLS config")
	}
}

func TestLoad_NoUsers(t *testing.T) {
	content := `
tls:
  cert: test.crt
  key: test.key
users: {}
`
	path := writeTempFile(t, content)
	_, err := Load(path)
	if err == nil {
		t.Error("expected error for empty users")
	}
}

func TestLoad_InvalidRoute(t *testing.T) {
	content := `
tls:
  cert: test.crt
  key: test.key
users:
  alice:
    password: "pass123"
    route: "nonexistent_node"
`
	path := writeTempFile(t, content)
	_, err := Load(path)
	if err == nil {
		t.Error("expected error for invalid route reference")
	}
}

func TestLoad_Hysteria2Node(t *testing.T) {
	content := `
tls:
  cert: test.crt
  key: test.key
users:
  alice:
    password: "pass123"
    route: "hy2_node"
nodes:
  hy2_node:
    type: hysteria2
    hysteria2:
      addr: "remote.example.com:443"
      auth: "some_auth"
      insecure: true
api:
  listen: ":9090"
`
	path := writeTempFile(t, content)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}

	node := cfg.Nodes["hy2_node"]
	if node.Type != "hysteria2" {
		t.Errorf("expected type hysteria2, got %s", node.Type)
	}
	if node.Hysteria2.Addr != "remote.example.com:443" {
		t.Errorf("expected addr remote.example.com:443, got %s", node.Hysteria2.Addr)
	}
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "config-*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	f.Close()
	return f.Name()
}
