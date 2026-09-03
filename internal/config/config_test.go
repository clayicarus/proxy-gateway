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
    routes:
      - direct
    maxBytes: 1000000
  bob:
    password: "secret"
    routes:
      - node1
      - direct
nodes:
  node1:
    type: hysteria2
    hysteria2:
      addr: "proxy.example.com:443"
      auth: "node-secret"
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
	if len(cfg.Users["bob"].Routes) != 2 {
		t.Errorf("expected bob to have 2 routes, got %d", len(cfg.Users["bob"].Routes))
	}
	if cfg.Users["bob"].Routes[0] != "node1" {
		t.Errorf("expected bob routes[0]=node1, got %s", cfg.Users["bob"].Routes[0])
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
    routes:
      - direct
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
	if cfg.DBPath != "proxy-gateway.db" {
		t.Errorf("expected default dbPath, got %s", cfg.DBPath)
	}
}

func TestLoad_MissingTLS(t *testing.T) {
	content := `
users:
  alice:
    password: "pass123"
    routes:
      - direct
`
	path := writeTempFile(t, content)
	_, err := Load(path)
	if err == nil {
		t.Error("expected error for missing TLS config")
	}
}

func TestLoad_AllowsEmptyRuntimeDatabase(t *testing.T) {
	content := `
tls:
  cert: test.crt
  key: test.key
users: {}
`
	path := writeTempFile(t, content)
	if _, err := Load(path); err != nil {
		t.Fatalf("runtime config should allow no legacy users: %v", err)
	}
}

func TestLoad_NoRoutes(t *testing.T) {
	content := `
tls:
  cert: test.crt
  key: test.key
users:
  alice:
    password: "pass123"
    routes: []
`
	path := writeTempFile(t, content)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	err = cfg.ValidateLegacy()
	if err == nil {
		t.Error("expected legacy validation error for empty routes")
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
    routes:
      - nonexistent_node
`
	path := writeTempFile(t, content)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	err = cfg.ValidateLegacy()
	if err == nil {
		t.Error("expected legacy validation error for invalid route reference")
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
    routes:
      - hy2_node
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

func TestLoad_MultipleRoutes(t *testing.T) {
	content := `
tls:
  cert: test.crt
  key: test.key
users:
  alice:
    password: "pass123"
    routes:
      - node_tokyo
      - node_sg
      - direct
nodes:
  node_tokyo:
    type: hysteria2
    hysteria2:
      addr: "tokyo.example.com:443"
      auth: "tokyo-secret"
  node_sg:
    type: hysteria2
    hysteria2:
      addr: "sg.example.com:443"
      auth: "sg-secret"
api:
  listen: ":9090"
`
	path := writeTempFile(t, content)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}

	alice := cfg.Users["alice"]
	if len(alice.Routes) != 3 {
		t.Errorf("expected 3 routes, got %d", len(alice.Routes))
	}
}

func TestValidateLegacy_RejectsRemovedNodeTypes(t *testing.T) {
	for _, nodeType := range []string{"socks5", "http", "direct"} {
		t.Run(nodeType, func(t *testing.T) {
			cfg := &Config{
				Users: map[string]UserConfig{"alice": {Password: "secret", Routes: []string{"node1"}}},
				Nodes: map[string]NodeConfig{"node1": {Type: nodeType}},
			}
			if err := cfg.ValidateLegacy(); err == nil {
				t.Fatalf("legacy validation accepted removed node type %q", nodeType)
			}
		})
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
