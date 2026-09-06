package config

import (
	"os"
	"strings"
	"testing"
	"time"
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

func TestLoad_TrojanDefaultsAndSharedNumericPort(t *testing.T) {
	content := `
listen: ":443"
trojan:
  listen: ":443"
tls:
  cert: test.crt
  key: test.key
`
	cfg, err := Load(writeTempFile(t, content))
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if cfg.Trojan == nil || cfg.Trojan.Listen != ":443" {
		t.Fatalf("unexpected Trojan config: %#v", cfg.Trojan)
	}
	if cfg.Trojan.HandshakeTimeout != DefaultTrojanHandshakeTimeout {
		t.Fatalf("handshake timeout = %v, want %v", cfg.Trojan.HandshakeTimeout, DefaultTrojanHandshakeTimeout)
	}
	if cfg.Trojan.MaxPendingConnections != DefaultTrojanMaxPendingConnections {
		t.Fatalf("pending limit = %d, want %d", cfg.Trojan.MaxPendingConnections, DefaultTrojanMaxPendingConnections)
	}
}

func TestLoad_TrojanDisabledWhenOmittedOrEmpty(t *testing.T) {
	for name, trojanBlock := range map[string]string{
		"omitted": "",
		"empty":   "trojan: {}\n",
	} {
		t.Run(name, func(t *testing.T) {
			content := trojanBlock + "tls:\n  cert: test.crt\n  key: test.key\n"
			cfg, err := Load(writeTempFile(t, content))
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Trojan != nil && cfg.Trojan.Listen != "" {
				t.Fatalf("Trojan unexpectedly enabled: %#v", cfg.Trojan)
			}
		})
	}
}

func TestLoad_TrojanCustomResourceBounds(t *testing.T) {
	content := `
trojan:
  listen: "127.0.0.1:8443"
  handshakeTimeout: 15s
  maxPendingConnections: 64
tls:
  cert: test.crt
  key: test.key
`
	cfg, err := Load(writeTempFile(t, content))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Trojan.HandshakeTimeout != 15*time.Second || cfg.Trojan.MaxPendingConnections != 64 {
		t.Fatalf("unexpected resource bounds: %#v", cfg.Trojan)
	}
}

func TestLoad_RejectsInvalidTrojanConfiguration(t *testing.T) {
	tests := map[string]string{
		"missing port":         "listen: localhost",
		"zero port":            "listen: ':0'",
		"port out of range":    "listen: ':70000'",
		"short timeout":        "listen: ':443'\n  handshakeTimeout: 500ms",
		"long timeout":         "listen: ':443'\n  handshakeTimeout: 3m",
		"negative pending":     "listen: ':443'\n  maxPendingConnections: -1",
		"excessive pending":    "listen: ':443'\n  maxPendingConnections: 65536",
		"future metadata typo": "listen: ':443'\n  serverAddr: example.com:443",
	}
	for name, trojanBlock := range tests {
		t.Run(name, func(t *testing.T) {
			content := "trojan:\n  " + trojanBlock + "\ntls:\n  cert: test.crt\n  key: test.key\n"
			if _, err := Load(writeTempFile(t, content)); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestLoad_RejectsTrojanTCPListenerConflicts(t *testing.T) {
	tests := map[string]string{
		"admin":        "admin:\n  listen: '127.0.0.1:8443'",
		"padded port":  "admin:\n  listen: '127.0.0.1:08443'",
		"legacy admin": "api:\n  listen: '127.0.0.1:8443'",
		"subscription": "sub:\n  listen: '127.0.0.1:8443'\n  serverAddr: 'gateway.example:443'",
	}
	for name, conflicting := range tests {
		t.Run(name, func(t *testing.T) {
			content := "trojan:\n  listen: ':8443'\ntls:\n  cert: test.crt\n  key: test.key\n" + conflicting + "\n"
			if _, err := Load(writeTempFile(t, content)); err == nil || !strings.Contains(err.Error(), "conflicts") {
				t.Fatalf("expected listener conflict, got %v", err)
			}
		})
	}
}

func TestLoad_RejectsUnsupportedTransportOptions(t *testing.T) {
	for _, option := range []string{"obfs", "masquerade"} {
		content := "tls:\n  cert: test.crt\n  key: test.key\n" + option + ": {}\n"
		if _, err := Load(writeTempFile(t, content)); err == nil || !strings.Contains(err.Error(), option+" is not supported") {
			t.Fatalf("unsupported %s was silently accepted: %v", option, err)
		}
	}
}

func TestLoad_SubscriptionRequiresExplicitClientAddress(t *testing.T) {
	for _, address := range []string{"", ":8443", "0.0.0.0:8443", "[::]:8443", "gateway.example", "gateway.example:0"} {
		content := "tls:\n  cert: test.crt\n  key: test.key\nsub:\n  listen: '127.0.0.1:9091'\n  serverAddr: '" + address + "'\n"
		if _, err := Load(writeTempFile(t, content)); err == nil || !strings.Contains(err.Error(), "sub.serverAddr") {
			t.Fatalf("unusable subscription address %q was accepted: %v", address, err)
		}
	}
	content := "tls:\n  cert: test.crt\n  key: test.key\nsub:\n  listen: '127.0.0.1:9091'\n  serverAddr: 'gateway.example:8443'\n"
	if _, err := Load(writeTempFile(t, content)); err != nil {
		t.Fatalf("explicit client address was rejected: %v", err)
	}
}

func TestLoad_RejectsNegativeTrafficFlushInterval(t *testing.T) {
	content := "tls:\n  cert: test.crt\n  key: test.key\ntrafficFlushInterval: -1s\n"
	if _, err := Load(writeTempFile(t, content)); err == nil || !strings.Contains(err.Error(), "trafficFlushInterval") {
		t.Fatalf("expected traffic flush validation error, got %v", err)
	}
}

func TestLoad_RejectsUnknownFieldsAndMultipleDocuments(t *testing.T) {
	unknown := "tls:\n  cert: test.crt\n  key: test.key\nlistenTypo: ':443'\n"
	if _, err := Load(writeTempFile(t, unknown)); err == nil {
		t.Fatal("expected unknown field to be rejected")
	}
	multiple := "tls:\n  cert: test.crt\n  key: test.key\n---\ntls:\n  cert: other.crt\n  key: other.key\n"
	if _, err := Load(writeTempFile(t, multiple)); err == nil {
		t.Fatal("expected multiple YAML documents to be rejected")
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
