package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const migratableLegacyYAML = `
listen: ":8443"
quic:
  maxIdleTimeout: 30s
  maxIncomingStreams: 128
tls:
  cert: ./cert.pem
  key: ./key.pem
admin:
  listen: "127.0.0.1:9090"
api:
  listen: "127.0.0.1:9191"
sub:
  listen: "127.0.0.1:9091"
  publicURL: "https://sub.example.com/sub/"
  serverAddr: "gateway.example.com:8443"
  sni: gateway.example.com
  insecure: true
dbPath: ./traffic.db
timezone: Asia/Shanghai
trafficFlushInterval: 7s
systemd:
  unit: gateway.service
  watchdog: true
`

func TestMigrateLegacyInboundsPreservesRuntimeValues(t *testing.T) {
	result, err := MigrateLegacyInbounds([]byte(migratableLegacyYAML))
	if err != nil {
		t.Fatalf("MigrateLegacyInbounds failed: %v", err)
	}
	if len(result.Diagnostics) != 1 || !strings.Contains(result.Diagnostics[0], "admin.listen") {
		t.Fatalf("expected listener precedence diagnostic, got %#v", result.Diagnostics)
	}
	cfg, err := ParseInboundConfig(result.YAML)
	if err != nil {
		t.Fatalf("generated YAML did not round trip: %v\n%s", err, result.YAML)
	}
	if got := cfg.Inbounds[0]; got.Name != "hy2-public" || got.Listen != ":8443" || got.QUIC == nil || got.QUIC.MaxIdleTimeout != 30*time.Second || got.QUIC.MaxIncomingStreams != 128 {
		t.Fatalf("inbound was not preserved: %#v", got)
	}
	if cfg.TLS.Cert != "./cert.pem" || cfg.TLS.Key != "./key.pem" || cfg.DBPath != "./traffic.db" {
		t.Fatalf("paths were not preserved: %#v", cfg)
	}
	if cfg.Admin.Listen != "127.0.0.1:9090" {
		t.Fatalf("admin precedence changed: %q", cfg.Admin.Listen)
	}
	if cfg.Sub == nil || cfg.Sub.Inbound != "hy2-public" || cfg.Sub.ServerAddr != "gateway.example.com:8443" || !cfg.Sub.Insecure {
		t.Fatalf("subscription was not preserved and bound: %#v", cfg.Sub)
	}
	if cfg.Timezone != "Asia/Shanghai" || cfg.TrafficFlushInterval != 7*time.Second || cfg.Systemd == nil || !cfg.Systemd.Watchdog {
		t.Fatalf("operational settings were not preserved: %#v", cfg)
	}
	output := string(result.YAML)
	for _, forbidden := range []string{"api:", "users:", "nodes:", "secret:"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("generated YAML contains forbidden legacy field %q:\n%s", forbidden, output)
		}
	}
}

func TestMigrateLegacyInboundsMakesDefaultListenExplicit(t *testing.T) {
	legacy := `
tls:
  cert: cert.pem
  key: key.pem
api:
  listen: "127.0.0.1:9090"
`
	result, err := MigrateLegacyInbounds([]byte(legacy))
	if err != nil {
		t.Fatalf("MigrateLegacyInbounds failed: %v", err)
	}
	if !strings.Contains(string(result.YAML), "listen: :443") {
		t.Fatalf("default listen was not explicit:\n%s", result.YAML)
	}
	cfg, err := ParseInboundConfig(result.YAML)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Admin.Listen != "127.0.0.1:9090" {
		t.Fatalf("api.listen was not migrated: %q", cfg.Admin.Listen)
	}
}

func TestMigrateLegacyInboundsRejectsUnsafeInputs(t *testing.T) {
	tests := []struct {
		name, fragment, want string
	}{
		{name: "users", fragment: "users:\n  alice:\n    password: secret\n    routes: [direct]\n", want: "management data"},
		{name: "nodes", fragment: "nodes:\n  node1:\n    type: hysteria2\n    hysteria2:\n      addr: example.com:443\n      auth: secret\n", want: "management data"},
		{name: "api secret", fragment: "api:\n  secret: secret-value\n", want: "subscription secret"},
		{name: "sub secret", fragment: "sub:\n  secret: secret-value\n", want: "subscription secret"},
		{name: "sub address", fragment: "sub:\n  listen: 127.0.0.1:9091\n", want: "sub.serverAddr must be configured"},
		{name: "obfs", fragment: "obfs: {}\n", want: "field obfs is unsupported"},
		{name: "masquerade", fragment: "masquerade: null\n", want: "field masquerade is unsupported"},
		{name: "unknown field", fragment: "fallback: direct\n", want: "field fallback not found"},
		{name: "duplicate key", fragment: "listen: :443\nlisten: :8443\n", want: "duplicate key"},
		{name: "multiple docs", fragment: "listen: :443\n---\nlisten: :8443\n", want: "multiple YAML documents"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := "tls:\n  cert: cert.pem\n  key: key.pem\n" + test.fragment
			_, err := MigrateLegacyInbounds([]byte(input))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestMigrateLegacyInboundsMigratesEnabledTrojan(t *testing.T) {
	result, err := MigrateLegacyInbounds([]byte(`
listen: :443
trojan:
  listen: :443
  serverAddr: gateway.example.com:443
tls:
  cert: cert.pem
  key: key.pem
`))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseInboundConfig(result.YAML)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Inbounds) != 2 || cfg.Inbounds[1].Type != TrojanInboundType || cfg.Inbounds[1].Listen != ":443" {
		t.Fatalf("Trojan inbound was not migrated: %#v", cfg.Inbounds)
	}
	if len(result.Diagnostics) != 1 {
		t.Fatalf("diagnostics = %#v, want Trojan subscription warning", result.Diagnostics)
	}
}

func TestMigrateLegacyInboundsAcceptsDisabledTrojan(t *testing.T) {
	input := `
tls:
  cert: cert.pem
  key: key.pem
trojan:
  listen: ""
  serverAddr: gateway.example.com:443
`
	if _, err := MigrateLegacyInbounds([]byte(input)); err != nil {
		t.Fatalf("disabled Trojan config must remain disabled: %v", err)
	}
}

func TestMigrateLegacyInboundsRejectsNewSchema(t *testing.T) {
	_, err := MigrateLegacyInbounds([]byte(validInboundYAML))
	if err == nil || !strings.Contains(err.Error(), "uses the new inbounds schema") {
		t.Fatalf("error = %v", err)
	}
}

func TestMigrateLegacyInboundsFileCreatesExclusivelyWithoutDatabaseAccess(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "legacy.yaml")
	outputPath := filepath.Join(dir, "new.yaml")
	dbPath := filepath.Join(dir, "must-not-exist.db")
	input := strings.Replace(migratableLegacyYAML, "./traffic.db", dbPath, 1)
	if err := os.WriteFile(inputPath, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	diagnostics, err := MigrateLegacyInboundsFile(inputPath, outputPath)
	if err != nil {
		t.Fatalf("MigrateLegacyInboundsFile failed: %v", err)
	}
	if len(diagnostics) != 1 {
		t.Fatalf("expected diagnostic, got %#v", diagnostics)
	}
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Fatalf("migration touched database path: %v", err)
	}
	before, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateLegacyInboundsFile(inputPath, outputPath); err == nil || !strings.Contains(err.Error(), "create output exclusively") {
		t.Fatalf("existing output was not rejected: %v", err)
	}
	after, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("failed overwrite attempt changed output")
	}
	if _, err := MigrateLegacyInboundsFile(inputPath, inputPath); err == nil {
		t.Fatal("source and target path must not be accepted")
	}
}
