package config

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

const validInboundYAML = `
inbounds:
  - name: hy2-public
    type: hysteria2
    listen: ":8443"
    quic:
      maxIdleTimeout: 30s
tls:
  cert: ./cert.pem
  key: ./key.pem
admin:
  listen: "127.0.0.1:9090"
sub:
  listen: "127.0.0.1:9091"
  publicURL: "https://sub.example.com/sub/"
  inbound: hy2-public
  serverAddr: "gateway.example.com:8443"
  sni: gateway.example.com
  insecure: false
dbPath: ./traffic.db
timezone: Asia/Shanghai
trafficFlushInterval: 10s
`

func TestParseInboundConfigValid(t *testing.T) {
	cfg, err := ParseInboundConfig([]byte(validInboundYAML))
	if err != nil {
		t.Fatalf("ParseInboundConfig failed: %v", err)
	}
	if len(cfg.Inbounds) != 1 || cfg.Inbounds[0].Name != "hy2-public" {
		t.Fatalf("unexpected inbounds: %#v", cfg.Inbounds)
	}
	if cfg.Inbounds[0].QUIC == nil || cfg.Inbounds[0].QUIC.MaxIdleTimeout != 30*time.Second {
		t.Fatalf("QUIC duration was not preserved: %#v", cfg.Inbounds[0].QUIC)
	}
	if cfg.Sub == nil || cfg.Sub.Inbound != "hy2-public" {
		t.Fatalf("subscription binding was not preserved: %#v", cfg.Sub)
	}
}

func TestLoadRuntimeProjectsSubscriptionInbound(t *testing.T) {
	path := t.TempDir() + "/gateway.yaml"
	yamlText := strings.Replace(validInboundYAML,
		"inbounds:\n  - name: hy2-public",
		"inbounds:\n  - name: private\n    type: hysteria2\n    listen: \"127.0.0.1:9443\"\n  - name: hy2-public", 1)
	if err := os.WriteFile(path, []byte(yamlText), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadRuntime(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Inbounds) != 2 || cfg.Listen != ":8443" || cfg.Sub == nil || cfg.Sub.Inbound != "hy2-public" {
		t.Fatalf("unexpected runtime projection: %#v", cfg)
	}
}

func TestLoadRuntimeRejectsLegacySchema(t *testing.T) {
	path := t.TempDir() + "/legacy.yaml"
	if err := os.WriteFile(path, []byte("listen: :443\ntls:\n  cert: cert.pem\n  key: key.pem\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRuntime(path); err == nil || !strings.Contains(err.Error(), "field listen not found") {
		t.Fatalf("legacy runtime schema error = %v", err)
	}
}

func TestParseInboundConfigDefaults(t *testing.T) {
	cfg, err := ParseInboundConfig([]byte(`
inbounds:
  - name: hy2
    type: hysteria2
    listen: ":443"
tls:
  cert: cert.pem
  key: key.pem
`))
	if err != nil {
		t.Fatalf("ParseInboundConfig failed: %v", err)
	}
	if cfg.DBPath != "proxy-gateway.db" || cfg.Timezone != "UTC" || cfg.TrafficFlushInterval != 10*time.Second {
		t.Fatalf("unexpected defaults: db=%q timezone=%q flush=%v", cfg.DBPath, cfg.Timezone, cfg.TrafficFlushInterval)
	}
}

func TestParseInboundConfigRejectsInvalidDocuments(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{name: "empty", yaml: "", wantErr: "empty"},
		{name: "unknown top-level field", yaml: validInboundYAML + "mystery: true\n", wantErr: "field mystery not found"},
		{name: "legacy listen", yaml: validInboundYAML + "listen: :443\n", wantErr: "field listen not found"},
		{name: "duplicate key", yaml: strings.Replace(validInboundYAML, "  cert: ./cert.pem", "  cert: ./cert.pem\n  cert: other.pem", 1), wantErr: "duplicate key \"cert\""},
		{name: "multiple documents", yaml: validInboundYAML + "---\n{}\n", wantErr: "multiple YAML documents"},
		{name: "unknown inbound type", yaml: strings.Replace(validInboundYAML, "type: hysteria2", "type: unknown", 1), wantErr: "unsupported value \"unknown\""},
		{name: "cross-type field", yaml: strings.Replace(validInboundYAML, "    listen: \":8443\"", "    listen: \":8443\"\n    handshakeTimeout: 10s", 1), wantErr: "field handshakeTimeout not found"},
		{name: "empty name", yaml: strings.Replace(validInboundYAML, "name: hy2-public", "name: \"\"", 1), wantErr: "name must be non-empty"},
		{name: "missing listen", yaml: strings.Replace(validInboundYAML, "    listen: \":8443\"\n", "", 1), wantErr: "listen must be configured"},
		{name: "bad listen", yaml: strings.Replace(validInboundYAML, "\":8443\"", "\"8443\"", 1), wantErr: "listen is invalid"},
		{name: "short idle timeout", yaml: strings.Replace(validInboundYAML, "30s", "1s", 1), wantErr: "maxIdleTimeout must be between 4s and 120s"},
		{name: "small stream window", yaml: strings.Replace(validInboundYAML, "      maxIdleTimeout: 30s", "      maxIdleTimeout: 30s\n      initStreamReceiveWindow: 1024", 1), wantErr: "initStreamReceiveWindow must be at least 16384"},
		{name: "few incoming streams", yaml: strings.Replace(validInboundYAML, "      maxIdleTimeout: 30s", "      maxIdleTimeout: 30s\n      maxIncomingStreams: 7", 1), wantErr: "maxIncomingStreams must be at least 8"},
		{name: "unknown subscription inbound", yaml: strings.Replace(validInboundYAML, "inbound: hy2-public", "inbound: missing", 1), wantErr: "references unknown inbound"},
		{name: "missing subscription address", yaml: strings.Replace(validInboundYAML, "  serverAddr: \"gateway.example.com:8443\"\n", "", 1), wantErr: "sub.serverAddr must be configured"},
		{name: "invalid subscription address", yaml: strings.Replace(validInboundYAML, "gateway.example.com:8443", "gateway.example.com", 1), wantErr: "sub.serverAddr is invalid"},
		{name: "wildcard subscription address", yaml: strings.Replace(validInboundYAML, "gateway.example.com:8443", ":8443", 1), wantErr: "must name a client-reachable host"},
		{name: "legacy subscription secret", yaml: strings.Replace(validInboundYAML, "  inbound: hy2-public", "  secret: forbidden\n  inbound: hy2-public", 1), wantErr: "field secret not found"},
		{name: "public admin", yaml: strings.Replace(validInboundYAML, "127.0.0.1:9090", ":9090", 1), wantErr: "admin.listen must use a loopback"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseInboundConfig([]byte(test.yaml))
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func TestParseInboundConfigTrojan(t *testing.T) {
	cfg, err := ParseInboundConfig([]byte(`
inbounds:
  - name: hy2
    type: hysteria2
    listen: ":443"
  - name: trojan
    type: trojan
    listen: ":443"
    trojan:
      handshakeTimeout: 10s
      maxPendingConnections: 128
tls:
  cert: cert.pem
  key: key.pem
`))
	if err != nil {
		t.Fatalf("ParseInboundConfig failed: %v", err)
	}
	if len(cfg.Inbounds) != 2 || cfg.Inbounds[1].Trojan == nil || cfg.Inbounds[1].Trojan.MaxPendingConnections != 128 {
		t.Fatalf("Trojan inbound was not preserved: %#v", cfg.Inbounds)
	}
}

func TestParseInboundConfigTrojanUDPIdleTimeout(t *testing.T) {
	template := `
inbounds:
  - name: trojan
    type: trojan
    listen: ":443"
    trojan:
      udpIdleTimeout: %s
tls:
  cert: cert.pem
  key: key.pem
`
	cfg, err := ParseInboundConfig([]byte(fmt.Sprintf(template, "90s")))
	if err != nil {
		t.Fatalf("ParseInboundConfig failed: %v", err)
	}
	if cfg.Inbounds[0].Trojan == nil || cfg.Inbounds[0].Trojan.UDPIdleTimeout != 90*time.Second {
		t.Fatalf("udpIdleTimeout was not preserved: %#v", cfg.Inbounds[0].Trojan)
	}
	for _, value := range []string{"-1s", "1s", "45m"} {
		if _, err := ParseInboundConfig([]byte(fmt.Sprintf(template, value))); err == nil {
			t.Fatalf("udpIdleTimeout %q was accepted", value)
		}
	}
}

func TestParseInboundConfigRejectsTrojanOptionsOnHysteria2(t *testing.T) {
	_, err := ParseInboundConfig([]byte(`
inbounds:
  - name: hy2
    type: hysteria2
    listen: ":443"
    trojan:
      udpIdleTimeout: 30s
tls:
  cert: cert.pem
  key: key.pem
`))
	if err == nil || !strings.Contains(err.Error(), "only valid for a trojan inbound") {
		t.Fatalf("cross-type option error = %v", err)
	}
}

func TestParseInboundConfigRejectsTrojanTCPConflict(t *testing.T) {
	_, err := ParseInboundConfig([]byte(`
inbounds:
  - name: trojan-one
    type: trojan
    listen: "127.0.0.1:443"
  - name: trojan-two
    type: trojan
    listen: "127.0.0.1:443"
tls:
  cert: cert.pem
  key: key.pem
`))
	if err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("Trojan TCP conflict error = %v", err)
	}
}

func TestParseInboundConfigRejectsDuplicateNamesAndListeners(t *testing.T) {
	base := `
inbounds:
  - name: first
    type: hysteria2
    listen: ":443"
  - name: %s
    type: hysteria2
    listen: %q
tls:
  cert: cert.pem
  key: key.pem
`
	for _, test := range []struct {
		name, secondName, secondListen, want string
	}{
		{name: "name", secondName: "first", secondListen: ":444", want: "duplicates"},
		{name: "wildcard listener", secondName: "second", secondListen: "127.0.0.1:443", want: "conflicts"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseInboundConfig([]byte(fmt.Sprintf(base, test.secondName, test.secondListen)))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestParseInboundConfigAllowsSamePortAcrossTransports(t *testing.T) {
	yamlText := strings.Replace(validInboundYAML, "127.0.0.1:9090", "127.0.0.1:8443", 1)
	if _, err := ParseInboundConfig([]byte(yamlText)); err != nil {
		t.Fatalf("UDP inbound and TCP admin listener may share a port: %v", err)
	}
}

func TestParseInboundConfigRejectsTCPListenerConflict(t *testing.T) {
	yamlText := strings.Replace(validInboundYAML, "127.0.0.1:9091", "127.0.0.1:9090", 1)
	_, err := ParseInboundConfig([]byte(yamlText))
	if err == nil || !strings.Contains(err.Error(), "sub.listen conflicts with admin.listen") {
		t.Fatalf("error = %v", err)
	}
}
