package config

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

const subscriptionInboundYAML = `inbounds:
  - name: hy2
    type: hysteria2
    listen: ":8443"
  - name: trojan
    type: trojan
    listen: ":9443"
tls:
  cert: cert.pem
  key: key.pem
sub:
`

func TestLoadRuntimeTrojanSubscription(t *testing.T) {
	// A deployment can publish Trojan without enabling a Hysteria2 listener.
	yamlText := strings.Replace(subscriptionInboundYAML, "  - name: hy2\n    type: hysteria2\n    listen: \":8443\"\n", "", 1) + `  inbound: trojan
  serverAddr: "trojan.example:443"
  sni: "tls.example"
`
	path := t.TempDir() + "/gateway.yaml"
	if err := os.WriteFile(path, []byte(yamlText), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadRuntime(path)
	if err != nil {
		t.Fatalf("Trojan-only subscription was rejected: %v", err)
	}
	want := []SubscriptionEndpoint{{Inbound: "trojan", ServerAddr: "trojan.example:443", SNI: "tls.example"}}
	if cfg.Listen != ":9443" || !reflect.DeepEqual(cfg.Sub.ClientEndpoints(), want) {
		t.Fatal("single Trojan subscription settings were not preserved")
	}
}

func TestLoadRuntimeMixedSubscription(t *testing.T) {
	yamlText := subscriptionInboundYAML + `  listen: "127.0.0.1:9091"
  publicURL: "https://sub.example/sub/"
  endpoints:
    - inbound: trojan
      serverAddr: "[2001:db8::1]:443"
      sni: trojan.example
      insecure: true
    - inbound: hy2
      serverAddr: "hy2.example:10443"
      sni: hy2.example
`
	path := t.TempDir() + "/gateway.yaml"
	if err := os.WriteFile(path, []byte(yamlText), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadRuntime(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []SubscriptionEndpoint{
		{Inbound: "trojan", ServerAddr: "[2001:db8::1]:443", SNI: "trojan.example", Insecure: true},
		{Inbound: "hy2", ServerAddr: "hy2.example:10443", SNI: "hy2.example"},
	}
	if cfg.Listen != ":9443" || cfg.Sub.Listen != "127.0.0.1:9091" || cfg.Sub.PublicURL != "https://sub.example/sub/" || !reflect.DeepEqual(cfg.Sub.ClientEndpoints(), want) {
		t.Fatal("published endpoints or subscription listener settings were lost")
	}
}

func TestParseInboundConfigRejectsInvalidSubscriptionEndpoints(t *testing.T) {
	valid := "  endpoints:\n    - inbound: trojan\n      serverAddr: 'trojan.example:443'\n"
	tests := []struct {
		name string
		sub  string
		want string
	}{
		{"empty endpoints", "  endpoints: []\n", "must contain at least one item"},
		{"mixed syntax", "  inbound: hy2\n" + valid, "cannot be combined"},
		{"shared address", "  serverAddr: hy2.example:443\n" + valid, "cannot be combined"},
		{"shared SNI", "  sni: shared.example\n" + valid, "cannot be combined"},
		{"shared insecure", "  insecure: true\n" + valid, "cannot be combined"},
		{"explicit default insecure", "  insecure: false\n" + valid, "cannot be combined"},
		{"explicit empty SNI", "  sni: ''\n" + valid, "cannot be combined"},
		{"explicit null address", "  serverAddr: null\n" + valid, "cannot be combined"},
		{"missing binding", strings.Replace(valid, "    - inbound: trojan\n      ", "    - ", 1), "sub.endpoints[0].inbound must be configured"},
		{"unknown binding", strings.Replace(valid, "inbound: trojan", "inbound: missing", 1), "references unknown inbound"},
		{"duplicate binding", valid + "    - inbound: trojan\n      serverAddr: other.example:443\n", "duplicates subscription inbound"},
		{"missing address", "  endpoints:\n    - inbound: trojan\n", "sub.endpoints[0].serverAddr must be configured"},
		{"missing port", strings.Replace(valid, "trojan.example:443", "trojan.example", 1), "serverAddr is invalid"},
		{"zero port", strings.Replace(valid, "trojan.example:443", "trojan.example:0", 1), "port between 1 and 65535"},
		{"oversized port", strings.Replace(valid, "trojan.example:443", "trojan.example:65536", 1), "port between 1 and 65535"},
		{"unspecified host", strings.Replace(valid, "trojan.example:443", ":443", 1), "client-reachable host"},
		{"IPv4 wildcard", strings.Replace(valid, "trojan.example:443", "0.0.0.0:443", 1), "client-reachable host"},
		{"IPv6 wildcard", strings.Replace(valid, "trojan.example:443", "[::]:443", 1), "client-reachable host"},
		{"unknown field", valid + "      protocol: trojan\n", "field protocol not found"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseInboundConfig([]byte(subscriptionInboundYAML + test.sub))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestMigrateLegacyTrojanSubscription(t *testing.T) {
	result, err := MigrateLegacyInbounds([]byte(`listen: :8443
trojan:
  listen: :9443
  serverAddr: trojan.example:443
  sni: trojan-tls.example
  insecure: true
tls:
  cert: cert.pem
  key: key.pem
sub:
  listen: 127.0.0.1:9091
  publicURL: https://sub.example/sub/
  serverAddr: hy2.example:10443
  sni: hy2-tls.example
`))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseInboundConfig(result.YAML)
	if err != nil {
		t.Fatal(err)
	}
	want := []SubscriptionEndpoint{
		{Inbound: "hy2-public", ServerAddr: "hy2.example:10443", SNI: "hy2-tls.example"},
		{Inbound: "trojan-public", ServerAddr: "trojan.example:443", SNI: "trojan-tls.example", Insecure: true},
	}
	if cfg.Sub == nil || cfg.Sub.Listen != "127.0.0.1:9091" || cfg.Sub.PublicURL != "https://sub.example/sub/" || !reflect.DeepEqual(cfg.Sub.Endpoints, want) {
		t.Fatal("migration discarded public addresses, TLS metadata or subscription settings")
	}
	if len(result.Diagnostics) != 1 || !strings.Contains(result.Diagnostics[0], "now publishes both") {
		t.Fatal("migration did not explain the newly published Trojan endpoint")
	}
}

func TestMigrateLegacyTrojanSubscriptionRequiresPublicAddress(t *testing.T) {
	_, err := MigrateLegacyInbounds([]byte(`listen: :8443
trojan:
  listen: :9443
  sni: trojan.example
tls:
  cert: cert.pem
  key: key.pem
sub:
  serverAddr: hy2.example:443
`))
	if err == nil || !strings.Contains(err.Error(), "trojan.serverAddr must be configured") {
		t.Fatalf("ambiguous Trojan subscription metadata error = %v", err)
	}
}
