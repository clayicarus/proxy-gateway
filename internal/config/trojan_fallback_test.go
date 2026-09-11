package config

import (
	"strings"
	"testing"
	"time"
)

const fallbackYAML = `inbounds:
  - name: trojan
    type: trojan
    listen: :443
    trojan:
      fallback:
        addr: 127.0.0.1:8080
tls:
  cert: cert.pem
  key: key.pem
`

func TestTrojanFallbackConfiguration(t *testing.T) {
	cfg, err := ParseInboundConfig([]byte(fallbackYAML))
	if err != nil {
		t.Fatal(err)
	}
	fallback, err := cfg.Inbounds[0].Trojan.Fallback.WithDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if fallback.Addr != "127.0.0.1:8080" || fallback.ProbeTimeout != time.Second || fallback.DialTimeout != 3*time.Second || fallback.Timeout != 30*time.Second || fallback.MaxConnections != 32 {
		t.Fatal("website fallback defaults do not match the documented contract")
	}
	cfg, err = ParseInboundConfig([]byte(strings.Replace(fallbackYAML, "        addr: 127.0.0.1:8080", `        addr: "[::1]:8080"
        probeTimeout: 250ms
        dialTimeout: 2s
        timeout: 45s
        maxConnections: 8`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	fallback, err = cfg.Inbounds[0].Trojan.Fallback.WithDefaults()
	if err != nil || fallback.Addr != "[::1]:8080" || fallback.ProbeTimeout != 250*time.Millisecond || fallback.DialTimeout != 2*time.Second || fallback.Timeout != 45*time.Second || fallback.MaxConnections != 8 {
		t.Fatal("explicit fallback address or resource limits were lost")
	}
}

func TestTrojanFallbackRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct{ name, replacement, want string }{
		{"missing address", "        timeout: 30s", "fallback.addr must be configured"},
		{"wildcard", "        addr: ':8080'", "fixed backend host"},
		{"IPv6 wildcard", "        addr: '[::]:8080'", "fixed backend host"},
		{"zero port", "        addr: '127.0.0.1:0'", "port between"},
		{"URL instead of address", "        addr: 'http://127.0.0.1:8080'", "fallback.addr is invalid"},
		{"invalid host", "        addr: 'bad host:8080'", "fixed backend host"},
		{"negative probe timeout", "        addr: localhost:8080\n        probeTimeout: -1s", "fallback.probeTimeout"},
		{"long probe timeout", "        addr: localhost:8080\n        probeTimeout: 11s", "fallback.probeTimeout"},
		{"negative dial timeout", "        addr: localhost:8080\n        dialTimeout: -1s", "fallback.dialTimeout"},
		{"long dial timeout", "        addr: localhost:8080\n        dialTimeout: 31s", "fallback.dialTimeout"},
		{"short lifetime", "        addr: localhost:8080\n        timeout: 100ms", "fallback.timeout"},
		{"long lifetime", "        addr: localhost:8080\n        timeout: 11m", "fallback.timeout"},
		{"negative capacity", "        addr: localhost:8080\n        maxConnections: -1", "fallback.maxConnections"},
		{"large capacity", "        addr: localhost:8080\n        maxConnections: 65536", "fallback.maxConnections"},
		{"unknown field", "        addr: localhost:8080\n        upstreamFromHost: true", "field upstreamFromHost not found"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := strings.Replace(fallbackYAML, "        addr: 127.0.0.1:8080", test.replacement, 1)
			_, err := ParseInboundConfig([]byte(input))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
	if _, err := ParseInboundConfig([]byte(strings.Replace(fallbackYAML, "type: trojan", "type: hysteria2", 1))); err == nil {
		t.Fatal("Trojan fallback settings were accepted on a Hysteria2 inbound")
	}
}
