package e2e

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/clayicarus/proxy-gateway/internal/config"
	hyInbound "github.com/clayicarus/proxy-gateway/internal/inbound/hysteria2"
	"github.com/clayicarus/proxy-gateway/internal/policy"
	"go.uber.org/zap"
)

// TestHy2Masquerade_UnauthenticatedProbeSeesWebsite confirms that an active
// probe of the Hysteria2 inbound receives the configured website instead of any
// evidence of a proxy. Without masquerade the same probe must get the upstream
// 404 default.
func TestHy2Masquerade_UnauthenticatedProbeSeesWebsite(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Server", "nginx")
		_, _ = writer.Write([]byte("<html>my website</html>"))
	}))
	defer backend.Close()

	t.Run("with masquerade", func(t *testing.T) {
		address := startHy2Inbound(t, &config.InboundMasqueradeConfig{
			Type:  config.MasqueradeProxyType,
			Proxy: &config.MasqueradeProxyConfig{URL: backend.URL},
		})
		status, body, header := probeHTTP3(t, address)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200", status)
		}
		if body != "<html>my website</html>" {
			t.Fatalf("body = %q", body)
		}
		if got := header.Get("Server"); got != "nginx" {
			t.Fatalf("Server header = %q, want the backend value", got)
		}
		for key := range header {
			if containsFold(key, "hysteria") {
				t.Fatalf("probe response leaked header %q", key)
			}
		}
	})

	t.Run("without masquerade", func(t *testing.T) {
		address := startHy2Inbound(t, nil)
		status, _, _ := probeHTTP3(t, address)
		if status != http.StatusNotFound {
			t.Fatalf("status = %d, want the upstream 404 default", status)
		}
	})
}

func startHy2Inbound(t *testing.T, masquerade *config.InboundMasqueradeConfig) string {
	t.Helper()
	certificate, err := generateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	kernel := policy.New(map[string]config.UserConfig{
		"alice": {Password: "alice_pass", Routes: []string{"direct"}},
	}, nil, nil, zap.NewNop(), time.UTC)
	t.Cleanup(kernel.CloseOutbounds)
	service, err := hyInbound.NewService(config.Inbound{
		Name: "hy2-masq", Type: config.Hysteria2InboundType, Listen: "127.0.0.1:0", Masquerade: masquerade,
	}, certificate, kernel, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = service.Serve() }()
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Errorf("close hysteria2 inbound: %v", err)
		}
	})
	return service.Addr().String()
}

func probeHTTP3(t *testing.T, address string) (int, string, http.Header) {
	t.Helper()
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- self-signed test certificate
		Dial: func(ctx context.Context, _ string, tlsConfig *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
			return quic.DialAddrEarly(ctx, address, tlsConfig, quicConfig)
		},
	}
	t.Cleanup(func() { _ = transport.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// A probe uses an ordinary request, not the Hysteria2 authentication
	// endpoint, so the inbound must answer it as a web server.
	request := (&http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Scheme: "https", Host: "probe.example.com", Path: "/"},
		Header: make(http.Header),
	}).WithContext(ctx)
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatalf("probe round trip: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read probe body: %v", err)
	}
	return response.StatusCode, string(body), response.Header
}

func containsFold(value, substring string) bool {
	if len(substring) == 0 {
		return true
	}
	lower := func(b byte) byte {
		if b >= 'A' && b <= 'Z' {
			return b + ('a' - 'A')
		}
		return b
	}
	for i := 0; i+len(substring) <= len(value); i++ {
		match := true
		for j := 0; j < len(substring); j++ {
			if lower(value[i+j]) != lower(substring[j]) {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
