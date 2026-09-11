package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	hyClient "github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/clayicarus/proxy-gateway/internal/api"
	"github.com/clayicarus/proxy-gateway/internal/config"
	hyInbound "github.com/clayicarus/proxy-gateway/internal/inbound/hysteria2"
	"github.com/clayicarus/proxy-gateway/internal/inbound/trojan"
	"github.com/clayicarus/proxy-gateway/internal/policy"
	"github.com/clayicarus/proxy-gateway/internal/storage"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// This client-side shape deliberately uses Clash field names independently of
// the subscription renderer, so an incorrect YAML tag cannot pass unnoticed.
type subscriptionClientProxy struct {
	Type       string   `yaml:"type"`
	Server     string   `yaml:"server"`
	Port       int      `yaml:"port"`
	Password   string   `yaml:"password"`
	SNI        string   `yaml:"sni"`
	SkipVerify bool     `yaml:"skip-cert-verify"`
	UDP        bool     `yaml:"udp"`
	ALPN       []string `yaml:"alpn"`
}

func (p subscriptionClientProxy) address() string {
	return net.JoinHostPort(p.Server, strconv.Itoa(p.Port))
}

// TestSubscriptionConnectsToPublishedInbounds exercises runtime YAML -> SQLite
// token -> HTTP subscription -> client authentication -> TCP/UDP payloads.
func TestSubscriptionConnectsToPublishedInbounds(t *testing.T) {
	for _, website := range []bool{false, true} {
		t.Run(fmt.Sprintf("website_%t", website), func(t *testing.T) {
			testSubscriptionConnectsToPublishedInbounds(t, website)
		})
	}
}

func testSubscriptionConnectsToPublishedInbounds(t *testing.T, website bool) {
	logger := zap.NewNop()
	store, err := storage.NewSQLiteStore(t.TempDir()+"/managed.db", logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	const password = "test:password:with:colons"
	if err := store.CreateUser(storage.ManagedUserInput{Username: "alice", Password: password, Routes: []string{"direct"}}, "test-subscription-token"); err != nil {
		t.Fatal(err)
	}
	users := map[string]config.UserConfig{"alice": {Password: password, Routes: []string{"direct"}}}
	kernel := policy.New(users, nil, nil, logger, time.UTC)
	t.Cleanup(kernel.CloseOutbounds)
	certificate, err := generateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)

	var siteBody []byte
	var originMux *http.ServeMux
	hyOptions, trojanOptions := "", ""
	if website {
		siteDir := filepath.Join("..", "..", "configs", "masquerade-site")
		siteBody, err = os.ReadFile(filepath.Join(siteDir, "index.html"))
		if err != nil {
			t.Fatal(err)
		}
		originMux = http.NewServeMux()
		originMux.Handle("/", http.FileServer(http.Dir(siteDir)))
		origin := httptest.NewServer(originMux)
		t.Cleanup(origin.Close)
		hyOptions = fmt.Sprintf("    masquerade:\n      type: proxy\n      proxy:\n        url: %s\n", origin.URL)
		trojanOptions = fmt.Sprintf("    trojan:\n      fallback:\n        addr: %s\n        probeTimeout: 100ms\n", origin.Listener.Addr())
	}
	yamlText := fmt.Sprintf(`inbounds:
  - name: hy2-public
    type: hysteria2
    listen: 127.0.0.1:443
%s  - name: trojan-public
    type: trojan
    listen: 127.0.0.1:443
%stls:
  cert: fixture-cert.pem
  key: fixture-key.pem
sub:
  endpoints:
    - inbound: hy2-public
      serverAddr: 127.0.0.1:443
      sni: localhost
    - inbound: trojan-public
      serverAddr: 127.0.0.1:443
      sni: localhost
`, hyOptions, trojanOptions)
	path := t.TempDir() + "/gateway.yaml"
	if err := os.WriteFile(path, []byte(yamlText), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadRuntime(path)
	if err != nil {
		t.Fatal(err)
	}
	// Keep protocol options from runtime YAML while binding isolated test ports.
	cfg.Inbounds[0].Listen = "127.0.0.1:0"
	cfg.Inbounds[1].Listen = "127.0.0.1:0"
	hyService, err := hyInbound.NewService(cfg.Inbounds[0], certificate, kernel, logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hyService.Close() })
	trojanService, err := trojan.NewService(cfg.Inbounds[1], certificate, kernel, logger)
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range []interface {
		Serve() error
		Close() error
	}{hyService, trojanService} {
		done := make(chan error, 1)
		go func() { done <- service.Serve() }()
		t.Cleanup(func() {
			if err := service.Close(); err != nil {
				t.Errorf("close inbound: %v", err)
			}
			select {
			case err := <-done:
				if err != nil && !errors.Is(err, quic.ErrServerClosed) {
					t.Errorf("inbound Serve: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Error("inbound did not stop")
			}
		})
	}

	cfg.Inbounds[0].Listen = hyService.Addr().String()
	cfg.Inbounds[1].Listen = trojanService.Addr().String()
	cfg.Sub.Endpoints[0].ServerAddr = hyService.Addr().String()
	cfg.Sub.Endpoints[1].ServerAddr = trojanService.Addr().String()
	subHandler := api.NewDatabaseSubscriptionHandler(cfg, store, users, nil, logger).Handler()
	subServer := httptest.NewServer(subHandler)
	t.Cleanup(subServer.Close)
	httpClient := &http.Client{Timeout: 5 * time.Second}
	subURL := subServer.URL + "/sub/test-subscription-token"
	if website {
		// The sample HTTP origin also forwards /sub/ to the subscription service.
		originMux.Handle("/sub/", subHandler)
		transport := &http.Transport{TLSClientConfig: &tls.Config{ServerName: "localhost", RootCAs: roots}, ForceAttemptHTTP2: true}
		t.Cleanup(transport.CloseIdleConnections)
		httpClient.Transport = transport
		subURL = "https://" + trojanService.Addr().String() + "/sub/test-subscription-token"
	}
	response, err := httpClient.Get(subURL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("subscription status = %d", response.StatusCode)
	}
	var subscription struct {
		Proxies []subscriptionClientProxy `yaml:"proxies"`
	}
	if err := yaml.NewDecoder(response.Body).Decode(&subscription); err != nil {
		t.Fatal(err)
	}
	if len(subscription.Proxies) != 2 || subscription.Proxies[0].Type != "hysteria2" || subscription.Proxies[1].Type != "trojan" {
		t.Fatal("subscription must publish both configured protocols")
	}
	for _, proxy := range subscription.Proxies {
		if proxy.SNI != "localhost" || proxy.SkipVerify {
			t.Fatal("subscription lost the explicit TLS name or enabled insecure verification")
		}
	}
	if website {
		checkSite := func(t *testing.T, client *http.Client, address, alpn string) {
			t.Helper()
			response, err := client.Get("https://" + address + "/")
			if err != nil {
				t.Fatalf("ordinary website request: %v", err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || response.StatusCode != http.StatusOK || !bytes.Equal(body, siteBody) {
				t.Fatalf("configured website was not served: status %d, error %v", response.StatusCode, err)
			}
			if response.TLS == nil || response.TLS.NegotiatedProtocol != alpn {
				t.Fatal("website negotiated the wrong application protocol")
			}
			stats := kernel.Traffic().GetSnapshot("alice:direct")
			if stats == nil || stats.TxBytes != 0 || stats.RxBytes != 0 || stats.OnlineCount != 0 || stats.LastActive != 0 {
				t.Fatal("anonymous website visit changed the proxy user's ledger")
			}
		}
		t.Run("https_website", func(t *testing.T) {
			transport := &http.Transport{
				TLSClientConfig:   &tls.Config{ServerName: "localhost", RootCAs: roots},
				ForceAttemptHTTP2: true,
			}
			defer transport.CloseIdleConnections()
			checkSite(t, &http.Client{Transport: transport, Timeout: 5 * time.Second}, trojanService.Addr().String(), "http/1.1")
		})
		t.Run("http3_website", func(t *testing.T) {
			transport := &http3.Transport{TLSClientConfig: &tls.Config{ServerName: "localhost", RootCAs: roots}}
			defer transport.Close()
			checkSite(t, &http.Client{Transport: transport, Timeout: 5 * time.Second}, hyService.Addr().String(), "h3")
		})
	}
	tcpTarget, udpTarget := startTCPEcho(t), startUDPEcho(t)
	payload := []byte("subscription client payload")

	t.Run("hysteria2_tcp", func(t *testing.T) {
		proxy := subscription.Proxies[0]
		address, err := net.ResolveUDPAddr("udp", proxy.address())
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		client, _, err := hyClient.NewClientContext(ctx, &hyClient.Config{
			ServerAddr: address, Auth: proxy.Password,
			TLSConfig: hyClient.TLSConfig{ServerName: proxy.SNI, RootCAs: roots},
		})
		if err != nil {
			t.Fatalf("connect using published Hysteria2 endpoint: %v", err)
		}
		defer client.Close()
		connection, err := client.TCPContext(ctx, tcpTarget)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := connection.Write(payload); err != nil {
			t.Fatal(err)
		}
		assertSubscriptionEcho(t, connection, payload)
	})

	trojanProxy := subscription.Proxies[1]
	if website {
		if len(trojanProxy.ALPN) != 1 || trojanProxy.ALPN[0] != "http/1.1" {
			t.Fatal("website-enabled Trojan subscription is missing its ALPN policy")
		}
	} else if len(trojanProxy.ALPN) != 0 {
		t.Fatal("ordinary Trojan subscription unexpectedly forced website ALPN")
	}
	digest := sha256.Sum224([]byte(trojanProxy.Password))
	credential := []byte(hex.EncodeToString(digest[:]) + "\r\n")
	dial := func(t *testing.T) *tls.Conn {
		t.Helper()
		connection, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", trojanProxy.address(), &tls.Config{
			ServerName: trojanProxy.SNI, RootCAs: roots, MinVersion: tls.VersionTLS12, NextProtos: trojanProxy.ALPN,
		})
		if err != nil {
			t.Fatalf("connect using published Trojan endpoint: %v", err)
		}
		t.Cleanup(func() { _ = connection.Close() })
		if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		return connection
	}
	t.Run("trojan_tcp", func(t *testing.T) {
		connection := dial(t)
		request := append(append([]byte(nil), credential...), 0x01)
		request = append(request, encodeIPv4Address(t, tcpTarget)...)
		request = append(request, '\r', '\n')
		if _, err := connection.Write(append(request, payload...)); err != nil {
			t.Fatal(err)
		}
		assertSubscriptionEcho(t, connection, payload)
	})
	t.Run("trojan_udp", func(t *testing.T) {
		if !trojanProxy.UDP {
			t.Fatal("Trojan subscription did not enable the supported UDP transport")
		}
		connection := dial(t)
		request := append(append([]byte(nil), credential...), 0x03, 0x01, 0, 0, 0, 0, 0, 0, '\r', '\n')
		address := encodeIPv4Address(t, udpTarget)
		request = append(request, address...)
		request = binary.BigEndian.AppendUint16(request, uint16(len(payload)))
		request = append(request, '\r', '\n')
		if _, err := connection.Write(append(request, payload...)); err != nil {
			t.Fatal(err)
		}
		// Parse the wire frame independently of the server's packet reader.
		header := make([]byte, len(address)+4)
		if _, err := io.ReadFull(connection, header); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(header[:len(address)], address) || int(binary.BigEndian.Uint16(header[len(address):])) != len(payload) || !bytes.Equal(header[len(address)+2:], []byte("\r\n")) {
			t.Fatal("invalid UDP response address or framing")
		}
		assertSubscriptionEcho(t, connection, payload)
	})
}

func assertSubscriptionEcho(t *testing.T, reader io.Reader, payload []byte) {
	t.Helper()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatalf("read payload through subscription proxy: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("proxy did not return the expected payload")
	}
}
