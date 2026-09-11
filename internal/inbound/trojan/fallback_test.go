package trojan

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/clayicarus/proxy-gateway/internal/config"
	"github.com/clayicarus/proxy-gateway/internal/policy"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func websiteOptions(address string) *config.TrojanInboundConfig {
	return &config.TrojanInboundConfig{Fallback: &config.TrojanFallbackConfig{
		Addr: address, ProbeTimeout: 100 * time.Millisecond,
		DialTimeout: 100 * time.Millisecond, Timeout: 2 * time.Second, MaxConnections: 4,
	}}
}

func assertNoProxyActivity(t *testing.T, kernel *policy.Kernel) {
	t.Helper()
	// Known users have zero-valued ledger entries even before any connection.
	snapshots := kernel.Traffic().GetAllSnapshots()
	stats := snapshots["alice:direct"]
	if len(snapshots) != 1 || stats == nil || stats.TxBytes != 0 || stats.RxBytes != 0 || stats.OnlineCount != 0 || stats.LastActive != 0 {
		t.Fatal("website traffic changed the proxy user ledger or online state")
	}
}

func readWebsiteResponse(t *testing.T, client net.Conn) (int, string) {
	t.Helper()
	if err := client.SetReadDeadline(time.Now().Add(4 * time.Second)); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("website response: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("website body: %v", err)
	}
	return response.StatusCode, string(body)
}

func startRawWebsite(t *testing.T, handler func(net.Conn)) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				handler(connection)
			}()
		}
	}()
	return listener.Addr().String()
}

func TestFallbackServesShortHTTPRequestAndNegotiatesHTTP1(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "<html>Field Notes</html>")
	}))
	defer backend.Close()
	service, kernel := startService(t, websiteOptions(backend.Listener.Addr().String()))
	client, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", service.Addr().String(), &tls.Config{
		InsecureSkipVerify: true, // #nosec G402 -- test fixture certificate
		NextProtos:         []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if client.ConnectionState().NegotiatedProtocol != "http/1.1" {
		t.Fatal("browser ALPN does not match the plaintext HTTP/1.1 backend")
	}
	started := time.Now()
	// This complete HTTP/1.0 request is shorter than the Trojan credential.
	if _, err := io.WriteString(client, "GET / HTTP/1.0\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	status, body := readWebsiteResponse(t, client)
	if status != http.StatusOK || body != "<html>Field Notes</html>" {
		t.Fatal("short HTTP request did not receive the configured website")
	}
	if time.Since(started) < 70*time.Millisecond {
		t.Fatal("incomplete credential did not use the common probe decision window")
	}
	assertNoProxyActivity(t, kernel)
}

func TestFallbackReplaysCredentialFailuresExactlyOnce(t *testing.T) {
	cases := []struct{ name, prefix string }{
		{"invalid hash", strings.Repeat("x", credentialLength) + "\r\n"},
		{"unknown hash", strings.Repeat("0", credentialLength) + "\r\n"},
		{"invalid delimiter", strings.Repeat("0", credentialLength) + "xx"},
		{"partial EOF", "abc123"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			received := make(chan []byte, 1)
			address := startRawWebsite(t, func(connection net.Conn) {
				data, _ := io.ReadAll(connection)
				received <- data
				_, _ = io.WriteString(connection, "origin-response")
			})
			service, kernel := startService(t, websiteOptions(address))
			client := dialService(t, service)
			if err := client.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
				t.Fatal(err)
			}
			payload := []byte(test.prefix)
			if test.name != "partial EOF" {
				payload = append(payload, bytes.Repeat([]byte("ordered-tail"), 4096)...)
			}
			started := time.Now()
			if _, err := client.Write(payload); err != nil {
				t.Fatal(err)
			}
			if err := client.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			response := make([]byte, len("origin-response"))
			if _, err := io.ReadFull(client, response); err != nil {
				t.Fatalf("origin response after client half-close: %v", err)
			}
			if string(response) != "origin-response" {
				t.Fatal("gateway substituted a response for the fixed backend")
			}
			if time.Since(started) < 70*time.Millisecond {
				t.Fatal("credential failure bypassed the common probe decision window")
			}
			select {
			case data := <-received:
				if !bytes.Equal(data, payload) {
					t.Fatal("consumed prefix or unread tail was lost, duplicated or reordered")
				}
			case <-time.After(time.Second):
				t.Fatal("origin did not receive the complete request")
			}
			assertNoProxyActivity(t, kernel)
		})
	}
}

func TestFallbackReplaysPartialReadAfterTimeout(t *testing.T) {
	connected := make(chan struct{})
	var once sync.Once
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "notes.example" || r.URL.Path != "/journal" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, "continued request")
	}))
	backend.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			once.Do(func() { close(connected) })
		}
	}
	backend.Start()
	defer backend.Close()
	service, _ := startService(t, websiteOptions(backend.Listener.Addr().String()))
	client := dialService(t, service)
	if _, err := io.WriteString(client, "GET "); err != nil {
		t.Fatal(err)
	}
	select {
	case <-connected:
	case <-time.After(2 * time.Second):
		t.Fatal("partial credential timeout did not enter fallback")
	}
	if _, err := io.WriteString(client, "/journal HTTP/1.1\r\nHost: notes.example\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	status, body := readWebsiteResponse(t, client)
	if status != http.StatusOK || body != "continued request" {
		t.Fatal("TLS read deadline recovery did not preserve the partial request")
	}
}

func TestFallbackUsesFixedBackend(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "fixed origin")
	}))
	defer backend.Close()
	service, _ := startService(t, websiteOptions(backend.Listener.Addr().String()))
	client := dialService(t, service)
	if _, err := io.WriteString(client, "GET http://unrelated.invalid/path HTTP/1.1\r\nHost: unrelated.invalid\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	status, body := readWebsiteResponse(t, client)
	if status != http.StatusOK || body != "fixed origin" {
		t.Fatal("request-selected host affected fallback destination")
	}
}

func TestFallbackDoesNotHandleAuthenticatedInvalidCommands(t *testing.T) {
	var connections atomic.Int32
	address := startRawWebsite(t, func(connection net.Conn) {
		connections.Add(1)
		_, _ = io.Copy(io.Discard, connection)
	})
	service, kernel := startService(t, websiteOptions(address))
	client := dialService(t, service)
	request := append(trojanCredentialHeader(t, "alice", "direct", "secret"), 0x02, addressIPv4)
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("authenticated unsupported command was accepted")
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	if connections.Load() != 0 {
		t.Fatal("authenticated invalid command reached the website")
	}
	assertNoProxyActivity(t, kernel)
}

func TestFallbackPreservesAuthenticatedRequestDeadline(t *testing.T) {
	backend := httptest.NewServer(http.NotFoundHandler())
	defer backend.Close()
	options := websiteOptions(backend.Listener.Addr().String())
	options.HandshakeTimeout = 2 * time.Second
	options.Fallback.ProbeTimeout = 50 * time.Millisecond
	service, _ := startService(t, options)
	client := dialService(t, service)
	if _, err := client.Write(trojanCredentialHeader(t, "alice", "direct", "secret")); err != nil {
		t.Fatal(err)
	}
	// The credential arrives in time; the command may use the remaining budget.
	time.Sleep(150 * time.Millisecond)
	payload := []byte("command after the probe window")
	request := trojanConnectRequest(t, "alice", "direct", "secret", startEchoServer(t), payload)
	if _, err := client.Write(request[credentialLength+2:]); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(client, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("valid client lost its original request deadline: %v", err)
	}
}

func TestFallbackCapacityIsSeparateFromAuthenticatedConnections(t *testing.T) {
	accepted := make(chan struct{}, 2)
	address := startRawWebsite(t, func(connection net.Conn) {
		accepted <- struct{}{}
		_, _ = io.Copy(io.Discard, connection)
	})
	options := websiteOptions(address)
	options.MaxPendingConnections = 1
	options.Fallback.MaxConnections = 1
	service, kernel := startService(t, options)
	first := dialService(t, service)
	if _, err := io.WriteString(first, strings.Repeat("x", credentialLength)+"\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("first website connection was not established")
	}
	second := dialService(t, service)
	if _, err := io.WriteString(second, strings.Repeat("x", credentialLength)+"\r\n"); err != nil {
		t.Fatal(err)
	}
	if err := second.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Read(make([]byte, 1)); err == nil {
		t.Fatal("website connection limit was ignored")
	}
	valid := dialService(t, service)
	payload := []byte("authenticated traffic")
	if _, err := valid.Write(trojanConnectRequest(t, "alice", "direct", "secret", startEchoServer(t), payload)); err != nil {
		t.Fatal(err)
	}
	if err := valid.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(valid, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("authenticated connection was blocked by website capacity: %v", err)
	}
	stats := kernel.Traffic().GetSnapshot("alice:direct")
	if stats == nil || stats.TxBytes != uint64(len(payload)) || stats.RxBytes != uint64(len(payload)) {
		t.Fatal("website traffic contaminated authenticated accounting")
	}
	select {
	case <-accepted:
		t.Fatal("website capacity created an extra origin connection")
	default:
	}
}

func TestFallbackLifetimeAndShutdown(t *testing.T) {
	for _, mode := range []string{"timeout", "shutdown", "pending probe shutdown"} {
		t.Run(mode, func(t *testing.T) {
			accepted, closed := make(chan struct{}), make(chan struct{})
			address := startRawWebsite(t, func(connection net.Conn) {
				close(accepted)
				_, _ = io.Copy(io.Discard, connection)
				close(closed)
			})
			options := websiteOptions(address)
			options.Fallback.Timeout = time.Second
			if mode == "pending probe shutdown" {
				options.Fallback.ProbeTimeout = 10 * time.Second
			}
			service, _ := startService(t, options)
			client := dialService(t, service)
			if _, err := io.WriteString(client, strings.Repeat("x", credentialLength)+"\r\n"); err != nil {
				t.Fatal(err)
			}
			if mode == "pending probe shutdown" {
				deadline := time.Now().Add(time.Second)
				for len(service.fallback.slots) == 0 && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
				}
				if len(service.fallback.slots) == 0 {
					t.Fatal("probe did not enter the bounded classification wait")
				}
			} else {
				select {
				case <-accepted:
				case <-time.After(2 * time.Second):
					t.Fatal("origin connection was not established")
				}
			}
			if mode != "timeout" {
				done := make(chan error, 1)
				go func() { done <- service.Close() }()
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("shutdown waited for the website/probe deadline")
				}
			}
			if err := client.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := client.Read(make([]byte, 1)); err == nil {
				t.Fatal("website connection survived timeout or shutdown")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := service.Wait(ctx); err != nil {
				t.Fatalf("website handler did not drain: %v", err)
			}
			if mode != "pending probe shutdown" {
				select {
				case <-closed:
				case <-time.After(time.Second):
					t.Fatal("website backend connection was left open")
				}
			}
		})
	}
}

func TestFallbackUnavailableBackendDoesNotExposeProbeData(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	core, logs := observer.New(zap.DebugLevel)
	service, _ := startServiceWithLogger(t, websiteOptions(address), zap.New(core))
	client := dialService(t, service)
	marker := "probe-content-must-not-be-logged"
	payload := strings.Repeat("0", credentialLength) + "\r\n" + marker
	if _, err := io.WriteString(client, payload); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(client)
	if len(body) != 0 {
		t.Fatal("unavailable origin exposed a gateway-generated response")
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(logs.AllUntimed())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(marker)) || bytes.Contains(encoded, []byte(strings.Repeat("0", credentialLength))) {
		t.Fatal("fallback logs exposed credential or probe bytes")
	}
	if logs.FilterMessage("Trojan website backend unavailable").Len() != 1 {
		t.Fatal("origin failure did not produce the expected sanitized diagnostic")
	}
}
