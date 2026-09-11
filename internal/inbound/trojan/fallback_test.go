package trojan

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
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
		DialTimeout: 100 * time.Millisecond, IdleTimeout: 2 * time.Second, MaxConnections: 4,
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
	if len(kernel.Tracker().Snapshots()) != 0 {
		t.Fatal("website traffic created a tracked proxy connection or request")
	}
}

func assertNoProxySessionIssued(t *testing.T, kernel *policy.Kernel) {
	t.Helper()
	// The next capability must still be the first one issued by this kernel.
	session, ok := kernel.AuthenticateTrojan("fallback-check", &net.TCPAddr{}, HashPassword(RawPassword("alice", "direct", "secret")))
	if !ok || session.ID() != "fallback-check/1" {
		t.Fatal("initial fallback traffic obtained a user proxy session")
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
	// This complete HTTP/1.0 request is shorter than the Trojan credential.
	if _, err := io.WriteString(client, "GET / HTTP/1.0\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	status, body := readWebsiteResponse(t, client)
	if status != http.StatusOK || body != "<html>Field Notes</html>" {
		t.Fatal("short HTTP request did not receive the configured website")
	}
	assertNoProxyActivity(t, kernel)
}

// Once a first flight is long enough to classify, the gateway must forward it
// without waiting out the probe window: every outcome is answered by the origin,
// so a gateway-side delay would only add latency to real page loads. An ordinary
// browser request exceeds the credential length, so it is classified on arrival.
// The probe timeout here is far larger than the assertion window, so a
// reintroduced wait fails the test instead of merely slowing it down.
func TestFallbackForwardsClassifiedRequestWithoutProbeWindowDelay(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "<html>Field Notes</html>")
	}))
	defer backend.Close()
	options := websiteOptions(backend.Listener.Addr().String())
	options.HandshakeTimeout = 30 * time.Second
	options.Fallback.ProbeTimeout = 10 * time.Second
	service, kernel := startService(t, options)
	client := dialService(t, service)
	if err := client.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	request := "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
	if len(request) <= credentialLength {
		t.Fatalf("test request of %d bytes cannot be classified on arrival", len(request))
	}
	started := time.Now()
	if _, err := io.WriteString(client, request); err != nil {
		t.Fatal(err)
	}
	status, body := readWebsiteResponse(t, client)
	if status != http.StatusOK || body != "<html>Field Notes</html>" {
		t.Fatal("website request was not served")
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("website response took %v; the gateway added a probe-window delay", elapsed)
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
			payload := []byte(test.prefix)
			if test.name != "partial EOF" {
				payload = append(payload, bytes.Repeat([]byte("ordered-tail"), 4096)...)
			}
			assertFallbackReplay(t, payload)
		})
	}
}

func assertFallbackReplay(t *testing.T, payload []byte) {
	t.Helper()
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
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	assertOriginReplay(t, client, received, payload)
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	assertNoProxyActivity(t, kernel)
	assertNoProxySessionIssued(t, kernel)
}

func assertOriginReplay(t *testing.T, client *tls.Conn, received <-chan []byte, payload []byte) {
	t.Helper()
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("origin response after client half-close: %v", err)
	}
	if string(response) != "origin-response" {
		t.Fatal("gateway substituted a response for the fixed backend")
	}
	select {
	case data := <-received:
		if !bytes.Equal(data, payload) {
			t.Fatal("consumed prefix or unread tail was lost, duplicated or reordered")
		}
	case <-time.After(time.Second):
		t.Fatal("origin did not receive the complete request")
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

func TestFallbackReplaysMalformedRequestsWithValidCredentials(t *testing.T) {
	ipv4 := []byte{commandConnect, addressIPv4, 127, 0, 0, 1, 0, 80, '\r', '\n'}
	ipv6 := append([]byte{commandConnect, addressIPv6}, net.IPv6loopback.To16()...)
	ipv6 = append(ipv6, 0, 80, '\r', '\n')
	longDomain := append([]byte{commandConnect, addressDomain, 255}, bytes.Repeat([]byte{'a'}, 255)...)
	longDomain = append(longDomain, 0, 80, '\r', 'x')
	cases := []struct {
		name      string
		header    []byte
		truncated bool
	}{
		{"BIND", []byte{0x02, addressIPv4}, false},
		{"unknown command", []byte{0x07, addressIPv4}, false},
		{"unknown address type", []byte{commandConnect, 0x05}, false},
		{"empty domain", []byte{commandConnect, addressDomain, 0}, false},
		{"bad IPv4 delimiter", append(append([]byte{}, ipv4[:8]...), '\n', '\n'), false},
		{"bad IPv6 delimiter", append(append([]byte{}, ipv6[:20]...), '\r', 'x'), false},
		{"bad domain delimiter", []byte{commandConnect, addressDomain, 1, 'a', 0, 80, '\n', '\n'}, false},
		{"maximum header", longDomain, false},
		{"missing command", nil, true},
		{"missing address type", ipv4[:1], true},
		{"partial IPv4", ipv4[:5], true},
		{"partial IPv6", ipv6[:17], true},
		{"missing domain length", []byte{commandConnect, addressDomain}, true},
		{"partial domain", []byte{commandConnect, addressDomain, 5, 'a', 'b'}, true},
		{"missing port", ipv4[:6], true},
		{"partial port", ipv4[:7], true},
		{"missing delimiter", ipv4[:8], true},
		{"partial delimiter", ipv4[:9], true},
		{"zero port with bad delimiter", []byte{commandConnect, addressIPv4, 127, 0, 0, 1, 0, 0, '\n', '\n'}, false},
		{"forbidden domain with bad delimiter", []byte{commandConnect, addressDomain, 3, 'a', ':', 'b', 0, 80, '\n', '\n'}, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			payload := append(trojanCredentialHeader(t, "alice", "direct", "secret"), test.header...)
			if !test.truncated {
				payload = append(payload, bytes.Repeat([]byte("ordered-tail"), 4096)...)
			}
			assertFallbackReplay(t, payload)
		})
	}
}

func TestFallbackReplaysCompleteRequestsWithUnknownCredentials(t *testing.T) {
	longest := append([]byte{commandConnect, addressDomain, 255}, bytes.Repeat([]byte{'a'}, 255)...)
	longest = append(longest, 0, 80, '\r', '\n')
	cases := []struct {
		name   string
		header []byte
	}{
		{"maximum header", longest},
		{"zero port", []byte{commandConnect, addressIPv4, 127, 0, 0, 1, 0, 0, '\r', '\n'}},
		{"forbidden domain", []byte{commandConnect, addressDomain, 3, 'a', ':', 'b', 0, 80, '\r', '\n'}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			payload := append(trojanCredentialHeader(t, "alice", "direct", "wrong"), test.header...)
			payload = append(payload, bytes.Repeat([]byte("unread-payload"), 4096)...)
			assertFallbackReplay(t, payload)
		})
	}
}

func TestFallbackReplaysRequestRemainderAfterTimeout(t *testing.T) {
	cases := []struct {
		name              string
		headerBytes       int
		handshakeDeadline bool
	}{
		{"missing command", 0, false},
		{"partial command", 1, false},
		{"partial address", 5, false},
		{"partial delimiter", 9, false},
		{"bounded by handshake", 5, true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			connected := make(chan struct{})
			received := make(chan []byte, 1)
			address := startRawWebsite(t, func(connection net.Conn) {
				close(connected)
				data, _ := io.ReadAll(connection)
				received <- data
				_, _ = io.WriteString(connection, "origin-response")
			})
			options := websiteOptions(address)
			options.HandshakeTimeout = 2 * time.Second
			if test.handshakeDeadline {
				options.HandshakeTimeout = 500 * time.Millisecond
				options.Fallback.ProbeTimeout = 2 * time.Second
			}
			service, kernel := startService(t, options)
			client := dialService(t, service)
			if err := client.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
				t.Fatal(err)
			}
			// A late but otherwise valid request must remain website traffic
			// after classification, including all bytes read before timeout.
			payload := trojanConnectRequest(t, "alice", "direct", "secret", "127.0.0.1:80", bytes.Repeat([]byte("late-data"), 4096))
			cut := credentialLength + 2 + test.headerBytes
			if _, err := client.Write(payload[:cut]); err != nil {
				t.Fatal(err)
			}
			select {
			case <-connected:
			case <-time.After(time.Second):
				t.Fatal("partial request did not fall back within its initial-header deadline")
			}
			if _, err := client.Write(payload[cut:]); err != nil {
				t.Fatal(err)
			}
			assertOriginReplay(t, client, received, payload)
			if err := service.Close(); err != nil {
				t.Fatal(err)
			}
			assertNoProxyActivity(t, kernel)
			assertNoProxySessionIssued(t, kernel)
		})
	}
}

func assertProxyClosed(t *testing.T, client net.Conn) {
	t.Helper()
	if err := client.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	read, err := client.Read(make([]byte, 32))
	var networkError net.Error
	if read != 0 || err == nil || (errors.As(err, &networkError) && networkError.Timeout()) {
		t.Fatalf("proxy failure did not close the connection: read %d, error %v", read, err)
	}
}

func TestFallbackDoesNotHandleProxyFailures(t *testing.T) {
	for _, mode := range []string{"dial failure", "zero port", "forbidden domain", "UDP framing"} {
		t.Run(mode, func(t *testing.T) {
			var connections atomic.Int32
			address := startRawWebsite(t, func(connection net.Conn) {
				connections.Add(1)
				_, _ = io.WriteString(connection, "unexpected-website")
			})
			service, kernel := startService(t, websiteOptions(address))
			client := dialService(t, service)
			var request []byte
			switch mode {
			case "dial failure":
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				target := listener.Addr().String()
				_ = listener.Close()
				request = trojanConnectRequest(t, "alice", "direct", "secret", target, nil)
			case "zero port":
				request = trojanConnectRequest(t, "alice", "direct", "secret", "127.0.0.1:0", nil)
			case "forbidden domain":
				request = append(trojanCredentialHeader(t, "alice", "direct", "secret"), commandConnect, addressDomain, 3, 'a', ':', 'b', 0, 80, '\r', '\n')
			case "UDP framing":
				request = append(trojanUDPAssociateRequest(t, "alice", "direct", "secret"), 0x02)
			}
			if _, err := client.Write(request); err != nil {
				t.Fatal(err)
			}
			assertProxyClosed(t, client)
			if err := service.Close(); err != nil {
				t.Fatal(err)
			}
			if connections.Load() != 0 {
				t.Fatal("proxy failure reached the website")
			}
			if len(kernel.Tracker().Snapshots()) != 0 {
				t.Fatal("failed proxy request remained tracked")
			}
		})
	}
}

func TestFallbackKeepsFragmentedTCPAndUDPRequestsInProxyPath(t *testing.T) {
	for _, protocol := range []string{"TCP", "UDP"} {
		t.Run(protocol, func(t *testing.T) {
			var connections atomic.Int32
			address := startRawWebsite(t, func(connection net.Conn) {
				connections.Add(1)
				_, _ = io.WriteString(connection, "unexpected-website")
			})
			options := websiteOptions(address)
			options.HandshakeTimeout = 2 * time.Second
			options.Fallback.ProbeTimeout = time.Second
			service, kernel := startService(t, options)
			client := dialService(t, service)
			if err := client.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
				t.Fatal(err)
			}
			payload := bytes.Repeat([]byte("valid-payload"), 100)
			rejected := []byte("rejected-payload")
			var request []byte
			if protocol == "TCP" {
				request = trojanConnectRequest(t, "alice", "direct", "secret", startEchoServer(t), payload)
			} else {
				target := startUDPEchoServer(t)
				packet, err := AppendPacket(nil, target, payload)
				if err != nil {
					t.Fatal(err)
				}
				request = append(trojanUDPAssociateRequest(t, "alice", "direct", "secret"), packet...)
				rejected, err = AppendPacket(nil, target, rejected)
				if err != nil {
					t.Fatal(err)
				}
			}
			// Separate TLS writes split both the credential and request header.
			for _, fragment := range [][]byte{request[:20], request[20:58], request[58:61], request[61:]} {
				if _, err := client.Write(fragment); err != nil {
					t.Fatal(err)
				}
			}
			got := make([]byte, len(payload))
			if protocol == "TCP" {
				if _, err := io.ReadFull(client, got); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, read, err := ReadPacket(client, got); err != nil || read != len(payload) {
					t.Fatalf("UDP response: read %d, error %v", read, err)
				}
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("valid fragmented request lost or changed proxy payload")
			}
			// Policy can reject later traffic on an already classified request.
			kernel.UpdateUsers(map[string]config.UserConfig{})
			if _, err := client.Write(rejected); err != nil {
				t.Fatal(err)
			}
			assertProxyClosed(t, client)
			if err := service.Close(); err != nil {
				t.Fatal(err)
			}
			stats := kernel.Traffic().GetSnapshot("alice:direct")
			if stats == nil || stats.TxBytes != uint64(len(payload)) || stats.RxBytes != uint64(len(payload)) || stats.OnlineCount != 0 {
				t.Fatal("fragmented proxy request or policy refusal corrupted accounting")
			}
			if connections.Load() != 0 || len(kernel.Tracker().Snapshots()) != 0 {
				t.Fatal("valid proxy request entered fallback or remained tracked after close")
			}
		})
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
	// Exhaustion must not close in silence: that is the fingerprint the fallback
	// removes, and a probe can cause exhaustion on demand.
	status, body := readWebsiteResponse(t, second)
	if status != http.StatusNotFound {
		t.Fatalf("over-capacity status = %d, want 404", status)
	}
	if body != "" {
		t.Fatalf("over-capacity body = %q, want no body", body)
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

// A TLS connection that never sends a request must not cost a website slot or an
// origin connection. Otherwise one handshake buys the full relay lifetime of
// both, and a handful of silent connections locks real visitors out.
func TestFallbackSilentConnectionCostsNoSlotOrOrigin(t *testing.T) {
	accepted := make(chan struct{}, 4)
	address := startRawWebsite(t, func(connection net.Conn) {
		accepted <- struct{}{}
		_, _ = io.Copy(io.Discard, connection)
	})
	options := websiteOptions(address)
	options.Fallback.MaxConnections = 1
	options.Fallback.IdleTimeout = 10 * time.Second
	service, kernel := startService(t, options)

	silent := dialService(t, service)
	if err := silent.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := silent.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// The gateway closes it once the probe window expires without a request.
	if _, err := silent.Read(make([]byte, 1)); err == nil {
		t.Fatal("silent probe was served instead of closed")
	}
	select {
	case <-accepted:
		t.Fatal("silent probe reached the origin")
	default:
	}
	if occupied := len(service.fallback.slots); occupied != 0 {
		t.Fatalf("silent probe held %d website slots", occupied)
	}

	// The single slot is still free for a real visitor.
	visitor := dialService(t, service)
	if _, err := io.WriteString(visitor, strings.Repeat("x", credentialLength)+"\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("website capacity was consumed by the silent probe")
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	assertNoProxyActivity(t, kernel)
}

// The website lifetime bound is idle, not absolute: a visitor that keeps
// transferring must never be cut off. The transfer here lasts several times the
// idle bound while no single gap approaches it, so an absolute deadline would
// truncate the stream.
func TestFallbackIdleTimeoutExtendsWithTransfers(t *testing.T) {
	const chunks = 8
	const chunk = "chunk"
	address := startRawWebsite(t, func(connection net.Conn) {
		_, _ = connection.Read(make([]byte, maxInitialHeaderSize))
		for i := 0; i < chunks; i++ {
			time.Sleep(200 * time.Millisecond)
			if _, err := io.WriteString(connection, chunk); err != nil {
				return
			}
		}
	})
	options := websiteOptions(address)
	options.Fallback.IdleTimeout = time.Second
	service, kernel := startService(t, options)
	client := dialService(t, service)
	if err := client.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := io.WriteString(client, strings.Repeat("x", credentialLength)+"\r\n"); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, chunks*len(chunk))
	if _, err := io.ReadFull(client, body); err != nil {
		t.Fatalf("idle deadline interrupted an active transfer: %v", err)
	}
	if string(body) != strings.Repeat(chunk, chunks) {
		t.Fatalf("transfer = %q", body)
	}
	if elapsed := time.Since(started); elapsed <= options.Fallback.IdleTimeout {
		t.Fatalf("transfer finished in %v, which does not outlive the idle bound", elapsed)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	assertNoProxyActivity(t, kernel)
}

func TestFallbackLifetimeAndShutdown(t *testing.T) {
	for _, mode := range []string{"timeout", "shutdown", "shutdown during classification"} {
		t.Run(mode, func(t *testing.T) {
			accepted, closed := make(chan struct{}), make(chan struct{})
			address := startRawWebsite(t, func(connection net.Conn) {
				close(accepted)
				_, _ = io.Copy(io.Discard, connection)
				close(closed)
			})
			options := websiteOptions(address)
			options.Fallback.IdleTimeout = time.Second
			classifying := mode == "shutdown during classification"
			if classifying {
				// Keep the header read blocked so shutdown lands before the
				// connection is ever classified.
				options.HandshakeTimeout = 30 * time.Second
				options.Fallback.ProbeTimeout = 10 * time.Second
			}
			service, _ := startService(t, options)
			client := dialService(t, service)
			header := strings.Repeat("x", credentialLength) + "\r\n"
			if classifying {
				header = "abc123"
			}
			if _, err := io.WriteString(client, header); err != nil {
				t.Fatal(err)
			}
			if classifying {
				// No observable signal exists mid-read; a short settle is enough
				// because the assertions below hold wherever the handler is.
				time.Sleep(50 * time.Millisecond)
				select {
				case <-accepted:
					t.Fatal("an unclassified connection reached the origin")
				default:
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
			if classifying {
				select {
				case <-accepted:
					t.Fatal("shutdown during classification still dialed the origin")
				default:
				}
				return
			}
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("website backend connection was left open")
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
