package trojan

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	hyServer "github.com/apernet/hysteria/core/v2/server"
	"github.com/clayicarus/proxy-gateway/internal/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

type testRouter struct {
	outbound hyServer.Outbound
	err      error
	calls    atomic.Int32
}

func (r *testRouter) GetOutboundForID(string) (hyServer.Outbound, error) {
	r.calls.Add(1)
	return r.outbound, r.err
}

type testOutbound struct {
	tcp   func(string) (net.Conn, error)
	calls atomic.Int32
}

func (o *testOutbound) TCP(target string) (net.Conn, error) {
	o.calls.Add(1)
	return o.tcp(target)
}

func (o *testOutbound) UDP(string) (hyServer.UDPConn, error) {
	return nil, errors.New("UDP is not supported by test outbound")
}

type trafficCall struct {
	id     string
	tx, rx uint64
}

type testTrafficLogger struct {
	mu       sync.Mutex
	traffic  []trafficCall
	online   []bool
	rejectTx bool
	rejectRx bool
}

func (l *testTrafficLogger) LogTraffic(id string, tx, rx uint64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.traffic = append(l.traffic, trafficCall{id: id, tx: tx, rx: rx})
	return !(l.rejectTx && tx > 0) && !(l.rejectRx && rx > 0)
}

func (l *testTrafficLogger) LogOnlineState(_ string, online bool) {
	l.mu.Lock()
	l.online = append(l.online, online)
	l.mu.Unlock()
}

func (l *testTrafficLogger) snapshot() ([]trafficCall, []bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]trafficCall(nil), l.traffic...), append([]bool(nil), l.online...)
}

type testTracker struct {
	mu          sync.Mutex
	connects    int
	disconnects int
	starts      int
	stops       int
}

func (t *testTracker) Connect(net.Addr, string) {
	t.mu.Lock()
	t.connects++
	t.mu.Unlock()
}

func (t *testTracker) Disconnect(net.Addr) {
	t.mu.Lock()
	t.disconnects++
	t.mu.Unlock()
}

func (t *testTracker) StartTCP(net.Addr, string) {
	t.mu.Lock()
	t.starts++
	t.mu.Unlock()
}

func (t *testTracker) StopTCP(net.Addr, string) {
	t.mu.Lock()
	t.stops++
	t.mu.Unlock()
}

func (t *testTracker) snapshot() (int, int, int, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.connects, t.disconnects, t.starts, t.stops
}

func TestServerRejectsUnknownCredentialWithoutDialOrSecretLeak(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	logger := zap.New(core)
	outbound := &testOutbound{tcp: func(string) (net.Conn, error) {
		return nil, errors.New("must not dial")
	}}
	router := &testRouter{outbound: outbound}
	trafficLogger := &testTrafficLogger{}
	tracker := &testTracker{}
	server, serveDone := startTestServer(t, ServerConfig{
		Authenticator:     NewAuthenticator(map[string]config.UserConfig{"alice": {Password: "secret", Routes: []string{"direct"}}}),
		Outbound:          router,
		TrafficLogger:     trafficLogger,
		ConnectionTracker: tracker,
		Logger:            logger,
	})

	unknownCredential := strings.Repeat("b", credentialLength)
	client := dialTestTLS(t, server)
	header := requestBytes(unknownCredential, commandConnect, addressDomain, append([]byte{11}, []byte("example.com")...), 443, "\r\n", "\r\n")
	if _, err := client.Write(header); err != nil {
		t.Fatal(err)
	}
	expectConnectionClosed(t, client)
	if got := router.calls.Load(); got != 0 {
		t.Fatalf("route lookup calls = %d, want 0", got)
	}
	if got := outbound.calls.Load(); got != 0 {
		t.Fatalf("outbound calls = %d, want 0", got)
	}
	if calls, online := trafficLogger.snapshot(); len(calls) != 0 || len(online) != 0 {
		t.Fatalf("traffic was recorded: %#v %#v", calls, online)
	}
	if connects, disconnects, starts, stops := tracker.snapshot(); connects+disconnects+starts+stops != 0 {
		t.Fatalf("tracker changed: %d/%d/%d/%d", connects, disconnects, starts, stops)
	}
	for _, entry := range observed.All() {
		if strings.Contains(entry.Message, unknownCredential) || strings.Contains(fmt.Sprint(entry.ContextMap()), unknownCredential) {
			t.Fatal("authentication credential leaked into logs")
		}
	}
	stopTestServer(t, server, serveDone)
}

func TestServerDialFailureDoesNotMarkConnectionOnline(t *testing.T) {
	outbound := &testOutbound{tcp: func(string) (net.Conn, error) {
		return nil, errors.New("dial failed")
	}}
	trafficLogger := &testTrafficLogger{}
	tracker := &testTracker{}
	authenticator := NewAuthenticator(map[string]config.UserConfig{"alice": {Password: "secret", Routes: []string{"direct"}}})
	server, serveDone := startTestServer(t, ServerConfig{
		Authenticator: authenticator, Outbound: &testRouter{outbound: outbound},
		TrafficLogger: trafficLogger, ConnectionTracker: tracker,
	})

	client := dialTestTLS(t, server)
	credential := HashPassword(RawPassword("alice", "direct", "secret"))
	header := requestBytes(credential, commandConnect, addressDomain, append([]byte{11}, []byte("example.com")...), 443, "\r\n", "\r\n")
	if _, err := client.Write(header); err != nil {
		t.Fatal(err)
	}
	expectConnectionClosed(t, client)
	if _, online := trafficLogger.snapshot(); len(online) != 0 {
		t.Fatalf("dial failure changed online state: %#v", online)
	}
	if connects, disconnects, starts, stops := tracker.snapshot(); connects+disconnects+starts+stops != 0 {
		t.Fatalf("dial failure changed tracker: %d/%d/%d/%d", connects, disconnects, starts, stops)
	}
	stopTestServer(t, server, serveDone)
}

func TestServerRejectedChunkIsNotForwardedAndLifecycleCleansOnce(t *testing.T) {
	targetPeer := make(chan net.Conn, 1)
	outbound := &testOutbound{tcp: func(string) (net.Conn, error) {
		serverSide, peer := net.Pipe()
		targetPeer <- peer
		return serverSide, nil
	}}
	trafficLogger := &testTrafficLogger{rejectTx: true}
	tracker := &testTracker{}
	authenticator := NewAuthenticator(map[string]config.UserConfig{"alice": {Password: "secret", Routes: []string{"direct"}}})
	server, serveDone := startTestServer(t, ServerConfig{
		Authenticator: authenticator, Outbound: &testRouter{outbound: outbound},
		TrafficLogger: trafficLogger, ConnectionTracker: tracker,
	})

	client := dialTestTLS(t, server)
	credential := HashPassword(RawPassword("alice", "direct", "secret"))
	header := requestBytes(credential, commandConnect, addressDomain, append([]byte{11}, []byte("example.com")...), 443, "\r\n", "\r\n")
	if _, err := client.Write(append(header, []byte("must-not-pass")...)); err != nil {
		t.Fatal(err)
	}
	peer := <-targetPeer
	defer peer.Close()
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 32)
	if read, err := peer.Read(buffer); err == nil || read != 0 {
		t.Fatalf("rejected payload reached target: n=%d err=%v data=%q", read, err, buffer[:read])
	}
	expectConnectionClosed(t, client)

	eventually(t, time.Second, func() bool {
		connects, disconnects, starts, stops := tracker.snapshot()
		return connects == 1 && disconnects == 1 && starts == 1 && stops == 1
	})
	trafficCalls, online := trafficLogger.snapshot()
	if len(trafficCalls) != 1 || trafficCalls[0].tx != uint64(len("must-not-pass")) || trafficCalls[0].rx != 0 {
		t.Fatalf("unexpected traffic calls: %#v", trafficCalls)
	}
	if len(online) != 2 || !online[0] || online[1] {
		t.Fatalf("online lifecycle = %#v, want [true false]", online)
	}
	stopTestServer(t, server, serveDone)
}

func TestServerHandshakeDeadlineAndPendingLimit(t *testing.T) {
	outbound := &testOutbound{tcp: func(string) (net.Conn, error) { return nil, errors.New("unused") }}
	server, serveDone := startTestServer(t, ServerConfig{
		Authenticator: NewAuthenticator(nil), Outbound: &testRouter{outbound: outbound},
		TrafficLogger: &testTrafficLogger{}, ConnectionTracker: &testTracker{},
		HandshakeTimeout: 100 * time.Millisecond, MaxPendingConnections: 1,
	})

	first, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	eventually(t, time.Second, func() bool { return len(server.pending) == 1 })

	second, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	expectConnectionClosed(t, second)
	if len(server.pending) > 1 {
		t.Fatalf("pending connections exceeded limit: %d", len(server.pending))
	}

	expectConnectionClosed(t, first)
	eventually(t, time.Second, func() bool { return len(server.pending) == 0 })
	stopTestServer(t, server, serveDone)
}

func TestServerBacksOffTemporaryAcceptErrorsAndReturnsPermanentFailure(t *testing.T) {
	listener := &scriptedListener{temporaryFailures: 2}
	server, err := newServer(listener, ServerConfig{
		TLSConfig:             &tls.Config{Certificates: []tls.Certificate{testCertificate(t)}},
		Authenticator:         NewAuthenticator(nil),
		Outbound:              &testRouter{outbound: &testOutbound{tcp: func(string) (net.Conn, error) { return nil, errors.New("unused") }}},
		TrafficLogger:         &testTrafficLogger{},
		ConnectionTracker:     &testTracker{},
		HandshakeTimeout:      time.Second,
		MaxPendingConnections: 1,
		Logger:                zap.NewNop(),
	})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	err = server.Serve()
	if err == nil || !strings.Contains(err.Error(), "permanent accept failure") {
		t.Fatalf("Serve error = %v", err)
	}
	if elapsed := time.Since(started); elapsed < initialAcceptBackoff*3 {
		t.Fatalf("temporary accept errors did not back off: %v", elapsed)
	}
	if listener.calls.Load() != 3 {
		t.Fatalf("Accept calls = %d, want 3", listener.calls.Load())
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestServerCloseStopsPendingAndIdleAuthenticatedConnections(t *testing.T) {
	targetPeer := make(chan net.Conn, 1)
	outbound := &testOutbound{tcp: func(string) (net.Conn, error) {
		serverSide, peer := net.Pipe()
		targetPeer <- peer
		return serverSide, nil
	}}
	trafficLogger := &testTrafficLogger{}
	tracker := &testTracker{}
	authenticator := NewAuthenticator(map[string]config.UserConfig{"alice": {Password: "secret", Routes: []string{"direct"}}})
	server, serveDone := startTestServer(t, ServerConfig{
		Authenticator: authenticator, Outbound: &testRouter{outbound: outbound},
		TrafficLogger: trafficLogger, ConnectionTracker: tracker,
		HandshakeTimeout: time.Minute, MaxPendingConnections: 4,
	})

	pendingClient, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer pendingClient.Close()
	eventually(t, time.Second, func() bool { return len(server.pending) == 1 })

	authenticatedClient := dialTestTLS(t, server)
	credential := HashPassword(RawPassword("alice", "direct", "secret"))
	header := requestBytes(credential, commandConnect, addressDomain, append([]byte{11}, []byte("example.com")...), 443, "\r\n", "\r\n")
	if _, err := authenticatedClient.Write(header); err != nil {
		t.Fatal(err)
	}
	peer := <-targetPeer
	defer peer.Close()
	eventually(t, time.Second, func() bool {
		connects, _, starts, _ := tracker.snapshot()
		return connects == 1 && starts == 1
	})

	started := time.Now()
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("server close took %v", elapsed)
	}
	if err := <-serveDone; err != nil {
		t.Fatalf("Serve returned during Close: %v", err)
	}
	expectConnectionClosed(t, pendingClient)
	expectConnectionClosed(t, authenticatedClient)
	eventually(t, time.Second, func() bool {
		connects, disconnects, starts, stops := tracker.snapshot()
		return connects == 1 && disconnects == 1 && starts == 1 && stops == 1
	})
	_, online := trafficLogger.snapshot()
	if len(online) != 2 || !online[0] || online[1] {
		t.Fatalf("online lifecycle = %#v", online)
	}
}

func TestServerConcurrentRelays(t *testing.T) {
	const clientCount = 32
	var peers sync.WaitGroup
	outbound := &testOutbound{tcp: func(string) (net.Conn, error) {
		serverSide, peer := net.Pipe()
		peers.Add(1)
		go func() {
			defer peers.Done()
			defer peer.Close()
			_, _ = io.Copy(peer, peer)
		}()
		return serverSide, nil
	}}
	trafficLogger := &testTrafficLogger{}
	tracker := &testTracker{}
	authenticator := NewAuthenticator(map[string]config.UserConfig{"alice": {Password: "secret", Routes: []string{"direct"}}})
	server, serveDone := startTestServer(t, ServerConfig{
		Authenticator: authenticator, Outbound: &testRouter{outbound: outbound},
		TrafficLogger: trafficLogger, ConnectionTracker: tracker,
		HandshakeTimeout: 5 * time.Second, MaxPendingConnections: clientCount * 2,
	})

	credential := HashPassword(RawPassword("alice", "direct", "secret"))
	payload := []byte("parallel relay payload")
	header := requestBytes(credential, commandConnect, addressDomain, append([]byte{11}, []byte("example.com")...), 443, "\r\n", "\r\n")
	errorsFound := make(chan error, clientCount)
	var clients sync.WaitGroup
	for index := 0; index < clientCount; index++ {
		clients.Add(1)
		go func() {
			defer clients.Done()
			client, err := tls.Dial("tcp", server.Addr().String(), &tls.Config{
				ServerName: "localhost", InsecureSkipVerify: true, MinVersion: tls.VersionTLS12,
			})
			if err != nil {
				errorsFound <- err
				return
			}
			defer client.Close()
			request := append(append([]byte(nil), header...), payload...)
			if _, err := client.Write(request); err != nil {
				errorsFound <- err
				return
			}
			response := make([]byte, len(payload))
			if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				errorsFound <- err
				return
			}
			if _, err := io.ReadFull(client, response); err != nil {
				errorsFound <- err
				return
			}
			if string(response) != string(payload) {
				errorsFound <- fmt.Errorf("response mismatch")
			}
		}()
	}
	clients.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, 2*time.Second, func() bool {
		connects, disconnects, starts, stops := tracker.snapshot()
		return connects == clientCount && disconnects == clientCount && starts == clientCount && stops == clientCount
	})
	trafficCalls, _ := trafficLogger.snapshot()
	var tx, rx uint64
	for _, call := range trafficCalls {
		tx += call.tx
		rx += call.rx
	}
	want := uint64(clientCount * len(payload))
	if tx != want || rx != want {
		t.Fatalf("aggregate traffic = %d/%d, want %d/%d", tx, rx, want, want)
	}
	stopTestServer(t, server, serveDone)
	peers.Wait()
}

func TestCopyMeteredMatchesHysteriaAccountingOrder(t *testing.T) {
	var logged uint64
	destination := &shortWriter{}
	err := copyMetered(destination, strings.NewReader("payload"), func(bytes uint64) bool {
		logged += bytes
		return true
	})
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("error = %v, want short write", err)
	}
	if logged != uint64(len("payload")) || destination.written != 1 {
		t.Fatalf("logged=%d written=%d", logged, destination.written)
	}

	var rejectedDestination strings.Builder
	err = copyMetered(&rejectedDestination, strings.NewReader("blocked"), func(uint64) bool { return false })
	if !errors.Is(err, ErrTrafficRejected) || rejectedDestination.Len() != 0 {
		t.Fatalf("rejected copy error=%v destination=%q", err, rejectedDestination.String())
	}
}

type shortWriter struct{ written int }

func (w *shortWriter) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	w.written++
	return 1, nil
}

type scriptedListener struct {
	temporaryFailures int
	calls             atomic.Int32
	closed            atomic.Bool
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	call := int(l.calls.Add(1))
	if l.closed.Load() {
		return nil, net.ErrClosed
	}
	if call <= l.temporaryFailures {
		return nil, temporaryAcceptError{}
	}
	return nil, errors.New("permanent accept failure")
}

func (l *scriptedListener) Close() error {
	l.closed.Store(true)
	return nil
}

func (l *scriptedListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}
}

type temporaryAcceptError struct{}

func (temporaryAcceptError) Error() string   { return "temporary accept failure" }
func (temporaryAcceptError) Timeout() bool   { return false }
func (temporaryAcceptError) Temporary() bool { return true }

func startTestServer(t *testing.T, config ServerConfig) (*Server, <-chan error) {
	t.Helper()
	config.Listen = "127.0.0.1:0"
	config.TLSConfig = &tls.Config{Certificates: []tls.Certificate{testCertificate(t)}, MinVersion: tls.VersionTLS12}
	if config.Logger == nil {
		config.Logger = zap.NewNop()
	}
	server, err := NewServer(config)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve() }()
	return server, done
}

func stopTestServer(t *testing.T, server *Server, serveDone <-chan error) {
	t.Helper()
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("Serve returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not stop")
	}
}

func dialTestTLS(t *testing.T, server *Server) net.Conn {
	t.Helper()
	client, err := tls.Dial("tcp", server.Addr().String(), &tls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true, // test-only self-signed certificate
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func expectConnectionClosed(t *testing.T, connection net.Conn) {
	t.Helper()
	defer connection.Close()
	if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1)
	if read, err := connection.Read(buffer); err == nil {
		t.Fatalf("connection remained open (read %d bytes)", read)
	}
}

func eventually(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	if !condition() {
		t.Fatal("condition was not met before timeout")
	}
}

func testCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}
