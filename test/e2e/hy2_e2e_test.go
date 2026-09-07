package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	hyClient "github.com/apernet/hysteria/core/v2/client"
	hyServer "github.com/apernet/hysteria/core/v2/server"
	"github.com/clayicarus/proxy-gateway/internal/auth"
	"github.com/clayicarus/proxy-gateway/internal/config"
	"github.com/clayicarus/proxy-gateway/internal/connection"
	hyInbound "github.com/clayicarus/proxy-gateway/internal/inbound/hysteria2"
	"github.com/clayicarus/proxy-gateway/internal/outbound"
	"github.com/clayicarus/proxy-gateway/internal/router"
	"github.com/clayicarus/proxy-gateway/internal/traffic"
	"go.uber.org/zap"
)

// generateSelfSignedCert creates a self-signed TLS certificate for testing.
func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

type cancellationSession struct{ id string }

func (s *cancellationSession) ID() string  { return s.id }
func (s *cancellationSession) Close(error) {}

type cancellationHarness struct {
	started chan struct{}
	calls   atomic.Int32
}

func (h *cancellationHarness) AuthenticateSession(context.Context, hyServer.Transport, string, uint64) (hyServer.Session, bool) {
	return &cancellationSession{id: "cancel-test"}, true
}
func (h *cancellationHarness) TCPContext(ctx context.Context, _ hyServer.Session, _ hyServer.RequestInfo) (net.Conn, error) {
	if h.calls.Add(1) == 1 {
		close(h.started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	server, target := net.Pipe()
	go func() {
		defer target.Close()
		buf := make([]byte, 64)
		n, err := target.Read(buf)
		if err == nil {
			_, _ = target.Write(buf[:n])
		}
	}()
	return server, nil
}
func (h *cancellationHarness) UDPContext(context.Context, hyServer.Session, hyServer.RequestInfo) (hyServer.UDPConn, error) {
	return nil, errors.New("UDP disabled")
}
func (h *cancellationHarness) LogTrafficContext(context.Context, hyServer.Session, hyServer.RequestInfo, uint64, uint64) bool {
	return true
}
func (h *cancellationHarness) LogOnlineStateSession(hyServer.Session, bool) {}

func TestHy2TCPContextCancellationKeepsConnectionUsable(t *testing.T) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	harness := &cancellationHarness{started: make(chan struct{})}
	server, err := hyServer.NewServer(&hyServer.Config{
		TLSConfig: hyServer.TLSConfig{Certificates: []tls.Certificate{cert}},
		Conn:      udpConn, DisableUDP: true,
		SessionAuthenticator: harness, SessionOutbound: harness, SessionTrafficLogger: harness,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve() }()
	serverAddr, _ := net.ResolveUDPAddr("udp", udpConn.LocalAddr().String())
	client, _, err := hyClient.NewClientContext(context.Background(), &hyClient.Config{
		ServerAddr: serverAddr, Auth: "ok",
		TLSConfig: hyClient.TLSConfig{ServerName: "localhost", InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = client.Close()
		_ = server.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := client.Wait(ctx); err != nil {
			t.Errorf("client wait: %v", err)
		}
		if err := server.Wait(ctx); err != nil {
			t.Errorf("server wait: %v", err)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, err := client.TCPContext(ctx, "blocked.example:443"); result <- err }()
	select {
	case <-harness.started:
	case <-time.After(3 * time.Second):
		t.Fatal("blocked request did not reach outbound")
	}
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("canceled CONNECT unexpectedly succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canceled CONNECT did not return")
	}

	conn, err := client.TCPContext(context.Background(), "echo.example:443")
	if err != nil {
		t.Fatalf("second request failed after cancellation: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("still-alive")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err := conn.Read(buf)
	if (err != nil && !errors.Is(err, io.EOF)) || string(buf[:n]) != "still-alive" {
		t.Fatalf("second request response n=%d err=%v data=%q", n, err, buf[:n])
	}
}

// TestHy2E2E_ClientServerConnect tests a real Hysteria2 client connecting
// to our gateway server, authenticating, and proxying TCP traffic.
func TestHy2E2E_ClientServerConnect(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// --- 1. Start a target TCP server (simulates the internet) ---
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create target listener: %v", err)
	}
	defer targetLn.Close()

	go func() {
		for {
			conn, err := targetLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 1024)
				for {
					n, err := conn.Read(buf)
					if err != nil {
						return
					}
					if _, err := conn.Write([]byte("echo:" + string(buf[:n]))); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	targetAddr := targetLn.Addr().String()
	t.Logf("target server listening on %s", targetAddr)
	udpTarget, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create UDP target: %v", err)
	}
	defer udpTarget.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := udpTarget.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = udpTarget.WriteTo(buf[:n], addr)
		}
	}()

	// --- 2. Generate self-signed TLS cert ---
	tlsCert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("failed to generate cert: %v", err)
	}

	// --- 3. Initialize gateway components ---
	users := map[string]config.UserConfig{
		"alice": {Password: "pass123", Routes: []string{"direct"}, MaxBytes: 10000000},
		"bob":   {Password: "secret", Routes: []string{"direct"}},
	}
	nodes := map[string]config.NodeConfig{}

	authenticator := auth.NewAuthenticator(users, logger)
	trafficLogger := traffic.NewTrafficLogger(users, nil, logger)
	routerEngine := router.NewRouter(users, logger)
	outboundFactory := outbound.NewOutboundFactory(nodes, logger)
	routingService := router.NewService(routerEngine, outboundFactory, logger)
	tracker := connection.NewTracker()
	adapter := hyInbound.New("hy2-e2e", authenticator, routingService, trafficLogger, tracker, logger)

	// --- 4. Start Hysteria2 server ---
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}

	serverAddr := udpConn.LocalAddr().String()
	t.Logf("hy2 server listening on %s", serverAddr)

	server, err := hyServer.NewServer(&hyServer.Config{
		TLSConfig: hyServer.TLSConfig{
			Certificates: []tls.Certificate{tlsCert},
		},
		Conn:                 udpConn,
		SessionAuthenticator: adapter,
		SessionOutbound:      adapter,
		SessionTrafficLogger: adapter,
		SessionEventLogger:   adapter,
	})
	if err != nil {
		t.Fatalf("failed to create hy2 server: %v", err)
	}

	go func() {
		server.Serve()
	}()
	defer func() {
		_ = server.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := server.Wait(ctx); err != nil {
			t.Errorf("server wait: %v", err)
		}
	}()

	// Give server a moment to start
	time.Sleep(100 * time.Millisecond)

	// --- 5. Connect with Hysteria2 client (alice) ---
	// Auth format: username:node_name:password
	t.Run("alice_auth_and_proxy", func(t *testing.T) {
		sAddr, _ := net.ResolveUDPAddr("udp", serverAddr)
		client, info, err := hyClient.NewClientContext(context.Background(), &hyClient.Config{
			ServerAddr: sAddr,
			Auth:       "alice:direct:pass123",
			TLSConfig: hyClient.TLSConfig{
				ServerName:         "localhost",
				InsecureSkipVerify: true,
			},
		})
		if err != nil {
			t.Fatalf("failed to create hy2 client: %v", err)
		}
		defer func() {
			_ = client.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := client.Wait(ctx); err != nil {
				t.Errorf("client wait: %v", err)
			}
		}()

		t.Logf("client connected, UDP enabled: %v, Tx: %d", info.UDPEnabled, info.Tx)

		// Proxy TCP through the gateway to the target server
		conn, err := client.TCP(targetAddr)
		if err != nil {
			t.Fatalf("client TCP failed: %v", err)
		}
		defer conn.Close()

		// Send data
		_, err = conn.Write([]byte("hello from alice"))
		if err != nil {
			t.Fatalf("write failed: %v", err)
		}

		// Read response
		buf := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("read failed: %v", err)
		}

		response := string(buf[:n])
		expected := "echo:hello from alice"
		if response != expected {
			t.Errorf("expected %q, got %q", expected, response)
		}

		t.Logf("alice received: %s", response)
		beforeUDP := trafficLogger.GetSnapshot("alice:direct")
		if beforeUDP == nil {
			t.Fatal("missing traffic before UDP")
		}
		beforeTx, beforeRx := beforeUDP.TxBytes, beforeUDP.RxBytes

		udp, err := client.UDP()
		if err != nil {
			t.Fatalf("client UDP failed: %v", err)
		}
		defer udp.Close()
		payload := make([]byte, 3000)
		for i := range payload {
			payload[i] = byte(i)
		}
		if err := udp.Send(payload, udpTarget.LocalAddr().String()); err != nil {
			t.Fatalf("UDP send: %v", err)
		}
		timeout := time.AfterFunc(5*time.Second, func() { _ = client.Close() })
		got, gotAddr, err := udp.Receive()
		timeout.Stop()
		if err != nil {
			t.Fatalf("UDP receive: %v", err)
		}
		if gotAddr != udpTarget.LocalAddr().String() || len(got) != len(payload) || string(got) != string(payload) {
			t.Fatalf("UDP echo mismatch: addr=%q bytes=%d", gotAddr, len(got))
		}
		afterUDP := trafficLogger.GetSnapshot("alice:direct")
		if afterUDP.TxBytes-beforeTx != 3000 || afterUDP.RxBytes-beforeRx != 6000 {
			t.Fatalf("UDP accounting delta = tx:%d rx:%d, want 3000/6000", afterUDP.TxBytes-beforeTx, afterUDP.RxBytes-beforeRx)
		}
	})

	// --- 6. Test auth failure ---
	t.Run("wrong_password", func(t *testing.T) {
		sAddr, _ := net.ResolveUDPAddr("udp", serverAddr)
		_, _, err := hyClient.NewClient(&hyClient.Config{
			ServerAddr: sAddr,
			Auth:       "alice:direct:wrongpass",
			TLSConfig: hyClient.TLSConfig{
				ServerName:         "localhost",
				InsecureSkipVerify: true,
			},
		})
		if err == nil {
			t.Error("expected auth to fail with wrong password")
		} else {
			t.Logf("auth correctly rejected: %v", err)
		}
	})

	// --- 7. Test second user (bob) ---
	t.Run("bob_auth_and_proxy", func(t *testing.T) {
		sAddr, _ := net.ResolveUDPAddr("udp", serverAddr)
		client, _, err := hyClient.NewClient(&hyClient.Config{
			ServerAddr: sAddr,
			Auth:       "bob:direct:secret",
			TLSConfig: hyClient.TLSConfig{
				ServerName:         "localhost",
				InsecureSkipVerify: true,
			},
		})
		if err != nil {
			t.Fatalf("failed to create hy2 client for bob: %v", err)
		}
		defer client.Close()

		conn, err := client.TCP(targetAddr)
		if err != nil {
			t.Fatalf("bob TCP failed: %v", err)
		}
		defer conn.Close()

		_, err = conn.Write([]byte("hello from bob"))
		if err != nil {
			t.Fatalf("write failed: %v", err)
		}

		buf := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("read failed: %v", err)
		}

		response := string(buf[:n])
		expected := "echo:hello from bob"
		if response != expected {
			t.Errorf("expected %q, got %q", expected, response)
		}

		t.Logf("bob received: %s", response)
	})

	// --- 8. Verify traffic stats ---
	t.Run("traffic_stats", func(t *testing.T) {
		// Give a moment for traffic to be logged
		time.Sleep(200 * time.Millisecond)

		// Traffic is now tracked per (user, node)
		aliceSnap := trafficLogger.GetSnapshot("alice:direct")
		if aliceSnap == nil {
			t.Fatal("expected traffic snapshot for alice:direct")
		}
		t.Logf("alice:direct traffic: tx=%d rx=%d", aliceSnap.TxBytes, aliceSnap.RxBytes)

		if aliceSnap.TxBytes == 0 && aliceSnap.RxBytes == 0 {
			t.Error("expected non-zero traffic for alice:direct")
		}

		bobSnap := trafficLogger.GetSnapshot("bob:direct")
		if bobSnap == nil {
			t.Fatal("expected traffic snapshot for bob:direct")
		}
		t.Logf("bob:direct traffic: tx=%d rx=%d", bobSnap.TxBytes, bobSnap.RxBytes)

		if bobSnap.TxBytes == 0 && bobSnap.RxBytes == 0 {
			t.Error("expected non-zero traffic for bob:direct")
		}
	})
}

// TestHy2E2E_UnknownUser tests that an unknown user is rejected.
func TestHy2E2E_UnknownUser(t *testing.T) {
	logger := zap.NewNop()

	tlsCert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("failed to generate cert: %v", err)
	}

	users := map[string]config.UserConfig{
		"alice": {Password: "pass123", Routes: []string{"direct"}},
	}
	nodes := map[string]config.NodeConfig{}

	authenticator := auth.NewAuthenticator(users, logger)
	trafficLogger := traffic.NewTrafficLogger(users, nil, logger)
	routerEngine := router.NewRouter(users, logger)
	outboundFactory := outbound.NewOutboundFactory(nodes, logger)
	routingService := router.NewService(routerEngine, outboundFactory, logger)
	adapter := hyInbound.New("unknown-user", authenticator, routingService, trafficLogger, connection.NewTracker(), logger)

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}

	server, err := hyServer.NewServer(&hyServer.Config{
		TLSConfig: hyServer.TLSConfig{
			Certificates: []tls.Certificate{tlsCert},
		},
		Conn:                 udpConn,
		SessionAuthenticator: adapter,
		SessionOutbound:      adapter,
		SessionTrafficLogger: adapter,
		SessionEventLogger:   adapter,
	})
	if err != nil {
		t.Fatalf("failed to create hy2 server: %v", err)
	}

	go server.Serve()
	defer server.Close()

	time.Sleep(100 * time.Millisecond)

	serverAddr := udpConn.LocalAddr().String()
	sAddr, _ := net.ResolveUDPAddr("udp", serverAddr)

	_, _, err = hyClient.NewClient(&hyClient.Config{
		ServerAddr: sAddr,
		Auth:       "unknown:direct:whatever",
		TLSConfig: hyClient.TLSConfig{
			ServerName:         "localhost",
			InsecureSkipVerify: true,
		},
	})
	if err == nil {
		t.Error("expected auth to fail for unknown user")
	} else {
		t.Logf("unknown user correctly rejected: %v", err)
	}
}

func TestHy2E2E_ExpiredUserDisconnectsExistingConnection(t *testing.T) {
	logger := zap.NewNop()
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer targetLn.Close()
	go func() {
		for {
			conn, err := targetLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buffer := make([]byte, 64)
				for {
					n, err := conn.Read(buffer)
					if err != nil {
						return
					}
					if _, err := conn.Write(buffer[:n]); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	tlsCert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	future := time.Now().UTC().Add(time.Hour)
	users := map[string]config.UserConfig{
		"alice": {Password: "pass123", Routes: []string{"direct"}, ExpiresAt: &future},
	}
	authenticator := auth.NewAuthenticator(users, logger)
	trafficLogger := traffic.NewTrafficLogger(users, nil, logger)
	routingService := router.NewService(router.NewRouter(users, logger), outbound.NewOutboundFactory(nil, logger), logger)
	adapter := hyInbound.New("expiry", authenticator, routingService, trafficLogger, connection.NewTracker(), logger)
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	server, err := hyServer.NewServer(&hyServer.Config{
		TLSConfig:            hyServer.TLSConfig{Certificates: []tls.Certificate{tlsCert}},
		Conn:                 udpConn,
		SessionAuthenticator: adapter,
		SessionOutbound:      adapter,
		SessionTrafficLogger: adapter,
		SessionEventLogger:   adapter,
	})
	if err != nil {
		t.Fatal(err)
	}
	go server.Serve()
	defer server.Close()

	serverAddr, err := net.ResolveUDPAddr("udp", udpConn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	client, _, err := hyClient.NewClient(&hyClient.Config{
		ServerAddr: serverAddr,
		Auth:       "alice:direct:pass123",
		TLSConfig: hyClient.TLSConfig{
			ServerName:         "localhost",
			InsecureSkipVerify: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	conn, err := client.TCP(targetLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("before-expiry")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Read(buffer); err != nil || string(buffer[:n]) != "before-expiry" {
		t.Fatalf("active connection failed before expiry: n=%d err=%v data=%q", n, err, buffer[:n])
	}

	past := time.Now().UTC().Add(-time.Hour)
	users["alice"] = config.UserConfig{Password: "pass123", Routes: []string{"direct"}, ExpiresAt: &past}
	authenticator.UpdateUsers(users)
	trafficLogger.UpdateUsers(users)
	_, _ = conn.Write([]byte("after-expiry"))
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Read(buffer); err == nil {
		t.Fatalf("expired existing connection remained usable: n=%d data=%q", n, buffer[:n])
	}
}
