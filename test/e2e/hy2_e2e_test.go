package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	hyClient "github.com/apernet/hysteria/core/v2/client"
	hyServer "github.com/apernet/hysteria/core/v2/server"
	"github.com/hy2-gateway/internal/auth"
	"github.com/hy2-gateway/internal/config"
	"github.com/hy2-gateway/internal/event"
	"github.com/hy2-gateway/internal/router"
	"github.com/hy2-gateway/internal/traffic"
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
			buf := make([]byte, 1024)
			n, _ := conn.Read(buf)
			conn.Write([]byte("echo:" + string(buf[:n])))
			conn.Close()
		}
	}()

	targetAddr := targetLn.Addr().String()
	t.Logf("target server listening on %s", targetAddr)

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
	outboundFactory := router.NewOutboundFactory(nodes, logger)
	routingOutbound := router.NewRoutingOutbound(routerEngine, outboundFactory, logger)
	eventLogger := event.NewEventLogger(routingOutbound, logger)

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
		Conn:          udpConn,
		Authenticator: authenticator,
		Outbound:      routingOutbound,
		TrafficLogger: trafficLogger,
		EventLogger:   eventLogger,
	})
	if err != nil {
		t.Fatalf("failed to create hy2 server: %v", err)
	}

	go func() {
		server.Serve()
	}()
	defer server.Close()

	// Give server a moment to start
	time.Sleep(100 * time.Millisecond)

	// --- 5. Connect with Hysteria2 client (alice) ---
	// Auth format: username:node_name:password
	t.Run("alice_auth_and_proxy", func(t *testing.T) {
		sAddr, _ := net.ResolveUDPAddr("udp", serverAddr)
		client, info, err := hyClient.NewClient(&hyClient.Config{
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
		defer client.Close()

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
	outboundFactory := router.NewOutboundFactory(nodes, logger)
	routingOutbound := router.NewRoutingOutbound(routerEngine, outboundFactory, logger)
	eventLogger := event.NewEventLogger(routingOutbound, logger)

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}

	server, err := hyServer.NewServer(&hyServer.Config{
		TLSConfig: hyServer.TLSConfig{
			Certificates: []tls.Certificate{tlsCert},
		},
		Conn:          udpConn,
		Authenticator: authenticator,
		Outbound:      routingOutbound,
		TrafficLogger: trafficLogger,
		EventLogger:   eventLogger,
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
