package e2e

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	hyClient "github.com/apernet/hysteria/core/v2/client"
	hyServer "github.com/apernet/hysteria/core/v2/server"
	"github.com/clayicarus/proxy-gateway/internal/config"
	hyInbound "github.com/clayicarus/proxy-gateway/internal/inbound/hysteria2"
	"github.com/clayicarus/proxy-gateway/internal/policy"
	"go.uber.org/zap"
)

// TestTwoHop_ClientGatewayNode tests the full two-hop data path:
//
//	User (hy2 client) → Gateway (hy2 server + hy2 client) → Node (hy2 server) → Target
//
// This validates that the Hysteria2Outbound correctly proxies traffic
// through a real hy2 QUIC connection to a remote node.
func TestTwoHop_ClientGatewayNode(t *testing.T) {
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
					if _, err := conn.Write([]byte("twohop-echo:" + string(buf[:n]))); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	targetAddr := targetLn.Addr().String()
	t.Logf("target server on %s", targetAddr)
	udpTarget, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create UDP target: %v", err)
	}
	defer udpTarget.Close()
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, addr, err := udpTarget.ReadFrom(buffer)
			if err != nil {
				return
			}
			_, _ = udpTarget.WriteTo(buffer[:n], addr)
		}
	}()

	// --- 2. Generate TLS certs ---
	nodeCert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("failed to generate node cert: %v", err)
	}
	gatewayCert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("failed to generate gateway cert: %v", err)
	}

	// --- 3. Start Node (remote hy2 server) ---
	nodeUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen node UDP: %v", err)
	}
	nodeAddr := nodeUDP.LocalAddr().String()
	t.Logf("node hy2 server on %s", nodeAddr)

	nodeAuthenticator := &simpleAuthenticator{password: "node_secret"}
	nodeServer, err := hyServer.NewServer(&hyServer.Config{
		TLSConfig: hyServer.TLSConfig{
			Certificates: []tls.Certificate{nodeCert},
		},
		Conn:          nodeUDP,
		Authenticator: nodeAuthenticator,
	})
	if err != nil {
		t.Fatalf("failed to create node server: %v", err)
	}
	go nodeServer.Serve()
	defer nodeServer.Close()

	time.Sleep(100 * time.Millisecond)

	// --- 4. Start Gateway ---
	users := map[string]config.UserConfig{
		"alice": {Password: "alice_pass", Routes: []string{"node1"}},
	}
	nodes := map[string]config.NodeConfig{
		"node1": {
			Type: "hysteria2",
			Hysteria2: &config.Hysteria2OutboundConfig{
				Addr:     nodeAddr,
				Auth:     "node_secret",
				Insecure: true,
			},
		},
	}

	kernel := policy.New(users, nodes, nil, logger, time.UTC)
	trafficLogger := kernel.Traffic()
	warmupCtx, warmupCancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := kernel.Warmup(warmupCtx); err != nil {
		warmupCancel()
		kernel.CloseOutbounds()
		t.Fatalf("failed to warm up node outbound: %v", err)
	}
	warmupCancel()
	adapter := hyInbound.New("two-hop", kernel)

	gatewayUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen gateway UDP: %v", err)
	}
	gatewayAddr := gatewayUDP.LocalAddr().String()
	t.Logf("gateway hy2 server on %s", gatewayAddr)

	gatewayServer, err := hyServer.NewServer(&hyServer.Config{
		TLSConfig: hyServer.TLSConfig{
			Certificates: []tls.Certificate{gatewayCert},
		},
		Conn:                 gatewayUDP,
		SessionAuthenticator: adapter,
		SessionOutbound:      adapter,
		SessionTrafficLogger: adapter,
		SessionEventLogger:   adapter,
	})
	if err != nil {
		t.Fatalf("failed to create gateway server: %v", err)
	}
	go gatewayServer.Serve()
	defer gatewayServer.Close()
	defer kernel.CloseOutbounds()

	time.Sleep(100 * time.Millisecond)

	// --- 5. Connect with hy2 client as end user ---
	// Auth format: username:node_name:password
	t.Run("two_hop_tcp_proxy", func(t *testing.T) {
		sAddr, _ := net.ResolveUDPAddr("udp", gatewayAddr)
		client, _, err := hyClient.NewClient(&hyClient.Config{
			ServerAddr: sAddr,
			Auth:       "alice:node1:alice_pass",
			TLSConfig: hyClient.TLSConfig{
				ServerName:         "localhost",
				InsecureSkipVerify: true,
			},
		})
		if err != nil {
			t.Fatalf("failed to create user client: %v", err)
		}
		defer client.Close()

		conn, err := client.TCP(targetAddr)
		if err != nil {
			t.Fatalf("client TCP failed: %v", err)
		}
		defer conn.Close()

		_, err = conn.Write([]byte("hello two-hop"))
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
		expected := "twohop-echo:hello two-hop"
		if response != expected {
			t.Errorf("expected %q, got %q", expected, response)
		}

		t.Logf("two-hop response: %s", response)
	})

	// Closing one UDP association must not close the shared client connection
	// that the second association uses to reach the remote node.
	t.Run("two_hop_udp_proxy_and_association_isolation", func(t *testing.T) {
		sAddr, _ := net.ResolveUDPAddr("udp", gatewayAddr)
		client, _, err := hyClient.NewClient(&hyClient.Config{
			ServerAddr: sAddr,
			Auth:       "alice:node1:alice_pass",
			TLSConfig: hyClient.TLSConfig{
				ServerName:         "localhost",
				InsecureSkipVerify: true,
			},
		})
		if err != nil {
			t.Fatalf("failed to create UDP client: %v", err)
		}
		defer client.Close()

		first, err := client.UDP()
		if err != nil {
			t.Fatalf("first UDP association: %v", err)
		}
		second, err := client.UDP()
		if err != nil {
			_ = first.Close()
			t.Fatalf("second UDP association: %v", err)
		}
		defer second.Close()

		exchange := func(conn hyClient.HyUDPConn, payload string) {
			t.Helper()
			if err := conn.Send([]byte(payload), udpTarget.LocalAddr().String()); err != nil {
				t.Fatalf("UDP send %q: %v", payload, err)
			}
			timeout := time.AfterFunc(5*time.Second, func() { _ = client.Close() })
			response, address, err := conn.Receive()
			timeout.Stop()
			if err != nil {
				t.Fatalf("UDP receive %q: %v", payload, err)
			}
			if address != udpTarget.LocalAddr().String() || string(response) != payload {
				t.Fatalf("UDP response = %q from %q, want %q from %q", response, address, payload, udpTarget.LocalAddr())
			}
		}

		exchange(first, "first association")
		exchange(second, "second association")
		if err := first.Close(); err != nil {
			t.Fatalf("close first UDP association: %v", err)
		}
		exchange(second, "second remains usable")
	})

	// --- 6. Verify traffic was logged ---
	t.Run("traffic_logged", func(t *testing.T) {
		time.Sleep(200 * time.Millisecond)
		snap := trafficLogger.GetSnapshot("alice:node1")
		if snap == nil {
			t.Fatal("expected traffic snapshot for alice:node1")
		}
		t.Logf("alice:node1 traffic: tx=%d rx=%d", snap.TxBytes, snap.RxBytes)
		if snap.TxBytes == 0 && snap.RxBytes == 0 {
			t.Error("expected non-zero traffic for alice:node1")
		}
	})

	// --- 7. Auth failure should still work ---
	t.Run("auth_failure", func(t *testing.T) {
		sAddr, _ := net.ResolveUDPAddr("udp", gatewayAddr)
		_, _, err := hyClient.NewClient(&hyClient.Config{
			ServerAddr: sAddr,
			Auth:       "alice:node1:wrong_pass",
			TLSConfig: hyClient.TLSConfig{
				ServerName:         "localhost",
				InsecureSkipVerify: true,
			},
		})
		if err == nil {
			t.Error("expected auth failure")
		} else {
			t.Logf("auth correctly rejected: %v", err)
		}
	})
}

// simpleAuthenticator is a minimal authenticator for the node server.
type simpleAuthenticator struct {
	password string
}

func (a *simpleAuthenticator) Authenticate(addr net.Addr, authStr string, tx uint64) (bool, string) {
	if authStr == a.password {
		return true, "node-user"
	}
	return false, ""
}
