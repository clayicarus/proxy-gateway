package e2e

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	hyClient "github.com/apernet/hysteria/core/v2/client"
	hyServer "github.com/apernet/hysteria/core/v2/server"
	"github.com/clayicarus/proxy-gateway/internal/auth"
	"github.com/clayicarus/proxy-gateway/internal/config"
	"github.com/clayicarus/proxy-gateway/internal/event"
	"github.com/clayicarus/proxy-gateway/internal/router"
	"github.com/clayicarus/proxy-gateway/internal/traffic"
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

	authenticator := auth.NewAuthenticator(users, logger)
	trafficLogger := traffic.NewTrafficLogger(users, nil, logger)
	routerEngine := router.NewRouter(users, logger)
	outboundFactory := router.NewOutboundFactory(nodes, logger)
	warmupCtx, warmupCancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := outboundFactory.Warmup(warmupCtx); err != nil {
		warmupCancel()
		outboundFactory.Close()
		t.Fatalf("failed to warm up node outbound: %v", err)
	}
	warmupCancel()
	routingOutbound := router.NewRoutingOutbound(routerEngine, outboundFactory, logger)
	eventLogger := event.NewEventLogger(routingOutbound, logger)

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
		Conn:          gatewayUDP,
		Authenticator: authenticator,
		Outbound:      routingOutbound,
		TrafficLogger: trafficLogger,
		EventLogger:   eventLogger,
	})
	if err != nil {
		t.Fatalf("failed to create gateway server: %v", err)
	}
	go gatewayServer.Serve()
	defer gatewayServer.Close()
	defer outboundFactory.Close()

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
