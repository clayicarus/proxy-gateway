package integration

import (
	"context"
	"net"
	"os"
	"testing"

	"github.com/clayicarus/proxy-gateway/internal/auth"
	"github.com/clayicarus/proxy-gateway/internal/config"
	"github.com/clayicarus/proxy-gateway/internal/outbound"
	"github.com/clayicarus/proxy-gateway/internal/router"
	"github.com/clayicarus/proxy-gateway/internal/storage"
	"github.com/clayicarus/proxy-gateway/internal/traffic"
	"go.uber.org/zap"
)

// TestE2E_FullPipeline simulates the full request lifecycle:
//
//	Client auth → explicit policy route → TrafficLogger.LogTraffic → SQLite
//	persistence.
func TestE2E_FullPipeline(t *testing.T) {
	logger := zap.NewNop()

	// --- Setup target server (simulates the internet) ---
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
			conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\nHello from target"))
			conn.Close()
		}
	}()

	targetAddr := targetLn.Addr().String()

	// --- Setup SQLite ---
	dbPath := t.TempDir() + "/e2e_test.db"
	defer os.Remove(dbPath)

	store, err := storage.NewSQLiteStore(dbPath, logger)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	// --- Setup config ---
	users := map[string]config.UserConfig{
		"alice": {Password: "pass123", Routes: []string{"direct"}, MaxBytes: 1000000},
		"bob":   {Password: "secret", Routes: []string{"direct"}, MaxBytes: 500},
	}
	nodes := map[string]config.NodeConfig{}

	// --- Initialize components ---
	authenticator := auth.NewAuthenticator(users, logger)
	trafficLogger := traffic.NewTrafficLogger(users, store, logger)
	routerEngine := router.NewRouter(users, logger)
	outboundFactory := outbound.NewOutboundFactory(nodes, logger)
	routingService := router.NewService(routerEngine, outboundFactory, logger)

	// --- Simulate client connection ---
	clientAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 54321}

	// Step 1: Authentication (new format: username:node_name:password)
	ok, id := authenticator.Authenticate(clientAddr, "alice:direct:pass123", 1000000)
	if !ok || id != "alice:direct" {
		t.Fatalf("auth failed: ok=%v id=%s", ok, id)
	}

	// The authenticated identity is explicit at the policy boundary.
	conn, err := routingService.TCPContext(context.Background(), id, targetAddr)
	if err != nil {
		t.Fatalf("routing TCP failed: %v", err)
	}

	// Step 5: Read response from target
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read from target failed: %v", err)
	}
	response := string(buf[:n])
	if response == "" {
		t.Error("expected non-empty response from target")
	}
	conn.Close()

	// Step 6: Log traffic (id is "alice:direct")
	ok = trafficLogger.LogTraffic(id, 100, uint64(n))
	if !ok {
		t.Error("expected LogTraffic to return true (under quota)")
	}

	// Step 7: Verify in-memory stats
	snap := trafficLogger.GetSnapshot("alice:direct")
	if snap == nil {
		t.Fatal("expected snapshot for alice:direct")
	}
	if snap.TxBytes != 100 {
		t.Errorf("expected tx=100, got %d", snap.TxBytes)
	}

	// Step 8: Flush to SQLite
	trafficLogger.Flush()

	// Step 9: Verify SQLite persistence (now per user+node)
	tx, rx, err := store.GetSummary("alice", "direct")
	if err != nil {
		t.Fatalf("get summary failed: %v", err)
	}
	if tx != 100 {
		t.Errorf("sqlite tx: expected 100, got %d", tx)
	}
	if rx != uint64(n) {
		t.Errorf("sqlite rx: expected %d, got %d", n, rx)
	}

	t.Logf("E2E pipeline completed: alice:direct sent %d bytes, received %d bytes", tx, rx)
}

// TestE2E_QuotaEnforcement tests that a user gets disconnected when quota is exceeded.
func TestE2E_QuotaEnforcement(t *testing.T) {
	logger := zap.NewNop()

	users := map[string]config.UserConfig{
		"bob": {Password: "secret", Routes: []string{"direct"}, MaxBytes: 500},
	}

	trafficLogger := traffic.NewTrafficLogger(users, nil, logger)

	// Log traffic that exceeds quota (total across all nodes)
	ok := trafficLogger.LogTraffic("bob:direct", 300, 300) // total = 600 > 500
	if ok {
		t.Error("expected LogTraffic to return false (quota exceeded)")
	}
}

// TestE2E_MultiUserRouting tests that different users get routed to different outbounds.
func TestE2E_MultiUserRouting(t *testing.T) {
	logger := zap.NewNop()

	// Create two target servers
	target1Ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer target1Ln.Close()
	go func() {
		for {
			conn, err := target1Ln.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("target1"))
			conn.Close()
		}
	}()

	target2Ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer target2Ln.Close()
	go func() {
		for {
			conn, err := target2Ln.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("target2"))
			conn.Close()
		}
	}()

	nodes := map[string]config.NodeConfig{}

	multiUsers := map[string]config.UserConfig{
		"alice": {Password: "p", Routes: []string{"direct"}},
		"bob":   {Password: "p", Routes: []string{"direct"}},
	}
	routerEngine := router.NewRouter(multiUsers, logger)
	outboundFactory := outbound.NewOutboundFactory(nodes, logger)
	routingService := router.NewService(routerEngine, outboundFactory, logger)

	conn1, err := routingService.TCPContext(context.Background(), "alice:direct", target1Ln.Addr().String())
	if err != nil {
		t.Fatalf("alice TCP failed: %v", err)
	}
	buf := make([]byte, 100)
	n, _ := conn1.Read(buf)
	if string(buf[:n]) != "target1" {
		t.Errorf("alice: expected 'target1', got %q", string(buf[:n]))
	}
	conn1.Close()

	conn2, err := routingService.TCPContext(context.Background(), "bob:direct", target2Ln.Addr().String())
	if err != nil {
		t.Fatalf("bob TCP failed: %v", err)
	}
	buf2 := make([]byte, 100)
	n2, _ := conn2.Read(buf2)
	if string(buf2[:n2]) != "target2" {
		t.Errorf("bob: expected 'target2', got %q", string(buf2[:n2]))
	}
	conn2.Close()

}

// TestE2E_NodeFailureIsReturned tests that Gateway does not substitute a
// server-side fallback when the client-selected node is unavailable.
func TestE2E_NodeFailureIsReturned(t *testing.T) {
	logger := zap.NewNop()

	users := map[string]config.UserConfig{
		"alice": {
			Password: "pass",
			Routes:   []string{"broken_node"},
		},
	}
	nodes := map[string]config.NodeConfig{
		"broken_node": {
			Type: "hysteria2",
			Hysteria2: &config.Hysteria2OutboundConfig{
				Addr:     "127.0.0.1:1", // unreachable port
				Auth:     "wrong_auth",
				Insecure: true,
			},
		},
	}

	routerEngine := router.NewRouter(users, logger)
	outboundFactory := outbound.NewOutboundFactory(nodes, logger)
	routingService := router.NewService(routerEngine, outboundFactory, logger)
	_, err := routingService.TCPContext(context.Background(), "alice:broken_node", "example.com:443")
	if err == nil {
		t.Fatal("expected error when selected node is unreachable")
	}
	t.Logf("correctly got error: %v", err)

}
