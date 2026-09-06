package trojan

import (
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/clayicarus/proxy-gateway/internal/config"
)

// This deliberately fills the default pending limit while established idle
// sessions remain open, then verifies that Close drains both populations.
// Resource measurements include this process's test clients as well as the
// server; they are a reproducible loopback probe, not a production capacity SLA.
func TestServerResourceBoundsUnderLoad(t *testing.T) {
	const idleCount = 64
	const excessCount = 32
	var peers sync.WaitGroup
	outbound := &testOutbound{tcp: func(string) (net.Conn, error) {
		connection, peer := net.Pipe()
		peers.Add(1)
		go func() {
			defer peers.Done()
			defer peer.Close()
			_, _ = io.Copy(peer, peer)
		}()
		return connection, nil
	}}
	tracker := &testTracker{}
	server, done := startTestServer(t, ServerConfig{
		Authenticator: NewAuthenticator(map[string]config.UserConfig{"alice": {Password: "test-password", Routes: []string{"direct"}}}),
		Outbound:      &testRouter{outbound: outbound}, TrafficLogger: &testTrafficLogger{}, ConnectionTracker: tracker,
		HandshakeTimeout: time.Minute, MaxPendingConnections: defaultMaxPendingConnections,
	})
	var before, peak runtime.MemStats
	runtime.ReadMemStats(&before)
	baselineGoroutines := runtime.NumGoroutine()
	clients := make([]net.Conn, 0, idleCount+defaultMaxPendingConnections)
	defer func() {
		for _, client := range clients {
			_ = client.Close()
		}
	}()
	credential := HashPassword(RawPassword("alice", "direct", "test-password"))
	header := requestBytes(credential, commandConnect, addressDomain, append([]byte{11}, []byte("example.com")...), 443, "\r\n", "\r\n")
	for i := 0; i < idleCount; i++ {
		client := dialTestTLS(t, server)
		clients = append(clients, client)
		if _, err := client.Write(header); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, 5*time.Second, func() bool {
		connects, _, starts, _ := tracker.snapshot()
		return connects == idleCount && starts == idleCount && len(server.pending) == 0
	})
	for i := 0; i < defaultMaxPendingConnections; i++ {
		client, err := net.DialTimeout("tcp", server.Addr().String(), 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, client)
	}
	eventually(t, 5*time.Second, func() bool { return len(server.pending) == defaultMaxPendingConnections })
	for i := 0; i < excessCount; i++ {
		client, err := net.DialTimeout("tcp", server.Addr().String(), 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		expectConnectionClosed(t, client)
		_ = client.Close()
	}
	runtime.ReadMemStats(&peak)
	peakGoroutines := runtime.NumGoroutine()
	started := time.Now()
	stopTestServer(t, server, done)
	peers.Wait()
	elapsed := time.Since(started)
	if elapsed > 5*time.Second {
		t.Fatalf("loaded server shutdown took %v", elapsed)
	}
	server.connectionsMu.Lock()
	remaining := len(server.connections)
	server.connectionsMu.Unlock()
	connects, disconnects, starts, stops := tracker.snapshot()
	if remaining != 0 || len(server.pending) != 0 || connects != idleCount || disconnects != idleCount || starts != idleCount || stops != idleCount {
		t.Fatalf("loaded server retained resources: connections=%d pending=%d lifecycle=%d/%d/%d/%d", remaining, len(server.pending), connects, disconnects, starts, stops)
	}
	t.Logf("loopback probe: pending=%d idle=%d excess_rejected=%d heap_delta_bytes=%d total_alloc_bytes=%d goroutine_delta=%d shutdown=%v",
		defaultMaxPendingConnections, idleCount, excessCount, int64(peak.HeapAlloc)-int64(before.HeapAlloc), peak.TotalAlloc-before.TotalAlloc, peakGoroutines-baselineGoroutines, elapsed)
}
