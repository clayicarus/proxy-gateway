package router

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	coreErrors "github.com/apernet/hysteria/core/v2/errors"
	"github.com/clayicarus/proxy-gateway/internal/config"
	"go.uber.org/zap"
)

type closeAwareUDPConn struct {
	closed chan struct{}
	once   sync.Once
}

func newCloseAwareUDPConn() *closeAwareUDPConn {
	return &closeAwareUDPConn{closed: make(chan struct{})}
}

func (c *closeAwareUDPConn) ReadFrom([]byte) (int, string, error) {
	<-c.closed
	return 0, "", io.EOF
}

func (c *closeAwareUDPConn) WriteTo([]byte, string) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
		return 1, nil
	}
}

func (c *closeAwareUDPConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func TestNodeUDPConnLocalCloseDoesNotFailSharedNode(t *testing.T) {
	inner := newCloseAwareUDPConn()
	var failures atomic.Int32
	conn := &nodeUDPConn{
		UDPConn: inner,
		failed:  func(error) { failures.Add(1) },
	}
	readDone := make(chan error, 1)
	go func() {
		_, _, err := conn.ReadFrom(nil)
		readDone <- err
	}()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-readDone; !errors.Is(err, io.EOF) {
		t.Fatalf("read error = %v, want EOF", err)
	}
	if failures.Load() != 0 {
		t.Fatalf("local association close failed shared node %d times", failures.Load())
	}
	if _, err := conn.WriteTo([]byte("x"), "example.com:53"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write after close error = %v, want net.ErrClosed", err)
	}
	if failures.Load() != 0 {
		t.Fatalf("write after local close failed shared node %d times", failures.Load())
	}
}

type failingUDPConn struct{ err error }

func (c failingUDPConn) ReadFrom([]byte) (int, string, error) { return 0, "", c.err }
func (c failingUDPConn) WriteTo([]byte, string) (int, error)  { return 0, c.err }
func (c failingUDPConn) Close() error                         { return nil }

func TestNodeUDPConnConnectionFailureFailsSharedNode(t *testing.T) {
	for _, operation := range []string{"read", "write"} {
		t.Run(operation, func(t *testing.T) {
			var failures atomic.Int32
			conn := &nodeUDPConn{
				UDPConn: failingUDPConn{err: io.EOF},
				failed:  func(error) { failures.Add(1) },
			}
			if operation == "read" {
				_, _, _ = conn.ReadFrom(nil)
			} else {
				_, _ = conn.WriteTo(nil, "example.com:53")
			}
			if failures.Load() != 1 {
				t.Fatalf("connection failure callback count = %d, want 1", failures.Load())
			}
		})
	}
}

func TestDirectOutbound_TCP(t *testing.T) {
	if directDialer.Timeout != 10*time.Second {
		t.Fatalf("unexpected direct TCP timeout: %v", directDialer.Timeout)
	}
	logger := zap.NewNop()
	d := &DirectOutbound{logger: logger}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			conn.Write([]byte("hello"))
			conn.Close()
		}
	}()

	conn, err := d.TCP(ln.Addr().String())
	if err != nil {
		t.Fatalf("direct TCP failed: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 5)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(buf[:n]) != "hello" {
		t.Errorf("expected 'hello', got %q", string(buf[:n]))
	}
}

type fakeConnectedOutbound struct {
	tcpErr error
	closed atomic.Bool
}

func (f *fakeConnectedOutbound) TCP(string) (net.Conn, error) { return nil, f.tcpErr }
func (f *fakeConnectedOutbound) UDP(string) (UDPConn, error) {
	return nil, f.tcpErr
}
func (f *fakeConnectedOutbound) Close() error {
	f.closed.Store(true)
	return nil
}

type fakeNodeConnector struct {
	connect func(context.Context, string, *config.Hysteria2OutboundConfig) (connectedOutbound, string, error)
}

func (f fakeNodeConnector) Connect(ctx context.Context, name string, cfg *config.Hysteria2OutboundConfig) (connectedOutbound, string, error) {
	return f.connect(ctx, name, cfg)
}

func validTestNode(addr string) config.NodeConfig {
	return config.NodeConfig{Type: "hysteria2", Hysteria2: &config.Hysteria2OutboundConfig{Addr: addr, Auth: "secret"}}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition was not satisfied before timeout")
}

func TestOutboundFactory_NodeFailureIsIsolatedAndFailsFast(t *testing.T) {
	connector := fakeNodeConnector{connect: func(_ context.Context, name string, _ *config.Hysteria2OutboundConfig) (connectedOutbound, string, error) {
		if name == "bad" {
			return nil, "", fmt.Errorf("handshake failed")
		}
		return &fakeConnectedOutbound{}, "192.0.2.10:443", nil
	}}
	factory := newOutboundFactory(map[string]config.NodeConfig{
		"bad":  validTestNode("bad.example:443"),
		"good": validTestNode("good.example:443"),
	}, zap.NewNop(), connector, func(int) time.Duration { return time.Hour })
	defer factory.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := factory.Warmup(ctx); err != nil {
		t.Fatalf("warmup should finish after every first attempt: %v", err)
	}
	if factory.NodeStatuses()["good"].State != NodeReady {
		t.Fatalf("good node was blocked by failed node: %#v", factory.NodeStatuses())
	}
	waitFor(t, func() bool {
		status := factory.NodeStatuses()["bad"]
		return status.State == NodeBackoff && !status.NextRetry.IsZero() && strings.Contains(status.LastError, "handshake failed")
	})
	bad, err := factory.Get("bad")
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := bad.TCP("example.com:443"); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("bad node did not fail fast: %v", err)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("unavailable request blocked for %v", elapsed)
	}
	if _, err := factory.Get("direct"); err != nil {
		t.Fatalf("direct route was affected by failed node: %v", err)
	}
}

func TestOutboundFactory_ClosedConnectionReconnectsInBackground(t *testing.T) {
	var calls atomic.Int32
	connector := fakeNodeConnector{connect: func(context.Context, string, *config.Hysteria2OutboundConfig) (connectedOutbound, string, error) {
		call := calls.Add(1)
		if call == 1 {
			return &fakeConnectedOutbound{tcpErr: coreErrors.ClosedError{}}, "192.0.2.1:443", nil
		}
		return &fakeConnectedOutbound{}, "192.0.2.2:443", nil
	}}
	factory := newOutboundFactory(map[string]config.NodeConfig{"node": validTestNode("node.example:443")}, zap.NewNop(), connector, func(int) time.Duration { return time.Millisecond })
	defer factory.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := factory.Warmup(ctx); err != nil {
		t.Fatal(err)
	}
	node, _ := factory.Get("node")
	if _, err := node.TCP("example.com:443"); !isClosedConnection(err) {
		t.Fatalf("expected closed connection error, got %v", err)
	}
	waitFor(t, func() bool {
		status := factory.NodeStatuses()["node"]
		return calls.Load() >= 2 && status.State == NodeReady && status.ResolvedAddr == "192.0.2.2:443"
	})
}

func TestOutboundFactory_BoundsConcurrentPreconnects(t *testing.T) {
	release := make(chan struct{})
	var active atomic.Int32
	var maximum atomic.Int32
	connector := fakeNodeConnector{connect: func(ctx context.Context, _ string, _ *config.Hysteria2OutboundConfig) (connectedOutbound, string, error) {
		current := active.Add(1)
		defer active.Add(-1)
		for {
			previous := maximum.Load()
			if current <= previous || maximum.CompareAndSwap(previous, current) {
				break
			}
		}
		select {
		case <-release:
			return &fakeConnectedOutbound{}, "192.0.2.1:443", nil
		case <-ctx.Done():
			return nil, "", ctx.Err()
		}
	}}
	nodes := make(map[string]config.NodeConfig, 12)
	for i := 0; i < 12; i++ {
		nodes[fmt.Sprintf("node-%02d", i)] = validTestNode("node.example:443")
	}
	factory := newOutboundFactory(nodes, zap.NewNop(), connector, func(int) time.Duration { return time.Hour })
	factory.Start()
	waitFor(t, func() bool { return maximum.Load() == maxConnectAttempts })
	close(release)
	defer factory.Close()
	if maximum.Load() > maxConnectAttempts {
		t.Fatalf("preconnect concurrency exceeded limit: %d", maximum.Load())
	}
}

func TestDefaultRetryDelayNeverExceedsCap(t *testing.T) {
	for i := 0; i < 1000; i++ {
		if delay := defaultRetryDelay(100); delay > time.Minute {
			t.Fatalf("retry delay exceeded cap: %v", delay)
		}
	}
}

type fakeIPResolver struct {
	mu      sync.Mutex
	calls   int
	answers []netip.Addr
}

func (r *fakeIPResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	return append([]netip.Addr(nil), r.answers...), nil
}

func TestHysteria2Connector_RefreshesDNSAndTriesAllAddresses(t *testing.T) {
	resolver := &fakeIPResolver{answers: []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}}
	var mu sync.Mutex
	var addresses, serverNames []string
	connector := &hysteria2Connector{
		resolver: resolver,
		logger:   zap.NewNop(),
		dial: func(_ *config.Hysteria2OutboundConfig, addr *net.UDPAddr, sni string, _ *zap.Logger) (connectedOutbound, error) {
			mu.Lock()
			defer mu.Unlock()
			addresses = append(addresses, addr.String())
			serverNames = append(serverNames, sni)
			if addr.IP.String() == "192.0.2.1" {
				return nil, fmt.Errorf("unreachable")
			}
			return &fakeConnectedOutbound{}, nil
		},
	}
	cfg := &config.Hysteria2OutboundConfig{Addr: "node.example:443", Auth: "secret"}
	for i := 0; i < 2; i++ {
		outbound, _, err := connector.Connect(context.Background(), "node", cfg)
		if err != nil {
			t.Fatal(err)
		}
		_ = outbound.Close()
	}
	if resolver.calls != 2 {
		t.Fatalf("DNS was not refreshed for each attempt: calls=%d", resolver.calls)
	}
	if got := strings.Join(addresses, ","); got != "192.0.2.1:443,[2001:db8::1]:443,192.0.2.1:443,[2001:db8::1]:443" {
		t.Fatalf("addresses were not tried sequentially: %s", got)
	}
	for _, sni := range serverNames {
		if sni != "node.example" {
			t.Fatalf("resolved IP replaced hostname SNI: %q", sni)
		}
	}

	connector.dial = func(_ *config.Hysteria2OutboundConfig, addr *net.UDPAddr, _ string, _ *zap.Logger) (connectedOutbound, error) {
		if addr.IP.String() != "2001:db8::2" {
			t.Fatalf("unexpected IPv6 literal address: %s", addr)
		}
		return &fakeConnectedOutbound{}, nil
	}
	outbound, _, err := connector.Connect(context.Background(), "literal", &config.Hysteria2OutboundConfig{Addr: "[2001:db8::2]:443", Auth: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	_ = outbound.Close()
	if resolver.calls != 2 {
		t.Fatalf("IPv6 literal unexpectedly used DNS: calls=%d", resolver.calls)
	}

	connector.dial = func(_ *config.Hysteria2OutboundConfig, addr *net.UDPAddr, sni string, _ *zap.Logger) (connectedOutbound, error) {
		if addr.Zone != "eth0" || sni != "fe80::1" {
			t.Fatalf("IPv6 zone leaked into SNI: addr=%s sni=%q", addr, sni)
		}
		return &fakeConnectedOutbound{}, nil
	}
	outbound, _, err = connector.Connect(context.Background(), "zoned", &config.Hysteria2OutboundConfig{Addr: "[fe80::1%eth0]:443", Auth: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	_ = outbound.Close()
}

func TestDirectOutbound_UDP(t *testing.T) {
	logger := zap.NewNop()
	d := &DirectOutbound{logger: logger}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create UDP listener: %v", err)
	}
	defer pc.Close()

	targetAddr := pc.LocalAddr().String()

	go func() {
		buf := make([]byte, 1024)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		pc.WriteTo(buf[:n], addr)
	}()

	udpConn, err := d.UDP(targetAddr)
	if err != nil {
		t.Fatalf("direct UDP failed: %v", err)
	}
	defer udpConn.Close()

	_, err = udpConn.WriteTo([]byte("ping"), targetAddr)
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	buf := make([]byte, 1024)
	n, _, err := udpConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(buf[:n]) != "ping" {
		t.Errorf("expected 'ping', got %q", string(buf[:n]))
	}
}

func TestOutboundFactory_Direct(t *testing.T) {
	logger := zap.NewNop()
	f := NewOutboundFactory(nil, logger)
	defer f.Close()

	ob, err := f.Get("direct")
	if err != nil {
		t.Fatalf("get direct failed: %v", err)
	}
	if ob == nil {
		t.Fatal("expected non-nil outbound")
	}
}

func TestOutboundFactory_Unknown(t *testing.T) {
	logger := zap.NewNop()
	nodes := map[string]config.NodeConfig{}
	f := NewOutboundFactory(nodes, logger)

	_, err := f.Get("nonexistent")
	if err == nil {
		t.Error("expected error for unknown node")
	}
}

func TestServiceRoutesExplicitIdentity(t *testing.T) {
	logger := zap.NewNop()
	nodes := map[string]config.NodeConfig{}

	r := NewRouter(map[string]config.UserConfig{
		"alice": {Password: "p", Routes: []string{"direct"}},
	}, logger)
	f := NewOutboundFactory(nodes, logger)
	service := NewService(r, f, logger)

	// Create a local listener for the test
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	conn, err := service.TCPContext(context.Background(), "alice:direct", ln.Addr().String())
	if err != nil {
		t.Fatalf("routing TCP failed: %v", err)
	}
	conn.Close()

}

func TestServiceRejectsMalformedIdentity(t *testing.T) {
	logger := zap.NewNop()
	service := NewService(NewRouter(nil, logger), NewOutboundFactory(nil, logger), logger)
	if _, err := service.TCPContext(context.Background(), "alice", "example.com:443"); err == nil || !strings.Contains(err.Error(), "node is required") {
		t.Fatalf("authenticated ID without an explicit node should fail closed, got %v", err)
	}
}

func TestServiceConcurrentSameTargetKeepsExplicitRoute(t *testing.T) {
	logger := zap.NewNop()
	const requests = 100
	nodes := make(map[string]config.NodeConfig, requests)
	for i := 0; i < requests; i++ {
		route := fmt.Sprintf("route-%03d", i)
		nodes[route] = config.NodeConfig{Type: "test-invalid"}
	}
	service := NewService(NewRouter(nil, logger), NewOutboundFactory(nodes, logger), logger)

	var wg sync.WaitGroup
	errors := make(chan error, requests)
	for i := 0; i < requests; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			route := fmt.Sprintf("route-%03d", i)
			_, err := service.TCPContext(context.Background(), "user:"+route, "same.example:443")
			if err == nil || !strings.Contains(err.Error(), "node "+route+" unavailable:") {
				errors <- fmt.Errorf("request %d used wrong route: %v", i, err)
			}
		}()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
}
