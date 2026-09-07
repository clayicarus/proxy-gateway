package hysteria2

import (
	"context"
	"errors"
	"net"
	"testing"

	hyServer "github.com/apernet/hysteria/core/v2/server"
	"github.com/clayicarus/proxy-gateway/internal/auth"
	"github.com/clayicarus/proxy-gateway/internal/config"
	"github.com/clayicarus/proxy-gateway/internal/connection"
	"github.com/clayicarus/proxy-gateway/internal/router"
	"github.com/clayicarus/proxy-gateway/internal/traffic"
	"go.uber.org/zap"
)

type testTransport struct {
	ctx    context.Context
	addr   net.Addr
	closed chan error
}

func (t *testTransport) Context() context.Context { return t.ctx }
func (t *testTransport) RemoteAddr() net.Addr     { return t.addr }
func (t *testTransport) Close(err error) error {
	select {
	case t.closed <- err:
	default:
	}
	return nil
}

func TestAdapterBindsIdentityToStableSessions(t *testing.T) {
	logger := zap.NewNop()
	users := map[string]config.UserConfig{"alice": {Password: "secret", Routes: []string{"direct"}}}
	tracker := connection.NewTracker()
	accounting := traffic.NewTrafficLogger(users, nil, logger)
	adapter := New("public", auth.NewAuthenticator(users, logger), router.NewRoutingOutbound(router.NewRouter(users, logger), router.NewOutboundFactory(nil, logger), logger), accounting, tracker, logger)
	transport := &testTransport{ctx: context.Background(), addr: &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}, closed: make(chan error, 1)}

	first, ok := adapter.AuthenticateSession(context.Background(), transport, "alice:direct:secret", 0)
	if !ok {
		t.Fatal("authentication failed")
	}
	second, ok := adapter.AuthenticateSession(context.Background(), transport, "alice:direct:secret", 0)
	if !ok || first.ID() == second.ID() {
		t.Fatalf("session IDs are not unique: %q", first.ID())
	}
	adapter.ConnectSession(transport, first, 0)
	request := hyServer.RequestInfo{ID: 7, Network: "tcp", Target: "example.com:443"}
	adapter.TCPRequestSession(first, request)
	if !adapter.LogTrafficContext(context.Background(), first, request, 10, 20) {
		t.Fatal("traffic rejected")
	}
	snapshots := tracker.Snapshots()
	if len(snapshots) != 1 || snapshots[0].SessionID != first.ID() || len(snapshots[0].Requests) != 1 || snapshots[0].Requests[0].ID != 7 {
		t.Fatalf("unexpected tracker state: %#v", snapshots)
	}
	stats := accounting.GetSnapshot("alice:direct")
	if stats.TxBytes != 10 || stats.RxBytes != 20 {
		t.Fatalf("unexpected traffic: %#v", stats)
	}
	adapter.TCPErrorSession(first, request, nil)
	adapter.DisconnectSession(transport, first, nil)
	if len(tracker.Snapshots()) != 0 {
		t.Fatal("session was not removed")
	}
}

func TestSessionCloseTargetsOnlyBoundTransport(t *testing.T) {
	cause := errors.New("quota")
	transport := &testTransport{ctx: context.Background(), addr: &net.UDPAddr{}, closed: make(chan error, 2)}
	ctx, cancel := context.WithCancelCause(context.Background())
	s := &session{id: "in/1", routeID: "alice:direct", transport: transport, ctx: ctx, cancel: cancel}
	s.Close(cause)
	s.Close(errors.New("second"))
	if !errors.Is(context.Cause(ctx), cause) {
		t.Fatalf("context cause = %v", context.Cause(ctx))
	}
	if got := <-transport.closed; !errors.Is(got, cause) {
		t.Fatalf("close cause = %v", got)
	}
	select {
	case <-transport.closed:
		t.Fatal("transport closed more than once")
	default:
	}
}
