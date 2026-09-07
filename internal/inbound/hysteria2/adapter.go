package hysteria2

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"

	hyServer "github.com/apernet/hysteria/core/v2/server"
	"github.com/clayicarus/proxy-gateway/internal/auth"
	"github.com/clayicarus/proxy-gateway/internal/connection"
	"github.com/clayicarus/proxy-gateway/internal/router"
	"github.com/clayicarus/proxy-gateway/internal/traffic"
	"go.uber.org/zap"
)

var globalSessionID atomic.Uint64

// Adapter is the only production bridge between Hy2 callbacks and Gateway
// identity, policy, accounting, routing, and management state.
type Adapter struct {
	inbound string
	auth    *auth.Authenticator
	router  *router.RoutingOutbound
	traffic *traffic.TrafficLogger
	tracker *connection.Tracker
	logger  *zap.Logger
}

func New(inbound string, authenticator *auth.Authenticator, routing *router.RoutingOutbound, accounting *traffic.TrafficLogger, tracker *connection.Tracker, logger *zap.Logger) *Adapter {
	return &Adapter{inbound: inbound, auth: authenticator, router: routing, traffic: accounting, tracker: tracker, logger: logger}
}

type session struct {
	id        string
	routeID   string
	transport hyServer.Transport
	ctx       context.Context
	cancel    context.CancelCauseFunc
	closeOnce sync.Once
}

func (s *session) ID() string { return s.id }

func (s *session) Close(cause error) {
	s.closeOnce.Do(func() {
		s.cancel(cause)
		_ = s.transport.Close(cause)
	})
}

func sessionFrom(value hyServer.Session) (*session, bool) {
	s, ok := value.(*session)
	return s, ok && s != nil
}

func (a *Adapter) AuthenticateSession(_ context.Context, transport hyServer.Transport, proof string, tx uint64) (hyServer.Session, bool) {
	ok, routeID := a.auth.Authenticate(transport.RemoteAddr(), proof, tx)
	if !ok {
		return nil, false
	}
	ctx, cancel := context.WithCancelCause(transport.Context())
	id := a.inbound + "/" + strconv.FormatUint(globalSessionID.Add(1), 10)
	return &session{id: id, routeID: routeID, transport: transport, ctx: ctx, cancel: cancel}, true
}

func (a *Adapter) TCPContext(ctx context.Context, value hyServer.Session, request hyServer.RequestInfo) (net.Conn, error) {
	s, ok := sessionFrom(value)
	if !ok {
		return nil, fmt.Errorf("invalid hysteria2 session")
	}
	return a.router.TCPContext(ctx, s.routeID, request.Target)
}

func (a *Adapter) UDPContext(ctx context.Context, value hyServer.Session, request hyServer.RequestInfo) (hyServer.UDPConn, error) {
	s, ok := sessionFrom(value)
	if !ok {
		return nil, fmt.Errorf("invalid hysteria2 session")
	}
	return a.router.UDPContext(ctx, s.routeID, request.Target)
}

func (a *Adapter) LogTrafficContext(ctx context.Context, value hyServer.Session, _ hyServer.RequestInfo, tx, rx uint64) bool {
	s, ok := sessionFrom(value)
	if !ok {
		return false
	}
	return a.traffic.LogTrafficContext(ctx, s.routeID, tx, rx)
}

func (a *Adapter) LogOnlineStateSession(value hyServer.Session, online bool) {
	if s, ok := sessionFrom(value); ok {
		a.traffic.LogOnlineState(s.routeID, online)
	}
}

func (a *Adapter) ConnectSession(transport hyServer.Transport, value hyServer.Session, tx uint64) {
	if s, ok := sessionFrom(value); ok {
		a.tracker.ConnectSession(s.id, a.inbound, transport.RemoteAddr(), s.routeID)
		a.logger.Info("client connected", zap.String("session", s.id), zap.String("inbound", a.inbound), zap.String("user", s.routeID), zap.Uint64("tx", tx))
	}
}

func (a *Adapter) DisconnectSession(_ hyServer.Transport, value hyServer.Session, err error) {
	if s, ok := sessionFrom(value); ok {
		a.tracker.DisconnectSession(s.id)
		a.logger.Info("client disconnected", zap.String("session", s.id), zap.String("inbound", a.inbound), zap.Error(err))
	}
}

func (a *Adapter) TCPRequestSession(value hyServer.Session, request hyServer.RequestInfo) {
	a.startRequest(value, request, "TCP")
}

func (a *Adapter) TCPErrorSession(value hyServer.Session, request hyServer.RequestInfo, _ error) {
	a.stopRequest(value, request)
}

func (a *Adapter) UDPRequestSession(value hyServer.Session, request hyServer.RequestInfo) {
	a.startRequest(value, request, "UDP")
}

func (a *Adapter) UDPErrorSession(value hyServer.Session, request hyServer.RequestInfo, _ error) {
	a.stopRequest(value, request)
}

func (a *Adapter) startRequest(value hyServer.Session, request hyServer.RequestInfo, protocol string) {
	if s, ok := sessionFrom(value); ok {
		a.tracker.StartRequest(s.id, request.ID, protocol, request.Target)
	}
}

func (a *Adapter) stopRequest(value hyServer.Session, request hyServer.RequestInfo) {
	if s, ok := sessionFrom(value); ok {
		a.tracker.StopRequest(s.id, request.ID)
	}
}

var (
	_ hyServer.SessionAuthenticator = (*Adapter)(nil)
	_ hyServer.SessionOutbound      = (*Adapter)(nil)
	_ hyServer.SessionTrafficLogger = (*Adapter)(nil)
	_ hyServer.SessionEventLogger   = (*Adapter)(nil)
)
