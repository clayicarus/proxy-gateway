package hysteria2

import (
	"context"
	"fmt"
	"net"
	"sync"

	hyServer "github.com/apernet/hysteria/core/v2/server"
	"github.com/clayicarus/proxy-gateway/internal/policy"
)

// Adapter is the Hysteria2 protocol bridge. All gateway policy access goes
// through Kernel; the adapter never receives a route ID or raw outbound.
type Adapter struct {
	inbound string
	kernel  *policy.Kernel
}

func New(inbound string, kernel *policy.Kernel) *Adapter {
	return &Adapter{inbound: inbound, kernel: kernel}
}

type session struct {
	core      *policy.Session
	transport hyServer.Transport
	ctx       context.Context
	cancel    context.CancelCauseFunc
	closeOnce sync.Once
}

func (s *session) ID() string { return s.core.ID() }

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
	core, ok := a.kernel.Authenticate(a.inbound, transport.RemoteAddr(), proof, tx)
	if !ok {
		return nil, false
	}
	ctx, cancel := context.WithCancelCause(transport.Context())
	return &session{core: core, transport: transport, ctx: ctx, cancel: cancel}, true
}

func (a *Adapter) TCPContext(ctx context.Context, value hyServer.Session, request hyServer.RequestInfo) (net.Conn, error) {
	s, ok := sessionFrom(value)
	if !ok {
		return nil, fmt.Errorf("invalid hysteria2 session")
	}
	return a.kernel.OpenTCP(ctx, s.core, request.Target)
}

func (a *Adapter) UDPContext(ctx context.Context, value hyServer.Session, request hyServer.RequestInfo) (hyServer.UDPConn, error) {
	s, ok := sessionFrom(value)
	if !ok {
		return nil, fmt.Errorf("invalid hysteria2 session")
	}
	return a.kernel.OpenUDP(ctx, s.core, request.Target)
}

func (a *Adapter) LogTrafficContext(ctx context.Context, value hyServer.Session, _ hyServer.RequestInfo, tx, rx uint64) bool {
	s, ok := sessionFrom(value)
	if !ok {
		return false
	}
	return a.kernel.Admit(ctx, s.core, tx, rx)
}

func (a *Adapter) LogOnlineStateSession(value hyServer.Session, online bool) {
	if s, ok := sessionFrom(value); ok {
		a.kernel.Online(s.core, online)
	}
}

func (a *Adapter) ConnectSession(transport hyServer.Transport, value hyServer.Session, tx uint64) {
	if s, ok := sessionFrom(value); ok {
		a.kernel.Connected(s.core, transport.RemoteAddr(), tx)
	}
}

func (a *Adapter) DisconnectSession(_ hyServer.Transport, value hyServer.Session, err error) {
	if s, ok := sessionFrom(value); ok {
		a.kernel.Disconnected(s.core, err)
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
		a.kernel.StartRequest(s.core, request.ID, protocol, request.Target)
	}
}

func (a *Adapter) stopRequest(value hyServer.Session, request hyServer.RequestInfo) {
	if s, ok := sessionFrom(value); ok {
		a.kernel.StopRequest(s.core, request.ID)
	}
}

var (
	_ hyServer.SessionAuthenticator = (*Adapter)(nil)
	_ hyServer.SessionOutbound      = (*Adapter)(nil)
	_ hyServer.SessionTrafficLogger = (*Adapter)(nil)
	_ hyServer.SessionEventLogger   = (*Adapter)(nil)
)
