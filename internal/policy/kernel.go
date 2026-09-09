// Package policy owns the authenticated Gateway data-plane boundary.
package policy

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/clayicarus/proxy-gateway/internal/auth"
	"github.com/clayicarus/proxy-gateway/internal/config"
	"github.com/clayicarus/proxy-gateway/internal/connection"
	"github.com/clayicarus/proxy-gateway/internal/outbound"
	"github.com/clayicarus/proxy-gateway/internal/storage"
	"github.com/clayicarus/proxy-gateway/internal/traffic"
	"go.uber.org/zap"
)

// Kernel is the protocol-neutral authenticated data-plane boundary. Protocol
// adapters receive only this type and an opaque Session; they cannot select an
// outbound or submit traffic for an arbitrary username:node string.
type Kernel struct {
	auth      *auth.Authenticator
	traffic   *traffic.TrafficLogger
	outbounds *outbound.OutboundFactory
	tracker   *connection.Tracker
	startup   map[string]config.UserConfig
	logger    *zap.Logger

	nextSession atomic.Uint64
	updateMu    sync.Mutex
}

// Session is an authenticated, inbound-bound capability. Its fields remain
// private so adapters cannot manufacture a route authorization.
type Session struct {
	owner   *Kernel
	id      string
	routeID string
	inbound string
}

func (s *Session) ID() string { return s.id }

func New(users map[string]config.UserConfig, nodes map[string]config.NodeConfig, store *storage.SQLiteStore, logger *zap.Logger, location *time.Location) *Kernel {
	authenticator := auth.NewAuthenticator(users, logger)
	return &Kernel{
		auth:      authenticator,
		traffic:   traffic.NewTrafficLoggerWithAuthenticator(authenticator, store, logger, location),
		outbounds: outbound.NewOutboundFactory(nodes, logger),
		tracker:   connection.NewTracker(),
		startup:   copyUsers(users),
		logger:    logger,
	}
}

func (k *Kernel) Authenticate(inbound string, addr net.Addr, proof string, tx uint64) (*Session, bool) {
	ok, routeID := k.auth.Authenticate(addr, proof, tx)
	if !ok {
		return nil, false
	}
	sequence := k.nextSession.Add(1)
	return &Session{owner: k, id: fmt.Sprintf("%s/%d", inbound, sequence), routeID: routeID, inbound: inbound}, true
}

func (k *Kernel) OpenTCP(ctx context.Context, session *Session, target string) (net.Conn, error) {
	if !k.owns(session) {
		return nil, fmt.Errorf("invalid gateway session")
	}
	ob, err := k.outboundFor(session)
	if err != nil {
		return nil, err
	}
	return ob.TCPContext(ctx, target)
}

func (k *Kernel) OpenUDP(ctx context.Context, session *Session, target string) (outbound.UDPConn, error) {
	if !k.owns(session) {
		return nil, fmt.Errorf("invalid gateway session")
	}
	ob, err := k.outboundFor(session)
	if err != nil {
		return nil, err
	}
	return ob.UDPContext(ctx, target)
}

func (k *Kernel) Admit(ctx context.Context, session *Session, tx, rx uint64) bool {
	return k.owns(session) && k.traffic.LogTrafficContext(ctx, session.routeID, tx, rx)
}

func (k *Kernel) Online(session *Session, online bool) {
	if k.owns(session) {
		k.traffic.LogOnlineState(session.routeID, online)
	}
}

func (k *Kernel) Connected(session *Session, addr net.Addr, tx uint64) {
	if !k.owns(session) {
		return
	}
	k.tracker.ConnectSession(session.id, session.inbound, addr, session.routeID)
	k.logger.Info("client connected", zap.String("session", session.id), zap.String("inbound", session.inbound), zap.String("user", session.routeID), zap.Uint64("tx", tx))
}

func (k *Kernel) Disconnected(session *Session, err error) {
	if !k.owns(session) {
		return
	}
	k.tracker.DisconnectSession(session.id)
	k.logger.Info("client disconnected", zap.String("session", session.id), zap.String("inbound", session.inbound), zap.Error(err))
}

func (k *Kernel) StartRequest(session *Session, requestID uint64, protocol, target string) {
	if k.owns(session) {
		k.tracker.StartRequest(session.id, requestID, protocol, target)
	}
}

func (k *Kernel) StopRequest(session *Session, requestID uint64) {
	if k.owns(session) {
		k.tracker.StopRequest(session.id, requestID)
	}
}

// UpdateUsers atomically publishes the lifecycle fields for all consumers of
// the kernel while retaining the restart-applied authorization topology.
func (k *Kernel) UpdateUsers(loaded map[string]config.UserConfig) {
	k.updateMu.Lock()
	defer k.updateMu.Unlock()
	previous := k.auth.Snapshot()
	updated := RefreshSnapshot(k.startup, loaded)
	k.auth.UpdateUsers(updated)
	k.traffic.NotifyUsersUpdated(previous, updated)
}

func (k *Kernel) Warmup(ctx context.Context) error             { return k.outbounds.Warmup(ctx) }
func (k *Kernel) CloseOutbounds()                              { k.outbounds.Close() }
func (k *Kernel) StopAdmission()                               { k.traffic.StopAdmission() }
func (k *Kernel) StopTraffic(ctx context.Context) error        { return k.traffic.StopContext(ctx) }
func (k *Kernel) Traffic() *traffic.TrafficLogger              { return k.traffic }
func (k *Kernel) Tracker() *connection.Tracker                 { return k.tracker }
func (k *Kernel) NodeStatuses() map[string]outbound.NodeStatus { return k.outbounds.NodeStatuses() }

func (k *Kernel) owns(session *Session) bool { return session != nil && session.owner == k }

func (k *Kernel) outboundFor(session *Session) (outbound.Outbound, error) {
	_, node := auth.ParseID(session.routeID)
	if node == "" {
		return nil, fmt.Errorf("session has no authorized route")
	}
	return k.outbounds.Get(node)
}

func copyUsers(users map[string]config.UserConfig) map[string]config.UserConfig {
	result := make(map[string]config.UserConfig, len(users))
	for username, user := range users {
		user.Routes = append([]string(nil), user.Routes...)
		result[username] = user
	}
	return result
}

// RefreshSnapshot applies live lifecycle changes while preserving users and
// route authorization from the restart-applied topology.
func RefreshSnapshot(startup, loaded map[string]config.UserConfig) map[string]config.UserConfig {
	updated := make(map[string]config.UserConfig, len(startup))
	for username, startupUser := range startup {
		if user, ok := loaded[username]; ok {
			user.Routes = append([]string(nil), startupUser.Routes...)
			updated[username] = user
			continue
		}
		startupUser.Routes = append([]string(nil), startupUser.Routes...)
		startupUser.Disabled = true
		updated[username] = startupUser
	}
	return updated
}
