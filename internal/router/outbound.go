package router

import (
	"fmt"
	"net"
	"sync"

	hyServer "github.com/apernet/hysteria/core/v2/server"
	"github.com/hy2-gateway/internal/config"
	"go.uber.org/zap"
)

// Compile-time check that RoutingOutbound implements server.Outbound.
var _ hyServer.Outbound = (*RoutingOutbound)(nil)

// OutboundFactory creates Outbound instances for different node types.
type OutboundFactory struct {
	nodes  map[string]config.NodeConfig
	cache  map[string]hyServer.Outbound
	mu     sync.RWMutex
	logger *zap.Logger
}

// NewOutboundFactory creates a factory from node configs.
func NewOutboundFactory(nodes map[string]config.NodeConfig, logger *zap.Logger) *OutboundFactory {
	return &OutboundFactory{
		nodes:  nodes,
		cache:  make(map[string]hyServer.Outbound),
		logger: logger,
	}
}

// Get returns an Outbound for the given node name.
func (f *OutboundFactory) Get(name string) (hyServer.Outbound, error) {
	if name == "direct" {
		return f.getDirect()
	}

	f.mu.RLock()
	if ob, ok := f.cache[name]; ok {
		f.mu.RUnlock()
		return ob, nil
	}
	f.mu.RUnlock()

	f.mu.Lock()
	defer f.mu.Unlock()

	// Double-check after acquiring write lock
	if ob, ok := f.cache[name]; ok {
		return ob, nil
	}

	nodeCfg, ok := f.nodes[name]
	if !ok {
		return nil, fmt.Errorf("unknown node: %s", name)
	}

	ob, err := f.createOutbound(name, nodeCfg)
	if err != nil {
		return nil, err
	}

	f.cache[name] = ob
	return ob, nil
}

func (f *OutboundFactory) getDirect() (hyServer.Outbound, error) {
	f.mu.RLock()
	if ob, ok := f.cache["direct"]; ok {
		f.mu.RUnlock()
		return ob, nil
	}
	f.mu.RUnlock()

	f.mu.Lock()
	defer f.mu.Unlock()

	if ob, ok := f.cache["direct"]; ok {
		return ob, nil
	}

	ob := &DirectOutbound{logger: f.logger}
	f.cache["direct"] = ob
	return ob, nil
}

func (f *OutboundFactory) createOutbound(name string, cfg config.NodeConfig) (hyServer.Outbound, error) {
	switch cfg.Type {
	case "direct":
		return &DirectOutbound{logger: f.logger}, nil
	case "socks5":
		if cfg.SOCKS5 == nil {
			return nil, fmt.Errorf("node %s: socks5 config is nil", name)
		}
		return NewSOCKS5Outbound(cfg.SOCKS5, f.logger), nil
	case "http":
		if cfg.HTTP == nil {
			return nil, fmt.Errorf("node %s: http config is nil", name)
		}
		return NewHTTPOutbound(cfg.HTTP, f.logger), nil
	case "hysteria2":
		if cfg.Hysteria2 == nil {
			return nil, fmt.Errorf("node %s: hysteria2 config is nil", name)
		}
		return NewHysteria2Outbound(cfg.Hysteria2, f.logger)
	default:
		return nil, fmt.Errorf("node %s: unsupported type %q", name, cfg.Type)
	}
}

// Close shuts down all cached outbounds that implement io.Closer.
func (f *OutboundFactory) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for name, ob := range f.cache {
		if closer, ok := ob.(interface{ Close() error }); ok {
			if err := closer.Close(); err != nil {
				f.logger.Warn("failed to close outbound",
					zap.String("name", name),
					zap.Error(err),
				)
			}
		}
	}
}

// RoutingOutbound is the main Outbound implementation that routes
// requests based on the current user context.
//
// Since Hysteria2's Outbound interface doesn't carry user info,
// we use the EventLogger callbacks to set user context before
// each outbound call. The key insight from reading the hy2 source:
//
//   handleTCPRequest() calls EventLogger.TCPRequest() BEFORE Outbound.TCP()
//
// So we record (clientAddr, reqAddr) → userId in TCPRequest,
// then look it up in TCP().
type RoutingOutbound struct {
	router  *Router
	factory *OutboundFactory
	// connCtx maps clientAddr -> userId for active connections
	connCtx sync.Map
	// Default outbound when user context is unavailable
	defaultOutbound hyServer.Outbound
	logger          *zap.Logger
}

// NewRoutingOutbound creates a new routing-aware outbound.
func NewRoutingOutbound(router *Router, factory *OutboundFactory, logger *zap.Logger) *RoutingOutbound {
	return &RoutingOutbound{
		router:          router,
		factory:         factory,
		defaultOutbound: &DirectOutbound{logger: logger},
		logger:          logger,
	}
}

// SetUserContext records the mapping from client address to user ID.
// Called by EventLogger.Connect.
func (ro *RoutingOutbound) SetUserContext(addr net.Addr, userId string) {
	ro.connCtx.Store(addr.String(), userId)
	ro.logger.Debug("user context set",
		zap.String("addr", addr.String()),
		zap.String("userId", userId),
	)
}

// ClearUserContext removes the mapping for a client address.
// Called by EventLogger.Disconnect.
func (ro *RoutingOutbound) ClearUserContext(addr net.Addr) {
	ro.connCtx.Delete(addr.String())
}

// GetOutboundForUser returns the appropriate outbound for a user.
func (ro *RoutingOutbound) GetOutboundForUser(userId string) (hyServer.Outbound, error) {
	route, err := ro.router.GetRoute(userId)
	if err != nil {
		return nil, err
	}
	return ro.factory.Get(route)
}

// TCP implements server.Outbound.
func (ro *RoutingOutbound) TCP(reqAddr string) (net.Conn, error) {
	userId := ro.getCurrentUser(reqAddr)
	if userId == "" {
		ro.logger.Warn("no user context for TCP request, using default outbound",
			zap.String("reqAddr", reqAddr),
		)
		return ro.defaultOutbound.TCP(reqAddr)
	}

	ob, err := ro.GetOutboundForUser(userId)
	if err != nil {
		ro.logger.Error("failed to get outbound for user",
			zap.String("userId", userId),
			zap.String("reqAddr", reqAddr),
			zap.Error(err),
		)
		return ro.defaultOutbound.TCP(reqAddr)
	}

	ro.logger.Debug("routing TCP request",
		zap.String("userId", userId),
		zap.String("reqAddr", reqAddr),
	)
	return ob.TCP(reqAddr)
}

// UDP implements server.Outbound.
func (ro *RoutingOutbound) UDP(reqAddr string) (hyServer.UDPConn, error) {
	userId := ro.getCurrentUser(reqAddr)
	if userId == "" {
		ro.logger.Warn("no user context for UDP request, using default outbound",
			zap.String("reqAddr", reqAddr),
		)
		return ro.defaultOutbound.UDP(reqAddr)
	}

	ob, err := ro.GetOutboundForUser(userId)
	if err != nil {
		ro.logger.Error("failed to get outbound for user",
			zap.String("userId", userId),
			zap.String("reqAddr", reqAddr),
			zap.Error(err),
		)
		return ro.defaultOutbound.UDP(reqAddr)
	}

	ro.logger.Debug("routing UDP request",
		zap.String("userId", userId),
		zap.String("reqAddr", reqAddr),
	)
	return ob.UDP(reqAddr)
}

// requestCtx maps a request key to userId.
// Set by EventLogger before Outbound is called.
var requestCtx sync.Map

// SetRequestContext is called by EventLogger.TCPRequest/UDPRequest
// to associate a request with a user before the Outbound is invoked.
func SetRequestContext(addr net.Addr, userId, reqAddr string) {
	key := fmt.Sprintf("%s->%s", addr.String(), reqAddr)
	requestCtx.Store(key, userId)
}

// ClearRequestContext removes the request context after use.
func ClearRequestContext(addr net.Addr, reqAddr string) {
	key := fmt.Sprintf("%s->%s", addr.String(), reqAddr)
	requestCtx.Delete(key)
}

// getCurrentUser tries to find the user for the current request.
func (ro *RoutingOutbound) getCurrentUser(reqAddr string) string {
	var found string
	requestCtx.Range(func(key, value any) bool {
		k := key.(string)
		suffix := "->" + reqAddr
		if len(k) > len(suffix) && k[len(k)-len(suffix):] == suffix {
			found = value.(string)
			requestCtx.Delete(key)
			return false
		}
		return true
	})
	return found
}
