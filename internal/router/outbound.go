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
//	handleTCPRequest() calls EventLogger.TCPRequest() BEFORE Outbound.TCP()
//
// The event callback hands one context to the immediately following outbound
// call. The one-slot channel serializes this handoff so concurrent requests to
// the same target cannot exchange identities.
type RoutingOutbound struct {
	router         *Router
	factory        *OutboundFactory
	requestContext chan outboundRequestContext
	logger         *zap.Logger
}

type outboundRequestContext struct {
	clientAddr string
	id         string
	reqAddr    string
	network    string
}

// NewRoutingOutbound creates a new routing-aware outbound.
func NewRoutingOutbound(router *Router, factory *OutboundFactory, logger *zap.Logger) *RoutingOutbound {
	return &RoutingOutbound{
		router:         router,
		factory:        factory,
		requestContext: make(chan outboundRequestContext, 1),
		logger:         logger,
	}
}

// GetOutboundForID returns the appropriate outbound for an authenticated ID.
func (ro *RoutingOutbound) GetOutboundForID(id string) (hyServer.Outbound, error) {
	route, err := ro.router.GetRoute(id)
	if err != nil {
		return nil, err
	}
	return ro.factory.Get(route)
}

// TCP implements server.Outbound.
func (ro *RoutingOutbound) TCP(reqAddr string) (net.Conn, error) {
	id, err := ro.takeRequestContext("tcp", reqAddr)
	if err != nil {
		return nil, err
	}

	ob, err := ro.GetOutboundForID(id)
	if err != nil {
		return nil, err
	}

	ro.logger.Debug("routing TCP request",
		zap.String("id", id),
		zap.String("reqAddr", reqAddr),
	)

	conn, err := ob.TCP(reqAddr)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// UDP implements server.Outbound.
func (ro *RoutingOutbound) UDP(reqAddr string) (hyServer.UDPConn, error) {
	id, err := ro.takeRequestContext("udp", reqAddr)
	if err != nil {
		return nil, err
	}

	ob, err := ro.GetOutboundForID(id)
	if err != nil {
		return nil, err
	}

	ro.logger.Debug("routing UDP request",
		zap.String("id", id),
		zap.String("reqAddr", reqAddr),
	)

	conn, err := ob.UDP(reqAddr)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// SetRequestContext is called by EventLogger.TCPRequest/UDPRequest
// to associate exactly one request with the immediately following Outbound
// call. A single-slot handoff prevents concurrent requests for the same target
// from consuming each other's user identity.
func (ro *RoutingOutbound) SetRequestContext(addr net.Addr, id, network, reqAddr string) {
	ro.requestContext <- outboundRequestContext{
		clientAddr: addr.String(),
		id:         id,
		reqAddr:    reqAddr,
		network:    network,
	}
}

func (ro *RoutingOutbound) takeRequestContext(network, reqAddr string) (string, error) {
	select {
	case current := <-ro.requestContext:
		if current.network != network || current.reqAddr != reqAddr {
			ro.logger.Error("routing request context mismatch",
				zap.String("clientAddr", current.clientAddr),
				zap.String("id", current.id),
				zap.String("contextNetwork", current.network),
				zap.String("requestNetwork", network),
				zap.String("contextAddr", current.reqAddr),
				zap.String("requestAddr", reqAddr),
			)
			return "", fmt.Errorf("routing request context mismatch")
		}
		return current.id, nil
	default:
		ro.logger.Error("routing request context missing",
			zap.String("network", network),
			zap.String("reqAddr", reqAddr),
		)
		return "", fmt.Errorf("routing request context missing")
	}
}
