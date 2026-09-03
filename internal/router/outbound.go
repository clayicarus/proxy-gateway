package router

import (
	"fmt"
	"net"

	hyServer "github.com/apernet/hysteria/core/v2/server"
	"go.uber.org/zap"
)

// Compile-time check that RoutingOutbound implements server.Outbound.
var _ hyServer.Outbound = (*RoutingOutbound)(nil)

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
