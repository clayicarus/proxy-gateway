package event

import (
	"net"

	hyServer "github.com/apernet/hysteria/core/v2/server"
	"github.com/clayicarus/proxy-gateway/internal/connection"
	"github.com/clayicarus/proxy-gateway/internal/router"
	"go.uber.org/zap"
)

// Compile-time check that EventLogger implements server.EventLogger.
var _ hyServer.EventLogger = (*EventLogger)(nil)

// EventLogger implements the Hysteria2 EventLogger interface.
// It bridges the gap between Hysteria2's event system and our routing logic
// by setting user context before outbound connections are made.
type EventLogger struct {
	routingOutbound *router.RoutingOutbound
	connections     *connection.Tracker
	logger          *zap.Logger
}

// NewEventLogger creates a new EventLogger.
func NewEventLogger(routingOutbound *router.RoutingOutbound, logger *zap.Logger, trackers ...*connection.Tracker) *EventLogger {
	result := &EventLogger{
		routingOutbound: routingOutbound,
		logger:          logger,
	}
	if len(trackers) > 0 {
		result.connections = trackers[0]
	}
	return result
}

// Connect is called when a client connects.
func (e *EventLogger) Connect(addr net.Addr, id string, tx uint64) {
	if e.connections != nil {
		e.connections.Connect(addr, id)
	}
	e.logger.Info("client connected",
		zap.String("addr", addr.String()),
		zap.String("user", id),
		zap.Uint64("tx", tx),
	)
}

// Disconnect is called when a client disconnects.
func (e *EventLogger) Disconnect(addr net.Addr, id string, err error) {
	if e.connections != nil {
		e.connections.Disconnect(addr)
	}
	if err != nil {
		e.logger.Info("client disconnected",
			zap.String("addr", addr.String()),
			zap.String("user", id),
			zap.Error(err),
		)
	} else {
		e.logger.Info("client disconnected",
			zap.String("addr", addr.String()),
			zap.String("user", id),
		)
	}
}

// TCPRequest is called when a client makes a TCP proxy request.
// CRITICAL: This is called BEFORE Outbound.TCP (confirmed by reading
// hysteria2 server.go handleTCPRequest), so we set the request
// context here for the routing outbound to pick up.
func (e *EventLogger) TCPRequest(addr net.Addr, id, reqAddr string) {
	e.routingOutbound.SetRequestContext(addr, id, "tcp", reqAddr)
	if e.connections != nil {
		e.connections.StartTCP(addr, reqAddr)
	}
	e.logger.Debug("TCP request",
		zap.String("addr", addr.String()),
		zap.String("user", id),
		zap.String("reqAddr", reqAddr),
	)
}

// TCPError is called when a TCP proxy connection ends.
// Note: Hysteria2 calls this for ALL connection closures, not just errors.
// A nil error means the connection closed normally.
func (e *EventLogger) TCPError(addr net.Addr, id, reqAddr string, err error) {
	if e.connections != nil {
		e.connections.StopTCP(addr, reqAddr)
	}
	if err != nil {
		e.logger.Warn("TCP error",
			zap.String("addr", addr.String()),
			zap.String("user", id),
			zap.String("reqAddr", reqAddr),
			zap.Error(err),
		)
	} else {
		e.logger.Debug("TCP closed",
			zap.String("addr", addr.String()),
			zap.String("user", id),
			zap.String("reqAddr", reqAddr),
		)
	}
}

// UDPRequest is called when a client makes a UDP proxy request.
func (e *EventLogger) UDPRequest(addr net.Addr, id string, sessionID uint32, reqAddr string) {
	e.routingOutbound.SetRequestContext(addr, id, "udp", reqAddr)
	if e.connections != nil {
		e.connections.StartUDP(addr, sessionID, reqAddr)
	}
	e.logger.Debug("UDP request",
		zap.String("addr", addr.String()),
		zap.String("user", id),
		zap.Uint32("sessionID", sessionID),
		zap.String("reqAddr", reqAddr),
	)
}

// UDPError is called when a UDP proxy request encounters an error.
func (e *EventLogger) UDPError(addr net.Addr, id string, sessionID uint32, err error) {
	if e.connections != nil {
		e.connections.StopUDP(addr, sessionID)
	}
	e.logger.Warn("UDP error",
		zap.String("addr", addr.String()),
		zap.String("user", id),
		zap.Uint32("sessionID", sessionID),
		zap.Error(err),
	)
}
