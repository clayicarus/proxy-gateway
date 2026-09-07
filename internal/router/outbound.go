package router

import (
	"context"
	"net"

	"go.uber.org/zap"
)

// UDPConn is the protocol-neutral datagram association required by Gateway
// egress. Protocol adapters may convert it to their library's identical
// interface at their boundary.
type UDPConn interface {
	ReadFrom([]byte) (int, string, error)
	WriteTo([]byte, string) (int, error)
	Close() error
}

// Outbound is the protocol-neutral outbound contract.
type Outbound interface {
	TCP(string) (net.Conn, error)
	UDP(string) (UDPConn, error)
}

type contextualOutbound interface {
	TCPContext(context.Context, string) (net.Conn, error)
	UDPContext(context.Context, string) (UDPConn, error)
}

// Service resolves an explicitly authenticated route and opens its outbound.
// It deliberately has no protocol callback or mutable request-handoff state.
type Service struct {
	router  *Router
	factory *OutboundFactory
	logger  *zap.Logger
}

func NewService(router *Router, factory *OutboundFactory, logger *zap.Logger) *Service {
	return &Service{router: router, factory: factory, logger: logger}
}

// OutboundForID returns the outbound authorized for one authenticated route.
func (s *Service) OutboundForID(id string) (Outbound, error) {
	route, err := s.router.GetRoute(id)
	if err != nil {
		return nil, err
	}
	return s.factory.Get(route)
}

func (s *Service) TCPContext(ctx context.Context, id, reqAddr string) (net.Conn, error) {
	ob, err := s.OutboundForID(id)
	if err != nil {
		return nil, err
	}
	s.logger.Debug("routing TCP request",
		zap.String("id", id),
		zap.String("reqAddr", reqAddr),
	)
	if contextual, ok := ob.(contextualOutbound); ok {
		return contextual.TCPContext(ctx, reqAddr)
	}
	return ob.TCP(reqAddr)
}

func (s *Service) UDPContext(ctx context.Context, id, reqAddr string) (UDPConn, error) {
	ob, err := s.OutboundForID(id)
	if err != nil {
		return nil, err
	}
	s.logger.Debug("routing UDP request",
		zap.String("id", id),
		zap.String("reqAddr", reqAddr),
	)
	if contextual, ok := ob.(contextualOutbound); ok {
		return contextual.UDPContext(ctx, reqAddr)
	}
	return ob.UDP(reqAddr)
}
