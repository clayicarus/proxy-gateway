package router

import (
	"context"
	"net"

	"github.com/clayicarus/proxy-gateway/internal/outbound"
	"go.uber.org/zap"
)

// Service resolves an explicitly authenticated route and opens its outbound.
// It deliberately has no protocol callback or mutable request-handoff state.
type Service struct {
	router  *Router
	factory *outbound.OutboundFactory
	logger  *zap.Logger
}

func NewService(router *Router, factory *outbound.OutboundFactory, logger *zap.Logger) *Service {
	return &Service{router: router, factory: factory, logger: logger}
}

// OutboundForID returns the outbound authorized for one authenticated route.
func (s *Service) OutboundForID(id string) (outbound.Outbound, error) {
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
	if contextual, ok := ob.(outbound.ContextualOutbound); ok {
		return contextual.TCPContext(ctx, reqAddr)
	}
	return ob.TCP(reqAddr)
}

func (s *Service) UDPContext(ctx context.Context, id, reqAddr string) (outbound.UDPConn, error) {
	ob, err := s.OutboundForID(id)
	if err != nil {
		return nil, err
	}
	s.logger.Debug("routing UDP request",
		zap.String("id", id),
		zap.String("reqAddr", reqAddr),
	)
	if contextual, ok := ob.(outbound.ContextualOutbound); ok {
		return contextual.UDPContext(ctx, reqAddr)
	}
	return ob.UDP(reqAddr)
}
