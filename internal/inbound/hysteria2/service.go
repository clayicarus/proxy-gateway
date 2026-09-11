package hysteria2

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	hyServer "github.com/apernet/hysteria/core/v2/server"
	"github.com/clayicarus/proxy-gateway/internal/config"
	"github.com/clayicarus/proxy-gateway/internal/policy"
	"go.uber.org/zap"
)

// Service owns one bound Hysteria2 listener and its upstream server instance.
type Service struct {
	name       string
	conn       *net.UDPConn
	server     hyServer.Server
	masquerade *masquerade
}

func NewService(inbound config.Inbound, certificate tls.Certificate, kernel *policy.Kernel, logger *zap.Logger) (*Service, error) {
	addr, err := net.ResolveUDPAddr("udp", inbound.Listen)
	if err != nil {
		return nil, fmt.Errorf("resolve inbound %s listen: %w", inbound.Name, err)
	}
	masq, err := newMasquerade(inbound.Masquerade, inbound.Name, logger)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("inbound %s listen: %w", inbound.Name, err)
	}
	adapter := New(inbound.Name, kernel)
	server, err := hyServer.NewServer(&hyServer.Config{
		TLSConfig:   hyServer.TLSConfig{Certificates: []tls.Certificate{certificate}},
		QUICConfig:  buildQUICConfig(inbound.QUIC),
		Conn:        conn,
		MasqHandler: masq.Handler(),

		SessionAuthenticator: adapter,
		SessionOutbound:      adapter,
		SessionTrafficLogger: adapter,
		SessionEventLogger:   adapter,
	})
	if err != nil {
		_ = conn.Close()
		masq.Close()
		return nil, fmt.Errorf("construct inbound %s: %w", inbound.Name, err)
	}
	return &Service{name: inbound.Name, conn: conn, server: server, masquerade: masq}, nil
}

func (s *Service) Name() string { return s.name }

// Addr returns the bound UDP address for diagnostics and integration tests.
func (s *Service) Addr() net.Addr { return s.conn.LocalAddr() }

func (s *Service) Serve() error { return s.server.Serve() }

func (s *Service) Close() error {
	err := s.server.Close()
	s.masquerade.Close()
	return err
}

func (s *Service) Wait(ctx context.Context) error { return s.server.Wait(ctx) }

func buildQUICConfig(input *config.QUICConfig) hyServer.QUICConfig {
	config := hyServer.QUICConfig{}
	if input != nil {
		config.InitialStreamReceiveWindow = input.InitStreamReceiveWindow
		config.MaxStreamReceiveWindow = input.MaxStreamReceiveWindow
		config.InitialConnectionReceiveWindow = input.InitConnReceiveWindow
		config.MaxConnectionReceiveWindow = input.MaxConnReceiveWindow
		config.MaxIdleTimeout = input.MaxIdleTimeout
		config.MaxIncomingStreams = input.MaxIncomingStreams
		config.DisablePathMTUDiscovery = input.DisablePathMTUDiscovery
	}
	return config
}
