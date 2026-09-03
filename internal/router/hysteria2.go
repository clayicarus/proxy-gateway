package router

import (
	"fmt"
	"net"
	"sync"

	hyClient "github.com/apernet/hysteria/core/v2/client"
	hyServer "github.com/apernet/hysteria/core/v2/server"
	"github.com/clayicarus/proxy-gateway/internal/config"
	"go.uber.org/zap"
)

// Compile-time check.
var _ hyServer.Outbound = (*Hysteria2Outbound)(nil)

// Hysteria2Outbound is one established connection to a remote Hysteria2 node.
// Reconnection and DNS refresh are owned by the node entry in factory.go.
type Hysteria2Outbound struct {
	cfg    *config.Hysteria2OutboundConfig
	client hyClient.Client
	logger *zap.Logger

	mu     sync.Mutex
	closed bool
}

func newHysteria2Outbound(cfg *config.Hysteria2OutboundConfig, serverAddr *net.UDPAddr, sni string, logger *zap.Logger) (*Hysteria2Outbound, error) {
	client, info, err := hyClient.NewClient(&hyClient.Config{
		ServerAddr: serverAddr,
		Auth:       cfg.Auth,
		TLSConfig: hyClient.TLSConfig{
			ServerName:         sni,
			InsecureSkipVerify: cfg.Insecure,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("hy2 outbound: %w", err)
	}
	logger.Info("hy2 outbound connected",
		zap.String("configuredAddr", cfg.Addr),
		zap.String("resolvedAddr", serverAddr.String()),
		zap.String("sni", sni),
		zap.Bool("udpEnabled", info.UDPEnabled),
		zap.Uint64("tx", info.Tx),
	)
	return &Hysteria2Outbound{cfg: cfg, client: client, logger: logger}, nil
}

// TCP implements server.Outbound.
// Opens a new QUIC stream on the existing connection to the remote node
// and sends a TCP proxy request.
func (h *Hysteria2Outbound) TCP(reqAddr string) (net.Conn, error) {
	h.logger.Debug("hy2 outbound TCP",
		zap.String("remote", h.cfg.Addr),
		zap.String("reqAddr", reqAddr),
	)
	return h.client.TCP(reqAddr)
}

// UDP implements server.Outbound.
// Creates a new UDP session on the existing QUIC connection and wraps
// the HyUDPConn into a server.UDPConn compatible interface.
func (h *Hysteria2Outbound) UDP(reqAddr string) (hyServer.UDPConn, error) {
	h.logger.Debug("hy2 outbound UDP",
		zap.String("remote", h.cfg.Addr),
		zap.String("reqAddr", reqAddr),
	)

	hyUDP, err := h.client.UDP()
	if err != nil {
		return nil, fmt.Errorf("hy2 outbound UDP: %w", err)
	}

	return &hyUDPConnAdapter{inner: hyUDP}, nil
}

// Close shuts down the hy2 client connection.
func (h *Hysteria2Outbound) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil
	}
	h.closed = true
	h.logger.Info("hy2 outbound closing", zap.String("addr", h.cfg.Addr))
	return h.client.Close()
}

// hyUDPConnAdapter adapts hyClient.HyUDPConn (Send/Receive) to
// hyServer.UDPConn (ReadFrom/WriteTo/Close).
type hyUDPConnAdapter struct {
	inner hyClient.HyUDPConn
}

func (a *hyUDPConnAdapter) ReadFrom(b []byte) (int, string, error) {
	data, addr, err := a.inner.Receive()
	if err != nil {
		return 0, "", err
	}
	n := copy(b, data)
	return n, addr, nil
}

func (a *hyUDPConnAdapter) WriteTo(b []byte, addr string) (int, error) {
	err := a.inner.Send(b, addr)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (a *hyUDPConnAdapter) Close() error {
	return a.inner.Close()
}
