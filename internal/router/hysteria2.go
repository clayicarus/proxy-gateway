package router

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	hyClient "github.com/apernet/hysteria/core/v2/client"
	"github.com/clayicarus/proxy-gateway/internal/config"
	"go.uber.org/zap"
)

// Compile-time check.
// Hysteria2Outbound is one established connection to a remote Hysteria2 node.
// Reconnection and DNS refresh are owned by the node entry in factory.go.
type Hysteria2Outbound struct {
	cfg    *config.Hysteria2OutboundConfig
	client hyClient.ContextClient
	logger *zap.Logger

	mu     sync.Mutex
	closed bool
}

func newHysteria2Outbound(cfg *config.Hysteria2OutboundConfig, serverAddr *net.UDPAddr, sni string, logger *zap.Logger) (*Hysteria2Outbound, error) {
	return newHysteria2OutboundContext(context.Background(), cfg, serverAddr, sni, logger)
}

func newHysteria2OutboundContext(ctx context.Context, cfg *config.Hysteria2OutboundConfig, serverAddr *net.UDPAddr, sni string, logger *zap.Logger) (*Hysteria2Outbound, error) {
	client, info, err := hyClient.NewClientContext(ctx, &hyClient.Config{
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
	return h.TCPContext(context.Background(), reqAddr)
}

func (h *Hysteria2Outbound) TCPContext(ctx context.Context, reqAddr string) (net.Conn, error) {
	h.logger.Debug("hy2 outbound TCP",
		zap.String("remote", h.cfg.Addr),
		zap.String("reqAddr", reqAddr),
	)
	return h.client.TCPContext(ctx, reqAddr)
}

// UDP implements server.Outbound.
// Creates a new UDP session on the existing QUIC connection and wraps
// the HyUDPConn into a server.UDPConn compatible interface.
func (h *Hysteria2Outbound) UDP(reqAddr string) (UDPConn, error) {
	return h.UDPContext(context.Background(), reqAddr)
}

func (h *Hysteria2Outbound) UDPContext(_ context.Context, reqAddr string) (UDPConn, error) {
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
	err := h.client.Close()
	return errors.Join(err, h.client.Wait(context.Background()))
}

// hyUDPConnAdapter adapts hyClient.HyUDPConn (Send/Receive) to
// the protocol-neutral UDP association contract (ReadFrom/WriteTo/Close).
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
