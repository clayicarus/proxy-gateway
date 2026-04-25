package router

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"

	hyServer "github.com/apernet/hysteria/core/v2/server"
	"github.com/hy2-gateway/internal/config"
	"go.uber.org/zap"
)

// Compile-time check.
var _ hyServer.Outbound = (*HTTPOutbound)(nil)

// HTTPOutbound routes TCP traffic through an HTTP CONNECT proxy.
type HTTPOutbound struct {
	host     string
	username string
	password string
	insecure bool
	logger   *zap.Logger
}

// NewHTTPOutbound creates a new HTTP proxy outbound.
func NewHTTPOutbound(cfg *config.HTTPConfig, logger *zap.Logger) *HTTPOutbound {
	return &HTTPOutbound{
		host:     cfg.URL,
		insecure: cfg.Insecure,
		logger:   logger,
	}
}

func (h *HTTPOutbound) TCP(reqAddr string) (net.Conn, error) {
	conn, err := net.Dial("tcp", h.host)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to http proxy %s: %w", h.host, err)
	}

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", reqAddr, reqAddr)
	if h.username != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(h.username + ":" + h.password))
		connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", auth)
	}
	connectReq += "\r\n"

	if _, err := conn.Write([]byte(connectReq)); err != nil {
		conn.Close()
		return nil, err
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("http proxy response error: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("http proxy returned status %d", resp.StatusCode)
	}

	return conn, nil
}

func (h *HTTPOutbound) UDP(reqAddr string) (hyServer.UDPConn, error) {
	return nil, fmt.Errorf("HTTP proxy does not support UDP")
}
