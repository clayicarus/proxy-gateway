package router

import (
	"fmt"
	"net"

	hyServer "github.com/apernet/hysteria/core/v2/server"
	"github.com/hy2-gateway/internal/config"
	"go.uber.org/zap"
)

// Compile-time check.
var _ hyServer.Outbound = (*SOCKS5Outbound)(nil)

// SOCKS5Outbound routes traffic through a SOCKS5 proxy.
type SOCKS5Outbound struct {
	addr     string
	username string
	password string
	logger   *zap.Logger
}

// NewSOCKS5Outbound creates a new SOCKS5 outbound.
func NewSOCKS5Outbound(cfg *config.SOCKS5Config, logger *zap.Logger) *SOCKS5Outbound {
	return &SOCKS5Outbound{
		addr:     cfg.Addr,
		username: cfg.Username,
		password: cfg.Password,
		logger:   logger,
	}
}

func (s *SOCKS5Outbound) TCP(reqAddr string) (net.Conn, error) {
	conn, err := net.Dial("tcp", s.addr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to socks5 proxy %s: %w", s.addr, err)
	}

	if err := s.handshake(conn, reqAddr); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 handshake failed: %w", err)
	}

	return conn, nil
}

func (s *SOCKS5Outbound) UDP(reqAddr string) (hyServer.UDPConn, error) {
	// SOCKS5 UDP association is complex; fall back to direct for now
	s.logger.Warn("SOCKS5 UDP not fully implemented, falling back to direct",
		zap.String("reqAddr", reqAddr),
	)
	return (&DirectOutbound{logger: s.logger}).UDP(reqAddr)
}

// handshake performs the SOCKS5 protocol handshake.
func (s *SOCKS5Outbound) handshake(conn net.Conn, reqAddr string) error {
	host, port, err := splitHostPort(reqAddr)
	if err != nil {
		return err
	}

	// Greeting
	var authMethod byte = 0x00 // No auth
	if s.username != "" {
		authMethod = 0x02 // Username/password
	}
	_, err = conn.Write([]byte{0x05, 0x01, authMethod})
	if err != nil {
		return err
	}

	// Read server choice
	buf := make([]byte, 2)
	if _, err := readFull(conn, buf); err != nil {
		return err
	}
	if buf[0] != 0x05 {
		return fmt.Errorf("unexpected SOCKS version: %d", buf[0])
	}

	// Username/password auth if needed
	if buf[1] == 0x02 {
		authMsg := []byte{0x01}
		authMsg = append(authMsg, byte(len(s.username)))
		authMsg = append(authMsg, []byte(s.username)...)
		authMsg = append(authMsg, byte(len(s.password)))
		authMsg = append(authMsg, []byte(s.password)...)
		if _, err := conn.Write(authMsg); err != nil {
			return err
		}
		authResp := make([]byte, 2)
		if _, err := readFull(conn, authResp); err != nil {
			return err
		}
		if authResp[1] != 0x00 {
			return fmt.Errorf("socks5 auth failed")
		}
	} else if buf[1] != 0x00 {
		return fmt.Errorf("unsupported auth method: %d", buf[1])
	}

	// Connect request
	req := []byte{0x05, 0x01, 0x00} // VER, CMD=CONNECT, RSV

	ip := net.ParseIP(host)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01) // IPv4
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04) // IPv6
			req = append(req, ip.To16()...)
		}
	} else {
		req = append(req, 0x03) // Domain
		req = append(req, byte(len(host)))
		req = append(req, []byte(host)...)
	}

	req = append(req, byte(port>>8), byte(port&0xff))

	if _, err := conn.Write(req); err != nil {
		return err
	}

	// Read response
	resp := make([]byte, 4)
	if _, err := readFull(conn, resp); err != nil {
		return err
	}
	if resp[1] != 0x00 {
		return fmt.Errorf("socks5 connect failed with code: %d", resp[1])
	}

	// Skip the bound address
	switch resp[3] {
	case 0x01:
		skip := make([]byte, 4+2)
		readFull(conn, skip)
	case 0x03:
		lenBuf := make([]byte, 1)
		readFull(conn, lenBuf)
		skip := make([]byte, int(lenBuf[0])+2)
		readFull(conn, skip)
	case 0x04:
		skip := make([]byte, 16+2)
		readFull(conn, skip)
	}

	return nil
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func splitHostPort(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	port := 0
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}
	if port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port: %s", portStr)
	}
	return host, port, nil
}
