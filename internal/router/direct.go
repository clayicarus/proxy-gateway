package router

import (
	"net"

	hyServer "github.com/apernet/hysteria/core/v2/server"
	"go.uber.org/zap"
)

// Compile-time check.
var _ hyServer.Outbound = (*DirectOutbound)(nil)

// DirectOutbound connects directly to the target address.
type DirectOutbound struct {
	logger *zap.Logger
}

func (d *DirectOutbound) TCP(reqAddr string) (net.Conn, error) {
	conn, err := net.Dial("tcp", reqAddr)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (d *DirectOutbound) UDP(reqAddr string) (hyServer.UDPConn, error) {
	conn, err := net.ListenPacket("udp", "")
	if err != nil {
		return nil, err
	}
	return &directUDPConn{conn: conn}, nil
}

// directUDPConn wraps net.PacketConn to implement hyServer.UDPConn.
type directUDPConn struct {
	conn net.PacketConn
}

func (c *directUDPConn) ReadFrom(b []byte) (int, string, error) {
	n, addr, err := c.conn.ReadFrom(b)
	if err != nil {
		return 0, "", err
	}
	return n, addr.String(), nil
}

func (c *directUDPConn) WriteTo(b []byte, addr string) (int, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return 0, err
	}
	return c.conn.WriteTo(b, udpAddr)
}

func (c *directUDPConn) Close() error {
	return c.conn.Close()
}
