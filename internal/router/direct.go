package router

import (
	"context"
	"net"
	"time"

	"go.uber.org/zap"
)

// DirectOutbound connects directly to the target address.
type DirectOutbound struct {
	logger *zap.Logger
}

var directDialer = net.Dialer{Timeout: 10 * time.Second}

func (d *DirectOutbound) TCP(reqAddr string) (net.Conn, error) {
	return d.TCPContext(context.Background(), reqAddr)
}

func (d *DirectOutbound) TCPContext(ctx context.Context, reqAddr string) (net.Conn, error) {
	conn, err := directDialer.DialContext(ctx, "tcp", reqAddr)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (d *DirectOutbound) UDP(reqAddr string) (UDPConn, error) {
	return d.UDPContext(context.Background(), reqAddr)
}

func (d *DirectOutbound) UDPContext(ctx context.Context, _ string) (UDPConn, error) {
	conn, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp", "")
	if err != nil {
		return nil, err
	}
	return &directUDPConn{conn: conn}, nil
}

// directUDPConn wraps net.PacketConn as a protocol-neutral UDP association.
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
