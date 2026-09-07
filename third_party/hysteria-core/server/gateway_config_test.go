package server

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"
)

type gatewayPacketConn struct{}

func (*gatewayPacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (*gatewayPacketConn) WriteTo([]byte, net.Addr) (int, error)  { return 0, net.ErrClosed }
func (*gatewayPacketConn) Close() error                           { return nil }
func (*gatewayPacketConn) LocalAddr() net.Addr                    { return &net.UDPAddr{} }
func (*gatewayPacketConn) SetDeadline(time.Time) error            { return nil }
func (*gatewayPacketConn) SetReadDeadline(time.Time) error        { return nil }
func (*gatewayPacketConn) SetWriteDeadline(time.Time) error       { return nil }

type gatewayAuthenticator struct{}

func (*gatewayAuthenticator) AuthenticateSession(context.Context, Transport, string, uint64) (Session, bool) {
	return nil, false
}

type gatewayOutbound struct{}

func (*gatewayOutbound) TCPContext(context.Context, Session, RequestInfo) (net.Conn, error) {
	return nil, net.ErrClosed
}
func (*gatewayOutbound) UDPContext(context.Context, Session, RequestInfo) (UDPConn, error) {
	return nil, net.ErrClosed
}

type gatewayTraffic struct{}

func (*gatewayTraffic) LogTrafficContext(context.Context, Session, RequestInfo, uint64, uint64) bool {
	return true
}
func (*gatewayTraffic) LogOnlineStateSession(Session, bool) {}

type gatewayHook struct{}

func (*gatewayHook) Check(bool, string) bool               { return false }
func (*gatewayHook) TCP(HyStream, *string) ([]byte, error) { return nil, nil }
func (*gatewayHook) UDP([]byte, *string) error             { return nil }

func gatewayConfig() Config {
	return Config{TLSConfig: TLSConfig{Certificates: []tls.Certificate{{}}}, Conn: &gatewayPacketConn{}, SessionAuthenticator: &gatewayAuthenticator{}}
}

func TestGatewaySessionConfigRequiresCompleteCapabilities(t *testing.T) {
	cfg := gatewayConfig()
	if err := cfg.fill(); err == nil || !strings.Contains(err.Error(), "SessionOutbound") {
		t.Fatalf("missing outbound error = %v", err)
	}
	cfg = gatewayConfig()
	cfg.SessionOutbound = &gatewayOutbound{}
	if err := cfg.fill(); err == nil || !strings.Contains(err.Error(), "SessionTrafficLogger") {
		t.Fatalf("missing traffic error = %v", err)
	}
	cfg.SessionTrafficLogger = &gatewayTraffic{}
	cfg.RequestHook = &gatewayHook{}
	if err := cfg.fill(); err == nil || !strings.Contains(err.Error(), "RequestHook") {
		t.Fatalf("request hook error = %v", err)
	}
	cfg.RequestHook = nil
	if err := cfg.fill(); err != nil {
		t.Fatalf("complete session config rejected: %v", err)
	}
}
