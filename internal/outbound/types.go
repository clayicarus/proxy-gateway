package outbound

import (
	"context"
	"net"
)

// UDPConn is the protocol-neutral datagram association required by Gateway
// egress. Protocol adapters convert it to their library's identical interface
// only at the protocol boundary.
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

// ContextualOutbound supports cancellation while opening a request.
type ContextualOutbound interface {
	TCPContext(context.Context, string) (net.Conn, error)
	UDPContext(context.Context, string) (UDPConn, error)
}
