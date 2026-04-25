package router

import (
	"net"
	"testing"

	"github.com/hy2-gateway/internal/config"
	"go.uber.org/zap"
)

func TestDirectOutbound_TCP(t *testing.T) {
	logger := zap.NewNop()
	d := &DirectOutbound{logger: logger}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			conn.Write([]byte("hello"))
			conn.Close()
		}
	}()

	conn, err := d.TCP(ln.Addr().String())
	if err != nil {
		t.Fatalf("direct TCP failed: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 5)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(buf[:n]) != "hello" {
		t.Errorf("expected 'hello', got %q", string(buf[:n]))
	}
}

func TestDirectOutbound_UDP(t *testing.T) {
	logger := zap.NewNop()
	d := &DirectOutbound{logger: logger}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create UDP listener: %v", err)
	}
	defer pc.Close()

	targetAddr := pc.LocalAddr().String()

	go func() {
		buf := make([]byte, 1024)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		pc.WriteTo(buf[:n], addr)
	}()

	udpConn, err := d.UDP(targetAddr)
	if err != nil {
		t.Fatalf("direct UDP failed: %v", err)
	}
	defer udpConn.Close()

	_, err = udpConn.WriteTo([]byte("ping"), targetAddr)
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	buf := make([]byte, 1024)
	n, _, err := udpConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(buf[:n]) != "ping" {
		t.Errorf("expected 'ping', got %q", string(buf[:n]))
	}
}

func TestOutboundFactory_Direct(t *testing.T) {
	logger := zap.NewNop()
	nodes := map[string]config.NodeConfig{
		"my_direct": {Type: "direct"},
	}
	f := NewOutboundFactory(nodes, logger)

	ob, err := f.Get("direct")
	if err != nil {
		t.Fatalf("get direct failed: %v", err)
	}
	if ob == nil {
		t.Fatal("expected non-nil outbound")
	}

	ob2, err := f.Get("my_direct")
	if err != nil {
		t.Fatalf("get my_direct failed: %v", err)
	}
	if ob2 == nil {
		t.Fatal("expected non-nil outbound for my_direct")
	}
}

func TestOutboundFactory_Unknown(t *testing.T) {
	logger := zap.NewNop()
	nodes := map[string]config.NodeConfig{}
	f := NewOutboundFactory(nodes, logger)

	_, err := f.Get("nonexistent")
	if err == nil {
		t.Error("expected error for unknown node")
	}
}

func TestRoutingOutbound_UserContext(t *testing.T) {
	logger := zap.NewNop()
	nodes := map[string]config.NodeConfig{}

	r := NewRouter(map[string]config.UserConfig{
		"alice": {Password: "p", Routes: []string{"direct"}},
	}, logger)
	f := NewOutboundFactory(nodes, logger)
	ro := NewRoutingOutbound(r, f, logger)

	addr := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 12345}

	// ID is now "username:node_name"
	ro.SetUserContext(addr, "alice:direct")

	// Create a local listener for the test
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	// Set request context (simulating EventLogger.TCPRequest)
	SetRequestContext(addr, "alice:direct", ln.Addr().String())

	conn, err := ro.TCP(ln.Addr().String())
	if err != nil {
		t.Fatalf("routing TCP failed: %v", err)
	}
	conn.Close()

	ro.ClearUserContext(addr)
}
