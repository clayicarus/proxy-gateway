package e2e

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	hyServer "github.com/apernet/hysteria/core/v2/server"
	"github.com/clayicarus/proxy-gateway/internal/config"
	"github.com/clayicarus/proxy-gateway/internal/inbound/trojan"
	"github.com/clayicarus/proxy-gateway/internal/policy"
	"go.uber.org/zap"
)

// TestTrojanTwoHop_ThroughHysteria2Node validates the full Trojan data path:
//
//	Trojan client → Gateway (Trojan inbound) → Node (hy2 server) → target
//
// Both TCP CONNECT and UDP ASSOCIATE must use the explicitly authorized node
// instead of falling back to direct, and both must reach the shared ledger.
func TestTrojanTwoHop_ThroughHysteria2Node(t *testing.T) {
	logger := zap.NewNop()
	tcpTarget := startTCPEcho(t)
	udpTarget := startUDPEcho(t)

	nodeCert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("node certificate: %v", err)
	}
	gatewayCert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("gateway certificate: %v", err)
	}

	nodeUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("node listener: %v", err)
	}
	nodeServer, err := hyServer.NewServer(&hyServer.Config{
		TLSConfig:     hyServer.TLSConfig{Certificates: []tls.Certificate{nodeCert}},
		Conn:          nodeUDP,
		Authenticator: &simpleAuthenticator{password: "node_secret"},
	})
	if err != nil {
		t.Fatalf("node server: %v", err)
	}
	go func() { _ = nodeServer.Serve() }()
	defer nodeServer.Close()

	users := map[string]config.UserConfig{
		"alice": {Password: "alice_pass", Routes: []string{"node1"}},
	}
	nodes := map[string]config.NodeConfig{
		"node1": {
			Type:      "hysteria2",
			Hysteria2: &config.Hysteria2OutboundConfig{Addr: nodeUDP.LocalAddr().String(), Auth: "node_secret", Insecure: true},
		},
	}
	kernel := policy.New(users, nodes, nil, logger, time.UTC)
	warmupCtx, cancelWarmup := context.WithTimeout(context.Background(), 10*time.Second)
	if err := kernel.Warmup(warmupCtx); err != nil {
		cancelWarmup()
		kernel.CloseOutbounds()
		t.Fatalf("warm up node outbound: %v", err)
	}
	cancelWarmup()
	defer kernel.CloseOutbounds()

	service, err := trojan.NewService(config.Inbound{
		Name: "trojan-two-hop", Type: config.TrojanInboundType, Listen: "127.0.0.1:0",
	}, gatewayCert, kernel, logger)
	if err != nil {
		t.Fatalf("trojan inbound: %v", err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- service.Serve() }()
	defer func() {
		if err := service.Close(); err != nil {
			t.Errorf("close trojan inbound: %v", err)
		}
		select {
		case err := <-serveDone:
			if err != nil {
				t.Errorf("trojan Serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("trojan inbound did not stop")
		}
	}()

	credential := trojan.HashPassword(trojan.RawPassword("alice", "node1", "alice_pass")) + "\r\n"

	t.Run("tcp_connect_through_node", func(t *testing.T) {
		client := dialTrojan(t, service.Addr().String())
		request := append([]byte(credential), 0x01)
		request = append(request, encodeIPv4Address(t, tcpTarget)...)
		request = append(request, '\r', '\n')
		payload := []byte("trojan two-hop tcp")
		if _, err := client.Write(append(request, payload...)); err != nil {
			t.Fatalf("write request: %v", err)
		}
		response := make([]byte, len(payload))
		if err := client.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(client, response); err != nil {
			t.Fatalf("read echo: %v", err)
		}
		if string(response) != string(payload) {
			t.Fatalf("response = %q, want %q", response, payload)
		}
	})

	t.Run("udp_associate_through_node", func(t *testing.T) {
		client := dialTrojan(t, service.Addr().String())
		// Nominal UDP ASSOCIATE header: unspecified IPv4 address, port zero.
		request := append([]byte(credential), 0x03, 0x01, 0, 0, 0, 0, 0, 0, '\r', '\n')
		if _, err := client.Write(request); err != nil {
			t.Fatalf("write associate: %v", err)
		}
		if err := client.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatal(err)
		}
		reader := bufio.NewReader(client)
		buffer := make([]byte, trojan.MaxUDPPayloadSize)
		for _, payload := range []string{"trojan two-hop udp", "trojan two-hop udp again"} {
			packet, err := trojan.AppendPacket(nil, udpTarget, []byte(payload))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Write(packet); err != nil {
				t.Fatalf("write datagram: %v", err)
			}
			source, read, err := trojan.ReadPacket(reader, buffer)
			if err != nil {
				t.Fatalf("read datagram: %v", err)
			}
			if source != udpTarget {
				t.Fatalf("source = %q, want %q", source, udpTarget)
			}
			if string(buffer[:read]) != payload {
				t.Fatalf("payload = %q, want %q", buffer[:read], payload)
			}
		}
	})

	t.Run("traffic_attributed_to_node", func(t *testing.T) {
		stats := kernel.Traffic().GetSnapshot("alice:node1")
		if stats == nil || stats.TxBytes == 0 || stats.RxBytes == 0 {
			t.Fatalf("traffic for alice:node1 = %#v", stats)
		}
		if direct := kernel.Traffic().GetSnapshot("alice:direct"); direct != nil {
			t.Fatalf("traffic leaked to direct: %#v", direct)
		}
	})
}

func dialTrojan(t *testing.T, address string) *tls.Conn {
	t.Helper()
	client, err := tls.Dial("tcp", address, &tls.Config{InsecureSkipVerify: true}) // #nosec G402 -- self-signed test certificate
	if err != nil {
		t.Fatalf("dial trojan inbound: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func encodeIPv4Address(t *testing.T, target string) []byte {
	t.Helper()
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		t.Fatalf("target %q is not IPv4", target)
	}
	encoded := append([]byte{0x01}, ip...)
	var encodedPort [2]byte
	binary.BigEndian.PutUint16(encodedPort[:], uint16(port))
	return append(encoded, encodedPort[:]...)
}

func startTCPEcho(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				_, _ = io.Copy(connection, connection)
			}()
		}
	}()
	return listener.Addr().String()
}

func startUDPEcho(t *testing.T) string {
	t.Helper()
	connection, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	go func() {
		buffer := make([]byte, 65535)
		for {
			read, source, err := connection.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			if _, err := connection.WriteToUDP(buffer[:read], source); err != nil {
				return
			}
		}
	}()
	return connection.LocalAddr().String()
}
