package trojan

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/clayicarus/proxy-gateway/internal/config"
	"github.com/clayicarus/proxy-gateway/internal/policy"
	"go.uber.org/zap"
)

func TestServiceRelaysThroughKernelAndAccountsTraffic(t *testing.T) {
	target := startEchoServer(t)
	service, kernel := startService(t, nil)

	client := dialService(t, service)
	payload := []byte("Trojan adapter through policy kernel")
	if _, err := client.Write(trojanConnectRequest(t, "alice", "direct", "secret", target, payload)); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(payload))
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != string(payload) {
		t.Fatalf("response = %q, want %q", response, payload)
	}
	stats := kernel.Traffic().GetSnapshot("alice:direct")
	if stats == nil || stats.TxBytes != uint64(len(payload)) || stats.RxBytes != uint64(len(payload)) {
		t.Fatalf("traffic = %#v, want tx/rx %d", stats, len(payload))
	}
}

func TestServiceRelaysUDPAssociationToMultipleTargets(t *testing.T) {
	first := startUDPEchoServer(t)
	second := startUDPEchoServer(t)
	service, kernel := startService(t, nil)

	client := dialService(t, service)
	if _, err := client.Write(trojanUDPAssociateRequest(t, "alice", "direct", "secret")); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(client)
	buffer := make([]byte, MaxUDPPayloadSize)
	expected := 0
	for _, exchange := range []struct {
		target  string
		payload string
	}{
		{target: first, payload: "first datagram"},
		{target: second, payload: "second datagram"},
		{target: first, payload: "first datagram again"},
	} {
		packet, err := AppendPacket(nil, exchange.target, []byte(exchange.payload))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Write(packet); err != nil {
			t.Fatal(err)
		}
		source, read, err := ReadPacket(reader, buffer)
		if err != nil {
			t.Fatalf("ReadPacket for %s: %v", exchange.target, err)
		}
		if source != exchange.target {
			t.Fatalf("source = %q, want %q", source, exchange.target)
		}
		if string(buffer[:read]) != exchange.payload {
			t.Fatalf("payload = %q, want %q", buffer[:read], exchange.payload)
		}
		expected += len(exchange.payload)
	}

	stats := kernel.Traffic().GetSnapshot("alice:direct")
	if stats == nil || stats.TxBytes != uint64(expected) || stats.RxBytes != uint64(expected) {
		t.Fatalf("traffic = %#v, want tx/rx %d", stats, expected)
	}
	// Datagram accounting must exclude the Trojan packet framing itself.
	if stats.TxBytes == 0 {
		t.Fatal("no UDP payload was accounted")
	}
}

func TestServiceClosesIdleUDPAssociation(t *testing.T) {
	startUDPEchoServer(t)
	service, _ := startService(t, &config.TrojanInboundConfig{UDPIdleTimeout: 150 * time.Millisecond})

	client := dialService(t, service)
	if _, err := client.Write(trojanUDPAssociateRequest(t, "alice", "direct", "secret")); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("idle UDP association stayed open")
	}
}

func TestServiceRejectsUDPAssociationForUnauthorizedNode(t *testing.T) {
	service, kernel := startService(t, nil)

	client := dialService(t, service)
	// alice is only authorized for direct, so a credential derived for another
	// node must never reach an association or the traffic ledger.
	if _, err := client.Write(trojanUDPAssociateRequest(t, "alice", "node-a", "secret")); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("unauthorized UDP association stayed open")
	}
	if stats := kernel.Traffic().GetSnapshot("alice:node-a"); stats != nil {
		t.Fatalf("unauthorized association was accounted: %#v", stats)
	}
}

func TestServiceClosesUDPAssociationWhenPolicyRejectsDatagram(t *testing.T) {
	echo := startUDPEchoServer(t)
	service, kernel := startService(t, nil)

	client := dialService(t, service)
	if _, err := client.Write(trojanUDPAssociateRequest(t, "alice", "direct", "secret")); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(client)
	buffer := make([]byte, MaxUDPPayloadSize)
	allowed := []byte("allowed datagram")
	packet, err := AppendPacket(nil, echo, allowed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(packet); err != nil {
		t.Fatal(err)
	}
	if _, read, err := ReadPacket(reader, buffer); err != nil || string(buffer[:read]) != string(allowed) {
		t.Fatalf("first datagram = (%q, %v)", buffer[:read], err)
	}

	// Removing the user from the live snapshot disables it while keeping the
	// established association. The next datagram must be refused and must not
	// be accounted.
	kernel.UpdateUsers(map[string]config.UserConfig{})
	rejected, err := AppendPacket(nil, echo, []byte("rejected datagram"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(rejected); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadPacket(reader, buffer); err == nil {
		t.Fatal("association survived a policy rejection")
	}
	stats := kernel.Traffic().GetSnapshot("alice:direct")
	if stats == nil || stats.TxBytes != uint64(len(allowed)) {
		t.Fatalf("traffic = %#v, want tx %d", stats, len(allowed))
	}
}

func startService(t *testing.T, options *config.TrojanInboundConfig) (*Service, *policy.Kernel) {
	t.Helper()
	certificate, err := tls.LoadX509KeyPair(
		filepath.Join("..", "..", "..", "third_party", "hysteria-core", "internal", "integration_tests", "test.crt"),
		filepath.Join("..", "..", "..", "third_party", "hysteria-core", "internal", "integration_tests", "test.key"),
	)
	if err != nil {
		t.Fatal(err)
	}
	users := map[string]config.UserConfig{
		"alice": {Password: "secret", Routes: []string{"direct"}},
	}
	kernel := policy.New(users, nil, nil, zap.NewNop(), time.UTC)
	service, err := NewService(config.Inbound{
		Name: "trojan-test", Type: config.TrojanInboundType, Listen: "127.0.0.1:0", Trojan: options,
	}, certificate, kernel, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- service.Serve() }()
	t.Cleanup(func() {
		_ = service.Close()
		select {
		case err := <-serveDone:
			if err != nil {
				t.Errorf("Trojan Serve: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("Trojan server did not stop")
		}
	})
	return service, kernel
}

func dialService(t *testing.T, service *Service) *tls.Conn {
	t.Helper()
	client, err := tls.Dial("tcp", service.Addr().String(), &tls.Config{InsecureSkipVerify: true}) // #nosec G402 -- test fixture certificate
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func startEchoServer(t *testing.T) string {
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

func startUDPEchoServer(t *testing.T) string {
	t.Helper()
	connection, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	go func() {
		buffer := make([]byte, MaxUDPPayloadSize)
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

func trojanCredentialHeader(t *testing.T, username, node, password string) []byte {
	t.Helper()
	return []byte(HashPassword(RawPassword(username, node, password)) + "\r\n")
}

func trojanConnectRequest(t *testing.T, username, node, password, target string, payload []byte) []byte {
	t.Helper()
	request := append(trojanCredentialHeader(t, username, node, password), commandConnect)
	request = append(request, encodeAddress(t, target)...)
	request = append(request, '\r', '\n')
	return append(request, payload...)
}

func trojanUDPAssociateRequest(t *testing.T, username, node, password string) []byte {
	t.Helper()
	// The nominal UDP ASSOCIATE header address is unspecified; each datagram
	// carries its own destination.
	request := append(trojanCredentialHeader(t, username, node, password), commandUDPAssociate, addressIPv4, 0, 0, 0, 0, 0, 0)
	return append(request, '\r', '\n')
}

func encodeAddress(t *testing.T, target string) []byte {
	t.Helper()
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		t.Fatalf("test target %q is not IPv4", target)
	}
	encoded := append([]byte{addressIPv4}, ip...)
	var encodedPort [2]byte
	binary.BigEndian.PutUint16(encodedPort[:], uint16(port))
	return append(encoded, encodedPort[:]...)
}
