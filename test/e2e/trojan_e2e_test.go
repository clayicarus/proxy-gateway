package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	hyClient "github.com/apernet/hysteria/core/v2/client"
	hyServer "github.com/apernet/hysteria/core/v2/server"
	"github.com/clayicarus/proxy-gateway/internal/auth"
	"github.com/clayicarus/proxy-gateway/internal/config"
	"github.com/clayicarus/proxy-gateway/internal/connection"
	"github.com/clayicarus/proxy-gateway/internal/event"
	"github.com/clayicarus/proxy-gateway/internal/router"
	"github.com/clayicarus/proxy-gateway/internal/storage"
	"github.com/clayicarus/proxy-gateway/internal/traffic"
	"github.com/clayicarus/proxy-gateway/internal/trojan"
	"go.uber.org/zap"
)

func TestTrojanE2E_DirectTrafficLifecycleAndSQLiteFlush(t *testing.T) {
	targetAddr, targetAccepts := startEchoTarget(t)
	certificate, err := generateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	store, err := storage.NewSQLiteStore(t.TempDir()+"/trojan-e2e.db", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	users := map[string]config.UserConfig{
		"alice": {Password: "secret", Routes: []string{"direct"}, MaxBytes: 1 << 20},
	}
	trafficLogger := traffic.NewTrafficLogger(users, store, zap.NewNop())
	t.Cleanup(trafficLogger.Stop)
	tracker := connection.NewTracker()
	factory := router.NewOutboundFactory(nil, zap.NewNop())
	t.Cleanup(factory.Close)
	routing := router.NewRoutingOutbound(router.NewRouter(users, zap.NewNop()), factory, zap.NewNop())
	server := startTrojanServer(t, certificate, trojan.NewAuthenticator(users), routing, trafficLogger, tracker)

	client := dialTrojanTLS(t, server.Addr().String())
	payload := []byte("hello through Trojan direct")
	if err := writeTrojanConnect(client, trojan.RawPassword("alice", "direct", "secret"), targetAddr, payload); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(payload))
	if err := client.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != string(payload) {
		t.Fatalf("response = %q, want %q", response, payload)
	}
	if targetAccepts.Load() != 1 {
		t.Fatalf("target accepts = %d, want 1", targetAccepts.Load())
	}

	eventuallyE2E(t, 2*time.Second, func() bool {
		snapshot := trafficLogger.GetSnapshot("alice:direct")
		connections := tracker.Snapshots()
		return snapshot != nil && snapshot.TxBytes == uint64(len(payload)) && snapshot.RxBytes == uint64(len(payload)) &&
			snapshot.OnlineCount == 1 && len(connections) == 1 && len(connections[0].Requests) == 1
	})

	trafficLogger.Flush()
	tx, rx, err := store.GetSummary("alice", "direct")
	if err != nil {
		t.Fatal(err)
	}
	if tx != uint64(len(payload)) || rx != uint64(len(payload)) {
		t.Fatalf("SQLite traffic = %d/%d, want %d/%d", tx, rx, len(payload), len(payload))
	}

	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	eventuallyE2E(t, 2*time.Second, func() bool {
		snapshot := trafficLogger.GetSnapshot("alice:direct")
		return snapshot != nil && snapshot.OnlineCount == 0 && len(tracker.Snapshots()) == 0
	})
}

func TestTrojanE2E_Hysteria2NodeDoesNotFallBackToDirect(t *testing.T) {
	targetAddr, _ := startEchoTarget(t)
	nodeCertificate, err := generateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	nodePacketConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	nodeEvents := &recordingNodeEvents{}
	nodeServer, err := hyServer.NewServer(&hyServer.Config{
		TLSConfig:     hyServer.TLSConfig{Certificates: []tls.Certificate{nodeCertificate}},
		Conn:          nodePacketConn,
		Authenticator: &simpleAuthenticator{password: "node-secret"},
		EventLogger:   nodeEvents,
	})
	if err != nil {
		t.Fatal(err)
	}
	nodeServeDone := make(chan error, 1)
	go func() { nodeServeDone <- nodeServer.Serve() }()
	t.Cleanup(func() {
		_ = nodeServer.Close()
		select {
		case <-nodeServeDone:
		case <-time.After(2 * time.Second):
			t.Error("Hysteria2 node server did not stop")
		}
	})

	users := map[string]config.UserConfig{
		"alice": {Password: "secret", Routes: []string{"node1"}},
	}
	nodes := map[string]config.NodeConfig{
		"node1": {
			Type: "hysteria2",
			Hysteria2: &config.Hysteria2OutboundConfig{
				Addr:     nodePacketConn.LocalAddr().String(),
				Auth:     "node-secret",
				Insecure: true,
			},
		},
	}
	factory := router.NewOutboundFactory(nodes, zap.NewNop())
	t.Cleanup(factory.Close)
	warmupContext, cancelWarmup := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelWarmup()
	if err := factory.Warmup(warmupContext); err != nil {
		t.Fatal(err)
	}
	eventuallyE2E(t, 5*time.Second, func() bool {
		return factory.NodeStatuses()["node1"].State == router.NodeReady
	})

	trafficLogger := traffic.NewTrafficLogger(users, nil, zap.NewNop())
	t.Cleanup(trafficLogger.Stop)
	tracker := connection.NewTracker()
	routing := router.NewRoutingOutbound(router.NewRouter(users, zap.NewNop()), factory, zap.NewNop())
	gatewayCertificate, err := generateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	server := startTrojanServer(t, gatewayCertificate, trojan.NewAuthenticator(users), routing, trafficLogger, tracker)

	client := dialTrojanTLS(t, server.Addr().String())
	defer client.Close()
	payload := []byte("Trojan to Hysteria2 node")
	if err := writeTrojanConnect(client, trojan.RawPassword("alice", "node1", "secret"), targetAddr, payload); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(payload))
	if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != string(payload) {
		t.Fatalf("response = %q, want %q", response, payload)
	}
	eventuallyE2E(t, 2*time.Second, func() bool {
		count, target := nodeEvents.tcpSnapshot()
		return count == 1 && target == targetAddr
	})
	snapshot := trafficLogger.GetSnapshot("alice:node1")
	if snapshot == nil || snapshot.TxBytes != uint64(len(payload)) || snapshot.RxBytes != uint64(len(payload)) {
		t.Fatalf("unexpected node traffic snapshot: %#v", snapshot)
	}
}

func TestTrojanE2E_CredentialLifecycle(t *testing.T) {
	targetAddr, targetAccepts := startEchoTarget(t)
	certificate, err := generateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	users := map[string]config.UserConfig{
		"alice": {Password: "old", Routes: []string{"direct"}},
	}
	authenticator := trojan.NewAuthenticator(users)
	trafficLogger := traffic.NewTrafficLogger(users, nil, zap.NewNop())
	t.Cleanup(trafficLogger.Stop)
	factory := router.NewOutboundFactory(nil, zap.NewNop())
	t.Cleanup(factory.Close)
	routing := router.NewRoutingOutbound(router.NewRouter(users, zap.NewNop()), factory, zap.NewNop())
	server := startTrojanServer(t, certificate, authenticator, routing, trafficLogger, connection.NewTracker())

	expectTrojanRejected(t, server.Addr().String(), trojan.HashPassword("wrong password"), targetAddr)
	unauthorized := trojan.HashPassword(trojan.RawPassword("alice", "node1", "old"))
	expectTrojanRejected(t, server.Addr().String(), unauthorized, targetAddr)

	disabled := map[string]config.UserConfig{
		"alice": {Password: "old", Routes: []string{"direct"}, Disabled: true},
	}
	authenticator.UpdateUsers(disabled)
	trafficLogger.UpdateUsers(disabled)
	expectTrojanRejected(t, server.Addr().String(), trojan.HashPassword(trojan.RawPassword("alice", "direct", "old")), targetAddr)

	past := time.Now().Add(-time.Minute)
	expired := map[string]config.UserConfig{
		"alice": {Password: "old", Routes: []string{"direct"}, ExpiresAt: &past},
	}
	authenticator.UpdateUsers(expired)
	trafficLogger.UpdateUsers(expired)
	expectTrojanRejected(t, server.Addr().String(), trojan.HashPassword(trojan.RawPassword("alice", "direct", "old")), targetAddr)

	reset := map[string]config.UserConfig{
		"alice": {Password: "new", Routes: []string{"direct"}},
	}
	authenticator.UpdateUsers(reset)
	trafficLogger.UpdateUsers(reset)
	expectTrojanRejected(t, server.Addr().String(), trojan.HashPassword(trojan.RawPassword("alice", "direct", "old")), targetAddr)

	client := dialTrojanTLS(t, server.Addr().String())
	payload := []byte("new credential works")
	if err := writeTrojanConnect(client, trojan.RawPassword("alice", "direct", "new"), targetAddr, payload); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(payload))
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, response); err != nil || string(response) != string(payload) {
		t.Fatalf("new credential response=%q err=%v", response, err)
	}
	_ = client.Close()
	if targetAccepts.Load() != 1 {
		t.Fatalf("rejected credentials reached target; accepts=%d", targetAccepts.Load())
	}
}

func TestTrojanE2E_ExpiredExistingConnectionStopsBeforeForward(t *testing.T) {
	targetAddr, _ := startEchoTarget(t)
	certificate, err := generateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	users := map[string]config.UserConfig{
		"alice": {Password: "secret", Routes: []string{"direct"}, ExpiresAt: &future},
	}
	authenticator := trojan.NewAuthenticator(users)
	trafficLogger := traffic.NewTrafficLogger(users, nil, zap.NewNop())
	t.Cleanup(trafficLogger.Stop)
	factory := router.NewOutboundFactory(nil, zap.NewNop())
	t.Cleanup(factory.Close)
	routing := router.NewRoutingOutbound(router.NewRouter(users, zap.NewNop()), factory, zap.NewNop())
	server := startTrojanServer(t, certificate, authenticator, routing, trafficLogger, connection.NewTracker())

	client := dialTrojanTLS(t, server.Addr().String())
	before := []byte("before expiry")
	if err := writeTrojanConnect(client, trojan.RawPassword("alice", "direct", "secret"), targetAddr, before); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(before))
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}

	past := time.Now().Add(-time.Minute)
	expired := map[string]config.UserConfig{
		"alice": {Password: "secret", Routes: []string{"direct"}, ExpiresAt: &past},
	}
	authenticator.UpdateUsers(expired)
	trafficLogger.UpdateUsers(expired)
	_, _ = client.Write([]byte("after expiry"))
	expectConnectionReadFailure(t, client)

	snapshot := trafficLogger.GetSnapshot("alice:direct")
	if snapshot.TxBytes != uint64(len(before)) || snapshot.RxBytes != uint64(len(before)) {
		t.Fatalf("inactive payload was accounted: %#v", snapshot)
	}
}

func TestTrojanE2E_QuotaRejectedChunkIsCountedButNotForwarded(t *testing.T) {
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = targetListener.Close() })
	targetRead := make(chan []byte, 1)
	go func() {
		connection, err := targetListener.Accept()
		if err != nil {
			targetRead <- nil
			return
		}
		defer connection.Close()
		data, _ := io.ReadAll(connection)
		targetRead <- data
	}()

	certificate, err := generateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("over quota")
	users := map[string]config.UserConfig{
		"alice": {Password: "secret", Routes: []string{"direct"}, MaxBytes: uint64(len(payload) - 1)},
	}
	trafficLogger := traffic.NewTrafficLogger(users, nil, zap.NewNop())
	t.Cleanup(trafficLogger.Stop)
	factory := router.NewOutboundFactory(nil, zap.NewNop())
	t.Cleanup(factory.Close)
	routing := router.NewRoutingOutbound(router.NewRouter(users, zap.NewNop()), factory, zap.NewNop())
	server := startTrojanServer(t, certificate, trojan.NewAuthenticator(users), routing, trafficLogger, connection.NewTracker())

	client := dialTrojanTLS(t, server.Addr().String())
	if err := writeTrojanConnect(client, trojan.RawPassword("alice", "direct", "secret"), targetListener.Addr().String(), payload); err != nil {
		t.Fatal(err)
	}
	expectConnectionReadFailure(t, client)
	select {
	case data := <-targetRead:
		if len(data) != 0 {
			t.Fatalf("quota-rejected payload reached target: %q", data)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("target connection was not closed")
	}
	snapshot := trafficLogger.GetSnapshot("alice:direct")
	if snapshot.TxBytes != uint64(len(payload)) {
		t.Fatalf("quota-triggering chunk accounting = %d, want %d to match Hysteria2", snapshot.TxBytes, len(payload))
	}
}

func TestTrojanE2E_DownloadLimitAndDisconnect(t *testing.T) {
	targetAddr, _ := startEchoTarget(t)
	certificate, err := generateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	users := map[string]config.UserConfig{"alice": {Password: "secret", Routes: []string{"direct"}, SpeedLimit: 1}}
	trafficLogger := traffic.NewTrafficLogger(users, nil, zap.NewNop())
	t.Cleanup(trafficLogger.Stop)
	tracker := connection.NewTracker()
	factory := router.NewOutboundFactory(nil, zap.NewNop())
	t.Cleanup(factory.Close)
	routing := router.NewRoutingOutbound(router.NewRouter(users, zap.NewNop()), factory, zap.NewNop())
	server := startTrojanServer(t, certificate, trojan.NewAuthenticator(users), routing, trafficLogger, tracker)
	client := dialTrojanTLS(t, server.Addr().String())
	defer client.Close()
	if err := writeTrojanConnect(client, trojan.RawPassword("alice", "direct", "secret"), targetAddr, []byte("hi")); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(client, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("!")); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("download bypassed the configured rate limit")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("expected a rate-limited read timeout, got %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	eventuallyE2E(t, time.Second, func() bool {
		return trafficLogger.GetSnapshot("alice:direct").OnlineCount == 0 && len(tracker.Snapshots()) == 0
	})
	if trafficLogger.GetSnapshot("alice:direct").RxBytes != 2 {
		t.Fatal("download cancelled by disconnect was accounted")
	}
	if !trafficLogger.LogTraffic("alice:direct", 1, 0) {
		t.Fatal("closing one Trojan connection stopped the shared traffic logger")
	}
}

func TestTrojanAndHysteria2SharePortCertificateQuotaAndRate(t *testing.T) {
	logger := zap.NewNop()
	targetAddr, _ := startEchoTarget(t)
	certificate, err := generateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	trust := x509.NewCertPool()
	trust.AddCert(parsed)
	users := map[string]config.UserConfig{"alice": {Password: "test-password", Routes: []string{"direct"}, SpeedLimit: 1, MaxBytes: 1000}}
	trafficLogger := traffic.NewTrafficLogger(users, nil, logger)
	t.Cleanup(trafficLogger.Stop)
	tracker := connection.NewTracker()
	factory := router.NewOutboundFactory(nil, logger)
	t.Cleanup(factory.Close)
	routing := router.NewRoutingOutbound(router.NewRouter(users, logger), factory, logger)
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close() })
	hy, err := hyServer.NewServer(&hyServer.Config{
		TLSConfig: hyServer.TLSConfig{Certificates: []tls.Certificate{certificate}}, Conn: udp,
		Authenticator: auth.NewAuthenticator(users, logger), Outbound: routing,
		TrafficLogger: trafficLogger, EventLogger: event.NewEventLogger(routing, logger, tracker),
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = hy.Serve() }()
	t.Cleanup(func() { _ = hy.Close() })
	server := startTrojanServer(t, certificate, trojan.NewAuthenticator(users), routing, trafficLogger, tracker, udp.LocalAddr().String())
	if server.Addr().String() != udp.LocalAddr().String() {
		t.Fatal("TCP and UDP listeners did not bind the same numeric port")
	}
	clientHy2, _, err := hyClient.NewClient(&hyClient.Config{
		ServerAddr: udp.LocalAddr(), Auth: "alice:direct:test-password",
		TLSConfig: hyClient.TLSConfig{ServerName: "localhost", RootCAs: trust},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clientHy2.Close()
	hyStream, err := clientHy2.TCP(targetAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer hyStream.Close()
	_ = hyStream.SetDeadline(time.Now().Add(3 * time.Second))
	payload := []byte("warm hy2 limiter")
	if _, err := hyStream.Write(payload); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(hyStream, make([]byte, len(payload))); err != nil {
		t.Fatal(err)
	}
	client, err := tls.Dial("tcp", server.Addr().String(), &tls.Config{ServerName: "localhost", RootCAs: trust, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := writeTrojanConnect(client, "alice:direct:test-password", targetAddr, []byte("!")); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("Trojan download did not share the Hysteria2 rate limit")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("unexpected download error: %v", err)
	}
	users["alice"] = config.UserConfig{Password: "test-password", Routes: []string{"direct"}, MaxBytes: 2 * uint64(len(payload)+1)}
	trafficLogger.UpdateUsers(users)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	response := make([]byte, 1)
	if _, err := io.ReadFull(client, response); err != nil || string(response) != "!" {
		t.Fatalf("hot speed update did not release Trojan response: %v", err)
	}
	eventuallyE2E(t, time.Second, func() bool {
		snapshot := trafficLogger.GetSnapshot("alice:direct")
		return snapshot.TxBytes == uint64(len(payload)+1) && snapshot.RxBytes == uint64(len(payload)+1) && snapshot.OnlineCount == 2 && len(tracker.Snapshots()) == 2
	})
	// Both protocols have now exactly consumed the same user's quota. The
	// next Trojan chunk is counted but must not reach the target or echo back.
	if _, err := client.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	expectConnectionReadFailure(t, client)
	eventuallyE2E(t, time.Second, func() bool {
		return trafficLogger.GetSnapshot("alice:direct").OnlineCount == 1 && len(tracker.Snapshots()) == 1
	})
}

func startTrojanServer(t *testing.T, certificate tls.Certificate, authenticator *trojan.Authenticator, routing *router.RoutingOutbound, trafficLogger *traffic.TrafficLogger, tracker *connection.Tracker, listen ...string) *trojan.Server {
	t.Helper()
	address := "127.0.0.1:0"
	if len(listen) != 0 {
		address = listen[0]
	}
	server, err := trojan.NewServer(trojan.ServerConfig{
		Listen:                address,
		TLSConfig:             &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12},
		Authenticator:         authenticator,
		Outbound:              routing,
		TrafficLogger:         trafficLogger,
		ConnectionTracker:     tracker,
		HandshakeTimeout:      2 * time.Second,
		MaxPendingConnections: 32,
		Logger:                zap.NewNop(),
	})
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve() }()
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
		select {
		case err := <-serveDone:
			if err != nil {
				t.Errorf("Trojan Serve returned error: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("Trojan server did not stop")
		}
	})
	return server
}

func dialTrojanTLS(t *testing.T, address string) net.Conn {
	t.Helper()
	client, err := tls.Dial("tcp", address, &tls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true, // test-only self-signed certificate
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func writeTrojanConnect(connection net.Conn, rawPassword, target string, payload []byte) error {
	return writeTrojanWireRequest(connection, trojan.HashPassword(rawPassword), target, payload)
}

func writeTrojanWireRequest(connection net.Conn, credential, target string, payload []byte) error {
	host, rawPort, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	port, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil || port == 0 {
		return errors.New("invalid test target port")
	}
	header := make([]byte, 0, len(credential)+len(host)+16)
	header = append(header, credential...)
	header = append(header, '\r', '\n', 0x01)
	if ip := net.ParseIP(host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			header = append(header, 0x01)
			header = append(header, ipv4...)
		} else {
			header = append(header, 0x04)
			header = append(header, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return errors.New("invalid test target domain")
		}
		header = append(header, 0x03, byte(len(host)))
		header = append(header, host...)
	}
	var encodedPort [2]byte
	binary.BigEndian.PutUint16(encodedPort[:], uint16(port))
	header = append(header, encodedPort[:]...)
	header = append(header, '\r', '\n')
	header = append(header, payload...)
	for len(header) > 0 {
		written, err := connection.Write(header)
		if err != nil {
			return err
		}
		header = header[written:]
	}
	return nil
}

func expectTrojanRejected(t *testing.T, address, credential, target string) {
	t.Helper()
	client := dialTrojanTLS(t, address)
	defer client.Close()
	if err := writeTrojanWireRequest(client, credential, target, []byte("must not pass")); err != nil {
		t.Fatal(err)
	}
	expectConnectionReadFailure(t, client)
}

func expectConnectionReadFailure(t *testing.T, connection net.Conn) {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1)
	if read, err := connection.Read(buffer); err == nil {
		t.Fatalf("connection remained readable with %d bytes", read)
	}
}

func startEchoTarget(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepts := &atomic.Int32{}
	var connections sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			connections.Add(1)
			go func() {
				defer connections.Done()
				defer client.Close()
				_, _ = io.Copy(client, client)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
		connections.Wait()
	})
	return listener.Addr().String(), accepts
}

func eventuallyE2E(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	if !condition() {
		t.Fatal("condition was not met before timeout")
	}
}

type recordingNodeEvents struct {
	tcpRequests atomic.Int32
	mu          sync.Mutex
	target      string
}

func (e *recordingNodeEvents) Connect(net.Addr, string, uint64)         {}
func (e *recordingNodeEvents) Disconnect(net.Addr, string, error)       {}
func (e *recordingNodeEvents) TCPError(net.Addr, string, string, error) {}
func (e *recordingNodeEvents) UDPRequest(net.Addr, string, uint32, string) {
}
func (e *recordingNodeEvents) UDPError(net.Addr, string, uint32, error) {}

func (e *recordingNodeEvents) TCPRequest(_ net.Addr, _ string, target string) {
	e.mu.Lock()
	e.target = target
	e.mu.Unlock()
	e.tcpRequests.Add(1)
}

func (e *recordingNodeEvents) tcpSnapshot() (int32, string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.tcpRequests.Load(), e.target
}
