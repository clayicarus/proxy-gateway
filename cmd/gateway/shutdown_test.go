package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	hyServer "github.com/apernet/hysteria/core/v2/server"
	"github.com/clayicarus/proxy-gateway/internal/auth"
	"github.com/clayicarus/proxy-gateway/internal/config"
	"github.com/clayicarus/proxy-gateway/internal/storage"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// The test binary doubles as an isolated Gateway process. Signals and the
// production logger's fatal exits must never affect the parent test process.
func TestGatewayProcessHelper(t *testing.T) {
	path := os.Getenv("PROXY_GATEWAY_TEST_HELPER_CONFIG")
	if path == "" {
		return
	}
	if err := runGateway([]string{"-c", path}); err != nil {
		t.Fatal(err)
	}
}

type stalledNodeOutbound struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (o *stalledNodeOutbound) TCP(string) (net.Conn, error) {
	o.once.Do(func() { close(o.entered) })
	<-o.release
	return nil, errors.New("test node stopped")
}

func (o *stalledNodeOutbound) UDP(string) (hyServer.UDPConn, error) {
	return nil, errors.New("UDP is unused by this test")
}

// Exercise the actual entrypoint, configuration, shared certificate, SQLite,
// signal handler and shutdown order. A remote Hy2 node deliberately withholds
// its CONNECT response; shutdown must close that client before waiting for the
// Trojan handler, while also persisting traffic from an active direct session.
func TestGatewaySIGTERMDrainsTrojanAndFlushesTraffic(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX SIGTERM subprocess coverage runs in Linux CI")
	}
	dir := t.TempDir()
	certPath, keyPath, certificate := writeShutdownCertificate(t, dir)
	logger := zap.NewNop()
	nodeUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer nodeUDP.Close()
	stalled := &stalledNodeOutbound{entered: make(chan struct{}), release: make(chan struct{})}
	defer close(stalled.release)
	node, err := hyServer.NewServer(&hyServer.Config{
		Conn: nodeUDP, TLSConfig: hyServer.TLSConfig{Certificates: []tls.Certificate{certificate}},
		Authenticator: auth.NewAuthenticator(map[string]config.UserConfig{"node": {Password: "test-node", Routes: []string{"direct"}}}, logger),
		Outbound:      stalled,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = node.Serve() }()
	defer node.Close()

	dbPath := filepath.Join(dir, "traffic.db")
	store, err := storage.NewSQLiteStore(dbPath, logger)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveNode("slow-node", config.NodeConfig{Type: "hysteria2", Hysteria2: &config.Hysteria2OutboundConfig{Addr: nodeUDP.LocalAddr().String(), Auth: "node:direct:test-node", SNI: "localhost", Insecure: true}}, true); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateUser(storage.ManagedUserInput{Username: "alice", Password: "test-user", Routes: []string{"direct", "slow-node"}}, "test-token"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reservation.Addr().String()
	_ = reservation.Close()
	cfg := config.Config{
		Listen: address, TLS: config.TLSConfig{Cert: certPath, Key: keyPath},
		Trojan: &config.TrojanConfig{Listen: address}, DBPath: dbPath, TrafficFlushInterval: time.Hour,
	}
	encoded, err := yaml.Marshal(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "gateway.yaml")
	if err := os.WriteFile(configPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "gateway.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	command := exec.Command(os.Args[0], "-test.run=^TestGatewayProcessHelper$")
	command.Env = append(os.Environ(), "PROXY_GATEWAY_TEST_HELPER_CONFIG="+configPath)
	command.Stdout, command.Stderr = logFile, logFile
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	finished := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- command.Wait()
		close(finished)
	}()
	defer func() {
		select {
		case <-finished:
		default:
			_ = command.Process.Kill()
			<-finished
		}
	}()
	var client *tls.Conn
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		client, err = tls.DialWithDialer(&net.Dialer{Timeout: 200 * time.Millisecond}, "tcp", address, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"})
		if err == nil {
			break
		}
		select {
		case <-finished:
			t.Fatal("Gateway exited before its Trojan listener became ready")
		case <-time.After(20 * time.Millisecond):
		}
	}
	if err != nil {
		t.Fatalf("Gateway did not start its Trojan listener: %v", err)
	}
	defer client.Close()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		connection, err := echo.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		_, _ = io.Copy(connection, connection)
	}()
	payload := []byte("persist this payload during SIGTERM")
	writeShutdownRequest(t, client, "alice:direct:test-user", echo.Addr().String(), payload)
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(client, make([]byte, len(payload))); err != nil {
		t.Fatal(err)
	}
	blocked, err := tls.Dial("tcp", address, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Close()
	writeShutdownRequest(t, blocked, "alice:slow-node:test-user", echo.Addr().String(), nil)
	select {
	case <-stalled.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("Trojan did not reach the stalled remote node")
	}
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("Gateway failed during graceful shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Gateway shutdown waited for the withheld Hy2 CONNECT response")
	}
	select {
	case <-echoDone:
	case <-time.After(time.Second):
		t.Fatal("direct target remained open after Gateway shutdown")
	}
	reopened, err := storage.NewSQLiteStore(dbPath, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if tx, rx, err := reopened.GetSummary("alice", "direct"); err != nil || tx != uint64(len(payload)) || rx != uint64(len(payload)) {
		t.Fatalf("SIGTERM final flush: tx=%d rx=%d error=%v", tx, rx, err)
	}
}

func writeShutdownRequest(t *testing.T, connection net.Conn, password, target string, payload []byte) {
	t.Helper()
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum224([]byte(password))
	request := append([]byte(hex.EncodeToString(sum[:])), '\r', '\n', 1, 1)
	request = append(request, net.ParseIP(host).To4()...)
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	request = append(request, '\r', '\n')
	request = append(request, payload...)
	if _, err := connection.Write(request); err != nil {
		t.Fatal(err)
	}
}

func writeShutdownCertificate(t *testing.T, dir string) (string, string, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"localhost"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath, certificate
}
