package interop

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	hyClient "github.com/apernet/hysteria/core/v2/client"
	hyServer "github.com/apernet/hysteria/core/v2/server"
)

type session struct{ transport hyServer.Transport }

func (*session) ID() string        { return "interop" }
func (s *session) Close(err error) { _ = s.transport.Close(err) }

type gatewayServer struct{}

func (*gatewayServer) AuthenticateSession(_ context.Context, transport hyServer.Transport, _ string, _ uint64) (hyServer.Session, bool) {
	return &session{transport: transport}, true
}
func (*gatewayServer) TCPContext(ctx context.Context, _ hyServer.Session, request hyServer.RequestInfo) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", request.Target)
}
func (*gatewayServer) UDPContext(context.Context, hyServer.Session, hyServer.RequestInfo) (hyServer.UDPConn, error) {
	return nil, context.Canceled
}
func (*gatewayServer) LogTrafficContext(context.Context, hyServer.Session, hyServer.RequestInfo, uint64, uint64) bool {
	return true
}
func (*gatewayServer) LogOnlineStateSession(hyServer.Session, bool) {}

func echoTarget(t *testing.T) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	return listener.Addr().String(), func() { _ = listener.Close() }
}

func fixtureDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs("upstream")
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func buildUpstream(t *testing.T, name string) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), name)
	command := exec.Command("go", "build", "-o", binary, "./cmd/"+name)
	command.Dir = fixtureDir(t)
	command.Env = append(os.Environ(), "GOCACHE=/tmp/hy2-gateway-go-build", "GOPROXY=off")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build upstream %s: %v\n%s", name, err, output)
	}
	return binary
}

func TestUpstreamClientToGatewayServer(t *testing.T) {
	target, closeTarget := echoTarget(t)
	defer closeTarget()
	cert, err := tls.LoadX509KeyPair("../../third_party/hysteria-core/internal/integration_tests/test.crt", "../../third_party/hysteria-core/internal/integration_tests/test.key")
	if err != nil {
		t.Fatal(err)
	}
	packet, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &gatewayServer{}
	server, err := hyServer.NewServer(&hyServer.Config{
		TLSConfig: hyServer.TLSConfig{Certificates: []tls.Certificate{cert}}, Conn: packet, DisableUDP: true,
		SessionAuthenticator: adapter, SessionOutbound: adapter, SessionTrafficLogger: adapter,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve() }()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, buildUpstream(t, "client"), packet.LocalAddr().String(), target, "anything")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("upstream client: %v\n%s", err, output)
	}
}

func TestGatewayClientToUpstreamServer(t *testing.T) {
	target, closeTarget := echoTarget(t)
	defer closeTarget()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cert, _ := filepath.Abs("../../third_party/hysteria-core/internal/integration_tests/test.crt")
	key, _ := filepath.Abs("../../third_party/hysteria-core/internal/integration_tests/test.key")
	command := exec.CommandContext(ctx, buildUpstream(t, "server"), cert, key)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = command.Process.Kill(); _ = command.Wait() }()
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() {
		t.Fatalf("upstream server address: %v", scanner.Err())
	}
	serverAddr, err := net.ResolveUDPAddr("udp", scanner.Text())
	if err != nil {
		t.Fatal(err)
	}
	client, _, err := hyClient.NewClientContext(ctx, &hyClient.Config{
		ServerAddr: serverAddr, Auth: "anything",
		TLSConfig: hyClient.TLSConfig{ServerName: "localhost", InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	conn, err := client.TCPContext(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := []byte("gateway-client")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo mismatch: %q", got)
	}
}
