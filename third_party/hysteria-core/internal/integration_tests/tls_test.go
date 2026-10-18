package integration_tests

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"
)

func TestServerTLSConfigWithoutCertificateFiles(t *testing.T) {
	t.Chdir(t.TempDir())
	config := serverTLSConfig()
	cert, err := x509.ParseCertificate(config.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)

	// An in-memory connection verifies the certificate and key without sockets.
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	server := tls.Server(serverConn, &tls.Config{Certificates: config.Certificates})
	client := tls.Client(clientConn, &tls.Config{RootCAs: roots, ServerName: "localhost"})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.HandshakeContext(ctx) }()
	if err := client.HandshakeContext(ctx); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
}
