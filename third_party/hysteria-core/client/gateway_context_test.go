package client

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestNewClientContextCancelsUnresponsiveAuthentication(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	client, _, err := NewClientContext(ctx, &Config{
		ServerAddr: server.LocalAddr(), Auth: "anything",
		TLSConfig: TLSConfig{ServerName: "localhost", InsecureSkipVerify: true},
	})
	if client != nil {
		_ = client.Close()
		t.Fatal("unresponsive authentication returned a client")
	}
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("cancellation took %v", elapsed)
	}
}
