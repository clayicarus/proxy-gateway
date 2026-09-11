package router

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/clayicarus/proxy-gateway/internal/config"
	"github.com/clayicarus/proxy-gateway/internal/outbound"
	"go.uber.org/zap"
)

func TestServiceRoutesExplicitIdentity(t *testing.T) {
	logger := zap.NewNop()
	service := NewService(NewRouter(map[string]config.UserConfig{
		"alice": {Password: "p", Routes: []string{"direct"}},
	}, logger), outbound.NewOutboundFactory(nil, logger), logger)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, _ := listener.Accept()
		if conn != nil {
			_ = conn.Close()
		}
	}()
	conn, err := service.TCPContext(context.Background(), "alice:direct", listener.Addr().String())
	if err != nil {
		t.Fatalf("routing TCP failed: %v", err)
	}
	_ = conn.Close()
}

func TestServiceRejectsMalformedIdentity(t *testing.T) {
	logger := zap.NewNop()
	service := NewService(NewRouter(nil, logger), outbound.NewOutboundFactory(nil, logger), logger)
	if _, err := service.TCPContext(context.Background(), "alice", "example.com:443"); err == nil || !strings.Contains(err.Error(), "node is required") {
		t.Fatalf("authenticated ID without an explicit node should fail closed, got %v", err)
	}
}

func TestServiceConcurrentSameTargetKeepsExplicitRoute(t *testing.T) {
	logger := zap.NewNop()
	const requests = 100
	nodes := make(map[string]config.NodeConfig, requests)
	for i := 0; i < requests; i++ {
		route := fmt.Sprintf("route-%03d", i)
		nodes[route] = config.NodeConfig{Type: "test-invalid"}
	}
	service := NewService(NewRouter(nil, logger), outbound.NewOutboundFactory(nodes, logger), logger)

	var wait sync.WaitGroup
	errors := make(chan error, requests)
	for i := 0; i < requests; i++ {
		i := i
		wait.Add(1)
		go func() {
			defer wait.Done()
			route := fmt.Sprintf("route-%03d", i)
			_, err := service.TCPContext(context.Background(), "user:"+route, "same.example:443")
			if err == nil || !strings.Contains(err.Error(), "node "+route+" unavailable:") {
				errors <- fmt.Errorf("request %d used wrong route: %v", i, err)
			}
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
}
