package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/clayicarus/proxy-gateway/internal/config"
	"go.uber.org/zap"
)

func TestKernelUpdateUsersPreservesStartupRoutesAndDisablesRemovedUsers(t *testing.T) {
	users := map[string]config.UserConfig{
		"alice": {Password: "before", Routes: []string{"direct"}},
	}
	kernel := New(users, nil, nil, zap.NewNop(), time.UTC)
	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}
	if _, ok := kernel.Authenticate("public", addr, "alice:direct:before", 0); !ok {
		t.Fatal("startup user was not authenticated")
	}

	kernel.UpdateUsers(map[string]config.UserConfig{
		"alice": {Password: "after", Routes: []string{"unapplied-route"}},
	})
	if _, ok := kernel.Authenticate("public", addr, "alice:direct:after", 0); !ok {
		t.Fatal("startup authorization route was not preserved")
	}
	if _, ok := kernel.Authenticate("public", addr, "alice:unapplied-route:after", 0); ok {
		t.Fatal("hot reload applied a restart-required route change")
	}

	kernel.UpdateUsers(map[string]config.UserConfig{})
	if _, ok := kernel.Authenticate("public", addr, "alice:direct:after", 0); ok {
		t.Fatal("removed user remained authenticated")
	}
}

func TestKernelAuthenticatesTrojanAsPrivateSession(t *testing.T) {
	users := map[string]config.UserConfig{"alice": {Password: "secret", Routes: []string{"direct"}}}
	kernel := New(users, nil, nil, zap.NewNop(), time.UTC)
	sum := sha256.Sum224([]byte("alice:direct:secret"))
	session, ok := kernel.AuthenticateTrojan("trojan-public", &net.TCPAddr{}, hex.EncodeToString(sum[:]))
	if !ok || session == nil || session.ID() == "" {
		t.Fatalf("Trojan authentication did not create a session: %v %#v", ok, session)
	}
	if !kernel.Admit(context.Background(), session, 1, 1) {
		t.Fatal("kernel rejected its own Trojan session")
	}
}

func TestKernelRejectsForeignSession(t *testing.T) {
	users := map[string]config.UserConfig{"alice": {Password: "secret", Routes: []string{"direct"}}}
	first := New(users, nil, nil, zap.NewNop(), time.UTC)
	second := New(users, nil, nil, zap.NewNop(), time.UTC)
	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}
	session, ok := first.Authenticate("public", addr, "alice:direct:secret", 0)
	if !ok {
		t.Fatal("authentication failed")
	}
	if second.Admit(nil, session, 1, 1) {
		t.Fatal("foreign session was accepted")
	}
}
