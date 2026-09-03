package auth

import (
	"net"
	"testing"

	"github.com/clayicarus/proxy-gateway/internal/config"
	"go.uber.org/zap"
)

func TestAuthenticator_Success(t *testing.T) {
	logger := zap.NewNop()
	users := map[string]config.UserConfig{
		"alice": {Password: "pass123", Routes: []string{"node1", "direct"}},
		"bob":   {Password: "secret", Routes: []string{"node1"}},
	}
	a := NewAuthenticator(users, logger)

	addr := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 12345}

	ok, id := a.Authenticate(addr, "alice:node1:pass123", 0)
	if !ok || id != "alice:node1" {
		t.Errorf("expected (true, alice:node1), got (%v, %s)", ok, id)
	}

	ok, id = a.Authenticate(addr, "alice:direct:pass123", 0)
	if !ok || id != "alice:direct" {
		t.Errorf("expected (true, alice:direct), got (%v, %s)", ok, id)
	}

	ok, id = a.Authenticate(addr, "bob:node1:secret", 0)
	if !ok || id != "bob:node1" {
		t.Errorf("expected (true, bob:node1), got (%v, %s)", ok, id)
	}
}

func TestAuthenticator_WrongPassword(t *testing.T) {
	logger := zap.NewNop()
	users := map[string]config.UserConfig{
		"alice": {Password: "pass123", Routes: []string{"direct"}},
	}
	a := NewAuthenticator(users, logger)
	addr := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 12345}

	ok, _ := a.Authenticate(addr, "alice:direct:wrongpass", 0)
	if ok {
		t.Error("expected auth to fail with wrong password")
	}
}

func TestAuthenticator_UnknownUser(t *testing.T) {
	logger := zap.NewNop()
	users := map[string]config.UserConfig{
		"alice": {Password: "pass123", Routes: []string{"direct"}},
	}
	a := NewAuthenticator(users, logger)
	addr := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 12345}

	ok, _ := a.Authenticate(addr, "unknown:direct:pass123", 0)
	if ok {
		t.Error("expected auth to fail with unknown user")
	}
}

func TestAuthenticator_NodeNotAllowed(t *testing.T) {
	logger := zap.NewNop()
	users := map[string]config.UserConfig{
		"alice": {Password: "pass123", Routes: []string{"node1"}},
	}
	a := NewAuthenticator(users, logger)
	addr := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 12345}

	// alice is not allowed to use node2
	ok, _ := a.Authenticate(addr, "alice:node2:pass123", 0)
	if ok {
		t.Error("expected auth to fail with disallowed node")
	}
}

func TestAuthenticator_NoColon(t *testing.T) {
	logger := zap.NewNop()
	users := map[string]config.UserConfig{
		"alice": {Password: "pass123", Routes: []string{"direct"}},
	}
	a := NewAuthenticator(users, logger)
	addr := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 12345}

	// No colon means empty username
	ok, _ := a.Authenticate(addr, "pass123", 0)
	if ok {
		t.Error("expected auth to fail with no colon (empty username)")
	}
}

func TestAuthenticator_LegacyTwoPartAuth(t *testing.T) {
	logger := zap.NewNop()
	users := map[string]config.UserConfig{
		"alice": {Password: "pass123", Routes: []string{"direct"}},
	}
	a := NewAuthenticator(users, logger)
	addr := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 12345}

	// Legacy "username:password" format should fail (empty node name)
	ok, _ := a.Authenticate(addr, "alice:pass123", 0)
	if ok {
		t.Error("expected auth to fail with legacy two-part format (no node)")
	}
}

func TestAuthenticator_PasswordWithColons(t *testing.T) {
	logger := zap.NewNop()
	users := map[string]config.UserConfig{
		"alice": {Password: "pass:with:colons", Routes: []string{"node1"}},
	}
	a := NewAuthenticator(users, logger)
	addr := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 12345}

	ok, id := a.Authenticate(addr, "alice:node1:pass:with:colons", 0)
	if !ok || id != "alice:node1" {
		t.Errorf("expected (true, alice:node1), got (%v, %s)", ok, id)
	}
}

func TestAuthenticator_UpdateUsers(t *testing.T) {
	logger := zap.NewNop()
	users := map[string]config.UserConfig{
		"alice": {Password: "pass123", Routes: []string{"direct"}},
	}
	a := NewAuthenticator(users, logger)
	addr := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 12345}

	// charlie doesn't exist yet
	ok, _ := a.Authenticate(addr, "charlie:node1:newpass", 0)
	if ok {
		t.Error("expected charlie to not exist")
	}

	// Update users
	a.UpdateUsers(map[string]config.UserConfig{
		"charlie": {Password: "newpass", Routes: []string{"node1", "direct"}},
	})

	ok, id := a.Authenticate(addr, "charlie:node1:newpass", 0)
	if !ok || id != "charlie:node1" {
		t.Errorf("expected (true, charlie:node1), got (%v, %s)", ok, id)
	}

	// alice should no longer exist
	ok, _ = a.Authenticate(addr, "alice:direct:pass123", 0)
	if ok {
		t.Error("expected alice to no longer exist after update")
	}
}

func TestParseID(t *testing.T) {
	tests := []struct {
		id       string
		wantUser string
		wantNode string
	}{
		{"alice:node1", "alice", "node1"},
		{"bob:direct", "bob", "direct"},
		{"charlie", "charlie", ""},
	}
	for _, tt := range tests {
		user, node := ParseID(tt.id)
		if user != tt.wantUser || node != tt.wantNode {
			t.Errorf("ParseID(%q) = (%q, %q), want (%q, %q)",
				tt.id, user, node, tt.wantUser, tt.wantNode)
		}
	}
}
