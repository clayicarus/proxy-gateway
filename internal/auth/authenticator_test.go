package auth

import (
	"net"
	"testing"

	"github.com/hy2-gateway/internal/config"
	"go.uber.org/zap"
)

func TestAuthenticator_Success(t *testing.T) {
	logger := zap.NewNop()
	users := map[string]config.UserConfig{
		"alice": {Password: "pass123", Route: "direct"},
		"bob":   {Password: "secret", Route: "node1"},
	}
	a := NewAuthenticator(users, logger)

	addr := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 12345}

	ok, id := a.Authenticate(addr, "alice:pass123", 0)
	if !ok || id != "alice" {
		t.Errorf("expected (true, alice), got (%v, %s)", ok, id)
	}

	ok, id = a.Authenticate(addr, "bob:secret", 0)
	if !ok || id != "bob" {
		t.Errorf("expected (true, bob), got (%v, %s)", ok, id)
	}
}

func TestAuthenticator_WrongPassword(t *testing.T) {
	logger := zap.NewNop()
	users := map[string]config.UserConfig{
		"alice": {Password: "pass123", Route: "direct"},
	}
	a := NewAuthenticator(users, logger)
	addr := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 12345}

	ok, _ := a.Authenticate(addr, "alice:wrongpass", 0)
	if ok {
		t.Error("expected auth to fail with wrong password")
	}
}

func TestAuthenticator_UnknownUser(t *testing.T) {
	logger := zap.NewNop()
	users := map[string]config.UserConfig{
		"alice": {Password: "pass123", Route: "direct"},
	}
	a := NewAuthenticator(users, logger)
	addr := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 12345}

	ok, _ := a.Authenticate(addr, "unknown:pass123", 0)
	if ok {
		t.Error("expected auth to fail with unknown user")
	}
}

func TestAuthenticator_NoColon(t *testing.T) {
	logger := zap.NewNop()
	users := map[string]config.UserConfig{
		"alice": {Password: "pass123", Route: "direct"},
	}
	a := NewAuthenticator(users, logger)
	addr := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 12345}

	// No colon means empty username
	ok, _ := a.Authenticate(addr, "pass123", 0)
	if ok {
		t.Error("expected auth to fail with no colon (empty username)")
	}
}

func TestAuthenticator_UpdateUsers(t *testing.T) {
	logger := zap.NewNop()
	users := map[string]config.UserConfig{
		"alice": {Password: "pass123", Route: "direct"},
	}
	a := NewAuthenticator(users, logger)
	addr := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 12345}

	// charlie doesn't exist yet
	ok, _ := a.Authenticate(addr, "charlie:newpass", 0)
	if ok {
		t.Error("expected charlie to not exist")
	}

	// Update users
	a.UpdateUsers(map[string]config.UserConfig{
		"charlie": {Password: "newpass", Route: "direct"},
	})

	ok, id := a.Authenticate(addr, "charlie:newpass", 0)
	if !ok || id != "charlie" {
		t.Errorf("expected (true, charlie), got (%v, %s)", ok, id)
	}

	// alice should no longer exist
	ok, _ = a.Authenticate(addr, "alice:pass123", 0)
	if ok {
		t.Error("expected alice to no longer exist after update")
	}
}
