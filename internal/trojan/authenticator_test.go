package trojan

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/clayicarus/proxy-gateway/internal/config"
)

func TestHashPasswordKnownVectorAndMapping(t *testing.T) {
	const expected = "2f6edcd07394804e8d57cd5a5cc95901abb5e5dcc80340b282026d87"
	raw := RawPassword("alice", "direct", "secret")
	if raw != "alice:direct:secret" {
		t.Fatal("derived raw password does not match the expected formula")
	}
	if got := HashPassword(raw); got != expected {
		t.Fatal("SHA-224 credential does not match the known vector")
	}

	authenticator := NewAuthenticator(map[string]config.UserConfig{
		"alice": {Password: "secret", Routes: []string{"node1", "direct"}},
	})
	for _, node := range []string{"node1", "direct"} {
		credential := HashPassword(RawPassword("alice", node, "secret"))
		if id, ok := authenticator.Authenticate(credential); !ok || id != "alice:"+node {
			t.Fatalf("credential for %s resolved to %q/%v", node, id, ok)
		}
	}
}

func TestAuthenticatorSupportsColonsInUserPassword(t *testing.T) {
	authenticator := NewAuthenticator(map[string]config.UserConfig{
		"alice": {Password: "pass:with:colon", Routes: []string{"node1"}},
	})
	credential := HashPassword("alice:node1:pass:with:colon")
	if id, ok := authenticator.Authenticate(credential); !ok || id != "alice:node1" {
		t.Fatalf("authentication = %q/%v", id, ok)
	}
}

func TestAuthenticatorRejectsMalformedAndUnknownCredentials(t *testing.T) {
	authenticator := NewAuthenticator(map[string]config.UserConfig{
		"alice": {Password: "secret", Routes: []string{"direct"}},
	})
	valid := HashPassword(RawPassword("alice", "direct", "secret"))
	invalid := []string{
		"",
		valid[:len(valid)-1],
		valid + "0",
		strings.ToUpper(valid),
		valid[:10] + "g" + valid[11:],
		valid + "\r\n",
		HashPassword("unknown"),
	}
	for _, credential := range invalid {
		if id, ok := authenticator.Authenticate(credential); ok || id != "" {
			t.Fatalf("malformed credential unexpectedly resolved to %q", id)
		}
	}
}

func TestAuthenticatorLifecycleAndAtomicRefresh(t *testing.T) {
	now := time.Date(2026, time.September, 5, 0, 0, 0, 0, time.UTC)
	future := now.Add(time.Hour)
	authenticator := NewAuthenticator(map[string]config.UserConfig{
		"alice": {Password: "old", Routes: []string{"direct"}, ExpiresAt: &future},
	})
	authenticator.now = func() time.Time { return now }
	oldCredential := HashPassword(RawPassword("alice", "direct", "old"))
	newCredential := HashPassword(RawPassword("alice", "direct", "new"))
	if _, ok := authenticator.Authenticate(oldCredential); !ok {
		t.Fatal("initial credential was rejected")
	}

	authenticator.UpdateUsers(map[string]config.UserConfig{
		"alice": {Password: "new", Routes: []string{"direct"}, ExpiresAt: &future},
	})
	if _, ok := authenticator.Authenticate(oldCredential); ok {
		t.Fatal("old credential survived password refresh")
	}
	if _, ok := authenticator.Authenticate(newCredential); !ok {
		t.Fatal("new credential was rejected")
	}

	authenticator.UpdateUsers(map[string]config.UserConfig{
		"alice": {Password: "new", Routes: []string{"direct"}, Disabled: true},
	})
	if _, ok := authenticator.Authenticate(newCredential); ok {
		t.Fatal("disabled user authenticated")
	}
	past := now.Add(-time.Second)
	authenticator.UpdateUsers(map[string]config.UserConfig{
		"alice": {Password: "new", Routes: []string{"direct"}, ExpiresAt: &past},
	})
	if _, ok := authenticator.Authenticate(newCredential); ok {
		t.Fatal("expired user authenticated")
	}
}

func TestAuthenticatorConcurrentReadersAndRefresh(t *testing.T) {
	oldUsers := map[string]config.UserConfig{"alice": {Password: "old", Routes: []string{"direct"}}}
	newUsers := map[string]config.UserConfig{"alice": {Password: "new", Routes: []string{"direct"}}}
	authenticator := NewAuthenticator(oldUsers)
	credentials := []string{
		HashPassword(RawPassword("alice", "direct", "old")),
		HashPassword(RawPassword("alice", "direct", "new")),
	}

	var wait sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for iteration := 0; iteration < 1000; iteration++ {
				_, _ = authenticator.Authenticate(credentials[iteration%len(credentials)])
			}
		}()
	}
	for iteration := 0; iteration < 100; iteration++ {
		if iteration%2 == 0 {
			authenticator.UpdateUsers(newUsers)
		} else {
			authenticator.UpdateUsers(oldUsers)
		}
	}
	wait.Wait()
}
