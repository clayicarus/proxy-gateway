package auth

import (
	"reflect"
	"testing"

	"github.com/clayicarus/proxy-gateway/internal/config"
)

func TestRefreshSnapshotPreservesStartupUsersAndRoutes(t *testing.T) {
	startup := map[string]config.UserConfig{
		"alice": {Password: "old", Routes: []string{"node1"}, MaxBytes: 1},
		"gone":  {Password: "old-gone", Routes: []string{"direct"}},
	}
	loaded := map[string]config.UserConfig{
		"alice": {Password: "new", Routes: []string{"node2", "direct"}, MaxBytes: 99, SpeedLimit: 42},
		"new":   {Password: "new-user", Routes: []string{"direct"}},
	}

	updated := RefreshSnapshot(startup, loaded)
	if len(updated) != 2 {
		t.Fatalf("updated users = %d, want 2", len(updated))
	}
	if _, ok := updated["new"]; ok {
		t.Fatal("new user became active before restart")
	}
	alice := updated["alice"]
	if alice.Password != "new" || alice.MaxBytes != 99 || alice.SpeedLimit != 42 {
		t.Fatal("hot password, quota or speed fields were not refreshed")
	}
	if !reflect.DeepEqual(alice.Routes, []string{"node1"}) {
		t.Fatalf("routes changed before restart: %#v", alice.Routes)
	}
	if !updated["gone"].Disabled {
		t.Fatal("deleted startup user was not disabled")
	}

	startup["alice"].Routes[0] = "mutated"
	if updated["alice"].Routes[0] != "node1" {
		t.Fatal("result aliases startup route storage")
	}
}
