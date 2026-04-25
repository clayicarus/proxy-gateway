package router

import (
	"testing"

	"github.com/hy2-gateway/internal/config"
	"go.uber.org/zap"
)

func TestRouter_GetRoute(t *testing.T) {
	logger := zap.NewNop()
	users := map[string]config.UserConfig{
		"alice": {Password: "p", Route: "node_tokyo"},
		"bob":   {Password: "p", Route: "direct"},
	}
	r := NewRouter(users, logger)

	route, err := r.GetRoute("alice")
	if err != nil || route != "node_tokyo" {
		t.Errorf("expected node_tokyo, got %s (err=%v)", route, err)
	}

	route, err = r.GetRoute("bob")
	if err != nil || route != "direct" {
		t.Errorf("expected direct, got %s (err=%v)", route, err)
	}

	_, err = r.GetRoute("unknown")
	if err == nil {
		t.Error("expected error for unknown user")
	}
}

func TestRouter_UpdateRoutes(t *testing.T) {
	logger := zap.NewNop()
	users := map[string]config.UserConfig{
		"alice": {Password: "p", Route: "node_tokyo"},
	}
	r := NewRouter(users, logger)

	// Update routes
	r.UpdateRoutes(map[string]config.UserConfig{
		"alice":   {Password: "p", Route: "node_sg"},
		"charlie": {Password: "p", Route: "direct"},
	})

	route, err := r.GetRoute("alice")
	if err != nil || route != "node_sg" {
		t.Errorf("expected node_sg after update, got %s", route)
	}

	route, err = r.GetRoute("charlie")
	if err != nil || route != "direct" {
		t.Errorf("expected direct for charlie, got %s", route)
	}
}
