package router

import (
	"testing"

	"github.com/hy2-gateway/internal/config"
	"go.uber.org/zap"
)

func TestRouter_GetRoute(t *testing.T) {
	logger := zap.NewNop()
	users := map[string]config.UserConfig{
		"alice": {Password: "p", Routes: []string{"node_tokyo"}},
		"bob":   {Password: "p", Routes: []string{"direct"}},
	}
	r := NewRouter(users, logger)

	route, err := r.GetRoute("alice:node_tokyo")
	if err != nil || route != "node_tokyo" {
		t.Errorf("expected node_tokyo, got route=%q err=%v", route, err)
	}

	route, err = r.GetRoute("bob:direct")
	if err != nil || route != "direct" {
		t.Errorf("expected direct, got route=%q err=%v", route, err)
	}

	if route, err = r.GetRoute("unknown"); err == nil || route != "" {
		t.Errorf("expected missing node to fail, got route=%q err=%v", route, err)
	}
}
