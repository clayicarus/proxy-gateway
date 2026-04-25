package router

import (
	"testing"

	"go.uber.org/zap"
)

func TestRouter_GetRoute(t *testing.T) {
	logger := zap.NewNop()
	r := NewRouter(logger)

	// ID format is "username:node_name"
	route := r.GetRoute("alice:node_tokyo")
	if route != "node_tokyo" {
		t.Errorf("expected node_tokyo, got %s", route)
	}

	route = r.GetRoute("bob:direct")
	if route != "direct" {
		t.Errorf("expected direct, got %s", route)
	}

	// No node in ID should default to "direct"
	route = r.GetRoute("unknown")
	if route != "direct" {
		t.Errorf("expected direct for ID without node, got %s", route)
	}
}
