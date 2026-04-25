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

func TestRouter_GetFallback(t *testing.T) {
	logger := zap.NewNop()
	users := map[string]config.UserConfig{
		"alice":   {Password: "p", Routes: []string{"node1"}, Fallback: "direct"},
		"bob":     {Password: "p", Routes: []string{"node1"}, Fallback: "node2"},
		"charlie": {Password: "p", Routes: []string{"node1"}}, // no fallback
	}
	r := NewRouter(users, logger)

	if fb := r.GetFallback("alice:node1"); fb != "direct" {
		t.Errorf("alice fallback: expected direct, got %s", fb)
	}
	if fb := r.GetFallback("bob:node1"); fb != "node2" {
		t.Errorf("bob fallback: expected node2, got %s", fb)
	}
	if fb := r.GetFallback("charlie:node1"); fb != "reject" {
		t.Errorf("charlie fallback: expected reject, got %s", fb)
	}
	if fb := r.GetFallback("unknown:node1"); fb != "reject" {
		t.Errorf("unknown fallback: expected reject, got %s", fb)
	}
}
