package router

import (
	"fmt"

	"github.com/clayicarus/proxy-gateway/internal/auth"
	"github.com/clayicarus/proxy-gateway/internal/config"
	"go.uber.org/zap"
)

// Router resolves the outbound node from the authenticated ID.
// The ID format is "username:node_name" (set by Authenticator).
type Router struct {
	logger *zap.Logger
}

// NewRouter creates a new Router.
func NewRouter(_ map[string]config.UserConfig, logger *zap.Logger) *Router {
	return &Router{
		logger: logger,
	}
}

// GetRoute extracts the node name from the authenticated ID ("username:node_name").
func (r *Router) GetRoute(id string) (string, error) {
	username, nodeName := auth.ParseID(id)
	if username == "" || nodeName == "" {
		r.logger.Warn("invalid authenticated ID: node is required", zap.String("id", id))
		return "", fmt.Errorf("invalid authenticated ID %q: node is required", id)
	}
	return nodeName, nil
}
