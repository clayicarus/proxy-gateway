package router

import (
	"github.com/hy2-gateway/internal/auth"
	"go.uber.org/zap"
)

// Router resolves the outbound node from the authenticated ID.
// Since the auth format is now "username:node_name:password",
// the ID returned by Authenticator is "username:node_name",
// so the route is directly embedded in the ID.
type Router struct {
	logger *zap.Logger
}

// NewRouter creates a new Router.
func NewRouter(logger *zap.Logger) *Router {
	return &Router{
		logger: logger,
	}
}

// GetRoute extracts the node name from the authenticated ID ("username:node_name").
func (r *Router) GetRoute(id string) string {
	_, nodeName := auth.ParseID(id)
	if nodeName == "" {
		r.logger.Warn("no node in ID, defaulting to direct", zap.String("id", id))
		return "direct"
	}
	return nodeName
}
