package router

import (
	"github.com/hy2-gateway/internal/auth"
	"github.com/hy2-gateway/internal/config"
	"go.uber.org/zap"
)

// Router resolves the outbound node from the authenticated ID.
// The ID format is "username:node_name" (set by Authenticator).
type Router struct {
	// fallbacks maps username -> fallback node name ("reject", "direct", or a node name)
	fallbacks map[string]string
	logger    *zap.Logger
}

// NewRouter creates a new Router.
func NewRouter(users map[string]config.UserConfig, logger *zap.Logger) *Router {
	fb := make(map[string]string, len(users))
	for name, u := range users {
		if u.Fallback == "" {
			fb[name] = "reject"
		} else {
			fb[name] = u.Fallback
		}
	}
	return &Router{
		fallbacks: fb,
		logger:    logger,
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

// GetFallback returns the fallback route for a user.
// Returns "reject" if no fallback is configured (caller should return error).
func (r *Router) GetFallback(id string) string {
	username, _ := auth.ParseID(id)
	if fb, ok := r.fallbacks[username]; ok {
		return fb
	}
	return "reject"
}
