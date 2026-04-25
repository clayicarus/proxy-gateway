package router

import (
	"fmt"
	"sync"

	"github.com/hy2-gateway/internal/config"
	"go.uber.org/zap"
)

// Router manages the mapping from user IDs to outbound nodes.
type Router struct {
	// userRoutes maps userId -> node name (or "direct")
	userRoutes map[string]string
	mu         sync.RWMutex
	logger     *zap.Logger
}

// NewRouter creates a new Router from user configs.
func NewRouter(users map[string]config.UserConfig, logger *zap.Logger) *Router {
	routes := make(map[string]string, len(users))
	for name, u := range users {
		routes[name] = u.Route
	}
	return &Router{
		userRoutes: routes,
		logger:     logger,
	}
}

// GetRoute returns the outbound node name for a given user.
func (r *Router) GetRoute(userId string) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	route, ok := r.userRoutes[userId]
	if !ok {
		return "", fmt.Errorf("no route configured for user %q", userId)
	}
	return route, nil
}

// UpdateRoutes replaces the routing table (for hot-reload).
func (r *Router) UpdateRoutes(users map[string]config.UserConfig) {
	routes := make(map[string]string, len(users))
	for name, u := range users {
		routes[name] = u.Route
	}
	r.mu.Lock()
	r.userRoutes = routes
	r.mu.Unlock()
}
