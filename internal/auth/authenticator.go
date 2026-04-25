package auth

import (
	"net"
	"strings"
	"sync"

	"github.com/hy2-gateway/internal/config"
	"go.uber.org/zap"
)

// Authenticator implements server.Authenticator from the Hysteria2 core library.
// It validates username:password pairs and returns the username as the client ID.
type Authenticator struct {
	users  map[string]string // username -> password
	mu     sync.RWMutex
	logger *zap.Logger
}

// NewAuthenticator creates a new Authenticator from user configs.
func NewAuthenticator(users map[string]config.UserConfig, logger *zap.Logger) *Authenticator {
	m := make(map[string]string, len(users))
	for name, u := range users {
		m[name] = u.Password
	}
	return &Authenticator{
		users:  m,
		logger: logger,
	}
}

// Authenticate implements server.Authenticator.
// The auth string is expected to be in "username:password" format.
// Returns (true, username) on success, (false, "") on failure.
func (a *Authenticator) Authenticate(addr net.Addr, auth string, tx uint64) (bool, string) {
	username, password := parseAuth(auth)
	if username == "" {
		a.logger.Warn("auth failed: empty username",
			zap.String("addr", addr.String()),
		)
		return false, ""
	}

	a.mu.RLock()
	expectedPassword, exists := a.users[username]
	a.mu.RUnlock()

	if !exists {
		a.logger.Warn("auth failed: unknown user",
			zap.String("addr", addr.String()),
			zap.String("username", username),
		)
		return false, ""
	}

	if password != expectedPassword {
		a.logger.Warn("auth failed: wrong password",
			zap.String("addr", addr.String()),
			zap.String("username", username),
		)
		return false, ""
	}

	a.logger.Info("auth success",
		zap.String("addr", addr.String()),
		zap.String("username", username),
		zap.Uint64("tx", tx),
	)
	return true, username
}

// UpdateUsers replaces the user map (for hot-reload).
func (a *Authenticator) UpdateUsers(users map[string]config.UserConfig) {
	m := make(map[string]string, len(users))
	for name, u := range users {
		m[name] = u.Password
	}
	a.mu.Lock()
	a.users = m
	a.mu.Unlock()
}

// parseAuth splits "username:password" into its parts.
// If there's no colon, the entire string is treated as a password with empty username.
func parseAuth(auth string) (username, password string) {
	idx := strings.IndexByte(auth, ':')
	if idx < 0 {
		return "", auth
	}
	return auth[:idx], auth[idx+1:]
}
