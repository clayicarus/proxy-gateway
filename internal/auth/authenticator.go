package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/clayicarus/proxy-gateway/internal/config"
	"go.uber.org/zap"
)

// userEntry holds the password and allowed nodes for a user.
type userEntry struct {
	password   string
	routes     map[string]bool // set of allowed node names
	disabled   bool
	expires    *time.Time
	maxBytes   uint64
	speedLimit uint64
}

// Authenticator implements server.Authenticator from the Hysteria2 core library.
// It validates "username:node_name:password" triples and returns "username:node_name"
// as the client ID, which is then used by the router and traffic logger.
type Authenticator struct {
	users  map[string]*userEntry // username -> entry
	trojan map[string]string     // SHA-224 credential -> username:node
	mu     sync.RWMutex
	logger *zap.Logger
}

// NewAuthenticator creates a new Authenticator from user configs.
func NewAuthenticator(users map[string]config.UserConfig, logger *zap.Logger) *Authenticator {
	return &Authenticator{
		users:  buildUserEntries(users),
		trojan: buildTrojanCredentials(users),
		logger: logger,
	}
}

// Authenticate implements server.Authenticator.
// The auth string is expected to be in "username:node_name:password" format.
// Returns (true, "username:node_name") on success, (false, "") on failure.
func (a *Authenticator) Authenticate(addr net.Addr, auth string, tx uint64) (bool, string) {
	username, nodeName, password := parseAuth(auth)
	if username == "" {
		a.logger.Warn("auth failed: empty username",
			zap.String("addr", addr.String()),
		)
		return false, ""
	}
	if nodeName == "" {
		a.logger.Warn("auth failed: empty node name",
			zap.String("addr", addr.String()),
			zap.String("username", username),
		)
		return false, ""
	}

	a.mu.RLock()
	entry, exists := a.users[username]
	a.mu.RUnlock()

	if !exists {
		a.logger.Warn("auth failed: unknown user",
			zap.String("addr", addr.String()),
			zap.String("username", username),
		)
		return false, ""
	}
	if entry.disabled || (entry.expires != nil && !entry.expires.After(time.Now())) {
		a.logger.Warn("auth failed: inactive user",
			zap.String("addr", addr.String()),
			zap.String("username", username),
		)
		return false, ""
	}

	if password != entry.password {
		a.logger.Warn("auth failed: wrong password",
			zap.String("addr", addr.String()),
			zap.String("username", username),
		)
		return false, ""
	}

	if !entry.routes[nodeName] {
		a.logger.Warn("auth failed: node not allowed for user",
			zap.String("addr", addr.String()),
			zap.String("username", username),
			zap.String("node", nodeName),
		)
		return false, ""
	}

	id := username + ":" + nodeName
	a.logger.Info("auth success",
		zap.String("addr", addr.String()),
		zap.String("username", username),
		zap.String("node", nodeName),
		zap.Uint64("tx", tx),
	)
	return true, id
}

// UpdateUsers replaces the user map (for hot-reload).
func (a *Authenticator) UpdateUsers(users map[string]config.UserConfig) {
	a.mu.Lock()
	a.users = buildUserEntries(users)
	a.trojan = buildTrojanCredentials(users)
	a.mu.Unlock()
}

// AuthenticateTrojan resolves Trojan's fixed SHA-224 credential to an
// authorized route. The raw Trojan password is never retained or logged.
func (a *Authenticator) AuthenticateTrojan(addr net.Addr, credential string) (bool, string) {
	if !validTrojanCredential(credential) {
		return false, ""
	}
	a.mu.RLock()
	id, ok := a.trojan[credential]
	if !ok {
		a.mu.RUnlock()
		return false, ""
	}
	username, _ := ParseID(id)
	entry := a.users[username]
	active := entry != nil && !entry.disabled && (entry.expires == nil || entry.expires.After(time.Now()))
	a.mu.RUnlock()
	if !active {
		return false, ""
	}
	return true, id
}

// User returns the currently published policy for one user. Callers that make
// authorization or accounting decisions must read this shared snapshot instead
// of retaining their own independently refreshed user map.
func (a *Authenticator) User(username string) (config.UserConfig, bool) {
	a.mu.RLock()
	entry, ok := a.users[username]
	if !ok {
		a.mu.RUnlock()
		return config.UserConfig{}, false
	}
	user := userConfig(entry)
	a.mu.RUnlock()
	return user, true
}

// Snapshot returns a copy of the currently published policy.
func (a *Authenticator) Snapshot() map[string]config.UserConfig {
	a.mu.RLock()
	users := make(map[string]config.UserConfig, len(a.users))
	for username, entry := range a.users {
		users[username] = userConfig(entry)
	}
	a.mu.RUnlock()
	return users
}

func buildUserEntries(users map[string]config.UserConfig) map[string]*userEntry {
	m := make(map[string]*userEntry, len(users))
	for name, u := range users {
		routes := make(map[string]bool, len(u.Routes))
		for _, r := range u.Routes {
			routes[r] = true
		}
		m[name] = &userEntry{
			password:   u.Password,
			routes:     routes,
			disabled:   u.Disabled,
			expires:    u.ExpiresAt,
			maxBytes:   u.MaxBytes,
			speedLimit: u.SpeedLimit,
		}
	}
	return m
}

func buildTrojanCredentials(users map[string]config.UserConfig) map[string]string {
	credentials := make(map[string]string)
	for username, user := range users {
		for _, node := range user.Routes {
			raw := username + ":" + node + ":" + user.Password
			sum := sha256.Sum224([]byte(raw))
			credentials[hex.EncodeToString(sum[:])] = username + ":" + node
		}
	}
	return credentials
}

func validTrojanCredential(value string) bool {
	if len(value) != sha256.Size224*2 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if (value[i] < '0' || value[i] > '9') && (value[i] < 'a' || value[i] > 'f') {
			return false
		}
	}
	return true
}

func userConfig(entry *userEntry) config.UserConfig {
	routes := make([]string, 0, len(entry.routes))
	for route := range entry.routes {
		routes = append(routes, route)
	}
	sort.Strings(routes)
	return config.UserConfig{
		Password: entry.password, Routes: routes, Disabled: entry.disabled,
		ExpiresAt: entry.expires, MaxBytes: entry.maxBytes, SpeedLimit: entry.speedLimit,
	}
}

// parseAuth splits "username:node_name:password" into its parts.
// Format: first colon separates username, second colon separates node_name from password.
// Everything after the second colon is the password (may contain colons).
func parseAuth(auth string) (username, nodeName, password string) {
	// Find first colon -> username
	idx1 := strings.IndexByte(auth, ':')
	if idx1 < 0 {
		return "", "", auth
	}
	username = auth[:idx1]
	rest := auth[idx1+1:]

	// Find second colon -> node_name : password
	idx2 := strings.IndexByte(rest, ':')
	if idx2 < 0 {
		// Only one colon: treat as username:password (legacy, will fail node check)
		return username, "", rest
	}
	nodeName = rest[:idx2]
	password = rest[idx2+1:]
	return
}

// ParseID splits a "username:node_name" ID back into its parts.
func ParseID(id string) (username, nodeName string) {
	idx := strings.IndexByte(id, ':')
	if idx < 0 {
		return id, ""
	}
	return id[:idx], id[idx+1:]
}
