package trojan

import (
	"crypto/sha256"
	"encoding/hex"
	"sync/atomic"
	"time"

	"github.com/clayicarus/proxy-gateway/internal/config"
)

const credentialLength = sha256.Size224 * 2

type credentialEntry struct {
	id       string
	disabled bool
	expires  *time.Time
}

type credentialIndex map[string]credentialEntry

// Authenticator atomically swaps immutable credential-index snapshots.
type Authenticator struct {
	index atomic.Pointer[credentialIndex]
	now   func() time.Time
}

// NewAuthenticator derives one protocol credential for every explicitly
// authorized (username, node) pair in users.
func NewAuthenticator(users map[string]config.UserConfig) *Authenticator {
	a := &Authenticator{now: time.Now}
	a.UpdateUsers(users)
	return a
}

// RawPassword returns the value configured as the password in a Trojan
// client. The Trojan wire protocol sends SHA-224 of this value.
func RawPassword(username, node, userPassword string) string {
	return username + ":" + node + ":" + userPassword
}

// HashPassword returns the lowercase, 56-character SHA-224 credential used
// on the Trojan wire protocol.
func HashPassword(password string) string {
	sum := sha256.Sum224([]byte(password))
	return hex.EncodeToString(sum[:])
}

// Authenticate resolves a fixed-format wire credential to username:node.
// It never returns or logs the credential itself.
func (a *Authenticator) Authenticate(credential string) (string, bool) {
	if !validCredential(credential) {
		return "", false
	}
	index := a.index.Load()
	if index == nil {
		return "", false
	}
	entry, ok := (*index)[credential]
	if !ok || entry.disabled || (entry.expires != nil && !entry.expires.After(a.now())) {
		return "", false
	}
	return entry.id, true
}

// UpdateUsers builds a new immutable index and publishes it atomically.
func (a *Authenticator) UpdateUsers(users map[string]config.UserConfig) {
	index := make(credentialIndex)
	for username, user := range users {
		for _, node := range user.Routes {
			credential := HashPassword(RawPassword(username, node, user.Password))
			index[credential] = credentialEntry{
				id:       username + ":" + node,
				disabled: user.Disabled,
				expires:  copyTime(user.ExpiresAt),
			}
		}
	}
	a.index.Store(&index)
}

func validCredential(credential string) bool {
	if len(credential) != credentialLength {
		return false
	}
	for i := 0; i < len(credential); i++ {
		if (credential[i] < '0' || credential[i] > '9') && (credential[i] < 'a' || credential[i] > 'f') {
			return false
		}
	}
	return true
}

func copyTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
