// Package migration contains one-shot management-data migration tools.
package migration

import (
	"fmt"
	"strings"

	"github.com/clayicarus/proxy-gateway/internal/config"
	"github.com/clayicarus/proxy-gateway/internal/storage"
	"github.com/clayicarus/proxy-gateway/internal/subtoken"
	"go.uber.org/zap"
)

// RunLegacy imports a legacy YAML configuration into the management database.
// ReplaceUsers changes only user data and deliberately retains managed nodes
// and traffic records.
func RunLegacy(configPath string, replaceUsers bool, logger *zap.Logger) (int, int, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return 0, 0, fmt.Errorf("load legacy config: %w", err)
	}
	secret := cfg.API.Secret
	if cfg.Sub != nil && cfg.Sub.Secret != "" {
		secret = cfg.Sub.Secret
	}
	if secret == "" {
		return 0, 0, fmt.Errorf("legacy subscription secret is required (sub.secret or api.secret)")
	}
	store, err := storage.NewSQLiteStore(cfg.DBPath, logger)
	if err != nil {
		return 0, 0, fmt.Errorf("open sqlite store: %w", err)
	}
	defer store.Close()

	legacyToken := func(username string) string { return subtoken.Legacy(username, secret) }
	if replaceUsers {
		if err := store.ReplaceLegacyUsers(cfg, legacyToken); err != nil {
			return 0, 0, fmt.Errorf("replace legacy users: %w", err)
		}
		return len(cfg.Users), 0, nil
	}
	if err := store.MigrateLegacy(cfg, legacyToken); err != nil {
		if strings.Contains(err.Error(), "managed user data already exists") || strings.Contains(err.Error(), "already been migrated") {
			err = fmt.Errorf("%w; use migrate --replace-users only when you intend to replace all managed users", err)
		}
		return 0, 0, fmt.Errorf("migrate legacy configuration: %w", err)
	}
	return len(cfg.Users), len(cfg.Nodes), nil
}
