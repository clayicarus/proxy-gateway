package auth

import "github.com/clayicarus/proxy-gateway/internal/config"

// RefreshSnapshot applies hot-reloadable user fields while preserving the
// users and route authorizations captured at process startup. New users and
// route changes therefore remain pending until the next restart.
func RefreshSnapshot(startup, loaded map[string]config.UserConfig) map[string]config.UserConfig {
	updated := make(map[string]config.UserConfig, len(startup))
	for username, startupUser := range startup {
		if user, ok := loaded[username]; ok {
			user.Routes = append([]string(nil), startupUser.Routes...)
			updated[username] = user
			continue
		}
		startupUser.Routes = append([]string(nil), startupUser.Routes...)
		startupUser.Disabled = true
		updated[username] = startupUser
	}
	return updated
}
