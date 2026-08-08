package api

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"text/template"

	"github.com/hy2-gateway/internal/config"
	"github.com/hy2-gateway/internal/storage"
	"go.uber.org/zap"
)

// DatabaseSubscriptionHandler serves bearer-token subscriptions backed by the
// managed-user database.
type DatabaseSubscriptionHandler struct {
	cfg          *config.Config
	store        *storage.SQLiteStore
	activeRoutes map[string][]string
	nodes        map[string]config.NodeConfig
	logger       *zap.Logger
	tmpl         *template.Template
}

// NewDatabaseSubscriptionHandler serves the restart-applied node and route
// snapshot. User lifecycle fields and credentials are intentionally looked up
// live, so a password reset, expiry, or soft delete does not need a restart.
func NewDatabaseSubscriptionHandler(cfg *config.Config, store *storage.SQLiteStore, users map[string]config.UserConfig, nodes map[string]config.NodeConfig, logger *zap.Logger) *DatabaseSubscriptionHandler {
	activeRoutes := make(map[string][]string, len(users))
	for username, user := range users {
		activeRoutes[username] = append([]string(nil), user.Routes...)
	}
	return &DatabaseSubscriptionHandler{
		cfg:          cfg,
		store:        store,
		activeRoutes: activeRoutes,
		nodes:        nodes,
		logger:       logger,
		tmpl:         template.Must(template.New("managed-clash").Parse(managedClashTemplate)),
	}
}

func (h *DatabaseSubscriptionHandler) Handler() http.Handler {
	return http.HandlerFunc(h.handle)
}

func (h *DatabaseSubscriptionHandler) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/sub/") {
		http.NotFound(w, r)
		return
	}
	token := strings.Trim(strings.TrimPrefix(r.URL.Path, "/sub/"), "/")
	if token == "" || strings.Contains(token, "/") {
		http.NotFound(w, r)
		return
	}
	user, err := h.store.FindUserByToken(token)
	if err != nil {
		h.logger.Error("subscription lookup failed", zap.Error(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if user == nil {
		http.Error(w, "invalid subscription", http.StatusForbidden)
		return
	}
	routes, active := h.activeRoutes[user.Username]
	if !active {
		// A newly created user is intentionally unavailable until Gateway has
		// restarted and loaded its node authorization snapshot.
		http.Error(w, "subscription pending Gateway restart", http.StatusServiceUnavailable)
		return
	}
	data := managedSubscriptionData{Username: user.Username, MonthlyBytes: user.MonthlyBytes}
	host, port := splitHostPort(h.gatewayAddress())
	for _, route := range routes {
		if route == "direct" {
			data.Proxies = append(data.Proxies, managedProxy{Name: "direct", Server: host, Port: port, Auth: fmt.Sprintf("%s:%s:%s", user.Username, route, user.Password)})
			continue
		}
		node, ok := h.nodes[route]
		if !ok {
			continue
		}
		name := node.Alias
		if name == "" {
			name = route
		}
		proxy := managedProxy{Name: name, Server: host, Port: port, Auth: fmt.Sprintf("%s:%s:%s", user.Username, route, user.Password), SNI: h.sni(), Insecure: h.insecure()}
		if h.cfg.Obfs != nil && h.cfg.Obfs.Type == "salamander" {
			proxy.Obfs = "salamander"
			proxy.ObfsPasswd = h.cfg.Obfs.Salamander.Password
		}
		data.Proxies = append(data.Proxies, proxy)
	}
	if len(data.Proxies) == 0 {
		http.Error(w, "subscription has no active routes", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.yaml"`, user.Username))
	w.Header().Set("Profile-Update-Interval", "24")
	// The standard header has no tx+rx notion. It is supplied as an advisory
	// total while Gateway remains the enforcement authority.
	if user.MonthlyBytes > 0 {
		w.Header().Set("Subscription-Userinfo", fmt.Sprintf("upload=0; download=0; total=%d", user.MonthlyBytes))
	}
	if err := h.tmpl.Execute(w, data); err != nil {
		h.logger.Error("render managed subscription", zap.Error(err))
	}
}

func (h *DatabaseSubscriptionHandler) gatewayAddress() string {
	if h.cfg.Sub != nil && h.cfg.Sub.ServerAddr != "" {
		return h.cfg.Sub.ServerAddr
	}
	return h.cfg.Listen
}

func (h *DatabaseSubscriptionHandler) sni() string {
	if h.cfg.Sub != nil {
		return h.cfg.Sub.SNI
	}
	return ""
}

func (h *DatabaseSubscriptionHandler) insecure() bool {
	return h.cfg.Sub != nil && h.cfg.Sub.Insecure
}

func splitHostPort(addr string) (host, port string) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, "443"
	}
	if host == "" {
		host = "127.0.0.1"
	}
	return host, port
}

type managedProxy struct {
	Name       string
	Server     string
	Port       string
	Auth       string
	SNI        string
	Insecure   bool
	Obfs       string
	ObfsPasswd string
}

type managedSubscriptionData struct {
	Username     string
	MonthlyBytes uint64
	Proxies      []managedProxy
}

const managedClashTemplate = `# managed user: {{.Username}}
ipv6: false
log-level: info
mode: rule
mixed-port: 7890

proxies:
{{- range .Proxies}}
  - name: "{{.Name}}"
    type: hysteria2
    server: {{.Server}}
    port: {{.Port}}
    password: "{{.Auth}}"
{{- if .SNI}}
    sni: {{.SNI}}
{{- end}}
{{- if .Insecure}}
    skip-cert-verify: true
{{- end}}
{{- if .Obfs}}
    obfs: {{.Obfs}}
    obfs-password: "{{.ObfsPasswd}}"
{{- end}}
{{- end}}

proxy-groups:
  - name: "规则代理"
    type: select
    proxies:
{{- range .Proxies}}
      - "{{.Name}}"
{{- end}}
      - DIRECT

rules:
  - GEOIP,CN,DIRECT
  - MATCH,规则代理
`
