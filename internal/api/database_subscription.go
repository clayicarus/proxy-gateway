package api

import (
	"bytes"
	"fmt"
	"maps"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/clayicarus/proxy-gateway/internal/config"
	"github.com/clayicarus/proxy-gateway/internal/storage"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// DatabaseSubscriptionHandler serves bearer-token subscriptions backed by the
// managed-user database.
type DatabaseSubscriptionHandler struct {
	cfg          *config.Config
	store        *storage.SQLiteStore
	activeRoutes map[string][]string
	nodes        map[string]config.NodeConfig
	logger       *zap.Logger
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
		nodes:        maps.Clone(nodes),
		logger:       logger,
	}
}

func (h *DatabaseSubscriptionHandler) Handler() http.Handler {
	return http.HandlerFunc(h.handle)
}

func (h *DatabaseSubscriptionHandler) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
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
	endpoints, err := h.subscriptionEndpoints()
	if err != nil {
		h.logger.Error("invalid subscription configuration", zap.Error(err))
		http.Error(w, "subscription is unavailable", http.StatusServiceUnavailable)
		return
	}
	protocolCounts := make(map[string]int)
	for _, endpoint := range endpoints {
		protocolCounts[endpoint.Type]++
	}
	// Built-in outbound and group names must not be shadowed by node aliases.
	usedNames := map[string]bool{
		"DIRECT": true, "REJECT": true, "REJECT-DROP": true,
		"PASS": true, "COMPATIBLE": true, "GLOBAL": true, "规则代理": true,
	}
	data := managedSubscriptionData{}
	for _, route := range routes {
		alias := route
		if route != "direct" {
			node, ok := h.nodes[route]
			if !ok {
				continue
			}
			if node.Alias != "" {
				alias = node.Alias
			}
		}
		for _, endpoint := range endpoints {
			name := alias
			// Preserve existing Hysteria2-only names. Mixed subscriptions and
			// Trojan entries make the selected protocol visible to the user.
			if len(endpoints) > 1 || endpoint.Type == config.TrojanInboundType {
				name += "-" + endpoint.Type
			}
			if protocolCounts[endpoint.Type] > 1 {
				name += "-" + endpoint.Inbound
			}
			data.Proxies = append(data.Proxies, managedProxy{
				Name: uniqueProxyName(name, usedNames), Type: endpoint.Type,
				Server: endpoint.Server, Port: endpoint.Port,
				Auth: fmt.Sprintf("%s:%s:%s", user.Username, route, user.Password),
				SNI:  endpoint.SNI, Insecure: endpoint.Insecure,
				UDP: endpoint.Type == config.TrojanInboundType, ALPN: endpoint.ALPN,
			})
		}
	}
	if len(data.Proxies) == 0 {
		http.Error(w, "subscription has no active routes", http.StatusServiceUnavailable)
		return
	}
	body, err := renderManagedSubscription(data)
	if err != nil {
		h.logger.Error("render managed subscription", zap.Error(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": user.Username + ".yaml"}))
	w.Header().Set("Profile-Update-Interval", "24")
	// The standard header has no tx+rx notion. It is supplied as an advisory
	// total while Gateway remains the enforcement authority.
	if user.MonthlyBytes > 0 {
		w.Header().Set("Subscription-Userinfo", fmt.Sprintf("upload=0; download=0; total=%d", user.MonthlyBytes))
	}
	_, _ = w.Write(body)
}

type subscriptionEndpoint struct {
	config.SubscriptionEndpoint
	Type   string
	Server string
	Port   int
	ALPN   []string
}

func (h *DatabaseSubscriptionHandler) subscriptionEndpoints() ([]subscriptionEndpoint, error) {
	inbounds := make(map[string]config.Inbound, len(h.cfg.Inbounds))
	for _, inbound := range h.cfg.Inbounds {
		inbounds[inbound.Name] = inbound
	}
	var endpoints []subscriptionEndpoint
	for _, published := range h.cfg.Sub.ClientEndpoints() {
		inbound := inbounds[published.Inbound]
		protocol := inbound.Type
		if protocol != config.Hysteria2InboundType && protocol != config.TrojanInboundType {
			return nil, fmt.Errorf("subscription inbound %q is missing or unsupported", published.Inbound)
		}
		host, rawPort, err := net.SplitHostPort(published.ServerAddr)
		if err != nil || host == "" || net.ParseIP(host).IsUnspecified() {
			return nil, fmt.Errorf("subscription inbound %q requires a client-reachable serverAddr", published.Inbound)
		}
		port, err := strconv.Atoi(rawPort)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("subscription inbound %q has an invalid serverAddr port", published.Inbound)
		}
		endpoint := subscriptionEndpoint{
			SubscriptionEndpoint: published, Type: protocol, Server: host, Port: port,
		}
		if protocol == config.TrojanInboundType && inbound.Trojan != nil && inbound.Trojan.Fallback != nil {
			endpoint.ALPN = []string{"http/1.1"}
		}
		endpoints = append(endpoints, endpoint)
	}
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("no subscription endpoints are configured")
	}
	return endpoints, nil
}

func uniqueProxyName(base string, used map[string]bool) string {
	name := base
	for suffix := 2; used[name]; suffix++ {
		name = fmt.Sprintf("%s (%d)", base, suffix)
	}
	used[name] = true
	return name
}

type managedProxy struct {
	Name     string   `yaml:"name"`
	Type     string   `yaml:"type"`
	Server   string   `yaml:"server"`
	Port     int      `yaml:"port"`
	Auth     string   `yaml:"password"`
	SNI      string   `yaml:"sni,omitempty"`
	Insecure bool     `yaml:"skip-cert-verify"`
	UDP      bool     `yaml:"udp,omitempty"`
	ALPN     []string `yaml:"alpn,omitempty"`
}

type managedSubscriptionData struct {
	Proxies []managedProxy
}

type managedProxyGroup struct {
	Name    string   `yaml:"name"`
	Type    string   `yaml:"type"`
	Proxies []string `yaml:"proxies"`
}

type managedClashConfig struct {
	IPv6        bool                `yaml:"ipv6"`
	LogLevel    string              `yaml:"log-level"`
	Mode        string              `yaml:"mode"`
	MixedPort   int                 `yaml:"mixed-port"`
	Proxies     []managedProxy      `yaml:"proxies"`
	ProxyGroups []managedProxyGroup `yaml:"proxy-groups"`
	Rules       []string            `yaml:"rules"`
}

func renderManagedSubscription(data managedSubscriptionData) ([]byte, error) {
	names := make([]string, 0, len(data.Proxies)+1)
	for i := range data.Proxies {
		names = append(names, data.Proxies[i].Name)
	}
	names = append(names, "DIRECT")
	cfg := managedClashConfig{
		IPv6:      false,
		LogLevel:  "info",
		Mode:      "rule",
		MixedPort: 7890,
		Proxies:   data.Proxies,
		ProxyGroups: []managedProxyGroup{{
			Name:    "规则代理",
			Type:    "select",
			Proxies: names,
		}},
		Rules: []string{"GEOIP,CN,DIRECT", "MATCH,规则代理"},
	}
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(cfg); err != nil {
		return nil, err
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}
