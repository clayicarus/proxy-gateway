package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"text/template"

	"github.com/hy2-gateway/internal/config"
	"go.uber.org/zap"
)

// SubscriptionHandler generates per-user Clash.Meta (mihomo) configs.
type SubscriptionHandler struct {
	cfg    *config.Config
	secret string // HMAC key for token generation
	logger *zap.Logger
	tmpl   *template.Template
}

// NewSubscriptionHandler creates a new subscription handler.
// secret is the HMAC key; if sub.secret is set it takes precedence over api.secret.
func NewSubscriptionHandler(cfg *config.Config, logger *zap.Logger) *SubscriptionHandler {
	secret := cfg.API.Secret
	if cfg.Sub != nil && cfg.Sub.Secret != "" {
		secret = cfg.Sub.Secret
	}

	h := &SubscriptionHandler{
		cfg:    cfg,
		secret: secret,
		logger: logger,
	}
	h.tmpl = template.Must(template.New("clash").Parse(clashTemplate))
	return h
}

// GenerateToken creates an HMAC-SHA256 token for a given username.
func (h *SubscriptionHandler) GenerateToken(username string) string {
	mac := hmac.New(sha256.New, []byte(h.secret))
	mac.Write([]byte(username))
	return hex.EncodeToString(mac.Sum(nil))
}

// ValidateToken checks the token and returns the matching username, or "" if invalid.
func (h *SubscriptionHandler) ValidateToken(token string) string {
	for username := range h.cfg.Users {
		if hmac.Equal([]byte(h.GenerateToken(username)), []byte(token)) {
			return username
		}
	}
	return ""
}

// HandleSubscription serves GET /sub/{token}
func (h *SubscriptionHandler) HandleSubscription(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract token from path: /sub/{token}
	token := strings.TrimPrefix(r.URL.Path, "/sub/")
	token = strings.TrimSuffix(token, "/")
	if token == "" || token == "tokens" {
		return // let other handlers deal with it
	}

	username := h.ValidateToken(token)
	if username == "" {
		h.logger.Warn("subscription: invalid token",
			zap.String("addr", r.RemoteAddr),
			zap.String("token", token[:min(8, len(token))]+"..."),
		)
		http.Error(w, "invalid token", http.StatusForbidden)
		return
	}

	userCfg := h.cfg.Users[username]
	data := h.buildTemplateData(username, userCfg)

	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.yaml"`, username))
	w.Header().Set("Profile-Update-Interval", "24")
	if userinfo := h.buildUserinfo(username); userinfo != "" {
		w.Header().Set("Subscription-Userinfo", userinfo)
	}

	if err := h.tmpl.Execute(w, data); err != nil {
		h.logger.Error("subscription: template render failed",
			zap.String("username", username),
			zap.Error(err),
		)
	}
}

// HandleTokenList serves GET /sub/tokens (admin endpoint, requires auth).
// Returns a JSON list of username -> token for convenience.
func (h *SubscriptionHandler) HandleTokenList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	type tokenEntry struct {
		Username string   `json:"username"`
		Token    string   `json:"token"`
		Routes   []string `json:"routes"`
	}

	entries := make([]tokenEntry, 0, len(h.cfg.Users))
	for username, userCfg := range h.cfg.Users {
		entries = append(entries, tokenEntry{
			Username: username,
			Token:    h.GenerateToken(username),
			Routes:   userCfg.Routes,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, entries)
}

type clashProxyData struct {
	Name       string
	Server     string
	Port       string
	Auth       string // username:node_name:password
	SNI        string
	Insecure   bool
	Obfs       string
	ObfsPasswd string
}

type clashTemplateData struct {
	Username string
	Proxies  []clashProxyData
}

func (h *SubscriptionHandler) buildTemplateData(username string, userCfg config.UserConfig) clashTemplateData {
	serverAddr := h.cfg.Listen
	if h.cfg.Sub != nil && h.cfg.Sub.ServerAddr != "" {
		serverAddr = h.cfg.Sub.ServerAddr
	}

	host, port := splitHostPort(serverAddr)

	sni := host
	if h.cfg.Sub != nil && h.cfg.Sub.SNI != "" {
		sni = h.cfg.Sub.SNI
	}

	insecure := false
	if h.cfg.Sub != nil {
		insecure = h.cfg.Sub.Insecure
	}

	var proxies []clashProxyData
	for _, route := range userCfg.Routes {
		// Auth format: username:node_name:password
		auth := fmt.Sprintf("%s:%s:%s", username, route, userCfg.Password)

		proxy := clashProxyData{
			Name:     route, // use node name as proxy name
			Server:   host,
			Port:     port,
			Auth:     auth,
			SNI:      sni,
			Insecure: insecure,
		}

		if h.cfg.Obfs != nil && h.cfg.Obfs.Type == "salamander" {
			proxy.Obfs = "salamander"
			proxy.ObfsPasswd = h.cfg.Obfs.Salamander.Password
		}

		proxies = append(proxies, proxy)
	}

	return clashTemplateData{
		Username: username,
		Proxies:  proxies,
	}
}

func (h *SubscriptionHandler) buildUserinfo(username string) string {
	userCfg := h.cfg.Users[username]
	if userCfg.MaxBytes == 0 {
		return ""
	}
	return fmt.Sprintf("upload=0; download=0; total=%d", userCfg.MaxBytes)
}

// splitHostPort splits "host:port" or ":port". If no port, defaults to "443".
func splitHostPort(addr string) (host, port string) {
	if idx := strings.LastIndex(addr, ":"); idx >= 0 {
		host = addr[:idx]
		port = addr[idx+1:]
	} else {
		host = addr
		port = "443"
	}
	if host == "" {
		host = "127.0.0.1"
	}
	return
}

const clashTemplate = `# Clash.Meta (mihomo) 配置
# 自动生成，请勿手动修改
# 用户: {{.Username}}

mixed-port: 7890
allow-lan: false
mode: rule
log-level: info
unified-delay: true
tcp-concurrent: true

dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  fallback:
    - https://dns.google/dns-query
    - https://cloudflare-dns.com/dns-query
  fallback-filter:
    geoip: true
    geoip-code: CN

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
  - name: "Proxy"
    type: select
    proxies:
{{- range .Proxies}}
      - "{{.Name}}"
{{- end}}
      - DIRECT

  - name: "Auto"
    type: url-test
    proxies:
{{- range .Proxies}}
      - "{{.Name}}"
{{- end}}
    url: https://www.gstatic.com/generate_204
    interval: 300

rules:
  # 私有地址直连
  - IP-CIDR,127.0.0.0/8,DIRECT
  - IP-CIDR,192.168.0.0/16,DIRECT
  - IP-CIDR,10.0.0.0/8,DIRECT
  - IP-CIDR,172.16.0.0/12,DIRECT

  # 国内域名直连
  - GEOSITE,cn,DIRECT
  - GEOIP,CN,DIRECT

  # 其余走代理
  - MATCH,Proxy
`
