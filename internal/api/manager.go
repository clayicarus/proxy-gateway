package api

import (
	"bytes"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hy2-gateway/internal/config"
	"github.com/hy2-gateway/internal/connection"
	"github.com/hy2-gateway/internal/storage"
	"github.com/hy2-gateway/internal/subtoken"
	"github.com/hy2-gateway/internal/systemd"
	"github.com/hy2-gateway/internal/traffic"
	"go.uber.org/zap"
)

// Manager serves the loopback-only management web UI. It deliberately uses
// server-rendered forms and does not expose a general management JSON API.
type Manager struct {
	cfg         *config.Config
	store       *storage.SQLiteStore
	traffic     *traffic.TrafficLogger
	connections *connection.Tracker
	logger      *zap.Logger
	csrf        string
	loc         *time.Location
	tmpl        *template.Template
}

type dashboardData struct {
	CSRF               string
	Users              []storage.ManagedUser
	Nodes              []storage.ManagedNode
	State              storage.ConfigState
	Monthly            map[string][2]uint64
	NodeMonthly        map[string][2]uint64
	MonthLabel         string
	Flash              string
	Now                time.Time
	RestartJobs        []storage.RestartJob
	ProcessRuns        []storage.ProcessRun
	SystemdInfo        string
	SystemdConfigured  bool
	TotalUsers         int
	ActiveUsers        int
	EnabledNodes       int
	MonthlyTotal       uint64
	NodeEgressTotal    uint64
	OnlineCount        int32
	GatewayListen      string
	AdminListen        string
	SubscriptionListen string
	DBPath             string
	FlushInterval      time.Duration
	Timezone           string
}

type liveTraffic struct {
	TxBytes uint64 `json:"txBytes"`
	RxBytes uint64 `json:"rxBytes"`
	Online  int32  `json:"online"`
}

type liveStatus struct {
	SampledAt   int64                  `json:"sampledAt"`
	Total       liveTraffic            `json:"total"`
	Users       map[string]liveTraffic `json:"users"`
	Nodes       map[string]liveTraffic `json:"nodes"`
	Connections []connection.Snapshot  `json:"connections"`
}

type rangeTraffic struct {
	Name    string `json:"name"`
	TxBytes uint64 `json:"txBytes"`
	RxBytes uint64 `json:"rxBytes"`
}

type hourlyTraffic struct {
	Hour    time.Time `json:"hour"`
	TxBytes uint64    `json:"txBytes"`
	RxBytes uint64    `json:"rxBytes"`
}

type trafficRangeStatus struct {
	Start      time.Time       `json:"start"`
	End        time.Time       `json:"end"`
	Timezone   string          `json:"timezone"`
	Total      rangeTraffic    `json:"total"`
	NodeEgress uint64          `json:"nodeEgressBytes"`
	Users      []rangeTraffic  `json:"users"`
	Nodes      []rangeTraffic  `json:"nodes"`
	Hours      []hourlyTraffic `json:"hours"`
}

//go:embed web/dashboard.html
var managerTemplate string

//go:embed web/admin.css
var managerCSS []byte

//go:embed web/admin.js
var managerJS []byte

// NewManager creates the local management application.
func NewManager(cfg *config.Config, store *storage.SQLiteStore, trafficLogger *traffic.TrafficLogger, logger *zap.Logger, trackers ...*connection.Tracker) (*Manager, error) {
	loc, err := time.LoadLocation(cfg.Timezone)
	if err != nil {
		return nil, err
	}
	csrf, err := randomCSRF()
	if err != nil {
		return nil, err
	}
	m := &Manager{cfg: cfg, store: store, traffic: trafficLogger, logger: logger, csrf: csrf, loc: loc}
	if len(trackers) > 0 {
		m.connections = trackers[0]
	}
	m.tmpl = template.Must(template.New("dashboard").Funcs(template.FuncMap{
		"bytes": formatBytes,
		"date": func(value *time.Time) string {
			if value == nil {
				return "never"
			}
			return value.In(loc).Format("2006-01-02 15:04")
		},
		"routes": strings.Join,
		"add":    func(a, b uint64) uint64 { return a + b },
		"contains": func(values []string, target string) bool {
			for _, value := range values {
				if value == target {
					return true
				}
			}
			return false
		},
		"datetime": func(value *time.Time) string {
			if value == nil {
				return ""
			}
			return value.In(loc).Format("2006-01-02T15:04")
		},
		"expired": func(value *time.Time, now time.Time) bool {
			return value != nil && !value.After(now)
		},
		"timefmt": func(value time.Time) string {
			return value.In(loc).Format("2006-01-02 15:04:05")
		},
		"percent": func(used, limit uint64) int {
			if limit == 0 {
				return 0
			}
			if used >= limit {
				return 100
			}
			return int(float64(used) / float64(limit) * 100)
		},
	}).Parse(managerTemplate))
	return m, nil
}

func randomCSRF() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

// Handler returns the loopback management handler.
func (m *Manager) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", m.dashboard)
	mux.HandleFunc("/assets/admin.css", m.staticAsset("text/css; charset=utf-8", managerCSS))
	mux.HandleFunc("/assets/admin.js", m.staticAsset("text/javascript; charset=utf-8", managerJS))
	mux.HandleFunc("/live", m.live)
	mux.HandleFunc("/traffic-range", m.trafficRange)
	mux.HandleFunc("/users", m.withCSRF(m.createUser))
	mux.HandleFunc("/users/", m.withCSRF(m.userAction))
	mux.HandleFunc("/nodes", m.withCSRF(m.saveNode))
	mux.HandleFunc("/nodes/", m.withCSRF(m.nodeAction))
	mux.HandleFunc("/restart", m.withCSRF(m.restartAction))
	return m.withSecurityHeaders(mux)
}

func (m *Manager) withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func (m *Manager) staticAsset(contentType string, body []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", contentType)
		// Admin assets are embedded in the binary and must change atomically with
		// the HTML that references them. Caching can pair new markup with old JS.
		w.Header().Set("Cache-Control", "no-store")
		if r.Method == http.MethodGet {
			_, _ = w.Write(body)
		}
	}
}

func (m *Manager) live(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	status := liveStatus{
		SampledAt: time.Now().UnixMilli(),
		Users:     make(map[string]liveTraffic),
		Nodes:     make(map[string]liveTraffic),
	}
	if m.connections != nil {
		status.Connections = m.connections.Snapshots()
	}
	for _, snapshot := range m.traffic.GetAllSnapshots() {
		user := status.Users[snapshot.Username]
		user.TxBytes += snapshot.TxBytes
		user.RxBytes += snapshot.RxBytes
		user.Online += snapshot.OnlineCount
		status.Users[snapshot.Username] = user

		node := status.Nodes[snapshot.Node]
		node.TxBytes += snapshot.TxBytes
		node.RxBytes += snapshot.RxBytes
		node.Online += snapshot.OnlineCount
		status.Nodes[snapshot.Node] = node

		status.Total.TxBytes += snapshot.TxBytes
		status.Total.RxBytes += snapshot.RxBytes
		status.Total.Online += snapshot.OnlineCount
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(status); err != nil {
		m.logger.Debug("write live management status", zap.Error(err))
	}
}

func (m *Manager) trafficRange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	start, err := time.ParseInLocation("2006-01-02T15:04", r.URL.Query().Get("start"), m.loc)
	if err != nil {
		http.Error(w, "invalid start time", http.StatusBadRequest)
		return
	}
	end, err := time.ParseInLocation("2006-01-02T15:04", r.URL.Query().Get("end"), m.loc)
	if err != nil {
		http.Error(w, "invalid end time", http.StatusBadRequest)
		return
	}
	if !end.After(start) {
		http.Error(w, "end time must be after start time", http.StatusBadRequest)
		return
	}
	if end.Sub(start) > 366*24*time.Hour {
		http.Error(w, "time range cannot exceed 366 days", http.StatusBadRequest)
		return
	}

	// Include the latest in-memory deltas in the persisted range query.
	m.traffic.Flush()
	buckets, err := m.store.GetTrafficBuckets(start.UTC(), end.UTC())
	if err != nil {
		m.writeError(w, err)
		return
	}
	users := make(map[string][2]uint64)
	nodes := make(map[string][2]uint64)
	hours := make(map[time.Time][2]uint64)
	status := trafficRangeStatus{
		Start:    start,
		End:      end,
		Timezone: m.cfg.Timezone,
		Users:    make([]rangeTraffic, 0),
		Nodes:    make([]rangeTraffic, 0),
		Hours:    make([]hourlyTraffic, 0),
	}
	for _, bucket := range buckets {
		user := users[bucket.UserID]
		user[0] += bucket.TxBytes
		user[1] += bucket.RxBytes
		users[bucket.UserID] = user
		node := nodes[bucket.NodeID]
		node[0] += bucket.TxBytes
		node[1] += bucket.RxBytes
		nodes[bucket.NodeID] = node
		hour := hours[bucket.Hour]
		hour[0] += bucket.TxBytes
		hour[1] += bucket.RxBytes
		hours[bucket.Hour] = hour
		status.Total.TxBytes += bucket.TxBytes
		status.Total.RxBytes += bucket.RxBytes
		if bucket.NodeID != "direct" {
			status.NodeEgress += bucket.TxBytes + bucket.RxBytes
		}
	}
	status.Total.Name = "全部"
	for name, usage := range users {
		status.Users = append(status.Users, rangeTraffic{Name: name, TxBytes: usage[0], RxBytes: usage[1]})
	}
	for name, usage := range nodes {
		status.Nodes = append(status.Nodes, rangeTraffic{Name: name, TxBytes: usage[0], RxBytes: usage[1]})
	}
	for hour, usage := range hours {
		status.Hours = append(status.Hours, hourlyTraffic{Hour: hour, TxBytes: usage[0], RxBytes: usage[1]})
	}
	sort.Slice(status.Users, func(i, j int) bool {
		return status.Users[i].TxBytes+status.Users[i].RxBytes > status.Users[j].TxBytes+status.Users[j].RxBytes
	})
	sort.Slice(status.Nodes, func(i, j int) bool {
		return status.Nodes[i].TxBytes+status.Nodes[i].RxBytes > status.Nodes[j].TxBytes+status.Nodes[j].RxBytes
	})
	sort.Slice(status.Hours, func(i, j int) bool { return status.Hours[i].Hour.Before(status.Hours[j].Hour) })
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(status); err != nil {
		m.logger.Debug("write traffic range status", zap.Error(err))
	}
}

func (m *Manager) withCSRF(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			next(w, r)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil || r.Form.Get("csrf") != m.csrf {
			http.Error(w, "invalid csrf token", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func (m *Manager) dashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" || r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	users, err := m.store.ListUsers()
	if err != nil {
		m.writeError(w, err)
		return
	}
	nodes, err := m.store.ListNodes()
	if err != nil {
		m.writeError(w, err)
		return
	}
	state, err := m.store.GetConfigState()
	if err != nil {
		m.writeError(w, err)
		return
	}
	start, end, label := monthRange(time.Now(), m.loc)
	monthly, err := m.store.GetUserMonthlyUsage(start, end)
	if err != nil {
		m.writeError(w, err)
		return
	}
	nodeMonthly, err := m.store.GetNodeMonthlyUsage(start, end)
	if err != nil {
		m.writeError(w, err)
		return
	}
	for _, node := range nodes {
		if _, ok := nodeMonthly[node.Name]; !ok {
			nodeMonthly[node.Name] = [2]uint64{}
		}
	}
	for _, user := range users {
		if containsRoute(user.Routes, "direct") {
			if _, ok := nodeMonthly["direct"]; !ok {
				nodeMonthly["direct"] = [2]uint64{}
			}
			break
		}
	}
	now := time.Now()
	activeUsers := 0
	enabledNodes := 0
	var monthlyTotal uint64
	var nodeEgressTotal uint64
	for _, user := range users {
		if user.DeletedAt == nil && (user.ExpiresAt == nil || user.ExpiresAt.After(now)) {
			activeUsers++
		}
		usage := monthly[user.Username]
		monthlyTotal += usage[0] + usage[1]
	}
	for _, node := range nodes {
		if node.Enabled {
			enabledNodes++
		}
	}
	for node, usage := range nodeMonthly {
		if node != "direct" {
			nodeEgressTotal += usage[0] + usage[1]
		}
	}
	var onlineCount int32
	for _, snapshot := range m.traffic.GetAllSnapshots() {
		onlineCount += snapshot.OnlineCount
	}
	restartJobs, err := m.store.ListRestartJobs(10)
	if err != nil {
		m.writeError(w, err)
		return
	}
	processRuns, err := m.store.ListProcessRuns(10)
	if err != nil {
		m.writeError(w, err)
		return
	}
	systemdInfo := "未配置"
	systemdConfigured := m.cfg.Systemd != nil
	if m.cfg.Systemd != nil {
		if status, err := systemd.Status(m.cfg.Systemd.Unit); err != nil {
			systemdInfo = "不可用：" + err.Error()
		} else {
			systemdInfo = fmt.Sprintf("%s / %s, PID %d, restarts %d, result %s", status.ActiveState, status.SubState, status.MainPID, status.NRestarts, status.Result)
		}
	}
	adminListen := m.cfg.Admin.Listen
	if adminListen == "" {
		adminListen = m.cfg.API.Listen
	}
	subscriptionListen := "未启用"
	if m.cfg.Sub != nil && m.cfg.Sub.Listen != "" {
		subscriptionListen = m.cfg.Sub.Listen
	}
	data := dashboardData{
		CSRF:               m.csrf,
		Users:              users,
		Nodes:              nodes,
		State:              state,
		Monthly:            monthly,
		NodeMonthly:        nodeMonthly,
		MonthLabel:         label,
		Flash:              r.URL.Query().Get("flash"),
		Now:                now,
		RestartJobs:        restartJobs,
		ProcessRuns:        processRuns,
		SystemdInfo:        systemdInfo,
		SystemdConfigured:  systemdConfigured,
		TotalUsers:         len(users),
		ActiveUsers:        activeUsers,
		EnabledNodes:       enabledNodes,
		MonthlyTotal:       monthlyTotal,
		NodeEgressTotal:    nodeEgressTotal,
		OnlineCount:        onlineCount,
		GatewayListen:      m.cfg.Listen,
		AdminListen:        adminListen,
		SubscriptionListen: subscriptionListen,
		DBPath:             m.cfg.DBPath,
		FlushInterval:      m.cfg.TrafficFlushInterval,
		Timezone:           m.cfg.Timezone,
	}
	var rendered bytes.Buffer
	if err := m.tmpl.Execute(&rendered, data); err != nil {
		m.logger.Error("render management dashboard", zap.Error(err))
		http.Error(w, "failed to render management dashboard", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(rendered.Bytes())
}

func containsRoute(routes []string, target string) bool {
	for _, route := range routes {
		if route == target {
			return true
		}
	}
	return false
}

func (m *Manager) restartAction(w http.ResponseWriter, r *http.Request) {
	if m.cfg.Systemd == nil {
		m.redirectError(w, r, fmt.Errorf("systemd integration is not configured"))
		return
	}
	runAt := time.Now().Add(2 * time.Second)
	if value := r.Form.Get("run_at"); value != "" {
		parsed, err := time.ParseInLocation("2006-01-02T15:04", value, m.loc)
		if err != nil {
			m.redirectError(w, r, fmt.Errorf("restart time: %w", err))
			return
		}
		runAt = parsed
	}
	if _, err := m.store.ScheduleRestart(runAt, "scheduled"); err != nil {
		m.redirectError(w, r, err)
		return
	}
	m.redirect(w, r, "restart scheduled", "faults")
}

func monthRange(now time.Time, loc *time.Location) (time.Time, time.Time, string) {
	local := now.In(loc)
	start := time.Date(local.Year(), local.Month(), 1, 0, 0, 0, 0, loc)
	return start.UTC(), start.AddDate(0, 1, 0).UTC(), start.Format("2006-01")
}

func (m *Manager) createUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	password, err := subtoken.Random()
	if err != nil {
		m.writeError(w, err)
		return
	}
	token, err := subtoken.Random()
	if err != nil {
		m.writeError(w, err)
		return
	}
	input, err := m.userInputFromForm(r, password)
	if err != nil {
		m.redirectError(w, r, err)
		return
	}
	if err := m.store.CreateUser(input, token); err != nil {
		m.redirectError(w, r, err)
		return
	}
	m.writeCredential(w, "用户已创建（重启 Gateway 后可用）", "密码："+password, m.subscriptionBase()+token)
}

func (m *Manager) userAction(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/users/"), "/"), "/")
	if len(parts) != 2 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	username, action := parts[0], parts[1]
	var err error
	flash := "用户配置已更新"
	switch action {
	case "delete":
		err = m.store.SetUserDeleted(username, true)
		flash = "用户已停用"
	case "restore":
		err = m.store.SetUserDeleted(username, false)
		flash = "用户已启用"
	case "password":
		password, randomErr := subtoken.Random()
		if randomErr != nil {
			err = randomErr
		} else {
			err = m.store.ResetUserPassword(username, password)
			if err == nil {
				m.writeCredential(w, "密码已重置", "新密码："+password, "")
				return
			}
		}
	case "token":
		token, randomErr := subtoken.Random()
		if randomErr != nil {
			err = randomErr
		} else {
			err = m.store.ResetUserToken(username, token)
			if err == nil {
				m.writeCredential(w, "订阅链接已重置", "", m.subscriptionBase()+token)
				return
			}
		}
	case "save":
		user, getErr := m.store.GetUser(username)
		if getErr != nil {
			err = getErr
			break
		}
		if user == nil {
			err = fmt.Errorf("user %q not found", username)
			break
		}
		input, parseErr := m.userInputFromForm(r, user.Password)
		if parseErr != nil {
			err = parseErr
			break
		}
		input.Username = username
		err = m.store.UpdateUser(input)
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		m.redirectError(w, r, err)
		return
	}
	m.redirect(w, r, flash, "users")
}

func (m *Manager) userInputFromForm(r *http.Request, password string) (storage.ManagedUserInput, error) {
	monthly, err := parseUint(r.Form.Get("monthly_bytes"))
	if err != nil {
		return storage.ManagedUserInput{}, fmt.Errorf("monthly bytes: %w", err)
	}
	speed, err := parseUint(r.Form.Get("download_speed"))
	if err != nil {
		return storage.ManagedUserInput{}, fmt.Errorf("download speed: %w", err)
	}
	var expiresAt *time.Time
	if value := r.Form.Get("expires_at"); value != "" {
		parsed, err := time.ParseInLocation("2006-01-02T15:04", value, m.loc)
		if err != nil {
			return storage.ManagedUserInput{}, fmt.Errorf("expiry: %w", err)
		}
		utc := parsed.UTC()
		expiresAt = &utc
	}
	return storage.ManagedUserInput{
		Username:      r.Form.Get("username"),
		Password:      password,
		ExpiresAt:     expiresAt,
		MonthlyBytes:  monthly,
		DownloadSpeed: speed,
		Routes:        r.Form["routes"],
	}, nil
}

func parseUint(value string) (uint64, error) {
	if value == "" {
		return 0, nil
	}
	return strconv.ParseUint(value, 10, 64)
}

func (m *Manager) saveNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name, node, enabled, err := nodeFromForm(r)
	if err == nil {
		err = m.store.SaveNode(name, node, enabled)
	}
	if err != nil {
		m.redirectError(w, r, err)
		return
	}
	m.redirect(w, r, "node saved; restart required before it is active", "overview")
}

func (m *Manager) nodeAction(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/nodes/"), "/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] != "disable" {
		http.NotFound(w, r)
		return
	}
	if err := m.store.SetNodeEnabled(parts[0], false); err != nil {
		m.redirectError(w, r, err)
		return
	}
	m.redirect(w, r, "node disabled; restart required before it is inactive", "overview")
}

func nodeFromForm(r *http.Request) (string, config.NodeConfig, bool, error) {
	name := r.Form.Get("name")
	node := config.NodeConfig{Type: r.Form.Get("type"), Alias: r.Form.Get("alias")}
	switch node.Type {
	case "direct":
		node.Direct = &config.DirectConfig{}
	case "hysteria2":
		node.Hysteria2 = &config.Hysteria2OutboundConfig{Addr: r.Form.Get("addr"), Auth: r.Form.Get("auth"), SNI: r.Form.Get("sni"), Insecure: r.Form.Get("insecure") == "on"}
	case "socks5":
		node.SOCKS5 = &config.SOCKS5Config{Addr: r.Form.Get("addr"), Username: r.Form.Get("proxy_username"), Password: r.Form.Get("proxy_password")}
	case "http":
		node.HTTP = &config.HTTPConfig{URL: r.Form.Get("url"), Insecure: r.Form.Get("insecure") == "on"}
	default:
		return "", node, false, fmt.Errorf("unsupported node type")
	}
	return name, node, r.Form.Get("enabled") == "on", nil
}

func (m *Manager) subscriptionBase() string {
	if m.cfg.Sub != nil && m.cfg.Sub.PublicURL != "" {
		return strings.TrimRight(m.cfg.Sub.PublicURL, "/") + "/"
	}
	return ""
}

func (m *Manager) redirect(w http.ResponseWriter, r *http.Request, flash, section string) {
	values := url.Values{"flash": []string{flash}}
	target := "/?" + values.Encode()
	if section != "" {
		target += "#" + section
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func (m *Manager) redirectError(w http.ResponseWriter, r *http.Request, err error) {
	m.logger.Warn("management request failed", zap.Error(err))
	section := "overview"
	if strings.HasPrefix(r.URL.Path, "/users") {
		section = "users"
	} else if strings.HasPrefix(r.URL.Path, "/restart") {
		section = "faults"
	}
	m.redirect(w, r, "error: "+err.Error(), section)
}

func (m *Manager) writeError(w http.ResponseWriter, err error) {
	m.logger.Error("management request failed", zap.Error(err))
	http.Error(w, "internal server error", http.StatusInternalServerError)
}

func (m *Manager) writeCredential(w http.ResponseWriter, title, password, subscriptionURL string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>%s</title><link rel="stylesheet" href="/assets/admin.css?v=4"></head><body class="credential-page"><main class="credential-panel"><div class="brand-mark">H2</div><p class="eyebrow">一次性凭据</p><h1>%s</h1><p class="muted-text">请立即记录以下内容，离开页面后不会再次显示。</p><div class="credential-value">%s%s</div><a class="button-link" href="/#users">返回管理后台</a></main></body></html>`, template.HTMLEscapeString(title), template.HTMLEscapeString(title), template.HTMLEscapeString(password), credentialLine(subscriptionURL))
}

func credentialLine(value string) string {
	if value == "" {
		return ""
	}
	return "<br>" + template.HTMLEscapeString(value)
}

func formatBytes(value uint64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	current := float64(value)
	idx := 0
	for current >= 1024 && idx < len(units)-1 {
		current /= 1024
		idx++
	}
	if idx == 0 {
		return fmt.Sprintf("%d %s", value, units[idx])
	}
	return fmt.Sprintf("%.2f %s", current, units[idx])
}
