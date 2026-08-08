package storage

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/hy2-gateway/internal/config"
)

// ManagedUser is the database-backed user record used by the management UI.
// Timestamps are kept as UTC Unix seconds in SQLite and exposed as time.Time.
type ManagedUser struct {
	Username      string
	Password      string
	DeletedAt     *time.Time
	ExpiresAt     *time.Time
	MonthlyBytes  uint64
	DownloadSpeed uint64
	TokenHash     []byte
	CreatedAt     time.Time
	UpdatedAt     time.Time
	Routes        []string
}

// ManagedNode is a restart-applied outbound definition.
type ManagedNode struct {
	Name      string
	Config    config.NodeConfig
	Enabled   bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ConfigState tracks the persisted and active configuration revisions.
type ConfigState struct {
	Revision       int64
	ActiveRevision int64
}

// UserMonthlyUsage is the user-level tx/rx total within a natural month.
type UserMonthlyUsage struct {
	Username string
	TxBytes  uint64
	RxBytes  uint64
}

// ManagedUserInput is the editable subset of a user record.
type ManagedUserInput struct {
	Username      string
	Password      string
	ExpiresAt     *time.Time
	MonthlyBytes  uint64
	DownloadSpeed uint64
	Routes        []string
}

// RestartJob is a durable one-time systemd restart request.
type RestartJob struct {
	ID         int64
	RunAt      time.Time
	Trigger    string
	Status     string
	Detail     string
	CreatedAt  time.Time
	ExecutedAt *time.Time
}

// ProcessRun records one Gateway process lifetime. systemd's ExecStopPost
// fills the exit fields after an unexpected termination or watchdog event.
type ProcessRun struct {
	ID             int64
	PID            int
	StartedAt      time.Time
	StoppedAt      *time.Time
	ConfigRevision int64
	Trigger        string
	SystemdResult  string
	ExitCode       string
	ExitStatus     string
	Detail         string
}

func unixTime(v int64) *time.Time {
	if v == 0 {
		return nil
	}
	t := time.Unix(v, 0).UTC()
	return &t
}

func timeUnix(v *time.Time) any {
	if v == nil || v.IsZero() {
		return nil
	}
	return v.UTC().Unix()
}

func tokenHash(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

func isValidName(value string) bool {
	return value != "" && !strings.ContainsAny(value, ":/\\\x00")
}

func (s *SQLiteStore) migrateManagement() error {
	schema := `
	CREATE TABLE IF NOT EXISTS managed_users (
		username       TEXT PRIMARY KEY,
		password       TEXT NOT NULL,
		deleted_at     INTEGER,
		expires_at     INTEGER,
		monthly_bytes  INTEGER NOT NULL DEFAULT 0,
		download_speed INTEGER NOT NULL DEFAULT 0,
		token_hash     BLOB NOT NULL UNIQUE,
		created_at     INTEGER NOT NULL,
		updated_at     INTEGER NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_managed_users_token ON managed_users(token_hash);

	CREATE TABLE IF NOT EXISTS managed_nodes (
		name       TEXT PRIMARY KEY,
		config_json TEXT NOT NULL,
		enabled    INTEGER NOT NULL DEFAULT 1,
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS user_nodes (
		username TEXT NOT NULL REFERENCES managed_users(username),
		node_name TEXT NOT NULL,
		PRIMARY KEY (username, node_name)
	);
	CREATE INDEX IF NOT EXISTS idx_user_nodes_node ON user_nodes(node_name);

	CREATE TABLE IF NOT EXISTS config_state (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		revision INTEGER NOT NULL DEFAULT 0,
		active_revision INTEGER NOT NULL DEFAULT 0
	);
	INSERT OR IGNORE INTO config_state (id, revision, active_revision) VALUES (1, 0, 0);

	CREATE TABLE IF NOT EXISTS management_migrations (
		name TEXT PRIMARY KEY,
		applied_at INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS restart_jobs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		run_at INTEGER NOT NULL,
		trigger TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'pending',
		created_at INTEGER NOT NULL,
		executed_at INTEGER,
		error_detail TEXT,
		started_process_run_id INTEGER
	);
	CREATE INDEX IF NOT EXISTS idx_restart_jobs_pending ON restart_jobs(status, run_at);

	CREATE TABLE IF NOT EXISTS process_runs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		pid INTEGER,
		started_at INTEGER NOT NULL,
		stopped_at INTEGER,
		config_revision INTEGER NOT NULL DEFAULT 0,
		trigger TEXT NOT NULL DEFAULT 'auto',
		systemd_result TEXT,
		exit_code TEXT,
		exit_status TEXT,
		detail TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_process_runs_started ON process_runs(started_at DESC);
	`
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}
	if err := s.ensureColumn("restart_jobs", "error_detail", "TEXT"); err != nil {
		return err
	}
	return s.ensureColumn("restart_jobs", "started_process_run_id", "INTEGER")
}

func (s *SQLiteStore) ensureColumn(table, column, definition string) error {
	rows, err := s.db.Query(fmt.Sprintf(`PRAGMA table_info(%s)`, table))
	if err != nil {
		return err
	}
	found := false
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, dataType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			return err
		}
		if name == column {
			found = true
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if found {
		return nil
	}
	_, err = s.db.Exec(fmt.Sprintf(`ALTER TABLE %s ADD COLUMN %s %s`, table, column, definition))
	return err
}

// MigrateLegacy imports legacy users and nodes exactly once. The caller must
// have loaded the old YAML configuration.
func (s *SQLiteStore) MigrateLegacy(cfg *config.Config, legacyToken func(string) string) error {
	if err := cfg.ValidateLegacy(); err != nil {
		return err
	}
	if legacyToken == nil {
		return fmt.Errorf("legacy token generator is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM managed_users`).Scan(&count); err != nil {
		return fmt.Errorf("check managed users: %w", err)
	}
	if count > 0 {
		return fmt.Errorf("managed user data already exists; refusing to overwrite it")
	}
	if err := tx.QueryRow(`SELECT COUNT(*) FROM management_migrations WHERE name = 'legacy-yaml-v1'`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return fmt.Errorf("legacy YAML has already been migrated")
	}

	now := time.Now().UTC().Unix()
	nodeNames := make([]string, 0, len(cfg.Nodes))
	for name := range cfg.Nodes {
		nodeNames = append(nodeNames, name)
	}
	sort.Strings(nodeNames)
	for _, name := range nodeNames {
		node := cfg.Nodes[name]
		if name == "direct" && node.Type == "direct" {
			continue
		}
		if node.Type == "direct" {
			return fmt.Errorf("legacy node %q uses direct type; authorize the built-in direct route instead", name)
		}
		if !isValidName(name) {
			return fmt.Errorf("invalid legacy node name %q", name)
		}
		encoded, err := json.Marshal(node)
		if err != nil {
			return fmt.Errorf("encode node %q: %w", name, err)
		}
		if _, err := tx.Exec(`INSERT INTO managed_nodes (name, config_json, enabled, created_at, updated_at) VALUES (?, ?, 1, ?, ?)`, name, string(encoded), now, now); err != nil {
			return fmt.Errorf("insert node %q: %w", name, err)
		}
	}

	if err := insertLegacyUsers(tx, cfg.Users, legacyToken, now); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE config_state SET revision = 1 WHERE id = 1`); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO management_migrations (name, applied_at) VALUES ('legacy-yaml-v1', ?)`, now); err != nil {
		return err
	}
	return tx.Commit()
}

// ReplaceLegacyUsers atomically replaces only managed users and their route
// assignments. Nodes, traffic, process history and restart jobs are retained.
// The caller must opt in explicitly because this invalidates users absent from
// the supplied legacy YAML.
func (s *SQLiteStore) ReplaceLegacyUsers(cfg *config.Config, legacyToken func(string) string) error {
	if len(cfg.Users) == 0 {
		return fmt.Errorf("at least one legacy user must be configured")
	}
	for username, user := range cfg.Users {
		if user.Password == "" {
			return fmt.Errorf("user %q has no password", username)
		}
		if len(user.Routes) == 0 {
			return fmt.Errorf("user %q has no routes", username)
		}
	}
	if legacyToken == nil {
		return fmt.Errorf("legacy token generator is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Routes are applied against the managed node snapshot, not against YAML.
	// Validate before commit so a partial or mismatched import cannot strand all
	// users with unusable node assignments.
	for username, user := range cfg.Users {
		for _, route := range user.Routes {
			if route == "direct" {
				continue
			}
			var count int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM managed_nodes WHERE name = ?`, route).Scan(&count); err != nil {
				return err
			}
			if count == 0 {
				return fmt.Errorf("cannot replace users: user %q references node %q missing from managed nodes", username, route)
			}
		}
	}
	if _, err := tx.Exec(`DELETE FROM user_nodes`); err != nil {
		return fmt.Errorf("clear managed user routes: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM managed_users`); err != nil {
		return fmt.Errorf("clear managed users: %w", err)
	}
	now := time.Now().UTC().Unix()
	if err := insertLegacyUsers(tx, cfg.Users, legacyToken, now); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE config_state SET revision = revision + 1 WHERE id = 1`); err != nil {
		return err
	}
	return tx.Commit()
}

func insertLegacyUsers(tx *sql.Tx, users map[string]config.UserConfig, legacyToken func(string) string, now int64) error {
	usernames := make([]string, 0, len(users))
	for username := range users {
		usernames = append(usernames, username)
	}
	sort.Strings(usernames)
	for _, username := range usernames {
		if !isValidName(username) {
			return fmt.Errorf("invalid legacy username %q", username)
		}
		user := users[username]
		token := legacyToken(username)
		if token == "" {
			return fmt.Errorf("legacy subscription token for %q is empty", username)
		}
		if _, err := tx.Exec(`INSERT INTO managed_users (username, password, monthly_bytes, download_speed, token_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`, username, user.Password, user.MaxBytes, user.SpeedLimit, tokenHash(token), now, now); err != nil {
			return fmt.Errorf("insert user %q: %w", username, err)
		}
		for _, route := range user.Routes {
			if _, err := tx.Exec(`INSERT INTO user_nodes (username, node_name) VALUES (?, ?)`, username, route); err != nil {
				return fmt.Errorf("insert user route %q/%q: %w", username, route, err)
			}
		}
	}
	return nil
}

// LoadRuntimeUsers returns all users and their routes. Deleted and expired
// states remain in the result so the authenticator can deny new connections.
func (s *SQLiteStore) LoadRuntimeUsers() (map[string]config.UserConfig, error) {
	rows, err := s.db.Query(`SELECT username, password, deleted_at, expires_at, monthly_bytes, download_speed FROM managed_users`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := make(map[string]config.UserConfig)
	for rows.Next() {
		var username, password string
		var deletedAt, expiresAt sql.NullInt64
		var maxBytes, speed uint64
		if err := rows.Scan(&username, &password, &deletedAt, &expiresAt, &maxBytes, &speed); err != nil {
			return nil, err
		}
		u := config.UserConfig{Password: password, MaxBytes: maxBytes, SpeedLimit: speed}
		if deletedAt.Valid {
			u.Disabled = true
		}
		if expiresAt.Valid {
			u.ExpiresAt = unixTime(expiresAt.Int64)
		}
		users[username] = u
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	routeRows, err := s.db.Query(`SELECT username, node_name FROM user_nodes ORDER BY username, node_name`)
	if err != nil {
		return nil, err
	}
	defer routeRows.Close()
	for routeRows.Next() {
		var username, node string
		if err := routeRows.Scan(&username, &node); err != nil {
			return nil, err
		}
		if user, ok := users[username]; ok {
			user.Routes = append(user.Routes, node)
			users[username] = user
		}
	}
	return users, routeRows.Err()
}

// LoadNodes loads all enabled and disabled nodes. The caller decides which
// snapshot is active; node changes only apply after Gateway restart.
func (s *SQLiteStore) LoadNodes() (map[string]config.NodeConfig, error) {
	rows, err := s.db.Query(`SELECT name, config_json FROM managed_nodes WHERE enabled = 1 ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	nodes := make(map[string]config.NodeConfig)
	for rows.Next() {
		var name, raw string
		if err := rows.Scan(&name, &raw); err != nil {
			return nil, err
		}
		var node config.NodeConfig
		if err := json.Unmarshal([]byte(raw), &node); err != nil {
			return nil, fmt.Errorf("decode node %q: %w", name, err)
		}
		nodes[name] = node
	}
	return nodes, rows.Err()
}

// ListUsers returns records for the management UI.
func (s *SQLiteStore) ListUsers() ([]ManagedUser, error) {
	rows, err := s.db.Query(`SELECT username, password, deleted_at, expires_at, monthly_bytes, download_speed, token_hash, created_at, updated_at FROM managed_users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]ManagedUser, 0)
	for rows.Next() {
		var u ManagedUser
		var deletedAt, expiresAt sql.NullInt64
		var createdAt, updatedAt int64
		if err := rows.Scan(&u.Username, &u.Password, &deletedAt, &expiresAt, &u.MonthlyBytes, &u.DownloadSpeed, &u.TokenHash, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		u.DeletedAt = unixTime(deletedAt.Int64)
		u.ExpiresAt = unixTime(expiresAt.Int64)
		u.CreatedAt = time.Unix(createdAt, 0).UTC()
		u.UpdatedAt = time.Unix(updatedAt, 0).UTC()
		result = append(result, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := s.populateUserRoutes(result); err != nil {
		return nil, err
	}
	return result, nil
}

// GetUser returns a single management record.
func (s *SQLiteStore) GetUser(username string) (*ManagedUser, error) {
	users, err := s.ListUsers()
	if err != nil {
		return nil, err
	}
	for i := range users {
		if users[i].Username == username {
			return &users[i], nil
		}
	}
	return nil, nil
}

func (s *SQLiteStore) populateUserRoutes(users []ManagedUser) error {
	byName := make(map[string]int, len(users))
	for i := range users {
		byName[users[i].Username] = i
	}
	rows, err := s.db.Query(`SELECT username, node_name FROM user_nodes ORDER BY username, node_name`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var username, node string
		if err := rows.Scan(&username, &node); err != nil {
			return err
		}
		if idx, ok := byName[username]; ok {
			users[idx].Routes = append(users[idx].Routes, node)
		}
	}
	return rows.Err()
}

// FindUserByToken returns an active user matched by its bearer token.
func (s *SQLiteStore) FindUserByToken(token string) (*ManagedUser, error) {
	var u ManagedUser
	var deletedAt, expiresAt sql.NullInt64
	var createdAt, updatedAt int64
	err := s.db.QueryRow(`SELECT username, password, deleted_at, expires_at, monthly_bytes, download_speed, token_hash, created_at, updated_at FROM managed_users WHERE token_hash = ?`, tokenHash(token)).Scan(&u.Username, &u.Password, &deletedAt, &expiresAt, &u.MonthlyBytes, &u.DownloadSpeed, &u.TokenHash, &createdAt, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u.DeletedAt = unixTime(deletedAt.Int64)
	u.ExpiresAt = unixTime(expiresAt.Int64)
	u.CreatedAt = time.Unix(createdAt, 0).UTC()
	u.UpdatedAt = time.Unix(updatedAt, 0).UTC()
	if u.DeletedAt != nil || (u.ExpiresAt != nil && !u.ExpiresAt.After(time.Now())) {
		return nil, nil
	}
	routes, err := s.userRoutes(u.Username)
	if err != nil {
		return nil, err
	}
	u.Routes = routes
	return &u, nil
}

func (s *SQLiteStore) userRoutes(username string) ([]string, error) {
	rows, err := s.db.Query(`SELECT node_name FROM user_nodes WHERE username = ? ORDER BY node_name`, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var routes []string
	for rows.Next() {
		var route string
		if err := rows.Scan(&route); err != nil {
			return nil, err
		}
		routes = append(routes, route)
	}
	return routes, rows.Err()
}

// GetConfigState returns the persisted and active config revisions.
func (s *SQLiteStore) GetConfigState() (ConfigState, error) {
	var state ConfigState
	err := s.db.QueryRow(`SELECT revision, active_revision FROM config_state WHERE id = 1`).Scan(&state.Revision, &state.ActiveRevision)
	return state, err
}

// SetActiveRevision records that a Gateway process successfully loaded a
// database configuration snapshot.
func (s *SQLiteStore) SetActiveRevision(revision int64) error {
	_, err := s.db.Exec(`UPDATE config_state SET active_revision = ? WHERE id = 1`, revision)
	return err
}

// GetUserMonthlyUsage returns persisted traffic totals for the supplied UTC
// boundaries. In-memory deltas are added by TrafficLogger before enforcement.
func (s *SQLiteStore) GetUserMonthlyUsage(start, end time.Time) (map[string][2]uint64, error) {
	rows, err := s.db.Query(`SELECT user_id, COALESCE(SUM(tx_bytes), 0), COALESCE(SUM(rx_bytes), 0) FROM traffic_logs WHERE created_at >= ? AND created_at < ? GROUP BY user_id`, start.UTC().Unix(), end.UTC().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string][2]uint64)
	for rows.Next() {
		var username string
		var tx, rx uint64
		if err := rows.Scan(&username, &tx, &rx); err != nil {
			return nil, err
		}
		result[username] = [2]uint64{tx, rx}
	}
	return result, rows.Err()
}

// GetNodeMonthlyUsage returns effective-payload tx/rx by selected route for a
// natural-month window. The UI uses tx+rx to show separate Gateway and Node
// egress estimates.
func (s *SQLiteStore) GetNodeMonthlyUsage(start, end time.Time) (map[string][2]uint64, error) {
	rows, err := s.db.Query(`SELECT node_id, COALESCE(SUM(tx_bytes), 0), COALESCE(SUM(rx_bytes), 0) FROM traffic_logs WHERE created_at >= ? AND created_at < ? GROUP BY node_id`, start.UTC().Unix(), end.UTC().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string][2]uint64)
	for rows.Next() {
		var node string
		var tx, rx uint64
		if err := rows.Scan(&node, &tx, &rx); err != nil {
			return nil, err
		}
		result[node] = [2]uint64{tx, rx}
	}
	return result, rows.Err()
}

// CreateUser inserts a user and its routes. The raw token is never persisted.
func (s *SQLiteStore) CreateUser(input ManagedUserInput, rawToken string) error {
	if !isValidName(input.Username) {
		return fmt.Errorf("invalid username")
	}
	if input.Password == "" {
		return fmt.Errorf("password is required")
	}
	if rawToken == "" {
		return fmt.Errorf("subscription token is required")
	}
	if len(input.Routes) == 0 {
		return fmt.Errorf("at least one node route is required")
	}
	if err := s.validateRoutes(input.Routes); err != nil {
		return err
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO managed_users (username, password, expires_at, monthly_bytes, download_speed, token_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, input.Username, input.Password, timeUnix(input.ExpiresAt), input.MonthlyBytes, input.DownloadSpeed, tokenHash(rawToken), now.Unix(), now.Unix()); err != nil {
		return err
	}
	for _, route := range uniqueRoutes(input.Routes) {
		if _, err := tx.Exec(`INSERT INTO user_nodes (username, node_name) VALUES (?, ?)`, input.Username, route); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`UPDATE config_state SET revision = revision + 1 WHERE id = 1`); err != nil {
		return err
	}
	return tx.Commit()
}

// UpdateUser updates a user's credentials, lifecycle and routes. Only a route
// change increases the restart-applied configuration revision; lifecycle and
// limit changes are picked up by the running Gateway's user refresh.
func (s *SQLiteStore) UpdateUser(input ManagedUserInput) error {
	if !isValidName(input.Username) {
		return fmt.Errorf("invalid username")
	}
	if input.Password == "" {
		return fmt.Errorf("password is required")
	}
	if len(input.Routes) == 0 {
		return fmt.Errorf("at least one node route is required")
	}
	if err := s.validateRoutes(input.Routes); err != nil {
		return err
	}
	now := time.Now().UTC().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT node_name FROM user_nodes WHERE username = ? ORDER BY node_name`, input.Username)
	if err != nil {
		return err
	}
	var existingRoutes []string
	for rows.Next() {
		var route string
		if err := rows.Scan(&route); err != nil {
			rows.Close()
			return err
		}
		existingRoutes = append(existingRoutes, route)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return err
	}
	requestedRoutes := uniqueRoutes(input.Routes)
	sort.Strings(requestedRoutes)
	routesChanged := !equalStrings(existingRoutes, requestedRoutes)

	result, err := tx.Exec(`UPDATE managed_users SET password = ?, expires_at = ?, monthly_bytes = ?, download_speed = ?, updated_at = ? WHERE username = ?`, input.Password, timeUnix(input.ExpiresAt), input.MonthlyBytes, input.DownloadSpeed, now, input.Username)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return fmt.Errorf("user %q not found", input.Username)
	}
	if routesChanged {
		if _, err := tx.Exec(`DELETE FROM user_nodes WHERE username = ?`, input.Username); err != nil {
			return err
		}
		for _, route := range requestedRoutes {
			if _, err := tx.Exec(`INSERT INTO user_nodes (username, node_name) VALUES (?, ?)`, input.Username, route); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(`UPDATE config_state SET revision = revision + 1 WHERE id = 1`); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// SetUserDeleted applies a reversible soft delete. Deletion immediately
// affects authentication when the Gateway refreshes its user snapshot.
func (s *SQLiteStore) SetUserDeleted(username string, deleted bool) error {
	now := time.Now().UTC().Unix()
	var deletedAt any
	if deleted {
		deletedAt = now
	}
	result, err := s.db.Exec(`UPDATE managed_users SET deleted_at = ?, updated_at = ? WHERE username = ?`, deletedAt, now, username)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return fmt.Errorf("user %q not found", username)
	}
	return nil
}

// ResetUserPassword changes the password without changing the subscription
// URL. The new password is emitted on the next subscription fetch.
func (s *SQLiteStore) ResetUserPassword(username, password string) error {
	if password == "" {
		return fmt.Errorf("password is required")
	}
	result, err := s.db.Exec(`UPDATE managed_users SET password = ?, updated_at = ? WHERE username = ?`, password, time.Now().UTC().Unix(), username)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return fmt.Errorf("user %q not found", username)
	}
	return nil
}

// ResetUserToken invalidates the prior subscription URL.
func (s *SQLiteStore) ResetUserToken(username, rawToken string) error {
	if rawToken == "" {
		return fmt.Errorf("subscription token is required")
	}
	result, err := s.db.Exec(`UPDATE managed_users SET token_hash = ?, updated_at = ? WHERE username = ?`, tokenHash(rawToken), time.Now().UTC().Unix(), username)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return fmt.Errorf("user %q not found", username)
	}
	return nil
}

func uniqueRoutes(routes []string) []string {
	seen := make(map[string]struct{}, len(routes))
	result := make([]string, 0, len(routes))
	for _, route := range routes {
		if _, ok := seen[route]; ok {
			continue
		}
		seen[route] = struct{}{}
		result = append(result, route)
	}
	return result
}

func (s *SQLiteStore) validateRoutes(routes []string) error {
	for _, route := range uniqueRoutes(routes) {
		if route == "direct" {
			continue
		}
		var enabled int
		err := s.db.QueryRow(`SELECT enabled FROM managed_nodes WHERE name = ?`, route).Scan(&enabled)
		if err == sql.ErrNoRows {
			return fmt.Errorf("unknown node %q", route)
		}
		if err != nil {
			return err
		}
		if enabled == 0 {
			return fmt.Errorf("node %q is disabled", route)
		}
	}
	return nil
}

// ListNodes returns all node records, including disabled nodes.
func (s *SQLiteStore) ListNodes() ([]ManagedNode, error) {
	rows, err := s.db.Query(`SELECT name, config_json, enabled, created_at, updated_at FROM managed_nodes ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []ManagedNode
	for rows.Next() {
		var node ManagedNode
		var raw string
		var enabled int
		var createdAt, updatedAt int64
		if err := rows.Scan(&node.Name, &raw, &enabled, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(raw), &node.Config); err != nil {
			return nil, fmt.Errorf("decode node %q: %w", node.Name, err)
		}
		node.Enabled = enabled != 0
		node.CreatedAt = time.Unix(createdAt, 0).UTC()
		node.UpdatedAt = time.Unix(updatedAt, 0).UTC()
		result = append(result, node)
	}
	return result, rows.Err()
}

// SaveNode creates or updates a node. All node changes require Gateway restart.
func (s *SQLiteStore) SaveNode(name string, node config.NodeConfig, enabled bool) error {
	if !isValidName(name) || name == "direct" {
		return fmt.Errorf("invalid node name")
	}
	if node.Type == "direct" {
		return fmt.Errorf("direct is a built-in route and cannot be saved as a managed node")
	}
	if err := validateNode(name, node); err != nil {
		return err
	}
	raw, err := json.Marshal(node)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO managed_nodes (name, config_json, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(name) DO UPDATE SET config_json = excluded.config_json, enabled = excluded.enabled, updated_at = excluded.updated_at`, name, string(raw), boolToInt(enabled), now, now); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE config_state SET revision = revision + 1 WHERE id = 1`); err != nil {
		return err
	}
	return tx.Commit()
}

// SetNodeEnabled changes a node's availability for future configuration
// snapshots. Existing running Gateways keep their startup snapshot until
// restart.
func (s *SQLiteStore) SetNodeEnabled(name string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE managed_nodes SET enabled = ?, updated_at = ? WHERE name = ?`, boolToInt(enabled), time.Now().UTC().Unix(), name)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return fmt.Errorf("node %q not found", name)
	}
	if _, err := tx.Exec(`UPDATE config_state SET revision = revision + 1 WHERE id = 1`); err != nil {
		return err
	}
	return tx.Commit()
}

// ScheduleRestart saves a one-time restart request. The scheduler claims it
// atomically before invoking systemd.
func (s *SQLiteStore) ScheduleRestart(runAt time.Time, trigger string) (int64, error) {
	if trigger == "" {
		trigger = "scheduled"
	}
	now := time.Now().UTC().Unix()
	result, err := s.db.Exec(`INSERT INTO restart_jobs (run_at, trigger, status, created_at) VALUES (?, ?, 'pending', ?)`, runAt.UTC().Unix(), trigger, now)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// ClaimDueRestart returns one pending job and marks it running. A process
// restart cannot execute the same job twice after a crash.
func (s *SQLiteStore) ClaimDueRestart(now time.Time) (*RestartJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	row := tx.QueryRow(`SELECT id, run_at, trigger, created_at FROM restart_jobs WHERE status = 'pending' AND run_at <= ? ORDER BY run_at, id LIMIT 1`, now.UTC().Unix())
	var job RestartJob
	var runAt, createdAt int64
	if err := row.Scan(&job.ID, &runAt, &job.Trigger, &createdAt); err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	result, err := tx.Exec(`UPDATE restart_jobs SET status = 'running', executed_at = ? WHERE id = ? AND status = 'pending'`, now.UTC().Unix(), job.ID)
	if err != nil {
		return nil, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return nil, nil
	}
	job.RunAt = time.Unix(runAt, 0).UTC()
	job.CreatedAt = time.Unix(createdAt, 0).UTC()
	job.Status = "running"
	executed := now.UTC()
	job.ExecutedAt = &executed
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &job, nil
}

func (s *SQLiteStore) CompleteRestartJob(id int64, success bool, detail string) error {
	status := "failed"
	if success {
		status = "completed"
		detail = ""
	}
	_, err := s.db.Exec(`UPDATE restart_jobs SET status = ?, error_detail = NULLIF(?, ''), executed_at = COALESCE(executed_at, ?) WHERE id = ?`, status, detail, time.Now().UTC().Unix(), id)
	return err
}

func (s *SQLiteStore) ListRestartJobs(limit int) ([]RestartJob, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := s.db.Query(`SELECT id, run_at, trigger, status, COALESCE(error_detail, ''), created_at, executed_at FROM restart_jobs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []RestartJob
	for rows.Next() {
		var job RestartJob
		var runAt, createdAt int64
		var executedAt sql.NullInt64
		if err := rows.Scan(&job.ID, &runAt, &job.Trigger, &job.Status, &job.Detail, &createdAt, &executedAt); err != nil {
			return nil, err
		}
		job.RunAt = time.Unix(runAt, 0).UTC()
		job.CreatedAt = time.Unix(createdAt, 0).UTC()
		job.ExecutedAt = unixTime(executedAt.Int64)
		result = append(result, job)
	}
	return result, rows.Err()
}

// StartProcessRun records a newly started Gateway process.
func (s *SQLiteStore) StartProcessRun(pid int, revision int64, trigger string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Unix()
	var restartJobID int64
	if trigger == "" {
		var jobTrigger string
		var jobStatus string
		err := tx.QueryRow(`SELECT id, trigger, status FROM restart_jobs WHERE status IN ('completed', 'running') AND started_process_run_id IS NULL AND executed_at >= ? ORDER BY executed_at DESC, id DESC LIMIT 1`, now-600).Scan(&restartJobID, &jobTrigger, &jobStatus)
		switch {
		case err == nil:
			trigger = "admin:" + jobTrigger
			if jobStatus == "running" {
				if _, err := tx.Exec(`UPDATE restart_jobs SET status = 'completed', error_detail = COALESCE(error_detail, 'new process observed before the scheduler recorded D-Bus completion') WHERE id = ?`, restartJobID); err != nil {
					return 0, err
				}
			}
		case err != sql.ErrNoRows:
			return 0, err
		default:
			var previousResult string
			err = tx.QueryRow(`SELECT COALESCE(systemd_result, '') FROM process_runs WHERE stopped_at IS NOT NULL ORDER BY id DESC LIMIT 1`).Scan(&previousResult)
			switch {
			case err == sql.ErrNoRows:
				trigger = "initial"
			case err != nil:
				return 0, err
			case previousResult != "" && previousResult != "success":
				trigger = "recovery:" + previousResult
			default:
				trigger = "external-start"
			}
		}
	}
	result, err := tx.Exec(`INSERT INTO process_runs (pid, started_at, config_revision, trigger) VALUES (?, ?, ?, ?)`, pid, now, revision, trigger)
	if err != nil {
		return 0, err
	}
	runID, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	if restartJobID != 0 {
		if _, err := tx.Exec(`UPDATE restart_jobs SET started_process_run_id = ? WHERE id = ? AND started_process_run_id IS NULL`, runID, restartJobID); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return runID, nil
}

// RecordProcessExit is called by the record-exit subcommand from ExecStopPost.
func (s *SQLiteStore) RecordProcessExit(pid int, result, exitCode, exitStatus string) error {
	query := `UPDATE process_runs SET stopped_at = ?, systemd_result = ?, exit_code = ?, exit_status = ? WHERE id = (SELECT id FROM process_runs WHERE stopped_at IS NULL`
	args := []any{time.Now().UTC().Unix(), result, exitCode, exitStatus}
	if pid > 0 {
		query += ` AND pid = ?`
		args = append(args, pid)
	}
	query += ` ORDER BY id DESC LIMIT 1)`
	updateResult, err := s.db.Exec(query, args...)
	if err != nil || pid <= 0 {
		return err
	}
	affected, err := updateResult.RowsAffected()
	if err != nil || affected != 0 {
		return err
	}
	// MAINPID is not consistently exported to ExecStopPost by every systemd
	// version. This service is single-process, so fall back to its latest open run.
	_, err = s.db.Exec(`UPDATE process_runs SET stopped_at = ?, systemd_result = ?, exit_code = ?, exit_status = ? WHERE id = (SELECT id FROM process_runs WHERE stopped_at IS NULL ORDER BY id DESC LIMIT 1)`, time.Now().UTC().Unix(), result, exitCode, exitStatus)
	return err
}

func (s *SQLiteStore) ListProcessRuns(limit int) ([]ProcessRun, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := s.db.Query(`SELECT id, COALESCE(pid, 0), started_at, stopped_at, config_revision, COALESCE(trigger, ''), COALESCE(systemd_result, ''), COALESCE(exit_code, ''), COALESCE(exit_status, ''), COALESCE(detail, '') FROM process_runs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []ProcessRun
	for rows.Next() {
		var run ProcessRun
		var stoppedAt sql.NullInt64
		var startedAt int64
		if err := rows.Scan(&run.ID, &run.PID, &startedAt, &stoppedAt, &run.ConfigRevision, &run.Trigger, &run.SystemdResult, &run.ExitCode, &run.ExitStatus, &run.Detail); err != nil {
			return nil, err
		}
		run.StartedAt = time.Unix(startedAt, 0).UTC()
		run.StoppedAt = unixTime(stoppedAt.Int64)
		result = append(result, run)
	}
	return result, rows.Err()
}

func validateNode(name string, node config.NodeConfig) error {
	switch node.Type {
	case "direct":
		return fmt.Errorf("node %q cannot use the built-in direct type", name)
	case "socks5":
		if node.SOCKS5 == nil || node.SOCKS5.Addr == "" {
			return fmt.Errorf("node %q requires socks5 addr", name)
		}
	case "http":
		if node.HTTP == nil || node.HTTP.URL == "" {
			return fmt.Errorf("node %q requires http url", name)
		}
	case "hysteria2":
		if node.Hysteria2 == nil || node.Hysteria2.Addr == "" || node.Hysteria2.Auth == "" {
			return fmt.Errorf("node %q requires hysteria2 addr and auth", name)
		}
	default:
		return fmt.Errorf("node %q has unknown type %q", name, node.Type)
	}
	return nil
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

// Ping exposes a cheap store health check for the systemd watchdog.
func (s *SQLiteStore) Ping() error { return s.db.Ping() }
