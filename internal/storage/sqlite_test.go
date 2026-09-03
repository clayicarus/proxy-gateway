package storage

import (
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/clayicarus/proxy-gateway/internal/config"
	"github.com/clayicarus/proxy-gateway/internal/subtoken"
	"go.uber.org/zap"
)

func TestSQLiteStore_FlushAndQuery(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	defer os.Remove(dbPath)

	logger := zap.NewNop()
	store, err := NewSQLiteStore(dbPath, logger)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	// Flush some traffic
	records := []TrafficRecord{
		{UserID: "alice", NodeID: "node1", TxBytes: 1000, RxBytes: 2000, Timestamp: time.Now()},
		{UserID: "alice", NodeID: "node2", TxBytes: 300, RxBytes: 400, Timestamp: time.Now()},
		{UserID: "bob", NodeID: "node1", TxBytes: 500, RxBytes: 300, Timestamp: time.Now()},
	}
	if err := store.FlushTraffic(records); err != nil {
		t.Fatalf("flush failed: %v", err)
	}

	// Query alice:node1
	tx, rx, err := store.GetSummary("alice", "node1")
	if err != nil {
		t.Fatalf("get summary failed: %v", err)
	}
	if tx != 1000 || rx != 2000 {
		t.Errorf("alice/node1: expected tx=1000 rx=2000, got tx=%d rx=%d", tx, rx)
	}

	// Query alice:node2
	tx, rx, err = store.GetSummary("alice", "node2")
	if err != nil {
		t.Fatalf("get summary failed: %v", err)
	}
	if tx != 300 || rx != 400 {
		t.Errorf("alice/node2: expected tx=300 rx=400, got tx=%d rx=%d", tx, rx)
	}

	// Flush more for alice:node1
	records2 := []TrafficRecord{
		{UserID: "alice", NodeID: "node1", TxBytes: 500, RxBytes: 100, Timestamp: time.Now()},
	}
	if err := store.FlushTraffic(records2); err != nil {
		t.Fatalf("flush2 failed: %v", err)
	}

	// Should be cumulative
	tx, rx, err = store.GetSummary("alice", "node1")
	if err != nil {
		t.Fatalf("get summary2 failed: %v", err)
	}
	if tx != 1500 || rx != 2100 {
		t.Errorf("alice/node1 cumulative: expected tx=1500 rx=2100, got tx=%d rx=%d", tx, rx)
	}

	// Query all summaries for alice
	userSums, err := store.GetUserSummaries("alice")
	if err != nil {
		t.Fatalf("get user summaries failed: %v", err)
	}
	if len(userSums) != 2 {
		t.Errorf("expected 2 nodes for alice, got %d", len(userSums))
	}

	// Query all
	all, err := store.GetAllSummaries()
	if err != nil {
		t.Fatalf("get all summaries failed: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("expected 3 rows, got %d", len(all))
	}
}

func TestSQLiteStore_UnknownUser(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	defer os.Remove(dbPath)

	logger := zap.NewNop()
	store, err := NewSQLiteStore(dbPath, logger)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	tx, rx, err := store.GetSummary("nobody", "node1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tx != 0 || rx != 0 {
		t.Errorf("expected 0/0 for unknown user, got %d/%d", tx, rx)
	}
}

func TestSQLiteStore_CreatesParentDirectory(t *testing.T) {
	dbPath := t.TempDir() + "/nested/management/traffic.db"
	store, err := NewSQLiteStore(dbPath, zap.NewNop())
	if err != nil {
		t.Fatalf("create store with missing parent: %v", err)
	}
	defer store.Close()
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("database file was not created: %v", err)
	}
}

func TestSQLiteStore_SkipZeroRecords(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	defer os.Remove(dbPath)

	logger := zap.NewNop()
	store, err := NewSQLiteStore(dbPath, logger)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	// Zero records should be skipped
	records := []TrafficRecord{
		{UserID: "alice", NodeID: "node1", TxBytes: 0, RxBytes: 0, Timestamp: time.Now()},
	}
	if err := store.FlushTraffic(records); err != nil {
		t.Fatalf("flush failed: %v", err)
	}

	all, err := store.GetAllSummaries()
	if err != nil {
		t.Fatalf("get all summaries failed: %v", err)
	}
	if len(all) != 0 {
		t.Errorf("expected 0 rows (zero records skipped), got %d", len(all))
	}
}

func TestSQLiteStore_GetTrafficBuckets(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir()+"/traffic.db", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	base := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	shanghai := time.FixedZone("Asia/Shanghai", 8*60*60)
	if err := store.FlushTraffic([]TrafficRecord{
		{UserID: "alice", NodeID: "node1", TxBytes: 10, RxBytes: 20, Timestamp: base.Add(5 * time.Minute).In(shanghai)},
		{UserID: "alice", NodeID: "node1", TxBytes: 30, RxBytes: 40, Timestamp: base.Add(55 * time.Minute)},
		{UserID: "alice", NodeID: "direct", TxBytes: 50, RxBytes: 60, Timestamp: base.Add(time.Hour)},
	}); err != nil {
		t.Fatal(err)
	}
	buckets, err := store.GetTrafficBuckets(base, base.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(buckets) != 2 {
		t.Fatalf("bucket count = %d, want 2: %#v", len(buckets), buckets)
	}
	if buckets[0].Hour != base || buckets[0].TxBytes != 40 || buckets[0].RxBytes != 60 {
		t.Fatalf("unexpected first bucket: %#v", buckets[0])
	}
	if buckets[1].Hour != base.Add(time.Hour) || buckets[1].NodeID != "direct" {
		t.Fatalf("unexpected second bucket: %#v", buckets[1])
	}
}

func TestSQLiteStore_NormalizesLegacyTrafficTimestamps(t *testing.T) {
	dbPath := t.TempDir() + "/legacy.db"
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
		CREATE TABLE traffic_logs (id INTEGER PRIMARY KEY, user_id TEXT NOT NULL, node_id TEXT NOT NULL, tx_bytes INTEGER NOT NULL, rx_bytes INTEGER NOT NULL, created_at DATETIME NOT NULL);
		CREATE TABLE traffic_summary (user_id TEXT NOT NULL, node_id TEXT NOT NULL, tx_total INTEGER NOT NULL, rx_total INTEGER NOT NULL, updated_at DATETIME NOT NULL, PRIMARY KEY (user_id, node_id));
		INSERT INTO traffic_logs (user_id, node_id, tx_bytes, rx_bytes, created_at) VALUES ('alice', 'direct', 1, 2, '2026-08-08 18:30:00+08:00');
		INSERT INTO traffic_summary (user_id, node_id, tx_total, rx_total, updated_at) VALUES ('alice', 'direct', 1, 2, '2026-08-08 18:30:00+08:00');
	`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := NewSQLiteStore(dbPath, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var kind string
	var timestamp int64
	if err := store.db.QueryRow(`SELECT typeof(created_at), CAST(created_at AS INTEGER) FROM traffic_logs`).Scan(&kind, &timestamp); err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 8, 8, 10, 30, 0, 0, time.UTC).Unix()
	if kind != "integer" || timestamp != want {
		t.Fatalf("normalized timestamp = %s/%d, want integer/%d", kind, timestamp, want)
	}
	buckets, err := store.GetTrafficBuckets(time.Unix(want-60, 0), time.Unix(want+60, 0))
	if err != nil || len(buckets) != 1 {
		t.Fatalf("query normalized traffic: buckets=%#v err=%v", buckets, err)
	}
}

func TestSQLiteStore_MigrateLegacyPreservesSubscriptionToken(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir()+"/managed.db", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	cfg := &config.Config{
		Users: map[string]config.UserConfig{
			"alice": {Password: "legacy-password", Routes: []string{"node1", "direct"}, MaxBytes: 1234, SpeedLimit: 55},
		},
		Nodes: map[string]config.NodeConfig{
			"node1": {Type: "hysteria2", Hysteria2: &config.Hysteria2OutboundConfig{Addr: "node.example:443", Auth: "node-auth"}},
		},
	}
	secret := "legacy-subscription-secret"
	if err := store.MigrateLegacy(cfg, func(username string) string { return subtoken.Legacy(username, secret) }); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	users, err := store.LoadRuntimeUsers()
	if err != nil {
		t.Fatal(err)
	}
	if got := users["alice"]; got.Password != "legacy-password" || got.MaxBytes != 1234 || len(got.Routes) != 2 {
		t.Fatalf("unexpected migrated user: %#v", got)
	}
	nodes, err := store.LoadNodes()
	if err != nil || nodes["node1"].Hysteria2 == nil {
		t.Fatalf("migrated nodes: %v, %#v", err, nodes)
	}
	user, err := store.FindUserByToken(subtoken.Legacy("alice", secret))
	if err != nil || user == nil || user.Username != "alice" {
		t.Fatalf("legacy token lookup: user=%#v err=%v", user, err)
	}
	if err := store.MigrateLegacy(cfg, func(username string) string { return subtoken.Legacy(username, secret) }); err == nil {
		t.Fatal("expected second migration to fail")
	}
}

func TestSQLiteStore_ReplaceLegacyUsersPreservesNodesAndTraffic(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir()+"/managed.db", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	initial := &config.Config{
		Users: map[string]config.UserConfig{
			"alice": {Password: "alice-password", Routes: []string{"node1"}},
		},
		Nodes: map[string]config.NodeConfig{
			"node1": {Type: "hysteria2", Hysteria2: &config.Hysteria2OutboundConfig{Addr: "node.example:443", Auth: "secret"}},
		},
	}
	if err := store.MigrateLegacy(initial, func(username string) string { return "old-" + username }); err != nil {
		t.Fatal(err)
	}
	if err := store.FlushTraffic([]TrafficRecord{{UserID: "alice", NodeID: "node1", TxBytes: 10, RxBytes: 20, Timestamp: time.Now()}}); err != nil {
		t.Fatal(err)
	}
	replacement := &config.Config{Users: map[string]config.UserConfig{
		"bob": {Password: "bob-password", Routes: []string{"node1", "direct"}, MaxBytes: 123},
	}}
	if err := store.ReplaceLegacyUsers(replacement, func(username string) string { return "new-" + username }); err != nil {
		t.Fatal(err)
	}
	users, err := store.ListUsers()
	if err != nil || len(users) != 1 || users[0].Username != "bob" || users[0].MonthlyBytes != 123 {
		t.Fatalf("replacement users: %#v err=%v", users, err)
	}
	nodes, err := store.ListNodes()
	if err != nil || len(nodes) != 1 || nodes[0].Name != "node1" {
		t.Fatalf("nodes changed during user replacement: %#v err=%v", nodes, err)
	}
	tx, rx, err := store.GetSummary("alice", "node1")
	if err != nil || tx != 10 || rx != 20 {
		t.Fatalf("traffic changed during user replacement: tx=%d rx=%d err=%v", tx, rx, err)
	}
	if user, err := store.FindUserByToken("new-bob"); err != nil || user == nil || user.Username != "bob" {
		t.Fatalf("replacement token not imported: user=%#v err=%v", user, err)
	}
	if user, err := store.FindUserByToken("old-alice"); err != nil || user != nil {
		t.Fatalf("old token remains active: user=%#v err=%v", user, err)
	}
	state, err := store.GetConfigState()
	if err != nil || state.Revision != 2 || state.ActiveRevision != 0 {
		t.Fatalf("replacement revision: %#v err=%v", state, err)
	}

	invalid := &config.Config{Users: map[string]config.UserConfig{
		"charlie": {Password: "password", Routes: []string{"missing-node"}},
	}}
	if err := store.ReplaceLegacyUsers(invalid, func(username string) string { return "invalid-" + username }); err == nil {
		t.Fatal("expected missing managed node to reject replacement")
	}
	users, err = store.ListUsers()
	if err != nil || len(users) != 1 || users[0].Username != "bob" {
		t.Fatalf("failed replacement was not rolled back: %#v err=%v", users, err)
	}
}

func TestSQLiteStore_UpdateUserOnlyRevisionsRouteChanges(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir()+"/managed.db", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.CreateUser(ManagedUserInput{Username: "alice", Password: "password", Routes: []string{"direct"}}, "token"); err != nil {
		t.Fatal(err)
	}
	state, err := store.GetConfigState()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateUser(ManagedUserInput{Username: "alice", Password: "password", MonthlyBytes: 1024, Routes: []string{"direct"}}); err != nil {
		t.Fatal(err)
	}
	afterLifecycle, err := store.GetConfigState()
	if err != nil {
		t.Fatal(err)
	}
	if afterLifecycle.Revision != state.Revision {
		t.Fatalf("lifecycle-only update changed revision: before=%d after=%d", state.Revision, afterLifecycle.Revision)
	}
	if err := store.SaveNode("node1", config.NodeConfig{Type: "hysteria2", Hysteria2: &config.Hysteria2OutboundConfig{Addr: "node.example:443", Auth: "secret"}}, true); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateUser(ManagedUserInput{Username: "alice", Password: "password", MonthlyBytes: 1024, Routes: []string{"node1"}}); err != nil {
		t.Fatal(err)
	}
	afterRoutes, err := store.GetConfigState()
	if err != nil {
		t.Fatal(err)
	}
	if afterRoutes.Revision != afterLifecycle.Revision+2 {
		t.Fatalf("expected node save and route update to increment revision, got %d", afterRoutes.Revision)
	}
}

func TestSQLiteStore_ListRunningProcess(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir()+"/managed.db", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.StartProcessRun(1234, 7, "scheduled"); err != nil {
		t.Fatal(err)
	}
	runs, err := store.ListProcessRuns(10)
	if err != nil {
		t.Fatalf("list running process: %v", err)
	}
	if len(runs) != 1 || runs[0].PID != 1234 || runs[0].SystemdResult != "" || runs[0].StoppedAt != nil {
		t.Fatalf("unexpected running process record: %#v", runs)
	}
}

func TestSQLiteStore_RestartJobLinksToNextProcess(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir()+"/managed.db", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	jobID, err := store.ScheduleRestart(time.Now().Add(-time.Second), "immediate")
	if err != nil {
		t.Fatal(err)
	}
	job, err := store.ClaimDueRestart(time.Now())
	if err != nil || job == nil || job.ID != jobID {
		t.Fatalf("claim restart job: job=%#v err=%v", job, err)
	}
	if err := store.CompleteRestartJob(jobID, true, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.StartProcessRun(2345, 8, ""); err != nil {
		t.Fatal(err)
	}
	runs, err := store.ListProcessRuns(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].Trigger != "admin:immediate" {
		t.Fatalf("restart trigger was not linked to process: %#v", runs)
	}
}

func TestSQLiteStore_AddsRestartDetailColumnsToExistingDatabase(t *testing.T) {
	dbPath := t.TempDir() + "/managed.db"
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE restart_jobs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		run_at INTEGER NOT NULL,
		trigger TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'pending',
		created_at INTEGER NOT NULL,
		executed_at INTEGER
	)`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := NewSQLiteStore(dbPath, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	jobID, err := store.ScheduleRestart(time.Now(), "immediate")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteRestartJob(jobID, false, "test detail"); err != nil {
		t.Fatal(err)
	}
	jobs, err := store.ListRestartJobs(10)
	if err != nil || len(jobs) != 1 || jobs[0].Detail != "test detail" {
		t.Fatalf("restart columns were not migrated: jobs=%#v err=%v", jobs, err)
	}
}

func TestSQLiteStore_RestartFailureKeepsDetail(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir()+"/managed.db", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	jobID, err := store.ScheduleRestart(time.Now(), "scheduled")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteRestartJob(jobID, false, "D-Bus permission denied"); err != nil {
		t.Fatal(err)
	}
	jobs, err := store.ListRestartJobs(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].Status != "failed" || jobs[0].Detail != "D-Bus permission denied" {
		t.Fatalf("restart failure detail missing: %#v", jobs)
	}
}

func TestSQLiteStore_ProcessRecoveryUsesSystemdResult(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir()+"/managed.db", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.StartProcessRun(1001, 1, "initial"); err != nil {
		t.Fatal(err)
	}
	// Use a different PID to exercise ExecStopPost's single-process fallback.
	if err := store.RecordProcessExit(9999, "watchdog", "killed", "6"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.StartProcessRun(1002, 1, ""); err != nil {
		t.Fatal(err)
	}
	runs, err := store.ListProcessRuns(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 2 || runs[0].Trigger != "recovery:watchdog" || runs[1].SystemdResult != "watchdog" {
		t.Fatalf("systemd recovery reason was not retained: %#v", runs)
	}
}

func TestSQLiteStore_RejectsUnsupportedNodeType(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir()+"/managed.db", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, nodeType := range []string{"direct", "socks5", "http"} {
		if err := store.SaveNode("unsupported", config.NodeConfig{Type: nodeType}, true); err == nil {
			t.Fatalf("managed %s node was accepted", nodeType)
		}
	}
}

func TestSQLiteStore_DeleteNodeRemovesConfigAndAuthorizations(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir()+"/managed.db", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	node := config.NodeConfig{Type: "hysteria2", Hysteria2: &config.Hysteria2OutboundConfig{Addr: "node.example:443", Auth: "secret"}}
	if err := store.SaveNode("node1", node, true); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateUser(ManagedUserInput{Username: "alice", Password: "password", Routes: []string{"node1", "direct"}}, "token"); err != nil {
		t.Fatal(err)
	}
	if err := store.FlushTraffic([]TrafficRecord{{UserID: "alice", NodeID: "node1", TxBytes: 10, RxBytes: 20, Timestamp: time.Now()}}); err != nil {
		t.Fatal(err)
	}
	before, err := store.GetConfigState()
	if err != nil {
		t.Fatal(err)
	}

	if err := store.DeleteNode("node1"); err != nil {
		t.Fatal(err)
	}
	nodes, err := store.ListNodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 0 {
		t.Fatalf("deleted node still listed: %#v", nodes)
	}
	user, err := store.GetUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	if user == nil || len(user.Routes) != 1 || user.Routes[0] != "direct" {
		t.Fatalf("node authorization was not removed: %#v", user)
	}
	tx, rx, err := store.GetSummary("alice", "node1")
	if err != nil || tx != 10 || rx != 20 {
		t.Fatalf("traffic history changed: tx=%d rx=%d err=%v", tx, rx, err)
	}
	after, err := store.GetConfigState()
	if err != nil {
		t.Fatal(err)
	}
	if after.Revision != before.Revision+1 {
		t.Fatalf("delete revision = %d, want %d", after.Revision, before.Revision+1)
	}
	if err := store.DeleteNode("node1"); err == nil {
		t.Fatal("deleting a missing node succeeded")
	}
}
