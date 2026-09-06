package traffic

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/clayicarus/proxy-gateway/internal/config"
	"github.com/clayicarus/proxy-gateway/internal/storage"
	"go.uber.org/zap"
)

func TestTrafficLogger_BasicAccounting(t *testing.T) {
	logger := zap.NewNop()
	users := map[string]config.UserConfig{
		"alice": {Password: "p", Routes: []string{"node1", "direct"}, MaxBytes: 0},
	}
	tl := NewTrafficLogger(users, nil, logger)

	// Log traffic on alice:node1
	ok := tl.LogTraffic("alice:node1", 100, 200)
	if !ok {
		t.Error("expected LogTraffic to return true")
	}

	ok = tl.LogTraffic("alice:node1", 50, 30)
	if !ok {
		t.Error("expected LogTraffic to return true")
	}

	snap := tl.GetSnapshot("alice:node1")
	if snap == nil {
		t.Fatal("expected snapshot for alice:node1")
	}
	if snap.TxBytes != 150 || snap.RxBytes != 230 {
		t.Errorf("expected tx=150 rx=230, got tx=%d rx=%d", snap.TxBytes, snap.RxBytes)
	}
	if snap.Username != "alice" || snap.Node != "node1" {
		t.Errorf("expected username=alice node=node1, got %s/%s", snap.Username, snap.Node)
	}
}

func TestTrafficLogger_MultiNodeAccounting(t *testing.T) {
	logger := zap.NewNop()
	users := map[string]config.UserConfig{
		"alice": {Password: "p", Routes: []string{"node1", "node2"}, MaxBytes: 0},
	}
	tl := NewTrafficLogger(users, nil, logger)

	tl.LogTraffic("alice:node1", 100, 200)
	tl.LogTraffic("alice:node2", 50, 60)

	snap1 := tl.GetSnapshot("alice:node1")
	snap2 := tl.GetSnapshot("alice:node2")

	if snap1.TxBytes != 100 || snap1.RxBytes != 200 {
		t.Errorf("node1: expected tx=100 rx=200, got tx=%d rx=%d", snap1.TxBytes, snap1.RxBytes)
	}
	if snap2.TxBytes != 50 || snap2.RxBytes != 60 {
		t.Errorf("node2: expected tx=50 rx=60, got tx=%d rx=%d", snap2.TxBytes, snap2.RxBytes)
	}
}

func TestTrafficLogger_QuotaAcrossNodes(t *testing.T) {
	logger := zap.NewNop()
	users := map[string]config.UserConfig{
		"bob": {Password: "p", Routes: []string{"node1", "node2"}, MaxBytes: 500},
	}
	tl := NewTrafficLogger(users, nil, logger)

	// 200 on node1
	ok := tl.LogTraffic("bob:node1", 100, 100)
	if !ok {
		t.Error("expected LogTraffic to return true (under quota)")
	}

	// 200 on node2 (total now 400, still under 500)
	ok = tl.LogTraffic("bob:node2", 100, 100)
	if !ok {
		t.Error("expected LogTraffic to return true (under quota)")
	}

	// 200 more on node1 (total now 600 > 500)
	ok = tl.LogTraffic("bob:node1", 100, 100)
	if ok {
		t.Error("expected LogTraffic to return false (over quota across nodes)")
	}
}

func TestTrafficLogger_OnlineState(t *testing.T) {
	logger := zap.NewNop()
	users := map[string]config.UserConfig{
		"alice": {Password: "p", Routes: []string{"node1"}},
	}
	tl := NewTrafficLogger(users, nil, logger)

	tl.LogOnlineState("alice:node1", true)
	tl.LogOnlineState("alice:node1", true)

	snap := tl.GetSnapshot("alice:node1")
	if snap.OnlineCount != 2 {
		t.Errorf("expected online=2, got %d", snap.OnlineCount)
	}

	tl.LogOnlineState("alice:node1", false)
	snap = tl.GetSnapshot("alice:node1")
	if snap.OnlineCount != 1 {
		t.Errorf("expected online=1, got %d", snap.OnlineCount)
	}
}

func TestTrafficLogger_UnknownUser(t *testing.T) {
	logger := zap.NewNop()
	users := map[string]config.UserConfig{}
	tl := NewTrafficLogger(users, nil, logger)

	// An authenticated ID that no longer has runtime user state must not retain
	// access through a stale connection.
	ok := tl.LogTraffic("unknown:node1", 100, 200)
	if ok {
		t.Error("expected LogTraffic to return false for unknown user")
	}

	snap := tl.GetSnapshot("unknown:node1")
	if snap != nil {
		t.Fatalf("inactive traffic must not be accounted, got snapshot %#v", snap)
	}
}

func TestTrafficLogger_DisconnectsInactiveExistingUsers(t *testing.T) {
	now := time.Now().UTC()
	future := now.Add(time.Hour)
	past := now.Add(-time.Hour)
	users := map[string]config.UserConfig{
		"alice": {Password: "p", Routes: []string{"node1"}, ExpiresAt: &future},
	}
	tl := NewTrafficLogger(users, nil, zap.NewNop())

	if ok := tl.LogTraffic("alice:node1", 100, 200); !ok {
		t.Fatal("active user traffic was rejected")
	}

	users["alice"] = config.UserConfig{Password: "p", Routes: []string{"node1"}, ExpiresAt: &past}
	tl.UpdateUsers(users)
	if ok := tl.LogTraffic("alice:node1", 10, 20); ok {
		t.Fatal("expired existing user traffic was accepted")
	}
	snapshot := tl.GetSnapshot("alice:node1")
	if snapshot.TxBytes != 100 || snapshot.RxBytes != 200 {
		t.Fatalf("expired traffic was accounted: tx=%d rx=%d", snapshot.TxBytes, snapshot.RxBytes)
	}

	users["alice"] = config.UserConfig{Password: "p", Routes: []string{"node1"}, ExpiresAt: &future}
	tl.UpdateUsers(users)
	if ok := tl.LogTraffic("alice:node1", 10, 20); !ok {
		t.Fatal("renewed user traffic was rejected")
	}

	users["alice"] = config.UserConfig{Password: "p", Routes: []string{"node1"}, Disabled: true}
	tl.UpdateUsers(users)
	if ok := tl.LogTraffic("alice:node1", 10, 20); ok {
		t.Fatal("disabled existing user traffic was accepted")
	}
}

func TestTrafficLogger_StopWaitsForFinalFlush(t *testing.T) {
	store, err := storage.NewSQLiteStore(t.TempDir()+"/traffic.db", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	users := map[string]config.UserConfig{
		"alice": {Password: "p", Routes: []string{"direct"}},
	}
	tl := NewTrafficLogger(users, store, zap.NewNop())
	tl.StartPeriodicFlush(time.Hour)
	if ok := tl.LogTraffic("alice:direct", 100, 200); !ok {
		t.Fatal("active traffic was rejected")
	}
	tl.Stop()
	tx, rx, err := store.GetSummary("alice", "direct")
	if err != nil {
		t.Fatal(err)
	}
	if tx != 100 || rx != 200 {
		t.Fatalf("final flush not persisted: tx=%d rx=%d", tx, rx)
	}
}

func TestTrafficLogger_FailedFlushRestoresDeltas(t *testing.T) {
	path := t.TempDir() + "/traffic.db"
	store, err := storage.NewSQLiteStore(path, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	users := map[string]config.UserConfig{
		"alice": {Password: "p", Routes: []string{"direct"}},
	}
	tl := NewTrafficLogger(users, store, zap.NewNop())
	if ok := tl.LogTraffic("alice:direct", 100, 200); !ok {
		t.Fatal("active traffic was rejected")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	tl.Flush()
	reopened, err := storage.NewSQLiteStore(path, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	tl.store = reopened
	if !tl.LogTraffic("alice:direct", 50, 30) {
		t.Fatal("traffic after reopening the database was rejected")
	}
	tl.Flush()
	tl.Flush()
	if tx, rx, err := reopened.GetSummary("alice", "direct"); err != nil || tx != 150 || rx != 230 {
		t.Fatalf("retried traffic = %d/%d, error=%v; want 150/230 exactly once", tx, rx, err)
	}
}

func TestTrafficLogger_MonthRolloverPreservesPendingTrafficAndQuota(t *testing.T) {
	for _, location := range []*time.Location{time.UTC, time.FixedZone("UTC+8", 8*3600), time.FixedZone("UTC-5", -5*3600)} {
		for _, failFlush := range []bool{false, true} {
			name := location.String()
			if failFlush {
				name += "/retry"
			}
			t.Run(name, func(t *testing.T) {
				path := t.TempDir() + "/traffic.db"
				store, err := storage.NewSQLiteStore(path, zap.NewNop())
				if err != nil {
					t.Fatal(err)
				}
				defer func() { store.Close() }()
				oldMonth := time.Date(2026, time.January, 31, 23, 59, 59, 0, location)
				newMonth := oldMonth.Add(time.Second)
				// Existing persisted usage must still count when a month is loaded.
				if err := store.FlushTraffic([]storage.TrafficRecord{{UserID: "alice", NodeID: "direct", TxBytes: 10, RxBytes: 10, Timestamp: newMonth}}); err != nil {
					t.Fatal(err)
				}
				users := map[string]config.UserConfig{"alice": {Routes: []string{"direct", "node1"}, MaxBytes: 100}}
				tl := NewTrafficLoggerWithLocation(users, store, zap.NewNop(), location)
				now := oldMonth
				tl.now = func() time.Time { return now }
				if !tl.LogTraffic("alice:node1", 60, 40) {
					t.Fatal("old-month traffic at quota was rejected")
				}
				if failFlush {
					if err := store.Close(); err != nil {
						t.Fatal(err)
					}
					tl.Flush()
					store, err = storage.NewSQLiteStore(path, zap.NewNop())
					if err != nil {
						t.Fatal(err)
					}
					tl.store = store
				}
				now = newMonth
				if !tl.LogTraffic("alice:direct", 20, 10) {
					t.Fatal("old-month pending bytes consumed the new-month quota")
				}
				if tl.LogTraffic("alice:node1", 51, 0) {
					t.Fatal("new-month persisted usage was omitted from the shared quota")
				}
				tl.Flush()
				tl.Flush() // No duplicate accounting on repeated flushes.
				for _, check := range []struct {
					time time.Time
					want [2]uint64
				}{{oldMonth, [2]uint64{60, 40}}, {newMonth, [2]uint64{81, 20}}} {
					_, start, end := tl.monthBounds(check.time)
					usage, err := store.GetUserMonthlyUsage(start, end)
					if err != nil {
						t.Fatal(err)
					}
					if usage["alice"] != check.want {
						t.Fatalf("usage at %v = %v, want %v", check.time, usage["alice"], check.want)
					}
				}
				restarted := NewTrafficLoggerWithLocation(users, store, zap.NewNop(), location)
				restarted.now = func() time.Time { return newMonth }
				if restarted.LogTraffic("alice:direct", 1, 0) {
					t.Fatal("restart reset persisted new-month usage")
				}
			})
		}
	}
}

func TestTrafficLogger_MonthReloadFailureRejectsUnaccountedTraffic(t *testing.T) {
	store, err := storage.NewSQLiteStore(t.TempDir()+"/traffic.db", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	tl := NewTrafficLogger(map[string]config.UserConfig{"alice": {Routes: []string{"direct"}, MaxBytes: 100}}, store, zap.NewNop())
	if tl.LogTraffic("alice:direct", 1, 0) {
		t.Fatal("failed monthly usage query granted traffic")
	}
	if snapshot := tl.GetSnapshot("alice:direct"); snapshot.TxBytes != 0 {
		t.Fatal("traffic without a known quota base was partially accounted")
	}
}

func TestTrafficLogger_Reset(t *testing.T) {
	logger := zap.NewNop()
	users := map[string]config.UserConfig{
		"alice": {Password: "p", Routes: []string{"node1"}},
	}
	tl := NewTrafficLogger(users, nil, logger)

	tl.LogTraffic("alice:node1", 100, 200)
	tl.ResetStats("alice:node1")

	snap := tl.GetSnapshot("alice:node1")
	if snap.TxBytes != 0 || snap.RxBytes != 0 {
		t.Errorf("expected tx=0 rx=0 after reset, got tx=%d rx=%d", snap.TxBytes, snap.RxBytes)
	}
}

func TestTrafficLogger_GetAllSnapshots(t *testing.T) {
	logger := zap.NewNop()
	users := map[string]config.UserConfig{
		"alice": {Password: "p", Routes: []string{"node1", "node2"}},
		"bob":   {Password: "p", Routes: []string{"node1"}},
	}
	tl := NewTrafficLogger(users, nil, logger)

	tl.LogTraffic("alice:node1", 100, 200)
	tl.LogTraffic("alice:node2", 10, 20)
	tl.LogTraffic("bob:node1", 50, 60)

	all := tl.GetAllSnapshots()
	if len(all) != 3 {
		t.Errorf("expected 3 entries, got %d", len(all))
	}
	if all["alice:node1"].TxBytes != 100 {
		t.Errorf("alice:node1 tx: expected 100, got %d", all["alice:node1"].TxBytes)
	}
	if all["bob:node1"].RxBytes != 60 {
		t.Errorf("bob:node1 rx: expected 60, got %d", all["bob:node1"].RxBytes)
	}
}

func TestTrafficLogger_DownloadLimitIsSharedAcrossNodes(t *testing.T) {
	users := map[string]config.UserConfig{
		"alice": {Password: "p", Routes: []string{"node1", "node2"}, SpeedLimit: 1000},
	}
	tl := NewTrafficLogger(users, nil, zap.NewNop())

	if ok := tl.LogTraffic("alice:node1", 0, 100); !ok {
		t.Fatal("first download chunk was rejected")
	}
	started := time.Now()
	if ok := tl.LogTraffic("alice:node2", 0, 1); !ok {
		t.Fatal("second download chunk was rejected")
	}
	if elapsed := time.Since(started); elapsed < 70*time.Millisecond {
		t.Fatalf("per-user limiter was not shared across nodes; wait=%v", elapsed)
	}
}

func TestTrafficLogger_BeginShutdownCancelsLimitWaitWithoutAccounting(t *testing.T) {
	users := map[string]config.UserConfig{
		"alice": {Password: "p", Routes: []string{"direct"}, SpeedLimit: 1},
	}
	tl := NewTrafficLogger(users, nil, zap.NewNop())
	if ok := tl.LogTraffic("alice:direct", 0, 2); !ok {
		t.Fatal("first download chunk was rejected")
	}

	result := make(chan bool, 1)
	var started sync.WaitGroup
	started.Add(1)
	go func() {
		started.Done()
		result <- tl.LogTraffic("alice:direct", 0, 1)
	}()
	started.Wait()
	select {
	case <-result:
		t.Fatal("limited traffic returned before its reservation")
	case <-time.After(50 * time.Millisecond):
	}

	tl.BeginShutdown()
	select {
	case ok := <-result:
		if ok {
			t.Fatal("shutdown-cancelled traffic was accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown did not cancel download-limit wait")
	}
	snapshot := tl.GetSnapshot("alice:direct")
	if snapshot.RxBytes != 2 {
		t.Fatalf("cancelled chunk was accounted: rx=%d", snapshot.RxBytes)
	}
	if ok := tl.LogTraffic("alice:direct", 1, 0); ok {
		t.Fatal("traffic was accepted after shutdown began")
	}
}

func TestTrafficLogger_PolicyChangesWakeDownloadReservations(t *testing.T) {
	expired := time.Now().Add(-time.Minute)
	for _, test := range []struct {
		name string
		user config.UserConfig
		want bool
	}{
		{"disabled", config.UserConfig{SpeedLimit: 1, Disabled: true}, false},
		{"expired", config.UserConfig{SpeedLimit: 1, ExpiresAt: &expired}, false},
		{"unlimited", config.UserConfig{}, true},
		{"faster", config.UserConfig{SpeedLimit: 10000}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			tl := NewTrafficLogger(map[string]config.UserConfig{"alice": {Routes: []string{"direct"}, SpeedLimit: 1}}, nil, zap.NewNop())
			defer tl.Stop()
			if !tl.LogTraffic("alice:direct", 0, 2) {
				t.Fatal("first chunk was rejected")
			}
			result := make(chan bool, 1)
			go func() { result <- tl.LogTraffic("alice:direct", 0, 1) }()
			select {
			case <-result:
				t.Fatal("second chunk skipped the shared rate limit")
			case <-time.After(50 * time.Millisecond):
			}
			tl.UpdateUsers(map[string]config.UserConfig{"alice": test.user})
			select {
			case got := <-result:
				if got != test.want {
					t.Fatalf("updated policy accepted=%v, want %v", got, test.want)
				}
			case <-time.After(time.Second):
				t.Fatal("policy update did not wake the old download reservation")
			}
			wantRx := uint64(2)
			if test.want {
				wantRx++
			}
			if got := tl.GetSnapshot("alice:direct").RxBytes; got != wantRx {
				t.Fatalf("accounted rx=%d, want %d", got, wantRx)
			}
		})
	}
}

func TestTrafficLogger_UnchangedRefreshPreservesLimitAndContextCancels(t *testing.T) {
	users := map[string]config.UserConfig{"alice": {Routes: []string{"direct"}, SpeedLimit: 1}}
	tl := NewTrafficLogger(users, nil, zap.NewNop())
	defer tl.Stop()
	tl.LogTraffic("alice:direct", 0, 2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan bool, 1)
	go func() { result <- tl.LogTrafficContext(ctx, "alice:direct", 0, 1) }()
	tl.UpdateUsers(users)
	select {
	case <-result:
		t.Fatal("an unchanged refresh reset the rate limit")
	case <-time.After(100 * time.Millisecond):
	}
	cancel()
	select {
	case accepted := <-result:
		if accepted {
			t.Fatal("cancelled relay traffic was accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("relay cancellation did not release the rate-limit wait")
	}
	if tl.GetSnapshot("alice:direct").RxBytes != 2 {
		t.Fatal("cancelled relay traffic was accounted")
	}
	if !tl.LogTraffic("alice:direct", 1, 0) {
		t.Fatal("cancelling one relay stopped other traffic")
	}
}

func TestTrafficLogger_ExpiryInterruptsDownloadWait(t *testing.T) {
	expires := time.Now().Add(150 * time.Millisecond)
	tl := NewTrafficLogger(map[string]config.UserConfig{"alice": {Routes: []string{"direct"}, SpeedLimit: 1, ExpiresAt: &expires}}, nil, zap.NewNop())
	defer tl.Stop()
	tl.LogTraffic("alice:direct", 0, 2)
	result := make(chan bool, 1)
	go func() { result <- tl.LogTraffic("alice:direct", 0, 1) }()
	select {
	case accepted := <-result:
		if accepted || tl.GetSnapshot("alice:direct").RxBytes != 2 {
			t.Fatal("traffic waiting past expiry was accepted or accounted")
		}
	case <-time.After(time.Second):
		t.Fatal("expiry did not release the download wait")
	}
}
