package traffic

import (
	"testing"

	"github.com/hy2-gateway/internal/config"
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

	// Unknown user should still work (auto-create, no quota)
	ok := tl.LogTraffic("unknown:node1", 100, 200)
	if !ok {
		t.Error("expected LogTraffic to return true for unknown user (no quota)")
	}

	snap := tl.GetSnapshot("unknown:node1")
	if snap == nil {
		t.Fatal("expected snapshot for unknown:node1")
	}
	if snap.TxBytes != 100 || snap.RxBytes != 200 {
		t.Errorf("expected tx=100 rx=200, got tx=%d rx=%d", snap.TxBytes, snap.RxBytes)
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
