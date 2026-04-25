package traffic

import (
	"testing"

	"github.com/hy2-gateway/internal/config"
	"go.uber.org/zap"
)

func TestTrafficLogger_BasicAccounting(t *testing.T) {
	logger := zap.NewNop()
	users := map[string]config.UserConfig{
		"alice": {Password: "p", Route: "direct", MaxBytes: 0},
	}
	tl := NewTrafficLogger(users, nil, logger)

	// Log some traffic
	ok := tl.LogTraffic("alice", 100, 200)
	if !ok {
		t.Error("expected LogTraffic to return true")
	}

	ok = tl.LogTraffic("alice", 50, 30)
	if !ok {
		t.Error("expected LogTraffic to return true")
	}

	snap := tl.GetSnapshot("alice")
	if snap == nil {
		t.Fatal("expected snapshot for alice")
	}
	if snap.TxBytes != 150 || snap.RxBytes != 230 {
		t.Errorf("expected tx=150 rx=230, got tx=%d rx=%d", snap.TxBytes, snap.RxBytes)
	}
}

func TestTrafficLogger_QuotaEnforcement(t *testing.T) {
	logger := zap.NewNop()
	users := map[string]config.UserConfig{
		"bob": {Password: "p", Route: "direct", MaxBytes: 500},
	}
	tl := NewTrafficLogger(users, nil, logger)

	// Under quota
	ok := tl.LogTraffic("bob", 200, 200)
	if !ok {
		t.Error("expected LogTraffic to return true (under quota)")
	}

	// Over quota (200+200+200 = 600 > 500)
	ok = tl.LogTraffic("bob", 100, 100)
	if ok {
		t.Error("expected LogTraffic to return false (over quota)")
	}
}

func TestTrafficLogger_OnlineState(t *testing.T) {
	logger := zap.NewNop()
	users := map[string]config.UserConfig{
		"alice": {Password: "p", Route: "direct"},
	}
	tl := NewTrafficLogger(users, nil, logger)

	tl.LogOnlineState("alice", true)
	tl.LogOnlineState("alice", true)

	snap := tl.GetSnapshot("alice")
	if snap.OnlineCount != 2 {
		t.Errorf("expected online=2, got %d", snap.OnlineCount)
	}

	tl.LogOnlineState("alice", false)
	snap = tl.GetSnapshot("alice")
	if snap.OnlineCount != 1 {
		t.Errorf("expected online=1, got %d", snap.OnlineCount)
	}
}

func TestTrafficLogger_UnknownUser(t *testing.T) {
	logger := zap.NewNop()
	users := map[string]config.UserConfig{}
	tl := NewTrafficLogger(users, nil, logger)

	// Unknown user should still work (auto-create)
	ok := tl.LogTraffic("unknown", 100, 200)
	if !ok {
		t.Error("expected LogTraffic to return true for unknown user (no quota)")
	}

	snap := tl.GetSnapshot("unknown")
	if snap == nil {
		t.Fatal("expected snapshot for unknown user")
	}
	if snap.TxBytes != 100 || snap.RxBytes != 200 {
		t.Errorf("expected tx=100 rx=200, got tx=%d rx=%d", snap.TxBytes, snap.RxBytes)
	}
}

func TestTrafficLogger_Reset(t *testing.T) {
	logger := zap.NewNop()
	users := map[string]config.UserConfig{
		"alice": {Password: "p", Route: "direct"},
	}
	tl := NewTrafficLogger(users, nil, logger)

	tl.LogTraffic("alice", 100, 200)
	tl.ResetStats("alice")

	snap := tl.GetSnapshot("alice")
	if snap.TxBytes != 0 || snap.RxBytes != 0 {
		t.Errorf("expected tx=0 rx=0 after reset, got tx=%d rx=%d", snap.TxBytes, snap.RxBytes)
	}
}

func TestTrafficLogger_GetAllSnapshots(t *testing.T) {
	logger := zap.NewNop()
	users := map[string]config.UserConfig{
		"alice": {Password: "p", Route: "direct"},
		"bob":   {Password: "p", Route: "direct"},
	}
	tl := NewTrafficLogger(users, nil, logger)

	tl.LogTraffic("alice", 100, 200)
	tl.LogTraffic("bob", 50, 60)

	all := tl.GetAllSnapshots()
	if len(all) != 2 {
		t.Errorf("expected 2 users, got %d", len(all))
	}
	if all["alice"].TxBytes != 100 {
		t.Errorf("alice tx: expected 100, got %d", all["alice"].TxBytes)
	}
	if all["bob"].RxBytes != 60 {
		t.Errorf("bob rx: expected 60, got %d", all["bob"].RxBytes)
	}
}
