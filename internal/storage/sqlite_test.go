package storage

import (
	"os"
	"testing"
	"time"

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
		{UserID: "alice", TxBytes: 1000, RxBytes: 2000, Timestamp: time.Now()},
		{UserID: "bob", TxBytes: 500, RxBytes: 300, Timestamp: time.Now()},
	}
	if err := store.FlushTraffic(records); err != nil {
		t.Fatalf("flush failed: %v", err)
	}

	// Query alice
	tx, rx, err := store.GetSummary("alice")
	if err != nil {
		t.Fatalf("get summary failed: %v", err)
	}
	if tx != 1000 || rx != 2000 {
		t.Errorf("alice: expected tx=1000 rx=2000, got tx=%d rx=%d", tx, rx)
	}

	// Flush more for alice
	records2 := []TrafficRecord{
		{UserID: "alice", TxBytes: 500, RxBytes: 100, Timestamp: time.Now()},
	}
	if err := store.FlushTraffic(records2); err != nil {
		t.Fatalf("flush2 failed: %v", err)
	}

	// Should be cumulative
	tx, rx, err = store.GetSummary("alice")
	if err != nil {
		t.Fatalf("get summary2 failed: %v", err)
	}
	if tx != 1500 || rx != 2100 {
		t.Errorf("alice cumulative: expected tx=1500 rx=2100, got tx=%d rx=%d", tx, rx)
	}

	// Query all
	all, err := store.GetAllSummaries()
	if err != nil {
		t.Fatalf("get all summaries failed: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("expected 2 users, got %d", len(all))
	}
	if all["bob"][0] != 500 || all["bob"][1] != 300 {
		t.Errorf("bob: expected [500, 300], got %v", all["bob"])
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

	tx, rx, err := store.GetSummary("nobody")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tx != 0 || rx != 0 {
		t.Errorf("expected 0/0 for unknown user, got %d/%d", tx, rx)
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
		{UserID: "alice", TxBytes: 0, RxBytes: 0, Timestamp: time.Now()},
	}
	if err := store.FlushTraffic(records); err != nil {
		t.Fatalf("flush failed: %v", err)
	}

	all, err := store.GetAllSummaries()
	if err != nil {
		t.Fatalf("get all summaries failed: %v", err)
	}
	if len(all) != 0 {
		t.Errorf("expected 0 users (zero records skipped), got %d", len(all))
	}
}
