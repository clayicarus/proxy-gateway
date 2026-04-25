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
