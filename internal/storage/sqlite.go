package storage

import (
	"database/sql"
	"fmt"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"go.uber.org/zap"
)

// TrafficRecord represents a single traffic record for persistence.
type TrafficRecord struct {
	UserID    string
	NodeID    string
	TxBytes   uint64
	RxBytes   uint64
	Timestamp time.Time
}

// SQLiteStore provides persistent storage for traffic statistics.
type SQLiteStore struct {
	db     *sql.DB
	mu     sync.Mutex
	logger *zap.Logger
}

// NewSQLiteStore opens (or creates) the SQLite database at the given path.
func NewSQLiteStore(dbPath string, logger *zap.Logger) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite: %w", err)
	}

	store := &SQLiteStore{db: db, logger: logger}
	if err := store.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to migrate sqlite: %w", err)
	}

	return store, nil
}

// migrate creates tables if they don't exist.
func (s *SQLiteStore) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS traffic_logs (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id    TEXT    NOT NULL,
		node_id    TEXT    NOT NULL DEFAULT '',
		tx_bytes   INTEGER NOT NULL DEFAULT 0,
		rx_bytes   INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME NOT NULL DEFAULT (datetime('now'))
	);

	CREATE INDEX IF NOT EXISTS idx_traffic_logs_user_node ON traffic_logs(user_id, node_id);
	CREATE INDEX IF NOT EXISTS idx_traffic_logs_created_at ON traffic_logs(created_at);

	CREATE TABLE IF NOT EXISTS traffic_summary (
		user_id    TEXT NOT NULL,
		node_id    TEXT NOT NULL DEFAULT '',
		tx_total   INTEGER NOT NULL DEFAULT 0,
		rx_total   INTEGER NOT NULL DEFAULT 0,
		updated_at DATETIME NOT NULL DEFAULT (datetime('now')),
		PRIMARY KEY (user_id, node_id)
	);
	`
	_, err := s.db.Exec(schema)
	return err
}

// FlushTraffic writes a batch of traffic deltas to the database.
// It updates both the incremental log and the cumulative summary.
func (s *SQLiteStore) FlushTraffic(records []TrafficRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	insertLog, err := tx.Prepare(`
		INSERT INTO traffic_logs (user_id, node_id, tx_bytes, rx_bytes, created_at)
		VALUES (?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("prepare insert log: %w", err)
	}
	defer insertLog.Close()

	upsertSummary, err := tx.Prepare(`
		INSERT INTO traffic_summary (user_id, node_id, tx_total, rx_total, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(user_id, node_id) DO UPDATE SET
			tx_total = tx_total + excluded.tx_total,
			rx_total = rx_total + excluded.rx_total,
			updated_at = excluded.updated_at
	`)
	if err != nil {
		return fmt.Errorf("prepare upsert summary: %w", err)
	}
	defer upsertSummary.Close()

	now := time.Now()
	for _, r := range records {
		if r.TxBytes == 0 && r.RxBytes == 0 {
			continue
		}
		ts := r.Timestamp
		if ts.IsZero() {
			ts = now
		}
		if _, err := insertLog.Exec(r.UserID, r.NodeID, r.TxBytes, r.RxBytes, ts); err != nil {
			return fmt.Errorf("insert log for %s/%s: %w", r.UserID, r.NodeID, err)
		}
		if _, err := upsertSummary.Exec(r.UserID, r.NodeID, r.TxBytes, r.RxBytes, ts); err != nil {
			return fmt.Errorf("upsert summary for %s/%s: %w", r.UserID, r.NodeID, err)
		}
	}

	return tx.Commit()
}

// GetSummary returns the cumulative traffic for a (user, node) pair.
func (s *SQLiteStore) GetSummary(userID, nodeID string) (txTotal, rxTotal uint64, err error) {
	row := s.db.QueryRow(
		`SELECT tx_total, rx_total FROM traffic_summary WHERE user_id = ? AND node_id = ?`,
		userID, nodeID,
	)
	err = row.Scan(&txTotal, &rxTotal)
	if err == sql.ErrNoRows {
		return 0, 0, nil
	}
	return
}

// GetUserSummaries returns cumulative traffic for all nodes of a given user.
func (s *SQLiteStore) GetUserSummaries(userID string) (map[string][2]uint64, error) {
	rows, err := s.db.Query(
		`SELECT node_id, tx_total, rx_total FROM traffic_summary WHERE user_id = ?`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string][2]uint64)
	for rows.Next() {
		var nodeID string
		var tx, rx uint64
		if err := rows.Scan(&nodeID, &tx, &rx); err != nil {
			return nil, err
		}
		result[nodeID] = [2]uint64{tx, rx}
	}
	return result, rows.Err()
}

// GetAllSummaries returns cumulative traffic for all (user, node) pairs.
func (s *SQLiteStore) GetAllSummaries() ([]TrafficSummaryRow, error) {
	rows, err := s.db.Query(`SELECT user_id, node_id, tx_total, rx_total FROM traffic_summary`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []TrafficSummaryRow
	for rows.Next() {
		var row TrafficSummaryRow
		if err := rows.Scan(&row.UserID, &row.NodeID, &row.TxTotal, &row.RxTotal); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

// TrafficSummaryRow represents a row from the traffic_summary table.
type TrafficSummaryRow struct {
	UserID  string `json:"userId"`
	NodeID  string `json:"nodeId"`
	TxTotal uint64 `json:"txTotal"`
	RxTotal uint64 `json:"rxTotal"`
}

// LoadSummaryForUserNode loads persisted totals so the in-memory counter can resume.
func (s *SQLiteStore) LoadSummaryForUserNode(userID, nodeID string) (tx, rx uint64, err error) {
	return s.GetSummary(userID, nodeID)
}

// Close closes the database connection.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}
