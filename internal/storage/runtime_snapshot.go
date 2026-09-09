package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/clayicarus/proxy-gateway/internal/config"
)

// LoadRuntimeSnapshot reads users, authorizations, enabled nodes and the
// topology revision from one consistent read-only SQLite view.
func (s *SQLiteStore) LoadRuntimeSnapshot(ctx context.Context) (*RuntimeSnapshot, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	users := make(map[string]config.UserConfig)
	rows, err := tx.QueryContext(ctx, `SELECT username, password, deleted_at, expires_at, monthly_bytes, download_speed FROM managed_users`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var username, password string
		var deletedAt, expiresAt sql.NullInt64
		var maxBytes, speed uint64
		if err := rows.Scan(&username, &password, &deletedAt, &expiresAt, &maxBytes, &speed); err != nil {
			rows.Close()
			return nil, err
		}
		user := config.UserConfig{Password: password, MaxBytes: maxBytes, SpeedLimit: speed}
		if deletedAt.Valid {
			user.Disabled = true
		}
		if expiresAt.Valid {
			user.ExpiresAt = unixTime(expiresAt.Int64)
		}
		users[username] = user
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}

	routes, err := tx.QueryContext(ctx, `SELECT username, node_name FROM user_nodes ORDER BY username, node_name`)
	if err != nil {
		return nil, err
	}
	for routes.Next() {
		var username, node string
		if err := routes.Scan(&username, &node); err != nil {
			routes.Close()
			return nil, err
		}
		if user, ok := users[username]; ok {
			user.Routes = append(user.Routes, node)
			users[username] = user
		}
	}
	if err := routes.Err(); err != nil {
		routes.Close()
		return nil, err
	}
	if err := routes.Close(); err != nil {
		return nil, err
	}

	nodes := make(map[string]config.NodeConfig)
	nodeRows, err := tx.QueryContext(ctx, `SELECT name, config_json FROM managed_nodes WHERE enabled = 1 ORDER BY name`)
	if err != nil {
		return nil, err
	}
	for nodeRows.Next() {
		var name, raw string
		if err := nodeRows.Scan(&name, &raw); err != nil {
			nodeRows.Close()
			return nil, err
		}
		var node config.NodeConfig
		if err := json.Unmarshal([]byte(raw), &node); err != nil {
			nodeRows.Close()
			return nil, fmt.Errorf("decode node %q: %w", name, err)
		}
		if err := validateNode(name, node); err != nil {
			nodeRows.Close()
			return nil, fmt.Errorf("load node: %w", err)
		}
		nodes[name] = node
	}
	if err := nodeRows.Err(); err != nil {
		nodeRows.Close()
		return nil, err
	}
	if err := nodeRows.Close(); err != nil {
		return nil, err
	}

	var revision int64
	if err := tx.QueryRowContext(ctx, `SELECT revision FROM config_state WHERE id = 1`).Scan(&revision); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &RuntimeSnapshot{Users: users, Nodes: nodes, Revision: revision}, nil
}
