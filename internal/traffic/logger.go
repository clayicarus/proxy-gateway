package traffic

import (
	"sync"
	"sync/atomic"
	"time"

	hyServer "github.com/apernet/hysteria/core/v2/server"
	"github.com/hy2-gateway/internal/auth"
	"github.com/hy2-gateway/internal/config"
	"github.com/hy2-gateway/internal/storage"
	"go.uber.org/zap"
)

// Compile-time check that TrafficLogger implements server.TrafficLogger.
var _ hyServer.TrafficLogger = (*TrafficLogger)(nil)

// UserNodeStats holds traffic statistics for a single (user, node) pair.
type UserNodeStats struct {
	// Cumulative bytes (in-memory, includes persisted base)
	TxBytes atomic.Uint64
	RxBytes atomic.Uint64
	// Delta since last flush (for periodic persistence)
	TxDelta atomic.Uint64
	RxDelta atomic.Uint64
	// Current online connections
	OnlineCount atomic.Int32
	// Quota (0 = unlimited) — this is the user-level quota
	MaxBytes uint64
	// Speed limit in bytes/sec (0 = unlimited)
	SpeedLimit uint64
	// Last activity
	LastActive atomic.Int64 // unix timestamp
}

// StatsSnapshot returns a point-in-time copy of the stats.
type StatsSnapshot struct {
	Username    string `json:"username"`
	Node        string `json:"node"`
	TxBytes     uint64 `json:"tx"`
	RxBytes     uint64 `json:"rx"`
	OnlineCount int32  `json:"online"`
	MaxBytes    uint64 `json:"maxBytes"`
	SpeedLimit  uint64 `json:"speedLimit"`
	LastActive  int64  `json:"lastActive"`
}

// TrafficLogger implements the Hysteria2 TrafficLogger interface
// and provides per-(user, node) traffic accounting with quota enforcement
// and periodic SQLite persistence.
//
// The id passed to LogTraffic is "username:node_name" as returned by Authenticator.
type TrafficLogger struct {
	stats  sync.Map // map[string]*UserNodeStats (id "user:node" -> stats)
	users  map[string]config.UserConfig
	mu     sync.RWMutex
	store  *storage.SQLiteStore
	logger *zap.Logger

	tracedStreams sync.Map // map[quic.StreamID]*server.StreamStats

	stopCh chan struct{}
}

// NewTrafficLogger creates a new TrafficLogger.
// If store is nil, traffic is only tracked in memory.
func NewTrafficLogger(users map[string]config.UserConfig, store *storage.SQLiteStore, logger *zap.Logger) *TrafficLogger {
	tl := &TrafficLogger{
		users:  users,
		store:  store,
		logger: logger,
		stopCh: make(chan struct{}),
	}
	// Pre-populate stats for known (user, node) pairs, loading persisted totals
	for name, u := range users {
		for _, route := range u.Routes {
			id := name + ":" + route
			s := &UserNodeStats{
				MaxBytes:   u.MaxBytes,
				SpeedLimit: u.SpeedLimit,
			}
			if store != nil {
				tx, rx, err := store.LoadSummaryForUserNode(name, route)
				if err != nil {
					logger.Warn("failed to load persisted traffic",
						zap.String("user", name),
						zap.String("node", route),
						zap.Error(err))
				} else {
					s.TxBytes.Store(tx)
					s.RxBytes.Store(rx)
				}
			}
			tl.stats.Store(id, s)
		}
	}
	return tl
}

// StartPeriodicFlush starts a goroutine that flushes traffic deltas
// to SQLite at the given interval.
func (tl *TrafficLogger) StartPeriodicFlush(interval time.Duration) {
	if tl.store == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				tl.Flush()
			case <-tl.stopCh:
				tl.Flush() // final flush on shutdown
				return
			}
		}
	}()
}

// Stop signals the periodic flush goroutine to stop and does a final flush.
func (tl *TrafficLogger) Stop() {
	close(tl.stopCh)
}

// Flush writes accumulated deltas to SQLite and resets them.
func (tl *TrafficLogger) Flush() {
	if tl.store == nil {
		return
	}

	var records []storage.TrafficRecord
	now := time.Now()

	tl.stats.Range(func(key, value any) bool {
		id := key.(string)
		stats := value.(*UserNodeStats)
		tx := stats.TxDelta.Swap(0)
		rx := stats.RxDelta.Swap(0)
		if tx > 0 || rx > 0 {
			username, nodeName := auth.ParseID(id)
			records = append(records, storage.TrafficRecord{
				UserID:    username,
				NodeID:    nodeName,
				TxBytes:   tx,
				RxBytes:   rx,
				Timestamp: now,
			})
		}
		return true
	})

	if len(records) == 0 {
		return
	}

	if err := tl.store.FlushTraffic(records); err != nil {
		tl.logger.Error("failed to flush traffic to sqlite", zap.Error(err))
	} else {
		tl.logger.Debug("flushed traffic to sqlite", zap.Int("records", len(records)))
	}
}

// LogTraffic implements server.TrafficLogger.
// id is "username:node_name".
// Returns false to disconnect the user (e.g., quota exceeded).
func (tl *TrafficLogger) LogTraffic(id string, tx, rx uint64) bool {
	stats := tl.getOrCreate(id)
	stats.TxBytes.Add(tx)
	stats.RxBytes.Add(rx)
	stats.TxDelta.Add(tx)
	stats.RxDelta.Add(rx)
	stats.LastActive.Store(time.Now().Unix())

	// Check quota — aggregate across all nodes for this user
	if stats.MaxBytes > 0 {
		username, _ := auth.ParseID(id)
		totalAllNodes := tl.getUserTotalTraffic(username)
		if totalAllNodes > stats.MaxBytes {
			tl.logger.Warn("user quota exceeded, disconnecting",
				zap.String("id", id),
				zap.Uint64("total", totalAllNodes),
				zap.Uint64("maxBytes", stats.MaxBytes),
			)
			return false
		}
	}

	return true
}

// getUserTotalTraffic sums tx+rx across all nodes for a given username.
func (tl *TrafficLogger) getUserTotalTraffic(username string) uint64 {
	var total uint64
	tl.stats.Range(func(key, value any) bool {
		id := key.(string)
		u, _ := auth.ParseID(id)
		if u == username {
			stats := value.(*UserNodeStats)
			total += stats.TxBytes.Load() + stats.RxBytes.Load()
		}
		return true
	})
	return total
}

// LogOnlineState implements server.TrafficLogger.
func (tl *TrafficLogger) LogOnlineState(id string, online bool) {
	stats := tl.getOrCreate(id)
	if online {
		stats.OnlineCount.Add(1)
	} else {
		stats.OnlineCount.Add(-1)
	}
	tl.logger.Debug("online state changed",
		zap.String("id", id),
		zap.Bool("online", online),
		zap.Int32("count", stats.OnlineCount.Load()),
	)
}

// GetSnapshot returns a snapshot of a (user, node) pair's stats.
func (tl *TrafficLogger) GetSnapshot(id string) *StatsSnapshot {
	val, ok := tl.stats.Load(id)
	if !ok {
		return nil
	}
	stats := val.(*UserNodeStats)
	username, nodeName := auth.ParseID(id)
	return &StatsSnapshot{
		Username:    username,
		Node:        nodeName,
		TxBytes:     stats.TxBytes.Load(),
		RxBytes:     stats.RxBytes.Load(),
		OnlineCount: stats.OnlineCount.Load(),
		MaxBytes:    stats.MaxBytes,
		SpeedLimit:  stats.SpeedLimit,
		LastActive:  stats.LastActive.Load(),
	}
}

// GetAllSnapshots returns snapshots for all (user, node) pairs.
func (tl *TrafficLogger) GetAllSnapshots() map[string]*StatsSnapshot {
	result := make(map[string]*StatsSnapshot)
	tl.stats.Range(func(key, value any) bool {
		id := key.(string)
		stats := value.(*UserNodeStats)
		username, nodeName := auth.ParseID(id)
		result[id] = &StatsSnapshot{
			Username:    username,
			Node:        nodeName,
			TxBytes:     stats.TxBytes.Load(),
			RxBytes:     stats.RxBytes.Load(),
			OnlineCount: stats.OnlineCount.Load(),
			MaxBytes:    stats.MaxBytes,
			SpeedLimit:  stats.SpeedLimit,
			LastActive:  stats.LastActive.Load(),
		}
		return true
	})
	return result
}

// ResetStats resets traffic counters for a specific id (in-memory only).
func (tl *TrafficLogger) ResetStats(id string) {
	val, ok := tl.stats.Load(id)
	if !ok {
		return
	}
	stats := val.(*UserNodeStats)
	stats.TxBytes.Store(0)
	stats.RxBytes.Store(0)
}

// ResetAllStats resets traffic counters for all entries (in-memory only).
func (tl *TrafficLogger) ResetAllStats() {
	tl.stats.Range(func(key, value any) bool {
		stats := value.(*UserNodeStats)
		stats.TxBytes.Store(0)
		stats.RxBytes.Store(0)
		return true
	})
}

func (tl *TrafficLogger) getOrCreate(id string) *UserNodeStats {
	val, ok := tl.stats.Load(id)
	if ok {
		return val.(*UserNodeStats)
	}

	username, _ := auth.ParseID(id)
	tl.mu.RLock()
	u, exists := tl.users[username]
	tl.mu.RUnlock()

	newStats := &UserNodeStats{}
	if exists {
		newStats.MaxBytes = u.MaxBytes
		newStats.SpeedLimit = u.SpeedLimit
	}

	actual, _ := tl.stats.LoadOrStore(id, newStats)
	return actual.(*UserNodeStats)
}

// TraceStream implements server.TrafficLogger.
func (tl *TrafficLogger) TraceStream(stream hyServer.HyStream, stats *hyServer.StreamStats) {
	tl.tracedStreams.Store(stream.StreamID(), stats)
}

// UntraceStream implements server.TrafficLogger.
func (tl *TrafficLogger) UntraceStream(stream hyServer.HyStream) {
	tl.tracedStreams.Delete(stream.StreamID())
}
