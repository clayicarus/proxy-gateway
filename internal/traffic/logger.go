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

	stopCh       chan struct{}
	stopOnce     sync.Once
	flushDone    chan struct{}
	flushStarted atomic.Bool

	location     *time.Location
	monthKey     string
	monthlyUsage map[string]uint64 // persisted current-month base plus in-memory deltas
	usageMu      sync.Mutex
	limiters     map[string]*downloadLimiter
	limiterMu    sync.Mutex
}

// downloadLimiter paces all download chunks for one user through a single
// reservation timeline. It intentionally has no burst: multiple streams
// therefore share the configured aggregate rate.
type downloadLimiter struct {
	mu   sync.Mutex
	next time.Time
}

// NewTrafficLogger creates a new TrafficLogger.
// If store is nil, traffic is only tracked in memory.
func NewTrafficLogger(users map[string]config.UserConfig, store *storage.SQLiteStore, logger *zap.Logger) *TrafficLogger {
	return NewTrafficLoggerWithLocation(users, store, logger, time.UTC)
}

// NewTrafficLoggerWithLocation creates a logger whose natural-month usage is
// evaluated in location. All persisted timestamps remain UTC.
func NewTrafficLoggerWithLocation(users map[string]config.UserConfig, store *storage.SQLiteStore, logger *zap.Logger, location *time.Location) *TrafficLogger {
	if location == nil {
		location = time.UTC
	}
	tl := &TrafficLogger{
		users:        copyUsers(users),
		store:        store,
		logger:       logger,
		stopCh:       make(chan struct{}),
		flushDone:    make(chan struct{}),
		location:     location,
		monthlyUsage: make(map[string]uint64),
		limiters:     make(map[string]*downloadLimiter),
	}
	tl.ensureMonthlyUsage(time.Now())
	// Pre-populate stats for known (user, node) pairs, loading persisted totals
	for name, u := range users {
		for _, route := range u.Routes {
			id := name + ":" + route
			s := &UserNodeStats{}
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

func copyUsers(users map[string]config.UserConfig) map[string]config.UserConfig {
	result := make(map[string]config.UserConfig, len(users))
	for name, user := range users {
		user.Routes = append([]string(nil), user.Routes...)
		result[name] = user
	}
	return result
}

func (tl *TrafficLogger) monthBounds(now time.Time) (key string, start, end time.Time) {
	local := now.In(tl.location)
	start = time.Date(local.Year(), local.Month(), 1, 0, 0, 0, 0, tl.location)
	end = start.AddDate(0, 1, 0)
	return start.Format("2006-01"), start.UTC(), end.UTC()
}

func (tl *TrafficLogger) ensureMonthlyUsage(now time.Time) {
	key, start, end := tl.monthBounds(now)
	tl.usageMu.Lock()
	defer tl.usageMu.Unlock()
	if tl.monthKey == key {
		return
	}
	total := make(map[string][2]uint64)
	if tl.store != nil {
		loaded, err := tl.store.GetUserMonthlyUsage(start, end)
		if err != nil {
			tl.logger.Warn("failed to load current month traffic", zap.Error(err))
		} else {
			total = loaded
		}
	}
	tl.monthKey = key
	tl.monthlyUsage = make(map[string]uint64, len(total))
	for username, value := range total {
		tl.monthlyUsage[username] = value[0] + value[1]
	}
}

// StartPeriodicFlush starts a goroutine that flushes traffic deltas
// to SQLite at the given interval.
func (tl *TrafficLogger) StartPeriodicFlush(interval time.Duration) {
	if tl.store == nil || !tl.flushStarted.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer close(tl.flushDone)
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
	tl.stopOnce.Do(func() { close(tl.stopCh) })
	if tl.flushStarted.Load() {
		<-tl.flushDone
		return
	}
	tl.Flush()
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
	username, _ := auth.ParseID(id)
	tl.mu.RLock()
	user, exists := tl.users[username]
	reason := ""
	switch {
	case !exists:
		reason = "unknown_user"
	case user.Disabled:
		reason = "disabled"
	case user.ExpiresAt != nil && !user.ExpiresAt.After(time.Now()):
		reason = "expired"
	}
	tl.mu.RUnlock()
	if reason != "" {
		tl.logger.Warn("inactive user traffic, disconnecting",
			zap.String("id", id),
			zap.String("reason", reason),
		)
		return false
	}

	stats := tl.getOrCreate(id)
	if rx > 0 {
		tl.limitDownload(username, rx)
	}
	stats.TxBytes.Add(tx)
	stats.RxBytes.Add(rx)
	stats.TxDelta.Add(tx)
	stats.RxDelta.Add(rx)
	stats.LastActive.Store(time.Now().Unix())

	// Check the calendar-month quota across all nodes. The same mutex makes
	// concurrent streams observe a single shared accounting value.
	total, maxBytes := tl.addMonthlyUsage(username, tx+rx)
	if maxBytes > 0 && total > maxBytes {
		tl.logger.Warn("user quota exceeded, disconnecting",
			zap.String("id", id),
			zap.Uint64("total", total),
			zap.Uint64("maxBytes", maxBytes),
		)
		return false
	}

	return true
}

func (tl *TrafficLogger) addMonthlyUsage(username string, delta uint64) (uint64, uint64) {
	tl.ensureMonthlyUsage(time.Now())
	tl.usageMu.Lock()
	tl.monthlyUsage[username] += delta
	total := tl.monthlyUsage[username]
	tl.mu.RLock()
	maxBytes := tl.users[username].MaxBytes
	tl.mu.RUnlock()
	tl.usageMu.Unlock()
	return total, maxBytes
}

func (tl *TrafficLogger) limitDownload(username string, bytes uint64) {
	tl.mu.RLock()
	rate := tl.users[username].SpeedLimit
	tl.mu.RUnlock()
	if rate == 0 {
		return
	}
	tl.limiterMu.Lock()
	limiter := tl.limiters[username]
	if limiter == nil {
		limiter = &downloadLimiter{}
		tl.limiters[username] = limiter
	}
	tl.limiterMu.Unlock()

	limiter.mu.Lock()
	now := time.Now()
	if limiter.next.Before(now) {
		limiter.next = now
	}
	waitUntil := limiter.next
	seconds := float64(bytes) / float64(rate)
	limiter.next = limiter.next.Add(time.Duration(seconds * float64(time.Second)))
	limiter.mu.Unlock()
	if wait := time.Until(waitUntil); wait > 0 {
		time.Sleep(wait)
	}
}

// UpdateUsers replaces runtime user state without changing the static node
// snapshot. It is used for password, expiry, deletion, quota and speed-limit
// changes that must affect new and existing connections immediately.
func (tl *TrafficLogger) UpdateUsers(users map[string]config.UserConfig) {
	tl.mu.Lock()
	tl.users = copyUsers(users)
	tl.mu.Unlock()
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
	maxBytes, speedLimit := tl.userLimits(username)
	return &StatsSnapshot{
		Username:    username,
		Node:        nodeName,
		TxBytes:     stats.TxBytes.Load(),
		RxBytes:     stats.RxBytes.Load(),
		OnlineCount: stats.OnlineCount.Load(),
		MaxBytes:    maxBytes,
		SpeedLimit:  speedLimit,
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
		maxBytes, speedLimit := tl.userLimits(username)
		result[id] = &StatsSnapshot{
			Username:    username,
			Node:        nodeName,
			TxBytes:     stats.TxBytes.Load(),
			RxBytes:     stats.RxBytes.Load(),
			OnlineCount: stats.OnlineCount.Load(),
			MaxBytes:    maxBytes,
			SpeedLimit:  speedLimit,
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

	newStats := &UserNodeStats{}
	actual, _ := tl.stats.LoadOrStore(id, newStats)
	return actual.(*UserNodeStats)
}

func (tl *TrafficLogger) userLimits(username string) (maxBytes, speedLimit uint64) {
	tl.mu.RLock()
	user := tl.users[username]
	tl.mu.RUnlock()
	return user.MaxBytes, user.SpeedLimit
}

// TraceStream implements server.TrafficLogger.
func (tl *TrafficLogger) TraceStream(stream hyServer.HyStream, stats *hyServer.StreamStats) {
	tl.tracedStreams.Store(stream.StreamID(), stats)
}

// UntraceStream implements server.TrafficLogger.
func (tl *TrafficLogger) UntraceStream(stream hyServer.HyStream) {
	tl.tracedStreams.Delete(stream.StreamID())
}
