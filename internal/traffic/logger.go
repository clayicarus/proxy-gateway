package traffic

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/clayicarus/proxy-gateway/internal/auth"
	"github.com/clayicarus/proxy-gateway/internal/config"
	"github.com/clayicarus/proxy-gateway/internal/storage"
	"go.uber.org/zap"
)

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

// TrafficLogger provides protocol-neutral per-(user, node) traffic accounting
// with quota enforcement and periodic SQLite persistence.
//
// The id passed to LogTraffic is "username:node_name" as returned by Authenticator.
type TrafficLogger struct {
	stats  sync.Map // map[string]*UserNodeStats (id "user:node" -> stats)
	users  map[string]config.UserConfig
	mu     sync.RWMutex
	store  *storage.SQLiteStore
	logger *zap.Logger
	now    func() time.Time

	stopCh       chan struct{}
	stopOnce     sync.Once
	flushDone    chan struct{}
	flushStarted atomic.Bool
	flushMu      sync.Mutex
	lastFlushErr error

	location     *time.Location
	monthKey     string
	monthlyUsage map[string]uint64 // persisted current-month base plus in-memory deltas
	usageMu      sync.Mutex
	pending      map[pendingKey]storage.TrafficRecord
	stopping     atomic.Bool
	limiters     map[string]*downloadLimiter
	limiterMu    sync.Mutex
}

// downloadLimiter paces all download chunks for one user through a single
// reservation timeline. It intentionally has no burst: multiple streams
// therefore share the configured aggregate rate.
type downloadLimiter struct {
	mu     sync.Mutex
	next   time.Time
	notify chan struct{}
}

type pendingKey struct {
	id    string
	month string
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
		now:          time.Now,
		stopCh:       make(chan struct{}),
		flushDone:    make(chan struct{}),
		location:     location,
		monthlyUsage: make(map[string]uint64),
		pending:      make(map[pendingKey]storage.TrafficRecord),
		limiters:     make(map[string]*downloadLimiter),
	}
	_ = tl.ensureMonthlyUsage(context.Background(), tl.now())
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

func (tl *TrafficLogger) ensureMonthlyUsage(ctx context.Context, now time.Time) error {
	key, start, end := tl.monthBounds(now)
	tl.usageMu.Lock()
	if tl.monthKey == key {
		tl.usageMu.Unlock()
		return nil
	}
	tl.usageMu.Unlock()

	// Serialize the baseline read with an in-flight flush so persisted data and
	// detached pending data cannot both be counted as the baseline.
	tl.flushMu.Lock()
	defer tl.flushMu.Unlock()
	tl.usageMu.Lock()
	if tl.monthKey == key {
		tl.usageMu.Unlock()
		return nil
	}
	tl.usageMu.Unlock()
	total := make(map[string][2]uint64)
	if tl.store != nil {
		loaded, err := tl.store.GetUserMonthlyUsageContext(ctx, start, end)
		if err != nil {
			tl.logger.Warn("failed to load current month traffic", zap.Error(err))
			return err
		}
		total = loaded
	}
	tl.usageMu.Lock()
	defer tl.usageMu.Unlock()
	tl.monthKey = key
	tl.monthlyUsage = make(map[string]uint64, len(total))
	for username, value := range total {
		tl.monthlyUsage[username] = value[0] + value[1]
	}
	for pendingKey, record := range tl.pending {
		if pendingKey.month == key {
			tl.monthlyUsage[record.UserID] += record.TxBytes + record.RxBytes
		}
	}
	return nil
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
				_ = tl.FlushContext(context.Background())
			case <-tl.stopCh:
				return
			}
		}
	}()
}

// Stop signals the periodic flush goroutine to stop and does a final flush.
func (tl *TrafficLogger) Stop() {
	_ = tl.StopContext(context.Background())
}

func (tl *TrafficLogger) StopAdmission() {
	tl.stopping.Store(true)
	tl.wakeLimiters()
}

func (tl *TrafficLogger) StopContext(ctx context.Context) error {
	tl.StopAdmission()
	tl.stopOnce.Do(func() { close(tl.stopCh) })
	if tl.flushStarted.Load() {
		select {
		case <-tl.flushDone:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return tl.FlushContext(ctx)
}

// Flush writes accumulated deltas to SQLite and resets them.
func (tl *TrafficLogger) Flush() {
	_ = tl.FlushContext(context.Background())
}

func (tl *TrafficLogger) FlushContext(ctx context.Context) error {
	if tl.store == nil {
		return nil
	}
	tl.flushMu.Lock()
	defer tl.flushMu.Unlock()

	tl.usageMu.Lock()
	batch := tl.pending
	tl.pending = make(map[pendingKey]storage.TrafficRecord)
	for _, record := range batch {
		stats := tl.getOrCreate(record.UserID + ":" + record.NodeID)
		stats.TxDelta.Add(^(record.TxBytes - 1))
		stats.RxDelta.Add(^(record.RxBytes - 1))
	}
	tl.usageMu.Unlock()
	records := make([]storage.TrafficRecord, 0, len(batch))
	for _, record := range batch {
		records = append(records, record)
	}

	if len(records) == 0 {
		return nil
	}

	if err := tl.store.FlushTrafficContext(ctx, records); err != nil {
		// FlushTraffic is transactional, so none of this batch was persisted.
		// Restore the deltas alongside traffic accumulated during the failed write;
		// the next periodic flush will retry the complete amount.
		tl.usageMu.Lock()
		for key, record := range batch {
			current := tl.pending[key]
			current.UserID, current.NodeID = record.UserID, record.NodeID
			current.TxBytes += record.TxBytes
			current.RxBytes += record.RxBytes
			if current.Timestamp.Before(record.Timestamp) {
				current.Timestamp = record.Timestamp
			}
			tl.pending[key] = current
			stats := tl.getOrCreate(record.UserID + ":" + record.NodeID)
			stats.TxDelta.Add(record.TxBytes)
			stats.RxDelta.Add(record.RxBytes)
		}
		tl.usageMu.Unlock()
		tl.logger.Error("failed to flush traffic to sqlite", zap.Error(err))
		tl.lastFlushErr = err
		return err
	} else {
		tl.logger.Debug("flushed traffic to sqlite", zap.Int("records", len(records)))
	}
	tl.lastFlushErr = nil
	return nil
}

// LogTraffic implements server.TrafficLogger.
// id is "username:node_name".
// Returns false to disconnect the user (e.g., quota exceeded).
func (tl *TrafficLogger) LogTraffic(id string, tx, rx uint64) bool {
	return tl.LogTrafficContext(context.Background(), id, tx, rx)
}

func (tl *TrafficLogger) LogTrafficContext(ctx context.Context, id string, tx, rx uint64) bool {
	if tl.stopping.Load() || ctx.Err() != nil {
		return false
	}
	username, _ := auth.ParseID(id)
	tl.mu.RLock()
	user, exists := tl.users[username]
	reason := ""
	switch {
	case !exists:
		reason = "unknown_user"
	case user.Disabled:
		reason = "disabled"
	case user.ExpiresAt != nil && !user.ExpiresAt.After(tl.now()):
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
		if err := tl.limitDownloadContext(ctx, username, rx); err != nil {
			return false
		}
	}
	if tl.stopping.Load() || ctx.Err() != nil {
		return false
	}
	now := tl.now()
	if err := tl.ensureMonthlyUsage(ctx, now); err != nil {
		return false
	}
	key, _, _ := tl.monthBounds(now)
	tl.usageMu.Lock()
	if tl.stopping.Load() || ctx.Err() != nil || tl.monthKey != key {
		tl.usageMu.Unlock()
		return false
	}
	stats.TxBytes.Add(tx)
	stats.RxBytes.Add(rx)
	stats.TxDelta.Add(tx)
	stats.RxDelta.Add(rx)
	stats.LastActive.Store(now.Unix())
	username, nodeName := auth.ParseID(id)
	pendingKey := pendingKey{id: id, month: key}
	record := tl.pending[pendingKey]
	record.UserID, record.NodeID = username, nodeName
	record.TxBytes += tx
	record.RxBytes += rx
	if record.Timestamp.Before(now) {
		record.Timestamp = now
	}
	tl.pending[pendingKey] = record

	// Check the calendar-month quota across all nodes. The same mutex makes
	// concurrent streams observe a single shared accounting value.
	tl.monthlyUsage[username] += tx + rx
	total := tl.monthlyUsage[username]
	tl.mu.RLock()
	maxBytes := tl.users[username].MaxBytes
	tl.mu.RUnlock()
	tl.usageMu.Unlock()
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

func (tl *TrafficLogger) limitDownload(username string, bytes uint64) {
	_ = tl.limitDownloadContext(context.Background(), username, bytes)
}

func (tl *TrafficLogger) limitDownloadContext(ctx context.Context, username string, bytes uint64) error {
	for {
		tl.mu.RLock()
		rate := tl.users[username].SpeedLimit
		tl.mu.RUnlock()
		if rate == 0 {
			return nil
		}
		tl.limiterMu.Lock()
		limiter := tl.limiters[username]
		if limiter == nil {
			limiter = &downloadLimiter{notify: make(chan struct{})}
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
		end := limiter.next.Add(time.Duration(seconds * float64(time.Second)))
		limiter.next = end
		notify := limiter.notify
		limiter.mu.Unlock()
		if wait := time.Until(waitUntil); wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-timer.C:
				return nil
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				tl.cancelReservation(limiter, end, waitUntil)
				return ctx.Err()
			case <-notify:
				if !timer.Stop() {
					<-timer.C
				}
				tl.cancelReservation(limiter, end, waitUntil)
				continue
			}
		}
		return nil
	}
}

func (tl *TrafficLogger) cancelReservation(limiter *downloadLimiter, end, start time.Time) {
	limiter.mu.Lock()
	if limiter.next.Equal(end) {
		limiter.next = start
	}
	limiter.mu.Unlock()
}

func (tl *TrafficLogger) wakeLimiters() {
	tl.limiterMu.Lock()
	for _, limiter := range tl.limiters {
		limiter.mu.Lock()
		close(limiter.notify)
		limiter.notify = make(chan struct{})
		limiter.next = time.Time{}
		limiter.mu.Unlock()
	}
	tl.limiterMu.Unlock()
}

// UpdateUsers replaces runtime user state without changing the static node
// snapshot. It is used for password, expiry, deletion, quota and speed-limit
// changes that must affect new and existing connections immediately.
func (tl *TrafficLogger) UpdateUsers(users map[string]config.UserConfig) {
	tl.mu.Lock()
	changedRate := false
	for name, old := range tl.users {
		if current, ok := users[name]; !ok || current.SpeedLimit != old.SpeedLimit {
			changedRate = true
			break
		}
	}
	tl.users = copyUsers(users)
	tl.mu.Unlock()
	if changedRate {
		tl.wakeLimiters()
	}
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
