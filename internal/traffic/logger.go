package traffic

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	hyServer "github.com/apernet/hysteria/core/v2/server"
	"github.com/clayicarus/proxy-gateway/internal/auth"
	"github.com/clayicarus/proxy-gateway/internal/config"
	"github.com/clayicarus/proxy-gateway/internal/storage"
	"go.uber.org/zap"
)

// Compile-time check that TrafficLogger implements server.TrafficLogger.
var _ hyServer.TrafficLogger = (*TrafficLogger)(nil)

// UserNodeStats holds traffic statistics for a single (user, node) pair.
type UserNodeStats struct {
	// Cumulative bytes (in-memory, includes persisted base)
	TxBytes atomic.Uint64
	RxBytes atomic.Uint64
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
	shutdownCh   chan struct{}
	shutdownOnce sync.Once
	flushDone    chan struct{}
	flushStarted atomic.Bool
	flushMu      sync.Mutex

	location     *time.Location
	now          func() time.Time
	monthKey     string
	monthlyUsage map[string]uint64                       // persisted current-month base plus in-memory deltas
	pending      map[trafficPeriod]storage.TrafficRecord // guarded by usageMu
	usageMu      sync.Mutex
	limiters     map[string]*downloadLimiter
	limiterMu    sync.Mutex
}

// Keep unflushed traffic in its accounting month, including when a failed
// transaction is retried after the month boundary.
type trafficPeriod struct {
	id    string
	month string
}

// downloadLimiter paces all download chunks for one user through a single
// reservation timeline. The first chunk can proceed immediately; subsequent
// chunks across all streams share the configured aggregate rate.
type downloadLimiter struct {
	mu      sync.Mutex
	next    time.Time
	changed chan struct{}
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
		shutdownCh:   make(chan struct{}),
		flushDone:    make(chan struct{}),
		location:     location,
		now:          time.Now,
		monthlyUsage: make(map[string]uint64),
		pending:      make(map[trafficPeriod]storage.TrafficRecord),
		limiters:     make(map[string]*downloadLimiter),
	}
	tl.loadMonthlyUsageLocked(tl.now())
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

// The caller holds usageMu and flushMu (or has not published the logger yet).
// Serializing a month reload with Flush avoids counting an in-flight batch
// twice, including if the wall clock moves back to a previously used month.
func (tl *TrafficLogger) loadMonthlyUsageLocked(now time.Time) bool {
	key, start, end := tl.monthBounds(now)
	if tl.monthKey == key {
		return true
	}
	total := make(map[string][2]uint64)
	if tl.store != nil {
		loaded, err := tl.store.GetUserMonthlyUsage(start, end)
		if err != nil {
			tl.logger.Warn("failed to load current month traffic", zap.Error(err))
			return false
		}
		total = loaded
	}
	tl.monthKey = key
	tl.monthlyUsage = make(map[string]uint64, len(total))
	for username, value := range total {
		tl.monthlyUsage[username] = value[0] + value[1]
	}
	for period, record := range tl.pending {
		if period.month == key {
			tl.monthlyUsage[record.UserID] += record.TxBytes + record.RxBytes
		}
	}
	return true
}

// StartPeriodicFlush starts a goroutine that flushes traffic deltas
// to SQLite at the given interval.
func (tl *TrafficLogger) StartPeriodicFlush(interval time.Duration) {
	if tl.store == nil || !tl.flushStarted.CompareAndSwap(false, true) {
		return
	}
	if interval <= 0 {
		interval = 10 * time.Second
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
	tl.BeginShutdown()
	tl.stopOnce.Do(func() { close(tl.stopCh) })
	if tl.flushStarted.Load() {
		<-tl.flushDone
		return
	}
	tl.Flush()
}

// BeginShutdown rejects new traffic and cancels pending download-limit waits
// without stopping persistence. Servers can therefore drain and close before
// Stop performs the final SQLite flush.
func (tl *TrafficLogger) BeginShutdown() {
	tl.shutdownOnce.Do(func() { close(tl.shutdownCh) })
}

// Flush writes accumulated deltas to SQLite and resets them.
func (tl *TrafficLogger) Flush() {
	if tl.store == nil {
		return
	}
	tl.flushMu.Lock()
	defer tl.flushMu.Unlock()

	tl.usageMu.Lock()
	batch := tl.pending
	tl.pending = make(map[trafficPeriod]storage.TrafficRecord)
	tl.usageMu.Unlock()
	if len(batch) == 0 {
		return
	}
	records := make([]storage.TrafficRecord, 0, len(batch))
	for _, record := range batch {
		records = append(records, record)
	}

	if err := tl.store.FlushTraffic(records); err != nil {
		// FlushTraffic is transactional, so none of this batch was persisted.
		// Restore the deltas alongside traffic accumulated during the failed write;
		// the next periodic flush will retry the complete amount.
		tl.usageMu.Lock()
		for period, record := range batch {
			if current, ok := tl.pending[period]; ok {
				record.TxBytes += current.TxBytes
				record.RxBytes += current.RxBytes
				if current.Timestamp.After(record.Timestamp) {
					record.Timestamp = current.Timestamp
				}
			}
			tl.pending[period] = record
		}
		tl.usageMu.Unlock()
		tl.logger.Error("failed to flush traffic to sqlite", zap.Error(err))
	} else {
		tl.logger.Debug("flushed traffic to sqlite", zap.Int("records", len(records)))
	}
}

// LogTraffic implements server.TrafficLogger.
// id is "username:node_name".
// Returns false to disconnect the user (e.g., quota exceeded).
func (tl *TrafficLogger) LogTraffic(id string, tx, rx uint64) bool {
	return tl.LogTrafficContext(context.Background(), id, tx, rx)
}

// LogTrafficContext also cancels a pending download reservation when an
// individual relay closes. Hysteria2 retains its upstream LogTraffic API.
func (tl *TrafficLogger) LogTrafficContext(ctx context.Context, id string, tx, rx uint64) bool {
	select {
	case <-tl.shutdownCh:
		return false
	case <-ctx.Done():
		return false
	default:
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

	if rx > 0 && !tl.limitDownload(ctx, username, rx) {
		return false
	}

	// Check the calendar-month quota across all nodes. The same mutex makes
	// concurrent streams observe one shared value and the same period as the
	// persistence record. A failed quota reload must never grant free traffic.
	total, maxBytes, ok := tl.recordTraffic(id, tx, rx)
	if !ok {
		return false
	}
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

func (tl *TrafficLogger) recordTraffic(id string, tx, rx uint64) (uint64, uint64, bool) {
	tl.usageMu.Lock()
	now := tl.now()
	key, _, _ := tl.monthBounds(now)
	if tl.monthKey != key {
		// Normal traffic does not wait for SQLite writes. Only a period change
		// must wait for an in-flight flush before reloading its persisted base.
		tl.usageMu.Unlock()
		tl.flushMu.Lock()
		defer tl.flushMu.Unlock()
		tl.usageMu.Lock()
		now = tl.now()
		if !tl.loadMonthlyUsageLocked(now) {
			tl.usageMu.Unlock()
			return 0, 0, false
		}
	}
	defer tl.usageMu.Unlock()

	select {
	case <-tl.shutdownCh:
		return 0, 0, false
	default:
	}
	username, node := auth.ParseID(id)
	// Policy may have changed while this chunk waited for its download slot.
	tl.mu.RLock()
	user, exists := tl.users[username]
	tl.mu.RUnlock()
	if !exists || user.Disabled || (user.ExpiresAt != nil && !user.ExpiresAt.After(now)) {
		return 0, 0, false
	}
	stats := tl.getOrCreate(id)
	stats.TxBytes.Add(tx)
	stats.RxBytes.Add(rx)
	stats.LastActive.Store(now.Unix())
	tl.monthlyUsage[username] += tx + rx
	if tl.store != nil && (tx > 0 || rx > 0) {
		period := trafficPeriod{id: id, month: tl.monthKey}
		record := tl.pending[period]
		record.UserID, record.NodeID = username, node
		record.TxBytes += tx
		record.RxBytes += rx
		record.Timestamp = now
		tl.pending[period] = record
	}
	return tl.monthlyUsage[username], user.MaxBytes, true
}

func (tl *TrafficLogger) limitDownload(ctx context.Context, username string, bytes uint64) bool {
	for {
		tl.mu.RLock()
		user, exists := tl.users[username]
		if !exists || user.Disabled || (user.ExpiresAt != nil && !user.ExpiresAt.After(tl.now())) {
			tl.mu.RUnlock()
			return false
		}
		if user.SpeedLimit == 0 {
			tl.mu.RUnlock()
			return ctx.Err() == nil
		}
		tl.limiterMu.Lock()
		limiter := tl.limiters[username]
		if limiter == nil {
			limiter = &downloadLimiter{changed: make(chan struct{})}
			tl.limiters[username] = limiter
		}
		tl.limiterMu.Unlock()
		limiter.mu.Lock()
		now := time.Now()
		if limiter.next.Before(now) {
			limiter.next = now
		}
		waitUntil := limiter.next
		seconds := float64(bytes) / float64(user.SpeedLimit)
		limiter.next = limiter.next.Add(time.Duration(seconds * float64(time.Second)))
		reservationEnd := limiter.next
		changed := limiter.changed
		limiter.mu.Unlock()
		tl.mu.RUnlock()

		wait := time.Until(waitUntil)
		if user.ExpiresAt != nil {
			if remaining := user.ExpiresAt.Sub(tl.now()); remaining < wait {
				wait = remaining
			}
		}
		timer := time.NewTimer(wait)
		accepted, retry := false, false
		select {
		case <-timer.C:
			accepted = ctx.Err() == nil // recordTraffic rechecks lifecycle state.
		case <-changed:
			retry = true
		case <-tl.shutdownCh:
		case <-ctx.Done():
		}
		timer.Stop()
		if !accepted {
			// Refund a cancelled tail reservation. Earlier reservations cannot
			// move an already waiting stream's deadline.
			limiter.mu.Lock()
			if limiter.changed == changed && limiter.next.Equal(reservationEnd) {
				limiter.next = waitUntil
			}
			limiter.mu.Unlock()
		}
		if !retry {
			return accepted
		}
	}
}

// UpdateUsers replaces runtime user state without changing the static node
// snapshot. It is used for password, expiry, deletion, quota and speed-limit
// changes that must affect new and existing connections immediately.
func (tl *TrafficLogger) UpdateUsers(users map[string]config.UserConfig) {
	tl.mu.Lock()
	tl.limiterMu.Lock()
	for username, limiter := range tl.limiters {
		previous, wasPresent := tl.users[username]
		updated, isPresent := users[username]
		sameExpiry := previous.ExpiresAt == nil && updated.ExpiresAt == nil ||
			previous.ExpiresAt != nil && updated.ExpiresAt != nil && previous.ExpiresAt.Equal(*updated.ExpiresAt)
		if wasPresent == isPresent && previous.SpeedLimit == updated.SpeedLimit &&
			previous.Disabled == updated.Disabled && previous.MaxBytes == updated.MaxBytes && sameExpiry {
			continue
		}
		limiter.mu.Lock()
		limiter.next = time.Time{}
		close(limiter.changed)
		limiter.changed = make(chan struct{})
		limiter.mu.Unlock()
	}
	tl.users = copyUsers(users)
	tl.limiterMu.Unlock()
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
