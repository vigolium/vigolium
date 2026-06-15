package ratelimit

import (
	"container/heap"
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sourcegraph/conc"
	"go.uber.org/zap"
)

// heapEntry tracks a host's last-used time for heap-based eviction.
type heapEntry struct {
	host     string
	lastUsed int64
	index    int
}

// hostHeap is a min-heap on lastUsed for O(log n) eviction.
type hostHeap []*heapEntry

func (h hostHeap) Len() int           { return len(h) }
func (h hostHeap) Less(i, j int) bool { return h[i].lastUsed < h[j].lastUsed }
func (h hostHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}
func (h *hostHeap) Push(x any) {
	entry := x.(*heapEntry)
	entry.index = len(*h)
	*h = append(*h, entry)
}
func (h *hostHeap) Pop() any {
	old := *h
	n := len(old)
	entry := old[n-1]
	old[n-1] = nil // avoid memory leak
	entry.index = -1
	*h = old[:n-1]
	return entry
}

const numShards = 32

// hostEntry holds the semaphore and metadata for a single host.
//
// Two concurrency primitives, picked at creation by the limiter's mode:
//   - Static mode uses sem, a fixed-capacity channel (acquire = send, release =
//     receive). This is the original lock-free hot path and is unchanged.
//   - Adaptive mode uses tokens, a resizable token pool (acquire = receive,
//     release = send-back), whose effective limit AIMD-adjusts from request
//     health. The pool channel is sized to the ramp ceiling; limit/inflight/debt
//     and the AIMD bookkeeping fields below are used only in this mode.
type hostEntry struct {
	sem      chan struct{} // static mode: fixed-cap semaphore (acquire = send)
	lastUsed atomic.Int64  // Unix nanos — updated atomically, no lock needed

	// Adaptive-mode fields (zero/unused in static mode).
	tokens   chan struct{} // resizable token pool (acquire = receive), cap = ceiling
	limit    atomic.Int64  // current allowed concurrency (available + inflight)
	inflight atomic.Int64  // checked-out tokens (for idle-eviction "active" check)
	debt     atomic.Int64  // tokens to drop on release (pending shrink)
	healthy  atomic.Int64  // consecutive healthy completions since last change
	lastDecr atomic.Int64  // unix nanos of last decrease (back-off cooldown)
	mu       sync.Mutex    // serializes setLimit; never held on the acquire hot path
}

func (e *hostEntry) touch() {
	e.lastUsed.Store(time.Now().UnixNano())
}

func (e *hostEntry) idleSince(d time.Duration) bool {
	return time.Since(time.Unix(0, e.lastUsed.Load())) > d
}

// hasInflight reports whether the entry has in-flight (acquired-not-released)
// requests, so the eviction loop won't reclaim a host mid-request. Static mode
// reads the semaphore length; adaptive mode reads the inflight counter.
func (e *hostEntry) hasInflight() bool {
	if e.tokens != nil {
		return e.inflight.Load() > 0
	}
	return len(e.sem) > 0
}

// hostShard is one bucket of the sharded host map.
type hostShard struct {
	mu           sync.RWMutex
	hosts        map[string]*hostEntry
	evictionHeap hostHeap
	heapIndex    map[string]*heapEntry
}

// HostRateLimiter limits concurrent requests per hostname.
// It uses per-host semaphores sharded across 32 buckets to reduce lock contention,
// and supports auto-eviction of idle hosts.
type HostRateLimiter struct {
	shards         [numShards]hostShard
	maxPerHost     int           // Max concurrent requests per host
	maxEntries     int           // Max tracked hosts before forced eviction
	evictAfter     time.Duration // Evict hosts idle for this duration
	acquireTimeout time.Duration // Max time to wait for a slot

	// Adaptive mode (off by default). When enabled, each host starts at
	// maxPerHost and AIMD-adjusts within [minPerHost, ceilingPerHost] from
	// per-request health fed back via Feedback: a distress signal (429/503/502/504,
	// connection error, timeout) halves the limit (bounded by a cooldown); a run of
	// healthy completions additively grows it back toward the ceiling.
	adaptive       bool
	minPerHost     int
	ceilingPerHost int

	stopEvict chan struct{}
	evictWg   conc.WaitGroup
}

// HostRateLimiterConfig configures the HostRateLimiter.
type HostRateLimiterConfig struct {
	MaxPerHost     int           // Max concurrent requests per host (default: 20)
	MaxEntries     int           // Max tracked hosts (default: 1000)
	EvictAfter     time.Duration // Evict idle hosts after (default: 30s)
	EvictInterval  time.Duration // How often to run eviction (default: 10s)
	AcquireTimeout time.Duration // Max time to wait for a slot (default: 30s)

	// Adaptive enables per-host AIMD concurrency control (default: false — the
	// static MaxPerHost semaphore). Each host still starts at MaxPerHost, so a
	// healthy scan behaves exactly like the static limiter; it only diverges by
	// backing off a host that returns distress signals and recovering afterwards.
	Adaptive bool
	// MinPerHost is the back-off floor in adaptive mode (default: max(1,
	// MaxPerHost/10)). Ignored when Adaptive is false.
	MinPerHost int
	// CeilingPerHost is the ramp ceiling in adaptive mode (default: MaxPerHost, so
	// adaptive never exceeds the configured concurrency). Set above MaxPerHost to
	// let healthy hosts ramp past it. Ignored when Adaptive is false.
	CeilingPerHost int
}

// DefaultHostRateLimiterConfig returns sensible defaults.
func DefaultHostRateLimiterConfig() HostRateLimiterConfig {
	return HostRateLimiterConfig{
		MaxPerHost:     20,
		MaxEntries:     1000,
		EvictAfter:     30 * time.Second,
		EvictInterval:  10 * time.Second,
		AcquireTimeout: 30 * time.Second,
	}
}

// NewHostRateLimiter creates a new HostRateLimiter with the given configuration.
func NewHostRateLimiter(cfg HostRateLimiterConfig) *HostRateLimiter {
	if cfg.MaxPerHost <= 0 {
		cfg.MaxPerHost = 20
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 1000
	}
	if cfg.EvictAfter <= 0 {
		cfg.EvictAfter = 30 * time.Second
	}
	if cfg.EvictInterval <= 0 {
		cfg.EvictInterval = 10 * time.Second
	}

	if cfg.AcquireTimeout <= 0 {
		cfg.AcquireTimeout = 30 * time.Second
	}

	// Adaptive bounds: floor defaults to a tenth of the start (min 1); ceiling
	// defaults to MaxPerHost so adaptive never exceeds the configured concurrency.
	minPerHost := cfg.MinPerHost
	if minPerHost <= 0 {
		minPerHost = max(cfg.MaxPerHost/10, 1)
	}
	minPerHost = min(minPerHost, cfg.MaxPerHost)
	ceilingPerHost := max(cfg.CeilingPerHost, cfg.MaxPerHost)

	h := &HostRateLimiter{
		maxPerHost:     cfg.MaxPerHost,
		maxEntries:     cfg.MaxEntries,
		evictAfter:     cfg.EvictAfter,
		acquireTimeout: cfg.AcquireTimeout,
		adaptive:       cfg.Adaptive,
		minPerHost:     minPerHost,
		ceilingPerHost: ceilingPerHost,
		stopEvict:      make(chan struct{}),
	}

	for i := range h.shards {
		h.shards[i].hosts = make(map[string]*hostEntry)
		h.shards[i].evictionHeap = make(hostHeap, 0)
		h.shards[i].heapIndex = make(map[string]*heapEntry)
	}

	// Start background eviction goroutine
	h.evictWg.Go(func() {
		h.evictionLoop(cfg.EvictInterval)
	})

	return h
}

// shardFor returns the shard responsible for the given host.
// Uses inline FNV-1a (32-bit) to avoid allocating a hash.Hash on every call.
func (h *HostRateLimiter) shardFor(host string) *hostShard {
	const (
		offset32 = 2166136261
		prime32  = 16777619
	)
	hash := uint32(offset32)
	for i := 0; i < len(host); i++ {
		hash ^= uint32(host[i])
		hash *= prime32
	}
	return &h.shards[hash%numShards]
}

// Acquire blocks until a slot is available for the given host.
// Returns context.Canceled/DeadlineExceeded if context is cancelled.
func (h *HostRateLimiter) Acquire(ctx context.Context, host string) error {
	shard := h.shardFor(host)
	entry := h.getOrCreateEntry(shard, host)

	// Adaptive mode: acquire a token from the resizable pool (receive). Same
	// lock-free hot path as the static send below, just the opposite channel
	// direction; the pool's current size is the effective per-host limit.
	if entry.tokens != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-entry.tokens:
			entry.inflight.Add(1)
			entry.touch()
			return nil
		}
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case entry.sem <- struct{}{}:
		// Record use for idle-eviction ordering via the atomic timestamp only —
		// no shard lock on the hot path. The eviction loop reconciles the heap
		// lazily: it reloads this atomic and re-fixes stale entries itself
		// (see evictIdle). Because touch() only ever moves lastUsed forward,
		// each heap entry's stored value is a lower bound on the real value, so
		// an up-to-date heap top is provably the globally-oldest host — eviction
		// stays correct without per-acquire heap maintenance. This keeps Acquire
		// lock-free in steady state, which matters most when a scan hammers a
		// single host and every request hashes to the same shard.
		entry.touch()
		return nil
	}
}

// AcquireWithTimeout blocks until a slot is available or the configured timeout expires.
// Returns context.DeadlineExceeded if the timeout is reached before a slot is available.
func (h *HostRateLimiter) AcquireWithTimeout(host string) error {
	ctx, cancel := context.WithTimeout(context.Background(), h.acquireTimeout)
	defer cancel()
	return h.Acquire(ctx, host)
}

// Release releases a slot for the given host.
// Must be called after Acquire to free the slot.
func (h *HostRateLimiter) Release(host string) {
	shard := h.shardFor(host)

	shard.mu.RLock()
	entry, exists := shard.hosts[host]
	shard.mu.RUnlock()

	if !exists {
		// Host was evicted while holding slot - this is fine
		return
	}

	// Adaptive mode: return the token unless the pool is shrinking, in which case
	// this token is retired against the outstanding debt (the limit decreased
	// while it was checked out, so it must not come back into circulation).
	if entry.tokens != nil {
		entry.inflight.Add(-1)
		for {
			d := entry.debt.Load()
			if d <= 0 {
				break
			}
			if entry.debt.CompareAndSwap(d, d-1) {
				return // token retired, not returned
			}
		}
		select {
		case entry.tokens <- struct{}{}:
		default:
			// Pool already at capacity — should not happen given the invariant
			// available+inflight == limit <= cap, but never block a release.
			zap.L().Warn("HostRateLimiter: adaptive token pool full on release", zap.String("host", host))
		}
		return
	}

	select {
	case <-entry.sem:
		// Released
	default:
		// Semaphore was empty - shouldn't happen but don't block
		zap.L().Warn("HostRateLimiter: Release called but semaphore was empty", zap.String("host", host))
	}
}

// getOrCreateEntry returns the entry for a host, creating it if needed.
// Uses double-check locking on the individual shard.
func (h *HostRateLimiter) getOrCreateEntry(shard *hostShard, host string) *hostEntry {
	shard.mu.RLock()
	entry, exists := shard.hosts[host]
	shard.mu.RUnlock()

	if exists {
		return entry
	}

	shard.mu.Lock()
	defer shard.mu.Unlock()

	// Double-check after acquiring write lock
	if entry, exists = shard.hosts[host]; exists {
		return entry
	}

	// If the limiter has been closed, Close() nils the shard maps. In-flight
	// scan goroutines can still reach this path when they outlive the runner's
	// shutdown (e.g. per-request workers spawned by a module), so hand them a
	// transient, immediately usable entry instead of panicking on a write to a
	// nil map. The entry isn't tracked — there's nothing left to track into.
	if shard.hosts == nil {
		return h.newEntry()
	}

	// Check if we need to evict (approximate: per-shard cap)
	if len(shard.hosts) >= h.maxEntries/numShards {
		h.evictOldestFromShard(shard)
	}

	now := time.Now().UnixNano()
	entry = h.newEntry()
	entry.lastUsed.Store(now)
	shard.hosts[host] = entry

	he := &heapEntry{host: host, lastUsed: now}
	heap.Push(&shard.evictionHeap, he)
	shard.heapIndex[host] = he

	zap.L().Debug("HostRateLimiter: Created entry", zap.String("host", host), zap.Int("shard_size", len(shard.hosts)))
	return entry
}

// evictOldestFromShard evicts the oldest entry from a single shard.
// Must be called with shard.mu held for writing.
func (h *HostRateLimiter) evictOldestFromShard(shard *hostShard) {
	if shard.evictionHeap.Len() == 0 {
		return
	}

	he := heap.Pop(&shard.evictionHeap).(*heapEntry)
	delete(shard.heapIndex, he.host)
	delete(shard.hosts, he.host)
	zap.L().Debug("HostRateLimiter: Evicted oldest entry", zap.String("host", he.host))
}

// evictionLoop periodically evicts idle hosts.
func (h *HostRateLimiter) evictionLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-h.stopEvict:
			return
		case <-ticker.C:
			h.evictIdle()
		}
	}
}

// evictIdle removes hosts that haven't been used recently.
// Pops from the min-heap while the oldest entry is idle and has no active slots.
func (h *HostRateLimiter) evictIdle() {
	totalEvicted := 0
	totalRemaining := 0

	for i := range h.shards {
		shard := &h.shards[i]

		shard.mu.Lock()
		for shard.evictionHeap.Len() > 0 {
			he := shard.evictionHeap[0]

			// Verify against the actual hostEntry's atomic lastUsed,
			// which may have been updated since the heap entry was last fixed.
			entry, exists := shard.hosts[he.host]
			if !exists {
				// Stale heap entry — host already removed
				heap.Pop(&shard.evictionHeap)
				delete(shard.heapIndex, he.host)
				continue
			}

			actualLastUsed := entry.lastUsed.Load()
			if actualLastUsed != he.lastUsed {
				// Heap is stale — update and re-fix
				he.lastUsed = actualLastUsed
				heap.Fix(&shard.evictionHeap, he.index)
				continue
			}

			if !entry.idleSince(h.evictAfter) || entry.hasInflight() {
				break // Oldest isn't idle yet, nothing else will be
			}

			heap.Pop(&shard.evictionHeap)
			delete(shard.heapIndex, he.host)
			delete(shard.hosts, he.host)
			totalEvicted++
		}
		totalRemaining += len(shard.hosts)
		shard.mu.Unlock()
	}

	if totalEvicted > 0 {
		zap.L().Debug("HostRateLimiter: Evicted idle entries",
			zap.Int("evicted", totalEvicted),
			zap.Int("remaining", totalRemaining))
	}
}

// Close stops the eviction goroutine and releases resources.
func (h *HostRateLimiter) Close() error {
	close(h.stopEvict)
	// conc re-panics on Wait() if the eviction goroutine panicked.
	// Absorb it gracefully so Close() doesn't crash the process.
	func() {
		defer func() {
			if r := recover(); r != nil {
				zap.L().Error("HostRateLimiter: panic in eviction goroutine", zap.Any("panic", r))
			}
		}()
		h.evictWg.Wait()
	}()

	for i := range h.shards {
		h.shards[i].mu.Lock()
		h.shards[i].hosts = nil
		h.shards[i].evictionHeap = nil
		h.shards[i].heapIndex = nil
		h.shards[i].mu.Unlock()
	}

	return nil
}

// Stats returns current statistics.
func (h *HostRateLimiter) Stats() (trackedHosts int, maxEntries int) {
	total := 0
	for i := range h.shards {
		h.shards[i].mu.RLock()
		total += len(h.shards[i].hosts)
		h.shards[i].mu.RUnlock()
	}
	return total, h.maxEntries
}
