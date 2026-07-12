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

	// armed gates AIMD adjustment for this host. newEntry stores h.adaptive into it:
	// plain Adaptive hosts start armed (adjust from the first request); WAF-auto-arm
	// hosts start unarmed — pinned at MaxPerHost, behaving exactly like the static
	// limiter — until a confirmed WAF block on this host flips it true (in Feedback),
	// at which point AIMD back-off/recovery engages.
	armed atomic.Bool

	// preArmed records that PreArm has proactively paced this entry, exactly once per
	// entry lifetime. It is distinct from armed so that (a) a birth-armed adaptive
	// host (armed from the first request) still receives the one-time proactive drop,
	// and (b) a fresh entry created after idle eviction re-arms rather than staying
	// pinned at full rate.
	preArmed atomic.Bool
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

	// preArmDisabled turns off the proactive edge-fingerprint pacing (PreArm) while
	// leaving reactive WAF-block back-off (Feedback) untouched. Set from
	// HostRateLimiterConfig.DisablePreArm (the --no-waf-pacing flag).
	preArmDisabled bool

	// wafAutoArm enables targeted adaptive throttling that stays dormant until a
	// confirmed WAF/CDN block. With it on (and adaptive off), every host uses the
	// adaptive token pool pinned at MaxPerHost — identical concurrency to the static
	// limiter — until a WAF block on that host arms it (via Feedback's wafBlocked
	// flag), after which the host AIMD-backs-off like adaptive mode and recovers to
	// MaxPerHost. A non-WAF scan therefore sees no change in behavior. Mutually
	// exclusive with adaptive: NewHostRateLimiter normalizes it to
	// cfg.WafAutoArm && !cfg.Adaptive, so plain Adaptive mode always wins.
	wafAutoArm bool

	// anyArmed is a global fast-path flag: false until the first host anywhere is
	// armed by a WAF block. While false, Feedback skips the per-host shard lookup for
	// every non-block response, keeping the common non-WAF hot path ~free even though
	// wafAutoArm puts all hosts on the adaptive token pool. Monotonic (never reset):
	// once any WAF block is seen the target is treated as WAF'd for the run.
	anyArmed atomic.Bool

	// preArmSink, when set, is invoked once per host the first time PreArm throttles
	// it for a CDN/WAF edge, so a front-end can tell the operator that host's
	// active-scan concurrency was reduced (the scan will pace it). It lives on the
	// limiter — not a requester — because the limiter is the single shared object
	// every requester feeds, so the notice fires exactly once per host no matter which
	// requester tripped the pre-arm. Set once during setup before concurrency starts
	// (same contract as the requester's block-notifier sink); read on the request
	// goroutine that arms the host.
	preArmSink func(PreArmNotice)

	// evictSink, when set, is invoked with the hostname each time an idle host entry
	// is evicted. It lets a requester keep its once-per-host edge-pacing dedup in sync
	// with the limiter's entry lifetime: after an evicted host's entry is recreated
	// (fresh, at full rate), the requester re-fingerprints and re-arms it instead of
	// treating it as permanently paced. Must be cheap and must NOT re-enter the limiter
	// (it is invoked while a shard lock is held). Set once during setup.
	evictSink func(host string)

	stopEvict chan struct{}
	evictWg   conc.WaitGroup
}

// PreArmNotice describes a proactive pacing adjustment. The first time a host is
// fingerprinted behind a CDN/WAF edge, PreArm drops its per-host concurrency from
// From to Start (ramping back toward Ceiling on healthy traffic). It is passed to the
// sink registered via SetPreArmNotifier, once per host.
type PreArmNotice struct {
	Host    string // host being paced
	Vendor  string // fingerprinted edge vendor (e.g. "cloudfront"); "" if unknown
	From    int    // per-host concurrency before the pre-arm (the ceiling/MaxPerHost)
	Start   int    // reduced per-host concurrency the host is dropped to
	Ceiling int    // limit the host ramps back toward on healthy traffic
}

// SetPreArmNotifier installs a sink invoked once per host the first time PreArm
// throttles it for a CDN/WAF edge. It lets a front-end warn the operator that the
// scan will pace (run slower against) that host. The sink runs on the request
// goroutine, so it must be cheap and non-blocking. Call once during setup, before
// scanning concurrency starts; a nil sink is a no-op.
func (h *HostRateLimiter) SetPreArmNotifier(sink func(PreArmNotice)) {
	h.preArmSink = sink
}

// SetEvictNotifier installs a sink invoked with the hostname whenever an idle host
// entry is evicted, so a requester can drop the host from its once-per-host
// edge-pacing dedup and re-fingerprint/re-arm the fresh entry created later. The
// sink is invoked while a shard lock is held, so it must be cheap and must NOT call
// back into the limiter. Call once during setup; a nil sink is a no-op.
func (h *HostRateLimiter) SetEvictNotifier(sink func(string)) {
	h.evictSink = sink
}

// notifyEvict fires the evict sink for host, if one is installed.
func (h *HostRateLimiter) notifyEvict(host string) {
	if h.evictSink != nil {
		h.evictSink(host)
	}
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

	// WafAutoArm enables WAF-triggered adaptive throttling: hosts run at the static
	// MaxPerHost until a confirmed WAF/CDN block arms per-host AIMD back-off. Safe to
	// leave on for every scan — a host that never trips a WAF behaves exactly like the
	// static limiter. Bounds reuse MinPerHost/CeilingPerHost. Redundant under Adaptive.
	WafAutoArm bool

	// DisablePreArm turns off only the PROACTIVE pacing (PreArm on a CDN/WAF-edge
	// fingerprint) while leaving the reactive WAF-block back-off intact. Wired from the
	// `--no-waf-pacing` CLI flag for operators who would rather keep full opening
	// concurrency and let the reactive path throttle after the first block.
	DisablePreArm bool
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
		// Mutually exclusive with Adaptive — plain Adaptive already arms every host,
		// so WAF-auto-arm is only meaningful when Adaptive is off.
		wafAutoArm:     cfg.WafAutoArm && !cfg.Adaptive,
		preArmDisabled: cfg.DisablePreArm,
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
	return h.AcquireWithTimeoutContext(context.Background(), host)
}

// AcquireWithTimeoutContext blocks until a slot is available, the configured
// acquire timeout expires, or the caller's context is cancelled — whichever
// comes first. Returns context.DeadlineExceeded on timeout, or the context's
// error (e.g. context.Canceled) on cancellation. Deriving the acquire deadline
// from ctx (rather than context.Background()) lets a scan shutdown or phase
// deadline unblock a waiting acquire promptly, instead of stranding the
// goroutine until acquireTimeout elapses.
func (h *HostRateLimiter) AcquireWithTimeoutContext(ctx context.Context, host string) error {
	// Fast path: an unsaturated host is by far the common case, and this is the
	// single hottest path in the scanner (every outgoing request). Try a
	// non-blocking acquire first so we avoid heap-allocating a timeout context
	// and arming a runtime timer when a slot is immediately available.
	if err := ctx.Err(); err != nil {
		return err
	}
	if h.tryAcquire(host) {
		return nil
	}

	// Slow path: the host is saturated — block up to acquireTimeout (derived
	// from ctx so a scan shutdown can unblock the wait promptly).
	acquireCtx, cancel := context.WithTimeout(ctx, h.acquireTimeout)
	defer cancel()
	return h.Acquire(acquireCtx, host)
}

// tryAcquire attempts a non-blocking slot acquisition. It returns true only if a
// slot was obtained immediately, and never blocks — callers use it to skip the
// timeout-context/timer setup on the uncontended hot path. The blocking retry
// (with the same touch/inflight bookkeeping) lives in Acquire.
func (h *HostRateLimiter) tryAcquire(host string) bool {
	shard := h.shardFor(host)
	entry := h.getOrCreateEntry(shard, host)

	if entry.tokens != nil {
		select {
		case <-entry.tokens:
			entry.inflight.Add(1)
			entry.touch()
			return true
		default:
			return false
		}
	}

	select {
	case entry.sem <- struct{}{}:
		entry.touch()
		return true
	default:
		return false
	}
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

// evictOldestFromShard evicts the oldest entry that has no in-flight requests
// from a single shard. Must be called with shard.mu held for writing.
//
// It deliberately skips entries with acquired-but-not-released slots: evicting a
// busy host would orphan its semaphore accounting — a later Release finds no
// entry and silently no-ops, while a concurrent getOrCreateEntry makes a fresh
// entry that has lost the in-flight count (mirrors the hasInflight() guard in
// evictIdle). If every entry in the shard is busy, it evicts nothing and lets
// the shard briefly exceed its soft cap rather than corrupt accounting.
func (h *HostRateLimiter) evictOldestFromShard(shard *hostShard) {
	if shard.evictionHeap.Len() == 0 {
		return
	}

	// Scan for the least-recently-used idle entry. The shard is small (~maxEntries
	// /numShards), so the linear scan is cheap and only runs on the forced-cap
	// path.
	var victim *heapEntry
	for _, he := range shard.evictionHeap {
		entry, exists := shard.hosts[he.host]
		if !exists || entry.hasInflight() {
			continue
		}
		if victim == nil || he.lastUsed < victim.lastUsed {
			victim = he
		}
	}
	if victim == nil {
		return // every entry is busy — don't evict an in-flight host
	}

	heap.Remove(&shard.evictionHeap, victim.index)
	delete(shard.heapIndex, victim.host)
	delete(shard.hosts, victim.host)
	h.notifyEvict(victim.host)
	zap.L().Debug("HostRateLimiter: Evicted oldest idle entry", zap.String("host", victim.host))
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
			h.notifyEvict(he.host)
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
