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

func (h hostHeap) Len() int            { return len(h) }
func (h hostHeap) Less(i, j int) bool   { return h[i].lastUsed < h[j].lastUsed }
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
type hostEntry struct {
	sem      chan struct{} // Semaphore for concurrency limiting
	lastUsed atomic.Int64 // Unix nanos — updated atomically, no lock needed
}

func (e *hostEntry) touch() {
	e.lastUsed.Store(time.Now().UnixNano())
}

func (e *hostEntry) idleSince(d time.Duration) bool {
	return time.Since(time.Unix(0, e.lastUsed.Load())) > d
}

// hostShard is one bucket of the sharded host map.
type hostShard struct {
	mu            sync.RWMutex
	hosts         map[string]*hostEntry
	evictionHeap  hostHeap
	heapIndex     map[string]*heapEntry
}

// HostRateLimiter limits concurrent requests per hostname.
// It uses per-host semaphores sharded across 32 buckets to reduce lock contention,
// and supports auto-eviction of idle hosts.
type HostRateLimiter struct {
	shards     [numShards]hostShard
	maxPerHost int           // Max concurrent requests per host
	maxEntries int           // Max tracked hosts before forced eviction
	evictAfter time.Duration // Evict hosts idle for this duration

	stopEvict chan struct{}
	evictWg   conc.WaitGroup
}

// HostRateLimiterConfig configures the HostRateLimiter.
type HostRateLimiterConfig struct {
	MaxPerHost    int           // Max concurrent requests per host (default: 10)
	MaxEntries    int           // Max tracked hosts (default: 1000)
	EvictAfter    time.Duration // Evict idle hosts after (default: 30s)
	EvictInterval time.Duration // How often to run eviction (default: 10s)
}

// DefaultHostRateLimiterConfig returns sensible defaults.
func DefaultHostRateLimiterConfig() HostRateLimiterConfig {
	return HostRateLimiterConfig{
		MaxPerHost:    10,
		MaxEntries:    1000,
		EvictAfter:    30 * time.Second,
		EvictInterval: 10 * time.Second,
	}
}

// NewHostRateLimiter creates a new HostRateLimiter with the given configuration.
func NewHostRateLimiter(cfg HostRateLimiterConfig) *HostRateLimiter {
	if cfg.MaxPerHost <= 0 {
		cfg.MaxPerHost = 10
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

	h := &HostRateLimiter{
		maxPerHost: cfg.MaxPerHost,
		maxEntries: cfg.MaxEntries,
		evictAfter: cfg.EvictAfter,
		stopEvict:  make(chan struct{}),
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

	select {
	case <-ctx.Done():
		return ctx.Err()
	case entry.sem <- struct{}{}:
		entry.touch()

		// Update heap entry under write lock to maintain eviction order
		shard.mu.Lock()
		if he, ok := shard.heapIndex[host]; ok {
			he.lastUsed = entry.lastUsed.Load()
			heap.Fix(&shard.evictionHeap, he.index)
		}
		shard.mu.Unlock()

		return nil
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

	// Check if we need to evict (approximate: per-shard cap)
	if len(shard.hosts) >= h.maxEntries/numShards {
		h.evictOldestFromShard(shard)
	}

	now := time.Now().UnixNano()
	entry = &hostEntry{
		sem: make(chan struct{}, h.maxPerHost),
	}
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

			if !entry.idleSince(h.evictAfter) || len(entry.sem) > 0 {
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
