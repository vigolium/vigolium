package core

import (
	"sync"
	"sync/atomic"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

const (
	// defaultIPCacheEntries is the entry cap used when no size is supplied.
	defaultIPCacheEntries = 4096

	// ipCacheMaxBytes bounds the total retained bytes across all insertion-point
	// cache entries. Entry count alone is not a memory bound here: the executor
	// auto-sizes this cache to as many as 25,000 entries (see NewExecutor) and a
	// single entry's retained size spans four orders of magnitude — one insertion
	// point on a short GET versus thousands of nested points on a large JSON body.
	// Entries are evicted oldest-first until the cache is back under this budget.
	//
	// Mirrors the same count/per-entry/total-bytes shape as the response clusterer
	// (see clusterCacheMaxBytes in pkg/http/clustering.go).
	ipCacheMaxBytes = 128 << 20 // 128 MiB

	// ipCacheMaxEntryBytes is the largest single entry eligible for caching. A
	// request whose insertion-point set exceeds this is still scanned normally —
	// it is simply re-derived on a later visit rather than allowed to consume a
	// large share of the budget on its own. Re-deriving even a 2,000-child nested
	// set costs ~2 ms, so the trade is heavily in favour of the bound.
	ipCacheMaxEntryBytes = 4 << 20 // 4 MiB
)

// ipCacheEntry pairs a cached insertion-point set with the retained-byte weight
// charged for it. The weight is stored rather than recomputed so eviction
// accounting can never drift from what admission charged, even if the estimator
// changes behaviour between the two calls.
type ipCacheEntry struct {
	// points is the standard set (no opt-in extras) — what the module-facing
	// provider and the per-request timeout scaling see.
	points []httpmsg.InsertionPoint
	// all adds the opt-in parameter-name and entire-body points (MISS-15); the
	// per-insertion-point stage dispatches from it and each module's allowed
	// types decide. nil for an entry stored through Add.
	all    []httpmsg.InsertionPoint
	weight int
}

// InsertionPointCache is a byte-aware LRU of insertion-point sets, keyed by
// request hash. It bounds both entry count (via the underlying LRU) and total
// retained bytes, and rejects individual entries above a per-entry ceiling.
//
// A nil *InsertionPointCache is usable: every method degrades to a miss, so a
// caller with no cache configured needs no branch of its own.
//
// All access is serialized on one mutex. That is deliberate: the byte counter and
// the LRU must move together or the budget drifts, and the eviction callback
// updates the counter while the LRU's own lock is held — so it must not attempt to
// re-acquire this mutex. Because every caller path holds the mutex around the LRU
// call, the callback runs with exclusive access already and updates the counter
// directly. Contention is not a concern: lookups are per-request, not per-payload.
type InsertionPointCache struct {
	mu    sync.Mutex
	lru   *lru.Cache[string, ipCacheEntry]
	bytes int64

	hits      atomic.Int64
	misses    atomic.Int64
	evictions atomic.Int64
	rejected  atomic.Int64
}

// NewInsertionPointCache creates a byte-aware insertion-point cache holding at
// most entries items. A non-positive entries value falls back to a safe default.
func NewInsertionPointCache(entries int) *InsertionPointCache {
	if entries < 1 {
		entries = defaultIPCacheEntries
	}

	c := &InsertionPointCache{}
	// entries >= 1 above and NewWithEvict errors only on a non-positive size, so
	// the ignored error is provably nil.
	c.lru, _ = lru.NewWithEvict(entries, c.discount)
	return c
}

// discount is the LRU's eviction callback: it removes an evicted entry's weight
// from the retained-byte total.
//
// It runs under the LRU's own lock, which is only ever taken while this cache's
// mutex is held (see the type comment), so it updates bytes without locking.
func (c *InsertionPointCache) discount(_ string, e ipCacheEntry) {
	c.bytes -= int64(e.weight)
	if c.bytes < 0 {
		c.bytes = 0
	}
}

// Get returns the cached insertion points for key.
func (c *InsertionPointCache) Get(key string) ([]httpmsg.InsertionPoint, bool) {
	if c == nil {
		return nil, false
	}

	c.mu.Lock()
	entry, ok := c.lru.Get(key)
	c.mu.Unlock()

	if ok {
		c.hits.Add(1)
		return entry.points, true
	}
	c.misses.Add(1)
	return nil, false
}

// Add caches points under key unless the set is too large to be worth retaining.
// Oversized sets are counted as rejections and left uncached — the caller's copy
// is unaffected either way, so a rejection costs only a later re-derivation.
func (c *InsertionPointCache) Add(key string, points []httpmsg.InsertionPoint) {
	c.add(key, points, nil)
}

// add stores the standard set and (optionally) the full set under key.
func (c *InsertionPointCache) add(key string, points, all []httpmsg.InsertionPoint) {
	if c == nil || (len(points) == 0 && len(all) == 0) {
		return
	}

	weighed := points
	if len(all) > len(weighed) {
		weighed = all
	}
	weight := httpmsg.EstimateRetainedBytes(weighed)
	if weight > ipCacheMaxEntryBytes {
		c.rejected.Add(1)
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Remove any previous value for this key first, so the evict callback
	// discounts its weight. lru.Add on an existing key REPLACES the value in place
	// WITHOUT firing the callback, so adding straight over it would leak the old
	// weight on every re-add — and a repeated request is exactly what this cache
	// exists to serve, so the counter would drift up until the budget evicted
	// everything. Remove is a no-op when the key is absent.
	c.lru.Remove(key)

	c.lru.Add(key, ipCacheEntry{points: points, all: all, weight: weight})
	c.bytes += int64(weight)

	// Trim back under the byte budget. Keeping one entry unconditionally means a
	// single entry larger than the whole budget (impossible given the per-entry
	// ceiling, but cheap to guarantee) cannot spin this loop — and it also makes
	// RemoveOldest's success unconditional, since Len() > 1 guarantees an entry.
	for c.bytes > ipCacheMaxBytes && c.lru.Len() > 1 {
		c.lru.RemoveOldest()
		c.evictions.Add(1)
	}
}

// GetOrCompute returns the insertion points for requestID, deriving and caching
// them on a miss.
//
// This owns the cache-key convention (the includeNested variants are separate
// entries) so no caller has to reproduce it. Both the per-insertion-point scan
// stage and the module-facing provider go through here; deriving a key inline
// instead is how the two ends up disagreeing about which variant they stored.
func (c *InsertionPointCache) GetOrCompute(raw []byte, requestID string, includeNested bool) ([]httpmsg.InsertionPoint, error) {
	std, _, err := c.getOrCompute(raw, requestID, includeNested)
	return std, err
}

// GetOrComputeAll is GetOrCompute including the opt-in parameter-name and
// entire-body points (ParamNames + EntireBody). Both views come from one parse
// and one cache entry.
func (c *InsertionPointCache) GetOrComputeAll(raw []byte, requestID string, includeNested bool) ([]httpmsg.InsertionPoint, error) {
	_, all, err := c.getOrCompute(raw, requestID, includeNested)
	return all, err
}

func (c *InsertionPointCache) getOrCompute(raw []byte, requestID string, includeNested bool) (std, all []httpmsg.InsertionPoint, err error) {
	key := requestID
	if !includeNested {
		key += ":shallow"
	}
	if c != nil {
		c.mu.Lock()
		entry, ok := c.lru.Get(key)
		c.mu.Unlock()
		if ok && entry.all != nil {
			c.hits.Add(1)
			return entry.points, entry.all, nil
		}
		c.misses.Add(1)
	}

	all, err = httpmsg.CreateInsertionPoints(raw, httpmsg.InsertionPointOptions{
		IncludeNested: includeNested,
		ParamNames:    true,
		EntireBody:    true,
	})
	if err != nil {
		return nil, nil, err
	}
	std = make([]httpmsg.InsertionPoint, 0, len(all))
	for _, p := range all {
		if !httpmsg.IsExtraInsertionPointType(p.Type()) {
			std = append(std, p)
		}
	}
	c.add(key, std, all)
	return std, all, nil
}

// InsertionPointCacheStats is a point-in-time snapshot of cache behaviour, for
// logging and metrics. Counters are cumulative for the cache's lifetime.
type InsertionPointCacheStats struct {
	Entries       int
	RetainedBytes int64
	Hits          int64
	Misses        int64
	// Evictions counts only byte-budget evictions. Ordinary count-bound LRU
	// evictions are not counted: they are the cache working as configured, while a
	// byte eviction means the budget — not the entry cap — is the binding limit.
	Evictions int64
	// Rejected counts sets never cached because they exceeded the per-entry ceiling.
	Rejected int64
}

// Stats returns a snapshot of the cache's current size and cumulative counters.
func (c *InsertionPointCache) Stats() InsertionPointCacheStats {
	if c == nil {
		return InsertionPointCacheStats{}
	}

	c.mu.Lock()
	entries := c.lru.Len()
	bytes := c.bytes
	c.mu.Unlock()

	return InsertionPointCacheStats{
		Entries:       entries,
		RetainedBytes: bytes,
		Hits:          c.hits.Load(),
		Misses:        c.misses.Load(),
		Evictions:     c.evictions.Load(),
		Rejected:      c.rejected.Load(),
	}
}
