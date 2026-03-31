package prompt

import (
	"strconv"
	"sync"
	"time"
)

// ContextCache caches EnrichContextFromDB results within a single swarm run
// to avoid redundant database queries across multiple agent phases.
//
// Lifecycle: created at swarm run start, passed to all phases, discarded at end.
// Invalidation: call Invalidate() after phases that modify findings (native scan, rescan).
type ContextCache struct {
	mu      sync.RWMutex
	entries map[string]contextCacheEntry
	ttl     time.Duration
}

type contextCacheEntry struct {
	value     string
	createdAt time.Time
}

// NewContextCache creates a cache scoped to a single swarm run.
// ttl controls staleness — 0 means entries never expire within the run.
func NewContextCache(ttl time.Duration) *ContextCache {
	return &ContextCache{
		entries: make(map[string]contextCacheEntry),
		ttl:     ttl,
	}
}

func contextCacheKey(hostname, variable string, limit int) string {
	return hostname + "|" + variable + "|" + strconv.Itoa(limit)
}

// Get retrieves a cached result. Returns ("", false) on miss or expiry.
func (c *ContextCache) Get(hostname, variable string, limit int) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := contextCacheKey(hostname, variable, limit)
	entry, ok := c.entries[key]
	if !ok {
		return "", false
	}
	if c.ttl > 0 && time.Since(entry.createdAt) > c.ttl {
		return "", false
	}
	return entry.value, true
}

// Set stores a result in the cache.
func (c *ContextCache) Set(hostname, variable string, limit int, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := contextCacheKey(hostname, variable, limit)
	c.entries[key] = contextCacheEntry{
		value:     value,
		createdAt: time.Now(),
	}
}

// Invalidate clears all cached entries. Call after phases that modify
// scan data (native scan, rescan) to ensure subsequent phases see fresh results.
func (c *ContextCache) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]contextCacheEntry)
}
