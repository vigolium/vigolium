package dedup

import (
	"sync"
	"sync/atomic"
)

// Counter provides thread-safe counting for deduplication with a max threshold.
// Uses in-memory storage since form structure hashes are bounded in number.
type Counter struct {
	entries sync.Map // key -> *atomic.Int32
	size    atomic.Int64
}

// NewCounter creates a new in-memory counter.
func NewCounter() *Counter {
	return &Counter{}
}

// IncrementAndCheck atomically increments the counter for key and returns true
// if the new count is within maxCount (allowed). Returns false if exceeded.
func (c *Counter) IncrementAndCheck(key string, maxCount int32) bool {
	// Fast path: key already exists (common after warmup), no allocation needed
	if val, ok := c.entries.Load(key); ok {
		return val.(*atomic.Int32).Add(1) <= maxCount
	}
	// Slow path: first encounter, allocate and race to store
	newCounter := &atomic.Int32{}
	val, loaded := c.entries.LoadOrStore(key, newCounter)
	if !loaded {
		c.size.Add(1)
	}
	return val.(*atomic.Int32).Add(1) <= maxCount
}

// Size returns the number of unique keys tracked.
func (c *Counter) Size() int64 {
	return c.size.Load()
}

// Close is a no-op for interface consistency with DiskSet.
func (c *Counter) Close() error {
	return nil
}
