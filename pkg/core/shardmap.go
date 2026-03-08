package core

import (
	"hash/maphash"
	"sync"
)

const defaultMaxPerShard = 8192 // max entries per shard before eviction

// shardedMap is a bounded concurrent map sharded by key hash to reduce lock contention.
// Each shard has its own RWMutex, so concurrent operations on different shards
// never block each other. Uses maphash for hardware-accelerated hashing and
// FIFO eviction to bound memory growth.
type shardedMap struct {
	shards []mapShard
	seed   maphash.Seed
	mask   uint64
}

type mapShard struct {
	mu      sync.RWMutex
	m       map[string]string
	order   []string // FIFO eviction ring (keys in insertion order)
	head    int      // next eviction index
	maxSize int
}

// newShardedMap creates a bounded sharded map. shardHint is rounded up to the
// next power of two (minimum 16) to enable fast bitwise shard selection.
// maxEntries sets the total capacity across all shards; 0 uses the default
// (defaultMaxPerShard * numShards).
func newShardedMap(shardHint int, maxEntries ...int) *shardedMap {
	n := 16
	for n < shardHint {
		n <<= 1
	}

	maxPerShard := defaultMaxPerShard
	if len(maxEntries) > 0 && maxEntries[0] > 0 {
		maxPerShard = maxEntries[0] / n
		if maxPerShard < 64 {
			maxPerShard = 64
		}
	}

	shards := make([]mapShard, n)
	for i := range shards {
		shards[i].m = make(map[string]string, maxPerShard/2)
		shards[i].order = make([]string, 0, maxPerShard)
		shards[i].maxSize = maxPerShard
	}
	return &shardedMap{
		shards: shards,
		seed:   maphash.MakeSeed(),
		mask:   uint64(n - 1),
	}
}

// shard uses runtime maphash (hardware-accelerated, 8-byte stride) to select
// a shard. This is ~3x faster than byte-by-byte FNV-1a for 64-byte keys.
func (sm *shardedMap) shard(key string) *mapShard {
	var h maphash.Hash
	h.SetSeed(sm.seed)
	h.WriteString(key)
	return &sm.shards[h.Sum64()&sm.mask]
}

// Store sets key to value, evicting the oldest entry if the shard is at capacity.
func (sm *shardedMap) Store(key, value string) {
	s := sm.shard(key)
	s.mu.Lock()

	if _, exists := s.m[key]; exists {
		s.m[key] = value
		s.mu.Unlock()
		return
	}

	// Evict oldest entry if shard is at capacity.
	if len(s.m) >= s.maxSize && len(s.order) > 0 {
		evictKey := s.order[s.head]
		delete(s.m, evictKey)
		s.order[s.head] = key
		s.head = (s.head + 1) % len(s.order)
	} else {
		s.order = append(s.order, key)
	}

	s.m[key] = value
	s.mu.Unlock()
}

// Load returns the value for key and whether it was found.
func (sm *shardedMap) Load(key string) (string, bool) {
	s := sm.shard(key)
	s.mu.RLock()
	v, ok := s.m[key]
	s.mu.RUnlock()
	return v, ok
}
