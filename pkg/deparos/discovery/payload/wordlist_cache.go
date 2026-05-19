package payload

import (
	"fmt"
	"sync"
)

// WordlistCacheKey identifies a cached wordlist by path and case sensitivity.
type WordlistCacheKey struct {
	FilePath      string
	CaseSensitive bool
}

// CachedWordlist holds shared wordlist data (loaded once).
// Immutable after creation - safe to share across providers.
type CachedWordlist struct {
	Payloads [][]byte
	FilePath string
	ListType BuiltInListType
}

// WordlistCache provides thread-safe caching of wordlist data.
// Load each file ONCE, share the underlying [][]byte across all providers.
type WordlistCache struct {
	mu    sync.RWMutex
	cache map[WordlistCacheKey]*CachedWordlist
}

// NewWordlistCache creates a new empty wordlist cache.
func NewWordlistCache() *WordlistCache {
	return &WordlistCache{
		cache: make(map[WordlistCacheKey]*CachedWordlist),
	}
}

// Get returns cached wordlist or loads it (lazy loading with double-check locking).
// Thread-safe: uses RWMutex for concurrent read access.
func (c *WordlistCache) Get(listType BuiltInListType, filePath string, caseSensitive bool) (*CachedWordlist, error) {
	if filePath == "" {
		return nil, fmt.Errorf("wordlist file path required for %s", listType)
	}

	key := WordlistCacheKey{FilePath: filePath, CaseSensitive: caseSensitive}

	// Fast path: read lock
	c.mu.RLock()
	if cached, ok := c.cache[key]; ok {
		c.mu.RUnlock()
		return cached, nil
	}
	c.mu.RUnlock()

	// Slow path: write lock
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock
	if cached, ok := c.cache[key]; ok {
		return cached, nil
	}

	// Load from disk (reuse existing loadWordlist function)
	payloads, err := loadWordlist(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load %s wordlist from %s: %w", listType, filePath, err)
	}

	// Apply case normalization if needed
	if !caseSensitive {
		payloads = normalizeAndDedup(payloads)
	}

	cached := &CachedWordlist{
		Payloads: payloads,
		FilePath: filePath,
		ListType: listType,
	}
	c.cache[key] = cached
	return cached, nil
}

// Clear removes all cached wordlists.
// Useful for cleanup or testing.
func (c *WordlistCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[WordlistCacheKey]*CachedWordlist)
}

// Size returns the number of cached wordlists.
func (c *WordlistCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cache)
}

// CustomListType is a sentinel value for custom wordlists.
const CustomListType BuiltInListType = -1

// GetCustom returns cached custom wordlist or loads it.
// Custom files are always case-sensitive (no normalization).
func (c *WordlistCache) GetCustom(filePath string) (*CachedWordlist, error) {
	if filePath == "" {
		return nil, fmt.Errorf("custom wordlist file path required")
	}

	// Custom files are always case-sensitive
	key := WordlistCacheKey{FilePath: filePath, CaseSensitive: true}

	// Fast path: read lock
	c.mu.RLock()
	if cached, ok := c.cache[key]; ok {
		c.mu.RUnlock()
		return cached, nil
	}
	c.mu.RUnlock()

	// Slow path: write lock
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock
	if cached, ok := c.cache[key]; ok {
		return cached, nil
	}

	// Load from disk
	payloads, err := loadWordlist(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load custom wordlist from %s: %w", filePath, err)
	}

	cached := &CachedWordlist{
		Payloads: payloads,
		FilePath: filePath,
		ListType: CustomListType,
	}
	c.cache[key] = cached
	return cached, nil
}
