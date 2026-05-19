package fingerprint

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"strings"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"
)

var logger *zap.Logger

// SetLogger configures the global logger for the fingerprint package
func SetLogger(l *zap.Logger) {
	if l == nil {
		logger = zap.NewNop()
	} else {
		logger = l
	}
}

func init() {
	// Default to no-op logger
	logger = zap.NewNop()
}

// CacheKey represents a unique key for signature caching.
// Signatures are cached per (host, path, extension) combination.
// Path enables per-directory baseline learning for accurate soft-404 detection.
type CacheKey struct {
	Host      string // "example.com:443"
	Path      string // "/" or "/bob/" (directory path, always ends with /)
	Extension string // ".json", ".php", "" for no extension
}

// String returns string representation of cache key
func (k CacheKey) String() string {
	if k.Path == "" || k.Path == "/" {
		if k.Extension == "" {
			return k.Host
		}
		return fmt.Sprintf("%s:%s", k.Host, k.Extension)
	}
	if k.Extension == "" {
		return fmt.Sprintf("%s%s", k.Host, k.Path)
	}
	return fmt.Sprintf("%s%s:%s", k.Host, k.Path, k.Extension)
}

// DefaultCacheMaxSize is the default maximum number of cache entries before eviction
const DefaultCacheMaxSize = 10000

// Cache stores learned fingerprint signatures per (host, path, extension)
// Thread-safe for concurrent access
type Cache struct {
	signatures sync.Map                                  // map[CacheKey][]*Signature
	pathIndex  map[string]map[string]map[string]struct{} // host → path → set of extensions
	size       int                                       // cached entry count (avoid O(n) Size())
	maxSize    int                                       // maximum entries before eviction
	learner    *Learner
	mu         sync.RWMutex // Protects pathIndex, size, and learner
}

// NewCache creates a new fingerprint cache with default max size
func NewCache(learner *Learner) *Cache {
	return NewCacheWithMaxSize(learner, DefaultCacheMaxSize)
}

// NewCacheWithMaxSize creates a new fingerprint cache with specified max size
func NewCacheWithMaxSize(learner *Learner, maxSize int) *Cache {
	if maxSize <= 0 {
		maxSize = DefaultCacheMaxSize
	}
	return &Cache{
		pathIndex: make(map[string]map[string]map[string]struct{}),
		maxSize:   maxSize,
		learner:   learner,
	}
}

// Get retrieves signatures for a cache key
func (c *Cache) Get(key CacheKey) ([]*Signature, bool) {
	value, ok := c.signatures.Load(key)
	if !ok {
		return nil, false
	}

	sigs, ok := value.([]*Signature)
	return sigs, ok
}

// Add adds a signature to the cache for a given key
// Thread-safe: uses mutex to prevent concurrent slice modifications
func (c *Cache) Add(key CacheKey, sig *Signature) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict if at capacity (before adding new entry)
	if c.size >= c.maxSize {
		c.evictRandomLocked()
	}

	// Track if this is a new key for size counting
	isNewKey := false

	// Get existing signatures or create new slice
	var sigs []*Signature

	if value, ok := c.signatures.Load(key); ok {
		if existing, ok := value.([]*Signature); ok {
			// Create new slice to avoid modifying shared slice
			sigs = make([]*Signature, len(existing), len(existing)+1)
			copy(sigs, existing)
		}
	} else {
		isNewKey = true
	}

	// Append new signature
	sigs = append(sigs, sig)

	// Store back
	c.signatures.Store(key, sigs)

	// Update path index
	if c.pathIndex[key.Host] == nil {
		c.pathIndex[key.Host] = make(map[string]map[string]struct{})
	}
	if c.pathIndex[key.Host][key.Path] == nil {
		c.pathIndex[key.Host][key.Path] = make(map[string]struct{})
	}
	c.pathIndex[key.Host][key.Path][key.Extension] = struct{}{}

	// Update size counter
	if isNewKey {
		c.size++
	}
}

// evictRandomLocked evicts ~10% of entries when cache is full.
// Must be called with c.mu held.
func (c *Cache) evictRandomLocked() {
	evictCount := c.maxSize / 10
	if evictCount < 1 {
		evictCount = 1
	}

	deleted := 0
	c.signatures.Range(func(key, value interface{}) bool {
		if deleted >= evictCount {
			return false
		}

		c.signatures.Delete(key)
		c.size--
		deleted++

		// Clean up pathIndex
		if k, ok := key.(CacheKey); ok {
			if paths, ok := c.pathIndex[k.Host]; ok {
				if exts, ok := paths[k.Path]; ok {
					delete(exts, k.Extension)
					if len(exts) == 0 {
						delete(paths, k.Path)
					}
				}
				if len(paths) == 0 {
					delete(c.pathIndex, k.Host)
				}
			}
		}
		return true
	})
}

// Matches checks if a sample matches any cached signature for the key.
// Returns true if sample matches a known 404 signature.
func (c *Cache) Matches(key CacheKey, sample *Sample) bool {
	sigs, ok := c.Get(key)
	if !ok || len(sigs) == 0 {
		return false
	}

	for _, sig := range sigs {
		if sig.Matches(sample) {
			return true
		}
	}

	return false
}

// LearnAndCache learns a new signature and caches it
func (c *Cache) LearnAndCache(ctx context.Context, key CacheKey, baseURL *url.URL) (*Signature, error) {
	c.mu.RLock()
	learner := c.learner
	c.mu.RUnlock()

	if learner == nil {
		return nil, fmt.Errorf("no learner configured")
	}

	// Learn signature
	sig, err := learner.Learn(ctx, baseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to learn signature: %w", err)
	}

	// Debug: Log learned signature details
	logger.Debug("Learned fingerprint signature",
		zap.String("key", key.String()),
		zap.String("url", baseURL.String()),
		zap.Int("stable_attrs", sig.StableAttributeCount()),
		zap.String("signature", sig.DebugString()))

	// Add to cache
	c.Add(key, sig)

	return sig, nil
}

// Size returns the number of cache entries (keys)
func (c *Cache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.size
}

// MaxSize returns the maximum cache size before eviction
func (c *Cache) MaxSize() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.maxSize
}

// Clear removes all cached signatures
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.signatures = sync.Map{}
	c.pathIndex = make(map[string]map[string]map[string]struct{})
	c.size = 0
}

// Remove removes all signatures for a specific key
func (c *Cache) Remove(key CacheKey) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if key exists before deletion
	if _, ok := c.signatures.Load(key); !ok {
		return
	}

	c.signatures.Delete(key)
	c.size--

	// Update path index
	if paths, ok := c.pathIndex[key.Host]; ok {
		if exts, ok := paths[key.Path]; ok {
			delete(exts, key.Extension)
			if len(exts) == 0 {
				delete(paths, key.Path)
			}
		}
		if len(paths) == 0 {
			delete(c.pathIndex, key.Host)
		}
	}
}

// GetAllKeys returns all cache keys
func (c *Cache) GetAllKeys() []CacheKey {
	keys := make([]CacheKey, 0)
	c.signatures.Range(func(key, value interface{}) bool {
		if k, ok := key.(CacheKey); ok {
			keys = append(keys, k)
		}
		return true
	})
	return keys
}

// ExtractCacheKey extracts cache key from URL.
// Uses host, directory path, and file extension for grouping.
func ExtractCacheKey(u *url.URL) CacheKey {
	key := CacheKey{
		Host: u.Host,
		Path: extractDirPath(u.Path),
	}

	// Extract extension from path
	if u.Path != "" {
		ext := path.Ext(u.Path)
		if ext != "" {
			key.Extension = ext
		}
	}

	return key
}

// ExtractCacheKeyForDirectory extracts cache key for a directory URL.
// The path should already end with "/".
func ExtractCacheKeyForDirectory(u *url.URL) CacheKey {
	dirPath := u.Path
	if dirPath == "" {
		dirPath = "/"
	}
	if !strings.HasSuffix(dirPath, "/") {
		dirPath += "/"
	}
	return CacheKey{
		Host:      u.Host,
		Path:      dirPath,
		Extension: "", // Directories have no extension
	}
}

// CacheStats holds cache statistics.
type CacheStats struct {
	TotalKeys       int
	TotalSignatures int
	KeyDetails      map[string]int // key -> signature count
}

// GetStats returns cache statistics
func (c *Cache) GetStats() CacheStats {
	stats := CacheStats{
		KeyDetails: make(map[string]int),
	}

	c.signatures.Range(func(key, value interface{}) bool {
		stats.TotalKeys++

		if k, ok := key.(CacheKey); ok {
			if sigs, ok := value.([]*Signature); ok {
				count := len(sigs)
				stats.TotalSignatures += count
				stats.KeyDetails[k.String()] = count
			}
		}

		return true
	})

	return stats
}

// MatchesWithCascade implements cascading signature check for soft-404 detection.
// This is the primary matching method that should be used instead of Matches().
//
// Check order (for each directory level, from target to root):
// 1. Check current directory signatures (all extensions)
// 2. Check parent directory signatures (all extensions)
// 3. Continue up to root "/"
// 4. Check base extension fallback (sample.php.backup → .php)
//
// Returns true if sample matches any known soft-404 signature.
func (c *Cache) MatchesWithCascade(targetURL *url.URL, sample *Sample) bool {
	host := targetURL.Host
	ext := path.Ext(targetURL.Path)

	// Get directory path from URL (e.g., /bob/admin/file.txt → /bob/admin/)
	dirPath := extractDirPath(targetURL.Path)

	// Cascade through directory hierarchy: /bob/admin/ → /bob/ → /
	for {
		// Check all extensions for this (host, path)
		if c.MatchesAnyForHostPath(host, dirPath, sample) {
			return true
		}

		// Move to parent directory
		if dirPath == "/" || dirPath == "" {
			break
		}
		dirPath = parentDirPath(dirPath)
	}

	// Check base extension fallback (sample.php.backup → .php)
	if ext != "" {
		baseName := strings.TrimSuffix(path.Base(targetURL.Path), ext)
		baseExt := path.Ext(baseName)
		if baseExt != "" && baseExt != ext {
			// Check all directory levels for base extension
			dirPath = extractDirPath(targetURL.Path)
			for {
				baseKey := CacheKey{Host: host, Path: dirPath, Extension: baseExt}
				if c.Matches(baseKey, sample) {
					return true
				}
				if dirPath == "/" || dirPath == "" {
					break
				}
				dirPath = parentDirPath(dirPath)
			}
		}
	}

	return false
}

// extractDirPath extracts the directory path from a URL path.
// /bob/admin/file.txt → /bob/admin/
// /bob/admin/ → /bob/admin/
// /file.txt → /
func extractDirPath(urlPath string) string {
	if urlPath == "" {
		return "/"
	}
	if strings.HasSuffix(urlPath, "/") {
		return urlPath
	}
	dir := path.Dir(urlPath)
	if dir == "." {
		return "/"
	}
	if !strings.HasSuffix(dir, "/") {
		dir += "/"
	}
	return dir
}

// parentDirPath returns the parent directory of a directory path.
// /bob/admin/ → /bob/
// /bob/ → /
// / → /
func parentDirPath(dirPath string) string {
	if dirPath == "/" || dirPath == "" {
		return "/"
	}
	// Remove trailing slash for path.Dir to work correctly
	trimmed := strings.TrimSuffix(dirPath, "/")
	parent := path.Dir(trimmed)
	if parent == "." || parent == "" {
		return "/"
	}
	if !strings.HasSuffix(parent, "/") {
		parent += "/"
	}
	return parent
}

// MatchesAnyForHostPath checks ALL cached signatures for a host and path.
// Used by MatchesWithCascade for cross-extension signature matching.
// Returns true if sample matches ANY signature for the given (host, path).
func (c *Cache) MatchesAnyForHostPath(host, dirPath string, sample *Sample) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	paths, ok := c.pathIndex[host]
	if !ok {
		return false
	}

	extensions, ok := paths[dirPath]
	if !ok {
		return false
	}

	for ext := range extensions {
		key := CacheKey{Host: host, Path: dirPath, Extension: ext}
		if c.Matches(key, sample) {
			return true
		}
	}
	return false
}

// HasSignaturesForHostPath returns true if any signatures exist for the given host and path.
func (c *Cache) HasSignaturesForHostPath(host, dirPath string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	paths, ok := c.pathIndex[host]
	if !ok {
		return false
	}
	_, ok = paths[dirPath]
	return ok
}

// HasSignaturesForHost returns true if any signatures exist for the given host (any path).
func (c *Cache) HasSignaturesForHost(host string) bool {
	c.mu.RLock()
	_, ok := c.pathIndex[host]
	c.mu.RUnlock()
	return ok
}

// PreWarm probes common (path, extension) combinations to seed the fingerprint cache
// before discovery workers start. This front-loads baseline learning and reduces
// inline learning pauses during the main discovery phase.
func (c *Cache) PreWarm(ctx context.Context, baseURL *url.URL) int {
	commonPaths := []string{"/", "/api/", "/admin/", "/static/", "/assets/"}
	commonExts := []string{"", ".html", ".php", ".js", ".json", ".xml", ".asp", ".jsp"}

	type probeTarget struct {
		path string
		ext  string
	}

	var targets []probeTarget
	host := baseURL.Host
	for _, p := range commonPaths {
		for _, ext := range commonExts {
			if c.HasSignaturesForHostPath(host, p) {
				// Already has some signatures for this path — check specific ext
				key := CacheKey{Host: host, Path: p, Extension: ext}
				if _, ok := c.Get(key); ok {
					continue
				}
			}
			targets = append(targets, probeTarget{path: p, ext: ext})
		}
	}

	if len(targets) == 0 {
		return 0
	}

	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	var learned atomic.Int32

	for _, t := range targets {
		if ctx.Err() != nil {
			break
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(p, ext string) {
			defer wg.Done()
			defer func() { <-sem }()

			if ctx.Err() != nil {
				return
			}

			dirURL := *baseURL
			dirURL.Path = p
			key := CacheKey{Host: host, Path: p, Extension: ext}

			if _, err := c.LearnAndCache(ctx, key, &dirURL); err != nil {
				zap.L().Debug("Pre-warm failed",
					zap.String("host", host),
					zap.String("path", p),
					zap.String("ext", ext),
					zap.Error(err))
				return
			}
			learned.Add(1)
		}(t.path, t.ext)
	}

	wg.Wait()
	zap.L().Info("Fingerprint cache pre-warmed",
		zap.String("host", host),
		zap.Int32("learned", learned.Load()),
		zap.Int("total_probes", len(targets)))

	return int(learned.Load())
}
