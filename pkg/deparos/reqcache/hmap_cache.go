// Package reqcache provides request deduplication using disk storage.
package reqcache

import (
	"os"

	"github.com/vigolium/vigolium/pkg/deparos/internal/dedup"
)

// Config holds cache configuration.
type Config struct {
	// Path is the directory for disk storage.
	// Empty string uses system temp directory.
	Path string

	// Cleanup removes cache on Close() if true.
	Cleanup bool
}

// HMapCache provides request deduplication using LevelDB.
// Thread-safe for concurrent access.
type HMapCache struct {
	ds *dedup.DiskSet
}

// NewHMapCache creates a new disk-backed request cache.
func NewHMapCache(cfg *Config) (*HMapCache, error) {
	if cfg == nil {
		cfg = &Config{Cleanup: true}
	}

	basePath := cfg.Path
	if basePath == "" {
		var err error
		basePath, err = os.MkdirTemp("", "reqcache-*")
		if err != nil {
			return nil, err
		}
	}

	ds, err := dedup.NewDiskSet(&dedup.Config{
		BasePath:  basePath,
		Namespace: "reqcache",
		Cleanup:   cfg.Cleanup,
	})
	if err != nil {
		return nil, err
	}

	return &HMapCache{ds: ds}, nil
}

// IsSeen returns true if the request was seen before.
// If not seen, marks it as seen atomically.
func (c *HMapCache) IsSeen(method, urlStr, body string) bool {
	key := dedup.HashRequest(method, urlStr, body)
	return c.ds.IsSeen(key)
}

// Size returns the number of unique requests cached.
func (c *HMapCache) Size() int64 {
	return c.ds.Size()
}

// Hits returns the number of duplicate requests detected.
func (c *HMapCache) Hits() uint64 {
	return c.ds.Hits()
}

// Close releases resources and optionally cleans up disk files.
func (c *HMapCache) Close() error {
	if c.ds != nil {
		return c.ds.Close()
	}
	return nil
}
