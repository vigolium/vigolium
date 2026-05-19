package tracker

import (
	"github.com/vigolium/vigolium/pkg/deparos/internal/dedup"
)

// URLTracker tracks URLs using disk-backed deduplication.
// Thread-safe for concurrent access.
type URLTracker struct {
	ds *dedup.DiskSet
}

// Config holds URLTracker configuration.
type Config struct {
	// BasePath is the base directory for disk storage.
	// Empty string uses system temp directory.
	BasePath string

	// Namespace isolates this tracker from others.
	Namespace string

	// Cleanup removes disk files on Close() if true.
	Cleanup bool
}

// New creates a new URL tracker with default temp storage.
// namespace should be unique per tracker instance (e.g., "directories", "files").
func New(namespace string) *URLTracker {
	ds, _ := dedup.NewDiskSet(&dedup.Config{
		Namespace: namespace,
		Cleanup:   true,
	})
	return &URLTracker{ds: ds}
}

// NewWithConfig creates a URL tracker with explicit configuration.
func NewWithConfig(cfg *Config) (*URLTracker, error) {
	if cfg == nil {
		cfg = &Config{Cleanup: true}
	}

	ds, err := dedup.NewDiskSet(&dedup.Config{
		BasePath:  cfg.BasePath,
		Namespace: cfg.Namespace,
		Cleanup:   cfg.Cleanup,
	})
	if err != nil {
		return nil, err
	}

	return &URLTracker{ds: ds}, nil
}

// HasBeenSeen returns true if URL has already been tracked.
func (t *URLTracker) HasBeenSeen(url string) bool {
	return t.ds.Contains(url)
}

// MarkSeen marks a URL as seen.
func (t *URLTracker) MarkSeen(url string) {
	t.ds.IsSeen(url)
}

// MarkSeenIfNew marks a URL as seen and returns true if newly added.
func (t *URLTracker) MarkSeenIfNew(url string) bool {
	return !t.ds.IsSeen(url)
}

// Size returns the number of unique URLs tracked.
func (t *URLTracker) Size() int64 {
	return t.ds.Size()
}

// Close releases resources and optionally removes disk files.
func (t *URLTracker) Close() error {
	if t.ds != nil {
		return t.ds.Close()
	}
	return nil
}
