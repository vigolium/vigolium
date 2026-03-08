// Package dedup provides disk-backed deduplication using LevelDB.
package dedup

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/filter"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

// DiskSet provides disk-backed deduplication using LevelDB with internal bloom filter.
// Thread-safe for concurrent access.
type DiskSet struct {
	db      *leveldb.DB
	mu      sync.Mutex // Required for atomic check-then-put in IsSeen
	hits    atomic.Uint64
	size    atomic.Int64
	path    string
	cleanup bool
}

// Config holds DiskSet configuration.
type Config struct {
	// BasePath is the base directory for disk storage.
	// Empty string uses system temp directory.
	BasePath string

	// Namespace isolates this DiskSet from others in the same BasePath.
	Namespace string

	// Cleanup removes the disk files on Close() if true.
	Cleanup bool
}

// NewDiskSet creates a disk-backed dedup set.
func NewDiskSet(cfg *Config) (*DiskSet, error) {
	if cfg == nil {
		cfg = &Config{Cleanup: true}
	}

	basePath := cfg.BasePath
	if basePath == "" {
		basePath = os.TempDir()
	}

	path := basePath
	if cfg.Namespace != "" {
		path = filepath.Join(basePath, cfg.Namespace)
	}

	opts := &opt.Options{
		Filter:              filter.NewBloomFilter(10), // LevelDB internal bloom (10 bits/key)
		CompactionTableSize: 32 * opt.MiB,
		WriteBuffer:         4 * opt.MiB,
		BlockCacheCapacity:  2 * opt.MiB,
	}

	db, err := leveldb.OpenFile(path, opts)
	if err != nil {
		return nil, fmt.Errorf("open leveldb at %s: %w", path, err)
	}

	return &DiskSet{
		db:      db,
		path:    path,
		cleanup: cfg.Cleanup,
	}, nil
}

// IsSeen returns true if key was seen before.
// If not seen, marks it as seen atomically.
// Thread-safe: mutex ensures atomic check-then-put.
func (s *DiskSet) IsSeen(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if DB is already closed (graceful shutdown)
	if s.db == nil {
		return true // Treat as already seen to stop processing
	}

	keyBytes := []byte(key)
	has, err := s.db.Has(keyBytes, nil)
	if err != nil || !has {
		_ = s.db.Put(keyBytes, nil, nil)
		s.size.Add(1)
		return false
	}

	s.hits.Add(1)
	return true
}

// Contains returns true if key exists (read-only check).
// Does not mark the key as seen if not present.
// Thread-safe: LevelDB handles concurrency internally.
func (s *DiskSet) Contains(key string) bool {
	keyBytes := []byte(key)
	has, err := s.db.Has(keyBytes, nil)
	return err == nil && has
}

// Size returns the number of unique keys stored.
func (s *DiskSet) Size() int64 {
	return s.size.Load()
}

// Hits returns the number of duplicate keys detected.
func (s *DiskSet) Hits() uint64 {
	return s.hits.Load()
}

// Close releases resources and optionally removes disk files.
func (s *DiskSet) Close() error {
	if s.db == nil {
		return nil
	}

	err := s.db.Close()
	s.db = nil

	if s.cleanup && s.path != "" {
		_ = os.RemoveAll(s.path)
	}

	return err
}
