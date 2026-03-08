package dedup

import (
	"encoding/binary"
	"os"
	"sync"
	"sync/atomic"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/filter"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

// DiskSet provides disk-backed deduplication using LevelDB.
// Thread-safe for concurrent access.
type DiskSet struct {
	db      *leveldb.DB
	mu      sync.Mutex // Required for atomic check-then-put in IsSeen
	hits    atomic.Uint64
	size    atomic.Int64
	path    string
	cleanup bool
}

// DiskSetOptions configures DiskSet behavior.
type DiskSetOptions struct {
	// Path is the directory for disk storage.
	// Empty string uses system temp directory.
	Path string

	// Cleanup removes the disk files on Close() if true.
	Cleanup bool
}

// DefaultDiskSetOptions provides sensible defaults.
var DefaultDiskSetOptions = DiskSetOptions{
	Cleanup: true,
}

// NewDiskSet creates a disk-backed dedup set.
func NewDiskSet(opts DiskSetOptions) (*DiskSet, error) {
	path := opts.Path
	if path == "" {
		var err error
		path, err = os.MkdirTemp("", "vigolium-diskset-*")
		if err != nil {
			return nil, err
		}
	}

	dbOpts := &opt.Options{
		Filter:              filter.NewBloomFilter(10), // 10 bits per key
		CompactionTableSize: 32 * opt.MiB,
		WriteBuffer:         4 * opt.MiB,
		BlockCacheCapacity:  2 * opt.MiB,
	}

	db, err := leveldb.OpenFile(path, dbOpts)
	if err != nil {
		return nil, err
	}

	return &DiskSet{
		db:      db,
		path:    path,
		cleanup: opts.Cleanup,
	}, nil
}

// IsSeen returns true if key was seen before.
// If not seen, marks it as seen atomically.
// Thread-safe: mutex ensures atomic check-then-put.
func (d *DiskSet) IsSeen(key string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.db == nil {
		return true // Treat as already seen to stop processing
	}

	keyBytes := []byte(key)
	has, err := d.db.Has(keyBytes, nil)
	if err != nil || !has {
		_ = d.db.Put(keyBytes, nil, nil)
		d.size.Add(1)
		return false
	}

	d.hits.Add(1)
	return true
}

// Contains returns true if key exists (read-only check).
// Does not mark the key as seen if not present.
// Thread-safe: LevelDB handles concurrency internally.
func (d *DiskSet) Contains(key string) bool {
	if d.db == nil {
		return false
	}
	has, err := d.db.Has([]byte(key), nil)
	return err == nil && has
}

// IncrementAndCheck atomically increments counter and checks against limit.
// Returns (newCount, shouldContinue) where shouldContinue is false if limit exceeded.
// Thread-safe: mutex ensures atomic read-modify-write.
func (d *DiskSet) IncrementAndCheck(key string, limit int) (int, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.db == nil {
		return 0, false
	}

	keyBytes := []byte(key)
	var count uint32

	data, err := d.db.Get(keyBytes, nil)
	if err == nil && len(data) == 4 {
		count = binary.LittleEndian.Uint32(data)
	}

	count++
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], count)
	_ = d.db.Put(keyBytes, buf[:], nil)

	return int(count), int(count) <= limit
}

// Size returns the number of unique keys stored.
func (d *DiskSet) Size() int64 {
	return d.size.Load()
}

// Hits returns the number of duplicate keys detected.
func (d *DiskSet) Hits() uint64 {
	return d.hits.Load()
}

// Close releases resources and optionally removes disk files.
func (d *DiskSet) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.db == nil {
		return nil
	}

	err := d.db.Close()
	d.db = nil

	if d.cleanup && d.path != "" {
		_ = os.RemoveAll(d.path)
	}

	return err
}
