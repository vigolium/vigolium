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

// defaultDiskSetMaxKeys bounds the number of keys a DiskSet retains before it
// starts evicting. Without a cap, a long-lived dedup Manager (e.g. the
// process-lifetime one in scan-on-receive) lets every DiskSet's on-disk
// keyspace grow without limit as new request/payload fingerprints are seen,
// inflating disk and LevelDB memtables for days. Eviction is FN-safe: an
// evicted fingerprint may be re-processed once, and findings are deduplicated
// again at the database layer.
const defaultDiskSetMaxKeys = 1_000_000

// diskSetEvictBatch is how many keys are dropped each time the cap is crossed,
// amortizing the iterator+batch-delete cost across many inserts.
const diskSetEvictBatch = 16384

// DiskSet provides disk-backed deduplication using LevelDB.
// Thread-safe for concurrent access.
type DiskSet struct {
	db      *leveldb.DB
	mu      sync.RWMutex // RLock guards the IsSeen read fast path; Lock guards inserts/eviction/Close
	hits    atomic.Uint64
	size    atomic.Int64
	maxKeys int64
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

	// MaxKeys caps the retained keyspace; once exceeded, the oldest-in-keyspace
	// keys are evicted in batches. Zero uses defaultDiskSetMaxKeys; a negative
	// value disables the cap (unbounded — legacy behavior).
	MaxKeys int
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

	maxKeys := int64(opts.MaxKeys)
	if opts.MaxKeys == 0 {
		maxKeys = defaultDiskSetMaxKeys
	} else if opts.MaxKeys < 0 {
		maxKeys = 0 // disabled (unbounded)
	}

	return &DiskSet{
		db:      db,
		path:    path,
		cleanup: opts.Cleanup,
		maxKeys: maxKeys,
	}, nil
}

// IsSeen returns true if key was seen before.
// If not seen, marks it as seen atomically.
//
// Hot path: most calls on a warm set are duplicates, so the common case takes
// only a read lock (concurrent with other readers) and a single LevelDB Has.
// Only a genuinely new key escalates to the write lock for the Put. This avoids
// serializing every worker — and every one of the 61 modules sharing a DiskSet
// — behind a single mutex held across LevelDB I/O.
func (d *DiskSet) IsSeen(key string) bool {
	keyBytes := []byte(key)

	d.mu.RLock()
	if d.db == nil {
		d.mu.RUnlock()
		return true // Treat as already seen to stop processing
	}
	has, err := d.db.Has(keyBytes, nil)
	d.mu.RUnlock()
	if err == nil && has {
		d.hits.Add(1)
		return true
	}

	// New (or unreadable) key: take the write lock and insert. Re-check under
	// the lock so a key inserted by another goroutine between the two locks is
	// reported as seen exactly once (keeps dedup precise and the size counter
	// accurate).
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.db == nil {
		return true
	}
	if has, err := d.db.Has(keyBytes, nil); err == nil && has {
		d.hits.Add(1)
		return true
	}
	_ = d.db.Put(keyBytes, nil, nil)
	if d.size.Add(1) > d.maxKeys && d.maxKeys > 0 {
		d.evictLocked()
	}
	return false
}

// evictLocked drops a batch of keys to keep the set under maxKeys. The caller
// must hold d.mu. Eviction order follows LevelDB's key sort order (effectively
// arbitrary), which is acceptable: dropping a fingerprint only risks
// re-processing it once. The batch delete keeps d.db stable (no close/reopen),
// so the lock-free Contains reader is unaffected.
func (d *DiskSet) evictLocked() {
	iter := d.db.NewIterator(nil, nil)
	defer iter.Release()

	batch := new(leveldb.Batch)
	n := 0
	for n < diskSetEvictBatch && iter.Next() {
		// iter.Key() is only valid until the next Next(); copy it.
		batch.Delete(append([]byte(nil), iter.Key()...))
		n++
	}
	if n > 0 {
		if err := d.db.Write(batch, nil); err == nil {
			d.size.Add(int64(-n))
		}
	}
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
