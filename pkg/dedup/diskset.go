package dedup

import (
	"encoding/binary"
	"os"
	"sync"
	"sync/atomic"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/filter"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/vigolium/vigolium/internal/scratch"
	"go.uber.org/zap"
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

// memTierMaxKeys is how many keys a set holds in memory before it spills to
// LevelDB. Sized so the common case never touches the disk while a real
// workload still gets the bounded, on-disk keyspace it needs: at roughly 80
// bytes per fingerprint this is well under a megabyte per set, and a scan that
// opens seventeen of them stays in single-digit megabytes.
const memTierMaxKeys = 8192

// DiskSet provides deduplication with a bounded in-memory tier that spills to
// LevelDB. Thread-safe for concurrent access.
//
// The disk tier is allocated lazily, on the first key past memTierMaxKeys.
// Opening it eagerly made every set cost an os.MkdirTemp, a LevelDB open, a
// manifest fsync and a RemoveAll — and sets are per module, so a probe of ONE
// host paid that seventeen times over for a handful of fingerprints that never
// came close to needing a database. Most sets in most scans never spill.
type DiskSet struct {
	db *leveldb.DB // nil until the set spills

	// mem is the pre-spill tier, and is nil once db exists. Values are the same
	// bytes LevelDB would hold, so IncrementAndCheck's counters work in either
	// tier without a second representation.
	mem map[string][]byte

	mu      sync.RWMutex // RLock guards the IsSeen read fast path; Lock guards inserts/eviction/spill/Close
	hits    atomic.Uint64
	size    atomic.Int64
	maxKeys int64
	path    string // empty until the set spills, or set from Options.Path
	cleanup bool

	// spillFailed records that spilling was attempted and did not work, so it is
	// not attempted again.
	//
	// Without it, a set past its memory tier retries the spill on EVERY
	// subsequent new key: an os.MkdirTemp plus a LevelDB open (which creates a
	// directory, writes a manifest and fsyncs) per insert, all under the write
	// lock, on IsSeen — the hottest path in the scanner, shared by every module
	// holding this set. The condition that makes spilling fail is a full or
	// read-only disk, which does not clear on its own within a scan, so those
	// retries are a syscall storm that serializes the scan and cannot succeed.
	//
	// Staying on the memory tier is the documented fallback and is already
	// bounded by maxKeys, so giving up costs nothing beyond the disk tier this
	// set was never going to get.
	spillFailed bool
}

// diskSetLevelDBOpts is shared by every set: it carries no per-instance state,
// and a change whose point is that a set costs nothing until it spills should
// not allocate an opt.Options plus a bloom filter per set to hold constants.
var diskSetLevelDBOpts = &opt.Options{
	Filter:              filter.NewBloomFilter(10), // 10 bits per key
	CompactionTableSize: 32 * opt.MiB,
	WriteBuffer:         4 * opt.MiB,
	BlockCacheCapacity:  2 * opt.MiB,
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

// NewDiskSet creates a dedup set. It touches the disk only if the caller pinned
// an explicit Path; otherwise the set starts in memory and allocates its
// LevelDB on the first key past memTierMaxKeys.
func NewDiskSet(opts DiskSetOptions) (*DiskSet, error) {
	maxKeys := int64(opts.MaxKeys)
	if opts.MaxKeys == 0 {
		maxKeys = defaultDiskSetMaxKeys
	} else if opts.MaxKeys < 0 {
		maxKeys = 0 // disabled (unbounded)
	}

	ds := &DiskSet{
		path:    opts.Path,
		cleanup: opts.Cleanup,
		maxKeys: maxKeys,
	}

	// An explicit Path names a store the caller wants on disk — very likely one
	// meant to outlive this process — so honour it immediately rather than
	// deferring to a spill that may never happen.
	if opts.Path != "" {
		db, err := leveldb.OpenFile(opts.Path, diskSetLevelDBOpts)
		if err != nil {
			return nil, err
		}
		ds.db = db
		return ds, nil
	}

	ds.mem = make(map[string][]byte)
	return ds, nil
}

// spillLocked moves the memory tier into a freshly opened LevelDB. The caller
// must hold d.mu for writing.
//
// A failure here leaves the set on its memory tier rather than failing the
// scan: dedup that stops growing is a bounded loss (a fingerprint may be
// re-processed, and findings are deduplicated again at the database layer),
// whereas losing the set outright is not.
func (d *DiskSet) spillLocked() {
	// Under the scratch root, not bare os.TempDir(): a run killed before Close
	// leaks its stores forever. See internal/scratch.
	path, err := scratch.MkdirTemp("diskset-*")
	if err != nil {
		d.markSpillFailed("create scratch directory", err)
		return
	}
	db, err := leveldb.OpenFile(path, diskSetLevelDBOpts)
	if err != nil {
		_ = os.RemoveAll(path)
		d.markSpillFailed("open LevelDB", err)
		return
	}

	batch := new(leveldb.Batch)
	for k, v := range d.mem {
		batch.Put([]byte(k), v)
	}
	if err := db.Write(batch, nil); err != nil {
		_ = db.Close()
		_ = os.RemoveAll(path)
		d.markSpillFailed("write memory tier", err)
		return
	}

	d.db = db
	d.path = path
	d.mem = nil
}

// markSpillFailed records a failed spill so it is not retried, and says so once.
// The caller must hold d.mu for writing.
//
// Logged at warn because the consequence is real but silent otherwise: the set
// keeps deduplicating from memory under its key cap, so a long scan can start
// evicting and re-processing fingerprints it would have remembered on disk. One
// line per set, not per insert, since the flag makes this reachable only once.
func (d *DiskSet) markSpillFailed(step string, err error) {
	d.spillFailed = true
	zap.L().Warn("dedup set could not spill to disk; continuing in memory",
		zap.String("step", step),
		zap.Int("memory_keys", len(d.mem)),
		zap.Int64("max_keys", d.maxKeys),
		zap.Error(err))
}

// hasLocked reports whether key is present in whichever tier is live. The
// caller must hold d.mu (read or write).
//
// Keyed on string, not []byte, because the memory tier is the common case and
// IsSeen is the hottest path in the scanner - once per response per passive
// module. A []byte conversion in the caller escapes unconditionally (hasLocked
// may hand it to LevelDB), so it heap-allocated on every call even for sets
// that never spill. Converting inside the db branch instead puts the cost next
// to a LevelDB call that dwarfs it.
func (d *DiskSet) hasLocked(key string) bool {
	if d.db != nil {
		has, err := d.db.Has([]byte(key), nil)
		return err == nil && has
	}
	_, ok := d.mem[key]
	return ok
}

// putLocked writes key/value into whichever tier is live, spilling first if the
// memory tier is full. The caller must hold d.mu for writing.
func (d *DiskSet) putLocked(key string, value []byte) {
	if d.db == nil && !d.spillFailed && len(d.mem) >= memTierMaxKeys {
		d.spillLocked()
	}
	if d.db != nil {
		_ = d.db.Put([]byte(key), value, nil)
		return
	}
	d.mem[key] = value
}

// closedLocked reports whether Close has already released this set.
func (d *DiskSet) closedLocked() bool {
	return d.db == nil && d.mem == nil
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
	d.mu.RLock()
	if d.closedLocked() {
		d.mu.RUnlock()
		return true // Treat as already seen to stop processing
	}
	has := d.hasLocked(key)
	d.mu.RUnlock()
	if has {
		d.hits.Add(1)
		return true
	}

	// New (or unreadable) key: take the write lock and insert. Re-check under
	// the lock so a key inserted by another goroutine between the two locks is
	// reported as seen exactly once (keeps dedup precise and the size counter
	// accurate).
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closedLocked() {
		return true
	}
	if d.hasLocked(key) {
		d.hits.Add(1)
		return true
	}
	d.putLocked(key, nil)
	if d.size.Add(1) > d.maxKeys && d.maxKeys > 0 {
		d.evictLocked()
	}
	return false
}

// evictLocked drops a batch of keys to keep the set under maxKeys. The caller
// must hold d.mu for writing. Eviction order is effectively arbitrary in either
// tier (LevelDB's key sort order; Go's map iteration order), which is
// acceptable: dropping a fingerprint only risks re-processing it once.
func (d *DiskSet) evictLocked() {
	if d.db == nil {
		n := 0
		for k := range d.mem {
			delete(d.mem, k)
			n++
			if n >= diskSetEvictBatch {
				break
			}
		}
		d.size.Add(int64(-n))
		return
	}

	// The batch delete keeps d.db stable (no close/reopen), so concurrent
	// readers are unaffected.
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

// ClaimOnMatch is the second half of match-first dedup: a module checks
// Contains(key) up front (cheap, read-only skip of an already-reported key),
// analyses the response, and only once it has actually MATCHED calls
// ClaimOnMatch(key). It returns true when this call won the claim (the key was
// new) and the caller should report; false when a concurrent caller claimed it
// first (or the set is closed).
//
// Calling IsSeen before matching marked a host "done" on its first response
// whether or not anything was found there, so a fingerprint visible only on a
// later response (an error page, a login form) was never reported.
func (d *DiskSet) ClaimOnMatch(key string) bool {
	return !d.IsSeen(key)
}

// Contains returns true if key exists (read-only check).
// Does not mark the key as seen if not present.
//
// The read lock is required, not decorative: the pre-spill tier is a Go map, so
// unlike LevelDB it does not carry its own concurrency guarantees.
func (d *DiskSet) Contains(key string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closedLocked() {
		return false
	}
	return d.hasLocked(key)
}

// IncrementAndCheck atomically increments counter and checks against limit.
// Returns (newCount, shouldContinue) where shouldContinue is false if limit exceeded.
// Thread-safe: mutex ensures atomic read-modify-write.
func (d *DiskSet) IncrementAndCheck(key string, limit int) (int, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closedLocked() {
		return 0, false
	}

	var count uint32

	if data, ok := d.getLocked(key); ok && len(data) == 4 {
		count = binary.LittleEndian.Uint32(data)
	}

	count++
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], count)
	d.putLocked(key, buf[:])

	return int(count), int(count) <= limit
}

// getLocked reads key from whichever tier is live. The caller must hold d.mu.
func (d *DiskSet) getLocked(key string) ([]byte, bool) {
	if d.db != nil {
		data, err := d.db.Get([]byte(key), nil)
		return data, err == nil
	}
	v, ok := d.mem[key]
	return v, ok
}

// Size returns the number of unique keys stored.
func (d *DiskSet) Size() int64 {
	return d.size.Load()
}

// Hits returns the number of duplicate keys detected.
func (d *DiskSet) Hits() uint64 {
	return d.hits.Load()
}

// Close releases resources and optionally removes disk files. A set that never
// spilled has nothing on disk to remove; dropping the map is the whole of it.
func (d *DiskSet) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closedLocked() {
		return nil
	}

	d.mem = nil

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
