package database

import (
	"context"
	"errors"
	"fmt"
	"hash/maphash"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"go.uber.org/zap"
)

// RecordWriterConfig configures the batching behavior of RecordWriter.
type RecordWriterConfig struct {
	// BufferSize is the channel capacity. Senders block when the buffer is full,
	// providing natural backpressure. Default: 4096.
	BufferSize int

	// BatchSize is the maximum number of records flushed in a single transaction.
	// Default: 128.
	BatchSize int

	// FlushInterval is the maximum time a record waits in the buffer before
	// being flushed, even if the batch isn't full. Default: 50ms.
	FlushInterval time.Duration

	// Shards is the number of independent flush goroutines. Each shard has its
	// own channel and flushLoop. Records are routed to shards by hashing the
	// host name, so writes for the same host are serialized within a shard.
	// Default (when <= 0): 1 for SQLite, 4 for PostgreSQL. SQLite is a
	// single-writer database, so multiple flush goroutines would only contend
	// on BEGIN IMMEDIATE / busy_timeout without gaining write parallelism;
	// PostgreSQL supports genuinely concurrent writers, so it fans out.
	Shards int

	// FlushTimeout bounds the shutdown drain, not steady-state flushes. Normal
	// flushes run on an uncancellable context.Background() so a slow insert never
	// drops records; only the drain triggered by Close() is capped by this single
	// budget, so a wedged database can't block Close() forever while a healthy one
	// still drains in full. Default: 2m (far longer than any healthy drain).
	FlushTimeout time.Duration

	// DedupCacheSize bounds the in-memory dedup cache (LRU) that maps a record's
	// dedup key to its UUID. A cache hit lets Write skip the per-record SELECT and
	// the redundant insert for a key already seen by this writer (common in
	// discovery/spidering, which re-encounter the same URLs). 0 disables the
	// cache. Default: 50000.
	DedupCacheSize int
}

func (c *RecordWriterConfig) withDefaults() RecordWriterConfig {
	out := *c
	if out.BufferSize <= 0 {
		out.BufferSize = 4096
	}
	if out.BatchSize <= 0 {
		out.BatchSize = 128
	}
	if out.FlushInterval <= 0 {
		out.FlushInterval = 50 * time.Millisecond
	}
	// Shards is defaulted driver-aware in NewRecordWriter (1 for SQLite, 4 for
	// PostgreSQL); leave a non-positive value untouched here so that decision
	// has the driver available.
	if out.FlushTimeout <= 0 {
		out.FlushTimeout = 2 * time.Minute
	}
	if out.DedupCacheSize == 0 {
		out.DedupCacheSize = 50000
	}
	return out
}

// writeRequest is an internal request sent to the flush goroutine.
type writeRequest struct {
	record *HTTPRecord
	result chan<- WriteResult
}

// WriteResult is the outcome of a single record write.
type WriteResult struct {
	UUID string
	Err  error
}

// RecordWriterMetrics exposes counters for monitoring.
type RecordWriterMetrics struct {
	Enqueued    int64
	Flushed     int64
	FlushErrors int64
	BatchCount  int64
	BufferDepth int64
}

// writerShard is a single flush goroutine with its own channel.
type writerShard struct {
	ch chan writeRequest
}

// RecordWriter serializes database writes through sharded goroutines that
// coalesce individual SaveRecord calls into batch transactions.
// Records are routed to shards by hashing the host name, so writes for the
// same host are serialized within a shard. With Shards=1 (default), behavior
// is identical to a single-goroutine writer.
// This eliminates SQLite SQLITE_BUSY errors under concurrent ingestion.
type RecordWriter struct {
	repo   *Repository
	cfg    RecordWriterConfig
	shards []*writerShard

	// aggregate metrics (sum across shards)
	enqueued    atomic.Int64
	flushed     atomic.Int64
	flushErrors atomic.Int64
	batchCount  atomic.Int64

	ctx    context.Context
	cancel context.CancelFunc
	closed atomic.Bool
	wg     sync.WaitGroup

	// admitMu + admitWG form the shutdown admission gate. A write takes admitMu
	// for read, checks closed, and (if open) adds itself to admitWG before
	// enqueueing; Close takes admitMu for write to set closed, then admitWG.Wait()s
	// for every in-flight enqueue to finish BEFORE cancelling the flush context.
	// This guarantees the drain observes every admitted record (no orphan) and that
	// an admitted write is never told it failed while its record was persisted —
	// once admitted, a write only awaits its real result.
	admitMu sync.RWMutex
	admitWG sync.WaitGroup

	// dedupCache maps a record's dedup key → UUID so a key already seen by this
	// writer skips the per-record SELECT and the redundant insert. nil disables it.
	dedupCache *lru.Cache[string, string]
}

// beginAdmit reserves an admission slot unless the writer is closing. On true the
// caller MUST call w.admitWG.Done() exactly once after its enqueue attempt
// finishes (whether the send succeeded or was abandoned on the caller's ctx).
// Holding admitMu.RLock across the closed check + Add makes it impossible for a
// write to admit after Close has taken the write lock and observed the count.
func (w *RecordWriter) beginAdmit() bool {
	w.admitMu.RLock()
	defer w.admitMu.RUnlock()
	if w.closed.Load() {
		return false
	}
	w.admitWG.Add(1)
	return true
}

// hashSeed is a package-level seed for consistent host hashing within
// a process lifetime.
var hashSeed = maphash.MakeSeed()

// ErrRecordWriterClosed is returned when writes are attempted after shutdown starts.
var ErrRecordWriterClosed = errors.New("record writer is closed")

// NewRecordWriter creates and starts a RecordWriter.
// Call Close() to flush remaining records and stop the background goroutines.
func NewRecordWriter(repo *Repository, cfg RecordWriterConfig) *RecordWriter {
	cfg = cfg.withDefaults()

	// Driver-aware shard default: SQLite has a single writer, so extra flush
	// goroutines only fight over BEGIN IMMEDIATE / busy_timeout. PostgreSQL has
	// real concurrent writers and benefits from fan-out.
	if cfg.Shards <= 0 {
		if repo != nil && repo.DB() != nil && repo.DB().Driver() == "postgres" {
			cfg.Shards = 4
		} else {
			cfg.Shards = 1
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	w := &RecordWriter{
		repo:   repo,
		cfg:    cfg,
		shards: make([]*writerShard, cfg.Shards),
		ctx:    ctx,
		cancel: cancel,
	}

	if cfg.DedupCacheSize > 0 {
		// Error only on a non-positive size, already guarded above.
		w.dedupCache, _ = lru.New[string, string](cfg.DedupCacheSize)
	}

	for i := range w.shards {
		s := &writerShard{
			ch: make(chan writeRequest, cfg.BufferSize),
		}
		w.shards[i] = s

		w.wg.Add(1)
		go w.flushLoop(ctx, s)
	}

	return w
}

// pendingWrite is the outcome of admitting one record: either it resolved
// immediately (cache hit, invalid input, or an enqueue abandoned on the caller's
// ctx) with uuid/err set, or it was enqueued and its result must be awaited on
// resultCh (dedupKey caches the resolved UUID on success).
type pendingWrite struct {
	dedupKey string
	resultCh chan WriteResult
	uuid     string
	err      error
	resolved bool
}

// admit converts a record, checks the dedup cache, and — on a miss — enqueues it
// to its shard through the admission gate WITHOUT waiting. Shared by Write (one
// record) and SaveRecordBatch (admit all, then await all), so a lone bulk caller
// fills real writer batches instead of paying one flush interval per record.
func (w *RecordWriter) admit(ctx context.Context, rr *httpmsg.HttpRequestResponse, source, projectUUID string) pendingWrite {
	if rr == nil || rr.Request() == nil {
		return pendingWrite{err: fmt.Errorf("invalid HttpRequestResponse"), resolved: true}
	}
	record := &HTTPRecord{}
	if err := record.FromHttpRequestResponse(rr); err != nil {
		return pendingWrite{err: fmt.Errorf("failed to convert request: %w", err), resolved: true}
	}
	record.Source = source
	// Default the project UUID before the dedup lookup so it matches what
	// SaveRecordsBatch persists. Otherwise an empty projectUUID makes the lookup
	// filter on project_uuid="" while inserts land under DefaultProjectUUID, and
	// duplicates slip through.
	record.ProjectUUID = defaultProjectUUID(projectUUID)

	// Fast path: a key already seen by this writer (cross-request repeat, common in
	// discovery/spidering) skips both the dedup SELECT and the redundant insert. On
	// a miss the flush goroutine runs the duplicate check in one batched query.
	dedupKey := recordDedupKey(record)
	if w.dedupCache != nil {
		if existingUUID, ok := w.dedupCache.Get(dedupKey); ok {
			return pendingWrite{uuid: existingUUID, resolved: true}
		}
	}

	// Admission gate: once admitted, Close() waits for this enqueue to finish
	// before draining, so the drain is guaranteed to flush the record and deliver
	// its result — no orphaned request, and no "closed" error for a persisted row.
	if !w.beginAdmit() {
		return pendingWrite{err: ErrRecordWriterClosed, resolved: true}
	}

	resultCh := make(chan WriteResult, 1)
	w.enqueued.Add(1)
	shard := w.shardFor(record.Hostname)

	// w.ctx is NOT cancelled while any admission is outstanding (Close waits for
	// admitWG before cancelling), so the flush loop is alive and consuming; the
	// send can only wait on buffer space, never on shutdown. Only the caller's own
	// ctx can abandon the send.
	select {
	case shard.ch <- writeRequest{record: record, result: resultCh}:
		w.admitWG.Done() // admitted; the drain now owns delivering our result
		return pendingWrite{dedupKey: dedupKey, resultCh: resultCh}
	case <-ctx.Done():
		w.admitWG.Done() // never sent; nothing to deliver
		return pendingWrite{err: ctx.Err(), resolved: true}
	}
}

// await returns an admitted record's result, blocking on the flush loop / drain
// (which always delivers exactly one result to an admitted request). Only the
// caller's ctx may abandon the wait; a concurrent Close() no longer fails an
// already-accepted write. Caches the resolved UUID on success.
func (w *RecordWriter) await(ctx context.Context, p pendingWrite) (string, error) {
	if p.resolved {
		return p.uuid, p.err
	}
	var res WriteResult
	select {
	case res = <-p.resultCh:
	case <-ctx.Done():
		res = WriteResult{Err: ctx.Err()}
	}
	if res.Err == nil {
		w.cacheDedup(p.dedupKey, res.UUID)
	}
	return res.UUID, res.Err
}

// Write enqueues a record for batched insertion.
// It blocks until the record is persisted (or the context is cancelled).
// This is safe to call from multiple goroutines concurrently.
func (w *RecordWriter) Write(ctx context.Context, rr *httpmsg.HttpRequestResponse, source string, projectUUID string) (string, error) {
	if w.closed.Load() {
		return "", ErrRecordWriterClosed
	}
	return w.await(ctx, w.admit(ctx, rr, source, projectUUID))
}

// cacheDedup records a dedup key → UUID mapping so a later Write of the same key
// short-circuits the SELECT and insert. No-op for an empty UUID or disabled cache.
func (w *RecordWriter) cacheDedup(key, uuid string) {
	if w.dedupCache != nil && uuid != "" {
		w.dedupCache.Add(key, uuid)
	}
}

// recordDedupKey builds the in-memory dedup key. It MUST mirror the columns
// findDuplicateRecordUUIDs matches on: (project_uuid, method, hostname, path, url),
// plus request_hash when the request carries a body OR its source requires exact
// identity (finding-evidence records) — otherwise the cache/batch grouping would
// collapse distinct payloads (or a header-only finding probe) to the same endpoint
// into one entry, diverging from the DB dedup and mislinking evidence.
func recordDedupKey(r *HTTPRecord) string {
	var b strings.Builder
	b.Grow(len(r.ProjectUUID) + len(r.Method) + len(r.Hostname) + len(r.Path) + len(r.URL) + len(r.RequestHash) + 6)
	b.WriteString(r.ProjectUUID)
	b.WriteByte('\x00')
	b.WriteString(r.Method)
	b.WriteByte('\x00')
	b.WriteString(r.Hostname)
	b.WriteByte('\x00')
	b.WriteString(r.Path)
	b.WriteByte('\x00')
	b.WriteString(r.URL)
	if r.RequestContentLength > 0 || recordSourceRequiresExactIdentity(r.Source) {
		b.WriteByte('\x00')
		b.WriteString(r.RequestHash)
	}
	return b.String()
}

// shardFor returns the shard responsible for the given hostname.
func (w *RecordWriter) shardFor(host string) *writerShard {
	if len(w.shards) == 1 {
		return w.shards[0]
	}
	var h maphash.Hash
	h.SetSeed(hashSeed)
	h.WriteString(host)
	idx := h.Sum64() % uint64(len(w.shards))
	return w.shards[idx]
}

// Metrics returns a snapshot of the writer's counters.
func (w *RecordWriter) Metrics() RecordWriterMetrics {
	var bufferDepth int64
	for _, s := range w.shards {
		bufferDepth += int64(len(s.ch))
	}
	return RecordWriterMetrics{
		Enqueued:    w.enqueued.Load(),
		Flushed:     w.flushed.Load(),
		FlushErrors: w.flushErrors.Load(),
		BatchCount:  w.batchCount.Load(),
		BufferDepth: bufferDepth,
	}
}

// SaveRecord implements the network.RecordSaver interface by delegating to Write.
func (w *RecordWriter) SaveRecord(ctx context.Context, rr *httpmsg.HttpRequestResponse, source string, projectUUID string) (string, error) {
	return w.Write(ctx, rr, source, projectUUID)
}

// SaveRecordBatch enqueues every record to its shard BEFORE awaiting any result,
// so a single bulk producer's records land in the same writer batch instead of
// paying one flush interval per record (the trap of a Write-in-a-loop: Write
// blocks until its record is flushed, so a lone producer never fills a batch).
// Results are returned positionally aligned with the input — uuids[i] corresponds
// to records[i] — including deduplicated, invalid, and failed entries, so callers
// can't misassociate a UUID. The first error encountered is returned alongside
// the (still complete) uuid slice.
func (w *RecordWriter) SaveRecordBatch(ctx context.Context, records []*httpmsg.HttpRequestResponse, source string, projectUUID string) ([]string, error) {
	uuids := make([]string, len(records))
	if len(records) == 0 {
		return uuids, nil
	}
	if w.closed.Load() {
		return uuids, ErrRecordWriterClosed
	}

	// Phase 1: admit ALL records without waiting, so they sit in the shard channels
	// together and the flush loop coalesces them into real batches.
	pend := make([]pendingWrite, len(records))
	for i, rr := range records {
		pend[i] = w.admit(ctx, rr, source, projectUUID)
	}

	// Phase 2: collect results in input order.
	var firstErr error
	for i := range pend {
		uuid, err := w.await(ctx, pend[i])
		uuids[i] = uuid
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return uuids, firstErr
}

// Close stops accepting new writes, flushes remaining records, and returns.
//
// Ordering matters: it marks the writer closed under the admission write lock (so
// no new write can admit past this point), waits for every already-admitted
// enqueue to finish landing in a shard channel, and only THEN cancels the flush
// context. That guarantees the shutdown drain observes every admitted record —
// none is orphaned in a channel after the flush loop exits, and every admitted
// write receives its real result instead of a spurious "closed" error.
func (w *RecordWriter) Close() {
	w.admitMu.Lock()
	if w.closed.Load() {
		w.admitMu.Unlock()
		return
	}
	w.closed.Store(true)
	w.admitMu.Unlock()

	w.admitWG.Wait() // all in-flight enqueues have landed (or been abandoned)
	w.cancel()       // now the drain sees every admitted record
	w.wg.Wait()
}

// flushLoop is the goroutine that drains a shard's channel and batch-inserts.
// Steady-state flushes (batch-full and ticker) use an uncancellable
// context.Background(): when Close() cancels w.ctx mid-flush, propagating that
// cancellation would abort the in-flight SQL transaction and lose records that
// were already pulled from the channel, so a slow insert must never be
// cancelled during normal operation. The shutdown drain (the ctx.Done() branch)
// is the only path that bounds its flushes — with a single FlushTimeout budget
// for the whole drain — so a wedged database can't hang Close() forever while
// healthy databases still drain in full.
func (w *RecordWriter) flushLoop(ctx context.Context, s *writerShard) {
	defer w.wg.Done()

	batch := make([]writeRequest, 0, w.cfg.BatchSize)
	ticker := time.NewTicker(w.cfg.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case req := <-s.ch:
			batch = append(batch, req)
			if len(batch) >= w.cfg.BatchSize {
				w.flush(context.Background(), batch)
				batch = batch[:0]
				ticker.Reset(w.cfg.FlushInterval)
			}

		case <-ticker.C:
			if len(batch) > 0 {
				w.flush(context.Background(), batch)
				batch = batch[:0]
			}

		case <-ctx.Done():
			// Shutdown drain. Bound the total flush time with a single budget so
			// Close() returns even against a wedged database; against a healthy
			// one every buffered batch still flushes well within it.
			drainCtx, cancel := context.WithTimeout(context.Background(), w.cfg.FlushTimeout)
			for {
				select {
				case req := <-s.ch:
					batch = append(batch, req)
					if len(batch) >= w.cfg.BatchSize {
						w.flush(drainCtx, batch)
						batch = batch[:0]
					}
				default:
					if len(batch) > 0 {
						w.flush(drainCtx, batch)
					}
					cancel()
					return
				}
			}
		}
	}
}

// flush resolves a batch of records and notifies callers. It first runs one
// batched duplicate lookup for the whole batch (replacing the per-record SELECT
// that used to sit on the scan worker's hot path), returns the existing UUID for
// any record that already lives in the database, collapses identical new records
// within the batch to a single insert, and inserts the remaining distinct new
// records in one transaction.
//
// The caller chooses the context: flushLoop uses an uncancellable
// context.Background() for steady-state flushes and a bounded context only for
// the shutdown drain (see flushLoop).
func (w *RecordWriter) flush(ctx context.Context, batch []writeRequest) {
	w.batchCount.Add(1)

	records := make([]*HTTPRecord, len(batch))
	for i, req := range batch {
		records[i] = req.record
	}

	// Batched duplicate lookup. On failure, fall back to treating every record as
	// new (all ""), matching the prior behavior where a failed dedup SELECT still
	// proceeded to insert; the post-scan dedup passes reconcile any duplicates.
	existing, err := w.repo.findDuplicateRecordUUIDs(ctx, records)
	if err != nil {
		zap.L().Debug("RecordWriter batched dedup lookup failed; inserting all",
			zap.Int("batch_size", len(batch)), zap.Error(err))
		existing = make([]string, len(batch))
	}

	// Partition into pre-existing duplicates (existing[i] != "") and new records,
	// collapsing identical new records in this batch so two callers with the same
	// key share one insert and one UUID instead of racing to insert two rows.
	// rep[i] points a new record at the batch index that carries its insert (its
	// own, or an earlier duplicate's); it is unused for pre-existing duplicates.
	rep := make([]int, len(batch))
	groups := make(map[string]int, len(batch)) // dedup key -> representative index
	var toInsert []*HTTPRecord
	for i := range batch {
		if existing[i] != "" {
			continue
		}
		key := recordDedupKey(records[i])
		repIdx, ok := groups[key]
		if !ok {
			repIdx = i
			groups[key] = i
			toInsert = append(toInsert, records[i])
		}
		rep[i] = repIdx
	}

	var insErr error
	if len(toInsert) > 0 {
		_, insErr = w.repo.SaveRecordsBatch(ctx, toInsert)
	}
	if insErr != nil {
		w.flushErrors.Add(1)
		zap.L().Error("RecordWriter batch flush failed",
			zap.Int("insert_count", len(toInsert)),
			zap.Int("batch_size", len(batch)),
			zap.Error(insErr))
	}

	w.flushed.Add(int64(len(batch)))

	for i, req := range batch {
		switch {
		case existing[i] != "":
			req.result <- WriteResult{UUID: existing[i]}
		case insErr != nil:
			req.result <- WriteResult{Err: fmt.Errorf("batch insert failed: %w", insErr)}
		default:
			// The representative record carries the freshly assigned UUID.
			req.result <- WriteResult{UUID: records[rep[i]].UUID}
		}
	}
}
