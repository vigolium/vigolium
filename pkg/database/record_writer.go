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

	// OperationTimeout bounds ONE steady-state flush. Steady flushes deliberately
	// do not inherit the scan's context — cancelling a scan mid-transaction would
	// abort records already pulled off the channel and fail writers waiting on
	// their results — but "uncancellable" was implemented as context.Background(),
	// i.e. no bound at all: one wedged transaction parked a shard's flush loop for
	// the rest of the process, its channel filled, and every Write routed to that
	// host blocked behind it. This is the bound, set far above SQLite's 60s
	// busy_timeout so a merely busy database still succeeds. Default: 2m.
	OperationTimeout time.Duration

	// DedupCacheSize bounds the in-memory dedup cache (LRU) that maps a record's
	// dedup key to its UUID. A cache hit lets Write skip the per-record SELECT and
	// the redundant insert for a key already seen by this writer (common in
	// discovery/spidering, which re-encounter the same URLs). Zero means "unset"
	// and selects the default of 50000; pass a NEGATIVE size to disable the cache.
	DedupCacheSize int

	// MaxSubmitRecords and MaxSubmitBytes bound ONE SaveRecordBatch submission:
	// how many records (and how many raw request+response bytes) it admits before
	// waiting for that slice to resolve. They cap the peak memory of a bulk caller
	// that hands over a whole collection at once — without them, peak retention is
	// set by the caller's corpus size and nothing else.
	//
	// Both defaults sit well above BatchSize, so a submission still fills many
	// writer batches and the coalescing SaveRecordBatch exists for is preserved.
	// Defaults: 1024 records, 128 MiB.
	MaxSubmitRecords int
	MaxSubmitBytes   int64

	// SurfaceScorer, when set, computes surface_score for a record at ingest
	// (when the record carries none). Injected so this package stays free of
	// module code; the runner wires surface_scoring.IngestScore (ECON-5).
	SurfaceScorer func(*httpmsg.HttpRequestResponse) int

	// ScanUUID, when set, is stamped on every row this writer INSERTS, unless
	// the write's own lineage names a scan. A dedup hit (cache or batched lookup)
	// keeps the existing row's scan_uuid: the column records the first scan to
	// store the exchange. One writer belongs to one scan phase, so the runner
	// sets it once rather than threading it through every caller (the browser
	// crawler writes through this writer without knowing about scans).
	ScanUUID string

	// insertBatch replaces the repository batch insert. Unexported, so only this
	// package's tests can set it — and it lives on the config rather than on the
	// writer because NewRecordWriter starts the flush goroutines, which read the
	// seam: assigning it afterwards would be a data race on every flush.
	insertBatch func(context.Context, []*HTTPRecord) error
}

func (c *RecordWriterConfig) withDefaults() RecordWriterConfig {
	out := *c
	if out.BufferSize <= 0 {
		out.BufferSize = 4096
	}
	if out.BatchSize <= 0 {
		out.BatchSize = 128
	}
	// Shards is defaulted driver-aware in NewRecordWriter (1 for SQLite, 4 for
	// PostgreSQL); leave a non-positive value untouched here so that decision
	// has the driver available.
	if out.FlushTimeout <= 0 {
		out.FlushTimeout = 2 * time.Minute
	}
	if out.OperationTimeout <= 0 {
		out.OperationTimeout = 2 * time.Minute
	}
	if out.DedupCacheSize == 0 {
		out.DedupCacheSize = 50000
	}
	if out.MaxSubmitRecords <= 0 {
		out.MaxSubmitRecords = 1024
	}
	if out.MaxSubmitBytes <= 0 {
		out.MaxSubmitBytes = 128 << 20
	}
	return out
}

// writeRequest is an internal request sent to the flush goroutine.
type writeRequest struct {
	record *HTTPRecord
	result chan<- WriteResult
	// dedupKey is recordDedupKey(record), computed once by admit. Carried here so
	// the flush loop's within-batch grouping reuses it instead of rebuilding the
	// same string for every record it handles.
	dedupKey string
}

// WriteResult is the outcome of a single record write.
type WriteResult struct {
	UUID string
	Err  error
}

// RecordWriterMetrics exposes counters for monitoring.
//
// Flushed and FlushFailed partition the batch entries that reached a terminal
// outcome: Flushed counts entries that ended up persisted or deduplicated onto
// an existing row, FlushFailed counts entries whose insert transaction failed.
// FlushErrors counts failing BATCHES, so it is not comparable with either —
// one failed batch fails every entry in it.
type RecordWriterMetrics struct {
	Enqueued    int64
	Flushed     int64
	FlushFailed int64
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
	flushFailed atomic.Int64
	flushErrors atomic.Int64
	batchCount  atomic.Int64

	ctx    context.Context
	cancel context.CancelFunc
	closed atomic.Bool
	wg     sync.WaitGroup

	// shutdown carries the single absolute deadline the whole shutdown shares —
	// the admission wait, every drain flush and the wait for the flush loops to
	// exit — and the once-only outcome. See shutdownBudget.
	shutdown shutdownBudget

	// insertBatch is the persistence seam. Defaults to the repository's batch
	// insert; replaced in tests to drive the stall and failure paths.
	insertBatch func(context.Context, []*HTTPRecord) error

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

	if w.insertBatch = cfg.insertBatch; w.insertBatch == nil {
		w.insertBatch = func(ctx context.Context, records []*HTTPRecord) error {
			_, err := repo.SaveRecordsBatch(ctx, records)
			return err
		}
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
func (w *RecordWriter) admit(ctx context.Context, rr *httpmsg.HttpRequestResponse, source, projectUUID string, lineage RecordLineage) pendingWrite {
	if rr == nil || rr.Request() == nil {
		return pendingWrite{err: fmt.Errorf("invalid HttpRequestResponse"), resolved: true}
	}
	// Identity first, enrichment only if this record survives the dedup cache.
	// The expensive half of conversion — normalized body hash, HTML title parse,
	// word count, response hashing, owning the raw bytes — is pure waste for a key
	// the cache is about to resolve from memory. See HTTPRecord.PrepareIdentity.
	record := &HTTPRecord{}
	if err := record.PrepareIdentity(rr); err != nil {
		return pendingWrite{err: fmt.Errorf("failed to convert request: %w", err), resolved: true}
	}
	record.Source = source
	record.ScanUUID = w.cfg.ScanUUID
	// Lineage is applied to a NEW row only; a dedup hit below returns the
	// existing row untouched. Deliberate: a shared redirect target already has
	// whatever chain it was first written under, and re-parenting it to the most
	// recent traversal would rewrite history for every earlier chain.
	lineage.applyTo(record)
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
			// The in-memory fast path skips the SELECT and the insert, so it must
			// also carry the lineage the flush path would have applied —
			// otherwise whether a redirect chain links up, and whether the row
			// is labelled with the phase that fetched it, would depend on cache
			// residency. One statement, and a no-op costs nothing (AdoptRecord
			// returns before issuing anything when there is nothing to set).
			w.repo.AdoptRecord(ctx, existingUUID, lineage, record.Source)
			return pendingWrite{uuid: existingUUID, resolved: true}
		}
	}

	// Cache miss: this record may really be stored, so finish converting it. This
	// is also where it takes ownership of its raw bytes, which it must do before
	// being handed to the shard channel below — from that point it outlives this
	// call. See HTTPRecord.FromHttpRequestResponse.
	if err := record.EnrichFromHttpRequestResponse(rr); err != nil {
		return pendingWrite{err: fmt.Errorf("failed to convert request: %w", err), resolved: true}
	}
	if record.SurfaceScore == 0 && w.cfg.SurfaceScorer != nil {
		record.SurfaceScore = w.cfg.SurfaceScorer(rr)
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

	// Normally w.ctx stays live while an admission is outstanding, so this send
	// only waits on buffer space. But if a steady-state flush wedges on a stalled
	// database, the shard channel fills and this send would block indefinitely —
	// so Close's bounded admitWG wait cancels w.ctx on timeout, and the
	// w.ctx.Done() case here releases the blocked send (resolved as closed) so
	// shutdown can complete. The caller's own ctx can also abandon the send.
	select {
	case shard.ch <- writeRequest{record: record, result: resultCh, dedupKey: dedupKey}:
		w.admitWG.Done() // admitted; the drain now owns delivering our result
		return pendingWrite{dedupKey: dedupKey, resultCh: resultCh}
	case <-ctx.Done():
		w.admitWG.Done() // never sent; nothing to deliver
		return pendingWrite{err: ctx.Err(), resolved: true}
	case <-w.ctx.Done():
		w.admitWG.Done() // writer shutting down with a full/wedged shard; give up the send
		return pendingWrite{err: ErrRecordWriterClosed, resolved: true}
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
	return w.WriteWithLineage(ctx, rr, source, projectUUID, RecordLineage{})
}

// WriteWithLineage is Write carrying the record's full chain metadata. See
// RecordLineage, and admit for why it is applied to new rows only.
func (w *RecordWriter) WriteWithLineage(ctx context.Context, rr *httpmsg.HttpRequestResponse, source string, projectUUID string, lineage RecordLineage) (string, error) {
	if w.closed.Load() {
		return "", ErrRecordWriterClosed
	}
	return w.await(ctx, w.admit(ctx, rr, source, projectUUID, lineage))
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
		FlushFailed: w.flushFailed.Load(),
		FlushErrors: w.flushErrors.Load(),
		BatchCount:  w.batchCount.Load(),
		BufferDepth: bufferDepth,
	}
}

// SaveRecord implements the network.RecordSaver interface by delegating to Write.
func (w *RecordWriter) SaveRecord(ctx context.Context, rr *httpmsg.HttpRequestResponse, source string, projectUUID string) (string, error) {
	return w.Write(ctx, rr, source, projectUUID)
}

// SaveRecordBatch enqueues records to their shards BEFORE awaiting any result,
// so a single bulk producer's records land in the same writer batch instead of
// paying one flush interval per record (the trap of a Write-in-a-loop: Write
// blocks until its record is flushed, so a lone producer never fills a batch).
// Results are returned positionally aligned with the input — uuids[i] corresponds
// to records[i] — including deduplicated, invalid, and failed entries, so callers
// can't misassociate a UUID. The first error encountered is returned alongside
// the (still complete) uuid slice.
//
// Submissions are admitted in BOUNDED slices rather than all at once. Callers
// hand this whole collections: discovery submits an entire provenance group in
// one call, which on a large corpus is tens of thousands of records. Admitting
// them together made every one of their converted HTTPRecords — each owning a
// full raw request and response — plus a result channel each live simultaneously,
// so peak memory scaled with the corpus rather than with anything configured.
// Slices stay large enough to fill many writer batches, so the coalescing this
// method exists for is unaffected.
func (w *RecordWriter) SaveRecordBatch(ctx context.Context, records []*httpmsg.HttpRequestResponse, source string, projectUUID string) ([]string, error) {
	uuids := make([]string, len(records))
	if len(records) == 0 {
		return uuids, nil
	}
	if w.closed.Load() {
		return uuids, ErrRecordWriterClosed
	}

	var firstErr error

	for start := 0; start < len(records); {
		end := w.submitSliceEnd(records, start)

		// Phase 1: admit this slice without waiting, so its records sit in the
		// shard channels together and the flush loop coalesces them.
		pend := make([]pendingWrite, 0, end-start)
		for _, rr := range records[start:end] {
			pend = append(pend, w.admit(ctx, rr, source, projectUUID, RecordLineage{}))
		}

		// Phase 2: collect this slice's results in input order.
		for i, p := range pend {
			uuid, err := w.await(ctx, p)
			uuids[start+i] = uuid
			if err != nil && firstErr == nil {
				firstErr = err
			}
		}
		start = end
	}
	return uuids, firstErr
}

// submitSliceEnd returns the exclusive end of the next submission slice starting
// at start, bounded by both record count and total wire bytes. It always takes at
// least one record, so a single oversized record is submitted on its own rather
// than stalling the batch forever.
func (w *RecordWriter) submitSliceEnd(records []*httpmsg.HttpRequestResponse, start int) int {
	var bytes int64
	for end := start; end < len(records); end++ {
		size := recordWireSize(records[end])
		if end > start && (end-start >= w.cfg.MaxSubmitRecords || bytes+size > w.cfg.MaxSubmitBytes) {
			return end
		}
		bytes += size
	}
	return len(records)
}

// recordWireSize estimates what one record will retain once converted: its raw
// request and response bytes, which dominate everything else on the record.
func recordWireSize(rr *httpmsg.HttpRequestResponse) int64 {
	if rr == nil {
		return 0
	}
	var n int64
	if req := rr.Request(); req != nil {
		n += int64(len(req.Raw()))
	}
	if resp := rr.Response(); resp != nil {
		n += int64(len(resp.Raw()))
	}
	return n
}

// Close stops accepting new writes, flushes remaining records, and returns.
//
// Ordering matters: it marks the writer closed under the admission write lock (so
// no new write can admit past this point), waits for every already-admitted
// enqueue to finish landing in a shard channel, and only THEN cancels the flush
// context. That guarantees the shutdown drain observes every admitted record —
// none is orphaned in a channel after the flush loop exits, and every admitted
// write receives its real result instead of a spurious "closed" error.
// Prefer Shutdown when the caller can report what happened; Close is the
// fire-and-forget form kept for existing call sites.
func (w *RecordWriter) Close() { _ = w.Shutdown() }

// Shutdown is Close that reports what became of every record it accepted.
//
// One absolute deadline (now+FlushTimeout) governs the entire shutdown: the wait
// for in-flight enqueues to settle, every flush the drain performs, and the wait
// for the flush loops to exit. Each of those used to start its own FlushTimeout,
// so a wedged database could hold Close for three times the configured budget —
// and the caller still learned nothing about what was lost.
//
// Idempotent: the outcome is computed once and every later or concurrent caller
// gets the same value.
// A nil writer is a no-op reporting a zero (clean) outcome: a phase that had no
// repository created no writer, and it accepted nothing, so there is nothing to
// report. Keeping that here rather than at every call site is what lets a caller
// pass the writers it owns without first proving each one exists — and a typed-nil
// pointer inside a PersistenceShutdowner interface is not caught by a nil check
// there anyway.
func (w *RecordWriter) Shutdown() PersistenceOutcome {
	if w == nil {
		return PersistenceOutcome{Writer: PersistenceWriterRecords}
	}
	w.shutdown.once.Do(func() {
		// Published BEFORE cancel so the drain branch adopts it rather than
		// starting a fresh budget of its own.
		deadline := w.shutdown.publish(w.cfg.FlushTimeout)

		w.admitMu.Lock()
		w.closed.Store(true)
		w.admitMu.Unlock()

		// Wait for in-flight enqueues to land in a shard channel, but BOUND it: if a
		// steady-state flush is wedged on a stalled database, its shard channel fills
		// and an admitted enqueue blocks on the send — admitWG.Wait() would then never
		// return and Close would hang forever, defeating FlushTimeout. On timeout we
		// cancel the flush context anyway; the admit-send also selects on w.ctx.Done(),
		// so cancelling releases any blocked send (resolved as closed) and unblocks
		// admitWG.
		admitSettled := waitBounded(&w.admitWG, time.Until(deadline))
		if !admitSettled {
			zap.L().Warn("RecordWriter shutdown: admitted enqueues did not settle before the flush deadline; forcing shutdown")
		}
		w.cancel() // drain sees every admitted record; also releases blocked admit-sends
		// Bound the flush-loop drain too: a steady-state flush already executing on
		// its own OperationTimeout when Close fired sits outside the drain's budget,
		// so without this bound wg.Wait() could still outlast the deadline.
		drained := waitBounded(&w.wg, time.Until(deadline))
		if !drained {
			zap.L().Warn("RecordWriter shutdown: flush loops did not drain before the flush deadline; proceeding")
		}

		enqueued := w.enqueued.Load()
		flushed := w.flushed.Load()
		failed := w.flushFailed.Load()

		w.shutdown.outcome = PersistenceOutcome{
			Writer: PersistenceWriterRecords,
			// Dedup-cache hits never enqueue: admit resolves them from memory and
			// returns the existing UUID, so they are not writes this writer
			// accepted and are deliberately absent from every count here.
			Accepted:  enqueued,
			Committed: flushed,
			Failed:    failed,
			// Admitted but neither resolved nor failed when the deadline passed.
			Unknown:  nonNegative(enqueued - flushed - failed),
			TimedOut: !admitSettled || !drained,
		}

		if o := w.shutdown.outcome; !o.Clean() {
			zap.L().Warn("RecordWriter: some records may not have been persisted",
				zap.Int64("failed", o.Failed),
				zap.Int64("unknown", o.Unknown),
				zap.Int64("committed", o.Committed),
				zap.Int64("accepted", o.Accepted),
				zap.Bool("timed_out", o.TimedOut))
		}
	})
	return w.shutdown.outcome
}

// flushLoop is the goroutine that drains a shard's channel and batch-inserts.
// Steady-state flushes are detached from w.ctx: when Close() cancels it mid-flush,
// propagating that cancellation would abort the in-flight SQL transaction and lose
// records that were already pulled from the channel, so a slow insert must never
// be cancelled during normal operation. They are still bounded, by
// OperationTimeout, so a wedged transaction fails instead of parking this
// goroutine for the rest of the process. The shutdown drain (the ctx.Done()
// branch) runs on the single absolute deadline Shutdown published, so a wedged
// database can't hang Close() forever while healthy databases still drain in full.
//
// A batch is formed from what is already queued and committed immediately; see
// the channel arm for why no timer can help it.
func (w *RecordWriter) flushLoop(ctx context.Context, s *writerShard) {
	defer w.wg.Done()

	batch := make([]writeRequest, 0, w.cfg.BatchSize)

	for {
		select {
		case req := <-s.ch:
			batch = append(batch, req)
			// Take everything already queued, then commit. The batch is bounded by
			// how many producers are actually waiting rather than by a clock, which
			// is the only thing that can bound it usefully here: Write() is
			// admit-then-await, so a worker cannot enqueue its next row until this
			// one commits, and the number of rows that can be in flight is
			// therefore capped by the worker count. On any scan with fewer workers
			// than BatchSize - the default is 128, well above the usual concurrency
			// - the batch-full branch was unreachable and EVERY row waited out a
			// 50 ms flush ticker. A redirect chain paid that per hop, serialized,
			// because each hop's parent UUID is the next one's input.
			//
			// Under load this still batches: a burst of concurrent producers is
			// already sitting in the channel and gets drained into one transaction,
			// up to BatchSize. What it no longer does is hold a finished batch
			// waiting for company that cannot arrive.
			batch = drainAvailable(batch, s.ch, w.cfg.BatchSize)
			w.flushBounded(batch)
			batch = resetBatch(batch)

		case <-ctx.Done():
			// Shutdown drain. It shares Shutdown's single absolute deadline, so
			// Close() returns even against a wedged database; against a healthy one
			// every buffered batch still flushes well within it.
			drainCtx, cancel := context.WithDeadline(context.Background(), w.shutdown.drainDeadline(w.cfg.FlushTimeout))
			defer cancel()
			for {
				batch = drainAvailable(batch, s.ch, w.cfg.BatchSize)
				if len(batch) == 0 {
					return
				}
				w.flush(drainCtx, batch)
				batch = resetBatch(batch)
			}
		}
	}
}

// flushBounded runs one steady-state flush under OperationTimeout, detached from
// the writer's own context so a Close cannot abort a transaction in progress.
func (w *RecordWriter) flushBounded(batch []writeRequest) {
	ctx, cancel := context.WithTimeout(context.Background(), w.cfg.OperationTimeout)
	defer cancel()
	w.flush(ctx, batch)
}

// resetBatch empties a flushed batch for reuse, clearing the entries first.
// A plain batch[:0] keeps the backing array's pointers live, so between a flush
// and the next record the loop would still pin up to BatchSize HTTPRecords —
// each holding a full raw request and response. At an idle shard that retention
// lasts as long as the idle does.
func resetBatch(batch []writeRequest) []writeRequest {
	clear(batch)
	return batch[:0]
}

// drainAvailable appends everything already sitting in ch to batch, without
// blocking, stopping at limit. It never waits for a record that has not been
// sent yet - "already queued" is the whole distinction, and waiting is what the
// caller is trying to stop doing.
func drainAvailable(batch []writeRequest, ch <-chan writeRequest, limit int) []writeRequest {
	for len(batch) < limit {
		select {
		case req := <-ch:
			batch = append(batch, req)
		default:
			return batch
		}
	}
	return batch
}

// flush resolves a batch of records and notifies callers. It first runs one
// batched duplicate lookup for the whole batch (replacing the per-record SELECT
// that used to sit on the scan worker's hot path), returns the existing UUID for
// any record that already lives in the database, collapses identical new records
// within the batch to a single insert, and inserts the remaining distinct new
// records in one transaction.
//
// The caller chooses the context: flushLoop uses an OperationTimeout-bounded
// context detached from the writer's own for steady-state flushes, and the shared
// shutdown deadline for the drain (see flushLoop).
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
		key := batch[i].dedupKey
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
		insErr = w.insertBatch(ctx, toInsert)
	}
	if insErr != nil {
		w.flushErrors.Add(1)
		zap.L().Error("RecordWriter batch flush failed",
			zap.Int("insert_count", len(toInsert)),
			zap.Int("batch_size", len(batch)),
			zap.Error(insErr))
	}

	// Flushed counts entries that reached a real terminal outcome (persisted or
	// deduplicated onto an existing row); failed entries go to FlushFailed. Adding
	// len(batch) unconditionally here used to report every record of a failed
	// insert as flushed, so a run that silently lost a whole batch still showed
	// enqueued == flushed — the one number an operator would check.
	var okCount, failCount int64

	// Lineage and source backfills for records that deduped onto an existing row,
	// collected here and applied AFTER every caller has its result. Each one is
	// its own UPDATE round trip, and running them inline made a duplicate-heavy
	// batch deliver results at the pace of up to BatchSize serial statements —
	// with every other caller in the batch blocked behind them. Deferring is safe
	// because both adoptions are promote-only (see Repository.AdoptRecordParent
	// and AdoptRecordSource): they add information the caller does not read back,
	// and neither can contradict what is already stored.
	// Batch indices only: existing[i] and records[i] are both still live and
	// unmutated below, so there is nothing to copy out.
	var adoptions []int

	for i, req := range batch {
		switch {
		case existing[i] != "":
			// A record that deduped onto an earlier row can still contribute its
			// lineage AND its source: the earlier row may have been written as
			// finding evidence, before the chain that contains it existed and
			// before anything knew which phase's traffic it was. AdoptRecord
			// decides whether there is anything to apply, so the gate here is
			// just "it deduped".
			adoptions = append(adoptions, i)
			okCount++
			req.result <- WriteResult{UUID: existing[i]}
		case insErr != nil:
			failCount++
			req.result <- WriteResult{Err: fmt.Errorf("batch insert failed: %w", insErr)}
		default:
			// The representative record carries the freshly assigned UUID.
			okCount++
			req.result <- WriteResult{UUID: records[rep[i]].UUID}
		}
	}

	// All of the batch's adoptions go in one transaction (ECON-10).
	batchAdoptions := make([]RecordAdoption, 0, len(adoptions))
	for _, i := range adoptions {
		// RootUUID is only real lineage when it names a DIFFERENT row. A
		// standalone record self-roots during enrichment, and that uuid belongs
		// to a row this batch discarded — adopting it would point the surviving
		// row at a chain root that was never inserted.
		root := records[i].RootUUID
		if root == records[i].UUID {
			root = ""
		}
		batchAdoptions = append(batchAdoptions, RecordAdoption{
			UUID: existing[i],
			Lineage: RecordLineage{
				ParentUUID:     records[i].ParentUUID,
				RootUUID:       root,
				Target:         records[i].Target,
				ChainTruncated: records[i].ChainTruncated,
			},
			Source: records[i].Source,
		})
	}
	w.repo.AdoptRecords(ctx, batchAdoptions)

	w.flushed.Add(okCount)
	w.flushFailed.Add(failCount)
}
