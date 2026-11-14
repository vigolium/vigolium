package database

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vigolium/vigolium/pkg/output"
	"go.uber.org/zap"
)

// FindingWriterConfig configures the batching behavior of FindingWriter.
type FindingWriterConfig struct {
	// BufferSize is the channel capacity. When full, Save persists inline rather
	// than blocking the scan worker. Default: 1024.
	BufferSize int

	// BatchSize is the maximum number of findings coalesced into one transaction.
	// Default: 64.
	BatchSize int

	// FlushInterval is the maximum time a finding waits in the buffer before
	// being flushed, even if the batch isn't full. Default: 50ms.
	FlushInterval time.Duration

	// FlushTimeout bounds the shutdown drain so a wedged database can't block
	// Close() forever. Steady-state flushes are bounded by OperationTimeout
	// instead, and remain immune to scan cancellation. Default: 2m.
	FlushTimeout time.Duration

	// OperationTimeout bounds ONE steady-state flush. Steady flushes deliberately
	// do not inherit the scan's context — cancelling a scan mid-transaction would
	// abort findings already pulled off the channel — but "not cancellable" was
	// implemented as context.Background(), i.e. no bound at all: a wedged database
	// parked the writer goroutine for the rest of the process. This is the bound,
	// set far above SQLite's 60s busy_timeout so a merely busy database still
	// succeeds. Default: 2m.
	OperationTimeout time.Duration

	// saveBatch replaces the repository batch save. Unexported, so only this
	// package's tests can set it — and it lives on the config rather than on the
	// writer because NewFindingWriter starts the flush goroutine, which reads the
	// seam: assigning it afterwards would be a data race on every flush.
	saveBatch func(context.Context, []FindingWrite) []FindingSaveResult
}

func (c *FindingWriterConfig) withDefaults() FindingWriterConfig {
	out := *c
	if out.BufferSize <= 0 {
		out.BufferSize = 1024
	}
	if out.BatchSize <= 0 {
		out.BatchSize = 64
	}
	if out.FlushInterval <= 0 {
		out.FlushInterval = 50 * time.Millisecond
	}
	if out.FlushTimeout <= 0 {
		out.FlushTimeout = 2 * time.Minute
	}
	if out.OperationTimeout <= 0 {
		out.OperationTimeout = 2 * time.Minute
	}
	return out
}

// findingWrite is a single queued finding.
type findingWrite struct {
	event       *output.ResultEvent
	recordUUIDs []string
	scanUUID    string
	projectUUID string
}

// FindingWriterMetrics exposes counters for monitoring.
//
// Written and Errors are exact per finding, not per batch: a flush asks for the
// per-finding outcomes and counts each one. They used to be charged by batch size
// on any batch error, so one unconvertible finding reported the whole batch as
// dropped and Written+Errors could exceed Enqueued.
type FindingWriterMetrics struct {
	Enqueued     int64 // findings handed to the background writer
	Written      int64 // findings the background writer persisted (or deduped onto an existing row)
	Inline       int64 // findings persisted synchronously (buffer full / shutting down)
	InlineFailed int64 // inline saves that returned an error
	Errors       int64 // findings that individually failed to persist in a flush
}

// FindingWriter decouples finding persistence from scan workers. SaveFinding is
// a multi-statement, dedup-aware operation; calling it synchronously on every
// worker blocks the worker on a database round-trip. FindingWriter funnels
// findings through a single background goroutine that coalesces them into batch
// transactions (one fsync for many findings) via Repository.SaveFindingsBatch.
//
// Findings are low-volume relative to HTTP records, so a single writer goroutine
// keeps up while also eliminating write contention between concurrent finding
// transactions. This mirrors RecordWriter's lifecycle (buffered channel,
// background flush, bounded shutdown drain) but is fire-and-forget: the result
// UUID is never needed by the caller, so Save does not block on persistence.
type FindingWriter struct {
	repo *Repository
	cfg  FindingWriterConfig
	ch   chan findingWrite

	// mu guards the closed flag against concurrent channel sends so Close can
	// guarantee no send is in flight when it stops accepting new findings.
	mu     sync.RWMutex
	closed bool

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// shutdown carries the single absolute deadline the whole shutdown shares —
	// the drain's flushes and the wait for the goroutine to exit — and the
	// once-only outcome. See shutdownBudget.
	shutdown shutdownBudget

	// saveBatch is the persistence seam. Defaults to the repository's aligned
	// batch save; replaced in tests to drive the failure and stall paths.
	saveBatch func(context.Context, []FindingWrite) []FindingSaveResult

	// onInserted, when set, is called for every finding persisted as a NEW
	// row (not a dedup-append), so notifications fire only for new findings
	// (SAFE-12). Called from the writer goroutine (or the inline saver).
	onInserted atomic.Pointer[func(*output.ResultEvent)]

	enqueued     atomic.Int64
	written      atomic.Int64
	inline       atomic.Int64
	inlineFailed atomic.Int64
	errors       atomic.Int64
}

// NewFindingWriter creates and starts a FindingWriter. Call Close() to flush
// remaining findings and stop the background goroutine.
func NewFindingWriter(repo *Repository, cfg FindingWriterConfig) *FindingWriter {
	cfg = cfg.withDefaults()
	ctx, cancel := context.WithCancel(context.Background())

	w := &FindingWriter{
		repo:   repo,
		cfg:    cfg,
		ch:     make(chan findingWrite, cfg.BufferSize),
		ctx:    ctx,
		cancel: cancel,
	}
	if w.saveBatch = cfg.saveBatch; w.saveBatch == nil {
		w.saveBatch = func(ctx context.Context, writes []FindingWrite) []FindingSaveResult {
			return repo.SaveFindingsBatchResults(ctx, writes)
		}
	}

	w.wg.Add(1)
	go w.flushLoop()

	return w
}

// Save enqueues a finding for batched persistence. It does not block on the
// database: if the buffer is full or the writer is shutting down, the finding is
// persisted synchronously so nothing is dropped. Safe for concurrent callers.
func (w *FindingWriter) Save(ctx context.Context, event *output.ResultEvent, recordUUIDs []string, scanUUID, projectUUID string) error {
	if event == nil {
		return fmt.Errorf("invalid ResultEvent")
	}
	fw := findingWrite{event: event, recordUUIDs: recordUUIDs, scanUUID: scanUUID, projectUUID: projectUUID}

	w.mu.RLock()
	if w.closed {
		w.mu.RUnlock()
		return w.saveInline(ctx, event, recordUUIDs, scanUUID, projectUUID)
	}
	// The non-blocking send happens under RLock so Close (which takes the write
	// lock before cancelling) can never race a send against the drain shutdown.
	select {
	case w.ch <- fw:
		w.mu.RUnlock()
		w.enqueued.Add(1)
		return nil
	default:
		w.mu.RUnlock()
		// Buffer full — persist inline rather than blocking the worker or
		// dropping the finding. Rare for low-volume findings.
		return w.saveInline(ctx, event, recordUUIDs, scanUUID, projectUUID)
	}
}

// saveInline persists a finding synchronously and counts the attempt. The failure
// count matters because Save's error goes to a caller that usually only logs it,
// so an inline save that failed was invisible in the shutdown accounting even
// though the finding is just as lost as one dropped by a flush.
func (w *FindingWriter) saveInline(ctx context.Context, event *output.ResultEvent, recordUUIDs []string, scanUUID, projectUUID string) error {
	w.inline.Add(1)
	inserted, err := w.repo.SaveFindingInserted(ctx, event, recordUUIDs, scanUUID, projectUUID)
	if err != nil {
		w.inlineFailed.Add(1)
		return err
	}
	if inserted {
		w.notifyInserted(event)
	}
	return nil
}

// SetOnInserted installs the new-finding callback (nil clears it). Safe to
// call while the writer runs.
func (w *FindingWriter) SetOnInserted(fn func(*output.ResultEvent)) {
	if w == nil {
		return
	}
	if fn == nil {
		w.onInserted.Store(nil)
		return
	}
	w.onInserted.Store(&fn)
}

func (w *FindingWriter) notifyInserted(event *output.ResultEvent) {
	if fn := w.onInserted.Load(); fn != nil && event != nil {
		(*fn)(event)
	}
}

// Metrics returns a snapshot of the writer's counters.
func (w *FindingWriter) Metrics() FindingWriterMetrics {
	return FindingWriterMetrics{
		Enqueued:     w.enqueued.Load(),
		Written:      w.written.Load(),
		Inline:       w.inline.Load(),
		InlineFailed: w.inlineFailed.Load(),
		Errors:       w.errors.Load(),
	}
}

// Close stops accepting new findings, flushes the buffer, and returns. After
// Close, Save persists synchronously. Prefer Shutdown when the caller can report
// what happened; Close is the fire-and-forget form kept for existing call sites.
func (w *FindingWriter) Close() { _ = w.Shutdown() }

// Shutdown stops accepting new findings, drains the buffer, and reports what
// became of everything it accepted.
//
// One absolute deadline (now+FlushTimeout) governs the whole shutdown and is
// published before the drain is woken, so the drain's flushes and the wait for the
// goroutine to exit share a single budget instead of each starting its own.
//
// Idempotent: the outcome is computed once and every later or concurrent caller
// gets that same value, so two phases closing the same writer cannot report the
// same findings twice.
// A nil writer is a no-op reporting a zero (clean) outcome — see
// RecordWriter.Shutdown for why that lives here rather than at every call site.
func (w *FindingWriter) Shutdown() PersistenceOutcome {
	if w == nil {
		return PersistenceOutcome{Writer: PersistenceWriterFindings}
	}
	w.shutdown.once.Do(func() {
		// Published BEFORE cancel: the drain branch reads it the moment it wakes.
		deadline := w.shutdown.publish(w.cfg.FlushTimeout)

		w.mu.Lock()
		w.closed = true
		w.mu.Unlock()
		// No send can be in flight now (Save holds RLock during its send, and we
		// hold the write lock above until all such sends complete), and no new send
		// will start because Save sees closed==true. Safe to wake the drain.
		w.cancel()

		timedOut := !waitBounded(&w.wg, time.Until(deadline))

		enqueued := w.enqueued.Load()
		written := w.written.Load()
		errCount := w.errors.Load()
		inline := w.inline.Load()
		inlineFailed := w.inlineFailed.Load()

		w.shutdown.outcome = PersistenceOutcome{
			Writer:    PersistenceWriterFindings,
			Accepted:  enqueued + inline,
			Committed: written + inline - inlineFailed,
			Failed:    errCount + inlineFailed,
			// Whatever was enqueued and has neither been written nor failed was
			// still queued or mid-flush when the deadline passed. It may yet land;
			// calling it lost would be as wrong as calling it stored.
			Unknown:  nonNegative(enqueued - written - errCount),
			TimedOut: timedOut,
		}

		// Surface fire-and-forget persistence failures at shutdown. Save returns nil
		// as soon as a finding is enqueued, so a later batch failure is otherwise
		// invisible — the scan would complete reporting success while silently having
		// dropped findings. This warning lands in the scan's captured stderr/log.
		if o := w.shutdown.outcome; !o.Clean() {
			zap.L().Warn("FindingWriter: some findings may not have been persisted",
				zap.Int64("failed", o.Failed),
				zap.Int64("unknown", o.Unknown),
				zap.Int64("committed", o.Committed),
				zap.Int64("accepted", o.Accepted),
				zap.Bool("timed_out", o.TimedOut))
		}
	})
	return w.shutdown.outcome
}

// flushLoop drains the channel and coalesces findings into batch transactions.
//
// Steady-state flushes never inherit the scan's context — cancelling a scan
// mid-transaction would abort findings already pulled off the channel — but they
// are bounded by OperationTimeout, so a wedged database fails the batch instead of
// parking this goroutine for the rest of the process. The shutdown drain runs on
// the single absolute deadline Shutdown published.
func (w *FindingWriter) flushLoop() {
	defer w.wg.Done()

	batch := make([]findingWrite, 0, w.cfg.BatchSize)
	ticker := time.NewTicker(w.cfg.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case fw := <-w.ch:
			batch = append(batch, fw)
			if len(batch) >= w.cfg.BatchSize {
				w.flushBounded(batch)
				batch = resetFindingBatch(batch)
				ticker.Reset(w.cfg.FlushInterval)
			}

		case <-ticker.C:
			if len(batch) > 0 {
				w.flushBounded(batch)
				batch = resetFindingBatch(batch)
			}

		case <-w.ctx.Done():
			drainCtx, cancel := context.WithDeadline(context.Background(), w.shutdown.drainDeadline(w.cfg.FlushTimeout))
			defer cancel()
			for {
				select {
				case fw := <-w.ch:
					batch = append(batch, fw)
					if len(batch) >= w.cfg.BatchSize {
						w.flush(drainCtx, batch)
						batch = resetFindingBatch(batch)
					}
				default:
					if len(batch) > 0 {
						w.flush(drainCtx, batch)
					}
					return
				}
			}
		}
	}
}

// flushBounded runs one steady-state flush under OperationTimeout, detached from
// any caller's context.
func (w *FindingWriter) flushBounded(batch []findingWrite) {
	ctx, cancel := context.WithTimeout(context.Background(), w.cfg.OperationTimeout)
	defer cancel()
	w.flush(ctx, batch)
}

// resetFindingBatch empties a flushed batch for reuse, clearing the entries
// first. This mirrors resetBatch in record_writer.go, for the same reason: a
// plain batch[:0] leaves the backing array's pointers live, so after a flush the
// loop still pins up to BatchSize findings — each one a *output.ResultEvent
// holding the full request, response and additional evidence that produced it.
// Findings are low-volume, so the writer is idle most of the time, and that is
// exactly when the stale retention lasts longest.
func resetFindingBatch(batch []findingWrite) []findingWrite {
	clear(batch)
	return batch[:0]
}

// flush persists a batch of findings in a single transaction and counts the
// per-finding outcomes exactly.
//
// The batch save already retries each finding individually when the transaction
// fails, so most "failed" batches persisted nearly all of their findings. Charging
// the whole batch to errors on any error therefore reported findings as dropped
// that are sitting in the database, and inflated the shutdown warning by up to
// BatchSize per incident.
func (w *FindingWriter) flush(ctx context.Context, batch []findingWrite) {
	writes := make([]FindingWrite, len(batch))
	for i, b := range batch {
		writes[i] = FindingWrite{
			Event:           b.event,
			HTTPRecordUUIDs: b.recordUUIDs,
			ScanUUID:        b.scanUUID,
			ProjectUUID:     b.projectUUID,
		}
	}

	results := w.saveBatch(ctx, writes)

	var ok, failed int64
	var firstErr error
	for i := range writes {
		// A result slice shorter than the input would silently drop findings from
		// the accounting, so anything unaccounted for counts as failed.
		if i >= len(results) || results[i].Err != nil {
			failed++
			if firstErr == nil && i < len(results) {
				firstErr = results[i].Err
			}
			continue
		}
		ok++
		if results[i].Inserted {
			w.notifyInserted(writes[i].Event)
		}
	}

	w.written.Add(ok)
	w.errors.Add(failed)
	if failed > 0 {
		zap.L().Warn("FindingWriter: some findings in a batch failed to persist",
			zap.Int("batch_size", len(batch)),
			zap.Int64("failed", failed),
			zap.Int64("persisted", ok),
			zap.Error(firstErr))
	}
}
