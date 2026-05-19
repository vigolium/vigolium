package database

import (
	"context"
	"errors"
	"fmt"
	"hash/maphash"
	"sync"
	"sync/atomic"
	"time"

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
	// Default: 1 (backward-compatible single-goroutine behavior).
	Shards int
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
	if out.Shards <= 0 {
		out.Shards = 4
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

	ctx, cancel := context.WithCancel(context.Background())

	w := &RecordWriter{
		repo:   repo,
		cfg:    cfg,
		shards: make([]*writerShard, cfg.Shards),
		ctx:    ctx,
		cancel: cancel,
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

// Write enqueues a record for batched insertion.
// It blocks until the record is persisted (or the context is cancelled).
// This is safe to call from multiple goroutines concurrently.
func (w *RecordWriter) Write(ctx context.Context, rr *httpmsg.HttpRequestResponse, source string, projectUUID string) (string, error) {
	if rr == nil || rr.Request() == nil {
		return "", fmt.Errorf("invalid HttpRequestResponse")
	}
	if w.closed.Load() {
		return "", ErrRecordWriterClosed
	}

	record := &HTTPRecord{}
	if err := record.FromHttpRequestResponse(rr); err != nil {
		return "", fmt.Errorf("failed to convert request: %w", err)
	}
	record.Source = source
	record.ProjectUUID = projectUUID

	if existingUUID, err := w.repo.findDuplicateRecord(ctx, record); err == nil && existingUUID != "" {
		return existingUUID, nil
	}

	resultCh := make(chan WriteResult, 1)
	req := writeRequest{record: record, result: resultCh}

	w.enqueued.Add(1)

	shard := w.shardFor(record.Hostname)

	select {
	case shard.ch <- req:
	case <-w.ctx.Done():
		return "", ErrRecordWriterClosed
	case <-ctx.Done():
		return "", ctx.Err()
	}

	// Prefer a delivered result over a shutdown signal: when both Close()
	// cancels w.ctx and flushLoop's drain has already written our result, the
	// caller should see the success rather than ErrRecordWriterClosed.
	select {
	case res := <-resultCh:
		return res.UUID, res.Err
	default:
	}

	// w.ctx.Done() is required here: Go's select is non-deterministic, so the
	// first select can pick `shard.ch <- req` even when w.ctx is already
	// cancelled. If flushLoop has since exited (its drain in <-ctx.Done() exits
	// once the channel reads `default`), our request is orphaned in the buffered
	// channel and resultCh is never written. Without this branch, the caller
	// blocks forever on a Close() that won the race.
	select {
	case res := <-resultCh:
		return res.UUID, res.Err
	case <-w.ctx.Done():
		return "", ErrRecordWriterClosed
	case <-ctx.Done():
		return "", ctx.Err()
	}
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

// SaveRecordBatch implements the network.RecordSaver interface by delegating
// each record to Write. The flush loop handles the actual batching.
func (w *RecordWriter) SaveRecordBatch(ctx context.Context, records []*httpmsg.HttpRequestResponse, source string, projectUUID string) ([]string, error) {
	uuids := make([]string, 0, len(records))
	for _, rr := range records {
		uuid, err := w.Write(ctx, rr, source, projectUUID)
		if err != nil {
			return uuids, err
		}
		uuids = append(uuids, uuid)
	}
	return uuids, nil
}

// Close stops accepting new writes, flushes remaining records, and returns.
func (w *RecordWriter) Close() {
	if !w.closed.CompareAndSwap(false, true) {
		return
	}
	w.cancel()
	w.wg.Wait()
}

// flushLoop is the goroutine that drains a shard's channel and batch-inserts.
// All w.flush calls intentionally use context.Background() instead of the
// cancellable ctx: when Close() cancels w.ctx mid-flush, propagating that
// cancellation aborts the in-flight SQL transaction and loses the records that
// were already pulled from the channel. The ctx parameter is used only to
// detect shutdown via ctx.Done() and trigger drain mode.
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
			// Drain remaining items from channel
			for {
				select {
				case req := <-s.ch:
					batch = append(batch, req)
					if len(batch) >= w.cfg.BatchSize {
						w.flush(context.Background(), batch)
						batch = batch[:0]
					}
				default:
					if len(batch) > 0 {
						w.flush(context.Background(), batch)
					}
					return
				}
			}
		}
	}
}

// flush inserts a batch of records in a single transaction and notifies callers.
func (w *RecordWriter) flush(ctx context.Context, batch []writeRequest) {
	records := make([]*HTTPRecord, len(batch))
	for i, req := range batch {
		records[i] = req.record
	}

	uuids, err := w.repo.SaveRecordsBatch(ctx, records)

	w.batchCount.Add(1)

	if err != nil {
		w.flushErrors.Add(1)
		zap.L().Error("RecordWriter batch flush failed",
			zap.Int("batch_size", len(batch)),
			zap.Error(err))
		// Notify all callers of the error
		for _, req := range batch {
			req.result <- WriteResult{Err: fmt.Errorf("batch insert failed: %w", err)}
		}
		return
	}

	w.flushed.Add(int64(len(batch)))

	// Notify each caller with their UUID
	for i, req := range batch {
		req.result <- WriteResult{UUID: uuids[i]}
	}
}
