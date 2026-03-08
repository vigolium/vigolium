package database

import (
	"context"
	"fmt"
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
	Enqueued     int64
	Flushed      int64
	FlushErrors  int64
	BatchCount   int64
	BufferDepth  int64
}

// RecordWriter serializes database writes through a single goroutine that
// coalesces individual SaveRecord calls into batch transactions.
// This eliminates SQLite SQLITE_BUSY errors under concurrent ingestion.
type RecordWriter struct {
	repo *Repository
	cfg  RecordWriterConfig
	ch   chan writeRequest

	// metrics
	enqueued    atomic.Int64
	flushed     atomic.Int64
	flushErrors atomic.Int64
	batchCount  atomic.Int64

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewRecordWriter creates and starts a RecordWriter.
// Call Close() to flush remaining records and stop the background goroutine.
func NewRecordWriter(repo *Repository, cfg RecordWriterConfig) *RecordWriter {
	cfg = cfg.withDefaults()

	ctx, cancel := context.WithCancel(context.Background())

	w := &RecordWriter{
		repo:   repo,
		cfg:    cfg,
		ch:     make(chan writeRequest, cfg.BufferSize),
		cancel: cancel,
	}

	w.wg.Add(1)
	go w.flushLoop(ctx)

	return w
}

// Write enqueues a record for batched insertion.
// It blocks until the record is persisted (or the context is cancelled).
// This is safe to call from multiple goroutines concurrently.
func (w *RecordWriter) Write(ctx context.Context, rr *httpmsg.HttpRequestResponse, source string, projectUUID string) (string, error) {
	if rr == nil || rr.Request() == nil {
		return "", fmt.Errorf("invalid HttpRequestResponse")
	}

	record := &HTTPRecord{}
	if err := record.FromHttpRequestResponse(rr); err != nil {
		return "", fmt.Errorf("failed to convert request: %w", err)
	}
	record.Source = source
	record.ProjectUUID = projectUUID

	resultCh := make(chan WriteResult, 1)
	req := writeRequest{record: record, result: resultCh}

	w.enqueued.Add(1)

	select {
	case w.ch <- req:
	case <-ctx.Done():
		return "", ctx.Err()
	}

	select {
	case res := <-resultCh:
		return res.UUID, res.Err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// Metrics returns a snapshot of the writer's counters.
func (w *RecordWriter) Metrics() RecordWriterMetrics {
	return RecordWriterMetrics{
		Enqueued:    w.enqueued.Load(),
		Flushed:     w.flushed.Load(),
		FlushErrors: w.flushErrors.Load(),
		BatchCount:  w.batchCount.Load(),
		BufferDepth: int64(len(w.ch)),
	}
}

// Close stops accepting new writes, flushes remaining records, and returns.
func (w *RecordWriter) Close() {
	w.cancel()
	w.wg.Wait()
}

// flushLoop is the single goroutine that drains the channel and batch-inserts.
func (w *RecordWriter) flushLoop(ctx context.Context) {
	defer w.wg.Done()

	batch := make([]writeRequest, 0, w.cfg.BatchSize)
	ticker := time.NewTicker(w.cfg.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case req := <-w.ch:
			batch = append(batch, req)
			if len(batch) >= w.cfg.BatchSize {
				w.flush(ctx, batch)
				batch = batch[:0]
				ticker.Reset(w.cfg.FlushInterval)
			}

		case <-ticker.C:
			if len(batch) > 0 {
				w.flush(ctx, batch)
				batch = batch[:0]
			}

		case <-ctx.Done():
			// Drain remaining items from channel
			for {
				select {
				case req := <-w.ch:
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
