package queue

import (
	"context"
	"errors"
	"io"
	"sync/atomic"

	"github.com/sourcegraph/conc"
	"go.uber.org/zap"
)

// HybridQueue combines an in-memory buffered channel with a persistent backend (disk/redis).
// Enqueue writes to the channel first (zero disk I/O); when the channel is full, tasks spill
// to the underlying queue. A background goroutine drains spillover back into the channel
// so consumers always read from one place.
type HybridQueue struct {
	mem     chan *ScanTask // in-memory buffer: fast enqueue + unified dequeue output
	backend Queue          // persistent spillover (disk or redis)

	closed    atomic.Bool
	closeChan chan struct{}
	wg        conc.WaitGroup

	// Cancel function for the drainer's context.
	drainCancel context.CancelFunc

	// Metrics
	totalEnqueued  atomic.Int64
	totalDequeued  atomic.Int64
	totalCompleted atomic.Int64
	memEnqueued    atomic.Int64
	diskEnqueued   atomic.Int64
	enqueueErrors  atomic.Int64
	dequeueErrors  atomic.Int64
}

// HybridQueueConfig holds configuration for HybridQueue.
type HybridQueueConfig struct {
	// MemBufferSize is the capacity of the in-memory channel.
	// Tasks beyond this count spill to the backend queue.
	// Default: 10000
	MemBufferSize int

	// Backend is the persistent queue used for spillover.
	// Typically a *DiskQueue.
	Backend Queue
}

// NewHybridQueue creates a hybrid queue wrapping the given backend.
func NewHybridQueue(cfg HybridQueueConfig) (*HybridQueue, error) {
	if cfg.MemBufferSize <= 0 {
		cfg.MemBufferSize = 10000
	}
	if cfg.Backend == nil {
		return nil, ErrNoActiveSegment // need a backend
	}

	q := &HybridQueue{
		mem:       make(chan *ScanTask, cfg.MemBufferSize),
		backend:   cfg.Backend,
		closeChan: make(chan struct{}),
	}

	// Start background goroutine that drains the backend into the memory channel.
	drainCtx, drainCancel := context.WithCancel(context.Background())
	q.drainCancel = drainCancel
	q.wg.Go(func() {
		q.drainBackendToMem(drainCtx)
	})

	zap.L().Info("HybridQueue initialized",
		zap.Int("mem_buffer_size", cfg.MemBufferSize))

	return q, nil
}

// Enqueue adds a task to the queue.
// Fast path: writes to the in-memory channel with no disk I/O.
// Slow path: spills to the backend when the channel is full.
func (q *HybridQueue) Enqueue(ctx context.Context, task *ScanTask) error {
	if q.closed.Load() {
		q.enqueueErrors.Add(1)
		return ErrQueueClosed
	}

	if !task.IsValid() {
		q.enqueueErrors.Add(1)
		return ErrInvalidTask
	}

	// Check context cancellation
	select {
	case <-ctx.Done():
		q.enqueueErrors.Add(1)
		return ctx.Err()
	default:
	}

	// Fast path: non-blocking write to in-memory channel
	select {
	case q.mem <- task:
		q.memEnqueued.Add(1)
		q.totalEnqueued.Add(1)
		return nil
	default:
	}

	// Slow path: channel full, spill to backend
	if err := q.backend.Enqueue(ctx, task); err != nil {
		q.enqueueErrors.Add(1)
		return err
	}
	q.diskEnqueued.Add(1)
	q.totalEnqueued.Add(1)
	return nil
}

// Dequeue retrieves the next pending task.
// Reads from the unified memory channel, which is fed by both direct enqueue and
// the background drainer (for spillover tasks).
func (q *HybridQueue) Dequeue(ctx context.Context) (*ScanTask, error) {
	for {
		select {
		case task, ok := <-q.mem:
			if !ok {
				return nil, io.EOF
			}
			q.totalDequeued.Add(1)
			return task, nil
		case <-ctx.Done():
			q.dequeueErrors.Add(1)
			return nil, ctx.Err()
		case <-q.closeChan:
			// Queue is closing — drain remaining in-memory items
			select {
			case task, ok := <-q.mem:
				if ok {
					q.totalDequeued.Add(1)
					return task, nil
				}
			default:
			}
			return nil, io.EOF
		}
	}
}

// Ack marks a task as completed.
// Tries the backend first (for spillover tasks), then treats as in-memory no-op.
func (q *HybridQueue) Ack(taskID string) error {
	err := q.backend.Ack(taskID)
	if err == nil {
		q.totalCompleted.Add(1)
		return nil
	}
	// For in-memory tasks that were never persisted, Ack is a no-op.
	if errors.Is(err, ErrTaskNotFound) {
		q.totalCompleted.Add(1)
		return nil
	}
	return err
}

// Close releases resources.
// Stops the drainer, closes the backend, and drains the memory channel.
func (q *HybridQueue) Close() error {
	if !q.closed.CompareAndSwap(false, true) {
		return nil
	}

	close(q.closeChan)

	// Stop the drainer goroutine
	q.drainCancel()
	func() {
		defer func() {
			if r := recover(); r != nil {
				zap.L().Error("HybridQueue: panic in drain goroutine", zap.Any("panic", r))
			}
		}()
		q.wg.Wait()
	}()

	// Close backend
	err := q.backend.Close()

	zap.L().Info("HybridQueue closed",
		zap.Int64("total_enqueued", q.totalEnqueued.Load()),
		zap.Int64("mem_enqueued", q.memEnqueued.Load()),
		zap.Int64("disk_enqueued", q.diskEnqueued.Load()),
		zap.Int64("total_dequeued", q.totalDequeued.Load()),
		zap.Int64("total_completed", q.totalCompleted.Load()))

	return err
}

// Metrics returns current queue statistics.
func (q *HybridQueue) Metrics() *QueueMetrics {
	backendMetrics := q.backend.Metrics()
	backendDepth := int64(0)
	if backendMetrics != nil {
		backendDepth = backendMetrics.Depth
	}

	return &QueueMetrics{
		Depth:          int64(len(q.mem)) + backendDepth,
		TotalEnqueued:  q.totalEnqueued.Load(),
		TotalDequeued:  q.totalDequeued.Load(),
		TotalCompleted: q.totalCompleted.Load(),
		EnqueueErrors:  q.enqueueErrors.Load(),
		DequeueErrors:  q.dequeueErrors.Load(),
	}
}

// drainBackendToMem continuously pulls tasks from the backend and feeds them
// into the memory channel. This ensures spillover tasks eventually reach consumers.
func (q *HybridQueue) drainBackendToMem(ctx context.Context) {
	for {
		task, err := q.backend.Dequeue(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, io.EOF) {
				return
			}
			// Transient error — the backend Dequeue will retry internally,
			// so if we get here it's a real problem. Log and stop.
			zap.L().Warn("HybridQueue drainer: backend dequeue error, stopping", zap.Error(err))
			return
		}

		// Push the spillover task into the memory channel.
		// This blocks if the channel is full (backpressure from slow consumers).
		select {
		case q.mem <- task:
			// ok
		case <-ctx.Done():
			return
		case <-q.closeChan:
			return
		}
	}
}
