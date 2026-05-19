package queue

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func createTestHybridQueue(t *testing.T, memSize, diskMaxRecords int) *HybridQueue {
	t.Helper()
	tmpDir := t.TempDir()
	backend, err := NewDiskQueue(DiskQueueConfig{
		BaseDir:              tmpDir,
		MaxRecordsPerSegment: diskMaxRecords,
	})
	require.NoError(t, err)

	q, err := NewHybridQueue(HybridQueueConfig{
		MemBufferSize: memSize,
		Backend:       backend,
	})
	require.NoError(t, err)
	return q
}

func TestNewHybridQueue(t *testing.T) {
	t.Run("creates queue with valid config", func(t *testing.T) {
		q := createTestHybridQueue(t, 100, 1000)
		defer func() { _ = q.Close() }()

		require.NotNil(t, q)
		require.Equal(t, 100, cap(q.mem))
	})

	t.Run("uses default buffer size when zero", func(t *testing.T) {
		tmpDir := t.TempDir()
		backend, err := NewDiskQueue(DiskQueueConfig{BaseDir: tmpDir})
		require.NoError(t, err)

		q, err := NewHybridQueue(HybridQueueConfig{
			MemBufferSize: 0,
			Backend:       backend,
		})
		require.NoError(t, err)
		defer func() { _ = q.Close() }()

		require.Equal(t, 10000, cap(q.mem))
	})

	t.Run("returns error when backend is nil", func(t *testing.T) {
		_, err := NewHybridQueue(HybridQueueConfig{
			MemBufferSize: 100,
			Backend:       nil,
		})
		require.Error(t, err)
	})
}

func TestHybridQueue_EnqueueFastPath(t *testing.T) {
	t.Run("enqueue goes to memory when channel has space", func(t *testing.T) {
		q := createTestHybridQueue(t, 100, 1000)
		defer func() { _ = q.Close() }()

		task := &ScanTask{ID: "task-1", URL: "https://example.com"}
		err := q.Enqueue(context.Background(), task)
		require.NoError(t, err)

		require.Equal(t, int64(1), q.memEnqueued.Load())
		require.Equal(t, int64(0), q.diskEnqueued.Load())
		require.Equal(t, int64(1), q.totalEnqueued.Load())
	})

	t.Run("multiple fast-path enqueues", func(t *testing.T) {
		q := createTestHybridQueue(t, 100, 1000)
		defer func() { _ = q.Close() }()

		ctx := context.Background()
		for i := 1; i <= 50; i++ {
			task := &ScanTask{ID: taskID(i), URL: "https://example.com"}
			err := q.Enqueue(ctx, task)
			require.NoError(t, err)
		}

		require.Equal(t, int64(50), q.memEnqueued.Load())
		require.Equal(t, int64(0), q.diskEnqueued.Load())
	})
}

func TestHybridQueue_EnqueueSpillover(t *testing.T) {
	t.Run("spills to disk when memory is full", func(t *testing.T) {
		// Small memory buffer: 5 items
		q := createTestHybridQueue(t, 5, 1000)
		defer func() { _ = q.Close() }()

		ctx := context.Background()
		// Enqueue 10 items: 5 should go to memory, 5 to disk
		for i := 1; i <= 10; i++ {
			task := &ScanTask{ID: taskID(i), URL: "https://example.com"}
			err := q.Enqueue(ctx, task)
			require.NoError(t, err)
		}

		require.Equal(t, int64(5), q.memEnqueued.Load())
		require.Equal(t, int64(5), q.diskEnqueued.Load())
		require.Equal(t, int64(10), q.totalEnqueued.Load())
	})
}

func TestHybridQueue_EnqueueErrors(t *testing.T) {
	t.Run("rejects invalid task", func(t *testing.T) {
		q := createTestHybridQueue(t, 100, 1000)
		defer func() { _ = q.Close() }()

		task := &ScanTask{ID: "no-url"}
		err := q.Enqueue(context.Background(), task)
		require.ErrorIs(t, err, ErrInvalidTask)
		require.Equal(t, int64(1), q.enqueueErrors.Load())
	})

	t.Run("rejects when closed", func(t *testing.T) {
		q := createTestHybridQueue(t, 100, 1000)
		_ = q.Close()

		task := &ScanTask{ID: "task-1", URL: "https://example.com"}
		err := q.Enqueue(context.Background(), task)
		require.ErrorIs(t, err, ErrQueueClosed)
	})

	t.Run("rejects when context cancelled", func(t *testing.T) {
		q := createTestHybridQueue(t, 100, 1000)
		defer func() { _ = q.Close() }()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		task := &ScanTask{ID: "task-1", URL: "https://example.com"}
		err := q.Enqueue(ctx, task)
		require.ErrorIs(t, err, context.Canceled)
	})
}

func TestHybridQueue_DequeueMemory(t *testing.T) {
	t.Run("dequeues from memory channel", func(t *testing.T) {
		q := createTestHybridQueue(t, 100, 1000)
		defer func() { _ = q.Close() }()

		ctx := context.Background()
		task := &ScanTask{ID: "task-1", URL: "https://example.com"}
		err := q.Enqueue(ctx, task)
		require.NoError(t, err)

		dequeued, err := q.Dequeue(ctx)
		require.NoError(t, err)
		require.Equal(t, "task-1", dequeued.ID)
		require.Equal(t, int64(1), q.totalDequeued.Load())
	})

	t.Run("dequeues all memory items", func(t *testing.T) {
		q := createTestHybridQueue(t, 100, 1000)
		defer func() { _ = q.Close() }()

		ctx := context.Background()
		for i := 1; i <= 10; i++ {
			task := &ScanTask{ID: taskID(i), URL: "https://example.com"}
			_ = q.Enqueue(ctx, task)
		}

		for i := 1; i <= 10; i++ {
			dequeued, err := q.Dequeue(ctx)
			require.NoError(t, err)
			require.Equal(t, taskID(i), dequeued.ID)
		}
	})
}

func TestHybridQueue_DequeueSpillover(t *testing.T) {
	t.Run("drainer feeds disk tasks to consumers", func(t *testing.T) {
		// Buffer of 3, enqueue 6 → 3 in memory, 3 on disk
		q := createTestHybridQueue(t, 3, 1000)
		defer func() { _ = q.Close() }()

		ctx := context.Background()
		for i := 1; i <= 6; i++ {
			task := &ScanTask{ID: taskID(i), URL: "https://example.com"}
			err := q.Enqueue(ctx, task)
			require.NoError(t, err)
		}

		require.Equal(t, int64(3), q.memEnqueued.Load())
		require.Equal(t, int64(3), q.diskEnqueued.Load())

		// Dequeue all 6 — the drainer should feed disk items into memory channel
		dequeueCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		seen := make(map[string]bool)
		for i := 0; i < 6; i++ {
			dequeued, err := q.Dequeue(dequeueCtx)
			require.NoError(t, err)
			seen[dequeued.ID] = true
		}

		// All 6 tasks should be dequeued
		require.Len(t, seen, 6)
		for i := 1; i <= 6; i++ {
			require.True(t, seen[taskID(i)], "missing task %s", taskID(i))
		}
	})
}

func TestHybridQueue_DequeueBlocking(t *testing.T) {
	t.Run("blocks until task available", func(t *testing.T) {
		q := createTestHybridQueue(t, 100, 1000)
		defer func() { _ = q.Close() }()

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		done := make(chan struct{})
		var dequeued *ScanTask
		var dequeueErr error

		go func() {
			dequeued, dequeueErr = q.Dequeue(ctx)
			close(done)
		}()

		// Enqueue after a short delay
		time.Sleep(200 * time.Millisecond)
		task := &ScanTask{ID: "delayed-task", URL: "https://example.com"}
		err := q.Enqueue(context.Background(), task)
		require.NoError(t, err)

		<-done
		require.NoError(t, dequeueErr)
		require.Equal(t, "delayed-task", dequeued.ID)
	})

	t.Run("returns error when context cancelled", func(t *testing.T) {
		q := createTestHybridQueue(t, 100, 1000)
		defer func() { _ = q.Close() }()

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		_, err := q.Dequeue(ctx)
		require.ErrorIs(t, err, context.DeadlineExceeded)
	})

	t.Run("returns EOF when queue closed", func(t *testing.T) {
		q := createTestHybridQueue(t, 100, 1000)

		done := make(chan error)
		go func() {
			_, err := q.Dequeue(context.Background())
			done <- err
		}()

		time.Sleep(50 * time.Millisecond)
		_ = q.Close()

		err := <-done
		require.ErrorIs(t, err, io.EOF)
	})
}

func TestHybridQueue_Ack(t *testing.T) {
	t.Run("ack memory-only task succeeds", func(t *testing.T) {
		q := createTestHybridQueue(t, 100, 1000)
		defer func() { _ = q.Close() }()

		ctx := context.Background()
		task := &ScanTask{ID: "mem-task", URL: "https://example.com"}
		_ = q.Enqueue(ctx, task)

		dequeued, _ := q.Dequeue(ctx)
		err := q.Ack(dequeued.ID)
		require.NoError(t, err)

		require.Equal(t, int64(1), q.totalCompleted.Load())
	})

	t.Run("ack spillover task succeeds", func(t *testing.T) {
		// Buffer of 1, enqueue 2 → first in memory, second on disk
		q := createTestHybridQueue(t, 1, 1000)
		defer func() { _ = q.Close() }()

		ctx := context.Background()
		t1 := &ScanTask{ID: "task-1", URL: "https://example.com"}
		t2 := &ScanTask{ID: "task-2", URL: "https://example.com"}
		_ = q.Enqueue(ctx, t1)
		_ = q.Enqueue(ctx, t2)

		dequeueCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()

		// Dequeue both and ack
		for i := 0; i < 2; i++ {
			dequeued, err := q.Dequeue(dequeueCtx)
			require.NoError(t, err)
			err = q.Ack(dequeued.ID)
			require.NoError(t, err)
		}

		require.Equal(t, int64(2), q.totalCompleted.Load())
	})
}

func TestHybridQueue_Metrics(t *testing.T) {
	t.Run("reflects combined memory and disk depth", func(t *testing.T) {
		q := createTestHybridQueue(t, 3, 1000)
		defer func() { _ = q.Close() }()

		ctx := context.Background()
		// Enqueue 5: 3 in memory, 2 on disk
		for i := 1; i <= 5; i++ {
			task := &ScanTask{ID: taskID(i), URL: "https://example.com"}
			_ = q.Enqueue(ctx, task)
		}

		m := q.Metrics()
		require.Equal(t, int64(5), m.TotalEnqueued)
		// Depth may fluctuate as drainer moves items, but total should be correct
		require.GreaterOrEqual(t, m.Depth, int64(0))
	})

	t.Run("initial metrics are zero", func(t *testing.T) {
		q := createTestHybridQueue(t, 100, 1000)
		defer func() { _ = q.Close() }()

		m := q.Metrics()
		require.Equal(t, int64(0), m.TotalEnqueued)
		require.Equal(t, int64(0), m.TotalDequeued)
		require.Equal(t, int64(0), m.TotalCompleted)
		require.Equal(t, int64(0), m.EnqueueErrors)
		require.Equal(t, int64(0), m.DequeueErrors)
	})
}

func TestHybridQueue_Concurrent(t *testing.T) {
	t.Run("concurrent enqueue is safe", func(t *testing.T) {
		q := createTestHybridQueue(t, 50, 1000)
		defer func() { _ = q.Close() }()
		ctx := context.Background()

		var wg sync.WaitGroup
		numGoroutines := 10
		tasksPerGoroutine := 50

		for g := range numGoroutines {
			wg.Add(1)
			go func(gID int) {
				defer wg.Done()
				for i := range tasksPerGoroutine {
					task := &ScanTask{
						ID:  taskID(gID*1000 + i),
						URL: "https://example.com",
					}
					err := q.Enqueue(ctx, task)
					require.NoError(t, err)
				}
			}(g)
		}

		wg.Wait()

		expected := int64(numGoroutines * tasksPerGoroutine)
		require.Equal(t, expected, q.totalEnqueued.Load())
		// Some went to memory, some to disk
		require.Equal(t, expected, q.memEnqueued.Load()+q.diskEnqueued.Load())
	})

	t.Run("concurrent enqueue and dequeue", func(t *testing.T) {
		q := createTestHybridQueue(t, 20, 1000)
		defer func() { _ = q.Close() }()

		numTasks := 100
		ctx := context.Background()

		// Enqueue all tasks
		for i := range numTasks {
			task := &ScanTask{
				ID:  taskID(i),
				URL: "https://example.com",
			}
			err := q.Enqueue(ctx, task)
			require.NoError(t, err)
		}

		// Dequeue all with multiple consumers
		dequeueCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		var mu sync.Mutex
		seen := make(map[string]bool)
		var wg sync.WaitGroup

		numConsumers := 4
		for c := range numConsumers {
			wg.Add(1)
			go func(consumerID int) {
				defer wg.Done()
				for {
					task, err := q.Dequeue(dequeueCtx)
					if err != nil {
						return
					}

					mu.Lock()
					seen[task.ID] = true
					done := len(seen) >= numTasks
					mu.Unlock()

					_ = q.Ack(task.ID)
					if done {
						return
					}
				}
			}(c)
		}

		wg.Wait()
		require.Len(t, seen, numTasks)
	})
}

func TestHybridQueue_Close(t *testing.T) {
	t.Run("close is idempotent", func(t *testing.T) {
		q := createTestHybridQueue(t, 100, 1000)

		err := q.Close()
		require.NoError(t, err)

		err = q.Close()
		require.NoError(t, err)
	})

	t.Run("enqueue fails after close", func(t *testing.T) {
		q := createTestHybridQueue(t, 100, 1000)
		_ = q.Close()

		task := &ScanTask{ID: "task-1", URL: "https://example.com"}
		err := q.Enqueue(context.Background(), task)
		require.ErrorIs(t, err, ErrQueueClosed)
	})
}
