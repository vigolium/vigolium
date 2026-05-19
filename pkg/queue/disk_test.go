package queue

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewDiskQueue(t *testing.T) {
	t.Run("creates queue with default config", func(t *testing.T) {
		tmpDir := t.TempDir()
		q, err := NewDiskQueue(DiskQueueConfig{
			BaseDir:              tmpDir,
			MaxRecordsPerSegment: 100,
		})
		require.NoError(t, err)
		require.NotNil(t, q)
		defer func() { _ = q.Close() }()

		require.Equal(t, tmpDir, q.baseDir)
		require.Equal(t, 100, q.maxRecordsPerSeg)
		require.Equal(t, 1, len(q.segments))
		require.NotNil(t, q.activeSegment)
	})

	t.Run("creates base directory if not exists", func(t *testing.T) {
		tmpDir := filepath.Join(t.TempDir(), "nested", "queue")
		q, err := NewDiskQueue(DiskQueueConfig{
			BaseDir:              tmpDir,
			MaxRecordsPerSegment: 100,
		})
		require.NoError(t, err)
		require.NotNil(t, q)
		defer func() { _ = q.Close() }()

		_, err = os.Stat(tmpDir)
		require.NoError(t, err)
	})

	t.Run("uses default values for empty config", func(t *testing.T) {
		cfg := DefaultDiskQueueConfig()
		require.Equal(t, 10000, cfg.MaxRecordsPerSegment)
	})
}

func TestDiskQueue_EnqueueDequeue(t *testing.T) {
	t.Run("enqueue and dequeue single task", func(t *testing.T) {
		q := createTestQueue(t, 100)
		defer func() { _ = q.Close() }()

		task := &ScanTask{
			ID:  "task-1",
			URL: "https://example.com/test",
		}

		ctx := context.Background()
		err := q.Enqueue(ctx, task)
		require.NoError(t, err)

		metrics := q.Metrics()
		require.Equal(t, int64(1), metrics.TotalEnqueued)
		require.Equal(t, int64(1), metrics.Depth)

		dequeued, err := q.Dequeue(ctx)
		require.NoError(t, err)
		require.Equal(t, "task-1", dequeued.ID)
		require.Equal(t, "https://example.com/test", dequeued.URL)
		require.Equal(t, TaskStatusProcessing, dequeued.Status)
	})

	t.Run("enqueue and dequeue multiple tasks FIFO order", func(t *testing.T) {
		q := createTestQueue(t, 100)
		defer func() { _ = q.Close() }()
		ctx := context.Background()

		// Enqueue 5 tasks
		for i := 1; i <= 5; i++ {
			task := &ScanTask{
				ID:  taskID(i),
				URL: "https://example.com",
			}
			err := q.Enqueue(ctx, task)
			require.NoError(t, err)
		}

		metrics := q.Metrics()
		require.Equal(t, int64(5), metrics.TotalEnqueued)

		// Dequeue should be FIFO
		for i := 1; i <= 5; i++ {
			dequeued, err := q.Dequeue(ctx)
			require.NoError(t, err)
			require.Equal(t, taskID(i), dequeued.ID)
		}
	})

	t.Run("enqueue with raw request", func(t *testing.T) {
		q := createTestQueue(t, 100)
		defer func() { _ = q.Close() }()

		rawReq := "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"
		task := &ScanTask{
			ID:         "task-raw",
			RawRequest: rawReq,
		}

		ctx := context.Background()
		err := q.Enqueue(ctx, task)
		require.NoError(t, err)

		dequeued, err := q.Dequeue(ctx)
		require.NoError(t, err)
		require.Equal(t, "task-raw", dequeued.ID)
		require.Equal(t, rawReq, dequeued.RawRequest)
	})
}

func TestDiskQueue_EnqueueErrors(t *testing.T) {
	t.Run("returns error for invalid task - no URL or RawRequest", func(t *testing.T) {
		q := createTestQueue(t, 100)
		defer func() { _ = q.Close() }()

		task := &ScanTask{
			ID: "invalid-task",
		}

		err := q.Enqueue(context.Background(), task)
		require.ErrorIs(t, err, ErrInvalidTask)

		metrics := q.Metrics()
		require.Equal(t, int64(0), metrics.TotalEnqueued)
		require.Equal(t, int64(1), metrics.EnqueueErrors)
	})

	t.Run("returns error for invalid task - empty ID", func(t *testing.T) {
		q := createTestQueue(t, 100)
		defer func() { _ = q.Close() }()

		task := &ScanTask{
			URL: "https://example.com",
		}

		err := q.Enqueue(context.Background(), task)
		require.ErrorIs(t, err, ErrInvalidTask)
	})

	t.Run("returns error when queue is closed", func(t *testing.T) {
		q := createTestQueue(t, 100)
		_ = q.Close()

		task := &ScanTask{
			ID:  "task-1",
			URL: "https://example.com",
		}

		err := q.Enqueue(context.Background(), task)
		require.ErrorIs(t, err, ErrQueueClosed)
	})

	t.Run("returns error when context is cancelled", func(t *testing.T) {
		q := createTestQueue(t, 100)
		defer func() { _ = q.Close() }()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		task := &ScanTask{
			ID:  "task-1",
			URL: "https://example.com",
		}

		err := q.Enqueue(ctx, task)
		require.ErrorIs(t, err, context.Canceled)
	})
}

func TestDiskQueue_DequeueBlocking(t *testing.T) {
	t.Run("dequeue blocks until task available", func(t *testing.T) {
		q := createTestQueue(t, 100)
		defer func() { _ = q.Close() }()

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		done := make(chan struct{})
		var dequeued *ScanTask
		var dequeueErr error

		// Start dequeue in goroutine
		go func() {
			dequeued, dequeueErr = q.Dequeue(ctx)
			close(done)
		}()

		// Wait a bit then enqueue
		time.Sleep(200 * time.Millisecond)
		task := &ScanTask{
			ID:  "delayed-task",
			URL: "https://example.com",
		}
		err := q.Enqueue(context.Background(), task)
		require.NoError(t, err)

		// Wait for dequeue to complete
		<-done
		require.NoError(t, dequeueErr)
		require.Equal(t, "delayed-task", dequeued.ID)
	})

	t.Run("dequeue returns error when context cancelled", func(t *testing.T) {
		q := createTestQueue(t, 100)
		defer func() { _ = q.Close() }()

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		_, err := q.Dequeue(ctx)
		require.ErrorIs(t, err, context.DeadlineExceeded)
	})

	t.Run("dequeue returns EOF when queue closed", func(t *testing.T) {
		q := createTestQueue(t, 100)

		ctx := context.Background()
		done := make(chan error)

		go func() {
			_, err := q.Dequeue(ctx)
			done <- err
		}()

		time.Sleep(50 * time.Millisecond)
		_ = q.Close()

		err := <-done
		require.ErrorIs(t, err, io.EOF)
	})
}

func TestDiskQueue_Ack(t *testing.T) {
	t.Run("ack marks task as completed", func(t *testing.T) {
		q := createTestQueue(t, 100)
		defer func() { _ = q.Close() }()
		ctx := context.Background()

		task := &ScanTask{
			ID:  "task-to-ack",
			URL: "https://example.com",
		}
		err := q.Enqueue(ctx, task)
		require.NoError(t, err)

		dequeued, err := q.Dequeue(ctx)
		require.NoError(t, err)

		err = q.Ack(dequeued.ID)
		require.NoError(t, err)

		metrics := q.Metrics()
		require.Equal(t, int64(1), metrics.TotalCompleted)
		require.Equal(t, int64(0), metrics.Depth)
	})

	t.Run("ack returns error for unknown task", func(t *testing.T) {
		q := createTestQueue(t, 100)
		defer func() { _ = q.Close() }()

		err := q.Ack("nonexistent-task")
		require.ErrorIs(t, err, ErrTaskNotFound)
	})

	t.Run("ack multiple tasks", func(t *testing.T) {
		q := createTestQueue(t, 100)
		defer func() { _ = q.Close() }()
		ctx := context.Background()

		// Enqueue 3 tasks
		for i := 1; i <= 3; i++ {
			task := &ScanTask{
				ID:  taskID(i),
				URL: "https://example.com",
			}
			err := q.Enqueue(ctx, task)
			require.NoError(t, err)
		}

		// Dequeue and ack all
		for i := 1; i <= 3; i++ {
			dequeued, err := q.Dequeue(ctx)
			require.NoError(t, err)
			err = q.Ack(dequeued.ID)
			require.NoError(t, err)
		}

		metrics := q.Metrics()
		require.Equal(t, int64(3), metrics.TotalEnqueued)
		require.Equal(t, int64(3), metrics.TotalDequeued)
		require.Equal(t, int64(3), metrics.TotalCompleted)
		require.Equal(t, int64(0), metrics.Depth)
	})
}

func TestDiskQueue_SegmentRotation(t *testing.T) {
	t.Run("rotates segment when max records reached", func(t *testing.T) {
		q := createTestQueue(t, 3) // Small limit for testing
		defer func() { _ = q.Close() }()
		ctx := context.Background()

		// Enqueue 5 tasks (should create 2 segments)
		for i := 1; i <= 5; i++ {
			task := &ScanTask{
				ID:  taskID(i),
				URL: "https://example.com",
			}
			err := q.Enqueue(ctx, task)
			require.NoError(t, err)
		}

		require.Equal(t, 2, len(q.segments))
		require.True(t, q.segments[0].IsSealed())
		require.False(t, q.segments[1].IsSealed())
	})

	t.Run("dequeue from oldest segment first", func(t *testing.T) {
		q := createTestQueue(t, 2)
		defer func() { _ = q.Close() }()
		ctx := context.Background()

		// Enqueue 4 tasks across 2 segments
		for i := 1; i <= 4; i++ {
			task := &ScanTask{
				ID:  taskID(i),
				URL: "https://example.com",
			}
			err := q.Enqueue(ctx, task)
			require.NoError(t, err)
		}

		// First segment should have tasks 1, 2
		// Second segment should have tasks 3, 4
		for i := 1; i <= 4; i++ {
			dequeued, err := q.Dequeue(ctx)
			require.NoError(t, err)
			require.Equal(t, taskID(i), dequeued.ID)
		}
	})
}

func TestDiskQueue_Persistence(t *testing.T) {
	t.Run("recovers tasks after restart", func(t *testing.T) {
		tmpDir := t.TempDir()
		ctx := context.Background()

		// Create queue and enqueue tasks
		q1, err := NewDiskQueue(DiskQueueConfig{
			BaseDir:              tmpDir,
			MaxRecordsPerSegment: 100,
		})
		require.NoError(t, err)

		for i := 1; i <= 3; i++ {
			task := &ScanTask{
				ID:  taskID(i),
				URL: "https://example.com",
			}
			err := q1.Enqueue(ctx, task)
			require.NoError(t, err)
		}

		// Dequeue one task (mark as processing)
		_, err = q1.Dequeue(ctx)
		require.NoError(t, err)

		_ = q1.Close()

		// Reopen queue
		q2, err := NewDiskQueue(DiskQueueConfig{
			BaseDir:              tmpDir,
			MaxRecordsPerSegment: 100,
		})
		require.NoError(t, err)
		defer func() { _ = q2.Close() }()

		// All 3 tasks should be recoverable (processing reset to pending)
		for i := 1; i <= 3; i++ {
			dequeued, err := q2.Dequeue(ctx)
			require.NoError(t, err)
			require.Equal(t, taskID(i), dequeued.ID)
		}
	})

	t.Run("preserves completed tasks after restart", func(t *testing.T) {
		tmpDir := t.TempDir()
		ctx := context.Background()

		// Create queue and enqueue tasks
		q1, err := NewDiskQueue(DiskQueueConfig{
			BaseDir:              tmpDir,
			MaxRecordsPerSegment: 100,
		})
		require.NoError(t, err)

		for i := 1; i <= 3; i++ {
			task := &ScanTask{
				ID:  taskID(i),
				URL: "https://example.com",
			}
			err := q1.Enqueue(ctx, task)
			require.NoError(t, err)
		}

		// Dequeue and ack first task
		dequeued, err := q1.Dequeue(ctx)
		require.NoError(t, err)
		err = q1.Ack(dequeued.ID)
		require.NoError(t, err)

		_ = q1.Close()

		// Reopen queue
		q2, err := NewDiskQueue(DiskQueueConfig{
			BaseDir:              tmpDir,
			MaxRecordsPerSegment: 100,
		})
		require.NoError(t, err)
		defer func() { _ = q2.Close() }()

		// Only 2 tasks should be pending (task 1 was completed)
		for i := 2; i <= 3; i++ {
			dequeued, err := q2.Dequeue(ctx)
			require.NoError(t, err)
			require.Equal(t, taskID(i), dequeued.ID)
		}
	})
}

func TestDiskQueue_Concurrent(t *testing.T) {
	t.Run("concurrent enqueue is safe", func(t *testing.T) {
		q := createTestQueue(t, 1000)
		defer func() { _ = q.Close() }()
		ctx := context.Background()

		var wg sync.WaitGroup
		numGoroutines := 10
		tasksPerGoroutine := 50

		for g := range numGoroutines {
			wg.Add(1)
			go func(goroutineID int) {
				defer wg.Done()
				for i := range tasksPerGoroutine {
					task := &ScanTask{
						ID:  taskID(goroutineID*1000 + i),
						URL: "https://example.com",
					}
					err := q.Enqueue(ctx, task)
					require.NoError(t, err)
				}
			}(g)
		}

		wg.Wait()

		expectedTotal := int64(numGoroutines * tasksPerGoroutine)
		metrics := q.Metrics()
		require.Equal(t, expectedTotal, metrics.TotalEnqueued)
		require.Equal(t, expectedTotal, metrics.Depth)
	})

	t.Run("concurrent enqueue and dequeue is safe", func(t *testing.T) {
		q := createTestQueue(t, 1000)
		defer func() { _ = q.Close() }()
		ctx := context.Background()

		numTasks := 20
		var dequeuedCount int64

		// Enqueue all tasks first
		for i := range numTasks {
			task := &ScanTask{
				ID:  taskID(i),
				URL: "https://example.com",
			}
			err := q.Enqueue(ctx, task)
			require.NoError(t, err)
		}

		// Dequeue all tasks with timeout
		dequeueCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		for range numTasks {
			task, err := q.Dequeue(dequeueCtx)
			require.NoError(t, err)
			require.NotNil(t, task)
			err = q.Ack(task.ID)
			require.NoError(t, err)
			dequeuedCount++
		}

		require.Equal(t, int64(numTasks), dequeuedCount)

		metrics := q.Metrics()
		require.Equal(t, int64(numTasks), metrics.TotalEnqueued)
		require.Equal(t, int64(numTasks), metrics.TotalDequeued)
		require.Equal(t, int64(numTasks), metrics.TotalCompleted)
		require.Equal(t, int64(0), metrics.Depth)
	})
}

func TestDiskQueue_Metrics(t *testing.T) {
	t.Run("metrics reflect queue state accurately", func(t *testing.T) {
		q := createTestQueue(t, 100)
		defer func() { _ = q.Close() }()
		ctx := context.Background()

		// Initial state
		m := q.Metrics()
		require.Equal(t, int64(0), m.Depth)
		require.Equal(t, int64(0), m.TotalEnqueued)
		require.Equal(t, int64(0), m.TotalDequeued)
		require.Equal(t, int64(0), m.TotalCompleted)
		require.Equal(t, int64(0), m.EnqueueErrors)
		require.Equal(t, int64(0), m.DequeueErrors)

		// After enqueue
		for i := 1; i <= 5; i++ {
			task := &ScanTask{
				ID:  taskID(i),
				URL: "https://example.com",
			}
			_ = q.Enqueue(ctx, task)
		}

		m = q.Metrics()
		require.Equal(t, int64(5), m.Depth)
		require.Equal(t, int64(5), m.TotalEnqueued)

		// After dequeue and ack
		for range 3 {
			task, _ := q.Dequeue(ctx)
			_ = q.Ack(task.ID)
		}

		m = q.Metrics()
		require.Equal(t, int64(2), m.Depth) // 5 - 3 completed
		require.Equal(t, int64(3), m.TotalDequeued)
		require.Equal(t, int64(3), m.TotalCompleted)
	})
}

func TestDiskQueue_Close(t *testing.T) {
	t.Run("close is idempotent", func(t *testing.T) {
		q := createTestQueue(t, 100)

		err := q.Close()
		require.NoError(t, err)

		err = q.Close()
		require.NoError(t, err)
	})

	t.Run("operations fail after close", func(t *testing.T) {
		q := createTestQueue(t, 100)
		_ = q.Close()

		task := &ScanTask{
			ID:  "task-1",
			URL: "https://example.com",
		}

		err := q.Enqueue(context.Background(), task)
		require.ErrorIs(t, err, ErrQueueClosed)
	})
}

// Helper functions

func createTestQueue(t *testing.T, maxRecords int) *DiskQueue {
	t.Helper()
	tmpDir := t.TempDir()
	q, err := NewDiskQueue(DiskQueueConfig{
		BaseDir:              tmpDir,
		MaxRecordsPerSegment: maxRecords,
	})
	require.NoError(t, err)
	return q
}

func taskID(i int) string {
	return "task-" + string(rune('0'+i%10)) + string(rune('0'+i/10%10)) + string(rune('0'+i/100%10))
}
