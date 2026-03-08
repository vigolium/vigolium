// Package queue provides task queue implementations for the Vigolium HTTP server.
// It supports both disk-based (LevelDB) and Redis-based queues with a unified interface.
package queue

import (
	"context"
)

// Queue is the abstraction for task queue operations.
// Implementations must be safe for concurrent access from multiple goroutines.
type Queue interface {
	// Enqueue adds a task to the queue.
	// Returns ctx.Err() if context is cancelled while waiting.
	Enqueue(ctx context.Context, task *ScanTask) error

	// Dequeue retrieves the next pending task from the queue.
	// Blocks until a task is available or context is cancelled.
	// Returns (nil, io.EOF) when queue is closed and drained.
	// Returns (nil, ctx.Err()) if context is cancelled.
	Dequeue(ctx context.Context) (*ScanTask, error)

	// Ack marks a task as completed.
	// For disk-based queue, this triggers segment cleanup check.
	// For Redis queue, this is typically a no-op (ack on dequeue).
	Ack(taskID string) error

	// Close releases resources and prevents new Enqueue calls.
	// Dequeue continues until queue is drained, then returns io.EOF.
	Close() error

	// Metrics returns current queue statistics.
	// May return nil if metrics are not available.
	Metrics() *QueueMetrics
}

// QueueMetrics holds statistics about queue operations.
type QueueMetrics struct {
	// Depth is the current number of pending tasks.
	// May be -1 if not available (e.g., for Redis without XPENDING call).
	Depth int64

	// TotalEnqueued is the total number of tasks added since start.
	TotalEnqueued int64

	// TotalDequeued is the total number of tasks retrieved since start.
	TotalDequeued int64

	// TotalCompleted is the total number of tasks acknowledged since start.
	TotalCompleted int64

	// EnqueueErrors is the number of failed enqueue operations.
	EnqueueErrors int64

	// DequeueErrors is the number of failed dequeue operations.
	DequeueErrors int64
}

// QueueType represents the type of queue implementation.
type QueueType string

const (
	// QueueTypeDisk is a disk-based queue using LevelDB with segment rotation.
	QueueTypeDisk QueueType = "disk"

	// QueueTypeRedis is a Redis-based queue using Redis Streams.
	QueueTypeRedis QueueType = "redis"

	// QueueTypeHybrid is an in-memory buffered queue that spills over to a disk/redis backend.
	// Fast path avoids disk I/O on enqueue; a background goroutine drains spillover back to memory.
	QueueTypeHybrid QueueType = "hybrid"
)
