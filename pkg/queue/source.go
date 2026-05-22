package queue

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/work"
	"go.uber.org/zap"
)

// QueueInputSource adapts Queue to the InputSource interface.
// This allows the existing Executor to consume tasks from queue without modification.
type QueueInputSource struct {
	queue  Queue
	closed atomic.Bool
}

// NewQueueInputSource creates a new QueueInputSource.
func NewQueueInputSource(queue Queue) *QueueInputSource {
	return &QueueInputSource{
		queue: queue,
	}
}

// Next returns the next WorkItem from the queue with ack callback.
// Implements source.InputSource interface.
func (q *QueueInputSource) Next(ctx context.Context) (*work.WorkItem, error) {
	if q.closed.Load() {
		return nil, io.EOF
	}

	task, err := q.queue.Dequeue(ctx)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("dequeue failed: %w", err)
	}

	if task == nil {
		// This shouldn't happen, but handle gracefully
		return q.Next(ctx)
	}

	// Convert ScanTask to HttpRequestResponse
	rr, err := q.taskToHttpRequestResponse(task)
	if err != nil {
		zap.L().Warn("Failed to convert task to HttpRequestResponse",
			zap.String("task_id", task.ID),
			zap.Error(err))
		// Ack the invalid task to prevent reprocessing
		if ackErr := q.queue.Ack(task.ID); ackErr != nil {
			zap.L().Warn("Failed to ack invalid task",
				zap.String("task_id", task.ID),
				zap.Error(ackErr))
		}
		// Try next task
		return q.Next(ctx)
	}

	// Closure captures task.ID - no race condition!
	taskID := task.ID
	return work.NewWithCallback(rr, task.EnableModules, func() {
		if err := q.queue.Ack(taskID); err != nil {
			zap.L().Warn("Failed to ack task",
				zap.String("task_id", taskID),
				zap.Error(err))
		}
	}), nil
}

// taskToHttpRequestResponse converts a ScanTask to HttpRequestResponse.
func (q *QueueInputSource) taskToHttpRequestResponse(task *ScanTask) (*httpmsg.HttpRequestResponse, error) {
	var rr *httpmsg.HttpRequestResponse
	var err error

	if task.RawRequest != "" {
		// Format 1: Raw HTTP string
		if task.URL != "" {
			rr, err = httpmsg.ParseRawRequestWithURL(task.RawRequest, task.URL)
		} else {
			rr, err = httpmsg.ParseRawRequest(task.RawRequest)
		}
	} else if task.URL != "" {
		// Format 2: URL only - create GET request
		rr, err = httpmsg.GetRawRequestFromURL(task.URL)
	} else {
		return nil, ErrInvalidTask
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse request: %w", err)
	}

	return rr, nil
}

// Queue returns the underlying queue.
func (q *QueueInputSource) Queue() Queue {
	return q.queue
}

// Close closes the source.
func (q *QueueInputSource) Close() error {
	if !q.closed.CompareAndSwap(false, true) {
		return nil
	}
	return q.queue.Close()
}
