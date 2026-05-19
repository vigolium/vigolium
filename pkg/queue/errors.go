package queue

import "errors"

var (
	// ErrQueueClosed is returned when attempting to enqueue to a closed queue.
	ErrQueueClosed = errors.New("queue is closed")

	// ErrQueueFull is returned when the queue capacity is reached (for bounded queues).
	ErrQueueFull = errors.New("queue is full")

	// ErrInvalidTask is returned when a task is missing required fields.
	ErrInvalidTask = errors.New("invalid task: must have either URL or RawRequest")

	// ErrTaskNotFound is returned when a task ID is not found.
	ErrTaskNotFound = errors.New("task not found")

	// ErrSegmentSealed is returned when attempting to write to a sealed segment.
	ErrSegmentSealed = errors.New("segment is sealed")

	// ErrNoActiveSegment is returned when there is no active segment for writing.
	ErrNoActiveSegment = errors.New("no active segment")
)
