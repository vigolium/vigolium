// Package queue provides a priority queue for discovery tasks.
// Extracted to break circular dependency between discovery and module packages.
package queue

import (
	"container/heap"
	"context"
	"errors"
	"regexp"
	"sort"
	"sync"
)

var (
	// ErrQueueStopped indicates the queue has been stopped.
	ErrQueueStopped = errors.New("queue stopped")
)

// TaskInfo provides read-only task information for modules.
// This is a subset of the full Task interface - only what modules need.
type TaskInfo interface {
	// Hash returns unique task identifier.
	Hash() uint64

	// Priority returns task priority (0-14, lower = higher priority).
	Priority() uint8

	// Depth returns the discovery depth (0 = root, higher = deeper).
	// Used for breadth-first ordering when priorities are equal.
	Depth() uint16

	// Description returns human-readable task description.
	Description() string

	// FullURL returns the full URL for this task (scheme://host + path).
	FullURL() []byte

	// Extension returns the extension to test per payload.
	// Empty string means no extension (test payload alone).
	Extension() string

	// IsFromSpider returns true if task originated from spider link extraction.
	// Spider tasks bypass module filtering (only dedupe applies).
	IsFromSpider() bool

	// FoundByName returns a short identifier for this task type.
	// Used for result attribution and TUI display.
	FoundByName() string
}

// TaskQueue is a priority queue for tasks with context-aware blocking.
// Lower priority value = higher priority = dequeued first.
// Thread-safe for concurrent enqueue/dequeue operations.
//
// Uses channel-based signaling (not sync.Cond) for proper context cancellation.
type TaskQueue struct {
	mu      sync.Mutex
	heap    taskHeap
	stopped bool
	signal  chan struct{} // Signaling channel, closed and recreated on each signal
}

// New creates a new priority queue.
func New() *TaskQueue {
	return &TaskQueue{
		heap:   make(taskHeap, 0, 1000),
		signal: make(chan struct{}),
	}
}

// Enqueue adds a task to the priority queue.
// Thread-safe. O(log n) complexity.
func (q *TaskQueue) Enqueue(task TaskInfo) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.stopped {
		return
	}

	heap.Push(&q.heap, task)

	// Signal waiting dequeuers by closing and recreating channel
	close(q.signal)
	q.signal = make(chan struct{})
}

// Dequeue returns the highest priority task.
// Blocks until a task is available, context is cancelled, or queue is stopped.
func (q *TaskQueue) Dequeue(ctx context.Context) (TaskInfo, error) {
	for {
		q.mu.Lock()

		// Check stop condition
		if q.stopped {
			q.mu.Unlock()
			return nil, ErrQueueStopped
		}

		// Return task if available
		if len(q.heap) > 0 {
			task, ok := heap.Pop(&q.heap).(TaskInfo)
			if !ok {
				q.mu.Unlock()
				return nil, ErrQueueStopped
			}
			q.mu.Unlock()
			return task, nil
		}

		// Get signal channel while holding lock
		signal := q.signal
		q.mu.Unlock()

		// Wait for signal or context cancellation (no lock held)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-signal:
			// Signal received, loop to check queue again
		}
	}
}

// Peek returns the highest priority task without removing it.
func (q *TaskQueue) Peek() TaskInfo {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.heap) == 0 {
		return nil
	}
	return q.heap[0]
}

// Size returns the number of tasks in the queue.
func (q *TaskQueue) Size() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.heap)
}

// IsEmpty returns true if queue has no tasks.
func (q *TaskQueue) IsEmpty() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.heap) == 0
}

// Stop signals the queue to stop accepting new tasks.
// Wakes all waiting dequeuers.
func (q *TaskQueue) Stop() {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.stopped = true
	close(q.signal)
	q.signal = make(chan struct{}) // Prevent panic on double close
}

// IsStopped returns true if queue has been stopped.
func (q *TaskQueue) IsStopped() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.stopped
}

// RemoveByPattern removes tasks matching regex pattern from queue.
// Returns count of removed tasks.
func (q *TaskQueue) RemoveByPattern(pattern string) int {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return 0
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	removed := 0
	newHeap := make(taskHeap, 0, len(q.heap))

	for _, task := range q.heap {
		baseURL := string(task.FullURL())
		if re.MatchString(baseURL) {
			removed++
		} else {
			newHeap = append(newHeap, task)
		}
	}

	if removed > 0 {
		q.heap = newHeap
		heap.Init(&q.heap)
	}

	return removed
}

// RemoveByPatternKeepOne removes tasks matching pattern but keeps one.
// Returns count of removed tasks.
func (q *TaskQueue) RemoveByPatternKeepOne(pattern string) int {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return 0
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	removed := 0
	keptOne := false
	newHeap := make(taskHeap, 0, len(q.heap))

	for _, task := range q.heap {
		baseURL := string(task.FullURL())
		if re.MatchString(baseURL) {
			if !keptOne {
				// Keep the first matching task
				newHeap = append(newHeap, task)
				keptOne = true
			} else {
				removed++
			}
		} else {
			newHeap = append(newHeap, task)
		}
	}

	if removed > 0 {
		q.heap = newHeap
		heap.Init(&q.heap)
	}

	return removed
}

// CountByPattern returns count of tasks matching pattern.
func (q *TaskQueue) CountByPattern(pattern string) int {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return 0
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	count := 0
	for _, task := range q.heap {
		baseURL := string(task.FullURL())
		if re.MatchString(baseURL) {
			count++
		}
	}

	return count
}

// PeekByPattern returns read-only view of tasks matching pattern.
func (q *TaskQueue) PeekByPattern(pattern string) []TaskInfo {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	var matching []TaskInfo
	for _, task := range q.heap {
		baseURL := string(task.FullURL())
		if re.MatchString(baseURL) {
			matching = append(matching, task)
		}
	}

	return matching
}

// PeekAll returns a copy of all tasks in the queue (for UI display).
// Returns tasks sorted by priority order (same as dequeue order).
func (q *TaskQueue) PeekAll(offset, limit int) []TaskInfo {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.heap) == 0 {
		return nil
	}

	// Make a copy and sort using same criteria as heap.Less()
	sortedTasks := make([]TaskInfo, len(q.heap))
	copy(sortedTasks, q.heap)

	// Sort using same logic as taskHeap.Less()
	sort.Slice(sortedTasks, func(i, j int) bool {
		pi, pj := sortedTasks[i].Priority(), sortedTasks[j].Priority()

		// Priority 0 (Spider/JSFetch) always first
		if pi == 0 && pj != 0 {
			return true
		}
		if pj == 0 && pi != 0 {
			return false
		}
		if pi == 0 && pj == 0 {
			return sortedTasks[i].Depth() < sortedTasks[j].Depth()
		}

		// For Priority 1-11: Depth band first
		bandI := depthBand(sortedTasks[i].Depth())
		bandJ := depthBand(sortedTasks[j].Depth())
		if bandI != bandJ {
			return bandI < bandJ
		}

		// Within same band: Priority ordering
		if pi != pj {
			return pi < pj
		}

		// Same band, same priority: exact depth ordering
		return sortedTasks[i].Depth() < sortedTasks[j].Depth()
	})

	// Apply offset
	if offset >= len(sortedTasks) {
		return nil
	}
	sortedTasks = sortedTasks[offset:]

	// Apply limit
	if limit > 0 && limit < len(sortedTasks) {
		sortedTasks = sortedTasks[:limit]
	}

	return sortedTasks
}

// RemoveByHash removes a task by its hash value.
// Returns true if task was found and removed.
func (q *TaskQueue) RemoveByHash(hash uint64) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	for i, task := range q.heap {
		if task.Hash() == hash {
			// Remove by swapping with last and truncating
			q.heap[i] = q.heap[len(q.heap)-1]
			q.heap = q.heap[:len(q.heap)-1]
			if len(q.heap) > 0 {
				heap.Init(&q.heap)
			}
			return true
		}
	}
	return false
}

// taskHeap implements heap.Interface for TaskInfo priority ordering.
type taskHeap []TaskInfo

func (h taskHeap) Len() int { return len(h) }

// Depth band thresholds for hybrid scheduling.
// Priority 0 bypasses depth bands entirely.
// Priority 1-11 uses depth bands as primary sort.
const (
	DepthBandShallow uint16 = 2 // Band 0: depth 0-1
	DepthBandMedium  uint16 = 4 // Band 1: depth 2-3
	// Band 2: depth 4+
)

// depthBand returns the band index for a given depth.
func depthBand(depth uint16) int {
	if depth < DepthBandShallow {
		return 0
	}
	if depth < DepthBandMedium {
		return 1
	}
	return 2
}

func (h taskHeap) Less(i, j int) bool {
	pi, pj := h[i].Priority(), h[j].Priority()

	// Priority 0 (Spider/JSFetch) always first - bypass depth band
	if pi == 0 && pj != 0 {
		return true
	}
	if pj == 0 && pi != 0 {
		return false
	}
	if pi == 0 && pj == 0 {
		// Both Priority 0: just use depth ordering
		return h[i].Depth() < h[j].Depth()
	}

	// For Priority 1-11: Depth band first
	bandI := depthBand(h[i].Depth())
	bandJ := depthBand(h[j].Depth())
	if bandI != bandJ {
		return bandI < bandJ
	}

	// Within same band: Priority ordering
	if pi != pj {
		return pi < pj
	}

	// Same band, same priority: exact depth ordering
	return h[i].Depth() < h[j].Depth()
}

func (h taskHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
}

func (h *taskHeap) Push(x interface{}) {
	task, ok := x.(TaskInfo)
	if !ok {
		panic("taskHeap.Push: x is not a TaskInfo")
	}
	*h = append(*h, task)
}

func (h *taskHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}
