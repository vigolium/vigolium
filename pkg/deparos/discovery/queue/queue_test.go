package queue

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mockTask implements TaskInfo interface for queue testing.
type mockTask struct {
	priority uint8
	depth    uint16
	desc     string
	baseURL  []byte
}

func newMockTask(priority uint8, desc string) *mockTask {
	return &mockTask{priority: priority, depth: 0, desc: desc, baseURL: []byte("http://test.com/")}
}

func newMockTaskWithDepth(priority uint8, depth uint16, desc string) *mockTask {
	return &mockTask{priority: priority, depth: depth, desc: desc, baseURL: []byte("http://test.com/")}
}

func (m *mockTask) Priority() uint8     { return m.priority }
func (m *mockTask) Depth() uint16       { return m.depth }
func (m *mockTask) Description() string { return m.desc }
func (m *mockTask) Hash() uint64        { return uint64(m.priority) }
func (m *mockTask) FullURL() []byte     { return m.baseURL }
func (m *mockTask) Extension() string   { return "" }
func (m *mockTask) IsFromSpider() bool  { return false }
func (m *mockTask) FoundByName() string { return "mock" }

// Ensure mockTask implements TaskInfo
var _ TaskInfo = (*mockTask)(nil)

func TestTaskQueue_EnqueueDequeue(t *testing.T) {
	q := New()
	ctx := context.Background()

	task1 := newMockTask(5, "task1")
	task2 := newMockTask(1, "task2")
	task3 := newMockTask(10, "task3")

	q.Enqueue(task1)
	q.Enqueue(task2)
	q.Enqueue(task3)

	if q.Size() != 3 {
		t.Errorf("expected size 3, got %d", q.Size())
	}

	// Dequeue should return tasks in priority order (lowest priority value first)
	got, err := q.Dequeue(ctx)
	if err != nil {
		t.Fatalf("dequeue failed: %v", err)
	}
	if got.Priority() != 1 {
		t.Errorf("expected priority 1, got %d", got.Priority())
	}

	got, err = q.Dequeue(ctx)
	if err != nil {
		t.Fatalf("dequeue failed: %v", err)
	}
	if got.Priority() != 5 {
		t.Errorf("expected priority 5, got %d", got.Priority())
	}

	got, err = q.Dequeue(ctx)
	if err != nil {
		t.Fatalf("dequeue failed: %v", err)
	}
	if got.Priority() != 10 {
		t.Errorf("expected priority 10, got %d", got.Priority())
	}
}

func TestTaskQueue_DequeueBlocks(t *testing.T) {
	q := New()
	ctx := context.Background()

	// Start dequeue in goroutine (should block)
	dequeued := make(chan TaskInfo, 1)
	go func() {
		task, err := q.Dequeue(ctx)
		if err != nil {
			t.Errorf("dequeue failed: %v", err)
			return
		}
		dequeued <- task
	}()

	// Brief delay to ensure goroutine is waiting
	time.Sleep(50 * time.Millisecond)

	// Enqueue task - should wake dequeue
	task := newMockTask(1, "task1")
	q.Enqueue(task)

	// Verify dequeue received the task
	select {
	case got := <-dequeued:
		if got.Description() != task.Description() {
			t.Errorf("expected %s, got %s", task.Description(), got.Description())
		}
	case <-time.After(1 * time.Second):
		t.Error("dequeue didn't receive task after enqueue")
	}
}

func TestTaskQueue_DequeueContextCancellation(t *testing.T) {
	q := New()
	ctx, cancel := context.WithCancel(context.Background())

	// Start dequeue in goroutine
	errChan := make(chan error, 1)
	go func() {
		_, err := q.Dequeue(ctx)
		errChan <- err
	}()

	// Brief delay to ensure goroutine is waiting
	time.Sleep(50 * time.Millisecond)

	// Cancel context
	cancel()

	// Verify dequeue returns context error
	select {
	case err := <-errChan:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Error("dequeue didn't return after context cancellation")
	}
}

func TestTaskQueue_Stop(t *testing.T) {
	q := New()
	ctx := context.Background()

	// Start dequeue in goroutine
	errChan := make(chan error, 1)
	go func() {
		_, err := q.Dequeue(ctx)
		errChan <- err
	}()

	// Brief delay to ensure goroutine is waiting
	time.Sleep(50 * time.Millisecond)

	// Stop queue
	q.Stop()

	// Verify dequeue returns ErrQueueStopped
	select {
	case err := <-errChan:
		if !errors.Is(err, ErrQueueStopped) {
			t.Errorf("expected ErrQueueStopped, got %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Error("dequeue didn't return after stop")
	}

	// Enqueue after stop should be ignored
	task := newMockTask(1, "task1")
	q.Enqueue(task)

	if q.Size() != 0 {
		t.Errorf("expected size 0 after enqueue on stopped queue, got %d", q.Size())
	}
}

func TestTaskQueue_ConcurrentEnqueue(t *testing.T) {
	q := New()
	const numGoroutines = 10
	const tasksPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Concurrently enqueue tasks
	for i := 0; i < numGoroutines; i++ {
		go func(base int) {
			defer wg.Done()
			for j := 0; j < tasksPerGoroutine; j++ {
				priority := uint8((base*tasksPerGoroutine + j) % 15)
				task := newMockTask(priority, "concurrent-task")
				q.Enqueue(task)
			}
		}(i)
	}

	wg.Wait()

	expectedSize := numGoroutines * tasksPerGoroutine
	if q.Size() != expectedSize {
		t.Errorf("expected size %d, got %d", expectedSize, q.Size())
	}
}

func TestTaskQueue_ConcurrentDequeue(t *testing.T) {
	q := New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const numTasks = 100

	// Enqueue tasks
	for i := 0; i < numTasks; i++ {
		priority := uint8(i % 15)
		task := newMockTask(priority, fmt.Sprintf("task-%d", i))
		q.Enqueue(task)
	}

	// Concurrently dequeue
	const numWorkers = 5
	dequeued := make(chan TaskInfo, numTasks)
	var dequeuedCount int32
	var wg sync.WaitGroup
	wg.Add(numWorkers)

	for i := 0; i < numWorkers; i++ {
		go func() {
			defer wg.Done()
			for {
				task, err := q.Dequeue(ctx)
				if err != nil {
					return // Context cancelled
				}
				if task == nil {
					return
				}
				dequeued <- task
				if atomic.AddInt32(&dequeuedCount, 1) >= numTasks {
					cancel() // Signal all workers to stop
					return
				}
			}
		}()
	}

	// Wait with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(5 * time.Second):
		cancel() // Cleanup
		t.Fatal("concurrent dequeue timed out")
	}

	close(dequeued)
	count := 0
	for range dequeued {
		count++
	}

	if count != numTasks {
		t.Errorf("expected %d dequeued tasks, got %d", numTasks, count)
	}
}

func TestTaskQueue_MaintainsPriorityOrder(t *testing.T) {
	q := New()
	ctx := context.Background()

	// Enqueue tasks with all priority levels (0-14)
	for priority := uint8(14); priority > 0; priority-- {
		task := newMockTask(priority, fmt.Sprintf("task-%d", priority))
		q.Enqueue(task)
	}
	q.Enqueue(newMockTask(0, "task-0"))

	// Dequeue all tasks - should come out in priority order (0-14)
	for expected := uint8(0); expected <= 14; expected++ {
		task, err := q.Dequeue(ctx)
		if err != nil {
			t.Fatalf("dequeue failed: %v", err)
		}
		if task.Priority() != expected {
			t.Errorf("expected priority %d, got %d", expected, task.Priority())
		}
	}
}

func TestTaskQueue_DepthOrderingWithEqualPriority(t *testing.T) {
	q := New()
	ctx := context.Background()

	// Enqueue tasks with same priority but different depths (in reverse order)
	// Simulates: /admin/v1 (depth 2) -> /admin (depth 1) -> / (depth 0)
	q.Enqueue(newMockTaskWithDepth(5, 2, "/admin/v1"))
	q.Enqueue(newMockTaskWithDepth(5, 1, "/admin"))
	q.Enqueue(newMockTaskWithDepth(5, 0, "/"))

	// Should dequeue in depth order (breadth-first): / -> /admin -> /admin/v1
	expectedDescs := []string{"/", "/admin", "/admin/v1"}
	for i, expected := range expectedDescs {
		task, err := q.Dequeue(ctx)
		if err != nil {
			t.Fatalf("dequeue failed: %v", err)
		}
		if task.Description() != expected {
			t.Errorf("position %d: expected %s, got %s", i, expected, task.Description())
		}
	}
}

func TestTaskQueue_DepthBandTakesPrecedenceOverPriority(t *testing.T) {
	q := New()
	ctx := context.Background()

	// With hybrid scheduling: depth band comes first for non-spider tasks (P1-11)
	// Band 0: depth 0-1
	// Band 1: depth 2-3
	// Band 2: depth 4+

	// Low priority but shallow (band 0) should come BEFORE high priority but medium (band 1)
	q.Enqueue(newMockTaskWithDepth(8, 1, "low-priority-shallow")) // Band 0, P8
	q.Enqueue(newMockTaskWithDepth(1, 3, "high-priority-deep"))   // Band 1, P1

	// Shallow band should come first regardless of priority
	task, _ := q.Dequeue(ctx)
	if task.Description() != "low-priority-shallow" {
		t.Errorf("expected low-priority-shallow first (band 0), got %s", task.Description())
	}

	task, _ = q.Dequeue(ctx)
	if task.Description() != "high-priority-deep" {
		t.Errorf("expected high-priority-deep second (band 1), got %s", task.Description())
	}
}

func TestTaskQueue_SpiderBypassesDepthBand(t *testing.T) {
	q := New()
	ctx := context.Background()

	// Spider mockTask with priority 0
	type spiderMockTask struct {
		mockTask
	}
	spiderTask := &spiderMockTask{mockTask{priority: 0, depth: 10, desc: "spider-deep", baseURL: []byte("http://test.com/")}}

	// Regular tasks
	observedTask := newMockTaskWithDepth(3, 1, "observed-shallow")   // Band 0, P3
	longWordlist := newMockTaskWithDepth(8, 0, "long-wordlist-root") // Band 0, P8

	q.Enqueue(observedTask)
	q.Enqueue(longWordlist)
	q.Enqueue(spiderTask)

	// Spider (P0) should come first regardless of deep depth
	task, _ := q.Dequeue(ctx)
	if task.Priority() != 0 {
		t.Errorf("expected spider task (P0) first, got priority %d", task.Priority())
	}

	// Then shallow band tasks in priority order
	task, _ = q.Dequeue(ctx)
	if task.Description() != "observed-shallow" {
		t.Errorf("expected observed-shallow second, got %s", task.Description())
	}

	task, _ = q.Dequeue(ctx)
	if task.Description() != "long-wordlist-root" {
		t.Errorf("expected long-wordlist-root third, got %s", task.Description())
	}
}

func TestTaskQueue_DepthBandOrdering(t *testing.T) {
	q := New()
	ctx := context.Background()

	// Add tasks in various depth bands (all non-spider P1-11)
	q.Enqueue(newMockTaskWithDepth(5, 3, "medium-band"))   // Band 1 (depth 2-3), P5
	q.Enqueue(newMockTaskWithDepth(3, 1, "shallow-band"))  // Band 0 (depth 0-1), P3
	q.Enqueue(newMockTaskWithDepth(8, 0, "shallow-band2")) // Band 0 (depth 0-1), P8
	q.Enqueue(newMockTaskWithDepth(1, 5, "deep-band"))     // Band 2 (depth 4+), P1

	// Expected order: Band 0 (by priority), then Band 1, then Band 2
	// Band 0: P3-D1, P8-D0
	// Band 1: P5-D3
	// Band 2: P1-D5

	task, _ := q.Dequeue(ctx)
	if task.Priority() != 3 || task.Depth() != 1 {
		t.Errorf("expected P3-D1 first, got P%d-D%d", task.Priority(), task.Depth())
	}

	task, _ = q.Dequeue(ctx)
	if task.Priority() != 8 || task.Depth() != 0 {
		t.Errorf("expected P8-D0 second, got P%d-D%d", task.Priority(), task.Depth())
	}

	task, _ = q.Dequeue(ctx)
	if task.Priority() != 5 || task.Depth() != 3 {
		t.Errorf("expected P5-D3 third, got P%d-D%d", task.Priority(), task.Depth())
	}

	task, _ = q.Dequeue(ctx)
	if task.Priority() != 1 || task.Depth() != 5 {
		t.Errorf("expected P1-D5 fourth, got P%d-D%d", task.Priority(), task.Depth())
	}
}

func TestTaskQueue_PriorityWithinSameBand(t *testing.T) {
	q := New()
	ctx := context.Background()

	// All tasks in band 0 (depth 0-1), different priorities
	q.Enqueue(newMockTaskWithDepth(8, 1, "P8-D1"))
	q.Enqueue(newMockTaskWithDepth(3, 0, "P3-D0"))
	q.Enqueue(newMockTaskWithDepth(5, 1, "P5-D1"))

	// Within same band, priority ordering should apply
	task, _ := q.Dequeue(ctx)
	if task.Priority() != 3 {
		t.Errorf("expected P3 first, got P%d", task.Priority())
	}

	task, _ = q.Dequeue(ctx)
	if task.Priority() != 5 {
		t.Errorf("expected P5 second, got P%d", task.Priority())
	}

	task, _ = q.Dequeue(ctx)
	if task.Priority() != 8 {
		t.Errorf("expected P8 third, got P%d", task.Priority())
	}
}

func TestTaskQueue_Peek(t *testing.T) {
	q := New()

	// Empty queue
	if q.Peek() != nil {
		t.Error("expected nil from empty queue")
	}

	task1 := newMockTask(5, "task1")
	task2 := newMockTask(1, "task2")

	q.Enqueue(task1)
	q.Enqueue(task2)

	// Peek should return highest priority (lowest value) without removing
	peeked := q.Peek()
	if peeked == nil {
		t.Fatal("expected task from peek")
	}
	if peeked.Priority() != 1 {
		t.Errorf("expected priority 1 from peek, got %d", peeked.Priority())
	}

	// Size unchanged
	if q.Size() != 2 {
		t.Errorf("expected size 2 after peek, got %d", q.Size())
	}
}

func TestTaskQueue_IsEmpty(t *testing.T) {
	q := New()

	if !q.IsEmpty() {
		t.Error("expected empty queue")
	}

	q.Enqueue(newMockTask(1, "task"))

	if q.IsEmpty() {
		t.Error("expected non-empty queue")
	}
}

func TestTaskQueue_BroadcastWake(t *testing.T) {
	q := New()
	ctx := context.Background()

	numWorkers := 5
	dequeued := make(chan TaskInfo, numWorkers*2)
	errors := make(chan error, numWorkers)
	ready := make(chan struct{}, numWorkers)

	// Start workers all blocked on empty queue
	for i := 0; i < numWorkers; i++ {
		go func() {
			ready <- struct{}{}
			task, err := q.Dequeue(ctx)
			if err != nil {
				errors <- err
				return
			}
			dequeued <- task
		}()
	}

	// Wait for all workers to be ready
	for i := 0; i < numWorkers; i++ {
		<-ready
	}
	time.Sleep(50 * time.Millisecond)

	// Add tasks for all workers
	for i := 0; i < numWorkers; i++ {
		q.Enqueue(newMockTask(5, fmt.Sprintf("task-%d", i)))
	}

	// All workers should eventually get a task
	received := 0
	timeout := time.After(3 * time.Second)
	for received < numWorkers {
		select {
		case <-dequeued:
			received++
		case err := <-errors:
			t.Fatalf("dequeue error: %v", err)
		case <-timeout:
			t.Fatalf("only %d/%d workers got tasks", received, numWorkers)
		}
	}

	if received != numWorkers {
		t.Errorf("expected %d workers to receive tasks, got %d", numWorkers, received)
	}
}

func TestTaskQueue_RemoveByPattern(t *testing.T) {
	q := New()

	// Add tasks with different base paths
	q.Enqueue(&mockTask{priority: 1, desc: "task1", baseURL: []byte("/api/users")})
	q.Enqueue(&mockTask{priority: 2, desc: "task2", baseURL: []byte("/api/posts")})
	q.Enqueue(&mockTask{priority: 3, desc: "task3", baseURL: []byte("/admin/users")})
	q.Enqueue(&mockTask{priority: 4, desc: "task4", baseURL: []byte("/api/comments")})

	if q.Size() != 4 {
		t.Fatalf("expected size 4, got %d", q.Size())
	}

	// Remove all /api/* tasks
	removed := q.RemoveByPattern("^/api/")
	if removed != 3 {
		t.Errorf("expected 3 removed, got %d", removed)
	}

	if q.Size() != 1 {
		t.Errorf("expected size 1 after removal, got %d", q.Size())
	}
}

func TestTaskQueue_RemoveByPatternKeepOne(t *testing.T) {
	q := New()

	// Add tasks with same prefix
	q.Enqueue(&mockTask{priority: 1, desc: "task1", baseURL: []byte("/api/users/1")})
	q.Enqueue(&mockTask{priority: 2, desc: "task2", baseURL: []byte("/api/users/2")})
	q.Enqueue(&mockTask{priority: 3, desc: "task3", baseURL: []byte("/api/users/3")})
	q.Enqueue(&mockTask{priority: 4, desc: "task4", baseURL: []byte("/admin/config")})

	if q.Size() != 4 {
		t.Fatalf("expected size 4, got %d", q.Size())
	}

	// Remove /api/users/* but keep one
	removed := q.RemoveByPatternKeepOne("^/api/users/")
	if removed != 2 {
		t.Errorf("expected 2 removed, got %d", removed)
	}

	if q.Size() != 2 {
		t.Errorf("expected size 2 after removal, got %d", q.Size())
	}
}

func TestTaskQueue_CountByPattern(t *testing.T) {
	q := New()

	q.Enqueue(&mockTask{priority: 1, desc: "task1", baseURL: []byte("/api/users")})
	q.Enqueue(&mockTask{priority: 2, desc: "task2", baseURL: []byte("/api/posts")})
	q.Enqueue(&mockTask{priority: 3, desc: "task3", baseURL: []byte("/admin/users")})

	count := q.CountByPattern("^/api/")
	if count != 2 {
		t.Errorf("expected count 2, got %d", count)
	}
}

func TestTaskQueue_PeekByPattern(t *testing.T) {
	q := New()

	q.Enqueue(&mockTask{priority: 1, desc: "task1", baseURL: []byte("/api/users")})
	q.Enqueue(&mockTask{priority: 2, desc: "task2", baseURL: []byte("/api/posts")})
	q.Enqueue(&mockTask{priority: 3, desc: "task3", baseURL: []byte("/admin/users")})

	tasks := q.PeekByPattern("^/api/")
	if len(tasks) != 2 {
		t.Errorf("expected 2 tasks, got %d", len(tasks))
	}

	// Original queue unchanged
	if q.Size() != 3 {
		t.Errorf("expected size 3 after peek, got %d", q.Size())
	}
}

func TestTaskQueue_PeekAll(t *testing.T) {
	q := New()

	// Empty queue
	if tasks := q.PeekAll(0, 10); len(tasks) != 0 {
		t.Errorf("expected empty slice from empty queue, got %d tasks", len(tasks))
	}

	// Add 5 tasks
	for i := 0; i < 5; i++ {
		q.Enqueue(&mockTask{priority: uint8(i), desc: fmt.Sprintf("task-%d", i), baseURL: []byte("/test")})
	}

	// Get all
	tasks := q.PeekAll(0, 0)
	if len(tasks) != 5 {
		t.Errorf("expected 5 tasks, got %d", len(tasks))
	}

	// With limit
	tasks = q.PeekAll(0, 3)
	if len(tasks) != 3 {
		t.Errorf("expected 3 tasks with limit, got %d", len(tasks))
	}

	// With offset
	tasks = q.PeekAll(2, 10)
	if len(tasks) != 3 {
		t.Errorf("expected 3 tasks with offset 2, got %d", len(tasks))
	}

	// Offset beyond size
	tasks = q.PeekAll(10, 10)
	if len(tasks) != 0 {
		t.Errorf("expected 0 tasks with large offset, got %d", len(tasks))
	}

	// Original queue unchanged
	if q.Size() != 5 {
		t.Errorf("expected size 5 after PeekAll, got %d", q.Size())
	}
}

func TestTaskQueue_RemoveByHash(t *testing.T) {
	q := New()

	// Add tasks with unique hashes (hash = priority in mockTask)
	task1 := &mockTask{priority: 1, desc: "task1", baseURL: []byte("/test1")}
	task2 := &mockTask{priority: 2, desc: "task2", baseURL: []byte("/test2")}
	task3 := &mockTask{priority: 3, desc: "task3", baseURL: []byte("/test3")}

	q.Enqueue(task1)
	q.Enqueue(task2)
	q.Enqueue(task3)

	if q.Size() != 3 {
		t.Fatalf("expected size 3, got %d", q.Size())
	}

	// Remove by hash (hash = priority = 2)
	if !q.RemoveByHash(2) {
		t.Error("expected RemoveByHash to return true for existing task")
	}

	if q.Size() != 2 {
		t.Errorf("expected size 2 after removal, got %d", q.Size())
	}

	// Remove non-existent hash
	if q.RemoveByHash(999) {
		t.Error("expected RemoveByHash to return false for non-existent hash")
	}

	if q.Size() != 2 {
		t.Errorf("expected size 2 unchanged, got %d", q.Size())
	}

	// Verify removed task is gone - remaining tasks should be 1 and 3
	ctx := context.Background()
	dequeued1, _ := q.Dequeue(ctx)
	dequeued2, _ := q.Dequeue(ctx)

	if dequeued1.Hash() == 2 || dequeued2.Hash() == 2 {
		t.Error("removed task hash 2 should not be in queue")
	}
}
