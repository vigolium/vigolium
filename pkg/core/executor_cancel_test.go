package core

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// TestGoActiveTask_ContextCancellationSkipsTask verifies that when every active
// task slot is occupied and the scan context is cancelled, goActiveTask abandons
// the task instead of blocking the dispatcher on semaphore acquisition.
func TestGoActiveTask_ContextCancellationSkipsTask(t *testing.T) {
	e, _ := newTestExecutor(ExecutorConfig{}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	var ran atomic.Bool
	item, _ := makeTestItem("example.com", "/", "ok")
	tr := e.newItemTracker(ctx, item, false)
	e.goActiveTask(ctx, tr, "example.com:80", func(releaseSlot func()) { ran.Store(true); releaseSlot() })
	tr.done()
	<-tr.finished

	if ran.Load() {
		t.Fatal("task ran even though the context was cancelled and the semaphore was full")
	}
}

// TestGoActiveTask_RunsWhenSlotAvailable confirms the normal path still schedules
// and runs the task when a slot is free.
func TestGoActiveTask_RunsWhenSlotAvailable(t *testing.T) {
	e, _ := newTestExecutor(ExecutorConfig{}, nil)

	done := make(chan struct{})
	item, _ := makeTestItem("example.com", "/", "ok")
	tr := e.newItemTracker(context.Background(), item, false)
	e.goActiveTask(context.Background(), tr, "example.com:80", func(releaseSlot func()) { close(done); releaseSlot() })
	tr.done()
	<-tr.finished

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("task with a free slot should have run")
	}
}
