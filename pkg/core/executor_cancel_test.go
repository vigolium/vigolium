package core

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sourcegraph/conc"
)

// TestGoActiveTask_ContextCancellationSkipsTask verifies that when every active
// task slot is occupied and the scan context is cancelled, goActiveTask abandons
// the task instead of blocking the dispatcher on semaphore acquisition.
func TestGoActiveTask_ContextCancellationSkipsTask(t *testing.T) {
	e, _ := newTestExecutor(ExecutorConfig{}, nil)
	e.activeTaskSem = make(chan struct{}, 1)
	e.activeTaskSem <- struct{}{} // occupy the only slot

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	var ran atomic.Bool
	var g conc.WaitGroup
	e.goActiveTask(ctx, &g, func() { ran.Store(true) })
	g.Wait()

	if ran.Load() {
		t.Fatal("task ran even though the context was cancelled and the semaphore was full")
	}
}

// TestGoActiveTask_RunsWhenSlotAvailable confirms the normal path still schedules
// and runs the task when a slot is free.
func TestGoActiveTask_RunsWhenSlotAvailable(t *testing.T) {
	e, _ := newTestExecutor(ExecutorConfig{}, nil)
	e.activeTaskSem = make(chan struct{}, 1)

	done := make(chan struct{})
	var g conc.WaitGroup
	e.goActiveTask(context.Background(), &g, func() { close(done) })
	g.Wait()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("task with a free slot should have run")
	}
}
