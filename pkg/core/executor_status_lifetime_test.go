package core

import (
	"context"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// TestStatusCallbackStopsAtExecutionEnd is the regression guard for the leaked
// status loop. Execute created an owned context only when MaxDuration > 0, so
// with MaxDuration == 0 (what the runner passes) the ticker goroutine exited only
// when the CALLER's context ended. Dynamic assessment builds one executor per
// round against a phase-long context, so every finished round left a goroutine
// firing OnStatus against a completed executor until the whole phase ended.
func TestStatusCallbackStopsAtExecutionEnd(t *testing.T) {
	var calls atomic.Int64

	// A live parent context that outlives the execution, like the phase context.
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()

	cfg := ExecutorConfig{}
	cfg.Workers = 1
	cfg.MaxDuration = 0 // the runner's value: no per-phase timeout
	cfg.StatusInterval = 10 * time.Millisecond
	cfg.OnStatus = func(_, _, _, _, _, _, _ int64, _ time.Duration) {
		calls.Add(1)
	}

	e := NewExecutor(cfg, &sliceSource{}, nil, nil)
	if _, err := e.Execute(parent); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// Execute has returned; record the count and wait several status intervals.
	atEnd := calls.Load()
	time.Sleep(50 * time.Millisecond)

	if after := calls.Load(); after != atEnd {
		t.Errorf("OnStatus fired %d more time(s) after Execute returned (%d → %d)",
			after-atEnd, atEnd, after)
	}
}

// Repeated executions under one live parent context must not accumulate
// goroutines — the per-round leak's cumulative symptom.
func TestRepeatedExecutionsLeaveNoStatusGoroutines(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()

	run := func() {
		cfg := ExecutorConfig{}
		cfg.Workers = 1
		cfg.MaxDuration = 0
		cfg.StatusInterval = 5 * time.Millisecond
		cfg.OnStatus = func(_, _, _, _, _, _, _ int64, _ time.Duration) {}
		e := NewExecutor(cfg, &sliceSource{}, nil, nil)
		if _, err := e.Execute(parent); err != nil {
			t.Fatalf("Execute: %v", err)
		}
	}

	run() // warm up: first run settles any lazily-started shared machinery
	settle()
	before := runtime.NumGoroutine()

	for range 8 {
		run()
	}
	settle()

	if after := runtime.NumGoroutine(); after > before+5 {
		t.Errorf("goroutines grew %d → %d across 8 executions; status loops are outliving Execute",
			before, after)
	}
}

// settle waits for the goroutine count to stop falling rather than sleeping a
// fixed amount, so the common case costs one tick instead of 100ms.
func settle() {
	prev := -1
	for range 20 {
		runtime.Gosched()
		time.Sleep(5 * time.Millisecond)
		if n := runtime.NumGoroutine(); n == prev {
			return
		} else {
			prev = n
		}
	}
}
