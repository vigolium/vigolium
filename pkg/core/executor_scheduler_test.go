package core

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"
)

// TestSchedulerHoldsAdmissionWhilePaused: queued tasks are not admitted while
// the pause controller is paused and run after Resume (MISS-39).
func TestSchedulerHoldsAdmissionWhilePaused(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	pc := NewPauseController()
	s := newActiveScheduler(4, nil)
	s.lowMemory = nil
	s.pause = pc
	pc.Pause()

	var ran atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		s.enqueue(&schedTask{ctx: context.Background(), host: "h:80", drop: wg.Done,
			run: func(release func()) {
				go func() { defer wg.Done(); ran.Add(1); release() }()
			}})
	}
	time.Sleep(30 * time.Millisecond)
	if got := ran.Load(); got != 0 {
		t.Fatalf("%d task(s) admitted while paused", got)
	}
	pc.Resume()
	wg.Wait()
	if got := ran.Load(); got != 3 {
		t.Fatalf("ran = %d after resume, want 3", got)
	}
}

// TestSchedulerLowMemoryHalvesGlobal: memory pressure halves G (RES-10 hook).
func TestSchedulerLowMemoryHalvesGlobal(t *testing.T) {
	s := newActiveScheduler(8, nil)
	s.lowMemory = func() bool { return true }
	if got := s.effectiveGlobal(); got != 4 {
		t.Fatalf("effectiveGlobal = %d, want 4", got)
	}
}
