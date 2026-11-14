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
// the pause controller is paused and run after Resume.
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

// TestSchedulerLowMemoryHalvesGlobal: memory pressure halves G.
func TestSchedulerLowMemoryHalvesGlobal(t *testing.T) {
	s := newActiveScheduler(8, nil)
	s.lowMemory = func() bool { return true }
	if got := s.effectiveGlobal(); got != 4 {
		t.Fatalf("effectiveGlobal = %d, want 4", got)
	}
}

// A task for an idle host is admitted on enqueue (the fast path), queues once
// its host is at cap, and a double release frees one slot only.
func TestSchedulerFastPathAndIdempotentRelease(t *testing.T) {
	s := newActiveScheduler(4, func(string) int { return 1 })
	s.lowMemory = nil

	var releases []func()
	task := func() *schedTask {
		return &schedTask{ctx: context.Background(), host: "h:80", drop: func() {},
			run: func(release func()) { releases = append(releases, release) }}
	}
	s.enqueue(task())
	if running, queued := s.stats(); running != 1 || queued != 0 || len(releases) != 1 {
		t.Fatalf("after first enqueue running=%d queued=%d started=%d", running, queued, len(releases))
	}
	s.enqueue(task())
	if running, queued := s.stats(); running != 1 || queued != 1 {
		t.Fatalf("at host cap: running=%d queued=%d, want 1/1", running, queued)
	}
	releases[0]()
	releases[0]()
	if running, queued := s.stats(); running != 1 || queued != 0 || len(releases) != 2 {
		t.Fatalf("after release: running=%d queued=%d started=%d, want 1/0/2", running, queued, len(releases))
	}
	releases[1]()
	if running, _ := s.stats(); running != 0 {
		t.Fatalf("running=%d after all releases", running)
	}
}
