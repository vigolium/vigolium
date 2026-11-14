package core

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/core/ratelimit"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/httpmsg"
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

// The scheduler queues tasks per host:port but the host limiter keys hosts
// bare, so the cap lookup must strip the port: a host the limiter has backed
// off must cap the scheduler at that reduced limit, not at its ceiling.
func TestHostTaskCapFuncReadsLimiterVerdict(t *testing.T) {
	hl := ratelimit.NewHostRateLimiter(ratelimit.HostRateLimiterConfig{MaxPerHost: 8, WafAutoArm: true, DisableThrottlePause: true})
	defer func() { _ = hl.Close() }()
	if err := hl.Acquire(context.Background(), "a.test"); err != nil {
		t.Fatal(err)
	}
	hl.Release("a.test")
	hl.Feedback("a.test", ratelimit.FeedbackOutcome{Status: 429})
	limit, _ := hl.CurrentLimit("a.test")
	if limit != 4 {
		t.Fatalf("precondition: limiter limit = %d, want 4 after one throttle", limit)
	}

	e := &Executor{cfg: ExecutorConfig{Services: &services.Services{HostLimiter: hl}}}
	capFor := e.hostTaskCapFunc(64)
	item, err := httpmsg.GetRawRequestFromURL("http://a.test/x")
	if err != nil {
		t.Fatal(err)
	}
	key := httpmsg.TargetHostPortKey(item)
	if key != "a.test:80" {
		t.Fatalf("queue key = %q, want a.test:80", key)
	}
	if got := capFor(key); got != limit {
		t.Errorf("capFor(%q) = %d, want the limiter's current limit %d", key, got, limit)
	}
}
