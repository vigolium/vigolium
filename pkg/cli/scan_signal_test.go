package cli

import (
	"os"
	"os/signal"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// TestScanShutdownSignalsMatchTheEventStream is the parity assertion.
//
// scanevents.TrapSignals has always trapped SIGINT and SIGTERM. The scan handler
// trapped only SIGINT, so a SIGTERM (a `timeout`, a container stop, a supervisor)
// emitted a terminal scan.finished{interrupted} — latching the emitter shut —
// while the runner ran on to completion and wrote `completed | complete` to the
// scan row. WP3/WP4 made "the stream and the row agree" a documented contract;
// a signal only one of them listens for breaks it.
func TestScanShutdownSignalsMatchTheEventStream(t *testing.T) {
	if !slices.Contains(scanShutdownSignals, os.Signal(os.Interrupt)) {
		t.Error("SIGINT must cancel a scan")
	}
	if !slices.Contains(scanShutdownSignals, os.Signal(syscall.SIGTERM)) {
		t.Error("SIGTERM must cancel a scan — scanevents.TrapSignals traps it, so the " +
			"stream would report `interrupted` while the scan row reported `completed`")
	}
}

// TestScanShutdownTrapsSIGTERM proves it through the real signal machinery: a
// SIGTERM delivered to this process reaches a channel registered with
// scanShutdownSignals.
//
// Safe because Notify is established before the signal is sent — Go's runtime
// then delivers it to the channel rather than letting the default action
// terminate the process — and Stop is deferred so nothing is left registered.
func TestScanShutdownTrapsSIGTERM(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SIGTERM cannot be raised on Windows")
	}

	c := make(chan os.Signal, 2)
	signal.Notify(c, scanShutdownSignals...)
	defer signal.Stop(c)

	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("raise SIGTERM: %v", err)
	}

	select {
	case got := <-c:
		if got != syscall.SIGTERM {
			t.Fatalf("received %v, want SIGTERM", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SIGTERM was not delivered to the scan shutdown handler")
	}
}

// fakeShutdownTarget records which release route the coordinator chose.
type fakeShutdownTarget struct {
	mu        sync.Mutex
	closed    int
	discarded int
	done      chan struct{}
	once      sync.Once
}

func newFakeShutdownTarget() *fakeShutdownTarget {
	return &fakeShutdownTarget{done: make(chan struct{})}
}

func (f *fakeShutdownTarget) Close() {
	f.mu.Lock()
	f.closed++
	f.mu.Unlock()
	f.once.Do(func() { close(f.done) })
}

func (f *fakeShutdownTarget) Discard() {
	f.mu.Lock()
	f.discarded++
	f.mu.Unlock()
	f.once.Do(func() { close(f.done) })
}

func (f *fakeShutdownTarget) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed, f.discarded
}

// newTestCoordinator builds a coordinator that does not touch real signals or
// os.Exit, so the handler logic can be driven by hand.
func newTestCoordinator(t *testing.T) (*scanSignalCoordinator, chan int) {
	t.Helper()
	exited := make(chan int, 1)
	c := &scanSignalCoordinator{
		ch:            make(chan os.Signal, 3),
		done:          make(chan struct{}),
		start:         time.Now(),
		exit:          func(code int) { exited <- code },
		flushDeadline: 200 * time.Millisecond,
	}
	go c.watch()
	t.Cleanup(c.stop)
	return c, exited
}

// TestCoordinatorClosesAttachedRunner: a signal reaches an attached, running
// scan and releases it through Close.
func TestCoordinatorClosesAttachedRunner(t *testing.T) {
	c, _ := newTestCoordinator(t)
	target := newFakeShutdownTarget()
	c.attach(target)
	c.markRunStarted()

	c.ch <- syscall.SIGTERM

	select {
	case <-target.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the attached runner was never released")
	}
	closed, discarded := target.counts()
	if closed != 1 || discarded != 0 {
		t.Fatalf("close=%d discard=%d, want close=1 discard=0", closed, discarded)
	}
	if !c.Interrupted() {
		t.Error("Interrupted() must report the signal the terminal event depends on")
	}
}

// TestCoordinatorInterruptBeforeAttach is the window the old handler had no
// answer for: a signal during setup, minutes before a runner exists. The
// interrupt must not be forgotten when one finally does.
func TestCoordinatorInterruptBeforeAttach(t *testing.T) {
	c, _ := newTestCoordinator(t)
	c.ch <- os.Interrupt

	// Wait for the handler to record the interrupt before attaching.
	deadline := time.Now().Add(5 * time.Second)
	for !c.Interrupted() {
		if time.Now().After(deadline) {
			t.Fatal("the coordinator never recorded the signal")
		}
		time.Sleep(time.Millisecond)
	}

	target := newFakeShutdownTarget()
	c.attach(target)

	select {
	case <-target.done:
	case <-time.After(5 * time.Second):
		t.Fatal("a runner attached after the signal was never released")
	}
	// Discard, not Close: the run never started, and Close would block on a
	// completion channel nothing will ever close.
	closed, discarded := target.counts()
	if discarded != 1 || closed != 0 {
		t.Fatalf("close=%d discard=%d, want close=0 discard=1", closed, discarded)
	}
}

// TestCoordinatorSecondSignalForcesExit: an impatient second signal must not
// wait out a graceful close that is taking its time.
func TestCoordinatorSecondSignalForcesExit(t *testing.T) {
	c, exited := newTestCoordinator(t)
	var notices []string
	var mu sync.Mutex
	c.notice = func(m string) { mu.Lock(); notices = append(notices, m); mu.Unlock() }
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	target := &blockingShutdownTarget{release: release}
	c.attach(target)
	c.markRunStarted()

	c.ch <- os.Interrupt
	// Let the handler enter the graceful close before escalating.
	time.Sleep(50 * time.Millisecond)
	c.ch <- os.Interrupt

	// The second signal hurries the runner and waits up to the flush deadline
	// for the normal exit path to write results, then exits 5 (incomplete).
	select {
	case code := <-exited:
		if code != ExitIncomplete {
			t.Fatalf("forced exit code %d, want %d", code, ExitIncomplete)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a second signal did not force an exit after the flush deadline")
	}
	if !target.hurried.Load() {
		t.Error("the second signal did not hurry the runner")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(notices) < 2 {
		t.Errorf("acknowledgements = %v, want one per signal on the terminal", notices)
	}
}

// TestCoordinatorSecondSignalWaitsForFlush: when the scan finishes flushing
// inside the deadline, the second signal does not force an exit.
func TestCoordinatorSecondSignalWaitsForFlush(t *testing.T) {
	c, exited := newTestCoordinator(t)
	c.flushDeadline = 2 * time.Second
	release := make(chan struct{})
	c.attach(&blockingShutdownTarget{release: release})
	c.markRunStarted()
	c.ch <- os.Interrupt
	time.Sleep(20 * time.Millisecond)
	c.ch <- os.Interrupt
	time.Sleep(20 * time.Millisecond)
	close(release)
	c.stop() // the normal exit path finished
	select {
	case code := <-exited:
		t.Fatalf("forced exit %d although the flush completed", code)
	case <-time.After(300 * time.Millisecond):
	}
}

// TestCoordinatorThirdSignalExitsImmediately: a third signal does not wait for
// the flush deadline.
func TestCoordinatorThirdSignalExitsImmediately(t *testing.T) {
	c, exited := newTestCoordinator(t)
	c.flushDeadline = time.Hour
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	c.attach(&blockingShutdownTarget{release: release})
	c.markRunStarted()
	for i := 0; i < 3; i++ {
		c.ch <- os.Interrupt
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case code := <-exited:
		if code != ExitIncomplete {
			t.Fatalf("exit code %d, want %d", code, ExitIncomplete)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a third signal did not exit immediately")
	}
}

// blockingShutdownTarget never finishes its close on its own.
type blockingShutdownTarget struct {
	release chan struct{}
	hurried atomic.Bool
}

func (b *blockingShutdownTarget) Close()   { <-b.release }
func (b *blockingShutdownTarget) Discard() { <-b.release }
func (b *blockingShutdownTarget) Hurry()   { b.hurried.Store(true) }

// TestCoordinatorStopIsIdempotent: stop is deferred on every scan path and may
// run twice (a nested helper plus the outer defer).
func TestCoordinatorStopIsIdempotent(t *testing.T) {
	c, _ := newTestCoordinator(t)
	c.stop()
	c.stop()
}

// TestCoordinatorNilIsSafe: every method is reachable before a scan starts, or
// from a command that never installs one.
func TestCoordinatorNilIsSafe(t *testing.T) {
	var c *scanSignalCoordinator
	if c.Interrupted() {
		t.Error("a nil coordinator must not report an interrupt")
	}
	c.attach(newFakeShutdownTarget())
	c.markRunStarted()
	c.stop()
}
