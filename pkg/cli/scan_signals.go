package cli

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// A scan had two independent signal handlers, installed at different times, and
// between them they could neither interrupt the scan reliably nor describe what
// they had done.
//
//   - scanevents.TrapSignals was installed with the event stream and wrote a
//     terminal scan.finished{interrupted} — but only when --events was on, and
//     it did not stop anything. The scan ran to completion and wrote `complete`
//     to its row, behind an already-latched emitter.
//   - setupScanSignalHandler was installed immediately before RunNativeScan and
//     closed the runner — but a signal arriving during the minutes of setup
//     before that point (database open, schema migration, session login, target
//     expansion) was not trapped by it at all.
//
// scanSignalCoordinator is one handler for the whole scan, installed before any
// of that setup and torn down after the terminal event. It owns three facts the
// old pair split between them: that a shutdown was requested (so the terminal
// event can say `interrupted` rather than `completed`), what to stop, and when
// an impatient second signal means stop waiting.
type scanSignalCoordinator struct {
	ch   chan os.Signal
	done chan struct{}

	mu     sync.Mutex
	target scanShutdownTarget

	interrupted atomic.Bool
	// started says RunNativeScan has been entered, which decides HOW a runner is
	// released — see releaseTarget.
	started  atomic.Bool
	released atomic.Bool

	start    time.Time
	stopOnce sync.Once
	// exit is os.Exit in production, injected in tests so the escalation path can
	// be driven without ending the test process.
	exit func(int)
	// flushDeadline bounds how long a second signal waits for the partial
	// results to flush before exiting 5 (forcedFlushDeadline in production).
	flushDeadline time.Duration
	// notice writes the operator-facing acknowledgements (stderr in
	// production; nil under --silent).
	notice func(string)
}

// forcedFlushDeadline is how long the second Ctrl-C waits for findings and the
// partial report to be written before exiting anyway.
const forcedFlushDeadline = 10 * time.Second

// hurrier is a shutdown target that can drop its shutdown graces (Runner.Hurry).
type hurrier interface{ Hurry() }

// scanShutdownTarget is what a coordinator can stop.
//
// Both methods, not just Close: Runner.Close waits on the channel RunNativeScan
// closes when it returns, so calling it on a runner that never started blocks
// for the entire shutdown timeout (30s by default) waiting for a run that will
// never happen. Discard is the entry point for exactly that case, and widening
// the window in which a signal is trapped is what makes "signalled before the
// run started" a case that actually occurs.
type scanShutdownTarget interface {
	Close()
	Discard()
}

// activeScanSignals is the coordinator for the scan this process is running.
//
// Package-level for the same reason the event emitter is: the scan's runner is
// constructed in half a dozen places (the ingest path, the DB-record path, the
// stdin raw-request path, scan-url) that are reached from executeNativeScan
// through several frames of branching, and threading a coordinator through all
// of them would be a parameter whose only value is to be nil everywhere except
// one call. Nil until a scan starts, and every method is nil-safe.
var activeScanSignals *scanSignalCoordinator

// startScanSignals installs the coordinator and makes it the active one. start
// is the scan's wall-clock anchor, used for the forced-exit terminal event.
func startScanSignals(start time.Time) *scanSignalCoordinator {
	c := &scanSignalCoordinator{
		// Buffered for two: the first signal and the escalating second. An
		// unbuffered channel would let the runtime drop the second while the
		// watcher is busy emitting the first, which is the one case where being
		// dropped is most visible to the operator holding Ctrl+C down.
		ch:            make(chan os.Signal, 3),
		done:          make(chan struct{}),
		start:         start,
		exit:          os.Exit,
		flushDeadline: forcedFlushDeadline,
	}
	if !globalSilent {
		c.notice = func(msg string) { fmt.Fprintln(os.Stderr, msg) }
	}
	signal.Notify(c.ch, scanShutdownSignals...)
	go c.watch()
	activeScanSignals = c
	return c
}

// attach registers the runner to stop when a signal arrives. Calling it after a
// signal has already been handled releases the runner immediately — the signal
// that arrived during setup must not be forgotten just because there was
// nothing to stop at the time.
func (c *scanSignalCoordinator) attach(r scanShutdownTarget) {
	if c == nil || r == nil {
		return
	}
	c.mu.Lock()
	c.target = r
	c.mu.Unlock()
	if c.interrupted.Load() {
		c.releaseTarget()
	}
}

// Interrupted reports whether a shutdown signal has been received.
func (c *scanSignalCoordinator) Interrupted() bool {
	return c != nil && c.interrupted.Load()
}

// markRunStarted records that the scan proper is under way.
func (c *scanSignalCoordinator) markRunStarted() {
	if c != nil {
		c.started.Store(true)
	}
}

// stop unregisters the handler and ends the watcher. Idempotent; safe to defer.
func (c *scanSignalCoordinator) stop() {
	if c == nil {
		return
	}
	c.stopOnce.Do(func() {
		signal.Stop(c.ch)
		close(c.done)
	})
}

// watch is the handler goroutine.
func (c *scanSignalCoordinator) watch() {
	var sig os.Signal
	select {
	case sig = <-c.ch:
	case <-c.done:
		return
	}

	c.interrupted.Store(true)
	zap.L().Info("Shutdown signal received: Exiting", zap.String("signal", sig.String()))
	zap.L().Info("Attempting graceful shutdown...")
	// Straight to the terminal, whatever the log level: an Info line was
	// hidden at the default level and the stop can take half a minute.
	c.say(terminal.WarnPrefix() + " stopping — finishing in-flight work and writing partial results (Ctrl-C again to stop faster)")

	// Nonterminal, and emitted BEFORE the graceful stop rather than after it: a
	// stop can take the full shutdown timeout, and a consumer watching a silent
	// stream for thirty seconds cannot tell a slow phase from a scan on its way
	// out. The terminal scan.finished still follows, from the normal exit path,
	// carrying the totals this one cannot know yet.
	scanevents.Emit(scanevents.Event{
		Type:    scanevents.TypeScanInterrupting,
		Message: sig.String(),
	})
	c.releaseTarget()

	// Keep listening for the impatient second signal until the scan's own
	// teardown stops us. Deliberately NOT "until the close finishes": the close
	// completing is not a reason to stop honouring Ctrl+C, and with the handler
	// registered a signal we stop listening for is a signal the process ignores
	// entirely rather than dying on.
	select {
	case <-c.ch:
	case <-c.done:
		return
	}

	// Second signal: stop waiting on graces, but still flush. The runner drops
	// its shutdown waits and the normal exit path writes the findings and the
	// partial report; if that has not finished within flushDeadline, exit 5
	// with a terminal event that says the flush did not complete.
	zap.L().Warn("Second shutdown signal received, flushing partial results before exit")
	c.say(terminal.WarnPrefix() + fmt.Sprintf(" stopping now — flushing findings and the partial report (up to %s; Ctrl-C again to exit immediately)", c.flushDeadline))
	c.mu.Lock()
	target := c.target
	c.mu.Unlock()
	if h, ok := target.(hurrier); ok {
		h.Hurry()
	}
	forced := time.AfterFunc(c.flushDeadline, func() { c.forceExit() })
	select {
	case <-c.ch:
		// Third signal: no more waiting.
		forced.Stop()
		c.forceExit()
	case <-c.done:
		forced.Stop()
	}
}

// forceExit ends the process with exit 5 (incomplete) after a terminal event
// saying the run was interrupted and its results may not be flushed. os.Exit
// runs no defers, so this is the stream's only terminal line on this path.
func (c *scanSignalCoordinator) forceExit() {
	flushed := false
	scanevents.Finish(scanevents.Event{
		Status:     scanevents.StatusInterrupted,
		DurationMS: time.Since(c.start).Milliseconds(),
		Flushed:    &flushed,
	})
	c.exit(ExitIncomplete)
}

// say writes an operator acknowledgement (no-op under --silent).
func (c *scanSignalCoordinator) say(msg string) {
	if c.notice != nil {
		c.notice(msg)
	}
}

// releaseTarget stops the attached runner, at most once, by whichever route is
// safe for its state. No-op when nothing is attached yet — attach will call back
// here once something is.
func (c *scanSignalCoordinator) releaseTarget() {
	c.mu.Lock()
	target := c.target
	c.mu.Unlock()
	if target == nil || !c.released.CompareAndSwap(false, true) {
		return
	}
	// In its own goroutine: Close blocks until the scan unwinds, and the watcher
	// must stay responsive to the second signal that exists to cut that short.
	go func() {
		if c.started.Load() {
			target.Close()
			return
		}
		target.Discard()
	}()
}

// runNativeScanPass hands the runner to the signal coordinator, runs the scan,
// and releases the runner — as one step, so the three cannot be sequenced
// wrongly. Every caller had been spelling the attach out itself immediately
// above the call, which is one line away from being forgotten.
//
// Attach happens BEFORE the interrupt test, not after: a signal arriving between
// the two still finds a target to release, where the reverse order has a window
// in which the scan runs to completion with the interrupt already delivered.
// attach itself handles the already-interrupted case, so the Discard below is
// the second one on that path — Runner.Discard is once-guarded.
//
// The interrupt test is where a signal received during SETUP takes effect:
// starting a scan the operator has already cancelled would run the whole thing
// before anyone looked at the interrupt again. Discard, not Close — the run
// never happened, so there is no completion to wait for.
func runNativeScanPass(r *runner.Runner) error {
	activeScanSignals.attach(r)
	if activeScanSignals.Interrupted() {
		r.Discard()
		return nil
	}
	activeScanSignals.markRunStarted()
	stopProgress := startProgressLine(r, time.Now())
	err := r.RunNativeScan()
	stopProgress()
	if by := r.StopRequestedBy(); by != "" {
		noteScanStopRequest(by)
	}
	// Close before the caller's export defers read the database, so buffered
	// records land first.
	r.Close()
	// A scope that refused every target is exit 1 with error.code
	// no_targets_in_scope, not a generic failure.
	return codedScanError(err)
}
