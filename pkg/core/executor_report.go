package core

import (
	"github.com/vigolium/vigolium/pkg/core/stats"
)

// ExecutionReport says whether one Execute call processed its whole input, and
// what it gave up on if not.
//
// Execute returns (bool, error) where the bool is "produced findings" and the
// error is nil on every one of these paths: a cancelled feed, an abandoned
// drain, abandoned workers, a skipped deferred flush. Each of those silently
// reduces coverage, and the caller had no way to learn about any of them — a
// scan whose workers were abandoned mid-flight reported exactly what a clean one
// did. This is that missing channel.
type ExecutionReport struct {
	// StoppedEarly — the input source was not read to EOF (cancelled, deadline,
	// or a paused scan that was stopped while waiting).
	StoppedEarly bool
	// DrainStalled — the feedback drain was abandoned with workers still in
	// flight and making no progress.
	DrainStalled bool
	// WorkersAbandoned — one or more workers did not exit within the shutdown
	// grace and were leaked.
	WorkersAbandoned bool
	// DeferredFlushSkipped — the end-of-run passive flush was skipped because a
	// worker was abandoned, so deferred findings (secret detection, anomaly
	// ranking) may be incomplete.
	DeferredFlushSkipped bool
	// Unacked counts work items a worker dequeued but deliberately did NOT
	// acknowledge, because the context was already cancelled when it got them.
	// Not acknowledging is what keeps the durable cursor behind them so a later
	// run re-serves them; this number is how many that was.
	Unacked int64
	// ScopeRejected counts input items this run dropped as out of scope, before
	// or after the baseline fetch. Not a coverage gap (scope is the operator's
	// choice), so Clean ignores it; a consumer compares it with Responded to
	// spot a run whose every input was rejected.
	ScopeRejected int64
	// Responded counts input items this run got an HTTP response for.
	Responded int64
	// SkippedQuarantined counts input items this run dropped because their
	// host:port was quarantined by the dead-host breaker — before dispatch, or
	// when the baseline fetch was refused for the same reason. A coverage gap
	// (the runner reports it as targets_unreachable), but not one Clean
	// covers: it is the target's doing, not the executor's.
	SkippedQuarantined int64
	// QuarantinedHosts breaks SkippedQuarantined down per host:port, sorted
	// by host and capped.
	QuarantinedHosts []QuarantinedHost
	// FeedbackDropped counts discovered requests modules fed back that were
	// dropped because the feedback overflow list was full. A coverage gap the
	// runner reports as feedback_dropped.
	FeedbackDropped int64
}

// Clean reports whether the run covered its whole input with nothing abandoned.
//
// A convenience for callers and tests that want the one-line question. The
// runner's own consumer (phaseTracker.noteExecution) deliberately does not use
// it: each flag maps to a distinct outcome reason code, so it has to read them
// individually.
func (r ExecutionReport) Clean() bool {
	return !r.StoppedEarly && !r.DrainStalled && !r.WorkersAbandoned &&
		!r.DeferredFlushSkipped && r.Unacked == 0
}

// Report returns this executor's coverage self-report. Call it after Execute has
// returned; before that the fields are still being written.
func (e *Executor) Report() ExecutionReport {
	rep := e.report
	rep.Unacked = e.unacked.Load()
	rep.ScopeRejected = e.scopeRejected.Load() - e.reportBase.scopeRejected
	rep.Responded = e.responded.Load() - e.reportBase.responded
	rep.FeedbackDropped = e.FeedbackDropped() - e.reportBase.feedbackDropped
	e.quarantineReport(&rep)
	return rep
}

// Processed returns the number of items processed by the executor.
func (e *Executor) Processed() int64 {
	if e.statsTracker != nil {
		return e.statsTracker.Processed()
	}
	return 0
}

// ModuleMetrics returns a point-in-time snapshot of per-module performance metrics.
func (e *Executor) ModuleMetrics() map[string]stats.ModuleStatsSnapshot {
	if e.moduleMetrics != nil {
		return e.moduleMetrics.Snapshot()
	}
	return nil
}

// FeedbackDropped returns the number of feedback items dropped due to channel capacity.
func (e *Executor) FeedbackDropped() int64 {
	if e.pool.feeder != nil {
		return e.pool.feeder.Dropped()
	}
	return 0
}

// SuppressedFindings returns the number of candidate findings dropped by the
// body-differential safety net because a real payload-vs-baseline difference
// could not be re-confirmed.
func (e *Executor) SuppressedFindings() int64 {
	return e.suppressedFindings.Load()
}

// Stored returns the number of input items whose primary record is in the
// database when this executor finished with them. Use this, not Processed(),
// to report how many records a run PERSISTED: Processed() counts attempts, and
// an attempt that never reached a host, or whose write failed, stores nothing.
func (e *Executor) Stored() int64 {
	return e.stored.Load()
}

// StoreFailed returns the number of input items whose primary record could not
// be written. Distinct from an item that was never stored because it got no
// response (Processed() minus Responded()) or because a filter dropped it: this
// one reached the database and the database refused it.
func (e *Executor) StoreFailed() int64 {
	return e.storeFailed.Load()
}

// Responded returns how many input items produced an HTTP response, which is
// always <= Processed(). Use this, not Processed(), to report how many targets
// answered: Processed() counts attempts, including the ones that never reached
// a server. See the responded field for why the two differ.
func (e *Executor) Responded() int64 {
	return e.responded.Load()
}

// InFlight returns the number of worker goroutines currently processing items.
// Zero means the executor is quiescent (all workers idle, no items in flight).
// Exposed for status reporting — callers typically combine this with source-level
// idle signals to distinguish "still doing work" from "waiting for input."
func (e *Executor) InFlight() int64 {
	return e.pool.inFlight.Load()
}

// ConsideredModuleCount returns the number of distinct modules whose CanProcess
// has been evaluated at least once during this scan. Reaches parity with the
// total enabled-module count once every module has been seen — including those
// whose CanProcess always rejects the input shape (e.g., POST-only modules in
// a GET-only scan). Use this for "modules scanned X/Y" status displays.
func (e *Executor) ConsideredModuleCount() int64 {
	if e.moduleMetrics == nil {
		return 0
	}
	return e.moduleMetrics.ConsideredCount()
}

// ResolveRequestUUID resolves a request hash to its database record UUID.
// Implements modkit.RequestUUIDResolver.
func (e *Executor) ResolveRequestUUID(requestHash string) string {
	val, _ := e.caches.requestUUIDs.Load(requestHash)
	return val
}
