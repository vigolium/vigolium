package runner

import (
	"context"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/knownissuescan"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/scanevents"
)

// progressInterval is how often a running phase reports phase.progress.
//
// Five seconds, because the counter this reports is the ONLY thing a consumer
// can read during a crawl that runs 5–15 minutes with no other output. Longer
// and a driver cannot distinguish "working" from "wedged" inside a reasonable
// patience window; shorter and a long scan's stream is mostly heartbeat.
const progressInterval = 5 * time.Second

// phaseTracker owns one phase's slice of the event stream: the started line, a
// progress heartbeat for as long as the phase runs, and the finished line with
// the phase's totals.
//
// It is ALSO the phase's outcome ledger, and that part runs whether or not a
// stream is attached. The two were separate once, and the separation was the
// bug: the only record of "this phase was cut short" lived on an event nobody
// emitted unless --events was passed, so a plain CLI scan and the scan row it
// wrote reported a clean completion for a run that had covered half its input.
// Recording always, emitting conditionally, means the database and the stream
// agree and neither depends on the other being switched on.
//
// The request counters are read off the shared requester rather than accumulated
// here, so a phase that dispatches through a clone (every phase does) is counted
// the same way as one that does not, and nothing on the request hot path has to
// know the event stream exists.
type phaseTracker struct {
	phase     string
	start     time.Time
	requester *http.Requester
	baseSent  int64
	findings  atomic.Int64
	stop      chan struct{}
	stopped   chan struct{}

	// mu guards the outcome ledger. Marks arrive from goroutines the phase does
	// not own — a deadline cancel func, an executor's worker teardown, a deferred
	// writer shutdown — while the phase goroutine is reading them in finish.
	mu         sync.Mutex
	reasons    map[string]struct{}
	limits     map[string]struct{}
	errs       int
	firstErr   string
	skipped    bool
	persist    database.PersistenceOutcome
	hasPersist bool
	unacked    int64
	counters   []phaseCounter
	// counts are the phase-specific tallies persisted on PhaseOutcome.Counts.
	counts map[string]int64
	// inScope are the counters behind requests_in_scope, for phases whose
	// requests_sent includes third-party traffic (the browser crawl). Nil means
	// the phase does not report the field.
	inScope []phaseCounter

	// Work-item progress (done/total/unit on phase.progress and phase.finished).
	// progress is nil for a phase with no count to report; lastTotal is the
	// largest total reported so far, the floor that keeps Total non-decreasing.
	// Guarded by mu.
	progressUnit string
	progress     func() (done, total int64)
	lastTotal    int64
	executors    []*core.Executor

	// quarantined are the hosts whose items the phase's executors dropped for
	// the dead-host breaker, merged across runs. Guarded by mu.
	quarantined map[string]core.QuarantinedHost

	// budgetHosts are the hosts whose --max-requests-per-host ran out during
	// the phase (see noteHostBudget). Guarded by mu.
	budgetHosts map[string]struct{}

	// finishers run in finish, before the outcome is read (see onFinish).
	// Guarded by mu.
	finishers []func(*phaseTracker)

	// findingsCapped is the per-module capped-finding count (see
	// setFindingsCapped). Guarded by mu.
	findingsCapped map[string]int64

	// baseBlocks is the requester's per-host WAF block count when the phase
	// began; a host whose count grew was blocked during the phase (edge_blocked).
	baseBlocks map[string]int64
	// blockedHosts is set at finish from that delta. Guarded by mu.
	blockedHosts []string

	// ledger is the scan's module ledger every executor report folds into
	// (nil-safe).
	ledger *moduleErrorLedger
}

// noteEdgeBlocks compares the requester's per-host block counts with the
// phase-start snapshot: a host blocked during the phase makes the phase
// partial with edge_blocked, so a blocked scan never reads "complete, 0
// findings".
func (t *phaseTracker) noteEdgeBlocks() {
	if t == nil || t.requester == nil {
		return
	}
	var hosts []string
	for host, n := range t.requester.BlockCounts() {
		if n > t.baseBlocks[host] {
			hosts = append(hosts, host)
		}
	}
	if len(hosts) == 0 {
		return
	}
	sort.Strings(hosts)
	t.mu.Lock()
	t.blockedHosts = hosts
	t.mu.Unlock()
	t.markPartial(database.ReasonEdgeBlocked)
}

// setFindingsCapped records the per-module findings the cap dropped and notes
// the findings_per_module limit when any were. The latest value wins: the
// dynamic-assessment phase reads it off its shared FindingAdmission, which is
// already the phase total.
func (t *phaseTracker) setFindingsCapped(capped map[string]int64) {
	if t == nil || len(capped) == 0 {
		return
	}
	t.mu.Lock()
	t.findingsCapped = make(map[string]int64, len(capped))
	for module, n := range capped {
		t.findingsCapped[module] = n
	}
	t.mu.Unlock()
	t.noteLimit(database.LimitFindingsPerModule)
}

// onFinish registers fn to run when the phase finishes, before its outcome is
// snapshotted, so it can still mark reasons, limits and counts — for state
// that lives outside the phase (a live session's logged-out tally).
func (t *phaseTracker) onFinish(fn func(*phaseTracker)) {
	if t == nil || fn == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.finishers = append(t.finishers, fn)
}

// Units for phase progress. One table so a consumer sees one spelling per kind.
const (
	progressUnitRecords = "records"
	progressUnitTargets = "targets"
)

// executorProgressUnit names the phases whose progress is read off the
// executors they run, and the unit each one counts. These phases feed an input
// source through core.Executor, so done is the executors' processed count and
// total is their sources' size.
//
// Phases that walk a target list themselves report through trackTargets
// instead. Discovery is absent on purpose: its executor's input is the deparos
// output stream, which has no size, and the honest figure is the coordinator's
// tasks done/enqueued.
//
// TODO(plan D): wire discovery as progressUnit "tasks" from the deparos
// coordinator's Progress() accessor once the discovery source exposes it.
var executorProgressUnit = map[NativePhase]string{
	PhaseDynamicAssessment: progressUnitRecords,
	PhaseSeed:              progressUnitRecords,
	PhaseProbe:             progressUnitTargets,
	PhaseFingerprint:       progressUnitRecords,
}

// phaseCounter is one additional request counter a phase contributes, with the
// value it held when it was registered. The delta is what counts: a counter whose
// owner was already in use before the phase began must only contribute what
// happened inside the phase.
type phaseCounter struct {
	read func() int64
	base int64
}

// beginPhase emits phase.started and starts the progress heartbeat. The returned
// tracker is always non-nil so the caller's finish call needs no guard; when the
// stream is off it still records the phase's outcome and simply emits nothing.
func (r *Runner) beginPhase(ctx context.Context, phase string, requester *http.Requester) *phaseTracker {
	t := &phaseTracker{
		phase:     phase,
		start:     time.Now(),
		requester: requester,
		reasons:   make(map[string]struct{}),
		limits:    make(map[string]struct{}),
	}
	if requester != nil {
		t.baseBlocks = requester.BlockCounts()
	}
	t.ledger = r.moduleErrors.Load()
	if !scanevents.On() {
		return t
	}
	t.baseSent = requester.RequestsSent()
	scanevents.Emit(scanevents.Event{Type: scanevents.TypePhaseStarted, Phase: phase})

	t.stop = make(chan struct{})
	t.stopped = make(chan struct{})
	go t.heartbeat(ctx)
	return t
}

func (t *phaseTracker) heartbeat(ctx context.Context) {
	defer close(t.stopped)
	ticker := time.NewTicker(progressInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			ev := scanevents.Event{
				Type:         scanevents.TypePhaseProgress,
				Phase:        t.phase,
				RequestsSent: scanevents.Int64(t.sentSoFar()),
				Findings:     scanevents.Int64(t.findings.Load()),
			}
			t.fillInScope(&ev)
			t.fillProgress(&ev)
			scanevents.Emit(ev)
		case <-t.stop:
			return
		case <-ctx.Done():
			return
		}
	}
}

// inScopeSoFar sums the in-scope counters; ok is false when none is registered.
func (t *phaseTracker) inScopeSoFar() (n int64, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, c := range t.inScope {
		n += c.read() - c.base
	}
	return n, len(t.inScope) > 0
}

// fillInScope sets requests_in_scope when the phase registered a counter for it.
func (t *phaseTracker) fillInScope(ev *scanevents.Event) {
	if n, ok := t.inScopeSoFar(); ok {
		ev.RequestsInScope = scanevents.Int64(n)
	}
}

func (t *phaseTracker) sentSoFar() int64 {
	var total int64
	if t.requester != nil {
		total = t.requester.RequestsSent() - t.baseSent
	}
	return total + t.extraSentSoFar()
}

// extraSentSoFar sums only the counters registered with addCounter — the
// requests this phase sent outside the shared requester. The liveness
// heartbeat adds it to the requester's scan-wide count. Nil-safe.
func (t *phaseTracker) extraSentSoFar() int64 {
	if t == nil {
		return 0
	}
	var total int64
	t.mu.Lock()
	for _, c := range t.counters {
		total += c.read() - c.base
	}
	t.mu.Unlock()
	return total
}

// addCounter registers an additional request counter with the running phase, read
// as a delta from its value right now.
//
// The tracker's primary figure is a delta on the SHARED requester, which is the
// right reading for every phase that dispatches through it. Two do not: discovery
// runs deparos, which owns its own HTTP client, and a rate-limit-overridden probe
// builds a phase-local requester. Both reported ≈0 requests for phases that sent
// the bulk of a scan's traffic. A counter added here is summed into every
// phase.progress and phase.finished line for the rest of the phase.
//
// Safe to call concurrently with the heartbeat that reads them.
func (t *phaseTracker) addCounter(f func() int64) {
	if t == nil || f == nil {
		return
	}
	base := f()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.counters = append(t.counters, phaseCounter{read: f, base: base})
}

// addInScopeCounter registers a counter for requests_in_scope, the in-scope
// share of the requests a counter given to addCounter reports. Read as a delta
// from its value now, like addCounter.
func (t *phaseTracker) addInScopeCounter(f func() int64) {
	if t == nil || f == nil {
		return
	}
	base := f()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.inScope = append(t.inScope, phaseCounter{read: f, base: base})
}

// setProgress installs the phase's work-item progress source: f reports how many
// items are done and the current bound on how many there are, in unit. The last
// call wins. Safe to call concurrently with the heartbeat that reads it.
//
// f may return a total that shrinks or reads below done (a live source's
// snapshot, a coalesced round); the tracker clamps it, so f can report its raw
// figures.
func (t *phaseTracker) setProgress(unit string, f func() (done, total int64)) {
	if t == nil || f == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.progressUnit = unit
	t.progress = f
}

// observeExecutor is the core.ExecutorObserver for a phase whose progress is
// read off its executors. Every executor the phase starts is summed, so a
// multi-round phase reports cumulative done and a total that grows round by
// round as each new round's source learns its size.
func (t *phaseTracker) observeExecutor(e *core.Executor) {
	if t == nil || e == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, seen := range t.executors {
		if seen == e {
			return
		}
	}
	t.executors = append(t.executors, e)
}

// executorProgress sums done/total over the executors the phase has started.
func (t *phaseTracker) executorProgress() (done, total int64) {
	t.mu.Lock()
	execs := append([]*core.Executor(nil), t.executors...)
	t.mu.Unlock()
	for _, e := range execs {
		done += e.Processed()
		total += e.KnownTotal()
	}
	return done, total
}

// targetProgress counts the targets a phase has finished against the number it
// set out to cover. Nil-safe, so a phase can call it whether or not a tracker is
// running.
type targetProgress struct {
	done  atomic.Int64
	total atomic.Int64
}

// Add records n more targets finished.
func (p *targetProgress) Add(n int) {
	if p == nil {
		return
	}
	p.done.Add(int64(n))
}

// Set records the number of targets finished so far, for a loop that already
// keeps its own running count.
func (p *targetProgress) Set(n int) {
	if p == nil {
		return
	}
	p.done.Store(int64(n))
}

// trackTargets makes the phase report done/total in targets, against total
// targets. Returns the counter the phase advances as each target finishes.
func (t *phaseTracker) trackTargets(total int) *targetProgress {
	if t == nil {
		return nil
	}
	p := &targetProgress{}
	p.total.Store(int64(total))
	t.setProgress(progressUnitTargets, func() (int64, int64) {
		return p.done.Load(), p.total.Load()
	})
	return p
}

// fillProgress sets done/total/unit on ev from the phase's progress source, and
// leaves them unset when the phase has none.
//
// Total is clamped to be non-decreasing and never below done, which is the
// documented contract: an upper bound that may grow. A total of zero with no
// earlier reading means "no bound known yet" and is omitted rather than
// reported as 0, which would read as "nothing to do".
func (t *phaseTracker) fillProgress(ev *scanevents.Event) {
	p := t.progressSnapshot()
	if p == nil {
		return
	}
	ev.Done = scanevents.Int64(p.Done)
	ev.Total = p.Total
	ev.Unit = p.Unit
}

// progressSnapshot reads the phase's progress source once, applying the
// clamp fillProgress documents. Nil when the phase has no source (or the
// tracker is nil); Total is nil until a bound is known. Shared by the event
// stream and the liveness heartbeat so both report the same numbers.
func (t *phaseTracker) progressSnapshot() *SessionProgress {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	f, unit := t.progress, t.progressUnit
	t.mu.Unlock()
	if f == nil {
		return nil
	}
	done, total := f()

	t.mu.Lock()
	known := total > 0 || t.lastTotal > 0
	if total < t.lastTotal {
		total = t.lastTotal
	}
	if known && total < done {
		total = done
	}
	t.lastTotal = total
	t.mu.Unlock()

	p := &SessionProgress{Done: done, Unit: unit}
	if known {
		p.Total = scanevents.Int64(total)
	}
	return p
}

// recordFinding counts a finding against the running phase, so phase.finished
// reports what the phase actually produced rather than a scan-wide total.
func (t *phaseTracker) recordFinding() {
	if t == nil {
		return
	}
	t.findings.Add(1)
}

// addCode inserts code into *set, allocating the set on first use and ignoring
// an empty code. Caller holds t.mu.
//
// The sets are lazily allocated because beginPhase is not the only way a tracker
// comes into existence — a bare &phaseTracker{} is a valid, nil-safe one — so
// every writer has to tolerate a nil map.
func addCode(set *map[string]struct{}, code string) {
	if code == "" {
		return
	}
	if *set == nil {
		*set = make(map[string]struct{})
	}
	(*set)[code] = struct{}{}
}

// markPartial records a reason the phase did not cover everything it was given.
// Idempotent per code: the same reason arriving from two places (a deadline that
// fired AND the skipped-target count it produced) is one reason, not two.
func (t *phaseTracker) markPartial(code string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	addCode(&t.reasons, code)
}

// noteLimit records that a configured bound was reached. Separate from a reason
// on purpose: a target that used its whole time budget behaved exactly as
// configured, and folding that into "partial" would mark every properly
// time-boxed scan as degraded.
func (t *phaseTracker) noteLimit(code string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	addCode(&t.limits, code)
}

// markSkipped records that the phase never ran, with the reason it was skipped.
func (t *phaseTracker) markSkipped(code string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.skipped = true
	addCode(&t.reasons, code)
}

// addPersistence folds a writer-shutdown outcome into the phase, and marks the
// phase partial when the writer could not account for every write it accepted.
// Several writers per phase merge into one figure (see PersistenceOutcome.Merge).
func (t *phaseTracker) addPersistence(o database.PersistenceOutcome) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.persist.Merge(o)
	t.hasPersist = true
	notClean := !o.Clean()
	t.mu.Unlock()
	if notClean {
		t.markPartial(database.ReasonPersistence)
	}
}

// noteExecution folds one Execute call's self-report into the phase. A phase can
// run several (dynamic assessment runs one executor per feedback round), so the
// marks accumulate and the un-acknowledged count sums.
func (t *phaseTracker) noteExecution(rep core.ExecutionReport) {
	if t == nil {
		return
	}
	if rep.StoppedEarly {
		t.markPartial(database.ReasonInputIncomplete)
	}
	if rep.DrainStalled {
		t.markPartial(database.ReasonDrainStalled)
	}
	if rep.WorkersAbandoned {
		t.markPartial(database.ReasonWorkersAbandoned)
	}
	if rep.DeferredFlushSkipped {
		t.markPartial(database.ReasonDeferredFlushSkipped)
	}
	t.noteQuarantineSkips(rep)
	// Every item scope looked at was refused and none got an answer: the
	// executor ran and covered nothing. For CLI targets the preflight admission
	// says so before the run; this is the same signal for input that is not a
	// target list (-i specs, DB rescans, scan-on-receive), where scope only
	// meets the records one by one.
	if rep.ScopeRejected > 0 && rep.Responded == 0 {
		t.markPartial(database.ReasonTargetsOutOfScope)
	}
	if rep.Unacked > 0 {
		t.mu.Lock()
		t.unacked += rep.Unacked
		t.mu.Unlock()
	}
	// The report carries the running total of the (possibly shared) admission,
	// so the latest one is the phase's.
	t.setFindingsCapped(rep.FindingsCapped)
	t.ledger.addExecution(rep)
}

// setCount records a phase-specific tally for PhaseOutcome.Counts. The last value
// set for a name wins; zero values are kept, so a consumer can tell "probed 0"
// from "did not report".
func (t *phaseTracker) setCount(name string, n int64) {
	if t == nil || name == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.counts == nil {
		t.counts = make(map[string]int64)
	}
	t.counts[name] = n
}

// finish closes out the phase: it always computes the phase's outcome, and emits
// phase.finished only when a stream is attached.
//
// status mapping: completed → "completed", partial → "curtailed", failed →
// "failed", skipped → "completed" (with its reason, since a skipped phase is not
// a degraded one). A phase whose own deadline fired now reports "curtailed"
// rather than "completed" — before, only the OUTER context was consulted, so a
// per-phase max_duration that fired inside a healthy scan was invisible.
func (t *phaseTracker) finish(ctx context.Context, err error) database.PhaseOutcome {
	if t == nil {
		return database.PhaseOutcome{}
	}
	// recordError, not noteError: an error that reaches finish is the one the
	// CALLER is returning, so it rides out on scan.finished. Emitting a non-fatal
	// `error` event for it too would contradict that event's contract, and a
	// failure the scan survives has already been through noteError (see
	// executeNativePhase).
	t.recordError(err)
	// The context the phase ran under explains a curtailment the phase itself
	// cannot see: the total scan budget, the request budget, or an operator's
	// Ctrl-C.
	if ctx != nil && ctx.Err() != nil {
		t.markPartial(contextStopReason(ctx))
	}
	t.noteEdgeBlocks()
	t.mu.Lock()
	finishers := t.finishers
	t.mu.Unlock()
	for _, fn := range finishers {
		fn(t)
	}

	out := t.outcome()

	if t.stop == nil {
		return out
	}
	close(t.stop)
	<-t.stopped

	status := scanevents.StatusCompleted
	switch out.State {
	case database.PhaseFailed:
		status = scanevents.StatusFailed
	case database.PhasePartial:
		status = scanevents.StatusCurtailed
	}
	ev := scanevents.Event{
		Type:         scanevents.TypePhaseFinished,
		Phase:        t.phase,
		Status:       status,
		DurationMS:   out.DurationMS,
		RequestsSent: scanevents.Int64(t.sentSoFar()),
		Findings:     scanevents.Int64(t.findings.Load()),
		Reasons:      out.Reasons,
		Limits:       out.Limits,
	}
	if len(out.FindingsCapped) > 0 {
		ev.FindingsCapped = out.FindingsCapped
	}
	if out.Message != "" {
		ev.Message = out.Message
	}
	t.fillInScope(&ev)
	t.fillProgress(&ev)
	scanevents.Emit(ev)
	return out
}

// outcome snapshots the ledger. Split out of finish so the outcome can be read
// without the emission side effects (and so the lock is held for exactly as long
// as the copy takes).
func (t *phaseTracker) outcome() database.PhaseOutcome {
	t.mu.Lock()
	defer t.mu.Unlock()

	out := database.PhaseOutcome{
		Phase:       t.phase,
		Reasons:     database.SortedCodes(t.reasons),
		Limits:      database.SortedCodes(t.limits),
		Errors:      t.errs,
		Message:     t.firstErr,
		Unprocessed: t.unacked,
		DurationMS:  time.Since(t.start).Milliseconds(),
	}
	out.State = database.ResolvePhaseState(out.Errors, out.Reasons, t.skipped)
	out.BudgetExhaustedHosts = database.SortedCodes(t.budgetHosts)
	t.fillQuarantined(&out)
	if t.hasPersist {
		p := t.persist
		out.Persistence = &p
	}
	if len(t.counts) > 0 {
		out.Counts = make(map[string]int64, len(t.counts))
		for name, n := range t.counts {
			out.Counts[name] = n
		}
	}
	if len(t.blockedHosts) > 0 {
		out.BlockedHosts = append([]string(nil), t.blockedHosts...)
	}
	if len(t.findingsCapped) > 0 {
		out.FindingsCapped = make(map[string]int64, len(t.findingsCapped))
		for module, n := range t.findingsCapped {
			out.FindingsCapped[module] = n
		}
	}
	return out
}

// attachEventObserver routes every finding the output writer emits into the
// machine event stream, and counts it against the phase that produced it and
// the scan's liveness heartbeat. One call, one seam: the runner has ~six
// OnResult callbacks and the writer is the only thing all of them reach.
//
// Attached whether or not a stream is on (the heartbeat counts findings on
// every run), and only once per writer: a Runner reused across agent rescans
// calls this per run, and chaining a second wrapper would count and emit every
// finding twice. The wrapper reads the current phase and heartbeat at call
// time, so one attachment serves every run.
func (r *Runner) attachEventObserver() {
	sw, ok := r.output.(*output.StandardWriter)
	if !ok {
		return
	}
	if !r.eventObserverAttached.CompareAndSwap(false, true) {
		return
	}
	prior := sw.OnEvent
	sw.OnEvent = func(ev *output.ResultEvent) {
		if prior != nil {
			prior(ev)
		}
		r.currentPhase.Load().recordFinding()
		if ev != nil {
			r.liveness.Load().RecordFinding(ev.Info.Severity.String())
		}
		emitFindingEvent(ev)
	}
}

// noteError reports a phase failure the scan SURVIVED. Most phases log and carry
// on, so their error never reaches the caller and never reaches phase.finished's
// status either — from the stream alone the phase looked fine. An `error` event
// is non-fatal by construction; a failure that ends the run rides on
// scan.finished instead.
//
// A method on the tracker rather than a free function taking a name: the tracker
// owns the CANONICAL phase id, while the scan log labels phases with the short
// tags ("heuristics", "harvest", "respider"). Hand-typing the label had already
// produced three phases that reported one spelling on phase.started and another
// on error, which silently breaks a consumer correlating the two.
func (t *phaseTracker) noteError(err error) {
	if t == nil || err == nil {
		return
	}
	// Record BEFORE the stream check. The outcome ledger is what the scan row and
	// the console banner read, and it has to be right whether or not --events was
	// passed — a phase that failed on a plain CLI run used to leave no structured
	// trace at all because this method bailed out here first.
	t.recordError(err)
	if !scanevents.On() {
		return
	}
	scanevents.Emit(scanevents.Event{
		Type:    scanevents.TypeError,
		Phase:   t.phase,
		Message: err.Error(),
	})
}

// recordError folds a phase failure into the ledger: the count, and the first
// error's text as the outcome's message.
//
// First rather than last, because the first failure in a phase is normally the
// cause and the rest are consequences of it (one unreachable host producing a
// failure per module), and because the message is bounded — keeping the latest
// would mean the stored explanation changes every time a downstream error
// arrives.
func (t *phaseTracker) recordError(err error) {
	if t == nil || err == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.errs++
	if t.firstErr == "" {
		t.firstErr = database.TruncateOutcomeMessage(err.Error())
	}
}

// emitBlockEvent mirrors the operator's [waf-block-detected] stderr line onto
// the machine stream. Both hang off the same notifier, so a consumer never has
// to scrape a rendered session log to recover a block — which is what it had to
// do before, at the cost of an N+1 subprocess walk per sweep.
func emitBlockEvent(n http.BlockNotice) {
	if !scanevents.On() {
		return
	}
	vendor := n.WAFType
	if vendor == "" || vendor == "generic" {
		vendor = "unknown"
	}
	scanevents.Emit(scanevents.Event{
		Type:       scanevents.TypeWAFBlock,
		Host:       n.Host,
		Vendor:     vendor,
		StatusCode: n.Status,
		Detail:     "edge is filtering scan traffic — results for this host may be incomplete",
	})
}

// emitPacingEvent mirrors [waf-pacing-armed] onto the machine stream, spelling
// out the concurrency drop so a consumer can attribute a slowdown to the pacing
// decision rather than to the target.
func emitPacingEvent(host, vendor string, from, to int) {
	if !scanevents.On() {
		return
	}
	if vendor == "" {
		vendor = "unknown"
	}
	scanevents.Emit(scanevents.Event{
		Type:            scanevents.TypeWAFPacing,
		Host:            host,
		Vendor:          vendor,
		ConcurrencyFrom: from,
		ConcurrencyTo:   to,
		Detail:          "proactive pacing: host is behind a CDN/WAF edge",
	})
}

// emitFindingEvent reports a finding as it is discovered. Deliberately a
// metadata line, not the finding: the stream is a progress channel, and the
// evidence lives in the database the consumer already has a handle to (the path
// is on scan.started). Carrying request/response bytes here would make the
// stream large enough that flushing per line stops being cheap.
func emitFindingEvent(result *output.ResultEvent) {
	if result == nil || !scanevents.On() {
		return
	}
	scanevents.Emit(scanevents.Event{
		Type:       scanevents.TypeFindingNew,
		Severity:   strings.ToLower(result.Info.Severity.String()),
		Confidence: strings.ToLower(result.Info.Confidence.String()),
		ModuleID:   result.ModuleID,
		URL:        result.URL,
		Host:       result.Host,
	})
}

// knownIssueScanEdge builds the pacing/detection hooks handed to the
// known-issue-scan phase. Both are backed by objects the rest of the scan
// already shares: the requester (whose block notifier and host-limiter feedback
// fire as a side effect of every probe) and the host limiter itself.
//
// Returns a zero Edge when there is no requester — the phase then behaves as it
// did before, which is the correct degradation for a caller that never built the
// shared infrastructure (a test, or an API path constructing the config by hand).
func (r *Runner) knownIssueScanEdge(infra *phaseInfra) knownissuescan.Edge {
	if infra == nil || infra.httpRequester == nil {
		return knownissuescan.Edge{}
	}
	requester := infra.httpRequester
	edge := knownissuescan.Edge{
		Probe: func(ctx context.Context, rawURL string) (bool, error) {
			return probeEdgeThroughRequester(ctx, requester, rawURL)
		},
	}
	if infra.hostLimiter != nil {
		limiter := infra.hostLimiter
		edge.HostLimit = limiter.CurrentLimit
	}
	return edge
}

// probeEdgeThroughRequester sends one GET to rawURL on the shared requester and
// reports whether the edge answered with a block.
//
// The classification is not done here: it is done inside the requester, by the
// same detector every other phase's traffic passes through, and its side effects
// (the one-time-per-host operator notice, the waf.block event, the limiter's
// WAF-auto-arm feedback) all fire from there. This function only needs to know
// whether the notifier considered the host blocked, which it learns by watching
// the requester's own classification via the response status and the block
// detector's verdict on the returned chain.
func probeEdgeThroughRequester(ctx context.Context, requester *http.Requester, rawURL string) (bool, error) {
	rr, err := httpmsg.GetRawRequestFromURL(rawURL)
	if err != nil {
		return false, err
	}
	chain, _, err := requester.ExecuteContext(ctx, rr, http.Options{})
	if err != nil {
		return false, err
	}
	return http.IsBlockedResponse(chain), nil
}

// LiveProgress reports the running phase, its work-item progress (nil when
// the phase has no count) and the findings it recorded so far. phase is ""
// between phases. For the CLI's foreground progress line.
func (r *Runner) LiveProgress() (phase string, progress *SessionProgress, findings int64) {
	t := r.currentPhase.Load()
	if t == nil {
		return "", nil, 0
	}
	return t.phase, t.progressSnapshot(), t.findings.Load()
}
