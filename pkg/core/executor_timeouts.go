package core

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"go.uber.org/zap"
)

// defaultPassiveModuleTimeout limits how long a single passive module can take per request.
const defaultPassiveModuleTimeout = 5 * time.Second

// defaultActiveModuleTimeout limits how long a single active module can take per
// (record / insertion-point) call. Active modules run multi-probe injection so this
// is much higher than the passive default; modules that legitimately need longer
// (e.g. diffscan behavioral timing analysis) opt in via modules.TimeoutHinter.
const defaultActiveModuleTimeout = 300 * time.Second

// moduleDeadlineGrace is how far before the hard per-module watchdog a contextual
// module's handed context is cancelled. It gives a deadline-aware module (one that
// checks its context between insertion points) a window to unwind its loop and
// return the findings it has already confirmed, so the executor collects them via
// the result channel instead of the hard timeout discarding everything.
const moduleDeadlineGrace = 15 * time.Second

const (
	// timeoutScaleRefPoints is the insertion-point count that maps a whole-request
	// module to the base per-module timeout (1x). A ScanPerRequest module loops
	// over every insertion point in a single call, so a browser-captured request
	// (many cookies + headers → 20+ points) legitimately needs proportionally
	// longer than a bare URL, or it exceeds the base timeout mid-loop.
	timeoutScaleRefPoints = 10
	// maxModuleTimeoutScale caps how far the per-module timeout may stretch for a
	// high-insertion-point request, so a pathological request can't wedge a phase.
	maxModuleTimeoutScale = 5
)

// scaleModuleTimeout stretches the base per-module timeout in proportion to the
// number of insertion points a whole-request module must cover, capped at
// maxModuleTimeoutScale x. Returns base unchanged when workUnits is at or below
// the reference (the common small-request case) or when base is non-positive.
func scaleModuleTimeout(base time.Duration, workUnits int) time.Duration {
	if base <= 0 || workUnits <= timeoutScaleRefPoints {
		return base
	}
	scale := min(float64(workUnits)/float64(timeoutScaleRefPoints), maxModuleTimeoutScale)
	return time.Duration(float64(base) * scale)
}

// passiveModuleTimeout returns the effective passive module timeout.
func (e *Executor) passiveModuleTimeout() time.Duration {
	if e.cfg.PassiveModuleTimeout > 0 {
		return e.cfg.PassiveModuleTimeout
	}
	return defaultPassiveModuleTimeout
}

// activeModuleTimeout returns the effective active module timeout.
func (e *Executor) activeModuleTimeout() time.Duration {
	if e.cfg.ActiveModuleTimeout > 0 {
		return e.cfg.ActiveModuleTimeout
	}
	return defaultActiveModuleTimeout
}

// Adaptive per-module timeout bounds (ECON-7).
const (
	adaptiveTimeoutMinSamples = 50
	adaptiveTimeoutFactor     = 3
	adaptiveTimeoutMin        = 30 * time.Second
	adaptiveTimeoutMax        = 300 * time.Second
)

// adaptiveActiveTimeout is the base per-call timeout for moduleID. With an
// operator-configured ActiveModuleTimeout that value is used as-is. Otherwise,
// once the module has at least adaptiveTimeoutMinSamples completed calls in
// this executor, the timeout follows its own observed latency — p99 × 3,
// clamped to [30s, 300s] — instead of a flat 300s, so a stuck call on a module
// that normally takes 2s is given up on in 30s rather than five minutes
// (ECON-7). A module's TimeoutHint still raises it (see runActiveCall).
func (e *Executor) adaptiveActiveTimeout(moduleID string) time.Duration {
	if e.cfg.ActiveModuleTimeout > 0 {
		return e.cfg.ActiveModuleTimeout
	}
	p99, n := e.moduleMetrics.LatencyQuantile(moduleID, 0.99)
	if n < adaptiveTimeoutMinSamples {
		return e.activeModuleTimeout()
	}
	t := p99 * adaptiveTimeoutFactor
	if t < adaptiveTimeoutMin {
		t = adaptiveTimeoutMin
	}
	if t > adaptiveTimeoutMax {
		t = adaptiveTimeoutMax
	}
	return t
}

// maxModuleTimeout returns the longest a single module call can legitimately
// run: the larger of the base active/passive timeouts and the largest
// TimeoutHint any registered module advertises (both scan wrappers raise their
// per-call timeout to the hint via modules.TimeoutHinter). The active
// contribution is the scaled ceiling (activeModuleTimeout x maxModuleTimeoutScale)
// because whole-request modules stretch their per-call timeout up to that scale
// via scaleModuleTimeout — so a legitimately long, high-insertion-point scan
// still running during the post-EOF drain is not mistaken for a wedged worker.
// The drain stall cap is derived from this.
func (e *Executor) maxModuleTimeout() time.Duration {
	maxT := e.activeModuleTimeout() * maxModuleTimeoutScale
	if pt := e.passiveModuleTimeout(); pt > maxT {
		maxT = pt
	}
	consider := func(m modules.Module) {
		if hinter, ok := m.(modules.TimeoutHinter); ok {
			if hint := hinter.TimeoutHint(); hint > maxT {
				maxT = hint
			}
		}
	}
	for _, m := range e.activeModules {
		consider(m)
	}
	for _, m := range e.passiveModules {
		consider(m)
	}
	return maxT
}

// feedbackDrainMaxStall returns the hard cap on how long the post-EOF feedback
// drain will wait while workers are still in flight but making no forward
// progress. The idle-detection branch in the drain loop only fires once
// inFlight reaches 0, so without this bound a module that ignores context
// cancellation (and never returns) would hang the drain — and the whole scan —
// indefinitely. Defaults to twice the longest legitimate module call
// (maxModuleTimeout, which includes per-module TimeoutHints) so a slow-but-not-
// wedged module isn't abandoned, while a truly stuck worker still trips the cap.
func (e *Executor) feedbackDrainMaxStall() time.Duration {
	if e.cfg.FeedbackDrainMaxStall > 0 {
		return e.cfg.FeedbackDrainMaxStall
	}
	return 2 * e.maxModuleTimeout()
}

// workerExitGraceDefault bounds how long Execute waits for worker goroutines to
// exit after the item channel is closed. It is deliberately short and fixed,
// unlike the drain-stall cap: by the time workers are joined the drain loop has
// already ended, so on a clean scan inFlight is 0 and this wait returns at once,
// while on cancellation a worker returns as soon as it observes ctx.Done. Only a
// worker wedged in inline passive code that ignores cancellation lingers — and
// inline passive modules are bounded and short — so a minute of grace is ample.
const workerExitGraceDefault = 60 * time.Second

// workerExitGrace returns the bounded wait for worker goroutines to exit after
// the item channel is closed. It is decoupled from feedbackDrainMaxStall so a
// stuck worker (or a scan cancelled by Ctrl-C / --scanning-max-duration) doesn't
// inherit that cap's up-to-50-minute worst case, which is sized for a
// legitimately slow module still running mid-drain, not for shutdown. It never
// exceeds the drain-stall cap, so an operator who tightens FeedbackDrainMaxStall
// also tightens shutdown.
func (e *Executor) workerExitGrace() time.Duration {
	grace := workerExitGraceDefault
	if e.cfg.WorkerExitGrace > 0 {
		grace = e.cfg.WorkerExitGrace
	}
	if stall := e.feedbackDrainMaxStall(); stall < grace {
		grace = stall
	}
	return grace
}

// timerPool recycles the watchdog timers used by the per-module timeout wrappers
// so each module call doesn't allocate a fresh runtime timer — these wrappers run
// on the hottest per-module dispatch loop (every active and passive call). A
// timer taken from the pool is always Reset before use and Stopped/drained before
// being returned, so a recycled timer never carries a stale fire.
var timerPool = sync.Pool{
	New: func() any {
		t := time.NewTimer(time.Hour)
		t.Stop()
		return t
	},
}

// acquireTimer returns a pooled timer armed to fire after d.
func acquireTimer(d time.Duration) *time.Timer {
	t := timerPool.Get().(*time.Timer)
	t.Reset(d)
	return t
}

// releaseTimer stops t and returns it to the pool, draining a pending fire so the
// next Reset starts clean.
func releaseTimer(t *time.Timer) {
	if !t.Stop() {
		// Already fired (or was already stopped): drain a queued value if the
		// select didn't consume it. The non-blocking default handles the case
		// where the firing value was already received.
		select {
		case <-t.C:
		default:
		}
	}
	timerPool.Put(t)
}

// callGuard sets up the per-module timeout guard shared by the active and passive
// wrappers: a cancel-only child context plus a pooled watchdog timer armed for
// timeout. It returns the child context to hand the scan function, the timer's
// fire channel (the genuine per-call timeout — selected separately from
// ctx.Done(), which is parent cancellation), and a stop func the caller defers to
// cancel the context and return the timer to the pool. The common non-contextual
// case (the hottest per-module dispatch loop) hands back the parent ctx unchanged
// and relies solely on the pooled watchdog timer, avoiding any per-call context
// allocation; only contextual modules pay for a child context, and it carries a
// soft deadline (a grace before the watchdog) so a deadline-aware module can return
// its already-confirmed findings before the hard timeout discards them. The child
// context is intentionally NOT bound into the requester — that is phase-context-bound
// in runActiveStage — so one module's timeout never cancels a request the clusterer
// shares with others.
func callGuard(ctx context.Context, timeout time.Duration, needCancel bool) (callCtx context.Context, timeoutC <-chan time.Time, stop func()) {
	t := acquireTimer(timeout)
	if !needCancel {
		// Non-contextual module: its scanFn ignores the handed context (it runs
		// against the phase-bound requester / e.scanCtx), so the WithCancel child
		// would never be observed. Skip that per-call heap allocation; the pooled
		// timer still enforces the per-module timeout via timeoutC.
		return ctx, t.C, func() { releaseTimer(t) }
	}
	// Contextual module: give its handed context a soft deadline a short grace
	// before the hard watchdog (timeoutC) fires. A deadline-aware module checks
	// this context between insertion points and returns the findings it has
	// already confirmed, so the executor collects them via the result channel
	// instead of the hard timeout discarding everything. The context stays
	// unbound from the requester (that is phase-context-bound), so this deadline
	// only gates the module's own loop, never a request the clusterer shares.
	soft := timeout - moduleDeadlineGrace
	if soft <= 0 {
		soft = timeout / 2
	}
	callCtx, cancel := context.WithTimeout(ctx, soft)
	return callCtx, t.C, func() {
		cancel()
		releaseTimer(t)
	}
}

// moduleCallResult carries a module scan function's return across the watchdog
// goroutine. Shared by the active and passive wrappers so they can use one
// channel pool.
type moduleCallResult struct {
	events []*output.ResultEvent
	err    error
}

// moduleResultChanPool recycles the 1-slot result channels used by the per-module
// timeout wrappers — the single highest-frequency allocation site in the
// dispatch loop (one per active and passive module call). A channel is returned
// to the pool ONLY on the normal completion path, where the watchdog goroutine
// has finished sending and will never touch it again; on the timeout / parent-
// cancel paths the abandoned goroutine still owns the channel (it sends when the
// slow scanFn eventually returns), so those channels are left for the GC.
var moduleResultChanPool = sync.Pool{
	New: func() any { return make(chan moduleCallResult, 1) },
}

// recordPassiveResult records the module's timing/metrics and normalizes its
// return: on error it notes the failure (noteModuleError) and drops the events
// (returns nil), otherwise it returns the events. Shared by the inline and
// watchdog-goroutine completion paths of runPassiveWithTimeout.
func (e *Executor) recordPassiveResult(module modules.PassiveModule, item *httpmsg.HttpRequestResponse, start time.Time, events []*output.ResultEvent, err error) []*output.ResultEvent {
	e.moduleMetrics.Record(module.ID(), time.Since(start), len(events), err)
	if err != nil {
		e.noteModuleError(module, item, err, moduleErrorKind(err))
		return nil
	}
	return events
}

// runPassiveWithTimeout executes a passive module scan function with a timeout guard.
func (e *Executor) runPassiveWithTimeout(
	ctx context.Context,
	scanFn func(context.Context) ([]*output.ResultEvent, error),
	module modules.PassiveModule,
	item *httpmsg.HttpRequestResponse,
) []*output.ResultEvent {
	return e.runPassiveCall(ctx, scanFn, module, item).events
}

// runPassiveCall is runPassiveWithTimeout returning the full callOutcome.
func (e *Executor) runPassiveCall(
	ctx context.Context,
	scanFn func(context.Context) ([]*output.ResultEvent, error),
	module modules.PassiveModule,
	item *httpmsg.HttpRequestResponse,
) callOutcome {
	// Fast exit when the scan/phase context is already cancelled: skip the
	// watchdog goroutine + pooled timer + result channel entirely. During
	// shutdown or after a phase deadline, many modules are still dispatched and
	// would each otherwise spawn a doomed goroutine.
	if ctx.Err() != nil {
		return callOutcome{}
	}

	// Only contextual passive modules observe the handed context.
	_, isContextual := module.(modules.ContextualPassiveModule)

	timeout := e.passiveModuleTimeout()
	// Allow modules to override with a per-module timeout hint
	hintedTimeout := false
	if hinter, ok := module.(modules.TimeoutHinter); ok {
		if hint := hinter.TimeoutHint(); hint > 0 {
			timeout = hint
			hintedTimeout = true
		}
	}

	// Fast inline path for the common case: a non-contextual passive module with
	// no explicit timeout hint. Passive modules send no traffic (no network I/O
	// to block on), read a size-capped body, and Go's regexp is RE2 (linear-time,
	// no catastrophic backtracking) — so their runtime is bounded and short, and
	// the per-call watchdog goroutine + pooled timer + result channel are pure
	// overhead on the single highest-frequency call in the dispatch loop. Running
	// inline is also safer against a module panic (it unwinds to the worker's
	// recoverFromPanic instead of crashing an unrecovered raw goroutine). Modules
	// that observe the context or ask for a specific timeout keep the enforced
	// goroutine path below; the end-of-scan drain-stall cap remains the backstop.
	// A panic is recovered here, at the module, rather than unwinding to the
	// worker: the item's other passive modules still run, and the failure is
	// counted against the module that caused it (error_kind panic).
	runInline := !isContextual && !hintedTimeout
	if runInline {
		start := time.Now()
		events, err := e.runScanFnGuarded(ctx, module.ID(), scanFn)
		return callOutcome{events: e.recordPassiveResult(module, item, start, events, err), completed: true, err: err}
	}

	// Enforced-timeout path: contextual modules need a cancellable child (see
	// callGuard); hinted modules asked for their timeout to be enforced.
	callCtx, timeoutC, stop := callGuard(ctx, timeout, isContextual)
	defer stop()

	start := time.Now()
	ch := moduleResultChanPool.Get().(chan moduleCallResult)
	go func() {
		// runScanFnGuarded recovers a module panic into an error: this goroutine
		// is outside the worker's and the active task's panic recovery, so an
		// unrecovered panic here would crash the process.
		events, err := e.runScanFnGuarded(callCtx, module.ID(), scanFn)
		ch <- moduleCallResult{events, err}
	}()

	select {
	case r := <-ch:
		moduleResultChanPool.Put(ch) // goroutine done; channel drained and safe to reuse
		return callOutcome{events: e.recordPassiveResult(module, item, start, r.events, r.err), completed: true, err: r.err}
	case <-timeoutC:
		// The scan goroutine is still running and still holds item, whose response
		// is built over the item's pooled buffer. Withhold that buffer from the
		// pool so this abandoned call cannot be fed another request's bytes.
		markResponseBufferEscaped(ctx)
		e.moduleMetrics.Record(module.ID(), time.Since(start), 0, nil)
		if ctx.Err() == nil {
			e.noteModuleError(module, item, fmt.Errorf("timed out after %s", timeout), ModuleErrorTimeout)
		}
		zap.L().Warn("Passive module timed out — skipping",
			zap.String("module", module.ID()),
			zap.String("url", item.Target()),
			zap.Duration("timeout", timeout))
		return callOutcome{}
	case <-ctx.Done():
		// Parent cancellation (scan shutdown / phase deadline) — not a per-module
		// timeout, so stay quiet; the scan is ending.
		markResponseBufferEscaped(ctx)
		e.moduleMetrics.Record(module.ID(), time.Since(start), 0, nil)
		return callOutcome{}
	}
}

// runActiveWithTimeout executes an active module scan function under a timeout
// derived from the phase context. It returns the module's results and whether
// the call completed within the bound. When the per-module timeout fires OR the
// phase deadline (ctx) is reached, it returns (nil, false) immediately so the
// task returns, its item can complete, and the phase ends on time. The scan function
// receives callCtx for explicit use. The executor also hands the module a
// requester bound to the PHASE context (http.Requester.WithContext), so
// context-less Execute calls abort in-flight requests on scan shutdown / phase
// deadline. It deliberately is NOT bound to callCtx: the request clusterer
// shares one in-flight request across modules, so a single module's per-module
// timeout must not cancel a request other modules deduped onto. The per-module
// timeout is still enforced here — a timed-out call returns (nil, false) and the
// caller skips processResults — it just doesn't sever the shared socket early.
// releaseSlot frees the active-task semaphore slot goActiveTask acquired for this
// call. runActiveWithTimeout owns it and MUST call it exactly once: from the
// background scan goroutine's defer (so the slot is held for as long as the real
// work runs, even past a per-module timeout) or directly on the pre-spawn early
// return. Releasing it when the wrapper merely *gives up waiting* would let the
// executor admit replacement work while abandoned scans still hold connections,
// so the active-task cap would understate true concurrency (a hot/slow target
// could then be hit far harder than --concurrency allows).
// workUnits estimates how much a whole-request/host module must cover in one call
// (its insertion-point count) so the per-module timeout can scale with it; pass 0
// to leave the base timeout untouched (per-insertion-point calls, which are already
// bounded and processed incrementally).
func (e *Executor) runActiveWithTimeout(
	ctx context.Context,
	scanFn func(context.Context, *http.Requester) ([]*output.ResultEvent, error),
	module modules.Module,
	item *httpmsg.HttpRequestResponse,
	reqClient *http.Requester,
	releaseSlot func(),
	workUnits int,
) ([]*output.ResultEvent, bool) {
	o := e.runActiveCall(ctx, scanFn, module, item, reqClient, releaseSlot, workUnits)
	return o.events, o.completed
}

// callOutcome is what one active-module call came to: its events, whether it
// completed inside its bound (false on a per-module timeout or a parent
// cancellation), and the module's returned error.
type callOutcome struct {
	events    []*output.ResultEvent
	completed bool
	err       error

	// late is set when the call hit its per-module timeout while the phase was
	// still live: the abandoned module goroutine delivers its result there when
	// it eventually unwinds. lateWait bounds how long a harvester waits for it,
	// and stats is the call's requester stats (nil without a requester).
	late     <-chan moduleCallResult
	lateWait time.Duration
	stats    *http.CallStats
}

// maxLateHarvestWait caps how long a timed-out call's findings are waited for.
const maxLateHarvestWait = 30 * time.Second

// failedTransiently reports whether the call failed for a reason that says
// nothing about the target's answer — it did not complete, or its error is a
// transport failure, a quarantined host or an abandoned request. A per-host
// claim taken for such a call is released so a later item retries it
// (MISS-19).
func (o callOutcome) failedTransiently() bool {
	if !o.completed {
		return true
	}
	return isTransientCallErr(o.err) || callHitTransportErrors(o.stats)
}

// callHitTransportErrors reports whether any request of the call failed
// transiently or was refused by a gate. Modules routinely swallow a send error
// and return a clean nil, so the module's error alone cannot tell a probe that
// was answered from one that never reached the host.
func callHitTransportErrors(cs *http.CallStats) bool {
	return cs != nil && (cs.TransportErrors.Load() > 0 || cs.Refused.Load() > 0)
}

func isTransientCallErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, hosterrors.ErrUnresponsiveHost) || errors.Is(err, http.ErrRequestAbandoned) {
		return true
	}
	switch http.ClassifyTransportError(err) {
	case http.TransportErrDNS, http.TransportErrRefused, http.TransportErrTimeout,
		http.TransportErrTLS, http.TransportErrReset:
		return true
	}
	return false
}

// runActiveCall is runActiveWithTimeout returning the full callOutcome.
func (e *Executor) runActiveCall(
	ctx context.Context,
	scanFn func(context.Context, *http.Requester) ([]*output.ResultEvent, error),
	module modules.Module,
	item *httpmsg.HttpRequestResponse,
	reqClient *http.Requester,
	releaseSlot func(),
	workUnits int,
) callOutcome {
	// Fast exit when the scan/phase context is already cancelled: skip the
	// watchdog goroutine + pooled timer + result channel entirely (mirrors the
	// <-ctx.Done() arm below). Avoids spawning doomed goroutines for the many
	// modules still dispatched during shutdown or after a phase deadline. No
	// background goroutine is spawned here, so release the slot directly.
	if ctx.Err() != nil {
		releaseSlot()
		return callOutcome{}
	}

	// Scale the timeout with the request's insertion-point count for whole-request
	// modules that loop over every point in a single call (workUnits 0, or at/below
	// the reference count, leaves it unchanged): without this a request with many
	// cookies/headers exceeds the base timeout mid-loop and its already-confirmed
	// findings are discarded (capped at maxModuleTimeoutScale x).
	timeout := scaleModuleTimeout(e.adaptiveActiveTimeout(module.ID()), workUnits)
	// Allow modules to override with a per-module timeout hint (e.g. diffscan
	// timing analysis legitimately needs longer than the global default).
	if hinter, ok := module.(modules.TimeoutHinter); ok {
		if hint := hinter.TimeoutHint(); hint > timeout {
			timeout = hint
		}
	}

	// Only contextual active modules observe the handed context, so only they
	// need a cancellable child (see callGuard).
	_, needCancel := module.(modules.ContextualActiveModule)
	callCtx, timeoutC, stop := callGuard(ctx, timeout, needCancel)
	defer stop()

	// Abandon signal: set the moment this wrapper stops waiting, on every path. A
	// module that outlives its timeout keeps running (a goroutine cannot be
	// killed) and used to keep issuing requests whose results are discarded by
	// definition — stealing per-host concurrency from live work and holding its
	// active-task slot until it finally unwound. Once set, its next Execute
	// returns ErrRequestAbandoned immediately, so it unwinds promptly and stops
	// generating load. In-flight requests are untouched, so a request the
	// clusterer shares with other modules is never severed.
	//
	// Deferring the set is correct on all three exits: on the normal path the
	// scan goroutine has already delivered its result, and on the timeout /
	// parent-cancel paths flagging it is precisely the intent.
	var abandoned atomic.Bool
	var callStats *http.CallStats
	if reqClient != nil {
		defer abandoned.Store(true)
		reqClient = reqClient.WithAbandonFlag(&abandoned)
		callStats = reqClient.CallStats()
	}

	start := time.Now()
	ch := moduleResultChanPool.Get().(chan moduleCallResult)
	go func() {
		// Hold the active-task slot for the whole life of the real work. On the
		// normal path this fires just as the wrapper receives the result; on the
		// timeout / parent-cancel paths the wrapper has already returned but this
		// abandoned goroutine keeps the slot until scanFn actually unwinds, so the
		// executor's concurrency cap keeps reflecting genuinely in-flight scans.
		defer releaseSlot()
		// runScanFnGuarded recovers a module panic into an error: this goroutine
		// is outside the worker's and the active task's panic recovery, so an
		// unrecovered panic here would crash the process.
		events, err := e.runScanFnGuarded(callCtx, module.ID(), func(c context.Context) ([]*output.ResultEvent, error) {
			return scanFn(c, reqClient)
		})
		// Settle the run-once host probes the module registered on this call's
		// requester (MISS-19) before handing the result over: a claim commits
		// only when the call finished inside its bound with every request
		// answered. Settling after the send would race the next item of the
		// same host, which could then see the claim still pending.
		e.scanCtx.SettleHostProbes(reqClient, !abandoned.Load() &&
			!isTransientCallErr(err) && !callHitTransportErrors(callStats))
		ch <- moduleCallResult{events, err}
	}()

	select {
	case r := <-ch:
		moduleResultChanPool.Put(ch) // goroutine done; channel drained and safe to reuse
		elapsed := time.Since(start)
		e.moduleMetrics.Record(module.ID(), elapsed, len(r.events), r.err)
		e.moduleMetrics.RecordCompletedDuration(module.ID(), elapsed)
		if r.err != nil {
			if IsLevelDBClosed(r.err) {
				// A store closed under a module at shutdown is not the module's
				// failure, so it is not counted.
				zap.L().Debug("Active module error (shutdown)",
					zap.String("module", module.ID()),
					zap.Error(r.err))
			} else {
				e.noteModuleError(module, item, r.err, moduleErrorKind(r.err))
			}
			// Keep whatever the module confirmed before it failed (MISS-20).
			return callOutcome{events: r.events, completed: true, err: r.err, stats: callStats}
		}
		e.noteThrottledCall(module, reqClient, r.events)
		return callOutcome{events: r.events, completed: true, stats: callStats}
	case <-timeoutC:
		// The scan goroutine outlives this wrapper and still holds item, whose
		// response is built over the item's pooled buffer — keep that buffer out of
		// the pool so the abandoned module cannot be handed another request's bytes.
		markResponseBufferEscaped(ctx)
		// Genuine per-module timeout. Count it only when the parent is still alive,
		// so cancelling a scan with many modules in flight doesn't inflate the
		// status-line count with modules that were merely interrupted at the same
		// instant.
		e.moduleMetrics.Record(module.ID(), time.Since(start), 0, nil)
		if ctx.Err() == nil {
			e.recordModuleTimeout()
			e.noteModuleSkip(module.ID(), SkipReasonTimeout)
			e.noteModuleError(module, item, fmt.Errorf("timed out after %s", timeout), ModuleErrorTimeout)
		}
		// Logged at debug level: a per-skip WARN floods stderr on slow targets.
		// The running count is surfaced in the status line via OnStatus instead.
		zap.L().Debug("Active module timed out — skipping",
			zap.String("module", module.ID()),
			zap.String("url", item.Target()),
			zap.Duration("timeout", timeout))
		if ctx.Err() != nil {
			return callOutcome{}
		}
		// The module keeps running and is told to stop sending (abandon flag);
		// whatever it confirmed is still worth having. Hand the result channel to
		// a bounded harvester (see harvestLate) instead of dropping it (MISS-20).
		return callOutcome{late: ch, lateWait: min(timeout, maxLateHarvestWait), stats: reqClient.CallStats()}
	case <-ctx.Done():
		// Parent cancellation (Ctrl-C, --scanning-max-duration, phase deadline) —
		// an interruption, not a timed-out module, so it is not counted.
		markResponseBufferEscaped(ctx)
		e.moduleMetrics.Record(module.ID(), time.Since(start), 0, nil)
		return callOutcome{}
	}
}

// recordModuleTimeout increments the active-module timeout counter — the shared
// phase counter when one was supplied via ExecutorConfig.ModuleTimeouts (so the
// total accumulates across a multi-round phase's per-round executors), otherwise
// this executor's own tally.
func (e *Executor) recordModuleTimeout() {
	if e.cfg.ModuleTimeouts != nil {
		e.cfg.ModuleTimeouts.Add(1)
		return
	}
	e.moduleTimeouts.Add(1)
}

// timedOutCount returns the active-module timeout total reported in the status
// line: the shared phase counter when present, else this executor's own tally.
func (e *Executor) timedOutCount() int64 {
	if e.cfg.ModuleTimeouts != nil {
		return e.cfg.ModuleTimeouts.Load()
	}
	return e.moduleTimeouts.Load()
}

// IsLevelDBClosed returns true if the error is caused by a closed LevelDB instance,
// which happens during shutdown when the dedup manager is closed before workers finish.
// The runner treats it as a fatal phase error.
//
// The typed sentinel (errors.Is) is the primary check and survives any future
// change to goleveldb's error message, but we keep a string fallback because the
// error reaches us through module/storage call chains that may format it with %v
// (non-wrapping), which defeats errors.Is. Matching both is strictly more robust
// than either alone.
func IsLevelDBClosed(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, leveldb.ErrClosed) || strings.Contains(err.Error(), "leveldb: closed")
}

// deliverCall hands a finished call's events to processResults, or — for a
// call that timed out with the phase still live — registers a harvester that
// does so if the module's result arrives within the late-wait bound.
func (e *Executor) deliverCall(ctx context.Context, o callOutcome, module modules.Module, item *httpmsg.HttpRequestResponse, ip httpmsg.InsertionPoint) {
	if o.completed {
		if len(o.events) > 0 {
			e.processResults(ctx, o.events, module, item, ip)
		}
		return
	}
	e.harvestLate(ctx, o, func(events []*output.ResultEvent) {
		e.processResults(ctx, events, module, item, ip)
	})
}

// harvestLate waits (on the scan's taskWG, bounded by o.lateWait and ctx) for
// a timed-out module call's result and delivers its events. A call whose
// requests were refused after the timeout (CallStats Refused/Abandoned > 0)
// may have stopped short of its confirmation steps, so its late findings are
// downgraded to Tentative with a note. The item's response buffer was already
// withheld from the pool when the call timed out, so reading item here is safe.
func (e *Executor) harvestLate(ctx context.Context, o callOutcome, deliver func([]*output.ResultEvent)) {
	if o.late == nil || o.lateWait <= 0 {
		return
	}
	e.pool.taskWG.Add(1)
	go func() {
		defer e.pool.taskWG.Done()
		timer := time.NewTimer(o.lateWait)
		defer timer.Stop()
		select {
		case r := <-o.late:
			if len(r.events) == 0 || ctx.Err() != nil {
				return
			}
			refused := o.stats != nil && (o.stats.Refused.Load() > 0 || o.stats.Abandoned.Load() > 0)
			for _, ev := range r.events {
				if ev == nil {
					continue
				}
				if ev.Metadata == nil {
					ev.Metadata = map[string]any{}
				}
				ev.Metadata["late_result"] = true
				if refused && ev.Info.Confidence > severity.Tentative {
					ev.Info.Confidence = severity.Tentative
					ev.Info.Description += " (reported after the module's call timed out; some of its requests were refused, so confirmation may be incomplete)"
				}
			}
			deliver(r.events)
		case <-timer.C:
		case <-ctx.Done():
		}
	}()
}
