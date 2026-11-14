package runner

import (
	"context"
	"errors"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core/egress"
	"github.com/vigolium/vigolium/pkg/database"
	"go.uber.org/zap"
)

// armRequestBudget builds the scan's request budget from --max-requests /
// --max-requests-per-host (scanning_pace.max_requests / max_requests_per_host)
// and returns the context the phases must run under.
//
// The budget itself lives in the egress gate (buildInfrastructure attaches it
// to the scan's root gate), so every gated sender is held to it exactly. What
// this adds is the scan-level reaction:
//
//   - the scan-wide limit running out cancels the returned context with the
//     *egress.BudgetError as its cause, so the running phase winds down, the
//     remaining phases are skipped, and every one of them is attributed to
//     `request_budget` (contextStopReason, scanStopReason) — the scan ends
//     partial, the way --scanning-max-duration ends it, not "cancelled";
//   - a host running out of its per-host limit is recorded on the running
//     phase as the `host_request_budget` limit plus the host's name, and its
//     further requests fail fast in the gate;
//   - a watcher samples the counters of engines that bypass the gate (the
//     browser crawl registers through trackUngatedRequests) every
//     egress.WatchInterval, so their traffic counts toward the scan-wide limit.
//
// With neither limit set it returns ctx unchanged and a no-op stop.
func (r *Runner) armRequestBudget(ctx context.Context) (context.Context, func()) {
	r.requestBudget = nil
	budget := egress.NewBudget(r.options.MaxRequests, r.options.MaxRequestsPerHost)
	if budget == nil {
		return ctx, func() {}
	}
	ctx, cancel := context.WithCancelCause(ctx)
	budget.SetHooks(egress.BudgetHooks{
		Global: func(e *egress.BudgetError) {
			zap.L().Warn("Request budget (--max-requests) exhausted; stopping the scan",
				zap.Int64("max_requests", e.Limit))
			cancel(e)
		},
		Host: func(host string) {
			zap.L().Info("Host request budget (--max-requests-per-host) exhausted; further requests to it are refused",
				zap.String("host", host), zap.Int64("max_requests_per_host", r.options.MaxRequestsPerHost))
			r.currentPhase.Load().noteHostBudget(host)
		},
	})
	r.requestBudget = budget
	stopWatch := budget.Watch(ctx, egress.WatchInterval)
	return ctx, func() {
		stopWatch()
		cancel(nil)
	}
}

// trackUngatedRequests registers a request counter of an engine that bypasses
// the egress gate (soft enforcement; see armRequestBudget). It stays counted for
// the rest of the scan.
func (r *Runner) trackUngatedRequests(read func() int64) {
	r.requestBudget.Track(read)
}

// noteHostBudget records that host used its whole --max-requests-per-host
// during this phase: the host_request_budget limit, plus the host for
// PhaseOutcome.BudgetExhaustedHosts. A limit, not a reason: the cap did what it
// was configured to do. Nil-safe (a host can run out between phases, when no
// tracker is running; the budget still refuses its requests).
func (t *phaseTracker) noteHostBudget(host string) {
	if t == nil {
		return
	}
	t.noteLimit(database.LimitHostRequestBudget)
	t.mu.Lock()
	defer t.mu.Unlock()
	addCode(&t.budgetHosts, host)
}

// contextStopReason names what ended a context that is done: the request
// budget, the total scan budget, or a cancellation.
func contextStopReason(ctx context.Context) string {
	switch {
	case egress.BudgetCause(ctx) != nil:
		return database.ReasonRequestBudget
	case authLostCause(ctx) != nil:
		return database.ReasonAuthLost
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return database.ReasonScanBudget
	default:
		return database.ReasonCancelled
	}
}

// ApplyRequestBudget folds a request budget's verdict into the completion of a
// single-request scan (DirectScanCompletion), which has no phase tracker to
// record it as it happens: hosts that ran out of --max-requests-per-host become
// the host_request_budget limit and BudgetExhaustedHosts on the assessment, and
// a scan-wide --max-requests that ran out makes the assessment partial with
// request_budget — the reason the Runner path records — and, when nothing else
// stopped the scan first, its stop reason. A nil budget, or one that refused
// nothing, returns c unchanged.
func ApplyRequestBudget(c database.ScanCompletion, b *egress.Budget) database.ScanCompletion {
	hosts := b.ExhaustedHosts()
	exhausted := b.Exhausted()
	if !exhausted && len(hosts) == 0 {
		return c
	}
	note := database.PhaseOutcome{Phase: string(PhaseDynamicAssessment), State: database.PhaseCompleted}
	if len(hosts) > 0 {
		note.Limits = []string{database.LimitHostRequestBudget}
		note.BudgetExhaustedHosts = hosts
	}
	if exhausted {
		note.Reasons = []string{database.ReasonRequestBudget}
		note.State = database.PhasePartial
	}
	stop := c.StopReason
	if stop == "" && exhausted {
		stop = database.ReasonRequestBudget
	}
	return mergeDirectNote(c, note, stop)
}

// discoveryRequestShare is discovery's share of the unspent --max-requests
// budget (ECON-5): scanning_pace.discovery.request_share when set (1 = no
// cap), else config.DefaultDiscoveryRequestShare.
func (r *Runner) discoveryRequestShare() float64 {
	if r.settings != nil {
		if s := r.settings.ScanningPace.Discovery.RequestShare; s > 0 {
			return s
		}
	}
	return config.DefaultDiscoveryRequestShare
}
