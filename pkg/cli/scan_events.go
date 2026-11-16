package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/core/egress"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
)

// beginScanEventStream installs the process event emitter for this scan and
// writes the opening scan.started line.
//
// The emitter is installed AFTER the scan uuid is pinned and the DB is open, so
// scan.started can carry the two facts a consumer most needs to attribute later
// events: which scan row this is, and which database it landed in. Everything
// before that point is setup that fails loudly on its own.
//
// The terminal event is returned as TWO functions because the facts it carries
// become available at two different moments, and a single deferred call could
// only ever be right about one of them:
//
//   - prepare reads the totals and the coverage verdict, and must run while the
//     database is still open — which is before the --db-isolate merge copies
//     the run into the real store.
//   - emit writes the line, and must run after everything that can still fail
//     has failed. A merge that cannot write is a failed scan, and the stream
//     used to say `completed` because its terminal event had already gone out.
//
// Deferred in that order (emit registered first, so LIFO runs it last), the
// line reports what prepare measured and the status the whole invocation
// earned.
func beginScanEventStream(db *database.DB, opts *types.Options, settings *config.Settings, strategyName string, start time.Time) (prepare func(error), emit func(error), err error) {
	format, err := scanevents.ParseFormat(opts.Events)
	if err != nil {
		return nil, nil, err
	}
	if format == "" {
		return func(error) {}, func(error) {}, nil
	}

	emitter := scanevents.NewStdout(opts.ScanUUID)
	scanevents.Install(emitter)

	globalPace, phasePace := resolvedPaceTable(settings, opts)
	target := ""
	if len(opts.Targets) == 1 {
		target = opts.Targets[0]
	}

	dbPath := ""
	if settings != nil && settings.Database.Driver == "sqlite" {
		dbPath = config.ExpandPath(settings.Database.SQLite.Path)
	}

	phases := plannedPhaseIDs(opts)
	started := scanevents.Event{
		Type:      scanevents.TypeScanStarted,
		Target:    target,
		Targets:   len(opts.Targets),
		Strategy:  strategyName,
		Phases:    phases,
		DBPath:    dbPath,
		Project:   opts.ProjectUUID,
		Pace:      &globalPace,
		PhasePace: phasePace,
		// Which outbound paths the rate limit and host slots govern, and which
		// they do not (and why), for the phases this scan runs.
		Egress: egress.Inventory(phases),
		// The request budgets in force; zeros are written (0 = unlimited).
		Budgets: &scanevents.Budgets{MaxRequests: opts.MaxRequests, MaxRequestsPerHost: opts.MaxRequestsPerHost},
	}
	// How strictly a budget holds for each phase's traffic, when one is set.
	if opts.MaxRequests > 0 || opts.MaxRequestsPerHost > 0 {
		started.RequestCapEnforcement = egress.RequestCapEnforcement(phases)
	}
	// Present only when the targets are the input (see scanTargetAdmission); a
	// zero is written, so "0 admitted" is visible before the run fails.
	if adm := opts.TargetAdmission; adm != nil {
		started.TargetsAdmitted = scanevents.Int(len(adm.Admitted))
		started.TargetsRejected = scanevents.Int(len(adm.Rejected))
	}
	scanevents.Emit(started)

	// A consumer that goes away must not take the scan with it. Without this the
	// first event written to a closed stdout killed the process outright on the
	// default SIGPIPE disposition — `vigolium scan --events ndjson | head -5`
	// terminated a running scan, mid-write, with no scan row and no findings.
	// Handled, the write returns EPIPE instead and the emitter latches.
	stopPipeGuard := guardEventStreamPipe()

	var ev scanevents.Event
	prepared := false

	prepare = func(runErr error) {
		ev.DurationMS = time.Since(start).Milliseconds()
		ev.Status = scanevents.StatusCompleted
		if runErr != nil {
			ev.Status = scanevents.StatusFailed
			ev.Message = runErr.Error()
		}
		// Reads the totals AND the coverage verdict from the scan row, which is
		// why this half has to happen while the database is open.
		scanFinishTotals(db, &ev, opts)
		prepared = true
	}

	emit = func(runErr error) {
		stopPipeGuard()
		if !prepared {
			// A path that reached emit without prepare has no totals to report;
			// a terminal event with none still beats no terminal event at all,
			// which a consumer reads as a SIGKILL.
			ev.Status = scanevents.StatusCompleted
		}
		ev.DurationMS = time.Since(start).Milliseconds()
		switch {
		case runErr != nil:
			// Later than prepare's view: the --db-isolate merge runs between
			// the two, and a run whose results never reached the real database
			// did not complete.
			ev.Status = scanevents.StatusFailed
			ev.Message = runErr.Error()
		case activeScanSignals.Interrupted():
			// Beats `curtailed`: both say the run did not cover everything, and
			// only this one says why. The reasons list still carries the detail.
			ev.Status = scanevents.StatusInterrupted
		}
		applyExitOutcome(&ev, withFailOnGate(runErr))
		scanevents.Finish(ev)
		reportEventStreamDelivery()
	}
	return prepare, emit, nil
}

// reportEventStreamDelivery warns on stderr when the stream was cut short.
//
// The emitter swallows write errors by design — a scan does not fail because
// nobody was listening — but swallowing them silently meant an operator whose
// consumer died early got a complete-looking exit 0 and a truncated stream,
// with nothing anywhere saying the two did not match. The exit code is
// deliberately unchanged: the scan really did run to completion.
func reportEventStreamDelivery() {
	err := scanevents.Default().Err()
	if err == nil || globalSilent {
		return
	}
	fmt.Fprintf(os.Stderr, "%s event stream delivery failed: %v; the scan ran to completion\n",
		terminal.WarnPrefix(), err)
}

// scanFinishTotals fills the terminal event's tallies from the database the scan
// wrote. Read here rather than accumulated during the run because the accurate
// number is the persisted one: findings are deduped and grouped on their way in,
// so a live counter of emitted results overstates what a consumer will actually
// find when it queries.
//
// The coverage verdict is read here for the same reason, from the same
// repository and under the same deadline: the scan row is authoritative after
// the runner's finalizer, and reading it in this one pass — rather than deciding
// the verdict where the event is built, before the row exists — is what keeps
// the row and the terminal event from disagreeing.
func scanFinishTotals(db *database.DB, ev *scanevents.Event, opts *types.Options) {
	if db == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	repo := database.NewRepository(db)
	if counts := repo.ScanSeverityTally(ctx, opts.ScanUUID); len(counts) > 0 {
		ev.FindingsBySeverity = counts
	}
	if n, err := repo.CountRecordsForScan(ctx, opts.ProjectUUID, opts.ScanUUID); err == nil {
		ev.RecordsWritten = scanevents.Int64(n)
	}
	if scan, err := repo.GetScanByUUID(ctx, opts.ScanUUID); err == nil {
		applyScanCompletion(ev, scan)
	}
	if sessions, err := repo.ListOpenOASTSessions(ctx, opts.ProjectUUID, opts.ScanUUID); err == nil {
		ev.OASTSessionsKept = keptOASTSessions(sessions)
	}
}

// keptOASTSessions is the oast_sessions_kept list: each open session's row id
// (what `oast poll` reports as session_id) and server.
func keptOASTSessions(sessions []*database.OASTSession) []scanevents.OASTSession {
	var out []scanevents.OASTSession
	for _, s := range sessions {
		if s != nil {
			out = append(out, scanevents.OASTSession{ID: s.ID, Server: s.ServerURL})
		}
	}
	return out
}

// applyExitOutcome stamps the status the invocation exits with on the
// terminal event: final is the run's error with the gates applied
// (withFailOnGate), so a consumer of the stream alone learns what the process
// exit code and the error envelope would say. exit_code is always written (a
// 0 is a reading); error_code only when the exit is not 0.
func applyExitOutcome(ev *scanevents.Event, final error) {
	code := classifyExitCode(final)
	ev.ExitCode = scanevents.Int(code)
	if final != nil && code != ExitSuccess {
		ev.ErrorCode = string(classifyErrorCode(final, code))
	}
}

// applyScanCompletion downgrades a "completed" terminal event to "curtailed"
// when the scan row says the run was only partial, and attaches the stop reason
// and the union of the phases' reasons.
//
// Pure, and applied to the event rather than decided when the event is built,
// because the verdict is not known until the runner's finalizer has written the
// row — and because `failed` and `interrupted` must pass through untouched: a
// scan that failed is not a scan that was curtailed, and relabelling it would
// lose the more serious of the two facts.
//
// `curtailed` is an existing status value (a phase already reported it), so a
// consumer switching on status sees nothing new in kind.
// phaseScopeExtras is what a scan's phase outcomes say was kept out of it:
// records refused per scope rule class (nil when none) and the controls the
// browser crawl's destructive-click guard did not click (nil when none). The
// scan.finished event and the scan document both report them.
func phaseScopeExtras(phases []database.PhaseOutcome) (map[string]int64, *scanevents.SkippedControls) {
	dropped := database.ScopeDropped(phases)
	if len(dropped) == 0 {
		dropped = nil
	}
	var skipped *scanevents.SkippedControls
	if n, sample := database.SkippedControls(phases); n > 0 || len(sample) > 0 {
		skipped = &scanevents.SkippedControls{Count: n, Sample: sample}
	}
	return dropped, skipped
}

func applyScanCompletion(ev *scanevents.Event, scan *database.Scan) {
	if ev == nil || scan == nil {
		return
	}
	if scan.StopReason != "" {
		ev.StopReason = scan.StopReason
	}
	if reasons := unionPhaseReasons(scan.PhaseOutcomes); len(reasons) > 0 {
		ev.Reasons = reasons
	}
	if hosts := unionBudgetExhaustedHosts(scan.PhaseOutcomes); len(hosts) > 0 {
		ev.BudgetExhaustedHosts = hosts
	}
	if capped := database.SumFindingsCapped(scan.PhaseOutcomes); len(capped) > 0 {
		ev.FindingsCapped = capped
	}
	ev.ScopeDropped, ev.SkippedControls = phaseScopeExtras(scan.PhaseOutcomes)
	// The preflight tally, as the runner recorded it (scope admission, and
	// reachability when the preflight GET ran).
	for _, p := range scan.PhaseOutcomes {
		if p.Phase == string(runner.PhasePreflight) && p.Targets != nil {
			ev.TargetsAdmitted = scanevents.Int(p.Targets.Admitted)
			ev.TargetsRejected = scanevents.Int(p.Targets.Requested - p.Targets.Admitted)
			if unreachable, checked := p.Targets.UnreachableCount(); checked {
				ev.TargetsReached = scanevents.Int(p.Targets.Reached)
				ev.TargetsUnreachable = scanevents.Int(unreachable)
			}
		}
	}
	if len(scan.ExtensionsFailed) > 0 {
		ev.ExtensionsFailed = scan.ExtensionsFailed
	}
	// Per-module error totals, persisted by the runner's finalizer.
	if len(scan.ModuleErrors) > 0 {
		ev.ModuleErrors = scan.ModuleErrors
	}
	for _, c := range database.CoverageCaveats(database.ScanCompletion{Phases: scan.PhaseOutcomes}, scan.ModuleErrors) {
		ev.Caveats = append(ev.Caveats, scanevents.Caveat(c))
	}
	// An empty Completeness means unknown (a row written by an older binary, or
	// by a caller with no outcome data) and must never change the status.
	if ev.Status == scanevents.StatusCompleted && scan.Completeness == database.CompletenessPartial {
		ev.Status = scanevents.StatusCurtailed
	}
}

// unionPhaseReasons collects every distinct reason across a scan's phases,
// sorted — so the terminal event answers "what went wrong anywhere in this run"
// without a consumer having to walk the per-phase list itself.
//
// A phase skipped for having nothing to do contributes nothing, by the same
// rule the completeness verdict and the partial banner use: `no_modules` on a
// phase with no modules is the plan working, not a gap, and unioning it here
// put a reason on scan.finished that the other two correctly omitted.
func unionPhaseReasons(phases []database.PhaseOutcome) []string {
	seen := make(map[string]struct{})
	for _, p := range phases {
		if p.BenignSkip() {
			continue
		}
		for _, reason := range p.Reasons {
			seen[reason] = struct{}{}
		}
	}
	return database.SortedCodes(seen)
}

// unionBudgetExhaustedHosts collects, sorted, the hosts any phase recorded as
// having used their whole --max-requests-per-host.
func unionBudgetExhaustedHosts(phases []database.PhaseOutcome) []string {
	seen := make(map[string]struct{})
	for _, p := range phases {
		for _, host := range p.BudgetExhaustedHosts {
			seen[host] = struct{}{}
		}
	}
	return database.SortedCodes(seen)
}

// plannedPhaseIDs returns the CANONICAL ids of the phases this scan will run, in
// execution order. Canonical, because --only/--skip and `vigolium run <phase>`
// all accept aliases (kis, cve, deparos, dast, …) and a consumer that asked for
// one spelling needs to be able to assert what it actually got.
func plannedPhaseIDs(opts *types.Options) []string {
	plan := runner.BuildNativeScanPlan(opts)
	out := make([]string, 0, len(plan.Steps))
	for _, step := range plan.Steps {
		if step.Enabled {
			out = append(out, string(step.Phase))
		}
	}
	return out
}

// validateEventsFlag rejects an --events value up front, before any scanning
// work, so a typo fails in milliseconds instead of after a 15-minute crawl and
// a scan whose whole reason for running was the stream it never produced.
func validateEventsFlag(value string) error {
	_, err := scanevents.ParseFormat(value)
	return err
}
