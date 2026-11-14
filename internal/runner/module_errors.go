package runner

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/vigolium/vigolium/pkg/core"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// moduleErrorLedger counts failed module calls per module id over one scan, on
// behalf of every executor the scan starts (ExecutorConfig.OnModuleError). The
// executor rate-limits module.error events by the running total it returns, so
// the count on an event is scan-wide rather than per feedback round; the
// finalizer persists the totals on scans.module_errors, which scan.finished
// reads back.
//
// It is also the scan's module ledger (RES-6): per module, calls, wire
// requests and findings folded from every executor's report, and calls not
// made by skip reason (database.ModuleSkipReasons), persisted on
// scans.module_stats.
type moduleErrorLedger struct {
	m sync.Map // module id → *atomic.Int64

	mu    sync.Mutex
	stats map[string]*database.ModuleStat // guarded by mu
}

// entryLocked returns moduleID's stat line; mu must be held.
func (l *moduleErrorLedger) entryLocked(moduleID string) *database.ModuleStat {
	if l.stats == nil {
		l.stats = make(map[string]*database.ModuleStat)
	}
	e := l.stats[moduleID]
	if e == nil {
		e = &database.ModuleStat{}
		l.stats[moduleID] = e
	}
	return e
}

// noteSkip records n calls of moduleID not made for reason.
func (l *moduleErrorLedger) noteSkip(moduleID, reason string, n int64) {
	if l == nil || moduleID == "" || reason == "" || n <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entryLocked(moduleID)
	if e.Skips == nil {
		e.Skips = make(map[string]int64)
	}
	e.Skips[reason] += n
}

// addExecution folds one executor's report into the ledger: its per-module
// metrics and its skip counters. Each executor reports its own metrics, so
// summing reports across a phase's executors (rounds) is the scan total.
func (l *moduleErrorLedger) addExecution(rep core.ExecutionReport) {
	if l == nil {
		return
	}
	l.mu.Lock()
	for id, m := range rep.ModuleStats {
		e := l.entryLocked(id)
		e.Invocations += m.Invocations
		e.Requests += m.Requests
		e.Findings += m.Findings
	}
	l.mu.Unlock()
	for id, reasons := range rep.ModuleSkips {
		for reason, n := range reasons {
			l.noteSkip(id, reason, n)
		}
	}
}

// moduleStats returns the ledger with the error totals folded in, nil when
// empty.
func (l *moduleErrorLedger) moduleStats() map[string]database.ModuleStat {
	if l == nil {
		return nil
	}
	errs := l.snapshot()
	l.mu.Lock()
	defer l.mu.Unlock()
	var out map[string]database.ModuleStat
	put := func(id string, s database.ModuleStat) {
		if out == nil {
			out = make(map[string]database.ModuleStat)
		}
		out[id] = s
	}
	for id, e := range l.stats {
		s := *e
		if len(e.Skips) > 0 {
			s.Skips = make(map[string]int64, len(e.Skips))
			for k, v := range e.Skips {
				s.Skips[k] = v
			}
		}
		s.Errors = errs[id]
		put(id, s)
	}
	for id, n := range errs {
		if _, ok := l.stats[id]; !ok {
			put(id, database.ModuleStat{Errors: n})
		}
	}
	return out
}

func newModuleErrorLedger() *moduleErrorLedger { return &moduleErrorLedger{} }

// note records one failure and returns the module's running total. Nil-safe:
// a nil ledger counts nothing and reports 1, so the executor still emits the
// first event.
func (l *moduleErrorLedger) note(moduleID, kind string) int64 {
	if l == nil {
		return 1
	}
	if kind == "timeout" {
		l.noteSkip(moduleID, database.SkipTimeout, 1)
	}
	v, ok := l.m.Load(moduleID)
	if !ok {
		v, _ = l.m.LoadOrStore(moduleID, new(atomic.Int64))
	}
	return v.(*atomic.Int64).Add(1)
}

// snapshot returns the totals, nil when no module failed.
func (l *moduleErrorLedger) snapshot() map[string]int64 {
	if l == nil {
		return nil
	}
	var out map[string]int64
	l.m.Range(func(k, v any) bool {
		if n := v.(*atomic.Int64).Load(); n > 0 {
			if out == nil {
				out = make(map[string]int64)
			}
			out[k.(string)] = n
		}
		return true
	})
	return out
}

// noteModuleError is the ExecutorConfig.OnModuleError every runner executor
// gets. It reads the ledger at call time, so one closure serves every run of a
// reused Runner.
func (r *Runner) noteModuleError(moduleID, kind string) int64 {
	return r.moduleErrors.Load().note(moduleID, kind)
}

// ModuleStats returns the running scan's module ledger (database.ModuleStat
// per module id), nil when no module ran.
func (r *Runner) ModuleStats() map[string]database.ModuleStat {
	return r.moduleErrors.Load().moduleStats()
}

// ModuleErrors returns the running scan's per-module error totals.
func (r *Runner) ModuleErrors() map[string]int64 {
	return r.moduleErrors.Load().snapshot()
}

// persistModuleErrors writes the ledger onto scans.module_errors. Called by the
// finalizer, before the row is completed, so `scan status` and scan.finished
// (which reads the row) carry the totals.
//
// It writes the module ledger onto scans.module_stats in the same update.
func (r *Runner) persistModuleErrors(ctx context.Context, scanUUID string) {
	counts := r.ModuleErrors()
	ledger := r.ModuleStats()
	if r.repository == nil || (len(counts) == 0 && len(ledger) == 0) {
		return
	}
	if err := r.repository.UpdateScanPartial(ctx, &database.Scan{UUID: scanUUID, ModuleErrors: counts, ModuleStats: ledger}); err != nil {
		zap.L().Warn("Failed to record module errors on scan", zap.Error(err))
	}
}

// moduleErrorSummaryLimit caps how many modules the summary line names.
const moduleErrorSummaryLimit = 3

// formatModuleErrorSummary renders the end-of-scan line for modules that
// failed: "3 modules errored (ext-csp ×41, …) — see vigolium log <uuid>".
// Modules are listed most errors first. Empty when nothing failed.
func formatModuleErrorSummary(counts map[string]int64, scanUUID string) string {
	if len(counts) == 0 {
		return ""
	}
	ids := make([]string, 0, len(counts))
	for id := range counts {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		if counts[ids[i]] != counts[ids[j]] {
			return counts[ids[i]] > counts[ids[j]]
		}
		return ids[i] < ids[j]
	})
	parts := make([]string, 0, moduleErrorSummaryLimit+1)
	for i, id := range ids {
		if i == moduleErrorSummaryLimit {
			parts = append(parts, "…")
			break
		}
		parts = append(parts, fmt.Sprintf("%s ×%d", id, counts[id]))
	}
	noun := "modules"
	if len(ids) == 1 {
		noun = "module"
	}
	return fmt.Sprintf("%d %s errored (%s) — see vigolium log %s", len(ids), noun, strings.Join(parts, ", "), scanUUID)
}

// printCoverageCaveats writes the scan's coverage caveats under the finished
// banner, one line each: what the run did not cover and why. Module errors
// are left to printModuleErrorSummary, which names the log to read.
func (r *Runner) printCoverageCaveats(w io.Writer) {
	for _, c := range database.CoverageCaveats(r.Completion(), nil) {
		_, _ = fmt.Fprintf(w, "  %s %s\n", terminal.Yellow(terminal.SymbolWarning), c.Line())
	}
}

// printSafeSkipped writes the --safe summary line: how many in-scope records
// use a method the GET/HEAD policy kept out of testing.
func (r *Runner) printSafeSkipped(ctx context.Context, w io.Writer) {
	if r.options == nil || !r.options.Safe || r.repository == nil {
		return
	}
	n, err := r.repository.CountRecordsWithMethodsNotIn(ctx, r.options.ProjectUUID, r.getInScopeDBHosts(ctx), SafeMethods)
	if err != nil || n == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "  %s %d write-method records not tested (--safe)\n", terminal.Purple(terminal.SymbolInfo), n)
}

// printModuleErrorSummary writes the module error line under the finished
// banner, when any module failed.
func (r *Runner) printModuleErrorSummary(w io.Writer, scanUUID string) {
	line := formatModuleErrorSummary(r.ModuleErrors(), scanUUID)
	if line == "" {
		return
	}
	_, _ = fmt.Fprintf(w, "  %s %s\n", terminal.Yellow(terminal.SymbolWarning), line)
}

// extensionsAllFailed reports whether every extension module the given
// executors ran failed on every call it made — an exception, timeout or panic
// each time. False when no extension ran: an extension that never matched an
// item did not fail.
func extensionsAllFailed(execs []*core.Executor) bool {
	calls := make(map[string]int64)
	errs := make(map[string]int64)
	for _, e := range execs {
		if e == nil {
			continue
		}
		for id, m := range e.ModuleMetrics() {
			if core.IsExtensionModule(id) {
				calls[id] += m.Invocations
			}
		}
		for id, n := range e.ModuleErrors() {
			if core.IsExtensionModule(id) {
				errs[id] += n
			}
		}
	}
	ran := false
	for id, n := range calls {
		if n == 0 {
			continue
		}
		ran = true
		if errs[id] < n {
			return false
		}
	}
	return ran
}

// noteExtensionsAllFailed is a phase finisher: when every extension the phase's
// executors ran failed on every item, the phase is partial with
// extensions_all_failed, so a run whose extensions did nothing but throw does
// not read as a clean one.
func noteExtensionsAllFailed(t *phaseTracker) {
	t.mu.Lock()
	execs := append([]*core.Executor(nil), t.executors...)
	t.mu.Unlock()
	if extensionsAllFailed(execs) {
		t.markPartial(database.ReasonExtensionsAllFailed)
	}
}
