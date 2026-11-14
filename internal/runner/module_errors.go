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
type moduleErrorLedger struct {
	m sync.Map // module id → *atomic.Int64
}

func newModuleErrorLedger() *moduleErrorLedger { return &moduleErrorLedger{} }

// note records one failure and returns the module's running total. Nil-safe:
// a nil ledger counts nothing and reports 1, so the executor still emits the
// first event.
func (l *moduleErrorLedger) note(moduleID, _ string) int64 {
	if l == nil {
		return 1
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

// ModuleErrors returns the running scan's per-module error totals.
func (r *Runner) ModuleErrors() map[string]int64 {
	return r.moduleErrors.Load().snapshot()
}

// persistModuleErrors writes the ledger onto scans.module_errors. Called by the
// finalizer, before the row is completed, so `scan status` and scan.finished
// (which reads the row) carry the totals.
func (r *Runner) persistModuleErrors(ctx context.Context, scanUUID string) {
	counts := r.ModuleErrors()
	if r.repository == nil || len(counts) == 0 {
		return
	}
	if err := r.repository.UpdateScanPartial(ctx, &database.Scan{UUID: scanUUID, ModuleErrors: counts}); err != nil {
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
