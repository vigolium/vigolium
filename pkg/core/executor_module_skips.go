package core

import (
	"sync"
	"sync/atomic"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
)

// Module skip reasons, persisted to scans.module_stats. Each names why a
// module did NOT test something it was considered for — the "why was this not
// tested?" half of the module ledger. pkg/database owns the list.
const (
	SkipReasonTechFilter            = database.SkipTechFilter
	SkipReasonCannotProcess         = database.SkipCannotProcess
	SkipReasonParamAlreadyFound     = database.SkipParamAlreadyFound
	SkipReasonIPType                = database.SkipIPType
	SkipReasonQuarantined           = database.SkipQuarantined
	SkipReasonTimeout               = database.SkipTimeout
	SkipReasonMethodPolicy          = database.SkipMethodPolicy
	SkipReasonHeaderGated           = database.SkipHeaderGated
	SkipReasonInconclusiveThrottled = database.SkipInconclusiveThrottled
)

// skipReasonIndex fixes each reason's slot in a module's counter slice.
var skipReasonIndex = func() map[string]int {
	m := make(map[string]int, len(database.ModuleSkipReasons))
	for i, r := range database.ModuleSkipReasons {
		m[r] = i
	}
	return m
}()

// moduleSkipLedger counts skips per (module, reason): module id → one atomic
// counter per reason. The zero value is ready to use; a nil ledger is a no-op.
type moduleSkipLedger struct {
	byModule sync.Map // module id → []atomic.Int64, indexed by skipReasonIndex
}

// note counts one skip of moduleID for reason. Unknown reasons are ignored.
func (l *moduleSkipLedger) note(moduleID, reason string) { l.add(moduleID, reason, 1) }

// add counts n skips of moduleID for reason; n <= 0 is a no-op.
func (l *moduleSkipLedger) add(moduleID, reason string, n int64) {
	i, ok := skipReasonIndex[reason]
	if l == nil || !ok || n <= 0 {
		return
	}
	v, ok := l.byModule.Load(moduleID)
	if !ok {
		v, _ = l.byModule.LoadOrStore(moduleID, make([]atomic.Int64, len(database.ModuleSkipReasons)))
	}
	v.([]atomic.Int64)[i].Add(n)
}

// snapshot returns module → reason → count, omitting zero counts.
func (l *moduleSkipLedger) snapshot() map[string]map[string]int64 {
	if l == nil {
		return nil
	}
	out := make(map[string]map[string]int64)
	l.byModule.Range(func(k, v any) bool {
		id, counts := k.(string), v.([]atomic.Int64)
		for i := range counts {
			if n := counts[i].Load(); n > 0 {
				if out[id] == nil {
					out[id] = make(map[string]int64)
				}
				out[id][database.ModuleSkipReasons[i]] = n
			}
		}
		return true
	})
	if len(out) == 0 {
		return nil
	}
	return out
}

// noteModuleSkip counts one skip on the executor's ledger.
func (e *Executor) noteModuleSkip(moduleID, reason string) {
	e.moduleSkips.note(moduleID, reason)
}

// ModuleSkips returns module → skip reason → count for this executor.
func (e *Executor) ModuleSkips() map[string]map[string]int64 {
	return e.moduleSkips.snapshot()
}

// noteThrottledCall classifies a completed module call: when the requester
// saw the host throttle the call (429/503 per its CallStats) and the
// module produced no finding, its negative is not a real negative — the
// payloads were answered by a rate limiter, not the application. Counted as
// inconclusive_throttled so the coverage ledger does not record a clean pass.
// Returns true when the call was classified inconclusive.
func (e *Executor) noteThrottledCall(module modules.Module, client *http.Requester, events []*output.ResultEvent) bool {
	cs := client.CallStats()
	if cs == nil || cs.Throttled.Load() == 0 {
		return false
	}
	for _, ev := range events {
		if ev != nil && ev.IsFinding() {
			return false
		}
	}
	e.noteModuleSkip(module.ID(), SkipReasonInconclusiveThrottled)
	e.moduleMetrics.RecordInconclusive(module.ID())
	return true
}
