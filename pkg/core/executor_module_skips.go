package core

import (
	"sync"
	"sync/atomic"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
)

// Module skip reasons (cross-track contract strings; Track C persists them to
// scans.module_stats). Each names why a module did NOT test something it was
// considered for — the "why was this not tested?" half of the module ledger.
const (
	SkipReasonTechFilter            = "tech_filter"
	SkipReasonCannotProcess         = "cannot_process"
	SkipReasonParamAlreadyFound     = "param_already_found"
	SkipReasonIPType                = "ip_type"
	SkipReasonQuarantined           = "quarantined"
	SkipReasonTimeout               = "timeout"
	SkipReasonMethodPolicy          = "method_policy"
	SkipReasonHeaderGated           = "header_gated"
	SkipReasonInconclusiveThrottled = "inconclusive_throttled"
)

// moduleSkipReasons fixes each reason's slot in a moduleSkipCounters array.
var moduleSkipReasons = [...]string{
	SkipReasonTechFilter,
	SkipReasonCannotProcess,
	SkipReasonParamAlreadyFound,
	SkipReasonIPType,
	SkipReasonQuarantined,
	SkipReasonTimeout,
	SkipReasonMethodPolicy,
	SkipReasonHeaderGated,
	SkipReasonInconclusiveThrottled,
}

var moduleSkipReasonIndex = func() map[string]int {
	m := make(map[string]int, len(moduleSkipReasons))
	for i, r := range moduleSkipReasons {
		m[r] = i
	}
	return m
}()

type moduleSkipCounters [len(moduleSkipReasons)]atomic.Int64

// moduleSkipLedger counts skips per (module, reason). The executor's modules
// are known at construction, so their counters are pre-allocated in a map that
// is read-only afterwards: counting on the dispatch hot path is one map lookup
// plus one atomic add. A module id not known up front (tests, extensions added
// later) falls back to a mutex-guarded overflow map.
type moduleSkipLedger struct {
	fixed map[string]*moduleSkipCounters

	mu    sync.Mutex
	extra map[string]*moduleSkipCounters
}

func newModuleSkipLedger(active []modules.ActiveModule, passive []modules.PassiveModule) *moduleSkipLedger {
	l := &moduleSkipLedger{fixed: make(map[string]*moduleSkipCounters, len(active)+len(passive))}
	for _, m := range active {
		l.fixed[m.ID()] = &moduleSkipCounters{}
	}
	for _, m := range passive {
		l.fixed[m.ID()] = &moduleSkipCounters{}
	}
	return l
}

func (l *moduleSkipLedger) counters(moduleID string) *moduleSkipCounters {
	if c, ok := l.fixed[moduleID]; ok {
		return c
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.extra == nil {
		l.extra = make(map[string]*moduleSkipCounters)
	}
	c := l.extra[moduleID]
	if c == nil {
		c = &moduleSkipCounters{}
		l.extra[moduleID] = c
	}
	return c
}

// note counts one skip of moduleID for reason. Safe on a nil ledger.
func (l *moduleSkipLedger) note(moduleID, reason string) {
	if l == nil {
		return
	}
	i, ok := moduleSkipReasonIndex[reason]
	if !ok {
		return
	}
	l.counters(moduleID)[i].Add(1)
}

// snapshot returns module → reason → count, omitting zero counts.
func (l *moduleSkipLedger) snapshot() map[string]map[string]int64 {
	if l == nil {
		return nil
	}
	out := make(map[string]map[string]int64)
	add := func(id string, c *moduleSkipCounters) {
		for i := range c {
			if n := c[i].Load(); n > 0 {
				if out[id] == nil {
					out[id] = make(map[string]int64)
				}
				out[id][moduleSkipReasons[i]] += n
			}
		}
	}
	for id, c := range l.fixed {
		add(id, c)
	}
	l.mu.Lock()
	for id, c := range l.extra {
		add(id, c)
	}
	l.mu.Unlock()
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
// saw the host throttle the call (429/503 per Track A's CallStats) and the
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
