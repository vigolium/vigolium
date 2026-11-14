package core

import (
	"context"
	"slices"
	"sync"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/work"
)

// LedgerSpec wires an executor into the coverage ledger. The phase builds one
// per tier pass.
type LedgerSpec struct {
	// Writer persists the per-record rows (shared by the phase's passes).
	Writer *database.ProgressWriter
	// Ordinals maps every module of the phase (all passes) to its bit in
	// done_bits — the order stored in scans.coverage_modules.
	Ordinals map[string]int
	// Tiers maps every active module of the phase to its pass (0, 1, …).
	Tiers map[string]int
	// MaxTier is the last pass's tier; tier_done reaching it means the record
	// is fully covered.
	MaxTier int
	// RunsPassives reports whether this executor runs the passive stage (the
	// first pass), so passive_done can be recorded.
	RunsPassives bool
}

// ledgerPlan is a LedgerSpec resolved once per executor, so writeProgress
// does no map iteration per item.
type ledgerPlan struct {
	// size is one past the highest ordinal (itemProgress length).
	size int
	// ownOrdinals are the ordinals of this executor's active modules.
	ownOrdinals []int
	// tierOrdinals[t] are the ordinals of the phase's tier-t modules.
	tierOrdinals [][]int
}

func newLedgerPlan(spec *LedgerSpec, active []modules.ActiveModule) *ledgerPlan {
	if spec == nil {
		return nil
	}
	p := &ledgerPlan{tierOrdinals: make([][]int, spec.MaxTier+1)}
	for _, ord := range spec.Ordinals {
		p.size = max(p.size, ord+1)
	}
	for _, m := range active {
		if ord, ok := spec.Ordinals[m.ID()]; ok {
			p.ownOrdinals = append(p.ownOrdinals, ord)
		}
	}
	for id, tier := range spec.Tiers {
		ord, ok := spec.Ordinals[id]
		if ok && tier >= 0 && tier <= spec.MaxTier {
			p.tierOrdinals[tier] = append(p.tierOrdinals[tier], ord)
		}
	}
	return p
}

// tierDone returns cov's tier_done: the highest tier whose modules (and every
// lower tier's) are all done, never below the stored cov.TierDone. Tier 0 also
// needs the passive stage, so passivePending holds it back when cov had no
// tier yet.
func (p *ledgerPlan) tierDone(cov *work.Coverage, passivePending bool) int {
	done := cov.TierDone
	notDone := func(ord int) bool { return !cov.ModuleDone(ord) }
	for tier, ords := range p.tierOrdinals {
		if slices.ContainsFunc(ords, notDone) {
			break
		}
		if tier <= cov.TierDone {
			continue
		}
		if tier == 0 && passivePending {
			break
		}
		done = tier
	}
	return done
}

// itemProgress is one item's ledger bookkeeping while its tasks run, indexed
// by module ordinal (LedgerSpec.Ordinals). Methods ignore an ordinal < 0 (a
// module the ledger does not track) and are nil-safe.
type itemProgress struct {
	mu         sync.Mutex
	pending    []int
	failed     []bool
	timedOut   int
	dispatched bool
	passiveRan bool
}

func newItemProgress(modules int) *itemProgress {
	return &itemProgress{pending: make([]int, modules), failed: make([]bool, modules)}
}

func (p *itemProgress) tracks(ord int) bool { return p != nil && ord >= 0 && ord < len(p.pending) }

// begin counts a task of the module at ord about to be queued.
func (p *itemProgress) begin(ord int) {
	if !p.tracks(ord) {
		return
	}
	p.mu.Lock()
	p.pending[ord]++
	p.mu.Unlock()
}

// end resolves one task of the module at ord; ok=false marks the module not
// done on this record (timeout, cancellation, transient transport failure,
// gate refusal), and timedOut counts a per-module timeout.
func (p *itemProgress) end(ord int, ok, timedOut bool) {
	if !p.tracks(ord) {
		return
	}
	p.mu.Lock()
	p.pending[ord]--
	if !ok {
		p.failed[ord] = true
	}
	if timedOut {
		p.timedOut++
	}
	p.mu.Unlock()
}

// fail marks the module at ord not done without a task having run (dropped
// or never queued because the phase was cancelled).
func (p *itemProgress) fail(ord int) {
	if !p.tracks(ord) {
		return
	}
	p.mu.Lock()
	p.failed[ord] = true
	p.mu.Unlock()
}

// ledgerOrdinal is moduleID's coverage ordinal, or -1 when the executor has
// no ledger or the ledger does not track the module.
func (e *Executor) ledgerOrdinal(moduleID string) int {
	if e.cfg.Ledger == nil {
		return -1
	}
	if ord, ok := e.cfg.Ledger.Ordinals[moduleID]; ok {
		return ord
	}
	return -1
}

// moduleDone reports whether item's stored coverage says moduleID already
// finished on it (the executor skips it).
func (e *Executor) moduleDone(item *work.WorkItem, moduleID string) bool {
	if item == nil || item.Coverage == nil {
		return false
	}
	return item.Coverage.ModuleDone(e.ledgerOrdinal(moduleID))
}

// writeProgress records t's coverage when its item completes. Only items that
// reached the active stage are written: an item whose baseline fetch failed or
// that scope dropped was not tested by anything. Modules of this executor
// without a failure are done (including modules that had nothing to do on the
// record); prior bits from item.Coverage are kept.
func (e *Executor) writeProgress(t *itemTracker) {
	spec, plan := e.cfg.Ledger, e.ledger
	p := t.prog
	if spec == nil || spec.Writer == nil || plan == nil || p == nil || t.item == nil || t.item.RecordUUID == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.dispatched {
		return
	}
	cancelled := t.ctx.Err() != nil

	cov := work.Coverage{TierDone: -1}
	if prev := t.item.Coverage; prev != nil {
		cov = work.Coverage{TierDone: prev.TierDone, PassiveDone: prev.PassiveDone, DoneBits: append([]byte(nil), prev.DoneBits...)}
	}
	for _, ord := range plan.ownOrdinals {
		if !p.tracks(ord) || p.failed[ord] || (cancelled && p.pending[ord] > 0) {
			continue
		}
		cov.SetModuleDone(ord)
	}
	if spec.RunsPassives && p.passiveRan {
		cov.PassiveDone = true
	}

	cov.TierDone = plan.tierDone(&cov, !cov.PassiveDone && len(e.passiveModules) > 0)

	spec.Writer.Write(database.ScanRecordProgress{
		ScanUUID:    e.scanUUID,
		RecordUUID:  t.item.RecordUUID,
		ProjectUUID: e.projectUUID,
		TierDone:    cov.TierDone,
		PassiveDone: cov.PassiveDone,
		TimedOut:    p.timedOut,
		DoneBits:    cov.DoneBits,
	})
}

// goModuleTask queues fn as moduleID's task on t, keeping the item's ledger
// bookkeeping: the task's outcome decides whether the module counts as done
// on this record; a task dropped before it ran (cancellation) does not.
func (e *Executor) goModuleTask(ctx context.Context, t *itemTracker, hostKey, moduleID string, fn func(releaseSlot func()) callOutcome) {
	ord := -1
	if t.prog != nil {
		ord = e.ledgerOrdinal(moduleID)
	}
	if ctx.Err() != nil {
		t.prog.fail(ord)
		return
	}
	t.prog.begin(ord)
	e.goActiveTask(ctx, t, hostKey, func(releaseSlot func()) {
		o := fn(releaseSlot)
		t.prog.end(ord, !o.failedTransiently(), !o.completed && ctx.Err() == nil)
	}, func() { t.prog.end(ord, false, false) })
}
