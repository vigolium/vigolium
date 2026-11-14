package core

import (
	"context"
	"sync"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/work"
)

// LedgerSpec wires an executor into the coverage ledger (ECON-4). The phase
// builds one per tier pass.
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

// itemProgress is one item's ledger bookkeeping while its tasks run.
type itemProgress struct {
	mu         sync.Mutex
	pending    map[string]int
	failed     map[string]bool
	timedOut   int
	dispatched bool
	passiveRan bool
}

func newItemProgress() *itemProgress {
	return &itemProgress{pending: map[string]int{}, failed: map[string]bool{}}
}

// begin counts a task of moduleID about to be queued.
func (p *itemProgress) begin(moduleID string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.pending[moduleID]++
	p.mu.Unlock()
}

// end resolves one task of moduleID; ok=false marks the module not done on
// this record (timeout, cancellation, transient transport failure, gate
// refusal), and timedOut counts a per-module timeout.
func (p *itemProgress) end(moduleID string, ok, timedOut bool) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.pending[moduleID]--
	if !ok {
		p.failed[moduleID] = true
	}
	if timedOut {
		p.timedOut++
	}
	p.mu.Unlock()
}

// fail marks moduleID not done without a task having run (dropped or never
// queued because the phase was cancelled).
func (p *itemProgress) fail(moduleID string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.failed[moduleID] = true
	p.mu.Unlock()
}

// moduleDone reports whether item's stored coverage says moduleID already
// finished on it (the executor skips it).
func (e *Executor) moduleDone(item *work.WorkItem, moduleID string) bool {
	if e.cfg.Ledger == nil || item == nil || item.Coverage == nil {
		return false
	}
	ord, ok := e.cfg.Ledger.Ordinals[moduleID]
	return ok && item.Coverage.ModuleDone(ord)
}

// writeProgress records t's coverage when its item completes. Only items that
// reached the active stage are written: an item whose baseline fetch failed or
// that scope dropped was not tested by anything. Modules of this executor
// without a failure are done (including modules that had nothing to do on the
// record); prior bits from item.Coverage are kept.
func (e *Executor) writeProgress(t *itemTracker) {
	spec := e.cfg.Ledger
	p := t.prog
	if spec == nil || spec.Writer == nil || p == nil || t.item == nil || t.item.RecordUUID == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.dispatched {
		return
	}
	cancelled := t.ctx.Err() != nil

	prev := t.item.Coverage
	var bits []byte
	prevTier := -1
	passiveDone := false
	if prev != nil {
		bits = append(bits, prev.DoneBits...)
		prevTier = prev.TierDone
		passiveDone = prev.PassiveDone
	}
	set := func(ord int) {
		for len(bits) <= ord/8 {
			bits = append(bits, 0)
		}
		bits[ord/8] |= 1 << uint(ord%8)
	}
	isSet := func(ord int) bool {
		return ord/8 < len(bits) && bits[ord/8]&(1<<uint(ord%8)) != 0
	}
	for _, m := range e.activeModules {
		id := m.ID()
		ord, ok := spec.Ordinals[id]
		if !ok || p.failed[id] || (cancelled && p.pending[id] > 0) {
			continue
		}
		set(ord)
	}
	if spec.RunsPassives && p.passiveRan {
		passiveDone = true
	}

	// tier_done: the highest tier whose modules (and every lower tier's) are
	// all done on this record.
	tierDone := prevTier
	for tier := prevTier + 1; tier <= spec.MaxTier; tier++ {
		complete := true
		for id, mt := range spec.Tiers {
			if mt > tier {
				continue
			}
			if ord, ok := spec.Ordinals[id]; ok && !isSet(ord) {
				complete = false
				break
			}
		}
		if !complete || (tier == 0 && !passiveDone && len(e.passiveModules) > 0) {
			break
		}
		tierDone = tier
	}

	spec.Writer.Write(database.ScanRecordProgress{
		ScanUUID:    e.scanUUID,
		RecordUUID:  t.item.RecordUUID,
		ProjectUUID: e.projectUUID,
		TierDone:    tierDone,
		PassiveDone: passiveDone,
		TimedOut:    p.timedOut,
		DoneBits:    bits,
	})
}

// goModuleTask queues fn as moduleID's task on t, keeping the item's ledger
// bookkeeping: the task's outcome decides whether the module counts as done
// on this record; a task dropped before it ran (cancellation) does not.
func (e *Executor) goModuleTask(ctx context.Context, t *itemTracker, hostKey, moduleID string, fn func(releaseSlot func()) callOutcome) {
	if ctx.Err() != nil {
		t.prog.fail(moduleID)
		return
	}
	t.prog.begin(moduleID)
	e.enqueueTask(ctx, t, hostKey, func(releaseSlot func()) {
		o := fn(releaseSlot)
		t.prog.end(moduleID, !o.failedTransiently(), !o.completed && ctx.Err() == nil)
	}, func() { t.prog.end(moduleID, false, false) })
}
