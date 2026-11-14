package core

import (
	"sync"
	"sync/atomic"
)

// moduleFindingTracker tracks finding count and one-time warning for a single module.
type moduleFindingTracker struct {
	count  atomic.Int64
	warned sync.Once
	// capped counts the distinct identities the cap dropped.
	capped atomic.Int64
}

// maxCappedIdentities bounds the identities remembered to count each capped
// finding once. Past it every capped emission is counted, which can only
// overstate a count that is already a lower bound of lost work.
const maxCappedIdentities = 100_000

// findingAdmission coordinates the first cap decision for one post-hook
// root-cause identity. Duplicate emissions wait for ready before using allowed,
// so they cannot race ahead and persist a finding that the owner is dropping.
type findingAdmission struct {
	ready   chan struct{}
	allowed bool
}

// FindingAdmission is the state behind the per-module finding cap: how many
// findings each module has had admitted, and which root-cause identities have
// already been admitted.
//
// It is a separate type so it can OUTLIVE one Executor. The dynamic-assessment
// phase builds a fresh executor per feedback round, so this state used to reset
// between rounds: a cap documented as holding "for the remainder of the scan"
// actually restarted every round, and a root cause re-found in round 2 re-fired
// every callback and notification for a finding already reported in round 1.
// Sharing one admission across the phase's rounds is what makes the documented
// contract true (triage C7: per dynamic-assessment phase, shared across rounds;
// other phases are uncapped).
//
// The zero value is ready to use, so an Executor built without a shared one gets
// its own by construction and a literal &Executor{cfg: …} in a test still works.
// Safe for concurrent use: both fields are sync.Maps.
type FindingAdmission struct {
	// counts is module ID → *moduleFindingTracker.
	counts sync.Map
	// ids tracks final post-hook root-cause identities and their admission
	// decisions. Repeated evidence is still persisted so the repository can merge
	// it, but only the first distinct finding consumes caps, stats, callbacks and
	// notifications.
	ids sync.Map
	// cappedIDs remembers identities the cap dropped (bounded by
	// maxCappedIdentities via cappedN), so Capped counts each once.
	cappedIDs sync.Map
	cappedN   atomic.Int64
}

// noteCapped counts one capped identity against moduleID's tracker.
func (a *FindingAdmission) noteCapped(id string, tracker *moduleFindingTracker) {
	if a.cappedN.Load() < maxCappedIdentities {
		if _, loaded := a.cappedIDs.LoadOrStore(id, struct{}{}); loaded {
			return
		}
		a.cappedN.Add(1)
	}
	tracker.capped.Add(1)
}

// Capped returns, per module, how many distinct findings the per-module cap
// dropped (identities, so repeated evidence of one dropped finding counts
// once). Modules that dropped nothing are absent; nil when none did.
func (a *FindingAdmission) Capped() map[string]int64 {
	if a == nil {
		return nil
	}
	var out map[string]int64
	a.counts.Range(func(k, v any) bool {
		if n := v.(*moduleFindingTracker).capped.Load(); n > 0 {
			if out == nil {
				out = make(map[string]int64)
			}
			out[k.(string)] = n
		}
		return true
	})
	return out
}

// NewFindingAdmission returns admission state a caller can share across several
// executors — one per dynamic-assessment phase, covering all of its rounds.
func NewFindingAdmission() *FindingAdmission { return &FindingAdmission{} }

// admission returns the state the cap decisions read: the caller's shared one
// when configured, otherwise this executor's own.
func (e *Executor) admission() *FindingAdmission {
	if e.cfg.FindingAdmission != nil {
		return e.cfg.FindingAdmission
	}
	return &e.caches.admission
}
