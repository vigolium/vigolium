package runner

import "github.com/vigolium/vigolium/pkg/database"

// ApplyDirectPhaseReason folds a reason the single-request path observed
// outside the executor's report into a DirectScanCompletion: the
// dynamic-assessment outcome turns partial with reason, as the Runner's phase
// tracker records it. Used for oast_unavailable (the out-of-band service could
// not register, so blind checks were skipped) and scan_budget
// (--scanning-max-duration ran out). An empty reason returns c unchanged.
//
// The stop reason is kept when something already stopped the scan; otherwise
// completionOf names the first phase reason, as on the Runner path.
func ApplyDirectPhaseReason(c database.ScanCompletion, reason string) database.ScanCompletion {
	if reason == "" {
		return c
	}
	note := database.PhaseOutcome{
		Phase:   string(PhaseDynamicAssessment),
		State:   database.PhasePartial,
		Reasons: []string{reason},
	}
	return mergeDirectNote(c, note, c.StopReason)
}

// mergeDirectNote merges note into c's outcome for the same phase (appending
// it when c has none) and rebuilds the completion with stop as the stop
// reason. c's phases are copied, never modified.
func mergeDirectNote(c database.ScanCompletion, note database.PhaseOutcome, stop string) database.ScanCompletion {
	phases := append([]database.PhaseOutcome(nil), c.Phases...)
	merged := false
	for i := range phases {
		if phases[i].Phase == note.Phase {
			phases[i].Merge(note)
			merged = true
		}
	}
	if !merged {
		phases = append(phases, note)
	}
	return completionOf(phases, stop)
}

// ApplyDirectPhaseNote records a caveat code on the direct scan's
// dynamic-assessment outcome without changing its coverage verdict (see
// PhaseOutcome.Notes).
func ApplyDirectPhaseNote(c database.ScanCompletion, code string) database.ScanCompletion {
	if code == "" {
		return c
	}
	note := database.PhaseOutcome{
		Phase: string(PhaseDynamicAssessment),
		State: database.PhaseCompleted,
		Notes: []string{code},
	}
	return mergeDirectNote(c, note, c.StopReason)
}
