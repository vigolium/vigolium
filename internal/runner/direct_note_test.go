package runner

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
)

// The public OAST server being unreachable is a caveat, not lost coverage: the
// completion stays complete and the caveat is still reported.
func TestOASTDefaultServerIsCaveatOnly(t *testing.T) {
	c := completionOf([]database.PhaseOutcome{{Phase: string(PhaseDynamicAssessment), State: database.PhaseCompleted}}, "")
	c = ApplyDirectPhaseNote(c, database.ReasonOASTUnavailable)
	if c.Completeness != database.CompletenessComplete {
		t.Fatalf("completeness = %s, want complete", c.Completeness)
	}
	caveats := database.CoverageCaveats(c, nil)
	if len(caveats) != 1 || caveats[0].Code != database.ReasonOASTUnavailable {
		t.Fatalf("caveats = %+v", caveats)
	}

	tr := &phaseTracker{phase: string(PhaseDynamicAssessment)}
	tr.noteCaveat(database.ReasonOASTUnavailable)
	out := tr.outcome()
	if out.State != database.PhaseCompleted || len(out.Reasons) != 0 || len(out.Notes) != 1 {
		t.Fatalf("tracker outcome = %+v", out)
	}

	// A configured server that is down stays partial.
	c = ApplyDirectPhaseReason(completionOf(nil, ""), database.ReasonOASTUnavailable)
	if c.Completeness != database.CompletenessPartial {
		t.Fatalf("configured server: completeness = %s, want partial", c.Completeness)
	}
}
