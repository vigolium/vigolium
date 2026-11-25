package runner

import (
	"slices"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
)

// Held-back write templates are a phase note carrying the largest count any
// pass saw (passes overlap, so they are not summed), and the scan's caveats
// render it as templates_skipped_unsafe_method with that count. Zero notes
// nothing.
func TestNoteWriteTemplatesSkipped(t *testing.T) {
	tr := &phaseTracker{phase: string(PhaseDynamicAssessment), start: time.Now()}
	tr.noteWriteTemplatesSkipped(0)
	if o := tr.outcome(); slices.Contains(o.Notes, database.LimitTemplatesSkippedUnsafeMethod) {
		t.Fatal("a pass that held nothing back noted the caveat")
	}
	tr.noteWriteTemplatesSkipped(3)
	tr.noteWriteTemplatesSkipped(2)
	o := tr.outcome()
	if !slices.Contains(o.Notes, database.LimitTemplatesSkippedUnsafeMethod) {
		t.Fatalf("notes %v lack %s", o.Notes, database.LimitTemplatesSkippedUnsafeMethod)
	}
	if got := o.Counts[database.LimitTemplatesSkippedUnsafeMethod]; got != 3 {
		t.Errorf("count = %d, want 3 (the largest pass)", got)
	}
	if o.State == database.PhasePartial {
		t.Error("held-back templates made the phase partial; they are a caveat, not a coverage defect")
	}
	var found bool
	for _, cv := range database.CoverageCaveats(database.ScanCompletion{Phases: []database.PhaseOutcome{o}}, nil) {
		if cv.Code == database.LimitTemplatesSkippedUnsafeMethod {
			found = true
			if cv.Count != 3 || cv.Phase != string(PhaseDynamicAssessment) {
				t.Errorf("caveat = %+v, want count 3 on dynamic-assessment", cv)
			}
		}
	}
	if !found {
		t.Error("no templates_skipped_unsafe_method caveat")
	}
}
