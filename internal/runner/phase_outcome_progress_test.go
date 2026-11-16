package runner

import (
	"context"
	"fmt"
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"github.com/vigolium/vigolium/pkg/spitolas"
)

// A phase's last work-item reading is kept on its outcome, so a curtailed
// phase can say how far it got (caveat done/total on scan.finished).
func TestPhaseOutcomeKeepsProgress(t *testing.T) {
	tr := newLedger("spidering")
	tr.setProgress("targets", func() (int64, int64) { return 3, 10 })
	tr.markPartial(database.ReasonPhaseDeadline)
	out := tr.finish(context.Background(), nil)
	if out.Progress == nil || out.Progress.Done != 3 || out.Progress.Total == nil || *out.Progress.Total != 10 || out.Progress.Unit != "targets" {
		t.Fatalf("progress = %+v, want 3/10 targets", out.Progress)
	}
	cv := database.CoverageCaveats(database.ScanCompletion{Phases: []database.PhaseOutcome{out}}, nil)
	if len(cv) != 1 || cv[0].Done == nil || *cv[0].Done != 3 || *cv[0].Total != 10 {
		t.Fatalf("phase_deadline caveat = %+v, want done 3 of 10", cv)
	}

	none := newLedger("discovery").finish(context.Background(), nil)
	if none.Progress != nil {
		t.Errorf("a phase with no progress source has no progress, got %+v", none.Progress)
	}
}

// The controls a crawl refused to click land on the running phase: an exact
// count and a bounded, deduplicated sample.
func TestNoteSkippedControls(t *testing.T) {
	tr := newLedger("spidering")
	r := &Runner{}
	r.currentPhase.Store(tr)
	res := &spitolas.SpiderResult{SkippedDestructive: 40}
	for i := 0; i < scanevents.MaxSkippedControlSample+5; i++ {
		res.SkippedControls = append(res.SkippedControls, scanevents.SkippedControl{Label: fmt.Sprintf("Delete %d", i), Reason: "deny_click"})
	}
	r.noteSkippedControls(res)
	r.noteSkippedControls(&spitolas.SpiderResult{SkippedDestructive: 2,
		SkippedControls: []scanevents.SkippedControl{{Label: "Delete 0", Reason: "deny_click"}}})
	out := tr.finish(context.Background(), nil)
	if got := out.Counts[database.CountSkippedControls]; got != 42 {
		t.Errorf("skipped_controls count = %d, want 42", got)
	}
	if len(out.SkippedControls) != scanevents.MaxSkippedControlSample {
		t.Errorf("sample = %d, want %d", len(out.SkippedControls), scanevents.MaxSkippedControlSample)
	}
	n, sample := database.SkippedControls([]database.PhaseOutcome{out, out})
	if n != 84 || len(sample) != scanevents.MaxSkippedControlSample {
		t.Errorf("scan-level roll-up = %d/%d, want 84 and a bounded sample", n, len(sample))
	}
}
