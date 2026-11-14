package runner

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/spitolas"
	"github.com/vigolium/vigolium/pkg/types"
)

// TestSpideringLaunchFailureIsPartial is MISS-27: a browser that never started
// leaves the phase partial with targets_failed and browser_unavailable, rather
// than "completed, 0 records".
func TestSpideringLaunchFailureIsPartial(t *testing.T) {
	r := &Runner{options: &types.Options{Silent: true}, scanLogger: database.NewScanLogger(nil, "")}
	tracker := r.beginPhase(context.Background(), string(PhaseSpidering), nil)
	r.currentPhase.Store(tracker)

	launchErr := fmt.Errorf("spider: failed to create browser pool: %w", spitolas.ErrBrowserLaunch)
	r.noteSpideringFailures(3, launchErr)
	out := tracker.finish(context.Background(), nil)

	if out.State != database.PhasePartial {
		t.Fatalf("state = %s, want partial", out.State)
	}
	for _, want := range []string{database.ReasonTargetsFailed, database.ReasonBrowserUnavailable} {
		if !slices.Contains(out.Reasons, want) {
			t.Errorf("reasons = %v, want %s", out.Reasons, want)
		}
	}
	if out.Counts["targets_failed"] != 3 {
		t.Errorf("targets_failed = %d, want 3", out.Counts["targets_failed"])
	}
}
