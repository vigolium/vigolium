package runner

import (
	"errors"
	"testing"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/database"
)

func trippedCache(t *testing.T, keys ...string) *hosterrors.Cache {
	t.Helper()
	c := hosterrors.NewWithConfig(hosterrors.Config{MaxHostError: 1, MaxHostsCount: 10})
	t.Cleanup(c.Close)
	for _, k := range keys {
		for i := 0; i < 3; i++ {
			c.MarkFailed(k, errors.New("dial tcp: connect: connection refused"), false)
		}
		if c.State(k) == hosterrors.StateClosed {
			t.Fatalf("%s did not trip", k)
		}
	}
	return c
}

// Requests the breaker refuses during a phase make it partial
// (targets_unreachable) and list the host, even though the executor skipped
// no input item.
func TestGateRefusalsMarkPhaseUnreachable(t *testing.T) {
	c := trippedCache(t, "app.example:80")
	tr := &phaseTracker{phase: "dynamic-assessment", reasons: map[string]struct{}{}}
	before := c.Refusals()
	if ok, _ := c.Admit("app.example:80"); ok {
		t.Fatal("a quarantined host was admitted")
	}
	tr.noteGateRefusals(c, before)
	out := tr.outcome()
	if out.State != database.PhasePartial || len(out.Reasons) != 1 || out.Reasons[0] != database.ReasonTargetsUnreachable {
		t.Fatalf("outcome = %+v", out)
	}
	if out.Targets == nil || len(out.Targets.Unreachable) != 1 || out.Targets.Unreachable[0].Target != "app.example:80" {
		t.Fatalf("unreachable = %+v", out.Targets)
	}

	// A phase with no new refusals stays clean.
	tr2 := &phaseTracker{phase: "discovery", reasons: map[string]struct{}{}}
	tr2.noteGateRefusals(c, c.Refusals())
	if out := tr2.outcome(); out.State != database.PhaseCompleted {
		t.Fatalf("clean phase = %+v", out)
	}
}

// Every admitted target quarantined at the end: failed, no_targets_reachable.
func TestAllTargetsQuarantinedFailsTheScan(t *testing.T) {
	r := &Runner{}
	c := trippedCache(t, "app.example:443")
	err := r.allTargetsQuarantined(c, []string{"https://app.example/"})
	if !errors.Is(err, ErrNoTargetsReachable) {
		t.Fatalf("err = %v", err)
	}
	if err := r.allTargetsQuarantined(c, []string{"https://app.example/", "http://other.example/"}); err != nil {
		t.Fatalf("one healthy target left: %v", err)
	}
}
