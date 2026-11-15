package database

import "testing"

func TestScopeDroppedSumsPhaseCounts(t *testing.T) {
	phases := []PhaseOutcome{
		{Phase: "discovery", Counts: map[string]int64{ScopeDroppedCountPrefix + "status_code": 3, "hosts_dead": 1}},
		{Phase: "dynamic-assessment", Counts: map[string]int64{ScopeDroppedCountPrefix + "status_code": 2, ScopeDroppedCountPrefix + "path": 1}},
	}
	got := ScopeDropped(phases)
	if got["status_code"] != 5 || got["path"] != 1 || len(got) != 2 {
		t.Fatalf("ScopeDropped = %v", got)
	}
	if ScopeDropped([]PhaseOutcome{{Phase: "x"}}) != nil {
		t.Fatal("no drops must be nil")
	}
}
