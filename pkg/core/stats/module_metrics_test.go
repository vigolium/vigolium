package stats

import (
	"errors"
	"testing"
	"time"
)

func TestModuleMetrics_RecordAndSnapshot(t *testing.T) {
	mm := &ModuleMetrics{}

	mm.Record("xss", 10*time.Millisecond, 2, nil)
	mm.Record("xss", 30*time.Millisecond, 0, errors.New("boom"))

	snap := mm.Snapshot()
	got, ok := snap["xss"]
	if !ok {
		t.Fatal("expected xss in snapshot")
	}
	if got.Invocations != 2 {
		t.Errorf("Invocations = %d, want 2", got.Invocations)
	}
	if got.Findings != 2 {
		t.Errorf("Findings = %d, want 2", got.Findings)
	}
	if got.Errors != 1 {
		t.Errorf("Errors = %d, want 1", got.Errors)
	}
	if got.TotalTime != 40*time.Millisecond {
		t.Errorf("TotalTime = %v, want 40ms", got.TotalTime)
	}
}

func TestModuleMetrics_RecordImpliesConsidered(t *testing.T) {
	mm := &ModuleMetrics{}
	mm.Record("sqli", time.Millisecond, 0, nil)

	if got := mm.ConsideredCount(); got != 1 {
		t.Fatalf("ConsideredCount() = %d, want 1 (Record implies considered)", got)
	}
	if got := mm.DistinctCount(); got != 1 {
		t.Fatalf("DistinctCount() = %d, want 1", got)
	}
}

func TestModuleMetrics_MarkConsideredWithoutRun(t *testing.T) {
	mm := &ModuleMetrics{}

	mm.MarkConsidered("a")
	mm.MarkConsidered("b")
	mm.MarkConsidered("a") // duplicate must not double-count

	if got := mm.ConsideredCount(); got != 2 {
		t.Errorf("ConsideredCount() = %d, want 2", got)
	}
	// Considered-but-never-run modules must not appear as invoked.
	if got := mm.DistinctCount(); got != 0 {
		t.Errorf("DistinctCount() = %d, want 0", got)
	}
	if got := mm.TotalInvocations(); got != 0 {
		t.Errorf("TotalInvocations() = %d, want 0", got)
	}
}

func TestModuleMetrics_TotalInvocations(t *testing.T) {
	mm := &ModuleMetrics{}
	mm.Record("a", time.Millisecond, 0, nil)
	mm.Record("a", time.Millisecond, 0, nil)
	mm.Record("b", time.Millisecond, 0, nil)

	if got := mm.TotalInvocations(); got != 3 {
		t.Errorf("TotalInvocations() = %d, want 3", got)
	}
	if got := mm.DistinctCount(); got != 2 {
		t.Errorf("DistinctCount() = %d, want 2", got)
	}
}

func TestModuleMetrics_NilReceiver(t *testing.T) {
	var mm *ModuleMetrics // nil — must be safe per the documented contract

	mm.Record("x", time.Second, 1, nil) // must not panic
	mm.MarkConsidered("x")              // must not panic

	if got := mm.ConsideredCount(); got != 0 {
		t.Errorf("ConsideredCount() on nil = %d, want 0", got)
	}
	if got := mm.DistinctCount(); got != 0 {
		t.Errorf("DistinctCount() on nil = %d, want 0", got)
	}
	if got := mm.TotalInvocations(); got != 0 {
		t.Errorf("TotalInvocations() on nil = %d, want 0", got)
	}
	if snap := mm.Snapshot(); snap != nil {
		t.Errorf("Snapshot() on nil = %v, want nil", snap)
	}
}
