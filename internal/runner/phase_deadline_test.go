package runner

import (
	"context"
	"errors"
	"testing"
	"time"
)

// These tests guard the per-phase max_duration enforcement. The original bug:
// the known-issue-scan phase computed the right budget but only applied it to
// one leg (Nuclei) while the secret-scan leg ran unbounded, so the phase could
// overrun max_duration. The fix routes every phase deadline through phaseDeadline.
//
// known-issue-scan later moved its two legs from ONE shared budget to INDEPENDENT
// per-leg budgets, so a Nuclei run that consumes its whole budget no longer starves
// the secret scan (TestPhaseDeadline_IndependentLegsEachGetOwnBudget).
// The shared-budget property still holds for phases that bound all their work under
// a single deadline (TestPhaseDeadline_BoundsSequentialLegs).
//
// Durations are kept small but upper-bound tolerances are generous so the tests
// stay deterministic on slow/loaded CI without false failures.

// TestPhaseDeadline_AppliesBudget: a positive budget produces a real deadline
// roughly maxDuration out, and the context expires with DeadlineExceeded.
func TestPhaseDeadline_AppliesBudget(t *testing.T) {
	const budget = 60 * time.Millisecond
	start := time.Now()

	ctx, cancel := phaseDeadline(context.Background(), budget)
	defer cancel()

	dl, ok := ctx.Deadline()
	if !ok {
		t.Fatal("phaseDeadline(budget>0) must set a deadline")
	}
	if got := dl.Sub(start); got < budget/2 || got > budget+500*time.Millisecond {
		t.Fatalf("deadline %v is not ~%v from start", got, budget)
	}

	select {
	case <-ctx.Done():
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Fatalf("ctx.Err() = %v, want DeadlineExceeded", ctx.Err())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("phase ctx never expired; the budget was not enforced")
	}
}

// TestPhaseDeadline_NoBudget: maxDuration <= 0 means "unbounded phase" — the
// parent ctx is returned unchanged (no deadline) and the cancel is a safe no-op.
func TestPhaseDeadline_NoBudget(t *testing.T) {
	for _, d := range []time.Duration{0, -1 * time.Second} {
		parent := context.Background()
		ctx, cancel := phaseDeadline(parent, d)

		if _, ok := ctx.Deadline(); ok {
			t.Fatalf("d=%v: expected no deadline on an unbounded phase", d)
		}
		if ctx != parent {
			t.Fatalf("d=%v: expected the parent ctx returned unchanged", d)
		}
		cancel() // must not panic, and must not cancel the parent
		if parent.Err() != nil {
			t.Fatalf("d=%v: no-op cancel must not affect the parent ctx", d)
		}
	}
}

// TestPhaseDeadline_CapsToParentDeadline: a phase budget larger than the time
// remaining on the parent (e.g. an overall scan deadline) must NOT extend it —
// a phase can never run past the scan. This is the property that lets each phase
// resolve its budget independently without overrunning a tighter outer bound.
func TestPhaseDeadline_CapsToParentDeadline(t *testing.T) {
	const parentBudget = 40 * time.Millisecond

	parent, cancelParent := context.WithTimeout(context.Background(), parentBudget)
	defer cancelParent()

	// Phase asks for far more than the parent has left.
	ctx, cancel := phaseDeadline(parent, 10*time.Second)
	defer cancel()

	dl, ok := ctx.Deadline()
	if !ok {
		t.Fatal("expected a deadline inherited from the parent")
	}
	if remaining := time.Until(dl); remaining > time.Second {
		t.Fatalf("phase deadline %v exceeded the parent's ~%v budget", remaining, parentBudget)
	}

	select {
	case <-ctx.Done():
		// Expired on the parent's schedule, as required.
	case <-time.After(2 * time.Second):
		t.Fatal("phase ctx outlived the parent deadline")
	}
}

// TestPhaseDeadline_BoundsSequentialLegs pins the shared-budget property: when two
// legs run sequentially under ONE shared deadline, a second leg that respects ctx
// must observe the deadline the first leg exhausted and return immediately instead
// of running unbounded. This is the contract for phases that bound all their work
// under a single phaseDeadline (e.g. dynamic-assessment). known-issue-scan no longer
// shares one budget between its legs — see TestPhaseDeadline_IndependentLegsEachGetOwnBudget.
func TestPhaseDeadline_BoundsSequentialLegs(t *testing.T) {
	const budget = 60 * time.Millisecond

	ctx, cancel := phaseDeadline(context.Background(), budget)
	defer cancel()

	// Leg 1 (e.g. the Nuclei scan) runs until the phase budget is exhausted.
	leg1 := runUntilCtxDone(ctx)
	if !errors.Is(leg1, context.DeadlineExceeded) {
		t.Fatalf("leg 1 ended with %v, want DeadlineExceeded", leg1)
	}

	// Leg 2 (e.g. the secret-scan batch) shares the same ctx. A ctx-respecting
	// leg must return effectively instantly rather than starting fresh work.
	start := time.Now()
	leg2 := runUntilCtxDone(ctx)
	elapsed := time.Since(start)

	if leg2 == nil {
		t.Fatal("leg 2 ran without observing the shared phase deadline (the original bug)")
	}
	if elapsed > 25*time.Millisecond {
		t.Fatalf("leg 2 ran %v past the exhausted phase deadline; expected immediate return", elapsed)
	}
}

// TestTotalScanBudget_BoundsSequentialPhases encodes the --scanning-max-duration
// fix: RunNativeScan wraps the root ctx in one total budget, then runs phases
// sequentially, each deriving its own (larger) per-phase budget via phaseDeadline.
// The bug was that without a total budget the per-phase budgets stacked
// back-to-back (discovery + known-issue + ... could each get the full flag value),
// so the whole scan ran far past the value the operator passed. Here three phases
// each ask for far more than the total budget; the total elapsed must stay within
// the budget, and phases launched after it is exhausted must return immediately
// (modeling the phase-loop guard that skips the remaining phases).
func TestTotalScanBudget_BoundsSequentialPhases(t *testing.T) {
	const totalBudget = 80 * time.Millisecond
	const perPhaseBudget = 10 * time.Second // each phase "wants" much more than the total

	start := time.Now()

	// Root scan ctx bounded by the total budget (the new wrap in RunNativeScan).
	root, cancelRoot := context.WithTimeout(context.Background(), totalBudget)
	defer cancelRoot()

	var ran int
	for phase := 0; phase < 3; phase++ {
		// Phase-loop guard: stop launching phases once the budget has elapsed.
		if root.Err() != nil {
			break
		}
		ran++

		phaseCtx, cancel := phaseDeadline(root, perPhaseBudget)
		// A phase that honors ctx runs until the (total-clamped) deadline fires.
		_ = runUntilCtxDone(phaseCtx)
		cancel()
	}

	elapsed := time.Since(start)
	if elapsed > totalBudget+500*time.Millisecond {
		t.Fatalf("total scan ran %v, exceeding the ~%v total budget — phases stacked past the cap", elapsed, totalBudget)
	}
	if ran == 3 {
		t.Fatal("all 3 phases ran to their per-phase deadline; the total budget did not curtail later phases")
	}
}

// TestPhaseDeadline_IndependentLegsEachGetOwnBudget encodes the known-issue-scan
// design after the secret-scan-starvation fix: the Nuclei and secret-scan legs each
// derive their OWN budget from the parent ctx instead of sharing one, so a first
// leg that exhausts its entire budget does NOT starve the second leg — the second
// leg starts fresh and runs for its own budget. (Each leg is still capped by the
// parent/overall-scan deadline; that clamp is covered by
// TestPhaseDeadline_CapsToParentDeadline.)
func TestPhaseDeadline_IndependentLegsEachGetOwnBudget(t *testing.T) {
	const budget = 60 * time.Millisecond

	parent := context.Background()

	// Leg 1 (Nuclei) gets its own budget and runs until it is exhausted.
	leg1Ctx, cancel1 := phaseDeadline(parent, budget)
	defer cancel1()
	if leg1 := runUntilCtxDone(leg1Ctx); !errors.Is(leg1, context.DeadlineExceeded) {
		t.Fatalf("leg 1 ended with %v, want DeadlineExceeded", leg1)
	}

	// Leg 2 (secret scan) gets a FRESH budget from the same parent. It must NOT be
	// curtailed by leg 1's exhausted deadline — it should run for ~its own budget.
	leg2Ctx, cancel2 := phaseDeadline(parent, budget)
	defer cancel2()
	start := time.Now()
	leg2 := runUntilCtxDone(leg2Ctx)
	elapsed := time.Since(start)

	if !errors.Is(leg2, context.DeadlineExceeded) {
		t.Fatalf("leg 2 ended with %v, want DeadlineExceeded (it should run on its own budget)", leg2)
	}
	if elapsed < budget/2 {
		t.Fatalf("leg 2 returned after only %v; it was starved by leg 1 instead of getting its own budget", elapsed)
	}
}

// runUntilCtxDone models a phase leg that does work while honoring ctx: it
// returns ctx.Err() when the phase deadline fires, or nil if it would have
// finished its (here, long) work first.
func runUntilCtxDone(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(10 * time.Second):
		return nil
	}
}
