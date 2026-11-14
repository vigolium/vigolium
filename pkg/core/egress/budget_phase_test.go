package egress

import (
	"errors"
	"testing"
)

// A phase's request share caps only that phase: discovery gets its share of
// the unspent --max-requests and the scan keeps the rest.
func TestBudgetLimitPhase(t *testing.T) {
	var globalHook int
	b := NewBudget(100, 0)
	b.SetHooks(BudgetHooks{Global: func(*BudgetError) { globalHook++ }})

	release := b.LimitPhase("discovery", 0.4)
	admitted := 0
	var lastErr error
	for i := 0; i < 100; i++ {
		if err := b.take(b.forHost("h")); err != nil {
			lastErr = err
			break
		}
		admitted++
	}
	if admitted != 40 {
		t.Fatalf("discovery admitted %d, want 40 (40%% of 100)", admitted)
	}
	var be *BudgetError
	if !errors.As(lastErr, &be) || be.Kind != BudgetPhase || be.Host != "discovery" {
		t.Fatalf("refusal = %v, want a phase BudgetError", lastErr)
	}
	if b.Exhausted() || globalHook != 0 {
		t.Fatal("a phase cap must not exhaust the scan-wide budget")
	}
	release()
	if err := b.take(b.forHost("h")); err != nil {
		t.Fatalf("after the phase ends the scan budget is usable again: %v", err)
	}

	// No scan-wide limit: no cap.
	var nb *Budget
	nb.LimitPhase("discovery", 0.4)()
	if NewBudget(0, 5).LimitPhase("discovery", 0.4) == nil {
		t.Fatal("release must never be nil")
	}
}
