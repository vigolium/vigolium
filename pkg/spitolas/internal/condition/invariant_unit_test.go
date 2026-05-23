package condition

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// TestNewInvariant verifies basic invariant construction.
func TestNewInvariant(t *testing.T) {
	cond := URLContains("admin")
	inv := NewInvariant("must be admin", cond)
	if inv.Description != "must be admin" {
		t.Errorf("Description = %q, want %q", inv.Description, "must be admin")
	}
	if inv.Condition != cond {
		t.Error("Condition pointer mismatch")
	}
	if inv.Preconditions == nil {
		t.Error("Preconditions should be non-nil")
	}
	if len(inv.Preconditions) != 0 {
		t.Errorf("Preconditions length = %d, want 0", len(inv.Preconditions))
	}
}

// TestInvariantWithPrecondition verifies precondition chaining.
func TestInvariantWithPrecondition(t *testing.T) {
	pre := URLContains("/secure")
	inv := NewInvariant("desc", JavaScript("true")).WithPrecondition(pre)
	if len(inv.Preconditions) != 1 {
		t.Fatalf("Preconditions length = %d, want 1", len(inv.Preconditions))
	}
	if inv.Preconditions[0] != pre {
		t.Error("precondition pointer mismatch")
	}
}

// TestInvariantFactories verifies the predefined invariant factories build
// well-formed structures without touching a browser.
func TestInvariantFactories(t *testing.T) {
	tests := []struct {
		name string
		inv  *Invariant
	}{
		{"NoErrorPage", NoErrorPage()},
		{"NoServerError", NoServerError()},
		{"NoEmptyPage", NoEmptyPage()},
		{"HasElement", HasElement("#main", "needs main")},
		{"URLContainsInvariant", URLContainsInvariant("/app", "in app")},
		{"URLNotContainsInvariant", URLNotContainsInvariant("/logout", "not logout")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.inv == nil {
				t.Fatal("invariant is nil")
			}
			if tt.inv.Description == "" {
				t.Error("invariant has empty description")
			}
			if tt.inv.Condition == nil {
				t.Error("invariant has nil condition")
			}
		})
	}
}

// TestNoErrorPageStructure verifies the NoErrorPage precondition wiring.
func TestNoErrorPageStructure(t *testing.T) {
	inv := NoErrorPage()
	// Condition is ElementExists("body").Not() with an Or precondition.
	if inv.Condition.Type != config.CondElementExists {
		t.Errorf("Condition.Type = %v, want %v", inv.Condition.Type, config.CondElementExists)
	}
	if !inv.Condition.Negate {
		t.Error("Condition should be negated")
	}
	if len(inv.Condition.Preconditions) != 1 {
		t.Fatalf("Condition.Preconditions length = %d, want 1", len(inv.Condition.Preconditions))
	}
}

// TestURLNotContainsInvariantNegate verifies negation is applied.
func TestURLNotContainsInvariantNegate(t *testing.T) {
	inv := URLNotContainsInvariant("/logout", "no logout")
	if !inv.Condition.Negate {
		t.Error("URLNotContainsInvariant condition should be negated")
	}
	if inv.Condition.Type != config.CondURLContains {
		t.Errorf("Condition.Type = %v, want %v", inv.Condition.Type, config.CondURLContains)
	}
	if inv.Condition.Value != "/logout" {
		t.Errorf("Condition.Value = %q, want %q", inv.Condition.Value, "/logout")
	}
}

// TestInvariantCheckerManagement verifies Add/AddCondition/Count/Get/GetAll
// without evaluating any page-dependent logic.
func TestInvariantCheckerManagement(t *testing.T) {
	ic := NewInvariantChecker()
	if ic.Count() != 0 {
		t.Errorf("Count() = %d, want 0", ic.Count())
	}

	inv1 := NewInvariant("a", URLContains("a"))
	ic.Add(inv1)
	ic.AddCondition("b", URLContains("b"))

	if ic.Count() != 2 {
		t.Errorf("Count() = %d, want 2", ic.Count())
	}

	if ic.Get(0) != inv1 {
		t.Error("Get(0) did not return the added invariant")
	}
	if got := ic.Get(1); got == nil || got.Description != "b" {
		t.Errorf("Get(1) = %v, want invariant with description b", got)
	}

	// Out-of-range indices return nil.
	if ic.Get(-1) != nil {
		t.Error("Get(-1) should be nil")
	}
	if ic.Get(99) != nil {
		t.Error("Get(99) should be nil")
	}

	all := ic.GetAll()
	if len(all) != 2 {
		t.Fatalf("GetAll length = %d, want 2", len(all))
	}
	// GetAll returns a copy: mutating it must not affect the checker.
	all[0] = nil
	if ic.Get(0) == nil {
		t.Error("mutating GetAll result affected the checker's internal slice")
	}
}
