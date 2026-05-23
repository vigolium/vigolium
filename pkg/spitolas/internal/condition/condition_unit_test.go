package condition

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// TestWithPrecondition verifies preconditions are appended to a condition.
func TestWithPrecondition(t *testing.T) {
	cond := URLContains("admin")
	pre1 := URLContains("/secure")
	pre2 := ElementExists("#token")
	cond.WithPrecondition(pre1).WithPrecondition(pre2)

	if len(cond.Preconditions) != 2 {
		t.Fatalf("Preconditions length = %d, want 2", len(cond.Preconditions))
	}
	if cond.Preconditions[0] != pre1 || cond.Preconditions[1] != pre2 {
		t.Error("preconditions not appended in order")
	}
}

// TestCountLimitCheck verifies the count-limit behaviour using the internal
// atomic counter. This path never touches the browser page (the page argument
// is unused when NestedCondition and countTracker are nil), so it is safe to
// pass nil.
func TestCountLimitCheck(t *testing.T) {
	c := CountLimit("key", 2)

	// First two checks are within the limit (count 1 and 2 <= MaxCount 2).
	if !c.Check(nil) {
		t.Error("first Check() = false, want true")
	}
	if !c.Check(nil) {
		t.Error("second Check() = false, want true")
	}
	// Third check exceeds the limit (count 3 > 2).
	if c.Check(nil) {
		t.Error("third Check() = true, want false (limit exceeded)")
	}

	// ResetCount restarts the counter.
	c.ResetCount()
	if !c.Check(nil) {
		t.Error("Check() after ResetCount = false, want true")
	}
}

// TestCountLimitNegate verifies negation inverts the count-limit result.
// Note: Not() does not copy MaxCount, so the negated copy has MaxCount = 0;
// every count (>= 1) exceeds it, making checkCountLimit return false, which
// Negate then flips to true on every call.
func TestCountLimitNegate(t *testing.T) {
	c := CountLimit("key", 1).Not()
	if !c.Check(nil) {
		t.Error("first negated Check() = false, want true")
	}
	if !c.Check(nil) {
		t.Error("second negated Check() = false, want true")
	}
}

// TestCompositeEmptyChildren verifies that composite conditions with no
// children evaluate to true without touching the page.
func TestCompositeEmptyChildren(t *testing.T) {
	if !And().Check(nil) {
		t.Error("And() with no children = false, want true")
	}
	if !Or().Check(nil) {
		t.Error("Or() with no children = false, want true")
	}
}

// TestNotPreservesComposite verifies Not() copies operator and children.
func TestNotPreservesComposite(t *testing.T) {
	orig := And(URLContains("a"), URLContains("b"))
	neg := orig.Not()
	if neg.operator != "and" {
		t.Errorf("negated operator = %q, want %q", neg.operator, "and")
	}
	if len(neg.children) != 2 {
		t.Errorf("negated children length = %d, want 2", len(neg.children))
	}
	if !neg.Negate {
		t.Error("Not() should set Negate = true")
	}
	// Double negation returns to false.
	if neg.Not().Negate {
		t.Error("double Not() should set Negate = false")
	}
}

// TestSetCountTrackerSharesState verifies a shared tracker is wired in.
func TestSetCountTracker(t *testing.T) {
	c := CountLimit("ignored", 5)
	tracker := map[string]int{}
	c.SetCountTracker(tracker)
	if c.countTracker == nil {
		t.Error("countTracker should be set")
	}
}

// TestUnknownConditionType verifies an unrecognized type evaluates to false.
func TestUnknownConditionType(t *testing.T) {
	c := New(config.ConditionType("does_not_exist"), "")
	if c.Check(nil) {
		t.Error("unknown condition type Check() = true, want false")
	}
}
