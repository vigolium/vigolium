package scanevents

import (
	"fmt"
	"testing"
)

func TestAppendSkippedControlsDedupsAndBounds(t *testing.T) {
	a := SkippedControl{Label: "Delete", Reason: "deny_click"}
	b := SkippedControl{Label: "Sign out", Reason: "logout"}
	got := AppendSkippedControls(nil, a, b, a)
	if len(got) != 2 || got[0] != a || got[1] != b {
		t.Fatalf("got %v, want [a b]", got)
	}
	for i := 0; i < MaxSkippedControlSample+5; i++ {
		got = AppendSkippedControls(got, SkippedControl{Label: fmt.Sprintf("Delete %d", i), Reason: "deny_click"})
	}
	if len(got) != MaxSkippedControlSample {
		t.Fatalf("sample = %d, want %d", len(got), MaxSkippedControlSample)
	}
}
