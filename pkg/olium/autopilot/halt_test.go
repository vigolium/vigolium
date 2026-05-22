package autopilot

import (
	"strings"
	"testing"
)

func TestHaltSignalIdempotent(t *testing.T) {
	h := &HaltSignal{}
	if halted, _ := h.Halted(); halted {
		t.Fatal("fresh signal must report not halted")
	}
	if h.Source() != HaltSourceUnset {
		t.Errorf("fresh signal source should be Unset, got %v", h.Source())
	}

	h.SetByModel("first")
	halted, reason := h.Halted()
	if !halted || reason != "first" {
		t.Fatalf("after SetByModel: halted=%v reason=%q", halted, reason)
	}
	if h.Source() != HaltSourceModel {
		t.Errorf("source=%v, want Model", h.Source())
	}

	// Subsequent calls must be ignored (idempotent until Reset).
	h.SetByBudget("second")
	if _, reason := h.Halted(); reason != "first" {
		t.Errorf("second SetByBudget overwrote reason: got %q, want %q", reason, "first")
	}
	if h.Source() != HaltSourceModel {
		t.Errorf("source mutated by ignored call: got %v, want Model", h.Source())
	}
}

func TestHaltSignalReset(t *testing.T) {
	h := &HaltSignal{}
	h.SetByModel("done")

	h.Reset()
	if halted, reason := h.Halted(); halted || reason != "" {
		t.Errorf("after Reset: halted=%v reason=%q (want false, '')", halted, reason)
	}
	if h.Source() != HaltSourceUnset {
		t.Errorf("after Reset source=%v, want Unset", h.Source())
	}

	// Reset clears the latch — a new Set must take effect.
	h.SetByBudget("budget tripped")
	halted, reason := h.Halted()
	if !halted || reason != "budget tripped" {
		t.Errorf("after Reset+SetByBudget: halted=%v reason=%q", halted, reason)
	}
	if h.Source() != HaltSourceBudget {
		t.Errorf("source=%v, want Budget", h.Source())
	}
}

func TestFormatCoverageGapPrompt(t *testing.T) {
	if got := formatCoverageGapPrompt(nil); got != "" {
		t.Errorf("nil gap should yield empty string, got %q", got)
	}

	gap := []string{"GET /a", "POST /b"}
	got := formatCoverageGapPrompt(gap)
	for _, sig := range gap {
		if !strings.Contains(got, sig) {
			t.Errorf("expected %q in prompt, got: %s", sig, got)
		}
	}
	if !strings.Contains(got, "halt_scan") {
		t.Errorf("re-entry prompt should mention halt_scan, got: %s", got)
	}

	// Above-cap input should truncate and surface total count.
	long := make([]string, 35)
	for i := range long {
		long[i] = "GET /route" + string(rune('a'+i%26))
	}
	got = formatCoverageGapPrompt(long)
	if !strings.Contains(got, "35") || !strings.Contains(got, "showing first 30") {
		t.Errorf("expected truncation notice for 35-item input, got: %s", got)
	}
}
