package cli

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func event(sev severity.Severity) *output.ResultEvent {
	return &output.ResultEvent{Info: output.Info{Severity: sev}}
}

func TestResetFailOnGateValidation(t *testing.T) {
	t.Cleanup(func() { scanFailOn = ""; failOnGateTriggered = false })

	scanFailOn = "HIGH " // mixed case + space, should normalize
	if err := resetFailOnGate(); err != nil {
		t.Fatalf("valid threshold rejected: %v", err)
	}
	if scanFailOn != "high" {
		t.Fatalf("threshold not normalized: %q", scanFailOn)
	}
	if failOnGateTriggered {
		t.Fatalf("reset should clear the triggered flag")
	}

	scanFailOn = "bogus"
	if err := resetFailOnGate(); err == nil {
		t.Fatalf("invalid threshold accepted")
	}

	scanFailOn = ""
	if err := resetFailOnGate(); err != nil {
		t.Fatalf("empty threshold should be a no-op: %v", err)
	}
}

func TestFailOnGateFromEvents(t *testing.T) {
	t.Cleanup(func() { scanFailOn = ""; failOnGateTriggered = false })

	events := []*output.ResultEvent{event(severity.Low), event(severity.High), event(severity.Info)}

	// Threshold high → trips (one High present).
	scanFailOn, failOnGateTriggered = "high", false
	failOnGateFromEvents(events, true)
	if !failOnGateTriggered {
		t.Fatalf("expected gate to trip on High at threshold high")
	}
	if err := failOnGateError(); err == nil {
		t.Fatalf("expected gate error when triggered")
	}

	// Threshold critical → does not trip (no Critical present).
	scanFailOn, failOnGateTriggered = "critical", false
	failOnGateFromEvents(events, true)
	if failOnGateTriggered {
		t.Fatalf("gate should not trip below threshold")
	}
	if err := failOnGateError(); err != nil {
		t.Fatalf("no gate error expected when not triggered: %v", err)
	}

	// Empty threshold → never trips.
	scanFailOn, failOnGateTriggered = "", false
	failOnGateFromEvents(events, true)
	if failOnGateTriggered {
		t.Fatalf("empty threshold must not trip the gate")
	}
}

func TestWithFailOnGate(t *testing.T) {
	t.Cleanup(func() { scanFailOn = ""; failOnGateTriggered = false })

	// A prior error always wins (scan failure outranks the gate).
	failOnGateTriggered = true
	scanFailOn = "high"
	prior := errExample
	if got := withFailOnGate(prior); got != prior {
		t.Fatalf("prior error should pass through unchanged")
	}

	// No prior error but gate tripped → gate error surfaces.
	if got := withFailOnGate(nil); got == nil {
		t.Fatalf("expected gate error to surface when no prior error")
	}

	// Gate not tripped → nil.
	failOnGateTriggered = false
	if got := withFailOnGate(nil); got != nil {
		t.Fatalf("expected nil when gate not tripped: %v", got)
	}
}

var errExample = &simpleErr{"boom"}

type simpleErr struct{ s string }

func (e *simpleErr) Error() string { return e.s }
