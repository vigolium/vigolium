package agent

import (
	"strings"
	"testing"
)

func TestAddWarning_AppendsAndMarksDegraded(t *testing.T) {
	r := &SwarmRunner{}
	result := &SwarmResult{}

	r.addWarning(result, "first %s warning", "test")
	r.addWarning(result, "second")

	if !result.Degraded {
		t.Error("addWarning should set result.Degraded=true")
	}
	if len(result.Warnings) != 2 {
		t.Fatalf("expected 2 warnings, got %d", len(result.Warnings))
	}
	if result.Warnings[0] != "first test warning" {
		t.Errorf("warning[0]: want format-expanded, got %q", result.Warnings[0])
	}
	if !strings.Contains(result.Warnings[1], "second") {
		t.Errorf("warning[1]: want contains 'second', got %q", result.Warnings[1])
	}
}

func TestAddWarning_NilResultSafe(t *testing.T) {
	r := &SwarmRunner{}
	// Must not panic.
	r.addWarning(nil, "anything")
}
