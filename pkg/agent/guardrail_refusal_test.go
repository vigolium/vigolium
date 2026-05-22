package agent

import (
	"errors"
	"strings"
	"testing"
)

// TestRefusalError verifies RefusalError wraps ErrPromptRefused (so callers can
// errors.Is it) while surfacing the verdict reason in the message.
func TestRefusalError(t *testing.T) {
	v := GuardrailVerdict{Allowed: false, Reason: "asks to read SSH keys"}
	err := RefusalError(v)

	if !errors.Is(err, ErrPromptRefused) {
		t.Error("RefusalError should wrap ErrPromptRefused")
	}
	if !strings.Contains(err.Error(), "asks to read SSH keys") {
		t.Errorf("error should include verdict reason, got %q", err.Error())
	}
}

func TestRefusalError_EmptyReason(t *testing.T) {
	err := RefusalError(GuardrailVerdict{Allowed: false})
	if !errors.Is(err, ErrPromptRefused) {
		t.Error("should still wrap ErrPromptRefused with empty reason")
	}
}
