package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestRunBlackboxFallback_NoTargetIsFatal verifies the guard that keeps a
// preflight failure terminal when there's nothing to scan. Source-only
// runs have no live target, so the AI provider failure must surface as an
// error (wrapping the original preflight cause) rather than silently
// degrading. This branch returns before touching the engine, repo, or the
// native scanner, so a zero-value runner is sufficient and the test stays
// fully offline.
func TestRunBlackboxFallback_NoTargetIsFatal(t *testing.T) {
	r := &AutopilotPipelineRunner{}
	preflight := errors.New("olium: openai-compatible: context deadline exceeded")

	result, err := r.runBlackboxFallback(
		context.Background(),
		AutopilotPipelineConfig{TargetURL: ""},
		time.Now(),
		preflight,
	)
	if err == nil {
		t.Fatalf("expected an error when no target is available, got nil (result=%+v)", result)
	}
	if !errors.Is(err, preflight) {
		t.Errorf("expected the original preflight error to be wrapped, got %v", err)
	}
	if msg := strings.ToLower(err.Error()); !strings.Contains(msg, "preflight") {
		t.Errorf("expected the error to mention preflight, got %q", err.Error())
	}
}
