package runner

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// captureStderr runs fn with os.Stderr redirected to a pipe and returns whatever
// was written. Restores the real stderr before returning.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	rPipe, wPipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = wPipe
	defer func() { os.Stderr = old }()

	fn()

	_ = wPipe.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, rPipe)
	return buf.String()
}

func liveFindingEvent() *output.ResultEvent {
	return &output.ResultEvent{
		ModuleID: "reflected-xss",
		Info:     output.Info{Severity: severity.High},
		URL:      "https://example.com/search?q=1",
		Matched:  "https://example.com/search?q=<script>",
	}
}

func TestFindingsVisibleOnStdout(t *testing.T) {
	// Console writer renders findings to stdout.
	r := &Runner{options: &types.Options{}, output: &output.StandardWriter{}}
	if !r.findingsVisibleOnStdout() {
		t.Errorf("console StandardWriter should report findings visible on stdout")
	}

	// Deferred/silent writer suppresses stdout (jsonl/html, or -silent).
	r = &Runner{options: &types.Options{}, output: &output.StandardWriter{DisableStdout: true}}
	if r.findingsVisibleOnStdout() {
		t.Errorf("stdout-disabled StandardWriter should report findings not visible")
	}

	// A writer that doesn't advertise the predicate defaults to "not visible"
	// so callers fall back to echoing.
	r = &Runner{options: &types.Options{}, output: nil}
	if r.findingsVisibleOnStdout() {
		t.Errorf("nil output should report findings not visible")
	}
}

func TestEchoLiveFindingEmitsWhenStdoutDeferred(t *testing.T) {
	// Deferred output (e.g. --format jsonl,html) → echo the finding to stderr.
	r := &Runner{options: &types.Options{}, output: &output.StandardWriter{DisableStdout: true}}
	out := captureStderr(t, func() {
		r.echoLiveFinding("dynamic-assessment", liveFindingEvent())
	})
	if !bytes.Contains([]byte(out), []byte("dynamic-assessment")) ||
		!bytes.Contains([]byte(out), []byte("reflected-xss")) {
		t.Errorf("expected a phase-tagged finding line on stderr, got %q", out)
	}
}

func TestEchoLiveFindingSuppressedWhenStdoutShowsFindings(t *testing.T) {
	// Console output already prints findings to stdout — don't double up on stderr.
	r := &Runner{options: &types.Options{}, output: &output.StandardWriter{}}
	out := captureStderr(t, func() {
		r.echoLiveFinding("dynamic-assessment", liveFindingEvent())
	})
	if out != "" {
		t.Errorf("expected no stderr echo in console mode, got %q", out)
	}
}

func TestEchoLiveFindingGuards(t *testing.T) {
	// Silent and nil-result are both no-ops even when stdout is deferred.
	r := &Runner{options: &types.Options{Silent: true}, output: &output.StandardWriter{DisableStdout: true}}
	if out := captureStderr(t, func() { r.echoLiveFinding("dynamic-assessment", liveFindingEvent()) }); out != "" {
		t.Errorf("silent run should not echo, got %q", out)
	}

	r = &Runner{options: &types.Options{}, output: &output.StandardWriter{DisableStdout: true}}
	if out := captureStderr(t, func() { r.echoLiveFinding("dynamic-assessment", nil) }); out != "" {
		t.Errorf("nil result should not echo, got %q", out)
	}

	// CapturedConsole (-P child) keeps findings in its own stdout log; no stderr echo.
	r = &Runner{options: &types.Options{CapturedConsole: true}, output: &output.StandardWriter{DisableStdout: true}}
	if out := captureStderr(t, func() { r.echoLiveFinding("dynamic-assessment", liveFindingEvent()) }); out != "" {
		t.Errorf("captured-console run should not echo, got %q", out)
	}
}
