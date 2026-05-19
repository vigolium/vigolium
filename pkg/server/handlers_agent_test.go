package server

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestIsTerminalAgentStatus(t *testing.T) {
	cases := map[string]bool{
		"completed": true,
		"failed":    true,
		"cancelled": true,
		"timeout":   true,
		"error":     true,
		"running":   false,
		"queued":    false,
		"":          false,
	}
	for status, want := range cases {
		if got := isTerminalAgentStatus(status); got != want {
			t.Errorf("isTerminalAgentStatus(%q) = %v, want %v", status, got, want)
		}
	}
}

func TestTailSessionLog_ExistingContent(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "runtime.log")
	payload := "phase one\nphase two\n"
	if err := os.WriteFile(logPath, []byte(payload), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}

	var buf bytes.Buffer
	w := bufio.NewWriter(&buf)
	tailSessionLog(w, logPath, func() bool { return true }, 10*time.Millisecond, time.Second, false)
	_ = w.Flush()

	out := buf.String()
	if !strings.Contains(out, "phase one") || !strings.Contains(out, "phase two") {
		t.Errorf("expected log payload in SSE output, got: %q", out)
	}
	if !strings.Contains(out, `"type":"chunk"`) {
		t.Errorf("expected chunk event, got: %q", out)
	}
	if !strings.Contains(out, `"type":"done"`) {
		t.Errorf("expected done event, got: %q", out)
	}
}

func TestTailSessionLog_MissingFile(t *testing.T) {
	var buf bytes.Buffer
	w := bufio.NewWriter(&buf)
	tailSessionLog(w, filepath.Join(t.TempDir(), "nope.log"), func() bool { return true }, 10*time.Millisecond, time.Second, false)
	_ = w.Flush()

	out := buf.String()
	if !strings.Contains(out, `"type":"error"`) {
		t.Errorf("expected error event for missing file, got: %q", out)
	}
}

func TestTailSessionLog_PollsUntilDone(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "runtime.log")
	if err := os.WriteFile(logPath, []byte("first\n"), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}

	// isDone flips true after a short delay, simulating a run that
	// finishes while the client is tailing.
	var done atomic.Bool
	go func() {
		time.Sleep(30 * time.Millisecond)
		f, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return
		}
		_, _ = f.WriteString("second\n")
		_ = f.Close()
		time.Sleep(20 * time.Millisecond)
		done.Store(true)
	}()

	var buf bytes.Buffer
	w := bufio.NewWriter(&buf)
	tailSessionLog(w, logPath, func() bool { return done.Load() }, 10*time.Millisecond, 2*time.Second, false)
	_ = w.Flush()

	out := buf.String()
	if !strings.Contains(out, "first") {
		t.Errorf("expected 'first' chunk in output, got: %q", out)
	}
	if !strings.Contains(out, "second") {
		t.Errorf("expected 'second' chunk (appended during poll) in output, got: %q", out)
	}
	if !strings.Contains(out, `"type":"done"`) {
		t.Errorf("expected done event after isDone flipped, got: %q", out)
	}
}

func TestTailSessionLog_SafetyTimeout(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "runtime.log")
	if err := os.WriteFile(logPath, []byte("only line\n"), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}

	var buf bytes.Buffer
	w := bufio.NewWriter(&buf)
	start := time.Now()
	tailSessionLog(w, logPath, func() bool { return false }, 10*time.Millisecond, 50*time.Millisecond, false)
	_ = w.Flush()

	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("safety timeout did not fire, elapsed=%v", elapsed)
	}
	if !strings.Contains(buf.String(), `"type":"done"`) {
		t.Errorf("expected done event after safety timeout, got: %q", buf.String())
	}
}

func TestTailSessionLog_StripANSI(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "runtime.log")
	// Red "hello" wrapped in SGR escapes plus a plain tail.
	payload := "\x1b[31mhello\x1b[0m world\n"
	if err := os.WriteFile(logPath, []byte(payload), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}

	var buf bytes.Buffer
	w := bufio.NewWriter(&buf)
	tailSessionLog(w, logPath, func() bool { return true }, 10*time.Millisecond, time.Second, true)
	_ = w.Flush()

	out := buf.String()
	// JSON encodes \x1b as \u001b; neither the raw nor encoded form should appear.
	if strings.Contains(out, "\\u001b") || strings.Contains(out, "\x1b[") {
		t.Errorf("expected ANSI codes stripped, got: %q", out)
	}
	if !strings.Contains(out, "hello world") {
		t.Errorf("expected payload text after strip, got: %q", out)
	}
}

func TestSnapshotAgentRawOutput(t *testing.T) {
	t.Run("missing dir returns empty", func(t *testing.T) {
		if got := snapshotAgentRawOutput(nil, ""); got != "" {
			t.Errorf("expected empty for blank dir, got %q", got)
		}
	})

	t.Run("missing log file returns empty", func(t *testing.T) {
		if got := snapshotAgentRawOutput(nil, t.TempDir()); got != "" {
			t.Errorf("expected empty for missing log, got %q", got)
		}
	})

	t.Run("strips ANSI from runtime.log", func(t *testing.T) {
		dir := t.TempDir()
		logPath := filepath.Join(dir, "runtime.log")
		payload := "\x1b[31mfailed\x1b[0m: boom\n"
		if err := os.WriteFile(logPath, []byte(payload), 0o644); err != nil {
			t.Fatalf("write log: %v", err)
		}
		got := snapshotAgentRawOutput(nil, dir)
		if got != "failed: boom\n" {
			t.Errorf("expected ANSI stripped, got %q", got)
		}
	})

	t.Run("head-truncates oversized logs", func(t *testing.T) {
		dir := t.TempDir()
		logPath := filepath.Join(dir, "runtime.log")
		// Build a payload > the 200 KiB cap with a unique tail marker.
		head := strings.Repeat("a", maxAgentRawOutputBytes+1024)
		tail := "TAIL_MARKER\n"
		if err := os.WriteFile(logPath, []byte(head+tail), 0o644); err != nil {
			t.Fatalf("write log: %v", err)
		}
		got := snapshotAgentRawOutput(nil, dir)
		if !strings.HasPrefix(got, "...[truncated head]...") {
			t.Errorf("expected head-truncation marker, got prefix %q", got[:min(40, len(got))])
		}
		if !strings.HasSuffix(got, tail) {
			t.Errorf("expected tail preserved, got suffix %q", got[max(0, len(got)-len(tail)-10):])
		}
		// Truncation marker plus the cap is the hard upper bound.
		if len(got) > maxAgentRawOutputBytes+len("...[truncated head]...\n") {
			t.Errorf("snapshot overshot the cap: %d bytes", len(got))
		}
	})
}

func TestStripANSI(t *testing.T) {
	cases := map[string]string{
		"\x1b[31mred\x1b[0m":               "red",
		"plain text":                       "plain text",
		"\x1b[1;32mbold green\x1b[0m tail": "bold green tail",
		"mix \x1b[33myellow\x1b[0m and \x1b[34mblue\x1b[0m end": "mix yellow and blue end",
	}
	for in, want := range cases {
		if got := stripANSI(in); got != want {
			t.Errorf("stripANSI(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseBoolParam(t *testing.T) {
	truthy := []string{"1", "true", "TRUE", "yes", "y", "on"}
	falsy := []string{"", "0", "false", "no", "nope", "maybe"}
	for _, v := range truthy {
		if !parseBoolParam(v) {
			t.Errorf("parseBoolParam(%q) = false, want true", v)
		}
	}
	for _, v := range falsy {
		if parseBoolParam(v) {
			t.Errorf("parseBoolParam(%q) = true, want false", v)
		}
	}
}
