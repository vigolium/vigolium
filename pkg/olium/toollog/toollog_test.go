package toollog

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/olium/engine"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// disableColor flips terminal.colorEnabled off for the duration of a test
// so assertions can match plain ASCII without ANSI noise.
func disableColor(t *testing.T) {
	t.Helper()
	prev := terminal.IsColorEnabled()
	terminal.SetColorEnabled(false)
	t.Cleanup(func() { terminal.SetColorEnabled(prev) })
}

func TestLoggerStartAndEndSuccess(t *testing.T) {
	disableColor(t)
	var buf bytes.Buffer
	l := New(&buf)

	l.Handle(engine.Event{
		Type:       engine.EventToolExecStart,
		ToolCallID: "call-1",
		ToolName:   "ls",
		ToolArgs:   map[string]any{"path": "/tmp"},
	})
	l.Handle(engine.Event{
		Type:       engine.EventToolExecEnd,
		ToolCallID: "call-1",
		ToolName:   "ls",
		ToolResult: strings.Repeat("x", 1694),
	})

	out := buf.String()
	if !strings.Contains(out, "▶ ls path=/tmp") {
		t.Errorf("expected start line with arrow + tool + args, got: %q", out)
	}
	if !strings.Contains(out, "✓ 1694 bytes") {
		t.Errorf("expected success line with byte count, got: %q", out)
	}
}

func TestLoggerErrorIncludesReason(t *testing.T) {
	disableColor(t)
	var buf bytes.Buffer
	l := New(&buf)

	l.Handle(engine.Event{
		Type:       engine.EventToolExecStart,
		ToolCallID: "call-2",
		ToolName:   "web_fetch",
		ToolArgs:   map[string]any{"url": "http://x"},
	})
	l.Handle(engine.Event{
		Type:       engine.EventToolExecEnd,
		ToolCallID: "call-2",
		ToolName:   "web_fetch",
		ToolIsErr:  true,
		ToolResult: "connection refused\nstack trace ...",
	})

	out := buf.String()
	if !strings.Contains(out, "✗ failed: connection refused") {
		t.Errorf("expected failure line with first error line, got: %q", out)
	}
	if strings.Contains(out, "stack trace") {
		t.Errorf("error summary should clip after first line, got: %q", out)
	}
}

func TestLoggerNilWriterIsNoop(t *testing.T) {
	l := New(nil)
	// Should not panic and should report not-handled.
	if l.Handle(engine.Event{Type: engine.EventToolExecStart, ToolCallID: "x"}) {
		t.Error("nil-writer logger should report unhandled")
	}
}

func TestFormatElapsed(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{0, "0ms"},
		{12 * time.Millisecond, "12ms"},
		{438 * time.Millisecond, "438ms"},
		{2500 * time.Millisecond, "2.5s"},
		{45 * time.Second, "45s"},
		{83 * time.Second, "1m23s"},
	}
	for _, c := range cases {
		if got := formatElapsed(c.in); got != c.want {
			t.Errorf("formatElapsed(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}
