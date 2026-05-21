package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/olium/provider"
	"github.com/vigolium/vigolium/pkg/olium/tool"
)

// fakeTool returns a fixed string and tracks whether it ran.
type fakeTool struct {
	name   string
	out    string
	isErr  bool
	called bool
}

func (f *fakeTool) Name() string             { return f.name }
func (f *fakeTool) Label() string            { return f.name }
func (f *fakeTool) Description() string      { return "fake" }
func (f *fakeTool) Schema() map[string]any   { return map[string]any{"type": "object"} }
func (f *fakeTool) Category() string         { return tool.CategoryBuiltin }
func (f *fakeTool) IsReadOnly() bool         { return true }
func (f *fakeTool) Execute(_ context.Context, _ map[string]any, _ tool.UpdateFn) (tool.Result, error) {
	f.called = true
	return tool.Result{Content: f.out, IsError: f.isErr}, nil
}

// drainEvents pulls everything off the channel so dispatchAndRecord's
// `out <-` sends don't block. Started in a goroutine before calling
// dispatchAndRecord.
func drainEvents(t *testing.T, ch <-chan Event) []Event {
	t.Helper()
	var got []Event
	for ev := range ch {
		got = append(got, ev)
	}
	return got
}

func TestOnToolResultHookModifiesHistoryButNotEvent(t *testing.T) {
	// The hook's contract: history sees the modified content (so the LLM
	// gets the pin on its next turn) but the event stream still emits
	// the raw tool output (so operator logs stay clean). This test
	// dispatches one tool call and asserts both sides separately.
	reg := tool.NewRegistry()
	reg.Register(&fakeTool{name: "noisy", out: "RAW_RESULT"})

	var seen []string
	e := &Engine{
		cfg: Config{
			Tools: reg,
			OnToolResult: func(toolName string, content string, isErr bool) string {
				seen = append(seen, toolName)
				return content + "\n[pinned: plan-state]"
			},
		},
		maxToolResultLen: 1024,
		toolTimeout:      0, // disable per-tool timeout for the test
	}

	ch := make(chan Event, 8)
	go func() {
		e.dispatchAndRecord(context.Background(), provider.ToolCall{ID: "c1", Name: "noisy"}, ch)
		close(ch)
	}()

	events := drainEvents(t, ch)

	if len(seen) != 1 || seen[0] != "noisy" {
		t.Fatalf("hook called %d times for %v, want 1 call for noisy", len(seen), seen)
	}

	// History should have the modified content.
	hist := e.History()
	if len(hist) != 1 {
		t.Fatalf("expected 1 history entry, got %d", len(hist))
	}
	if !strings.Contains(hist[0].Content, "RAW_RESULT") {
		t.Errorf("history missing raw tool output:\n%s", hist[0].Content)
	}
	if !strings.Contains(hist[0].Content, "[pinned: plan-state]") {
		t.Errorf("history missing hook-appended content (the whole point):\n%s", hist[0].Content)
	}

	// Event stream should NOT carry the pin — operator log stays clean.
	var execEnd *Event
	for i := range events {
		if events[i].Type == EventToolExecEnd {
			execEnd = &events[i]
			break
		}
	}
	if execEnd == nil {
		t.Fatal("no EventToolExecEnd in event stream")
	}
	if !strings.Contains(execEnd.ToolResult, "RAW_RESULT") {
		t.Errorf("event missing raw output: %q", execEnd.ToolResult)
	}
	if strings.Contains(execEnd.ToolResult, "[pinned:") {
		t.Errorf("event should NOT carry pin (operator log noise): %q", execEnd.ToolResult)
	}
}

func TestOnToolResultHookNilIsPassThrough(t *testing.T) {
	// No hook configured — engine must not panic and content goes
	// straight into history unchanged. Required so swarm/query callers
	// (which don't set the hook) keep working.
	reg := tool.NewRegistry()
	reg.Register(&fakeTool{name: "plain", out: "DATA"})

	e := &Engine{
		cfg:              Config{Tools: reg},
		maxToolResultLen: 1024,
	}

	ch := make(chan Event, 8)
	go func() {
		e.dispatchAndRecord(context.Background(), provider.ToolCall{ID: "c2", Name: "plain"}, ch)
		close(ch)
	}()
	drainEvents(t, ch)

	hist := e.History()
	if len(hist) != 1 || hist[0].Content != "DATA" {
		t.Errorf("nil hook should pass through unchanged, got %q", hist[0].Content)
	}
}

func TestOnToolResultRunsAfterShrink(t *testing.T) {
	// Hook fires after shrink/spill, so the pin lives outside the
	// content the engine clamped or pushed to disk. This guards against
	// a future refactor that runs the hook on the full pre-shrink
	// content and then truncates the pin off the end.
	reg := tool.NewRegistry()
	big := strings.Repeat("X", 5000)
	reg.Register(&fakeTool{name: "fat", out: big})

	var sawContentLen int
	e := &Engine{
		cfg: Config{
			Tools: reg,
			OnToolResult: func(_ string, content string, _ bool) string {
				sawContentLen = len(content)
				return content + "|PIN|"
			},
		},
		maxToolResultLen: 1000,
	}

	ch := make(chan Event, 8)
	go func() {
		e.dispatchAndRecord(context.Background(), provider.ToolCall{ID: "c3", Name: "fat"}, ch)
		close(ch)
	}()
	drainEvents(t, ch)

	if sawContentLen > 1200 {
		t.Errorf("hook saw pre-shrink content (%d bytes); expected post-shrink near 1000", sawContentLen)
	}
	hist := e.History()
	if len(hist) != 1 || !strings.HasSuffix(hist[0].Content, "|PIN|") {
		t.Errorf("pin should land at the very end of history content, got tail %q",
			hist[0].Content[max(0, len(hist[0].Content)-32):])
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
