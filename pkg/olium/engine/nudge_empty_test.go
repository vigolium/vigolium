package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/olium/provider"
	"github.com/vigolium/vigolium/pkg/olium/tool"
)

// TestEngine_NudgesOnEmptyToolCallsThenExits checks the new tolerance for
// text-only turns: with NudgeOnEmptyToolCalls=2, the engine should re-stream
// twice (each time after injecting the nudge as a user message) before
// finally accepting that the model is done. Drives an httptest openai-
// compatible endpoint so the streaming + history-append paths are exercised
// end to end, not unit-stubbed.
func TestEngine_NudgesOnEmptyToolCallsThenExits(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		completeSSEResponse(w, fmt.Sprintf("text-only turn %d", attempts.Load()))
	}))
	defer srv.Close()

	prov := provider.NewOpenAICompatible(srv.URL+"/v1", "", nil, nil)
	eng := New(Config{
		Provider:              prov,
		Tools:                 tool.NewRegistry(),
		Model:                 "test-model",
		MaxTurns:              10,
		NudgeOnEmptyToolCalls: 2,
		NudgeOnEmptyMessage:   "NUDGE-TEXT",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	got := drainEngine(t, eng.Run(ctx, "go"), 5*time.Second)

	// First turn empty -> nudge#1, second turn empty -> nudge#2, third turn
	// empty -> exhausted, exit. 3 total provider calls.
	if n := attempts.Load(); n != 3 {
		t.Errorf("expected 3 provider calls (1 initial + 2 nudges), got %d", n)
	}
	if got.turnsDone != 3 {
		t.Errorf("expected 3 EventTurnDone, got %d", got.turnsDone)
	}
	if !got.runDone {
		t.Error("expected EventRunDone after nudge budget exhausted")
	}
	if got.errMsg != "" {
		t.Errorf("expected clean exit, got engine error: %s", got.errMsg)
	}
	if len(got.info) != 2 {
		t.Errorf("expected 2 EventInfo nudge notices, got %d (%v)", len(got.info), got.info)
	}

	// Conversation history must show: user(prompt) → assistant(text1) →
	// user(NUDGE-TEXT) → assistant(text2) → user(NUDGE-TEXT) → assistant(text3).
	// The user-role nudge entries are the proof the loop didn't just
	// re-stream blindly — it actually inserted the reminder.
	hist := eng.History()
	if len(hist) != 6 {
		t.Fatalf("expected 6 history entries, got %d: %#v", len(hist), hist)
	}
	for _, idx := range []int{2, 4} {
		if hist[idx].Role != provider.RoleUser || !strings.Contains(hist[idx].Text, "NUDGE-TEXT") {
			t.Errorf("history[%d] should be a user nudge, got role=%s text=%q",
				idx, hist[idx].Role, hist[idx].Text)
		}
	}
}

// TestEngine_NudgeResetsAfterProductiveTurn pins the consecutive-streak
// semantics: a tool-calling turn between two empty turns resets the
// counter, so a long run with intermittent quiet patches doesn't
// accumulate into a forced exit. Without this, a model that occasionally
// pauses for thought (very common with reasoning models) would burn its
// budget across an entire session and exit mid-investigation.
func TestEngine_NudgeResetsAfterProductiveTurn(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		// Sequence: empty, empty, TOOL-CALL, empty, empty, empty (exit).
		// Reset after attempt 3 means attempts 4 & 5 are nudges 1 & 2,
		// attempt 6 exhausts and exits cleanly.
		switch n {
		case 3:
			toolCallSSEResponse(w, "ping")
		default:
			completeSSEResponse(w, fmt.Sprintf("quiet %d", n))
		}
	}))
	defer srv.Close()

	reg := tool.NewRegistry()
	reg.Register(&fakeTool{name: "ping", out: "pong"})

	prov := provider.NewOpenAICompatible(srv.URL+"/v1", "", nil, nil)
	eng := New(Config{
		Provider:              prov,
		Tools:                 reg,
		Model:                 "test-model",
		MaxTurns:              10,
		NudgeOnEmptyToolCalls: 2,
		NudgeOnEmptyMessage:   "NUDGE",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	got := drainEngine(t, eng.Run(ctx, "go"), 5*time.Second)

	// 6 provider calls: 1+2 empty (2 nudges used), 3 produces a tool call
	// (resets), 4+5 empty (2 fresh nudges), 6 empty (exhausted, exit).
	if n := attempts.Load(); n != 6 {
		t.Errorf("expected 6 provider calls, got %d", n)
	}
	if !got.runDone {
		t.Error("expected clean EventRunDone after second nudge budget exhaustion")
	}
	if got.errMsg != "" {
		t.Errorf("expected clean exit, got engine error: %s", got.errMsg)
	}
	if got.toolStarts != 1 {
		t.Errorf("expected exactly 1 tool-call-start (turn 3), got %d", got.toolStarts)
	}
	if len(got.info) != 4 {
		t.Errorf("expected 4 nudge notices (2 streaks of 2), got %d (%v)", len(got.info), got.info)
	}
}

// TestEngine_NudgeDisabledByDefault guards backward compatibility: callers
// that don't opt in (query mode, swarm sub-calls) must still exit on the
// first empty turn so a single-shot doesn't burn extra rounds. The legacy
// "no tool calls = done" contract is preserved for NudgeOnEmptyToolCalls=0.
func TestEngine_NudgeDisabledByDefault(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		completeSSEResponse(w, "done")
	}))
	defer srv.Close()

	prov := provider.NewOpenAICompatible(srv.URL+"/v1", "", nil, nil)
	eng := New(Config{
		Provider: prov,
		Tools:    tool.NewRegistry(),
		Model:    "test-model",
		MaxTurns: 10,
		// NudgeOnEmptyToolCalls: 0 (default)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	got := drainEngine(t, eng.Run(ctx, "go"), 5*time.Second)

	if n := attempts.Load(); n != 1 {
		t.Errorf("expected exactly 1 provider call (legacy single-shot exit), got %d", n)
	}
	if !got.runDone {
		t.Error("expected EventRunDone on first empty turn when nudge disabled")
	}
	if len(got.info) != 0 {
		t.Errorf("expected zero nudge notices when disabled, got %d (%v)", len(got.info), got.info)
	}
}

// toolCallSSEResponse writes a single SSE chunk containing a complete
// tool_call (name + finish_reason), so the provider emits ToolCallStart +
// ToolCallEnd and the engine treats the turn as productive. Kept here
// (not in stream_retry_e2e_test.go) so the helper lives next to its
// only consumer.
func toolCallSSEResponse(w http.ResponseWriter, toolName string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, "data: %s\n\n",
		fmt.Sprintf(`{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_%s","type":"function","function":{"name":%q,"arguments":"{}"}}]},"finish_reason":"tool_calls"}]}`,
			toolName, toolName))
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
}
