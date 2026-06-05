package engine

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/olium/provider"
	"github.com/vigolium/vigolium/pkg/olium/stream"
	"github.com/vigolium/vigolium/pkg/olium/tool"
)

// scriptedProvider is a minimal provider.Provider whose stream is scripted
// per attempt, so a test can replay an exact failure-then-recovery sequence
// without HTTP/auth machinery. fn is called with the 1-based attempt number
// and returns the events to emit for that attempt; the channel is closed
// after they drain (no trailing error == clean stream end).
type scriptedProvider struct {
	attempts atomic.Int32
	fn       func(attempt int32) []stream.Event
}

func (p *scriptedProvider) Name() string { return "scripted" }

func (p *scriptedProvider) Stream(_ context.Context, _ provider.Request) (<-chan stream.Event, error) {
	n := p.attempts.Add(1)
	evs := p.fn(n)
	ch := make(chan stream.Event, len(evs))
	for _, e := range evs {
		ch <- e
	}
	close(ch)
	return ch, nil
}

// TestEngine_RecoversFromCodexErrorFrameMidToolCall is the end-to-end
// regression for the reported abort-on-mid-tool-call bug, driven through the
// real engine retry loop with the exact codex failure shape: attempt 1
// forwards a tool-call-start (the model committed to a function_call output
// item) and then errors with the literal "codex stream error" — codex's
// content-less {"type":"error"} frame. Before the fix the in-flight
// tool-call-start gated retry off and the whole run was torn down; now the
// engine must retry and recover. Pairs with the provider-side regression
// TestCodex_SSEErrorFrameAfterToolCallStartIsTransient.
func TestEngine_RecoversFromCodexErrorFrameMidToolCall(t *testing.T) {
	prov := &scriptedProvider{fn: func(attempt int32) []stream.Event {
		if attempt == 1 {
			return []stream.Event{
				{Type: stream.EventToolCallStart, ToolCall: &stream.ToolCall{ID: "call_codex", Name: "bash"}},
				// Content-less codex error frame, mid-tool-call (no matching
				// EventToolCallEnd). "stream error" substring ⇒ transient.
				{Type: stream.EventError, Err: "codex stream error"},
			}
		}
		// Retry attempt streams a clean, tool-less completion.
		return []stream.Event{
			{Type: stream.EventTextDelta, Delta: "recovered after codex retry"},
			{Type: stream.EventDone, StopReason: stream.StopReasonStop},
		}
	}}

	eng := New(Config{
		Provider:            prov,
		Tools:               tool.NewRegistry(),
		Model:               "test-model",
		MaxTurns:            1,
		RetryInitialBackoff: fastRetryBackoff,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	got := drainEngine(t, eng.Run(ctx, "test"), 5*time.Second)

	if n := prov.attempts.Load(); n != 2 {
		t.Errorf("expected 2 provider attempts (mid-tool-call codex error + retry), got %d", n)
	}
	if got.errMsg != "" {
		t.Errorf("expected recovery from %q, got engine error: %s", "codex stream error", got.errMsg)
	}
	if got.toolStarts < 1 {
		t.Errorf("expected the forwarded tool-call-start from attempt 1, got %d", got.toolStarts)
	}
	if len(got.info) == 0 {
		t.Error("expected at least one EventInfo retry notice, got none")
	}
	if !strings.Contains(got.text, "recovered after codex retry") {
		t.Errorf("expected retry's text in output, got %q", got.text)
	}
	if !got.runDone {
		t.Error("expected EventRunDone after recovery, run did not complete")
	}
}

// TestEngine_StillAbortsOnNonTransientMidToolCall is the negative guard for
// the loosened retry: dropping the tool-call-start gate must NOT turn
// non-transient mid-tool-call errors into retries. A tool-call-start followed
// by a non-transient error (here an auth-shaped message) must still fail
// terminally on the first attempt — otherwise we'd burn attempts on errors a
// retry can never fix.
func TestEngine_StillAbortsOnNonTransientMidToolCall(t *testing.T) {
	prov := &scriptedProvider{fn: func(_ int32) []stream.Event {
		return []stream.Event{
			{Type: stream.EventToolCallStart, ToolCall: &stream.ToolCall{ID: "call_x", Name: "bash"}},
			{Type: stream.EventError, Err: "invalid api key"},
		}
	}}

	eng := New(Config{
		Provider:            prov,
		Tools:               tool.NewRegistry(),
		Model:               "test-model",
		MaxTurns:            1,
		RetryInitialBackoff: fastRetryBackoff,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	got := drainEngine(t, eng.Run(ctx, "test"), 5*time.Second)

	if n := prov.attempts.Load(); n != 1 {
		t.Errorf("expected exactly 1 attempt for a non-transient mid-tool-call error, got %d", n)
	}
	if got.errMsg == "" {
		t.Error("expected terminal EventError for the non-transient error, got none")
	}
	if got.runDone {
		t.Error("expected run to NOT complete on a non-transient error")
	}
}
