package provider

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/olium/stream"
)

// drainState feeds one decoded SSE event into a fresh codexStreamState and
// returns whatever the handler emits on the channel.
func drainState(s *codexStreamState, t string, ev map[string]any) []stream.Event {
	out := make(chan stream.Event, 8)
	s.handle(t, ev, out)
	close(out)
	var got []stream.Event
	for e := range out {
		got = append(got, e)
	}
	return got
}

// TestCodex_ContentlessErrorIsTransient is the regression for the
// abort-on-mid-tool-call bug's upstream trigger: codex intermittently sends
// an in-band SSE {"type":"error"} frame with an empty message. The provider
// must map it to a non-empty, stable string ("codex stream error") so that
// (a) logs aren't blank and (b) stream.IsTransientErr recognizes it and the
// engine retries instead of tearing down the run. If this string ever drifts
// out of TransientErrSubstrings, this test catches it before production does.
func TestCodex_ContentlessErrorIsTransient(t *testing.T) {
	// Empty-message error frame — the exact shape reported in the field.
	got := drainState(&codexStreamState{}, "error", map[string]any{})
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 event, got %d: %+v", len(got), got)
	}
	ev := got[0]
	if ev.Type != stream.EventError {
		t.Fatalf("expected EventError, got %s", ev.Type)
	}
	if ev.Err != "codex stream error" {
		t.Fatalf("expected stable %q fallback, got %q", "codex stream error", ev.Err)
	}
	if !stream.IsTransientErr(errors.New(ev.Err)) {
		t.Errorf("codex content-less error %q must classify as transient so the engine retries it", ev.Err)
	}
}

// TestCodex_ErrorPassesThroughMessage verifies the non-empty path is left
// intact — a real upstream message must not be clobbered by the fallback.
func TestCodex_ErrorPassesThroughMessage(t *testing.T) {
	got := drainState(&codexStreamState{}, "error", map[string]any{"message": "rate limited"})
	if len(got) != 1 || got[0].Type != stream.EventError {
		t.Fatalf("expected 1 EventError, got %+v", got)
	}
	if got[0].Err != "rate limited" {
		t.Errorf("expected upstream message preserved, got %q", got[0].Err)
	}
}

// TestCodex_SSEErrorFrameAfterToolCallStartIsTransient drives the REAL codex
// SSE consumer (framing + JSON decode + state.handle) over the exact wire
// shape behind the abort-on-mid-tool-call report: the model commits to a
// function_call output item (→ EventToolCallStart forwarded to the consumer),
// then the stream emits a content-less {"type":"error"} frame. The consumer
// must see a tool-call-start followed by a transient "codex stream error" —
// the precise conditions the engine's retry depends on. This is the
// provider-side half of the end-to-end regression; the engine-side half lives
// in TestEngine_RecoversFromCodexErrorFrameMidToolCall.
func TestCodex_SSEErrorFrameAfterToolCallStartIsTransient(t *testing.T) {
	// Two complete SSE frames: a function_call output item, then a
	// content-less error frame. Trailing blank line terminates the second.
	sse := strings.Join([]string{
		`data: {"type":"response.output_item.added","item":{"type":"function_call","call_id":"call_codex","name":"bash","arguments":""}}`,
		"",
		`data: {"type":"error"}`,
		"",
		"",
	}, "\n")

	out := make(chan stream.Event, 16)
	go (&Codex{}).consumeSSE(context.Background(), io.NopCloser(strings.NewReader(sse)), out)

	var got []stream.Event
	for e := range out {
		got = append(got, e)
	}

	if len(got) < 2 {
		t.Fatalf("expected at least tool-call-start + error, got %d events: %+v", len(got), got)
	}
	if got[0].Type != stream.EventToolCallStart || got[0].ToolCall == nil || got[0].ToolCall.Name != "bash" {
		t.Fatalf("expected first event to be a bash tool-call-start, got %+v", got[0])
	}
	last := got[len(got)-1]
	if last.Type != stream.EventError {
		t.Fatalf("expected final event EventError, got %s (%+v)", last.Type, got)
	}
	if last.Err != "codex stream error" {
		t.Fatalf("expected %q, got %q", "codex stream error", last.Err)
	}
	if !stream.IsTransientErr(errors.New(last.Err)) {
		t.Errorf("codex SSE error frame %q must classify transient so the engine retries it", last.Err)
	}
}
