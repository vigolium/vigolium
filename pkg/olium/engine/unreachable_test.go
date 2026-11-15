package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/olium/stream"
	"github.com/vigolium/vigolium/pkg/olium/tool"
)

// A provider that refuses the connection before any call has succeeded is
// not retried: the run fails at once, marked provider unreachable.
func TestEngine_DialFailureBeforeFirstSuccessIsTerminal(t *testing.T) {
	prov := &scriptedProvider{fn: func(int32) []stream.Event {
		return []stream.Event{{Type: stream.EventError, Err: `Post "http://127.0.0.1:1/v1/chat/completions": dial tcp 127.0.0.1:1: connect: connection refused`}}
	}}
	eng := New(Config{Provider: prov, Tools: tool.NewRegistry(), Model: "m", MaxTurns: 1, RetryInitialBackoff: time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	got := drainEngine(t, eng.Run(ctx, "test"), 5*time.Second)
	if n := prov.attempts.Load(); n != 1 {
		t.Fatalf("provider attempts = %d, want 1 (no retry of a refused connection)", n)
	}
	if !strings.Contains(got.errMsg, stream.ErrProviderUnreachable.Error()) {
		t.Fatalf("engine error = %q, want it marked %q", got.errMsg, stream.ErrProviderUnreachable)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("took %s", time.Since(start))
	}
}

// Once a call has succeeded, the same error is a blip and is retried.
func TestEngine_DialFailureAfterSuccessIsRetried(t *testing.T) {
	prov := &scriptedProvider{fn: func(attempt int32) []stream.Event {
		if attempt == 2 {
			return []stream.Event{{Type: stream.EventError, Err: "dial tcp: connection refused"}}
		}
		return []stream.Event{{Type: stream.EventTextDelta, Delta: "ok"}, {Type: stream.EventDone, StopReason: stream.StopReasonStop}}
	}}
	eng := New(Config{Provider: prov, Tools: tool.NewRegistry(), Model: "m", MaxTurns: 1, RetryInitialBackoff: fastRetryBackoff})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	drainEngine(t, eng.Run(ctx, "first"), 5*time.Second)
	got := drainEngine(t, eng.Run(ctx, "second"), 5*time.Second)
	if n := prov.attempts.Load(); n != 3 {
		t.Fatalf("provider attempts = %d, want 3 (success, refused, retry)", n)
	}
	if got.errMsg != "" {
		t.Fatalf("second run failed: %s", got.errMsg)
	}
}
