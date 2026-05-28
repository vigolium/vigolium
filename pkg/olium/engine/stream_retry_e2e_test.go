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

// fastRetryBackoff keeps the e2e tests' retry sleeps in the ms range so the
// whole file finishes in well under a second instead of waiting on the
// production 1s+2s backoff schedule.
const fastRetryBackoff = 10 * time.Millisecond

// These tests exercise streamOnceWithRetry end-to-end through a real
// openai-compatible provider pointed at an httptest server that simulates
// the user-reported failure mode: HTTP/2 INTERNAL_ERROR mid-stream. We
// approximate it by hijacking the connection and closing it mid-line so
// the SSE reader surfaces a transient error (unexpected EOF / reset).

// hijackCloseMidStream writes `prefix` to the response, flushes, then
// hijacks the conn and closes it without a graceful TLS / HTTP close —
// matches what happens when an upstream proxy RST_STREAMs us. The SSE
// reader's bufio.Scanner returns an `unexpected EOF` / `connection reset`
// error, which TransientErrSubstrings recognizes as retryable.
func hijackCloseMidStream(t *testing.T, w http.ResponseWriter, prefix string) {
	t.Helper()
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(prefix)); err != nil {
		t.Fatalf("write prefix: %v", err)
	}
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		t.Fatal("response writer does not support Hijacker — test setup broken")
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		t.Fatalf("hijack: %v", err)
	}
	_ = conn.Close()
}

func completeSSEResponse(w http.ResponseWriter, content string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, "data: %s\n\n",
		fmt.Sprintf(`{"choices":[{"delta":{"content":%q}}]}`, content))
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
}

type runOutcome struct {
	text       string
	thinking   string
	info       []string
	errMsg     string
	turnsDone  int
	runDone    bool
	toolStarts int
}

func drainEngine(t *testing.T, ch <-chan Event, deadline time.Duration) runOutcome {
	t.Helper()
	var out runOutcome
	timer := time.NewTimer(deadline)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			t.Fatalf("engine drain timed out after %s; partial state: %+v", deadline, out)
		case ev, ok := <-ch:
			if !ok {
				return out
			}
			switch ev.Type {
			case EventTextDelta:
				out.text += ev.Delta
			case EventThinkingDelta:
				out.thinking += ev.Delta
			case EventInfo:
				out.info = append(out.info, ev.Delta)
			case EventToolCallStart:
				out.toolStarts++
			case EventTurnDone:
				out.turnsDone++
			case EventRunDone:
				out.runDone = true
			case EventError:
				out.errMsg = ev.Err
				return out
			}
		}
	}
}

// TestEngine_RecoversFromMidStreamTransientError reproduces the user's
// report (`stream error: stream ID N; INTERNAL_ERROR; received from peer`
// surfaced after planning text was already on screen) and asserts the
// engine retries the failing stream instead of tearing down the whole
// session. Without the retry, the run terminates with EventError; with
// it, the operator sees an info notice followed by the retry's full text.
func TestEngine_RecoversFromMidStreamTransientError(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		switch n {
		case 1:
			// Mid-stream cut: partial text deltas, then conn close before
			// the SSE frame terminator. The scanner errors on next read.
			hijackCloseMidStream(t, w, "data: "+`{"choices":[{"delta":{"content":"plan"}}]}`+"\n\n"+
				"data: "+`{"choices":[{"delta":{"content":"ning"}}]}`)
		default:
			completeSSEResponse(w, "recovered output")
		}
	}))
	defer srv.Close()

	prov := provider.NewOpenAICompatible(srv.URL+"/v1", "", nil, nil)
	eng := New(Config{
		Provider:            prov,
		Tools:               tool.NewRegistry(),
		Model:               "test-model",
		MaxTurns:            1,
		RetryInitialBackoff: fastRetryBackoff,
	})

	// Backoff is 10ms+20ms+40ms ≈ negligible; 3s gives plenty of slack.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	got := drainEngine(t, eng.Run(ctx, "test"), 3*time.Second)

	if n := attempts.Load(); n != 2 {
		t.Errorf("expected 2 provider attempts (1 transient fail + 1 retry), got %d", n)
	}
	if got.errMsg != "" {
		t.Errorf("expected clean recovery, got engine error: %s", got.errMsg)
	}
	if len(got.info) == 0 {
		t.Errorf("expected at least one EventInfo retry notice, got none")
	}
	if !strings.Contains(got.text, "recovered output") {
		t.Errorf("expected retry's text in output, got %q", got.text)
	}
	if !got.runDone {
		t.Error("expected EventRunDone, run did not complete cleanly")
	}
}

// TestEngine_GivesUpAfterMaxAttempts proves the retry loop is bounded.
// Three consecutive transient failures must surface EventError rather
// than retrying indefinitely.
func TestEngine_GivesUpAfterMaxAttempts(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		hijackCloseMidStream(t, w, "data: "+`{"choices":[{"delta":{"content":"x"}}]}`)
	}))
	defer srv.Close()

	prov := provider.NewOpenAICompatible(srv.URL+"/v1", "", nil, nil)
	eng := New(Config{
		Provider:            prov,
		Tools:               tool.NewRegistry(),
		Model:               "test-model",
		MaxTurns:            1,
		RetryInitialBackoff: fastRetryBackoff,
	})

	// Backoff is fastRetryBackoff×{1,2,4} ≈ 70ms total; 3s ceiling.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	got := drainEngine(t, eng.Run(ctx, "test"), 3*time.Second)

	if n := attempts.Load(); n != 3 {
		t.Errorf("expected 3 provider attempts (maxAttempts), got %d", n)
	}
	if got.errMsg == "" {
		t.Error("expected EventError after exhausting retries, got none")
	}
	if got.runDone {
		t.Error("expected run to NOT complete on exhausted retries")
	}
}

// TestEngine_DoesNotRetryAfterToolCallStart guards the correctness
// invariant: once a tool-call-start has been forwarded to the consumer,
// the engine must NOT retry on a subsequent transient error. Otherwise
// the consumer (toollog, autopilot, the model on the next turn) sees a
// phantom tool announcement that never gets an exec follow-up. This was
// the over-zealous-retry hazard called out in code review; the test
// pins the safe behavior so a future loosening of the guard breaks
// here, not in production.
func TestEngine_DoesNotRetryAfterToolCallStart(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		// Send a tool_call delta with name + id (triggers EventToolCallStart
		// in the openai provider), then drop the conn before the matching
		// finish_reason event. Engine must fail terminally here.
		hijackCloseMidStream(t, w,
			"data: "+`{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_test","type":"function","function":{"name":"bash","arguments":""}}]}}]}`+"\n\n")
	}))
	defer srv.Close()

	prov := provider.NewOpenAICompatible(srv.URL+"/v1", "", nil, nil)
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

	if n := attempts.Load(); n != 1 {
		t.Errorf("expected exactly 1 provider attempt (no retry after tool-call-start), got %d", n)
	}
	if got.toolStarts != 1 {
		t.Errorf("expected exactly 1 EventToolCallStart, got %d", got.toolStarts)
	}
	if got.errMsg == "" {
		t.Error("expected EventError for the mid-tool-call drop, got none")
	}
}

// TestEngine_DoesNotRetryNonTransientError verifies the classifier:
// errors that aren't in TransientErrSubstrings (e.g. an HTTP 401) must
// fail immediately with no retry. Without this gate, an auth failure
// would burn 3 attempts on a problem the user has to fix manually.
func TestEngine_DoesNotRetryNonTransientError(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"invalid api key"}}`))
	}))
	defer srv.Close()

	prov := provider.NewOpenAICompatible(srv.URL+"/v1", "bad-key", nil, nil)
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

	if n := attempts.Load(); n != 1 {
		t.Errorf("expected exactly 1 provider attempt for non-transient error, got %d", n)
	}
	if got.errMsg == "" {
		t.Error("expected EventError for 401, got none")
	}
}
