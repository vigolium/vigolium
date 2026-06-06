package provider

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestSetDebugToggle(t *testing.T) {
	t.Cleanup(func() { SetDebug(false) })

	SetDebug(true)
	if !DebugEnabled() {
		t.Fatal("DebugEnabled() = false after SetDebug(true)")
	}
	SetDebug(false)
	if DebugEnabled() {
		t.Fatal("DebugEnabled() = true after SetDebug(false)")
	}
}

// TestOpenAICompatibleDebugTracing is the regression guard for the bug where
// `vigolium ol --debug` showed nothing for the openai-compatible provider: the
// provider must dump its request payload and each raw SSE chunk to stderr when
// tracing is on, and stay silent when it is off.
func TestOpenAICompatibleDebugTracing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "data: %s\n\n", `{"choices":[{"delta":{"content":"hi"}}]}`)
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer srv.Close()

	run := func(t *testing.T, debug bool) string {
		t.Helper()
		t.Cleanup(func() { SetDebug(false) })
		SetDebug(debug)

		// Capture os.Stderr — the debug call sites write there directly.
		old := os.Stderr
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("pipe: %v", err)
		}
		os.Stderr = w

		p := NewOpenAICompatible(srv.URL+"/v1", "", nil, nil)
		events, err := p.Stream(context.Background(), Request{
			Model:    "qwen3.6:latest",
			Messages: []Message{{Role: RoleUser, Text: "ping"}},
		})
		if err != nil {
			os.Stderr = old
			_ = w.Close()
			t.Fatalf("Stream: %v", err)
		}
		// Drain fully so the SSE goroutine finishes writing before we close.
		for range events {
		}
		_ = w.Close()
		os.Stderr = old
		out, _ := io.ReadAll(r)
		return string(out)
	}

	t.Run("enabled dumps request and sse", func(t *testing.T) {
		out := run(t, true)
		if !strings.Contains(out, "[openai-compatible-req]") {
			t.Errorf("debug output missing request dump:\n%s", out)
		}
		if !strings.Contains(out, `"model":"qwen3.6:latest"`) {
			t.Errorf("request dump missing model on the wire:\n%s", out)
		}
		if !strings.Contains(out, "[openai-compatible-sse]") {
			t.Errorf("debug output missing SSE dump:\n%s", out)
		}
		if !strings.Contains(out, "[DONE]") {
			t.Errorf("debug output missing [DONE] sentinel:\n%s", out)
		}
	})

	t.Run("disabled is silent", func(t *testing.T) {
		out := run(t, false)
		if strings.Contains(out, "[openai-compatible-req]") || strings.Contains(out, "[openai-compatible-sse]") {
			t.Errorf("expected no debug output when disabled, got:\n%s", out)
		}
	})
}
