package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/olium/stream"
)

// drainProvider runs one Stream call to completion and returns all events. It
// fails the test if Stream itself errors; callers assert on the collected
// events (a mid-stream EventError shows up in the returned slice).
func drainProvider(t *testing.T, p Provider, req Request) []stream.Event {
	t.Helper()
	ch, err := p.Stream(context.Background(), req)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	var got []stream.Event
	for ev := range ch {
		got = append(got, ev)
	}
	return got
}

// responsesSSEReply is a minimal well-formed Responses-API stream: a message
// item opens, streams one text delta, closes, then response.completed carries
// usage. Enough for the shared consumer to emit text_start/delta/end + done.
const responsesSSEReply = `data: {"type":"response.output_item.added","item":{"type":"message"}}

data: {"type":"response.output_text.delta","delta":"hi"}

data: {"type":"response.output_item.done","item":{"type":"message","content":[{"type":"output_text","text":"hi"}]}}

data: {"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":5,"output_tokens":2,"total_tokens":7}}}

`

// TestOpenAIResponses_RequestShapeAndHeaders verifies the public Responses
// driver hits POST /v1/responses with Bearer auth, and marshals the shared
// Responses wire format (input array, tools, tool_choice, store:false).
func TestOpenAIResponses_RequestShapeAndHeaders(t *testing.T) {
	var (
		gotMethod string
		gotAuth   string
		gotCType  string
		gotAccept string
		gotBody   map[string]any
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		gotCType = r.Header.Get("Content-Type")
		gotAccept = r.Header.Get("Accept")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, responsesSSEReply)
	}))
	defer srv.Close()

	p := NewOpenAIResponses("sk-test-key")
	p.baseURL = srv.URL // point the driver at the fake server

	events := drainProvider(t, p, Request{
		Model:    "gpt-5.5",
		System:   "you are a test",
		Messages: []Message{{Role: RoleUser, Text: "ping"}},
		Tools:    []ToolDef{{Name: "bash", Description: "run", Schema: map[string]any{"type": "object"}}},
	})

	var sawStart, sawDelta, sawDone bool
	for _, ev := range events {
		switch ev.Type {
		case stream.EventTextStart:
			sawStart = true
		case stream.EventTextDelta:
			sawDelta = true
			if ev.Delta != "hi" {
				t.Errorf("text delta = %q, want %q", ev.Delta, "hi")
			}
		case stream.EventDone:
			sawDone = true
		case stream.EventError:
			t.Fatalf("stream error: %s", ev.Err)
		}
	}
	if !sawStart || !sawDelta || !sawDone {
		t.Fatalf("missing events: start=%v delta=%v done=%v", sawStart, sawDelta, sawDone)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotAuth != "Bearer sk-test-key" {
		t.Errorf("Authorization = %q, want Bearer sk-test-key", gotAuth)
	}
	if gotCType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotCType)
	}
	if gotAccept != "text/event-stream" {
		t.Errorf("Accept = %q, want text/event-stream", gotAccept)
	}
	// Wire-format spot checks.
	if gotBody["model"] != "gpt-5.5" {
		t.Errorf("body.model = %v, want gpt-5.5", gotBody["model"])
	}
	if gotBody["instructions"] != "you are a test" {
		t.Errorf("body.instructions = %v, want the system prompt", gotBody["instructions"])
	}
	if store, ok := gotBody["store"].(bool); !ok || store {
		t.Errorf("body.store = %v, want false", gotBody["store"])
	}
	if tc, _ := gotBody["tool_choice"].(string); tc != "auto" {
		t.Errorf("body.tool_choice = %v, want auto", gotBody["tool_choice"])
	}
	input, ok := gotBody["input"].([]any)
	if !ok || len(input) != 1 {
		t.Fatalf("body.input = %v, want a single user message", gotBody["input"])
	}
	tools, ok := gotBody["tools"].([]any)
	if !ok || len(tools) != 1 {
		t.Fatalf("body.tools = %v, want one function tool", gotBody["tools"])
	}
	if p.Name() != "openai-responses" {
		t.Errorf("Name() = %q, want openai-responses", p.Name())
	}
}

// TestOpenAIResponses_ReasoningGating asserts the request only carries the
// reasoning / verbosity controls for model families that accept them —
// sending them to a gpt-4o-class model is a hard 400 upstream.
func TestOpenAIResponses_ReasoningGating(t *testing.T) {
	cases := []struct {
		model         string
		wantReasoning bool
		wantVerbosity bool
		wantCacheKey  bool
		sessionID     string
	}{
		{model: "gpt-5.5", wantReasoning: true, wantVerbosity: true, wantCacheKey: true, sessionID: "sess-1"},
		{model: "o3", wantReasoning: true, wantVerbosity: false},
		{model: "gpt-4o", wantReasoning: false, wantVerbosity: false},
	}
	for _, c := range cases {
		t.Run(c.model, func(t *testing.T) {
			body := buildOpenAIResponsesRequest(Request{
				Model:     c.model,
				Messages:  []Message{{Role: RoleUser, Text: "hi"}},
				SessionID: c.sessionID,
			})
			if (body.Reasoning != nil) != c.wantReasoning {
				t.Errorf("reasoning present = %v, want %v", body.Reasoning != nil, c.wantReasoning)
			}
			if c.wantReasoning && len(body.Include) == 0 {
				t.Errorf("expected reasoning.encrypted_content include for %s", c.model)
			}
			if (body.Text != nil) != c.wantVerbosity {
				t.Errorf("verbosity present = %v, want %v", body.Text != nil, c.wantVerbosity)
			}
			if (body.PromptCacheKey != "") != c.wantCacheKey {
				t.Errorf("prompt_cache_key present = %v, want %v", body.PromptCacheKey != "", c.wantCacheKey)
			}
		})
	}
}

// TestOpenAIResponses_AuthError surfaces a friendly hint on 401 so it doesn't
// read as a transient blip and trigger a retry loop.
func TestOpenAIResponses_AuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprint(w, `{"error":{"message":"invalid api key"}}`)
	}))
	defer srv.Close()

	p := NewOpenAIResponses("bad")
	p.baseURL = srv.URL
	_, err := p.Stream(context.Background(), Request{Model: "gpt-5.5", Messages: []Message{{Role: RoleUser, Text: "x"}}})
	if err == nil {
		t.Fatal("expected an error on 401")
	}
	if !strings.Contains(err.Error(), "Responses API access") {
		t.Errorf("error = %q, want the Responses-API access hint", err.Error())
	}
}

func TestIsResponsesReasoningModel(t *testing.T) {
	for _, m := range []string{"gpt-5.5", "gpt-5", "o1", "o3-mini", "o4", "O5"} {
		if !isResponsesReasoningModel(m) {
			t.Errorf("isResponsesReasoningModel(%q) = false, want true", m)
		}
	}
	for _, m := range []string{"gpt-4o", "gpt-4.1", "gpt-3.5-turbo", ""} {
		if isResponsesReasoningModel(m) {
			t.Errorf("isResponsesReasoningModel(%q) = true, want false", m)
		}
	}
}
