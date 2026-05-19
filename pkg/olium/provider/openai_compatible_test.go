package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/olium/stream"
)

// TestOpenAICompatible_RoutingAndHeaders verifies the three behaviors that
// distinguish openai-compatible from the canonical OpenAI provider:
//   - the request is sent to the configured base_url, not api.openai.com
//   - the Authorization header is suppressed when the api_key is empty
//     (so unauthenticated local servers like Ollama work)
//   - extra_headers are applied and can override standard headers
//
// The fake server replies with a single content delta + [DONE] so the SSE
// reader has just enough to produce text_start / text_delta / text_end / done.
func TestOpenAICompatible_RoutingAndHeaders(t *testing.T) {
	type capture struct {
		method     string
		path       string
		authHeader string
		extra      string
		ctype      string
		accept     string
	}

	cases := []struct {
		name         string
		baseURLPath  string // appended to httptest server URL — covers normalization
		apiKey       string
		extraHeaders map[string]string
		wantAuth     string // value expected in Authorization; "" means header must be absent
		wantExtra    string // value expected in X-Test header
	}{
		{
			name:        "ollama_style_no_key_v1_root",
			baseURLPath: "/v1",
			apiKey:      "",
			wantAuth:    "",
		},
		{
			name:        "openrouter_style_with_key_full_url",
			baseURLPath: "/v1/chat/completions",
			apiKey:      "or-test-key",
			wantAuth:    "Bearer or-test-key",
		},
		{
			name:         "extra_headers_applied_and_can_override_auth",
			baseURLPath:  "/v1",
			apiKey:       "ignored-by-override",
			extraHeaders: map[string]string{"Authorization": "Api-Key custom-scheme", "X-Test": "hello"},
			wantAuth:     "Api-Key custom-scheme",
			wantExtra:    "hello",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got capture
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got.method = r.Method
				got.path = r.URL.Path
				got.authHeader = r.Header.Get("Authorization")
				got.extra = r.Header.Get("X-Test")
				got.ctype = r.Header.Get("Content-Type")
				got.accept = r.Header.Get("Accept")

				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
				// Minimal valid OpenAI SSE stream: one content delta then [DONE].
				_, _ = fmt.Fprintf(w, "data: %s\n\n", `{"choices":[{"delta":{"content":"hi"}}]}`)
				_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
			}))
			defer srv.Close()

			p := NewOpenAICompatible(srv.URL+tc.baseURLPath, tc.apiKey, tc.extraHeaders)

			events, err := p.Stream(context.Background(), Request{
				Model:    "test-model",
				System:   "you are a test",
				Messages: []Message{{Role: RoleUser, Text: "ping"}},
			})
			if err != nil {
				t.Fatalf("Stream: %v", err)
			}
			// Drain to ensure the reader doesn't error out on our fake stream.
			var sawDone bool
			for ev := range events {
				if ev.Type == stream.EventDone {
					sawDone = true
				}
				if ev.Type == stream.EventError {
					t.Fatalf("stream error: %s", ev.Err)
				}
			}
			if !sawDone {
				t.Fatalf("expected EventDone, got none")
			}

			if got.method != http.MethodPost {
				t.Errorf("method = %q, want POST", got.method)
			}
			if !strings.HasSuffix(got.path, "/chat/completions") {
				t.Errorf("path = %q, expected to end in /chat/completions", got.path)
			}
			if got.authHeader != tc.wantAuth {
				t.Errorf("Authorization = %q, want %q", got.authHeader, tc.wantAuth)
			}
			if tc.wantExtra != "" && got.extra != tc.wantExtra {
				t.Errorf("X-Test header = %q, want %q", got.extra, tc.wantExtra)
			}
			if got.ctype != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", got.ctype)
			}
			if got.accept != "text/event-stream" {
				t.Errorf("Accept = %q, want text/event-stream", got.accept)
			}
			if p.Name() != "openai-compatible" {
				t.Errorf("Name() = %q, want openai-compatible", p.Name())
			}
		})
	}
}

// TestNormalizeOpenAIBaseURL covers the URL handling we promise users — a
// /v1 root and a full /v1/chat/completions URL should both work, and
// trailing slashes shouldn't produce double-slash paths.
func TestNormalizeOpenAIBaseURL(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"http://localhost:11434/v1", "http://localhost:11434/v1/chat/completions"},
		{"http://localhost:11434/v1/", "http://localhost:11434/v1/chat/completions"},
		{"http://localhost:11434/v1/chat/completions", "http://localhost:11434/v1/chat/completions"},
		{"http://localhost:11434/v1/chat/completions/", "http://localhost:11434/v1/chat/completions"},
		{"  https://openrouter.ai/api/v1  ", "https://openrouter.ai/api/v1/chat/completions"},
		{"", ""},
	}
	for _, c := range cases {
		if got := normalizeOpenAIBaseURL(c.in); got != c.want {
			t.Errorf("normalizeOpenAIBaseURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
