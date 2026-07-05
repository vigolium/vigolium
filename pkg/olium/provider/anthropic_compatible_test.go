package provider

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/olium/stream"
)

// anthropicSSEReply is a minimal well-formed Messages stream: one text block
// opens, streams a delta, closes, then message_delta/message_stop carry the
// stop reason and usage. Enough for consumeAnthropicSSE to emit
// text_start/delta/end + done.
const anthropicSSEReply = `data: {"type":"message_start","message":{"usage":{"input_tokens":3}}}

data: {"type":"content_block_start","index":0,"content_block":{"type":"text"}}

data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}

data: {"type":"content_block_stop","index":0}

data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":2}}

data: {"type":"message_stop"}

`

// TestAnthropicCompatible_RoutingAndHeaders verifies the behaviors that
// distinguish anthropic-compatible from the canonical Anthropic provider:
//   - the request is sent to the configured base_url, not api.anthropic.com
//   - x-api-key is suppressed when the api_key is empty (unauthenticated proxy)
//   - extra_headers are applied last and can override the auth scheme
func TestAnthropicCompatible_RoutingAndHeaders(t *testing.T) {
	type capture struct {
		method     string
		path       string
		apiKey     string
		authHeader string
		version    string
		extra      string
		ctype      string
		accept     string
	}

	cases := []struct {
		name         string
		baseURLPath  string // appended to the httptest server URL — covers normalization
		apiKey       string
		extraHeaders map[string]string
		wantAPIKey   string // expected x-api-key; "" means header must be absent
		wantAuth     string // expected Authorization; "" means absent
		wantExtra    string
	}{
		{
			name:        "keyed_v1_root_normalizes_to_messages",
			baseURLPath: "/v1",
			apiKey:      "sk-gw-key",
			wantAPIKey:  "sk-gw-key",
		},
		{
			name:        "unauthenticated_proxy_suppresses_api_key",
			baseURLPath: "/v1/messages",
			apiKey:      "",
			wantAPIKey:  "",
		},
		{
			name:         "extra_headers_override_to_bearer",
			baseURLPath:  "/v1",
			apiKey:       "ignored-when-overridden",
			extraHeaders: map[string]string{"Authorization": "Bearer gw-token", "X-Test": "hello"},
			wantAPIKey:   "ignored-when-overridden", // x-api-key still set; gateway keys off Authorization
			wantAuth:     "Bearer gw-token",
			wantExtra:    "hello",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got capture
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got.method = r.Method
				got.path = r.URL.Path
				got.apiKey = r.Header.Get("x-api-key")
				got.authHeader = r.Header.Get("Authorization")
				got.version = r.Header.Get("anthropic-version")
				got.extra = r.Header.Get("X-Test")
				got.ctype = r.Header.Get("Content-Type")
				got.accept = r.Header.Get("Accept")

				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
				_, _ = fmt.Fprint(w, anthropicSSEReply)
			}))
			defer srv.Close()

			p := NewAnthropicCompatible(srv.URL+tc.baseURLPath, tc.apiKey, tc.extraHeaders)

			events := drainProvider(t, p, Request{
				Model:    "claude-opus-4-7",
				System:   "you are a test",
				Messages: []Message{{Role: RoleUser, Text: "ping"}},
			})
			var sawDone bool
			for _, ev := range events {
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
			if !strings.HasSuffix(got.path, "/v1/messages") {
				t.Errorf("path = %q, expected to end in /v1/messages", got.path)
			}
			if got.apiKey != tc.wantAPIKey {
				t.Errorf("x-api-key = %q, want %q", got.apiKey, tc.wantAPIKey)
			}
			if got.authHeader != tc.wantAuth {
				t.Errorf("Authorization = %q, want %q", got.authHeader, tc.wantAuth)
			}
			if got.version != anthropicVersion {
				t.Errorf("anthropic-version = %q, want %q", got.version, anthropicVersion)
			}
			if tc.wantExtra != "" && got.extra != tc.wantExtra {
				t.Errorf("X-Test = %q, want %q", got.extra, tc.wantExtra)
			}
			if got.ctype != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", got.ctype)
			}
			if got.accept != "text/event-stream" {
				t.Errorf("Accept = %q, want text/event-stream", got.accept)
			}
			if p.Name() != "anthropic-compatible" {
				t.Errorf("Name() = %q, want anthropic-compatible", p.Name())
			}
		})
	}
}

// TestNormalizeAnthropicBaseURL covers the URL handling we promise users: a
// bare host, a /v1 root, and a full /v1/messages URL all resolve to a complete
// messages endpoint, and trailing slashes never produce double slashes.
func TestNormalizeAnthropicBaseURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://gw.example.com", "https://gw.example.com/v1/messages"},
		{"https://gw.example.com/", "https://gw.example.com/v1/messages"},
		{"https://gw.example.com/v1", "https://gw.example.com/v1/messages"},
		{"https://gw.example.com/v1/", "https://gw.example.com/v1/messages"},
		{"https://gw.example.com/v1/messages", "https://gw.example.com/v1/messages"},
		{"https://gw.example.com/v1/messages/", "https://gw.example.com/v1/messages"},
		{"  https://gw.example.com/anthropic/v1  ", "https://gw.example.com/anthropic/v1/messages"},
		{"", ""},
	}
	for _, c := range cases {
		if got := normalizeAnthropicBaseURL(c.in); got != c.want {
			t.Errorf("normalizeAnthropicBaseURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestAnthropicCanonicalNameUnchanged guards that adding the name field didn't
// change what the api-key / oauth constructors report.
func TestAnthropicCanonicalNameUnchanged(t *testing.T) {
	if got := NewAnthropic("sk-ant-api-x").Name(); got != "anthropic" {
		t.Errorf("NewAnthropic().Name() = %q, want anthropic", got)
	}
	if got := NewAnthropicOAuth("sk-ant-oat-x").Name(); got != "anthropic" {
		t.Errorf("NewAnthropicOAuth().Name() = %q, want anthropic", got)
	}
}
