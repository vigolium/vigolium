package server

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRedactJSONBody_ScrubsKnownFields(t *testing.T) {
	in := []byte(`{
		"source": "/repo",
		"api_key": "sk-ant-api-secret",
		"oauth_token": "sk-ant-oat01-secret",
		"oauth_cred_file": "/etc/codex/auth.json",
		"nested": {
			"llm_api_key": "sk-openai-secret"
		},
		"list": [
			{"password": "hunter2"},
			{"benign": "yes"}
		]
	}`)
	out := redactJSONBody(in)
	if len(out) == 0 {
		t.Fatalf("empty output")
	}

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}

	checks := []struct {
		path string
		want string
	}{
		{"api_key", redactedPlaceholder},
		{"oauth_token", redactedPlaceholder},
		{"oauth_cred_file", redactedPlaceholder},
		{"source", "/repo"},
	}
	for _, c := range checks {
		if got[c.path] != c.want {
			t.Errorf("path %s: got %q, want %q", c.path, got[c.path], c.want)
		}
	}

	nested, _ := got["nested"].(map[string]any)
	if nested == nil || nested["llm_api_key"] != redactedPlaceholder {
		t.Errorf("nested.llm_api_key not redacted: %v", nested)
	}

	list, _ := got["list"].([]any)
	if len(list) != 2 {
		t.Fatalf("list length: %d", len(list))
	}
	first, _ := list[0].(map[string]any)
	if first["password"] != redactedPlaceholder {
		t.Errorf("list[0].password not redacted: %v", first)
	}
	second, _ := list[1].(map[string]any)
	if second["benign"] != "yes" {
		t.Errorf("list[1].benign should pass through: %v", second)
	}
}

func TestRedactJSONBody_EmptyValuePreserved(t *testing.T) {
	in := []byte(`{"api_key":""}`)
	out := redactJSONBody(in)
	// Empty values are not credentials, so the body should pass through
	// unredacted. The unchanged-body short-circuit returns the input
	// verbatim; assert on parsed semantics rather than byte-equality to
	// stay robust to that optimization.
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("output not JSON: %v\n%s", err, out)
	}
	if got["api_key"] != "" {
		t.Errorf("empty api_key should pass through: got %q", got["api_key"])
	}
}

func TestRedactJSONBody_NonJSONSummarized(t *testing.T) {
	in := []byte("plain text not json")
	out := string(redactJSONBody(in))
	if !strings.Contains(out, "non-JSON body redacted") {
		t.Errorf("non-JSON should be summarized, got %q", out)
	}
}

func TestRedactJSONBody_MalformedJSONSummarized(t *testing.T) {
	in := []byte(`{"a": 1,`)
	out := string(redactJSONBody(in))
	if !strings.Contains(out, "malformed JSON body redacted") {
		t.Errorf("malformed JSON should be summarized, got %q", out)
	}
}

func TestRedactJSONBody_EmptyInput(t *testing.T) {
	if got := redactJSONBody(nil); got != nil {
		t.Errorf("nil input should yield nil, got %v", got)
	}
	if got := redactJSONBody([]byte{}); got != nil {
		t.Errorf("empty input should yield nil, got %v", got)
	}
}

func TestRedactSensitiveHeaders(t *testing.T) {
	in := map[string][]string{
		"Authorization":  {"Bearer xxx"},
		"X-API-Key":      {"sk-ant-foo"},
		"Cookie":         {"session=abc"},
		"Content-Type":   {"application/json"},
		"X-Project-UUID": {"proj-123"},
	}
	out := redactSensitiveHeaders(in)
	for _, h := range []string{"Authorization", "X-API-Key", "Cookie"} {
		if out[h] != redactedPlaceholder {
			t.Errorf("%s not redacted: %q", h, out[h])
		}
	}
	if out["Content-Type"] != "application/json" {
		t.Errorf("Content-Type should pass through: %q", out["Content-Type"])
	}
	if out["X-Project-UUID"] != "proj-123" {
		t.Errorf("X-Project-UUID should pass through: %q", out["X-Project-UUID"])
	}
}
