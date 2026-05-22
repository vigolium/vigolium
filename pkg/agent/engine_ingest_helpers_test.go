package agent

import (
	"strings"
	"testing"
)

func TestToHTTPRequestResponse(t *testing.T) {
	t.Run("requires URL", func(t *testing.T) {
		if _, err := ToHTTPRequestResponse(AgentHTTPRecord{}); err == nil {
			t.Error("empty URL should error")
		}
	})

	t.Run("invalid URL errors", func(t *testing.T) {
		if _, err := ToHTTPRequestResponse(AgentHTTPRecord{URL: "://bad"}); err == nil {
			t.Error("malformed URL should error")
		}
	})

	t.Run("defaults method to GET and injects Host", func(t *testing.T) {
		rr, err := ToHTTPRequestResponse(AgentHTTPRecord{URL: "http://example.com/api/x"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		raw := string(rr.Request().Raw())
		if !strings.HasPrefix(raw, "GET /api/x HTTP/1.1") {
			t.Errorf("request line wrong:\n%s", raw)
		}
		if !strings.Contains(raw, "Host: example.com") {
			t.Errorf("Host header not injected:\n%s", raw)
		}
	})

	t.Run("root path when URL has no path", func(t *testing.T) {
		rr, err := ToHTTPRequestResponse(AgentHTTPRecord{URL: "http://example.com"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		raw := string(rr.Request().Raw())
		if !strings.HasPrefix(raw, "GET / HTTP/1.1") {
			t.Errorf("expected origin-form root path:\n%s", raw)
		}
	})

	t.Run("explicit Host header is not duplicated", func(t *testing.T) {
		rr, err := ToHTTPRequestResponse(AgentHTTPRecord{
			URL:     "http://example.com/x",
			Headers: map[string]string{"Host": "override.example.com"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		raw := string(rr.Request().Raw())
		if strings.Count(raw, "Host:") != 1 {
			t.Errorf("expected exactly one Host header:\n%s", raw)
		}
		if !strings.Contains(raw, "Host: override.example.com") {
			t.Errorf("explicit Host header not preserved:\n%s", raw)
		}
	})
}

func TestDetectLanguage(t *testing.T) {
	cases := []struct {
		name  string
		files []string
		want  string
	}{
		{"go majority", []string{"a.go", "b.go", "c.py"}, "Go"},
		{"python majority", []string{"a.py", "b.py", "c.go"}, "Python"},
		{"typescript", []string{"x.ts", "y.tsx"}, "TypeScript"},
		{"unknown ext only", []string{"a.txt", "b.md"}, ""},
		{"empty", nil, ""},
	}
	for _, tc := range cases {
		if got := detectLanguage(tc.files); got != tc.want {
			t.Errorf("%s: detectLanguage = %q, want %q", tc.name, got, tc.want)
		}
	}
}
