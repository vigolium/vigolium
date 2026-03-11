package jsext

import (
	"testing"
)

func TestSubstituteVars(t *testing.T) {
	tests := []struct {
		input    string
		vars     map[string]string
		expected string
	}{
		{"no vars", nil, "no vars"},
		{"hello {{name}}", map[string]string{"name": "world"}, "hello world"},
		{"{{a}} and {{b}}", map[string]string{"a": "1", "b": "2"}, "1 and 2"},
		{"{{missing}}", map[string]string{}, "{{missing}}"},
		{"{{tok}} {{tok}}", map[string]string{"tok": "x"}, "x x"},
	}
	for _, tt := range tests {
		result := substituteVars(tt.input, tt.vars)
		if result != tt.expected {
			t.Errorf("substituteVars(%q, %v) = %q, want %q", tt.input, tt.vars, result, tt.expected)
		}
	}
}

func TestExtractJSONValue(t *testing.T) {
	body := `{"data":{"token":"abc123","nested":{"key":"val"}},"status":"ok"}`

	tests := []struct {
		path     string
		expected string
	}{
		{"data.token", "abc123"},
		{"data.nested.key", "val"},
		{"status", "ok"},
		{"$.data.token", "abc123"},
		{"missing", ""},
		{"data.missing", ""},
		{"", ""},
	}
	for _, tt := range tests {
		result := extractJSONValue(body, tt.path)
		if result != tt.expected {
			t.Errorf("extractJSONValue(body, %q) = %q, want %q", tt.path, result, tt.expected)
		}
	}
}

func TestExtractHeaderValue(t *testing.T) {
	headers := map[string]string{
		"content-type":  "application/json",
		"x-request-id":  "req-123",
		"authorization": "Bearer tok",
	}

	tests := []struct {
		name     string
		expected string
	}{
		{"content-type", "application/json"},
		{"Content-Type", "application/json"},
		{"x-request-id", "req-123"},
		{"missing", ""},
		{"", ""},
	}
	for _, tt := range tests {
		result := extractHeaderValue(tt.name, headers)
		if result != tt.expected {
			t.Errorf("extractHeaderValue(%q) = %q, want %q", tt.name, result, tt.expected)
		}
	}
}

func TestExtractRegexValue(t *testing.T) {
	tests := []struct {
		body     string
		pattern  string
		expected string
	}{
		{`csrf_token=abc123&next=/`, `csrf_token=([^&]+)`, "abc123"},
		{`name="token" value="xyz789"`, `value="([^"]+)"`, "xyz789"},
		{"no match here", `missing=(\w+)`, ""},
		{"some text", "", ""},
		{"test", `(test)`, "test"},
	}
	for _, tt := range tests {
		result := extractRegexValue(tt.body, tt.pattern)
		if result != tt.expected {
			t.Errorf("extractRegexValue(%q, %q) = %q, want %q", tt.body, tt.pattern, result, tt.expected)
		}
	}
}

func TestExtractCookieValue(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nSet-Cookie: session=abc123; Path=/\r\nSet-Cookie: csrf=xyz; HttpOnly\r\nContent-Type: text/html\r\n\r\n<html></html>"

	tests := []struct {
		name     string
		expected string
	}{
		{"session", "abc123"},
		{"csrf", "xyz"},
		{"missing", ""},
		// Empty name returns first Set-Cookie value
		{"", "abc123"},
	}
	for _, tt := range tests {
		result := extractCookieValue(tt.name, raw, nil)
		if result != tt.expected {
			t.Errorf("extractCookieValue(%q) = %q, want %q", tt.name, result, tt.expected)
		}
	}
}

func TestExtractURLFromRaw(t *testing.T) {
	tests := []struct {
		rawReq   string
		expected string
	}{
		{
			"GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"http://example.com/api/users",
		},
		{
			"POST https://example.com/login HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"https://example.com/login",
		},
		{
			"GET / HTTP/1.1\r\n\r\n",
			"",
		},
	}
	for _, tt := range tests {
		result := extractURLFromRaw(tt.rawReq)
		if result != tt.expected {
			t.Errorf("extractURLFromRaw(%q) = %q, want %q", tt.rawReq, result, tt.expected)
		}
	}
}

func TestRemoveHeadersFromRaw(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc\r\nAuthorization: Bearer tok\r\nAccept: */*\r\n\r\n"

	// We need a VM for the sobek.Object, but we can test the core logic
	// by verifying the helper splits correctly
	headerSection, body := splitHTTPMessage(raw)
	lines := splitHeaderLines(headerSection)

	if len(lines) != 5 {
		t.Fatalf("expected 5 header lines, got %d", len(lines))
	}
	if body != "" {
		t.Fatalf("expected empty body, got %q", body)
	}
}

func TestApplySessionHeaderTemplate(t *testing.T) {
	sess := &jsSession{
		defaultHeaders: make(map[string]string),
	}

	applySessionHeaderTemplate(sess, "Authorization: Bearer {value}", "tok123")
	if sess.defaultHeaders["Authorization"] != "Bearer tok123" {
		t.Errorf("expected 'Bearer tok123', got %q", sess.defaultHeaders["Authorization"])
	}

	applySessionHeaderTemplate(sess, "X-API-Key: {value}", "key456")
	if sess.defaultHeaders["X-API-Key"] != "key456" {
		t.Errorf("expected 'key456', got %q", sess.defaultHeaders["X-API-Key"])
	}

	// Invalid template (no colon)
	applySessionHeaderTemplate(sess, "invalid", "val")
	if _, ok := sess.defaultHeaders["invalid"]; ok {
		t.Error("invalid template should not set a header")
	}
}
