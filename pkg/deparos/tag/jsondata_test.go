package tag

import (
	"strings"
	"testing"
)

func TestJSONDataMatcher_Match(t *testing.T) {
	matcher := NewJSONDataMatcher()

	// Helper to create valid JSON body of exact size
	makeJSON := func(size int) string {
		// {"d":"xxx..."} = 8 chars wrapper
		wrapper := 8 // len(`{"d":""}`)
		padding := size - wrapper
		if padding < 0 {
			padding = 0
		}
		return `{"d":"` + strings.Repeat("x", padding) + `"}`
	}

	tests := []struct {
		name       string
		statusCode int
		mimeType   string
		body       string
		wantMatch  bool
	}{
		// Positive cases
		{
			name:       "200 + JSON + body > 500 bytes",
			statusCode: 200,
			mimeType:   "application/json",
			body:       makeJSON(600),
			wantMatch:  true,
		},
		{
			name:       "200 + JSON with charset + body > 500 bytes",
			statusCode: 200,
			mimeType:   "application/json; charset=utf-8",
			body:       makeJSON(600),
			wantMatch:  true,
		},
		{
			name:       "200 + JSON + large array",
			statusCode: 200,
			mimeType:   "application/json",
			body:       `{"users":[{"id":1,"name":"John","email":"john@example.com"},{"id":2,"name":"Jane","email":"jane@example.com"},{"id":3,"name":"Bob","email":"bob@example.com"},{"id":4,"name":"Alice","email":"alice@example.com"},{"id":5,"name":"Charlie","email":"charlie@example.com"},{"id":6,"name":"Dave","email":"dave@example.com"},{"id":7,"name":"Eve","email":"eve@example.com"},{"id":8,"name":"Frank","email":"frank@example.com"},{"id":9,"name":"Grace","email":"grace@example.com"},{"id":10,"name":"Henry","email":"henry@example.com"}]}`,
			wantMatch:  true,
		},

		// Boundary cases
		{
			name:       "200 + JSON + body = 500 bytes - should NOT match",
			statusCode: 200,
			mimeType:   "application/json",
			body:       makeJSON(500),
			wantMatch:  false,
		},
		{
			name:       "200 + JSON + body < 500 bytes - should NOT match",
			statusCode: 200,
			mimeType:   "application/json",
			body:       makeJSON(100),
			wantMatch:  false,
		},
		{
			name:       "200 + JSON + body = 501 bytes - should match",
			statusCode: 200,
			mimeType:   "application/json",
			body:       makeJSON(501),
			wantMatch:  true,
		},

		// Status code filtering
		{
			name:       "401 + JSON + body > 500 - should NOT match",
			statusCode: 401,
			mimeType:   "application/json",
			body:       makeJSON(600),
			wantMatch:  false,
		},
		{
			name:       "403 + JSON + body > 500 - should NOT match",
			statusCode: 403,
			mimeType:   "application/json",
			body:       makeJSON(600),
			wantMatch:  false,
		},
		{
			name:       "404 + JSON + body > 500 - should NOT match",
			statusCode: 404,
			mimeType:   "application/json",
			body:       makeJSON(600),
			wantMatch:  false,
		},
		{
			name:       "500 + JSON + body > 500 - should NOT match",
			statusCode: 500,
			mimeType:   "application/json",
			body:       makeJSON(600),
			wantMatch:  false,
		},
		{
			name:       "201 + JSON + body > 500 - should NOT match (only 200)",
			statusCode: 201,
			mimeType:   "application/json",
			body:       makeJSON(600),
			wantMatch:  false,
		},

		// Various JSON MIME types
		{
			name:       "200 + text/json + body > 500 - should match",
			statusCode: 200,
			mimeType:   "text/json",
			body:       makeJSON(600),
			wantMatch:  true,
		},
		{
			name:       "200 + application/vnd.api+json + body > 500 - should match",
			statusCode: 200,
			mimeType:   "application/vnd.api+json",
			body:       makeJSON(600),
			wantMatch:  true,
		},
		{
			name:       "200 + application/hal+json + body > 500 - should match",
			statusCode: 200,
			mimeType:   "application/hal+json",
			body:       makeJSON(600),
			wantMatch:  true,
		},
		{
			name:       "200 + application/ld+json + body > 500 - should match",
			statusCode: 200,
			mimeType:   "application/ld+json",
			body:       makeJSON(600),
			wantMatch:  true,
		},

		// Content fallback - no MIME type but valid JSON body
		{
			name:       "200 + empty content-type + JSON object body - should match",
			statusCode: 200,
			mimeType:   "",
			body:       makeJSON(600),
			wantMatch:  true,
		},
		{
			name:       "200 + empty content-type + JSON array body - should match",
			statusCode: 200,
			mimeType:   "",
			body:       `[` + strings.Repeat(`{"id":1},`, 60) + `{"id":2}]`,
			wantMatch:  true,
		},
		{
			name:       "200 + empty content-type + JSON with whitespace - should match",
			statusCode: 200,
			mimeType:   "",
			body:       "  \n\t" + makeJSON(600),
			wantMatch:  true,
		},

		// Non-JSON content types with JSON-like body - should still match via content inspection
		{
			name:       "200 + text/plain + JSON body - should match (content fallback)",
			statusCode: 200,
			mimeType:   "text/plain",
			body:       makeJSON(600),
			wantMatch:  true,
		},

		// Non-JSON content and body
		{
			name:       "200 + text/html + HTML body - should NOT match",
			statusCode: 200,
			mimeType:   "text/html",
			body:       "<html><body>" + strings.Repeat("<p>content</p>", 50) + "</body></html>",
			wantMatch:  false,
		},
		{
			name:       "200 + application/xml + XML body - should NOT match",
			statusCode: 200,
			mimeType:   "application/xml",
			body:       "<root>" + strings.Repeat("<item>data</item>", 50) + "</root>",
			wantMatch:  false,
		},

		// Invalid JSON
		{
			name:       "200 + JSON content-type + invalid JSON - should NOT match",
			statusCode: 200,
			mimeType:   "application/json",
			body:       strings.Repeat("not valid json", 50),
			wantMatch:  false,
		},
		{
			name:       "200 + JSON content-type + truncated JSON - should NOT match",
			statusCode: 200,
			mimeType:   "application/json",
			body:       `{"users":[{"id":1,"name":"John"` + strings.Repeat(",", 500),
			wantMatch:  false,
		},

		// Edge cases
		{
			name:       "empty body",
			statusCode: 200,
			mimeType:   "application/json",
			body:       "",
			wantMatch:  false,
		},
		{
			name:       "small valid JSON array",
			statusCode: 200,
			mimeType:   "application/json",
			body:       `{"data":[]}`,
			wantMatch:  false,
		},
		{
			name:       "small error response",
			statusCode: 200,
			mimeType:   "application/json",
			body:       `{"error":"unauthorized","code":401}`,
			wantMatch:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := &MatchInput{
				StatusCode:   tt.statusCode,
				MIMEType:     tt.mimeType,
				ResponseBody: []byte(tt.body),
			}
			got := matcher.Match(input)
			if got != tt.wantMatch {
				t.Errorf("Match() = %v, want %v (body size: %d)", got, tt.wantMatch, len(tt.body))
			}
		})
	}
}

func TestJSONDataMatcher_Tag(t *testing.T) {
	matcher := NewJSONDataMatcher()
	if matcher.Tag() != TagJSONData {
		t.Errorf("Tag() = %v, want %v", matcher.Tag(), TagJSONData)
	}
}

func TestLooksLikeJSON(t *testing.T) {
	tests := []struct {
		name     string
		mimeType string
		body     string
		want     bool
	}{
		// MIME type detection
		{"application/json", "application/json", "", true},
		{"application/json with charset", "application/json; charset=utf-8", "", true},
		{"text/json", "text/json", "", true},
		{"application/vnd.api+json", "application/vnd.api+json", "", true},
		{"application/hal+json", "application/hal+json", "", true},
		{"application/ld+json", "application/ld+json", "", true},
		{"APPLICATION/JSON uppercase", "APPLICATION/JSON", "", true},

		// Content fallback - empty MIME type
		{"empty mime + object body", "", `{"key":"value"}`, true},
		{"empty mime + array body", "", `[1,2,3]`, true},
		{"empty mime + whitespace + object", "", "  \n{}", true},
		{"empty mime + whitespace + array", "", "\t\n[]", true},
		{"empty mime + non-json body", "", "hello world", false},
		{"empty mime + empty body", "", "", false},
		{"empty mime + html body", "", "<html>", false},
		{"empty mime + xml body", "", "<?xml", false},

		// Non-JSON MIME types - fallback to content
		{"text/html + json body", "text/html", `{"key":"value"}`, true},
		{"text/plain + json body", "text/plain", `[1,2,3]`, true},
		{"text/html + html body", "text/html", "<html>", false},
		{"application/xml + xml body", "application/xml", "<root>", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := looksLikeJSON(tt.mimeType, []byte(tt.body))
			if got != tt.want {
				t.Errorf("looksLikeJSON(%q, %q) = %v, want %v", tt.mimeType, tt.body, got, tt.want)
			}
		})
	}
}
