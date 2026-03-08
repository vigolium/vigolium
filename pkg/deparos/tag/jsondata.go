package tag

import (
	"bytes"
	"encoding/json"
	"strings"
)

const jsonDataMinBodySize = 500

// JSONDataMatcher detects JSON responses with substantial data payload.
// Useful for finding potentially unauthenticated REST API endpoints.
type JSONDataMatcher struct{}

// NewJSONDataMatcher creates a new JSON data matcher.
func NewJSONDataMatcher() *JSONDataMatcher {
	return &JSONDataMatcher{}
}

// Tag returns the tag this matcher detects.
func (m *JSONDataMatcher) Tag() Tag {
	return TagJSONData
}

// Match returns true if response is successful JSON with body > 500 bytes.
func (m *JSONDataMatcher) Match(input *MatchInput) bool {
	// Only successful responses
	if input.StatusCode != 200 {
		return false
	}

	// Check body size threshold
	if len(input.ResponseBody) <= jsonDataMinBodySize {
		return false
	}

	// Check if JSON via MIME type or content inspection
	if !looksLikeJSON(input.MIMEType, input.ResponseBody) {
		return false
	}

	// Validate JSON
	return json.Valid(input.ResponseBody)
}

// looksLikeJSON returns true if response appears to be JSON.
// Checks MIME type first, then falls back to content inspection.
func looksLikeJSON(mimeType string, body []byte) bool {
	// Check MIME type: application/json, text/json, application/*+json, etc.
	if mimeType != "" {
		mt := strings.ToLower(mimeType)
		// Matches: /json, +json (for vendor types like application/vnd.api+json)
		if strings.Contains(mt, "/json") || strings.Contains(mt, "+json") {
			return true
		}
	}

	// Fallback: check if body starts with { or [
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return false
	}
	return trimmed[0] == '{' || trimmed[0] == '['
}

// Ensure JSONDataMatcher implements TagMatcher
var _ TagMatcher = (*JSONDataMatcher)(nil)
