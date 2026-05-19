package tag

import (
	"bytes"
	"strings"
)

// ModernAppMatcher detects modern frontend frameworks (React, Next.js, Angular, Vue, etc.)
// by analyzing JavaScript loading patterns in HTML source.
type ModernAppMatcher struct {
	// Pre-allocated byte patterns for fast substring search
	frameworkPatterns [][]byte
}

// NewModernAppMatcher creates a new modern app matcher.
func NewModernAppMatcher() *ModernAppMatcher {
	return &ModernAppMatcher{
		frameworkPatterns: [][]byte{
			// Next.js
			[]byte("__NEXT_DATA__"),
			[]byte("/_next/static/"),

			// React
			[]byte("__REACT_DEVTOOLS_GLOBAL_HOOK__"),
			[]byte("react.production.min.js"),
			[]byte("react-dom.production.min.js"),

			// Angular
			[]byte("ng-version=\""),
			[]byte(" ng-app"),

			// Vue / Nuxt.js
			[]byte("__NUXT__"),
			[]byte("__VUE__"),
			[]byte("/_nuxt/"),

			// Svelte / SvelteKit
			[]byte("__sveltekit"),
			[]byte("/_app/immutable/"),
		},
	}
}

// Tag returns the tag this matcher detects.
func (m *ModernAppMatcher) Tag() Tag {
	return TagModernApp
}

// Match returns true if modern framework patterns found in HTML response.
func (m *ModernAppMatcher) Match(input *MatchInput) bool {
	// Only match valid paths (no extension or ends with /)
	if !isValidModernAppPath(input.RequestPath) {
		return false
	}

	// Only check HTML responses
	if !isHTMLResponse(input.MIMEType) {
		return false
	}

	// Need response body to analyze
	if len(input.ResponseBody) == 0 {
		return false
	}

	// Fast path: check byte patterns
	for _, pattern := range m.frameworkPatterns {
		if bytes.Contains(input.ResponseBody, pattern) {
			return true
		}
	}

	return false
}

// isValidModernAppPath returns true if path is valid for modern app detection.
// Valid paths: "/", "", "/app", "/app/", "/dashboard/settings"
// Invalid paths: "/app.js", "/api.php", "/file.html"
func isValidModernAppPath(path string) bool {
	// Root path or empty
	if path == "/" || path == "" {
		return true
	}

	// Ends with / (directory-style)
	if strings.HasSuffix(path, "/") {
		return true
	}

	// Check last segment for extension
	lastSlash := strings.LastIndex(path, "/")
	segment := path
	if lastSlash >= 0 {
		segment = path[lastSlash+1:]
	}

	// No extension = valid
	return !strings.Contains(segment, ".")
}

// isHTMLResponse returns true if MIME type indicates HTML content.
func isHTMLResponse(mimeType string) bool {
	if mimeType == "" {
		return true // Assume HTML if unknown
	}
	mt := strings.ToLower(mimeType)
	return strings.Contains(mt, "/html") || strings.Contains(mt, "/xhtml")
}

// Ensure ModernAppMatcher implements TagMatcher
var _ TagMatcher = (*ModernAppMatcher)(nil)
