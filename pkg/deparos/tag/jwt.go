package tag

import (
	"regexp"
)

// JWTMatcher detects JWT tokens in response body.
type JWTMatcher struct {
	// Pre-compiled regex for JWT pattern
	// JWT format: base64url.base64url.base64url
	jwtPattern *regexp.Regexp
}

// NewJWTMatcher creates a new JWT matcher.
func NewJWTMatcher() *JWTMatcher {
	return &JWTMatcher{
		// JWT regex: three base64url-encoded segments separated by dots
		// Header always starts with eyJ (base64 for {"...)
		// Minimum reasonable lengths: header(20+), payload(20+), signature(20+)
		jwtPattern: regexp.MustCompile(`eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}`),
	}
}

// Tag returns the tag this matcher detects.
func (m *JWTMatcher) Tag() Tag {
	return TagHasJWT
}

// Match returns true if JWT token found in body.
func (m *JWTMatcher) Match(input *MatchInput) bool {
	// Check response body only
	if len(input.ResponseBody) == 0 {
		return false
	}

	return m.jwtPattern.Match(input.ResponseBody)
}

// Ensure JWTMatcher implements TagMatcher
var _ TagMatcher = (*JWTMatcher)(nil)
