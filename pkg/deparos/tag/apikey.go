package tag

import (
	"regexp"
)

// APIKeyMatcher detects API keys in response body.
type APIKeyMatcher struct {
	// Body patterns for common API key formats
	bodyPatterns []*regexp.Regexp
}

// NewAPIKeyMatcher creates a new API key matcher.
func NewAPIKeyMatcher() *APIKeyMatcher {
	return &APIKeyMatcher{
		bodyPatterns: []*regexp.Regexp{
			// Common API key patterns in JSON/text
			regexp.MustCompile(`(?i)["']?api[-_]?key["']?\s*[:=]\s*["']?[A-Za-z0-9_-]{20,}["']?`),
			regexp.MustCompile(`(?i)["']?secret[-_]?key["']?\s*[:=]\s*["']?[A-Za-z0-9_-]{20,}["']?`),
			regexp.MustCompile(`(?i)["']?access[-_]?key["']?\s*[:=]\s*["']?[A-Za-z0-9_-]{20,}["']?`),
			regexp.MustCompile(`(?i)["']?client[-_]?secret["']?\s*[:=]\s*["']?[A-Za-z0-9_-]{20,}["']?`),

			// AWS patterns
			regexp.MustCompile(`AKIA[0-9A-Z]{16}`), // AWS Access Key ID

			// Google API Key pattern
			regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),

			// GitHub tokens
			regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,}`),  // GitHub PAT v2
			regexp.MustCompile(`github_pat_[A-Za-z0-9_]{22,}`), // GitHub PAT (fine-grained)
			regexp.MustCompile(`gho_[A-Za-z0-9_]{36,}`),        // GitHub OAuth
			regexp.MustCompile(`ghp_[A-Za-z0-9_]{36,}`),        // GitHub Personal Access Token
			regexp.MustCompile(`ghr_[A-Za-z0-9_]{36,}`),        // GitHub Refresh Token

			// Stripe API keys
			regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`),
			regexp.MustCompile(`pk_live_[0-9a-zA-Z]{24,}`),
			regexp.MustCompile(`sk_test_[0-9a-zA-Z]{24,}`),
			regexp.MustCompile(`pk_test_[0-9a-zA-Z]{24,}`),

			// Slack tokens
			regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,}`),

			// Generic long hex strings that look like keys
			regexp.MustCompile(`(?i)["']?(?:api|auth|secret|private)[-_]?(?:key|token|secret)["']?\s*[:=]\s*["']?[a-f0-9]{32,}["']?`),
		},
	}
}

// Tag returns the tag this matcher detects.
func (m *APIKeyMatcher) Tag() Tag {
	return TagHasAPIKey
}

// Match returns true if API key found in body.
func (m *APIKeyMatcher) Match(input *MatchInput) bool {
	// Check response body only
	if len(input.ResponseBody) == 0 {
		return false
	}

	for _, re := range m.bodyPatterns {
		if re.Match(input.ResponseBody) {
			return true
		}
	}

	return false
}

// Ensure APIKeyMatcher implements TagMatcher
var _ TagMatcher = (*APIKeyMatcher)(nil)
