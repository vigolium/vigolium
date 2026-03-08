package authzutil

import "strings"

// enforcementBodyLimit caps the number of bytes inspected in a response body for enforcement strings.
const enforcementBodyLimit = 4096

// EnforcementStrings are substrings in response bodies that indicate authorization enforcement.
var EnforcementStrings = []string{
	"unauthorized",
	"forbidden",
	"access denied",
	"access_denied",
	"not authorized",
	"not_authorized",
	"permission denied",
	"permission_denied",
	"insufficient privileges",
	"insufficient permissions",
	"requires authentication",
	"authentication required",
	"login required",
	"you do not have permission",
	"you don't have permission",
	"not allowed",
	"no access",
	"invalid token",
	"token expired",
}

// LoginRedirectPatterns are URL path prefixes that indicate a login redirect.
var LoginRedirectPatterns = []string{
	"/login",
	"/signin",
	"/sign-in",
	"/auth/login",
	"/auth/signin",
	"/sso/",
	"/oauth/",
	"/cas/login",
}

// ContainsEnforcementString checks if the first 4KB of a response body contains any
// soft-denial substring indicating authorization enforcement.
func ContainsEnforcementString(body string) bool {
	limit := min(len(body), enforcementBodyLimit)
	lower := strings.ToLower(body[:limit])

	for _, s := range EnforcementStrings {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

// IsLoginRedirect checks if a response is a redirect to a login page.
func IsLoginRedirect(statusCode int, location string) bool {
	if statusCode < 300 || statusCode >= 400 {
		return false
	}
	if location == "" {
		return false
	}
	lower := strings.ToLower(location)
	for _, pattern := range LoginRedirectPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}
