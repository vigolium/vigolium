package database

import (
	"regexp"
	"strings"
)

var (
	reNumeric   = regexp.MustCompile(`^\d+$`)
	reUUID      = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reHexLong   = regexp.MustCompile(`(?i)^[0-9a-f]{8,}$`)
	reTokenLong = regexp.MustCompile(`^[A-Za-z0-9_-]{20,}$`)
	reVersion   = regexp.MustCompile(`(?i)^v\d+$`)
)

// HasDynamicSegment returns true if the path contains at least one dynamic
// segment — a numeric ID, UUID, long hex string, or long alphanumeric token.
// Version-like segments (v1, v2, v10) are not considered dynamic.
func HasDynamicSegment(path string) bool {
	for _, seg := range strings.Split(path, "/") {
		if seg == "" || reVersion.MatchString(seg) {
			continue
		}
		if reNumeric.MatchString(seg) ||
			reUUID.MatchString(seg) ||
			reHexLong.MatchString(seg) ||
			reTokenLong.MatchString(seg) {
			return true
		}
	}
	return false
}

// PathToTemplate normalizes a URL path for related-record lookup by replacing
// dynamic path segments (IDs, UUIDs, tokens) with a wildcard "*".
// Static segments and version segments (v1, v2, v10) are preserved.
// The resulting template uses "*" which callers can replace with "%" for SQL LIKE.
//
// Segments are replaced if they match any of:
//   - Pure numeric: `^\d+$`
//   - UUID: `^[0-9a-f]{8}-...-[0-9a-f]{12}$` (case-insensitive)
//   - All-hex ≥ 8 chars: `^[0-9a-f]{8,}$` (case-insensitive)
//   - Long alphanumeric ≥ 20 chars (token-like): `^[A-Za-z0-9_-]{20,}$`
//
// Version-like segments (v1, v2, v10) are always kept as-is.
func PathToTemplate(path string) string {
	if path == "" {
		return path
	}

	segments := strings.Split(path, "/")
	for i, seg := range segments {
		if seg == "" {
			continue
		}
		// Keep version-like segments (v1, v2, v10) as-is
		if reVersion.MatchString(seg) {
			continue
		}
		if reNumeric.MatchString(seg) ||
			reUUID.MatchString(seg) ||
			reHexLong.MatchString(seg) ||
			reTokenLong.MatchString(seg) {
			segments[i] = "*"
		}
	}
	return strings.Join(segments, "/")
}
