package linkfinder

import (
	"net/url"
	"strings"
)

// extractPathFromURL extracts the path portion from a URL string.
// For absolute URLs (https://example.com/path?q=1), returns path with query (/path?q=1).
// For protocol-relative URLs (//example.com/path?q=1), extracts path with query after host.
// For relative paths, returns unchanged.
func extractPathFromURL(s string) string {
	// Fast check: if starts with /, check if it's protocol-relative
	if len(s) > 0 && s[0] == '/' {
		// Protocol-relative URL: //host/path
		if len(s) > 2 && s[1] == '/' && s[2] != '/' {
			// Find the path after the host
			slashIdx := strings.Index(s[2:], "/")
			if slashIdx == -1 {
				return "/" // No path, return root
			}
			return s[2+slashIdx:]
		}
		// Regular path starting with /
		return s
	}

	// Check for absolute URL with scheme
	// Fast path: common schemes
	hasScheme := strings.HasPrefix(s, "http://") ||
		strings.HasPrefix(s, "https://") ||
		strings.HasPrefix(s, "ws://") ||
		strings.HasPrefix(s, "wss://") ||
		strings.HasPrefix(s, "ftp://")

	if !hasScheme {
		// Try general case: look for ://
		if !strings.Contains(s, "://") {
			return s // Not an absolute URL, return as-is
		}
	}

	// Parse as URL
	u, err := url.Parse(s)
	if err != nil {
		return s // Can't parse, return as-is
	}

	// If has scheme and host, extract path with query string
	if u.Scheme != "" && u.Host != "" {
		path := u.Path
		if path == "" {
			path = "/"
		}
		// Include query string if present
		if u.RawQuery != "" {
			path = path + "?" + u.RawQuery
		}
		return path
	}

	return s // Not an absolute URL, return as-is
}

const defaultParamValue = "1"

// maxSpacesPerSegment is the maximum number of spaces allowed in a single path segment.
// If a segment has more than this, the entire path is rejected.
const maxSpacesPerSegment = 4

// Template indicator characters in path segments.
// If a segment contains any of these, it's likely a template variable.
var templateChars = [...]byte{
	'{', '}', // Spring, FastAPI, OpenAPI: {param}
	'[', ']', // Next.js, Nuxt: [param]
	'<', '>', // Flask: <param>
	'$', // JS template: ${param}, shell: $VAR
}

// NormalizePathTemplates returns normalized path variants.
// If first segment is a template, returns 2 variants:
//   - With first segment replaced by default value
//   - With first segment removed entirely
//
// Other template segments are always replaced with default value.
//
// Returns nil if:
//   - Path is empty
//   - First segment is template but no real (non-template) segments after
//
// Examples:
//   - "${basePath}/v2/users" → ["/1/v2/users", "/v2/users"]
//   - "/api/{id}"            → ["/api/1"]  (template not at start)
//   - "/users/123"           → ["/users/123"] (no template)
//   - "${a}/${b}"            → nil (no real segment after first template)
func NormalizePathTemplates(path string) []string {
	if path == "" {
		return nil
	}

	// Extract path from absolute URLs (https://example.com/path -> /path)
	// This also handles protocol-relative URLs (//example.com/path -> /path)
	path = extractPathFromURL(path)

	// URL decode (handles %7B, %7D, %5B, %5D, etc.)
	// Try up to 2 decodes for double-encoded paths
	originalPath := urlDecodeMultiple(path, 2)

	// Extract path again after decoding (might have decoded to absolute URL)
	originalPath = extractPathFromURL(originalPath)

	// Sanitize decoded segments (remove garbage chars like \, ", space, etc.)
	originalPath = sanitizeDecodedSegments(originalPath)
	if originalPath == "" {
		return nil // No valid segments after sanitization
	}

	// Ensure leading slash for template detection
	normalizedPath := originalPath
	if !strings.HasPrefix(normalizedPath, "/") {
		normalizedPath = "/" + normalizedPath
	}

	segments := strings.Split(normalizedPath, "/")

	// Track which segments are templates
	isTemplateAt := make([]bool, len(segments))
	firstNonEmptyIdx := -1
	hasRealSegmentAfterFirst := false

	for i, seg := range segments {
		if seg == "" {
			continue
		}

		isTemplate := containsTemplateChar(seg) || isColonParam(seg)
		isTemplateAt[i] = isTemplate

		if firstNonEmptyIdx == -1 {
			firstNonEmptyIdx = i
		} else if !isTemplate {
			hasRealSegmentAfterFirst = true
		}
	}

	// No segments found (e.g., "/" only)
	if firstNonEmptyIdx == -1 {
		return []string{originalPath}
	}

	firstIsTemplate := isTemplateAt[firstNonEmptyIdx]

	// If first is template but no real segments after → skip entire path
	if firstIsTemplate && !hasRealSegmentAfterFirst {
		return nil
	}

	// Normalize: replace all templates with default value
	modified := false
	for i, seg := range segments {
		if seg != "" && isTemplateAt[i] {
			segments[i] = defaultParamValue
			modified = true
		}
	}

	// No templates found → return original path unchanged
	if !modified {
		return []string{originalPath}
	}

	normalizedFull := strings.Join(segments, "/")

	if !firstIsTemplate {
		return []string{normalizedFull}
	}

	// Create variant with first segment removed
	// ["", "1", "api", "v1"] → "/" + "api/v1"
	withoutFirst := "/" + strings.Join(segments[firstNonEmptyIdx+1:], "/")

	return []string{normalizedFull, withoutFirst}
}

// containsTemplateChar checks if segment is a valid template.
// Returns true only for properly formed template patterns with balanced brackets.
// Valid: {id}, [slug], <param>, ${expr}, $VAR
// Invalid: plain], [invalid, foo}, ]
func containsTemplateChar(seg string) bool {
	// Must have template chars
	if !hasTemplateChar(seg) {
		return false
	}
	// Must have balanced brackets
	return hasBalancedBrackets(seg)
}

// hasTemplateChar checks for raw presence of template characters.
func hasTemplateChar(seg string) bool {
	for i := 0; i < len(seg); i++ {
		for _, tc := range templateChars {
			if seg[i] == tc {
				return true
			}
		}
	}
	return false
}

// isColonParam checks if segment is a colon-prefixed parameter.
// Must start with : followed by letter/underscore (not number for port).
func isColonParam(seg string) bool {
	if len(seg) < 2 || seg[0] != ':' {
		return false
	}
	c := seg[1]
	// :param starts with letter or underscore, not digit
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'
}

// urlDecodeMultiple decodes URL encoding up to n times.
func urlDecodeMultiple(s string, n int) string {
	for i := 0; i < n; i++ {
		decoded, err := url.PathUnescape(s)
		if err != nil || decoded == s {
			break
		}
		s = decoded
	}
	return s
}

// Garbage characters to remove from path segments (not valid in paths).
// These are characters that may appear after URL decoding but are noise.
// Note: $, <, >, =, & are kept for templates and query strings.
// Note: Space is allowed but limited to maxSpacesPerSegment per segment.
var garbageChars = [...]byte{
	'\\', '"', '\'', // Escape/quote chars
	'\t', '\n', '\r', // Whitespace (space is allowed with limit)
	'!', '@', '#', '^', // Special chars (part 1) - $ kept for templates
	'*', '(', ')', '~', '`', // Special chars (part 2) - +, = kept for query strings
	'|', ';', // Delimiters - <, > kept for Flask templates
}

// isGarbageChar checks if byte is a garbage character.
func isGarbageChar(c byte) bool {
	for _, gc := range garbageChars {
		if c == gc {
			return true
		}
	}
	return false
}

// Unbalanced bracket chars to trim from segment edges.
var unbalancedBracketChars = [...]byte{
	'[', ']', '{', '}', '<', '>',
}

// isUnbalancedBracketChar checks if byte is a bracket character.
func isUnbalancedBracketChar(c byte) bool {
	for _, bc := range unbalancedBracketChars {
		if c == bc {
			return true
		}
	}
	return false
}

// trimUnbalancedBrackets removes unbalanced bracket chars from segment edges.
// Only trims if the segment has unbalanced brackets overall.
// If balanced (e.g., [id], {param}), returns unchanged.
//
// Examples:
//   - "plain]" → "plain" (unbalanced, trim ])
//   - "]" → "" (unbalanced, becomes empty)
//   - "[invalid" → "invalid" (unbalanced, trim [)
//   - "]]test[[" → "test" (unbalanced, trim all)
//   - "{foo" → "foo" (unbalanced, trim {)
//   - "[id]" → "[id]" (balanced, unchanged)
//   - "{param}" → "{param}" (balanced, unchanged)
func trimUnbalancedBrackets(seg string) string {
	// Check if brackets are balanced - if so, return unchanged
	if hasBalancedBrackets(seg) {
		return seg
	}

	// Trim unbalanced brackets from edges recursively
	for len(seg) > 0 {
		changed := false

		// Trim from start if it's a bracket
		if len(seg) > 0 && isUnbalancedBracketChar(seg[0]) {
			seg = seg[1:]
			changed = true
		}

		// Trim from end if it's a bracket
		if len(seg) > 0 && isUnbalancedBracketChar(seg[len(seg)-1]) {
			seg = seg[:len(seg)-1]
			changed = true
		}

		if !changed {
			break
		}
	}

	return seg
}

// hasBalancedBrackets checks if segment has balanced brackets.
func hasBalancedBrackets(seg string) bool {
	openSquare := strings.Count(seg, "[")
	closeSquare := strings.Count(seg, "]")
	openCurly := strings.Count(seg, "{")
	closeCurly := strings.Count(seg, "}")
	openAngle := strings.Count(seg, "<")
	closeAngle := strings.Count(seg, ">")

	if openSquare != closeSquare || openCurly != closeCurly || openAngle != closeAngle {
		return false
	}

	// Also check proper ordering (opening before closing)
	if openSquare > 0 && strings.Index(seg, "[") > strings.LastIndex(seg, "]") {
		return false
	}
	if openCurly > 0 && strings.Index(seg, "{") > strings.LastIndex(seg, "}") {
		return false
	}
	if openAngle > 0 && strings.Index(seg, "<") > strings.LastIndex(seg, ">") {
		return false
	}

	return true
}

// sanitizeDecodedSegments cleans decoded path segments by removing garbage.
// Returns cleaned path or empty string if no valid segments remain.
//
// For each segment:
//  1. Skip relative path markers (. and ..)
//  2. Remove all garbage chars (escape, whitespace, special)
//  3. Skip if no alphanumeric content remains
//  4. Rejoin valid segments
//
// Special case: "/" (root path) is preserved as-is.
func sanitizeDecodedSegments(path string) string {
	// Preserve root path
	if path == "/" {
		return "/"
	}

	segments := strings.Split(path, "/")
	result := make([]string, 0, len(segments))
	hasValidSegment := false

	for _, seg := range segments {
		if seg == "" {
			result = append(result, "")
			continue
		}

		// Skip relative path markers - not useful for discovery
		if seg == "." || seg == ".." {
			continue
		}

		// Remove garbage chars
		cleaned := removeGarbageChars(seg)

		// Trim unbalanced brackets from edges (e.g., "plain]" → "plain")
		cleaned = trimUnbalancedBrackets(cleaned)

		// Check space limit - if > maxSpacesPerSegment, reject entire path
		if countSpaces(cleaned) > maxSpacesPerSegment {
			return "" // Reject path
		}

		// Check for segment starting with '+' (garbage from JS concatenation)
		if startsWithPlus(cleaned) {
			return "" // Reject path
		}

		// Skip if no alphanumeric content
		if cleaned == "" || !hasAlphanumeric(cleaned) {
			continue
		}

		result = append(result, cleaned)
		hasValidSegment = true
	}

	// No valid segments found (only garbage segments)
	if !hasValidSegment {
		return ""
	}

	return strings.Join(result, "/")
}

// removeGarbageChars removes all garbage characters from string.
func removeGarbageChars(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if !isGarbageChar(s[i]) {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// hasAlphanumeric checks if string contains at least one a-zA-Z0-9.
func hasAlphanumeric(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			return true
		}
	}
	return false
}

// countSpaces returns the number of space characters in a string.
func countSpaces(s string) int {
	count := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			count++
		}
	}
	return count
}

// startsWithPlus checks if segment starts with '+'.
// Segments starting with '+' are garbage from JS concatenation in regex extraction.
// Example garbage: "+t[n.image]", "+[id]", "+test"
func startsWithPlus(seg string) bool {
	return len(seg) > 0 && seg[0] == '+'
}
