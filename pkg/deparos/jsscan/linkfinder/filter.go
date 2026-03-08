package linkfinder

import "strings"

// cleanupMatch cleans up a matched string.
// Removes literal escape chars and trailing syntax noise.
func cleanupMatch(match string) string {
	// Remove literal escape characters
	match = strings.ReplaceAll(match, `\`, "")
	match = strings.ReplaceAll(match, "\t", "")
	match = strings.ReplaceAll(match, "\n", "")
	match = strings.ReplaceAll(match, "$", "")
	match = strings.ReplaceAll(match, "`", "")

	// Remove trailing syntax chars
	match = strings.TrimSuffix(match, "(")
	match = strings.TrimSuffix(match, ";")
	match = strings.TrimSuffix(match, ",")
	match = strings.TrimSuffix(match, "#")

	return strings.TrimSpace(match)
}

// shouldKeepMatch determines if a matched string should be kept.
func shouldKeepMatch(match string) bool {
	if match == "" {
		return false
	}

	// Check for only special chars
	if onlySpecialCharsPattern.MatchString(match) {
		return false
	}

	// Check for unusual characters
	if containsUnusualChars(match) {
		return false
	}

	// Check timezone pattern
	if timezonePattern.MatchString(match) {
		return false
	}

	// Filter hex escape sequences
	if strings.HasPrefix(match, "/\\x") || strings.HasPrefix(match, "\\x") {
		return false
	}

	// Filter relative paths that are too simple
	if match == "./" || match == "../" || match == "/./" || match == "/../" {
		return false
	}

	// Filter common JS bundle noise
	if strings.HasPrefix(match, "webpack/") || strings.HasPrefix(match, "polyfills") {
		return false
	}

	// Filter unbalanced or noise bracket patterns
	if hasUnbalancedOrNoiseBrackets(match) {
		return false
	}

	// Filter paths with invalid segments (regex patterns, malformed params)
	if hasInvalidSegments(match) {
		return false
	}

	// Filter root paths
	if match == "/" || match == "//" {
		return false
	}

	// Filter ignored prefixes
	if ignorePrefix.MatchString(match) {
		return false
	}

	// Filter node_modules
	if strings.Contains(match, "node_modules") {
		return false
	}

	// Check file extension
	ext := getExtensionOfPath(match)
	if ext != "" {
		extLower := strings.ToLower(ext)
		if unwantedExts[extLower] {
			return false
		}
	}

	// Check blacklist using Aho-Corasick O(n) matching
	if containsBlacklistedPattern(match) {
		return false
	}

	// Check spam patterns
	if isSpamPattern(match) {
		return false
	}

	// Check CSS/JS noise pattern (single combined regex)
	if cssValuePattern.MatchString(match) {
		return false
	}

	// Contains space or pipe
	if strings.Contains(match, " ") || strings.Contains(match, "|") {
		return false
	}
	// +t[...]
	if strings.Contains(match, "+") && (strings.Contains(match, "[") || strings.Contains(match, "]")) {
		return false
	}

	// Too short
	if len(match) < 2 {
		return false
	}

	// Too long
	if len(match) > 2000 {
		return false
	}

	// Filter URLs with dangerous encoded characters
	if dangerousEncodedPattern.MatchString(match) {
		return false
	}

	return true
}

// filterNewLines removes non-printable characters and trims whitespace.
func filterNewLines(s string) string {
	return nonPrintableRegex.ReplaceAllString(strings.TrimSpace(s), " ")
}

// getExtensionOfPath extracts file extension from a URL path.
func getExtensionOfPath(urlPath string) string {
	matches := reGetExtName.FindStringSubmatch(urlPath)
	if len(matches) > 1 {
		return strings.ToLower(strings.TrimSpace(matches[1]))
	}
	return ""
}

// startsWithAlphabets checks if string starts with a letter.
func startsWithAlphabets(s string) bool {
	if len(s) == 0 {
		return false
	}
	c := s[0]
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// validateEnclosurePairs validates nested braces like {baseUrl}.
func validateEnclosurePairs(link string) bool {
	if !strings.HasPrefix(link, "{") || !strings.HasSuffix(link, "}") {
		return false
	}
	nestedStart := strings.Index(link, "{")
	nestedEnd := strings.LastIndex(link, "}")
	return nestedStart != -1 && nestedEnd != -1 && nestedStart != nestedEnd
}

// containsUnusualChars checks if a string has unusual characters.
func containsUnusualChars(str string) bool {
	if str == "" {
		return false
	}

	// Skip leading slash
	str = strings.TrimPrefix(str, "/")
	if str == "" {
		return false
	}

	totalChars := len(str)
	unusualChars := 0

	for _, c := range str {
		// Check if character is outside printable ASCII range (32-126)
		if c < 32 || c > 126 {
			unusualChars++
		}
	}

	// If unusual character ratio > 5%, consider unusual
	ratio := float64(unusualChars) / float64(totalChars)
	return ratio > 0.05
}

// hasUnbalancedOrNoiseBrackets detects paths with unbalanced brackets or bracket noise.
// Valid: /users/[id], /api/{version}
// Invalid: /plain], /[, /], /[[[, /foo]bar, ]plan, text/plain]
func hasUnbalancedOrNoiseBrackets(path string) bool {
	openSquare := strings.Count(path, "[")
	closeSquare := strings.Count(path, "]")
	openCurly := strings.Count(path, "{")
	closeCurly := strings.Count(path, "}")

	// Unbalanced brackets = invalid
	if openSquare != closeSquare || openCurly != closeCurly {
		return true
	}

	// Check each segment for bracket issues
	for _, segment := range strings.Split(path, "/") {
		if segment == "" {
			continue
		}

		// Check for unbalanced brackets within segment
		segOpenSquare := strings.Count(segment, "[")
		segCloseSquare := strings.Count(segment, "]")
		segOpenCurly := strings.Count(segment, "{")
		segCloseCurly := strings.Count(segment, "}")

		if segOpenSquare != segCloseSquare || segOpenCurly != segCloseCurly {
			return true
		}

		// Segment with only brackets and no alphanumeric content
		hasAlphaNum := false
		for _, c := range segment {
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
				hasAlphaNum = true
				break
			}
		}
		if !hasAlphaNum && (strings.ContainsAny(segment, "[]{}")) {
			return true
		}
	}

	return false
}

// isSpamPattern detects spam-like patterns in strings.
// Uses 2 merged regex patterns + helper functions for performance.
func isSpamPattern(str string) bool {
	if str == "" {
		return false
	}

	checkStr := strings.TrimPrefix(str, "/")
	if checkStr == "" {
		return false
	}

	// Pattern 1+2+3: Spam char patterns (merged regex)
	// Detects: X_Y patterns, repeated underscores, 4+ consecutive special chars
	if spamCharPattern.MatchString(checkStr) {
		return true
	}

	// Pattern 4: High underscore + special char ratio (non-regex)
	if hasHighSpamCharRatio(checkStr) {
		return true
	}

	// Pattern 5: Unicode spam chars + special chars (non-regex)
	if hasUnicodeSpamChars(checkStr) && strings.ContainsAny(checkStr, "_<>=") {
		return true
	}

	// Pattern 6: HTML tags (merged regex)
	if htmlTagPattern.MatchString(str) {
		return true
	}

	return false
}

// hasUnicodeSpamChars checks for specific unicode spam characters.
// Replaces unicodeSpamPattern regex with O(n) rune iteration.
func hasUnicodeSpamChars(s string) bool {
	for _, r := range s {
		switch r {
		case '·', '¡', '£', 'ü', 'ë', 'è', 'Æ', '¿', 'ñ', 'Ý', 'Þ', '³', 'ý', 'ô', 'À', '×', 'í', 'Õ':
			return true
		}
	}
	return false
}

// hasHighSpamCharRatio checks for high underscore + special char ratio.
// Returns true if underscore ratio > 30% AND special char ratio > 10%.
func hasHighSpamCharRatio(s string) bool {
	if len(s) <= 5 {
		return false
	}

	underscoreCount := strings.Count(s, "_")
	specialCharCount := 0
	for _, c := range s {
		if strings.ContainsRune("!@#$%^&*()+=<>?.,;:", c) {
			specialCharCount++
		}
	}

	underscoreRatio := float64(underscoreCount) / float64(len(s))
	specialCharRatio := float64(specialCharCount) / float64(len(s))
	return underscoreRatio > 0.3 && specialCharRatio > 0.1
}

// isInvalidSegment checks if a path segment contains invalid patterns.
func isInvalidSegment(segment string) bool {
	if segment == "" {
		return false
	}

	// Regex metacharacter patterns (e.g., +((, .*, ++, (?=)
	if regexMetaPattern.MatchString(segment) {
		return true
	}

	// Comma-prefixed parameters (e.g., ,fn=)
	if commaStartPattern.MatchString(segment) {
		return true
	}

	// Unbalanced parentheses in segment
	if strings.Count(segment, "(") != strings.Count(segment, ")") {
		return true
	}

	return false
}

// hasInvalidSegments checks if any path segment contains invalid patterns.
func hasInvalidSegments(path string) bool {
	for _, segment := range strings.Split(path, "/") {
		if isInvalidSegment(segment) {
			return true
		}
	}
	return false
}

// IsSpamURL returns true if the URL path matches spam patterns and should be filtered out.
// This is used by the storage package to filter spam URLs when loading from database.
func IsSpamURL(urlPath string) bool {
	if urlPath == "" {
		return true
	}
	return !shouldKeepMatch(urlPath)
}
