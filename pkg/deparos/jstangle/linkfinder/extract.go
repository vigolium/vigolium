package linkfinder

import (
	"encoding/base64"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// extractRawPaths extracts raw paths from data using all regex patterns.
// Returns a map of unique paths (deduplication).
func extractRawPaths(data string) map[string]struct{} {
	// Preprocess body
	data = preprocessBody(data)

	// Use map for deduplication
	seen := make(map[string]struct{})

	// Extract backticks first (before unescaping)
	extractFromBackticks(data, seen)

	// Unescape body
	data = unescapeBody(data)

	// Extract using all methods
	extractUsingURLRegex(data, seen)
	extractUsingJSPatterns(data, seen)
	extractUsingLinkfinder(data, seen)
	extractUsingHTMLHref(data, seen)
	extractUsingWindowOpen(data, seen)
	extractFromQuotes(data, seen)

	return seen
}

// preprocessBody performs preprocessing to reduce noise.
func preprocessBody(body string) string {
	if body == "" {
		return body
	}

	// Remove import/require/export statements (single combined pattern). The
	// regex can only match when one of these keywords is literally present, so a
	// cheap substring check avoids a full-body regex scan on bodies that have none.
	if strings.Contains(body, "import") || strings.Contains(body, "require") || strings.Contains(body, "export") {
		body = jsImportExportPattern.ReplaceAllString(body, `"PLACEHOLDER"`)
	}

	// Remove bundled language dictionaries — the pattern always begins with "./".
	if strings.Contains(body, `"./`) {
		body = bundledLanguagePattern.ReplaceAllString(body, "")
	}

	// Remove file comments. Only pay the full-body Split + Join (a copy plus a
	// per-line slice) when a marker line is actually present — the overwhelming
	// majority of bodies carry neither marker.
	if strings.Contains(body, "//[file:") || strings.Contains(body, "For license information please see") {
		lines := strings.Split(body, "\n")
		filtered := lines[:0]
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//[file:") {
				continue
			}
			if strings.Contains(trimmed, "For license information please see") {
				continue
			}
			filtered = append(filtered, line)
		}
		body = strings.Join(filtered, "\n")
	}

	return body
}

// unescapeBody performs multiple unescaping operations.
func unescapeBody(body string) string {
	// Try to decode base64 (only if looks like base64)
	if len(body) > 100 && len(body) < 10000 && !strings.Contains(body, " ") {
		if decoded, err := base64.StdEncoding.DecodeString(body); err == nil {
			body = string(decoded)
		}
	}

	// HTML unescape (html.UnescapeString self-short-circuits, returning body
	// unchanged with no copy when there is no '&').
	body = html.UnescapeString(body)

	// JSON / escape-char replacement. Every remaining target contains a
	// backslash, a backtick, or a percent sign, so one presence check per group
	// skips the whole group — including its Count scans — when that escape char
	// is absent, which is the common case for already-clean bodies. Order within
	// each group is preserved (e.g. \" before \\).
	if strings.IndexByte(body, '\\') >= 0 {
		body = strings.ReplaceAll(body, `\"`, `"`)
		body = strings.ReplaceAll(body, `\\`, `\`)
		body = strings.ReplaceAll(body, `\/`, `/`)
		body = strings.ReplaceAll(body, `\.`, `.`)
		body = strings.ReplaceAll(body, `\:`, `:`)
		body = strings.ReplaceAll(body, `\;`, `;`)
	}
	if strings.IndexByte(body, '`') >= 0 {
		body = strings.ReplaceAll(body, "`", "")
	}
	if strings.Contains(body, "%5") {
		body = strings.ReplaceAll(body, "%5cn", "")
		body = strings.ReplaceAll(body, "%5Cn", "")
		body = strings.ReplaceAll(body, "%5cr", "")
		body = strings.ReplaceAll(body, "%5Cr", "")
	}

	return body
}

// extractFromBackticks extracts strings from backtick-quoted content.
func extractFromBackticks(data string, seen map[string]struct{}) {
	processMatchesForPatterns(stringInBackticks, data, seen)
}

// extractFromQuotes extracts strings from quoted content.
func extractFromQuotes(data string, seen map[string]struct{}) {
	processMatchesForPatterns(stringInDoubleQuotes, data, seen)
	processMatchesForPatterns(stringInSingleQuotes, data, seen)
}

// processMatchesForPatterns processes pattern matches.
func processMatchesForPatterns(pattern *regexp.Regexp, data string, seen map[string]struct{}) {
	matches := pattern.FindAllStringSubmatch(data, -1)
	for _, match := range matches {
		i := pattern.SubexpIndex("href")
		if i <= 0 || i >= len(match) || match[i] == "" {
			continue
		}

		link := strings.TrimSpace(match[i])

		// Skip if contains space or pipe
		if strings.Contains(link, " ") || strings.Contains(link, "|") {
			continue
		}

		// Template variables with paths: {baseUrl}/index?id=1
		if strings.HasPrefix(link, "{") && strings.Contains(link, "/") && validateEnclosurePairs(link) {
			seen[link] = struct{}{}
			continue
		}

		// Query string patterns: index?id=value
		if startsWithAlphabets(link) && strings.Contains(link, "?") && strings.Contains(link, "=") {
			seen[link] = struct{}{}
			continue
		}

		// Root-relative paths: "/apex/APP_Login_NewCaptcha?source=x", "/register?ref=y".
		// These appear as quoted attribute/route strings in framework payloads
		// (Salesforce Aura component defs, SPA route tables) and were previously
		// dropped unless they had 2+ slashes or an api/ marker — so a single-segment
		// route with a reflected query param was lost. shouldKeepMatch downstream
		// still prunes junk like a bare "/".
		if strings.HasPrefix(link, "/") && !strings.HasPrefix(link, "//") && len(link) > 1 {
			seen[link] = struct{}{}
			continue
		}

		// Multiple slashes indicate path
		if strings.Count(link, "/") > 1 {
			seen[link] = struct{}{}
			continue
		}

		// API-like patterns
		if strings.Contains(link, "api/") || strings.Contains(link, "v1/") ||
			strings.Contains(link, "v2/") || strings.Contains(link, "v3/") ||
			strings.Contains(link, "v4/") || strings.Contains(link, "rest/") {
			seen[link] = struct{}{}
			continue
		}
	}
}

// extractUsingURLRegex extracts direct HTTP(S) URLs.
func extractUsingURLRegex(data string, seen map[string]struct{}) {
	matches := urlRegex.FindAllStringSubmatch(data, -1)
	for _, match := range matches {
		if len(match) > 1 && match[1] != "" {
			path := strings.TrimSpace(match[1])
			seen[path] = struct{}{}
		}
	}
}

// extractUsingJSPatterns extracts using JavaScript-specific patterns.
// Uses 4 merged patterns instead of 14 original patterns for performance.
func extractUsingJSPatterns(data string, seen map[string]struct{}) {
	patterns := []*regexp.Regexp{
		jsHTTPMethodPattern,
		jsPropertyPattern,
		jsVariablePattern,
		jsAttributePattern,
	}

	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(data, -1)
		for _, match := range matches {
			// Extract from named groups: href, href1, href2, href3, etc.
			for i, name := range pattern.SubexpNames() {
				if strings.HasPrefix(name, "href") && i < len(match) && match[i] != "" {
					path := strings.TrimSpace(match[i])
					seen[path] = struct{}{}
				}
			}
		}
	}
}

// extractUsingLinkfinder extracts using LinkFinder-style pattern.
func extractUsingLinkfinder(data string, seen map[string]struct{}) {
	matches := linkfdPattern.FindAllStringSubmatch(data, -1)
	for _, match := range matches {
		if len(match) > 1 {
			path := filterNewLines(match[1])
			if path == "" {
				continue
			}
			path = html.UnescapeString(strings.Trim(path, `\`))
			path = strings.TrimSuffix(path, ",")
			path = strings.ReplaceAll(path, "`", "")
			seen[path] = struct{}{}
		}
	}
}

// extractUsingHTMLHref extracts from HTML href/src/action attributes.
func extractUsingHTMLHref(data string, seen map[string]struct{}) {
	matches := htmlHrefPattern.FindAllStringSubmatch(data, -1)
	for _, match := range matches {
		i := htmlHrefPattern.SubexpIndex("href")
		if i > 0 && i < len(match) && match[i] != "" {
			path := strings.TrimSpace(match[i])
			seen[path] = struct{}{}
		}
	}
}

// extractUsingWindowOpen extracts URLs from window.open() calls.
func extractUsingWindowOpen(data string, seen map[string]struct{}) {
	matches := windowOpenRegex.FindAllStringSubmatch(data, -1)
	for _, match := range matches {
		i := windowOpenRegex.SubexpIndex("href")
		if i > 0 && i < len(match) && match[i] != "" {
			path := strings.TrimSpace(match[i])
			seen[path] = struct{}{}
		}
	}
}
