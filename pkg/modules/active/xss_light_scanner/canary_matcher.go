package xss_light_scanner

import (
	"bytes"
	"sort"
	"strconv"
	"strings"
)

// MatchMode represents encoding detection mode
type MatchMode int

const (
	MatchSimple MatchMode = iota
	MatchHTMLDecode
	MatchBackslashUnescape
	MatchBoth
)

func (m MatchMode) String() string {
	switch m {
	case MatchSimple:
		return "simple"
	case MatchHTMLDecode:
		return "html_decode"
	case MatchBackslashUnescape:
		return "backslash_unescape"
	case MatchBoth:
		return "both"
	default:
		return "unknown"
	}
}

// CanaryMatch represents a found canary match in the response
type CanaryMatch struct {
	StartOffset   int
	EndOffset     int
	MatchedBytes  []byte
	DetectionMode MatchMode
}

// EncodingAwareCanaryMatcher finds canary payloads with encoding awareness
type EncodingAwareCanaryMatcher struct {
	payload *CanaryPayload
}

// NewEncodingAwareCanaryMatcher creates a new matcher
func NewEncodingAwareCanaryMatcher(payload *CanaryPayload) *EncodingAwareCanaryMatcher {
	return &EncodingAwareCanaryMatcher{payload: payload}
}

// FindAllMatches finds all reflections of the canary payload in response
func (m *EncodingAwareCanaryMatcher) FindAllMatches(responseBody []byte) []*CanaryMatch {
	var allMatches []*CanaryMatch

	modes := []MatchMode{MatchSimple, MatchHTMLDecode, MatchBackslashUnescape, MatchBoth}
	for _, mode := range modes {
		matches := m.findMatchesWithMode(responseBody, mode)
		allMatches = append(allMatches, matches...)
	}

	// Sort by offset
	sort.Slice(allMatches, func(i, j int) bool {
		return allMatches[i].StartOffset < allMatches[j].StartOffset
	})

	return m.removeDuplicates(allMatches)
}

func (m *EncodingAwareCanaryMatcher) findMatchesWithMode(responseBody []byte, mode MatchMode) []*CanaryMatch {
	var matches []*CanaryMatch
	pattern := []byte(m.payload.FullPayload)

	// For MatchSimple: offset is same, extract directly
	if mode == MatchSimple {
		searchFrom := 0
		for searchFrom <= len(responseBody)-len(pattern) {
			offset := bytes.Index(responseBody[searchFrom:], pattern)
			if offset == -1 {
				break
			}

			actualOffset := searchFrom + offset
			endOffset := actualOffset + len(pattern)
			matchedBytes := make([]byte, len(pattern))
			copy(matchedBytes, responseBody[actualOffset:endOffset])

			matches = append(matches, &CanaryMatch{
				StartOffset:   actualOffset,
				EndOffset:     endOffset,
				MatchedBytes:  matchedBytes,
				DetectionMode: mode,
			})
			searchFrom = actualOffset + 1
		}
		return matches
	}

	// For transformed modes: need to map offset back to original
	var searchSpace []byte
	switch mode {
	case MatchHTMLDecode:
		searchSpace = htmlDecode(responseBody)
	case MatchBackslashUnescape:
		searchSpace = backslashUnescape(responseBody)
	case MatchBoth:
		searchSpace = backslashUnescape(htmlDecode(responseBody))
	}

	searchFrom := 0
	for searchFrom <= len(searchSpace)-len(pattern) {
		offset := bytes.Index(searchSpace[searchFrom:], pattern)
		if offset == -1 {
			break
		}

		transformedOffset := searchFrom + offset

		// Map offset back to original responseBody
		actualOffset := mapToOriginalOffset(responseBody, transformedOffset, mode)

		// Find end in original (consume len(pattern) transformed chars)
		endOffset := findMatchEndInOriginal(responseBody, actualOffset, len(pattern), mode)

		// Extract matchedBytes from ORIGINAL responseBody (contains escape sequences!)
		if endOffset > len(responseBody) {
			endOffset = len(responseBody)
		}
		matchedBytes := make([]byte, endOffset-actualOffset)
		copy(matchedBytes, responseBody[actualOffset:endOffset])

		matches = append(matches, &CanaryMatch{
			StartOffset:   actualOffset,
			EndOffset:     endOffset,
			MatchedBytes:  matchedBytes,
			DetectionMode: mode,
		})
		searchFrom = transformedOffset + 1
	}

	return matches
}

// mapToOriginalOffset maps offset from transformed space back to original responseBody
// Uses character-by-character mapping to account for escape sequences
func mapToOriginalOffset(original []byte, transformedOffset int, mode MatchMode) int {
	origIdx := 0
	transIdx := 0

	for transIdx < transformedOffset && origIdx < len(original) {
		origLen, transLen := getCharMapping(original, origIdx, mode)
		if transIdx+transLen > transformedOffset {
			// Partial match within an escape sequence
			break
		}
		origIdx += origLen
		transIdx += transLen
	}

	return origIdx
}

// getCharMapping returns (original length, transformed length) for char at offset
// Example: \' in original → ' in transformed = (2, 1)
// Example: &lt; in original → < in transformed = (4, 1)
func getCharMapping(data []byte, offset int, mode MatchMode) (int, int) {
	switch mode {
	case MatchBackslashUnescape:
		return getBackslashCharMapping(data, offset)

	case MatchHTMLDecode:
		return getHTMLCharMapping(data, offset)

	case MatchBoth:
		// HTML entities have priority (processed first in transform)
		if data[offset] == '&' {
			entityLen := findEntityLength(data, offset)
			if entityLen > 0 {
				return entityLen, 1
			}
		}
		// Then backslash escapes
		return getBackslashCharMapping(data, offset)
	}

	return 1, 1
}

// getBackslashCharMapping returns mapping for backslash escape sequences
func getBackslashCharMapping(data []byte, offset int) (int, int) {
	if offset+1 < len(data) && data[offset] == '\\' {
		next := data[offset+1]
		switch next {
		case '"', '\'', '`', '\\', '/', 'n', 'r', 't':
			return 2, 1 // 2 chars in original → 1 char in transformed
		}
	}
	return 1, 1
}

// getHTMLCharMapping returns mapping for HTML entities
func getHTMLCharMapping(data []byte, offset int) (int, int) {
	if data[offset] == '&' {
		entityLen := findEntityLength(data, offset)
		if entityLen > 0 {
			return entityLen, 1 // N chars entity → 1 char
		}
	}
	return 1, 1
}

// findMatchEndInOriginal finds end offset in original after consuming patternLen transformed chars
func findMatchEndInOriginal(original []byte, startOffset int, patternLen int, mode MatchMode) int {
	origIdx := startOffset
	transCount := 0

	for origIdx < len(original) && transCount < patternLen {
		origLen, transLen := getCharMapping(original, origIdx, mode)
		origIdx += origLen
		transCount += transLen
	}

	return origIdx
}

// findEntityLength returns the length of HTML entity at offset, or 0 if not an entity
func findEntityLength(data []byte, offset int) int {
	if offset >= len(data) || data[offset] != '&' {
		return 0
	}

	// Check named entities (order matters - longer first to avoid partial match)
	namedEntities := []string{
		"&dollar;", "&grave;", "&quot;", "&apos;", "&amp;", "&lt;", "&gt;",
		// Without semicolon (malformed but still decoded)
		"&dollar", "&grave", "&quot", "&apos", "&amp", "&lt", "&gt",
	}
	for _, ent := range namedEntities {
		if offset+len(ent) <= len(data) && string(data[offset:offset+len(ent)]) == ent {
			return len(ent)
		}
	}

	// Check numeric entities: &#39; &#x27; etc.
	if offset+3 < len(data) && data[offset+1] == '#' {
		endIdx := offset + 2
		for endIdx < len(data) && endIdx < offset+12 { // max reasonable entity length
			if data[endIdx] == ';' {
				return endIdx - offset + 1
			}
			endIdx++
		}
	}

	return 0
}

// htmlDecode decodes common HTML entities
func htmlDecode(data []byte) []byte {
	str := string(data)

	// Standard entities with semicolon
	replacements := []struct{ old, new string }{
		{"&lt;", "<"},
		{"&gt;", ">"},
		{"&quot;", "\""},
		{"&apos;", "'"},
		{"&grave;", "`"},
		{"&dollar;", "$"},
		{"&#39;", "'"},
		{"&#x27;", "'"},
		{"&#96;", "`"},
		{"&#x60;", "`"},
		{"&amp;", "&"},
		// Malformed entities without semicolon
		{"&dollar", "$"},
		{"&apos", "'"},
		{"&lt", "<"},
		{"&gt", ">"},
		{"&quot", "\""},
		{"&amp", "&"},
	}

	for _, r := range replacements {
		str = strings.ReplaceAll(str, r.old, r.new)
	}

	str = decodeNumericEntities(str)

	return []byte(str)
}

// decodeNumericEntities decodes numeric HTML entities: &#97; or &#x61;
func decodeNumericEntities(str string) string {
	var result strings.Builder
	i := 0

	for i < len(str) {
		if str[i] == '&' && i+2 < len(str) && str[i+1] == '#' {
			semicolonPos := strings.Index(str[i+2:], ";")
			if semicolonPos != -1 && semicolonPos <= 8 {
				entityCode := str[i+2 : i+2+semicolonPos]
				var codePoint int64
				var err error

				if len(entityCode) > 0 && (entityCode[0] == 'x' || entityCode[0] == 'X') {
					codePoint, err = strconv.ParseInt(entityCode[1:], 16, 32)
				} else {
					codePoint, err = strconv.ParseInt(entityCode, 10, 32)
				}

				if err == nil && codePoint >= 0 && codePoint <= 0x10FFFF {
					result.WriteRune(rune(codePoint))
					i = i + 2 + semicolonPos + 1
					continue
				}
			}
		}

		result.WriteByte(str[i])
		i++
	}

	return result.String()
}

// backslashUnescape unescapes backslash sequences
func backslashUnescape(data []byte) []byte {
	str := string(data)
	var result strings.Builder
	i := 0

	for i < len(str) {
		if str[i] == '\\' && i+1 < len(str) {
			next := str[i+1]
			switch next {
			case '"':
				result.WriteByte('"')
			case '\'':
				result.WriteByte('\'')
			case '`':
				result.WriteByte('`')
			case '\\':
				result.WriteByte('\\')
			case '/':
				result.WriteByte('/')
			case 'n':
				result.WriteByte('\n')
			case 'r':
				result.WriteByte('\r')
			case 't':
				result.WriteByte('\t')
			default:
				result.WriteByte('\\')
				result.WriteByte(next)
			}
			i += 2
		} else {
			result.WriteByte(str[i])
			i++
		}
	}

	return []byte(result.String())
}

// removeDuplicates removes duplicate matches at same offset
func (m *EncodingAwareCanaryMatcher) removeDuplicates(matches []*CanaryMatch) []*CanaryMatch {
	var unique []*CanaryMatch
	lastOffset := -1

	for _, match := range matches {
		if match.StartOffset != lastOffset {
			unique = append(unique, match)
			lastOffset = match.StartOffset
		}
	}

	return unique
}

// FindCanaryMatches is a convenience function to find all canary matches
func FindCanaryMatches(body []byte, payload *CanaryPayload) []*CanaryMatch {
	matcher := NewEncodingAwareCanaryMatcher(payload)
	return matcher.FindAllMatches(body)
}

// ExtractPresentChars extracts which breakout characters are present in a match
func ExtractPresentChars(matchedBytes []byte, payload *CanaryPayload) map[byte]bool {
	presentChars := make(map[byte]bool)
	matchStr := string(matchedBytes)

	// Check breakout chars
	for _, ch := range BreakoutChars {
		segBefore := payload.GetSegmentBefore(ch)
		segAfter := payload.GetSegmentAfter(ch)
		expectedPattern := segBefore + string(ch) + segAfter

		if strings.Contains(matchStr, expectedPattern) {
			presentChars[ch] = true
		}
	}

	return presentChars
}
