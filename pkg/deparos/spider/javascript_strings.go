package spider

import (
	"bytes"
	"context"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// JavaScriptStringExtractor extracts string literals from JavaScript code
// and scans them for URLs (both inline and HTML-embedded).
//
// This is a SHARED component injected into multiple extractors:
// - Event handler parser
// - Script content parser
type JavaScriptStringExtractor struct {
	inlineScanner *InlineURLScanner
	htmlExtractor *HTMLAttributeExtractor
}

// JSString represents a JavaScript string literal with its position.
type JSString struct {
	Value    string // The string content
	Position int    // The position in the source
}

// parserMode indicates the current parsing state.
type parserMode byte

const (
	modeDoubleQuote  parserMode = 0 // Double quote string
	modeSingleQuote  parserMode = 1 // Single quote string
	modeNormal       parserMode = 2 // Normal (not in string/comment)
	modeLineComment  parserMode = 3 // Line comment //
	modeBlockComment parserMode = 4 // Block comment /* */
)

// NewJavaScriptStringExtractor creates a new JavaScript string extractor.
func NewJavaScriptStringExtractor(inlineScanner *InlineURLScanner, htmlExtractor *HTMLAttributeExtractor) *JavaScriptStringExtractor {
	return &JavaScriptStringExtractor{
		inlineScanner: inlineScanner,
		htmlExtractor: htmlExtractor,
	}
}

// ExtractStrings extracts string literals from JavaScript code.
// Returns a list of strings with their positions.
func (e *JavaScriptStringExtractor) ExtractStrings(jsCode string, offset int) []*JSString {
	return e.extractStringsFromRange(jsCode, 0, len(jsCode), offset)
}

// extractStringsFromRange extracts strings from a specific range.
func (e *JavaScriptStringExtractor) extractStringsFromRange(jsCode string, start, end, offset int) []*JSString {
	result := make([]*JSString, 0, 50)
	pos := start

	for pos < end {
		// Find the next string or comment delimiter
		mode := modeNormal

		// Scan for delimiter
		for pos < end {
			ch := jsCode[pos]

			// Check for single quote
			if ch == '\'' {
				mode = modeSingleQuote
				break
			}

			// Check for double quote
			if ch == '"' {
				mode = modeDoubleQuote
				break
			}

			// Check for line comment //
			if pos+1 < end && ch == '/' && jsCode[pos+1] == '/' {
				mode = modeLineComment
				break
			}

			// Check for block comment /* */
			if pos+1 < end && ch == '/' && jsCode[pos+1] == '*' {
				mode = modeBlockComment
				break
			}

			pos++
		}

		if pos >= end {
			break
		}

		// Advance past the opening delimiter and capture start position
		pos++
		stringStart := pos

		// Find the closing delimiter
		for pos < end {
			ch := jsCode[pos]

			// Handle escape sequences
			if ch == '\\' {
				pos += 2 // Skip backslash and next character
				if pos > end {
					break
				}
				continue
			}

			// Check for closing delimiter based on mode
			if (mode == modeSingleQuote && ch == '\'') ||
				(mode == modeDoubleQuote && ch == '"') ||
				(mode == modeLineComment && (ch == '\n' || ch == '\r')) ||
				(mode == modeBlockComment && pos+1 < end && ch == '*' && jsCode[pos+1] == '/') {
				break
			}

			pos++
		}

		if pos >= end {
			break
		}

		// Collect string literals (not comments)
		if mode == modeSingleQuote || mode == modeDoubleQuote {
			value := jsCode[stringStart:pos]
			result = append(result, &JSString{
				Value:    value,
				Position: offset + stringStart,
			})
		}

		// Advance past the closing delimiter
		if mode == modeBlockComment {
			pos += 2 // Skip */
		} else {
			pos++
		}
	}

	return result
}

// ScanStringForURLs scans a JavaScript string for URLs using the inline scanner.
// When callback is non-nil it emits any RELATIVE route it finds — absolute
// (scheme) URLs are deliberately left to the companion whole-value
// inlineScanner.Extract pass that every caller of this helper also runs, so we
// don't emit the same absolute URL twice. Returns true if the string contains
// ANY URL (absolute or relative), so the caller can skip redundant HTML parsing.
//
// This closes the fallback gap: relative routes in JS string literals (e.g.
// /admin, /api/users) were previously detected but never surfaced as links.
func (e *JavaScriptStringExtractor) ScanStringForURLs(ctx context.Context, baseURL *url.URL, str string, position int, callback LinkCallback) bool {
	if len(str) < 10 {
		return false
	}

	data := []byte(str)
	// Emit relative routes (the actual coverage gap). If one was found we already
	// know the string contains a URL, so skip the second (absolute-inclusive) scan.
	if e.inlineScanner.ScanBytesRelativeEmit(ctx, baseURL, data, position, callback) {
		return true
	}
	// No relative route — report whether the string contains an absolute URL for
	// the caller's skip-HTML-parse decision.
	return e.inlineScanner.ScanBytes(ctx, baseURL, data, position)
}

// LooksLikeHTML performs a simple heuristic check to see if a string looks like HTML.
// Uses a simple heuristic: contains < and >
func (e *JavaScriptStringExtractor) LooksLikeHTML(str string) bool {
	// Simple heuristic: contains < and > which suggests HTML tags
	return strings.Contains(str, "<") && strings.Contains(str, ">")
}

// Extract implements the LinkExtractor interface.
// This is NOT typically called directly - instead, other extractors
// (event handlers, script content) use ExtractStrings() and scan each string.
//
// However, we provide this for completeness and testing.
func (e *JavaScriptStringExtractor) Extract(ctx context.Context, baseURL *url.URL, response *HTTPResponse, callback LinkCallback) error {
	// Extract all string literals
	strings := e.ExtractStrings(string(response.Body), response.BodyStart)

	for _, str := range strings {
		// Skip short strings (< 10 chars)
		if len(str.Value) < 10 {
			continue
		}

		// First, scan for inline URLs (emit any discovered link via the callback).
		foundURL := e.ScanStringForURLs(ctx, baseURL, str.Value, str.Position, callback)
		if foundURL {
			// URL found, resolved, and emitted by the inline scanner.
			continue
		}

		// If no URL found, check if string looks like HTML
		if e.LooksLikeHTML(str.Value) {
			// Parse as HTML and extract links
			// Only parse if htmlExtractor is available
			if e.htmlExtractor != nil {
				// Parse HTML from string
				doc, err := html.Parse(bytes.NewReader([]byte(str.Value)))
				if err != nil {
					// Not valid HTML, skip
					continue
				}

				// Create temporary response with parsed HTML
				tempResp := &HTTPResponse{
					Body:      []byte(str.Value),
					BodyStart: str.Position,
					URL:       baseURL,
					HTML:      doc,
				}

				// Extract links from parsed HTML
				_ = e.htmlExtractor.Extract(ctx, baseURL, tempResp, callback)
			}
			continue
		}
	}

	return nil
}

// Ensure JavaScriptStringExtractor implements spider.LinkExtractor
var _ LinkExtractor = (*JavaScriptStringExtractor)(nil)
