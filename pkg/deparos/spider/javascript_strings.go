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
// - Event handler parser (hjn.java)
// - Script content parser (r6.java)
//
// Burp mapping: eba.java (JavaScript string parser) + c13.java (usage pattern)
type JavaScriptStringExtractor struct {
	inlineScanner *InlineURLScanner
	htmlExtractor *HTMLAttributeExtractor
}

// JSString represents a JavaScript string literal with its position.
// Burp mapping: fdl.java
type JSString struct {
	Value    string // fdl.a - The string content
	Position int    // fdl.b - The position in the source
}

// parserMode indicates the current parsing state.
// Burp mapping: eba.java var6/var5
type parserMode byte

const (
	modeDoubleQuote  parserMode = 0 // var6 = 0: Double quote string
	modeSingleQuote  parserMode = 1 // var6 = 1: Single quote string
	modeNormal       parserMode = 2 // var6 = 2: Normal (not in string/comment)
	modeLineComment  parserMode = 3 // var6 = 3: Line comment //
	modeBlockComment parserMode = 4 // var6 = 4: Block comment /* */
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
//
// Burp mapping: eba.a(String var0, int var1, int var2) - Lines 9-124
func (e *JavaScriptStringExtractor) ExtractStrings(jsCode string, offset int) []*JSString {
	return e.extractStringsFromRange(jsCode, 0, len(jsCode), offset)
}

// extractStringsFromRange extracts strings from a specific range.
//
// Burp mapping: eba.a(String var0, int var1, int var2) - Lines 9-124
func (e *JavaScriptStringExtractor) extractStringsFromRange(jsCode string, start, end, offset int) []*JSString {
	result := make([]*JSString, 0, 50)
	pos := start

	for pos < end {
		// Find the next string or comment delimiter
		// Burp mapping: Lines 14-62 (while var5 < var2)
		mode := modeNormal

		// Scan for delimiter
		// Burp mapping: Lines 19-57
		for pos < end {
			ch := jsCode[pos]

			// Check for single quote
			// Burp mapping: Lines 25-30
			if ch == '\'' {
				mode = modeSingleQuote
				break
			}

			// Check for double quote
			// Burp mapping: Lines 32-37
			if ch == '"' {
				mode = modeDoubleQuote
				break
			}

			// Check for line comment //
			// Burp mapping: Lines 39-44
			if pos+1 < end && ch == '/' && jsCode[pos+1] == '/' {
				mode = modeLineComment
				break
			}

			// Check for block comment /* */
			// Burp mapping: Lines 46-51
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
		// Burp mapping: Line 65: int var12 = ++var5
		pos++
		stringStart := pos

		// Find the closing delimiter
		// Burp mapping: Lines 67-87
		for pos < end {
			ch := jsCode[pos]

			// Handle escape sequences
			// Burp mapping: Lines 69-74
			if ch == '\\' {
				pos += 2 // Skip backslash and next character
				if pos > end {
					break
				}
				continue
			}

			// Check for closing delimiter based on mode
			// Burp mapping: Lines 76-81
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
		// Burp mapping: Lines 93-95
		if mode == modeSingleQuote || mode == modeDoubleQuote {
			value := jsCode[stringStart:pos]
			result = append(result, &JSString{
				Value:    value,
				Position: offset + stringStart,
			})
		}

		// Advance past the closing delimiter
		// Burp mapping: Lines 97-106
		if mode == modeBlockComment {
			pos += 2 // Skip */
		} else {
			pos++
		}
	}

	return result
}

// ScanStringForURLs scans a JavaScript string for URLs using the inline scanner.
// Returns true if a URL was found.
//
// This is a helper used by extractors to check if a string contains URLs
// before attempting HTML parsing.
//
// Burp mapping: c13.java line 21 (inline scanner check)
func (e *JavaScriptStringExtractor) ScanStringForURLs(ctx context.Context, baseURL *url.URL, str string, position int) bool {
	if len(str) < 10 {
		return false
	}

	return e.inlineScanner.ScanBytes(ctx, baseURL, []byte(str), position)
}

// LooksLikeHTML performs a simple heuristic check to see if a string looks like HTML.
//
// Burp mapping: c13.java line 22 (dje.a(var9, 0) == 256)
// The Burp code checks if the content type is HTML (256).
// We use a simple heuristic: contains < and >
func (e *JavaScriptStringExtractor) LooksLikeHTML(str string) bool {
	// Simple heuristic: contains < and > which suggests HTML tags
	return strings.Contains(str, "<") && strings.Contains(str, ">")
}

// Extract implements the LinkExtractor interface.
// This is NOT typically called directly - instead, other extractors
// (event handlers, script content) use ExtractStrings() and scan each string.
//
// However, we provide this for completeness and testing.
//
// Burp mapping: c13.java lines 14-33
func (e *JavaScriptStringExtractor) Extract(ctx context.Context, baseURL *url.URL, response *HTTPResponse, callback LinkCallback) error {
	// Extract all string literals
	strings := e.ExtractStrings(string(response.Body), response.BodyStart)

	for _, str := range strings {
		// Skip short strings (< 10 chars)
		// Burp mapping: c13.java line 19
		if len(str.Value) < 10 {
			continue
		}

		// First, scan for inline URLs
		// Burp mapping: c13.java line 21
		// this.b.a(var1, var9, var3 + var7.b, (byte)3, var4)
		foundURL := e.ScanStringForURLs(ctx, baseURL, str.Value, str.Position)
		if foundURL {
			// URL found and processed by inline scanner
			continue
		}

		// If no URL found, check if string looks like HTML
		// Burp mapping: c13.java line 22
		// if (var10 == null && dje.a(var9, 0) == 256)
		if e.LooksLikeHTML(str.Value) {
			// Parse as HTML and extract links
			// Burp mapping: c13.java lines 23-24
			// List var11 = bql.a(var9, 0, var9.length, (byte)0);
			// this.a.a(var1, var11, var3 + var7.b, var4);

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
