package wordlist

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"

	"golang.org/x/net/html"
)

// HTMLPreprocessor extracts text content from HTML, stripping tags and decoding entities.
type HTMLPreprocessor struct{}

// Process extracts text content from HTML.
// It strips all tags and decodes HTML entities.
// Script and style tag contents are preserved for separate JS/CSS extraction.
func (p *HTMLPreprocessor) Process(_ context.Context, reader io.Reader) (io.Reader, error) {
	tokenizer := html.NewTokenizer(reader)
	var output bytes.Buffer

	// Track if we're inside script or style tags
	var inScript, inStyle bool

	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			err := tokenizer.Err()
			if errors.Is(err, io.EOF) {
				break
			}
			// Continue processing on parse errors
			break
		}

		switch tt {
		case html.StartTagToken, html.SelfClosingTagToken:
			tagName, _ := tokenizer.TagName()
			tagNameStr := strings.ToLower(string(tagName))

			switch tagNameStr {
			case "script":
				inScript = true
			case "style":
				inStyle = true
			}

			// Extract attribute values as potential words
			for {
				key, val, more := tokenizer.TagAttr()
				if len(val) > 0 {
					// Skip common non-word attributes
					keyStr := string(key)
					if !isSkippableAttribute(keyStr) {
						// Decode HTML entities in attribute values
						decoded := html.UnescapeString(string(val))
						output.WriteString(decoded)
						output.WriteByte(' ')
					}
				}
				if !more {
					break
				}
			}

		case html.EndTagToken:
			tagName, _ := tokenizer.TagName()
			tagNameStr := strings.ToLower(string(tagName))

			switch tagNameStr {
			case "script":
				inScript = false
			case "style":
				inStyle = false
			}

		case html.TextToken:
			text := tokenizer.Text()
			if len(text) == 0 {
				continue
			}

			// Include script/style content for JS/CSS word extraction
			if inScript || inStyle {
				output.Write(text)
				output.WriteByte(' ')
				continue
			}

			// Decode HTML entities
			decoded := html.UnescapeString(string(text))
			// Trim and add space
			trimmed := strings.TrimSpace(decoded)
			if len(trimmed) > 0 {
				output.WriteString(trimmed)
				output.WriteByte(' ')
			}

		case html.CommentToken:
			// Extract comment content as potential hidden info
			comment := tokenizer.Text()
			if len(comment) > 0 {
				output.Write(comment)
				output.WriteByte(' ')
			}
		}
	}

	return bytes.NewReader(output.Bytes()), nil
}

// ContentTypes returns the MIME types handled by this preprocessor.
func (p *HTMLPreprocessor) ContentTypes() []string {
	return []string{
		"/html",
		"/xhtml+xml",
	}
}

// isSkippableAttribute returns true for attributes that typically don't contain useful words.
func isSkippableAttribute(attr string) bool {
	skip := map[string]struct{}{
		"style":  {},
		"width":  {},
		"height": {},
		"xmlns":  {},
		"lang":   {},
		"dir":    {},
	}
	_, ok := skip[strings.ToLower(attr)]
	return ok
}
