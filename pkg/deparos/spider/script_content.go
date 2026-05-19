package spider

import (
	"context"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// ScriptContentExtractor extracts URLs from <script> tag content.
//
// Scans JavaScript code for:
//   - Inline URLs (http://, https://, etc.)
//   - JavaScript string literals
type ScriptContentExtractor struct {
	inlineScanner *InlineURLScanner
	jsExtractor   *JavaScriptStringExtractor
}

// NewScriptContentExtractor creates a new script content extractor.
func NewScriptContentExtractor(inlineScanner *InlineURLScanner, jsExtractor *JavaScriptStringExtractor) *ScriptContentExtractor {
	return &ScriptContentExtractor{
		inlineScanner: inlineScanner,
		jsExtractor:   jsExtractor,
	}
}

// Extract examines HTML content and reports URLs found in <script> tag content.
func (e *ScriptContentExtractor) Extract(ctx context.Context, baseURL *url.URL, response *HTTPResponse, callback LinkCallback) error {
	// Ensure HTML is parsed (cached with sync.Once)
	if response.HTML == nil {
		return nil // Not HTML or parse failed
	}

	doc := response.HTML

	// Traverse DOM recursively
	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.ElementNode {
			tagName := strings.ToLower(n.Data)

			// Look for script tags and extract their content
			if tagName == "script" {
				// Get text content of script tag
				scriptContent := getScriptContent(n)
				if scriptContent != "" {
					// Scan for JavaScript strings
					jsStrings := e.jsExtractor.ExtractStrings(scriptContent, response.BodyStart)
					for _, jsStr := range jsStrings {
						// Check for inline URLs in string
						e.inlineScanner.ScanBytes(ctx, baseURL, []byte(jsStr.Value), jsStr.Position)
					}

					// Also scan script content directly for inline URLs
					// Intentionally ignore error - nested extraction failures shouldn't stop parent extractor
					_ = e.inlineScanner.Extract(ctx, baseURL, &HTTPResponse{
						Body:      []byte(scriptContent),
						BodyStart: response.BodyStart,
						URL:       baseURL,
					}, callback)
				}
			}
		}

		// Traverse children
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}

	traverse(doc)
	return nil
}

// getScriptContent extracts all text content from a script element.
func getScriptContent(n *html.Node) string {
	var content strings.Builder
	var traverse func(*html.Node)
	traverse = func(node *html.Node) {
		if node.Type == html.TextNode {
			content.WriteString(node.Data)
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}
	traverse(n)
	return content.String()
}

// Ensure ScriptContentExtractor implements LinkExtractor
var _ LinkExtractor = (*ScriptContentExtractor)(nil)
