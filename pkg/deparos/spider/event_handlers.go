package spider

import (
	"context"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// EventHandlersExtractor extracts URLs from HTML event handler attributes.
//
// Scans for event handlers like onclick, onload, onmouseover, etc. that contain:
//   - javascript: protocol URLs
//   - Inline URLs in JavaScript code
type EventHandlersExtractor struct {
	inlineScanner *InlineURLScanner
	jsExtractor   *JavaScriptStringExtractor
}

// NewEventHandlersExtractor creates a new event handlers extractor.
func NewEventHandlersExtractor(inlineScanner *InlineURLScanner, jsExtractor *JavaScriptStringExtractor) *EventHandlersExtractor {
	return &EventHandlersExtractor{
		inlineScanner: inlineScanner,
		jsExtractor:   jsExtractor,
	}
}

// Extract examines HTML content and reports URLs found in event handler attributes.
func (e *EventHandlersExtractor) Extract(ctx context.Context, baseURL *url.URL, response *HTTPResponse, callback LinkCallback) error {
	// Ensure HTML is parsed (cached with sync.Once)
	if response.HTML == nil {
		return nil // Not HTML or parse failed
	}

	doc := response.HTML

	// Traverse DOM recursively
	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.ElementNode {
			// Skip ASP.NET specific attributes (__VIEWSTATE, __EVENTVALIDATION)
			if e.shouldSkipElement(n) {
				// Skip traversal of children for this element
				return
			}

			// Extract URLs from event handler attributes
			e.extractFromElement(ctx, n, baseURL, response.BodyStart, callback)
		}

		// Traverse children
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}

	traverse(doc)
	return nil
}

// shouldSkipElement checks if element should be skipped (ASP.NET specific).
func (e *EventHandlersExtractor) shouldSkipElement(n *html.Node) bool {
	// Check for __VIEWSTATE or __EVENTVALIDATION attributes
	// These are ASP.NET specific and shouldn't be processed
	name := getAttr(n, "name")

	if strings.EqualFold(name, "__VIEWSTATE") {
		return true
	}

	if strings.EqualFold(name, "__EVENTVALIDATION") {
		return true
	}

	return false
}

// extractFromElement extracts URLs from event handler attributes of an element.
//
// Processes both "on*" event handlers and "javascript:" protocol attributes.
func (e *EventHandlersExtractor) extractFromElement(ctx context.Context, n *html.Node, baseURL *url.URL, bodyStart int, callback LinkCallback) {
	// Iterate over all attributes
	for _, attr := range n.Attr {
		attrName := strings.ToLower(attr.Key)
		attrValue := attr.Val

		// Check for "on*" event handler attributes
		if strings.HasPrefix(attrName, "on") {
			// Extract JavaScript code from event handler
			// Intentionally ignore error - nested extraction failures shouldn't stop parent extractor
			_ = e.jsExtractor.Extract(ctx, baseURL, &HTTPResponse{
				Body:      []byte(attrValue),
				BodyStart: bodyStart,
				URL:       baseURL,
			}, callback)
		}

		// Check for javascript: protocol
		if strings.HasPrefix(strings.ToLower(attrValue), "javascript:") {
			// Extract JavaScript code after "javascript:"
			jsCode := strings.TrimPrefix(attrValue, "javascript:")
			jsCode = strings.TrimPrefix(jsCode, "javascript:") // Case-insensitive

			// Extract strings from JavaScript code
			// Intentionally ignore error - nested extraction failures shouldn't stop parent extractor
			_ = e.jsExtractor.Extract(ctx, baseURL, &HTTPResponse{
				Body:      []byte(jsCode),
				BodyStart: bodyStart + 11, // len("javascript:")
				URL:       baseURL,
			}, callback)
		}

		// Also scan attribute value for inline URLs
		// Intentionally ignore error - nested extraction failures shouldn't stop parent extractor
		_ = e.inlineScanner.Extract(ctx, baseURL, &HTTPResponse{
			Body:      []byte(attrValue),
			BodyStart: bodyStart,
			URL:       baseURL,
		}, callback)
	}
}

// Ensure EventHandlersExtractor implements LinkExtractor
var _ LinkExtractor = (*EventHandlersExtractor)(nil)
