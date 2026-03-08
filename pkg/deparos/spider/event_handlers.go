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
//
// Burp mapping: hjn.java (Event handlers extractor)
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
//
// Burp mapping: hjn.a(hik var1, List<ahe> var2, fi3 var3) - Lines 15-53
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
			// Burp mapping: Line 19: if (var6.cU() == 0 || var6.cU() == 4)
			// Process start tags only (not end tags or other nodes)

			// Skip ASP.NET specific attributes
			// Burp mapping: Lines 56-68: Skip __VIEWSTATE and __EVENTVALIDATION
			if e.shouldSkipElement(n) {
				// Skip traversal of children for this element
				return
			}

			// Extract URLs from event handler attributes
			// Burp mapping: Line 24: for (ffv var8 : var6.cS().a5())
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
//
// Burp mapping: hjn.a(ahe var1) - Lines 56-68
func (e *EventHandlersExtractor) shouldSkipElement(n *html.Node) bool {
	// Check for __VIEWSTATE or __EVENTVALIDATION attributes
	// These are ASP.NET specific and shouldn't be processed
	// Burp mapping: Line 57: String var2 = var1.cS().e("name")
	name := getAttr(n, "name")

	// Burp mapping: Line 59: if ("__VIEWSTATE".equals(var2))
	if strings.EqualFold(name, "__VIEWSTATE") {
		return true
	}

	// Burp mapping: Line 63: if ("__EVENTVALIDATION".equals(var2))
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
	// Burp mapping: Line 24: for (ffv var8 : var6.cS().a5())
	for _, attr := range n.Attr {
		attrName := strings.ToLower(attr.Key)
		attrValue := attr.Val

		// Check for "on*" event handler attributes
		// Burp mapping: Lines 26-31
		if strings.HasPrefix(attrName, "on") {
			// Extract JavaScript code from event handler
			// Burp mapping: Line 27: this.a.a(var1, var8.cY(), var8.c0(), var3)
			// Intentionally ignore error - nested extraction failures shouldn't stop parent extractor
			// Burp mapping: wb.java continues processing even if individual extractors fail
			_ = e.jsExtractor.Extract(ctx, baseURL, &HTTPResponse{
				Body:      []byte(attrValue),
				BodyStart: bodyStart,
				URL:       baseURL,
			}, callback)
		}

		// Check for javascript: protocol
		// Burp mapping: Lines 33-38
		if strings.HasPrefix(strings.ToLower(attrValue), "javascript:") {
			// Extract JavaScript code after "javascript:"
			// Burp mapping: Line 34: this.a.a(var1, var8.cY().substring("javascript:".length()), ...)
			jsCode := strings.TrimPrefix(attrValue, "javascript:")
			jsCode = strings.TrimPrefix(jsCode, "javascript:") // Case-insensitive

			// Extract strings from JavaScript code
			// Burp mapping: Line 27
			// Intentionally ignore error - nested extraction failures shouldn't stop parent extractor
			// Burp mapping: wb.java continues processing even if individual extractors fail
			_ = e.jsExtractor.Extract(ctx, baseURL, &HTTPResponse{
				Body:      []byte(jsCode),
				BodyStart: bodyStart + 11, // len("javascript:")
				URL:       baseURL,
			}, callback)
		}

		// Also scan attribute value for inline URLs
		// Burp mapping: Lines 40-41: this.b.a(var1, net.portswigger.h9.a(var8.cY()), ...)
		// Intentionally ignore error - nested extraction failures shouldn't stop parent extractor
		// Burp mapping: wb.java continues processing even if individual extractors fail
		_ = e.inlineScanner.Extract(ctx, baseURL, &HTTPResponse{
			Body:      []byte(attrValue),
			BodyStart: bodyStart,
			URL:       baseURL,
		}, callback)
	}
}

// Ensure EventHandlersExtractor implements LinkExtractor
var _ LinkExtractor = (*EventHandlersExtractor)(nil)
