package spider

import (
	"context"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// MetaRefreshExtractor extracts URLs from <meta http-equiv="refresh"> tags.
//
// Parses the content attribute to extract URLs in the format:
//   - <meta http-equiv="refresh" content="5;url=...">
//   - <meta http-equiv="refresh" content="url=...">
//
// Burp mapping: bb9.java (Meta refresh extractor)
type MetaRefreshExtractor struct {
	inlineScanner *InlineURLScanner
}

// NewMetaRefreshExtractor creates a new meta refresh extractor.
func NewMetaRefreshExtractor(inlineScanner *InlineURLScanner) *MetaRefreshExtractor {
	return &MetaRefreshExtractor{
		inlineScanner: inlineScanner,
	}
}

// Extract examines HTML content and reports URLs from meta refresh tags.
//
// Burp mapping: bb9.a(hik var1, List<ahe> var2, fi3 var3) - Lines 13-45
func (e *MetaRefreshExtractor) Extract(ctx context.Context, baseURL *url.URL, response *HTTPResponse, callback LinkCallback) error {
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

			// Look for <meta> tags
			// Burp mapping: Line 17: "meta".equalsIgnoreCase(var6.cS().a4())
			if tagName == "meta" {
				// Check for http-equiv="Refresh"
				httpEquiv := getAttr(n, "http-equiv")
				if strings.EqualFold(httpEquiv, "Refresh") {
					// Extract URL from content attribute
					// Burp mapping: Line 35-42: extract from content attribute
					e.extractFromMetaTag(ctx, n, baseURL, callback)
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

// extractFromMetaTag extracts URL from a meta refresh tag's content attribute.
//
// Burp mapping: bb9.a(hik var1, ahe var2, fi3 var3) - Lines 35-45
func (e *MetaRefreshExtractor) extractFromMetaTag(ctx context.Context, n *html.Node, baseURL *url.URL, callback LinkCallback) {
	// Get content attribute
	// Burp mapping: Line 36: ffv var4 = var2.cS().f("content")
	content := getAttr(n, "content")
	if content == "" {
		return
	}

	// Find "url=" in content (case-insensitive)
	// Burp mapping: Line 39: int var6 = var5.toLowerCase().indexOf("url=")
	urlIndex := strings.Index(strings.ToLower(content), "url=")
	if urlIndex == -1 {
		return
	}

	// Extract URL string after "url="
	// Burp mapping: Line 41: byte[] var7 = net.portswigger.h9.a(var5.substring(var6 + 4))
	urlStart := urlIndex + 4 // len("url=")
	urlStr := content[urlStart:]

	// Scan for URLs using inline scanner
	// Burp mapping: Line 42: this.a.a(var1, var7, var4.c0() + var6 + 4, (byte)0, var3)
	// Intentionally ignore error - nested extraction failures shouldn't stop parent extractor
	// Burp mapping: wb.java continues processing even if individual extractors fail
	_ = e.inlineScanner.Extract(ctx, baseURL, &HTTPResponse{
		Body:      []byte(urlStr),
		BodyStart: urlStart,
		URL:       baseURL,
	}, callback)
}

// Ensure MetaRefreshExtractor implements LinkExtractor
var _ LinkExtractor = (*MetaRefreshExtractor)(nil)
