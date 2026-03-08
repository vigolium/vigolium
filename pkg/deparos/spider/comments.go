package spider

import (
	"context"
	"net/url"

	"golang.org/x/net/html"
)

// CommentsExtractor extracts URLs from HTML comments.
//
// Parses HTML comment nodes and scans their content for inline URLs.
// Format: <!-- http://... -->
//
// Burp mapping: c17.java (Comments extractor)
type CommentsExtractor struct {
	inlineScanner *InlineURLScanner
}

// NewCommentsExtractor creates a new comments extractor.
func NewCommentsExtractor(inlineScanner *InlineURLScanner) *CommentsExtractor {
	return &CommentsExtractor{
		inlineScanner: inlineScanner,
	}
}

// Extract examines HTML content and reports URLs found in HTML comments.
//
// Burp mapping: c17.a(hik var1, hkk var2, byte[] var3, fi3 var4) - Lines 17-29
func (e *CommentsExtractor) Extract(ctx context.Context, baseURL *url.URL, response *HTTPResponse, callback LinkCallback) error {
	// Ensure HTML is parsed (cached with sync.Once)
	if response.HTML == nil {
		return nil // Not HTML or parse failed
	}

	doc := response.HTML

	// Traverse DOM recursively looking for comment nodes
	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		// Burp mapping: Line 21: if (var7.cU() == 2)
		// Node type 2 is comment node
		if n.Type == html.CommentNode {
			// Extract URLs from comment content
			// Burp mapping: Lines 22-23
			e.extractFromComment(ctx, n, baseURL, response.BodyStart, callback)
		}

		// Traverse children
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}

	traverse(doc)
	return nil
}

// extractFromComment extracts URLs from a comment node's content.
//
// Burp mapping: c17.a(hik var1, byte[] var2, ahe var3, fi3 var4) - Lines 32-35
func (e *CommentsExtractor) extractFromComment(ctx context.Context, n *html.Node, baseURL *url.URL, bodyStart int, callback LinkCallback) {
	// Get comment content
	// Burp mapping: Line 33: int var5 = var3.cR() + a (a = "<!--".length())
	commentStart := bodyStart + 4 // Skip "<!--"

	// Burp mapping: Line 34: int var6 = var3.cV() - b (b = "-->".length())
	commentContent := n.Data
	if commentContent == "" {
		return
	}

	// Scan comment content for inline URLs
	// Burp mapping: Line 35: this.d.a(var1, var2, var5, var6, var4)
	// Intentionally ignore error - nested extraction failures shouldn't stop parent extractor
	// Burp mapping: wb.java continues processing even if individual extractors fail
	_ = e.inlineScanner.Extract(ctx, baseURL, &HTTPResponse{
		Body:      []byte(commentContent),
		BodyStart: commentStart,
		URL:       baseURL,
	}, callback)
}

// Ensure CommentsExtractor implements LinkExtractor
var _ LinkExtractor = (*CommentsExtractor)(nil)
