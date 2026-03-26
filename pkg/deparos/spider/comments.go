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
func (e *CommentsExtractor) Extract(ctx context.Context, baseURL *url.URL, response *HTTPResponse, callback LinkCallback) error {
	// Ensure HTML is parsed (cached with sync.Once)
	if response.HTML == nil {
		return nil // Not HTML or parse failed
	}

	doc := response.HTML

	// Traverse DOM recursively looking for comment nodes
	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		// Check for comment nodes
		if n.Type == html.CommentNode {
			// Extract URLs from comment content
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
func (e *CommentsExtractor) extractFromComment(ctx context.Context, n *html.Node, baseURL *url.URL, bodyStart int, callback LinkCallback) {
	// Get comment content
	commentStart := bodyStart + 4 // Skip "<!--"

	commentContent := n.Data
	if commentContent == "" {
		return
	}

	// Scan comment content for inline URLs
	// Intentionally ignore error - nested extraction failures shouldn't stop parent extractor
	_ = e.inlineScanner.Extract(ctx, baseURL, &HTTPResponse{
		Body:      []byte(commentContent),
		BodyStart: commentStart,
		URL:       baseURL,
	}, callback)
}

// Ensure CommentsExtractor implements LinkExtractor
var _ LinkExtractor = (*CommentsExtractor)(nil)
