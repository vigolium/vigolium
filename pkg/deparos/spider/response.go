package spider

import (
	"bytes"
	"errors"
	"net/url"
	"sync"

	"golang.org/x/net/html"
)

// MaxBodySize is the maximum allowed body size for HTML parsing (10MB).
// Bodies larger than this will return ErrBodyTooLarge to prevent DoS.
const MaxBodySize = 50 * 1024 * 1024 // 50MB

// ErrBodyTooLarge is returned when the response body exceeds MaxBodySize.
var ErrBodyTooLarge = errors.New("response body too large for HTML parsing")

// HTTPResponse wraps HTTP response data for link extraction.
// HTML parsing is cached using sync.Once for efficiency.
type HTTPResponse struct {
	URL       *url.URL            // Response URL (for robots.txt detection)
	Headers   map[string][]string // HTTP headers (for header extraction)
	Body      []byte              // Raw response body
	BodyStart int                 // Body offset for position tracking
	HTML      *html.Node          // Cached parsed HTML DOM (golang.org/x/net/html)

	htmlOnce sync.Once // Ensures single parse
	htmlErr  error     // Parse error cache
}

// NewHTTPResponse creates a new HTTP response wrapper.
func NewHTTPResponse(u *url.URL, headers map[string][]string, body []byte, bodyStart int) *HTTPResponse {
	return &HTTPResponse{
		URL:       u,
		Headers:   headers,
		Body:      body,
		BodyStart: bodyStart,
	}
}

// ParseHTML parses the response body as HTML and caches the result.
//
// This method uses sync.Once to guarantee exactly-once parsing, even when
// called concurrently by multiple extractors. This is critical for the
// "parse once, extract many" optimization pattern.
//
// Subsequent calls return the cached parse result (or error) immediately
// without re-parsing.
//
// Returns:
//   - nil if HTML was parsed successfully
//   - ErrBodyTooLarge if body exceeds MaxBodySize
//   - error if parsing failed (not HTML, malformed, etc.)
//
// Burp mapping: Inferred from optimization requirements
func (r *HTTPResponse) ParseHTML() error {
	r.htmlOnce.Do(func() {
		// Check body size to prevent DoS from large HTML
		if len(r.Body) > MaxBodySize {
			r.htmlErr = ErrBodyTooLarge
			return
		}

		// Parse HTML from body
		doc, err := html.Parse(bytes.NewReader(r.Body))
		if err != nil {
			r.htmlErr = err
			return
		}

		r.HTML = doc
		r.htmlErr = nil
	})

	return r.htmlErr
}
