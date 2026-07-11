package spider

import (
	"bytes"
	"errors"
	"net/url"
	"strings"
	"sync"

	"golang.org/x/net/html"
)

// MaxBodySize is the maximum allowed body size for HTML parsing (10MB).
// Bodies larger than this will return ErrBodyTooLarge to prevent DoS.
const MaxBodySize = 50 * 1024 * 1024 // 50MB

// ErrBodyTooLarge is returned when the response body exceeds MaxBodySize.
var ErrBodyTooLarge = errors.New("response body too large for HTML parsing")

// ErrNotHTMLContentType marks a response whose Content-Type is definitively not
// HTML/XML, so the HTML parser is skipped for it (the raw-bytes URL scanners
// still run). See isHTMLParseableContentType.
var ErrNotHTMLContentType = errors.New("content type is not HTML; skipping HTML parse")

// isHTMLParseableContentType reports whether a body with this Content-Type is
// worth running through the HTML parser. HTML/XHTML/XML are parsed; JSON,
// JavaScript, CSS, and binary/media types are NOT (running html.Parse over a
// large JSON or binary body is wasted work — the inline URL scanner still runs
// on their raw bytes). An empty/unknown Content-Type is treated as parseable:
// servers sometimes serve HTML without one, and being lenient avoids missing
// links.
func isHTMLParseableContentType(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.IndexByte(ct, ';'); i >= 0 { // strip charset/boundary params
		ct = strings.TrimSpace(ct[:i])
	}
	if ct == "" {
		return true
	}
	if strings.Contains(ct, "html") || strings.Contains(ct, "xml") {
		return true
	}
	switch {
	case strings.Contains(ct, "json"),
		strings.Contains(ct, "javascript"),
		strings.Contains(ct, "ecmascript"),
		strings.Contains(ct, "css"),
		strings.HasPrefix(ct, "image/"),
		strings.HasPrefix(ct, "audio/"),
		strings.HasPrefix(ct, "video/"),
		strings.Contains(ct, "font"), // covers font/* and application/font-*
		strings.Contains(ct, "octet-stream"),
		strings.Contains(ct, "pdf"),
		strings.Contains(ct, "protobuf"),
		strings.Contains(ct, "grpc"),
		strings.Contains(ct, "wasm"),
		strings.Contains(ct, "zip"): // covers zip and gzip
		return false
	default:
		// Other text/* (e.g. text/plain) and unknown types: lenient — parse.
		return true
	}
}

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

// NewHTTPResponseWithHTML creates a response wrapper pre-seeded with an
// already-parsed HTML DOM (and its parse error, if any). It consumes the
// internal sync.Once so a later ParseHTML() returns the supplied node without
// re-parsing — used by the coordinator to reuse the ResponseChain's shared parse
// instead of building a second DOM over the same body.
func NewHTTPResponseWithHTML(u *url.URL, headers map[string][]string, body []byte, bodyStart int, doc *html.Node, parseErr error) *HTTPResponse {
	r := &HTTPResponse{
		URL:       u,
		Headers:   headers,
		Body:      body,
		BodyStart: bodyStart,
		HTML:      doc,
		htmlErr:   parseErr,
	}
	r.htmlOnce.Do(func() {}) // mark parse as already done
	return r
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
