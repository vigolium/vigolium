package http

import (
	"bytes"
	"context"
	"fmt"
	"io"
	nethttp "net/http"
	"net/url"
	"strings"
)

// RequestBuilder provides a fluent API for building HTTP requests.
type RequestBuilder struct {
	method  string
	url     string
	headers map[string]string
	body    []byte
	depth   int
	ctx     context.Context
	err     error
}

// NewRequest creates a new RequestBuilder for the specified URL.
func NewRequest(targetURL string) *RequestBuilder {
	return &RequestBuilder{
		method:  "GET",
		url:     targetURL,
		headers: make(map[string]string),
		ctx:     context.Background(),
	}
}

// Method sets the HTTP method (GET, POST, HEAD, etc.).
func (rb *RequestBuilder) Method(method string) *RequestBuilder {
	rb.method = method
	return rb
}

// Header sets a single header value.
func (rb *RequestBuilder) Header(key, value string) *RequestBuilder {
	rb.headers[key] = value
	return rb
}

// Headers sets multiple headers at once.
func (rb *RequestBuilder) Headers(headers map[string]string) *RequestBuilder {
	for k, v := range headers {
		rb.headers[k] = v
	}
	return rb
}

// Body sets the request body.
func (rb *RequestBuilder) Body(body []byte) *RequestBuilder {
	rb.body = body
	return rb
}

// BodyString sets the request body from a string.
func (rb *RequestBuilder) BodyString(body string) *RequestBuilder {
	rb.body = []byte(body)
	return rb
}

// Depth sets the discovery depth (for spider tracking).
func (rb *RequestBuilder) Depth(depth int) *RequestBuilder {
	rb.depth = depth
	return rb
}

// Context sets the context for the request.
func (rb *RequestBuilder) Context(ctx context.Context) *RequestBuilder {
	rb.ctx = ctx
	return rb
}

// Build constructs the final nethttp.Request.
// Returns an error if the URL is invalid or other build errors occur.
func (rb *RequestBuilder) Build() (*nethttp.Request, error) {
	// Check for builder errors
	if rb.err != nil {
		return nil, rb.err
	}

	// Validate URL
	if _, err := url.Parse(rb.url); err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// Create body reader
	var bodyReader io.Reader
	if len(rb.body) > 0 {
		bodyReader = bytes.NewReader(rb.body)
	}

	// Create request
	req, err := nethttp.NewRequestWithContext(rb.ctx, rb.method, rb.url, bodyReader)
	if err != nil {
		return nil, err
	}

	// Set headers
	for key, value := range rb.headers {
		// Special handling for Host header - Go's net/http ignores Header["Host"]
		// Must set req.Host directly for the Host header to be sent
		if strings.EqualFold(key, "Host") {
			req.Host = value
		} else {
			req.Header.Set(key, value)
		}
	}

	// Set default browser-like headers if not provided (for WAF bypass)
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	}
	if req.Header.Get("Accept-Language") == "" {
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	}
	// If the Transport requests gzip on its own and gets a gzipped response, it's transparently decoded. However, if the user explicitly requested gzip it is not automatically uncompressed.
	// if req.Header.Get("Accept-Encoding") == "" {
	// 	req.Header.Set("Accept-Encoding", "gzip, deflate")
	// }
	if req.Header.Get("Cache-Control") == "" {
		req.Header.Set("Cache-Control", "no-cache")
	}
	if req.Header.Get("Pragma") == "" {
		req.Header.Set("Pragma", "no-cache")
	}

	// Set Origin header (scheme://host without path)
	if req.Header.Get("Origin") == "" {
		parsedURL, _ := url.Parse(rb.url)
		if parsedURL != nil {
			origin := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
			req.Header.Set("Origin", origin)
		}
	}

	// Set Referer header (full URL being requested)
	if req.Header.Get("Referer") == "" {
		req.Header.Set("Referer", rb.url)
	}

	return req, nil
}
