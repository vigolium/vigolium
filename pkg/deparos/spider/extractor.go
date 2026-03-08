package spider

import (
	"context"
	"net/url"
)

// LinkExtractor defines the interface for all link extraction strategies.
// Each extractor examines HTTP responses and reports discovered links via callback.
type LinkExtractor interface {
	// Extract examines the response and invokes the callback for each discovered link.
	// The baseURL is used to resolve relative URLs.
	Extract(ctx context.Context, baseURL *url.URL, response *HTTPResponse, callback LinkCallback) error
}
