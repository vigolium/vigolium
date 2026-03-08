// Package waf provides WAF/CDN blocking detection types and interfaces.
package waf

import (
	"time"

	"github.com/vigolium/vigolium/pkg/deparos/responsechain"
)

// Detector detects WAF/CDN blocking responses.
// Thread-safe for concurrent use from multiple workers.
type Detector interface {
	// Detect analyzes an HTTP response for WAF/CDN blocking patterns.
	// Returns nil if response is not a WAF block.
	Detect(rc *responsechain.ResponseChain) *BlockResult
}

// BlockResult represents a detected WAF/CDN block.
type BlockResult struct {
	// IsBlocked indicates whether the response is a WAF block.
	IsBlocked bool

	// WAFType identifies the WAF/CDN that blocked the request.
	// Examples: "cloudflare", "akamai", "aws_waf", "imperva", "f5_bigip", "sucuri", "modsecurity", "generic"
	WAFType string

	// Indicators lists what triggered detection (headers, body patterns).
	Indicators []string
}

// BlockInfo contains information about a detected WAF block.
// Used by BlockTracker for logging and statistics.
type BlockInfo struct {
	// WAFType identifies the WAF/CDN that blocked the request.
	WAFType string

	// StatusCode is the HTTP status code of the blocked response.
	StatusCode int

	// URL is the requested URL that was blocked.
	URL string

	// Timestamp when the block was detected.
	Timestamp time.Time

	// Indicators lists what triggered detection.
	Indicators []string
}
