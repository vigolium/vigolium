package types

import (
	"net/url"
	"time"
)

// ResultEvent represents a unified discovery result.
// This type consolidates discovery results from various sources (spider, bruteforce, etc.)
// into a single, consistent format for processing and output.
type ResultEvent struct {
	// URL is the complete URL of the discovered resource
	URL *url.URL `json:"url"`

	// Host is the hostname portion of the URL
	Host string `json:"host"`

	// Path is the path portion of the URL
	Path string `json:"path"`

	// Method is the HTTP method used (GET, POST, etc.)
	Method string `json:"method,omitempty"`

	// StatusCode is the HTTP response status code
	StatusCode int `json:"status_code"`

	// ContentType is the MIME type from the response headers
	ContentType string `json:"content_type,omitempty"`

	// ContentLength is the size of the response body in bytes
	ContentLength int `json:"content_length"`

	// Location is the redirect target from Location header
	Location string `json:"location,omitempty"`

	// Title is the HTML title extracted from the response
	Title string `json:"title,omitempty"`

	// ResponseHeaders contains selected response headers
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`

	// ResponseBody contains the raw response body (not serialized to JSON)
	ResponseBody []byte `json:"-"`

	// FoundBy indicates which discovery method found this result (e.g., "spider", "bruteforce")
	FoundBy string `json:"found_by"`

	// Depth is the traversal depth from the seed URL
	Depth int `json:"depth"`

	// Timestamp is when this result was discovered
	Timestamp time.Time `json:"timestamp"`

	// Type indicates whether this is a file or directory
	Type ResultType `json:"type"`

	// Confidence is the confidence score for 404 detection (0-100)
	Confidence int `json:"confidence,omitempty"`

	// Tags are custom labels for categorizing results
	Tags []string `json:"tags,omitempty"`

	// Duration is the time taken to receive the response
	Duration time.Duration `json:"duration,omitempty"`
}

// ResultType categorizes the discovered resource.
type ResultType string

const (
	// ResultTypeFile indicates a file resource
	ResultTypeFile ResultType = "file"

	// ResultTypeDirectory indicates a directory resource
	ResultTypeDirectory ResultType = "directory"
)

// FailureEvent represents a failure during discovery.
// This type captures errors that occur during scanning for diagnostics and debugging.
type FailureEvent struct {
	// URL is the URL that failed to be processed
	URL string `json:"url"`

	// Error is the error message describing the failure
	Error string `json:"error"`

	// Timestamp is when the failure occurred
	Timestamp time.Time `json:"timestamp"`
}
