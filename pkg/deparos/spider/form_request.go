package spider

import (
	"net/url"

	"github.com/vigolium/vigolium/pkg/deparos/spider/formparser"
)

// ExtractionResult contains all outputs from the extraction pipeline.
type ExtractionResult struct {
	// Links are discovered URLs from the response
	Links []*url.URL

	// DiscoveredLinks are discovered URLs with source type information.
	// Used for database storage with source tracking.
	DiscoveredLinks []*DiscoveredLink

	// JSURLs are JavaScript file URLs for path extraction
	JSURLs []*url.URL

	// FormRequests are actionable form submissions
	FormRequests []*FormRequest
}

// FormRequest represents an actionable form submission request.
// It contains pre-built request data ready to be sent.
type FormRequest struct {
	// SourceURL is the URL where this form was found (the page containing the form HTML).
	// Used for correct action URL resolution and attribution.
	SourceURL *url.URL

	// URL is the resolved action URL
	URL *url.URL

	// Method is HTTP method (GET or POST)
	Method string

	// ContentType is the Content-Type header value
	// Empty for GET requests, "application/x-www-form-urlencoded" or
	// "multipart/form-data" for POST requests
	ContentType string

	// Body is the encoded request body (POST only)
	Body string

	// Inputs are the submitted form input values
	Inputs []*FormInputValue

	// SourceForm is a reference to the original parsed form
	SourceForm *formparser.FormInfo
}

// FormInputValue represents a submitted form input name/value pair.
type FormInputValue struct {
	Name  string
	Value string
	Type  formparser.InputType
}
