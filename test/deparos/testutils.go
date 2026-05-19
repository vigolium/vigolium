package integration_test

// JSONResult mirrors pkg/reporting/exporters/json.go JSONResult for test assertions.
// Used for exact-match validation of deparos discovery output.
type JSONResult struct {
	URL           string            `json:"url"`
	Method        string            `json:"method,omitempty"`
	StatusCode    int               `json:"status_code,omitempty"`
	ContentType   string            `json:"content_type,omitempty"`
	ContentLength int               `json:"content_length"`
	Location      string            `json:"location,omitempty"`
	Title         string            `json:"title,omitempty"`
	FoundBy       string            `json:"found_by,omitempty"`
	Depth         int               `json:"depth,omitempty"`
	Type          string            `json:"type,omitempty"`
	Tags          []string          `json:"tags,omitempty"`
	Timestamp     string            `json:"timestamp,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
}

// ResponseScenario defines an HTTP response for the test server.
// Each scenario maps a path pattern to a specific response.
type ResponseScenario struct {
	// Path is the URL path to match (exact match).
	Path string

	// Method is the HTTP method to match (GET, POST, etc.).
	// Empty string matches all methods.
	Method string

	// StatusCode is the HTTP status code to return.
	StatusCode int

	// Headers are the response headers to set.
	Headers map[string]string

	// Body is the response body content.
	Body string
}

// ExpectedResult defines exact match criteria for assertion.
// Nil fields are not checked (wildcard).
type ExpectedResult struct {
	// URL is the expected URL (required, exact match).
	URL string

	// StatusCode is the expected HTTP status code.
	// Nil means don't check.
	StatusCode *int

	// ContentLength is the expected response body length.
	// Nil means don't check.
	ContentLength *int

	// ContentType is the expected MIME type.
	// Nil means don't check.
	ContentType *string

	// Location is the expected redirect location.
	// Nil means don't check.
	Location *string

	// Title is the expected HTML title.
	// Nil means don't check.
	Title *string

	// FoundBy is how the URL was discovered (spider, wordlist, etc.).
	// Nil means don't check.
	FoundBy *string

	// Type is the node type (file or directory).
	// Nil means don't check.
	Type *string

	// Depth is the discovery depth from start URL.
	// Nil means don't check.
	Depth *int
}

// RunResult holds the result of a deparos discovery run.
type RunResult struct {
	// Results are the discovered URLs converted to JSONResult.
	Results []JSONResult

	// Count is the total number of discovered URLs.
	Count int
}

// Helper functions for creating pointer values in ExpectedResult

// IntPtr returns a pointer to the given int value.
func IntPtr(i int) *int {
	return &i
}

// StringPtr returns a pointer to the given string value.
func StringPtr(s string) *string {
	return &s
}
