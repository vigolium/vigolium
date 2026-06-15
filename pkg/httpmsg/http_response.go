package httpmsg

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
)

// HttpResponse represents an HTTP response with raw bytes as source of truth.
//
// Design:
//   - Raw bytes are the source of truth
//   - Parsed fields (statusCode, headers) are cached on first access
//   - With* methods return new instances (immutable pattern)
type HttpResponse struct {
	raw []byte // Source of truth - complete raw HTTP response

	// Cached parsed fields (populated on first access via ensureParsed)
	statusCode int
	headers    []HttpHeader
	bodyOffset int
	parsed     bool

	// Memoized body derivations. The native-scan executor hands the SAME
	// *HttpResponse to every passive module for a record (they run concurrently),
	// and the common idioms — `body := resp.BodyToString()` then
	// `strings.ToLower(body)` — would otherwise re-copy the full body once per
	// module. Computing each form once and sharing it turns ~N full-body copies
	// (N ≈ 90 passive modules) into one. The lowercased form is derived from the
	// memoized body string, so it adds at most one extra allocation. Guarded by mu;
	// invalidated by TruncateBody (the only in-place body mutation — the With*
	// builders return fresh structs).
	bodyString      string
	bodyStringOK    bool
	bodyLowerString string
	bodyLowerStrOK  bool

	mu sync.RWMutex
}

// NewHttpResponse creates a new HttpResponse from raw bytes.
func NewHttpResponse(raw []byte) *HttpResponse {
	return &HttpResponse{
		raw: raw,
	}
}

// Raw returns the raw HTTP response bytes.
func (r *HttpResponse) Raw() []byte {
	return r.raw
}

// StatusCode returns the HTTP status code.
// Lazily parsed from raw bytes on first access.
func (r *HttpResponse) StatusCode() int {
	r.ensureParsed()
	return r.statusCode
}

// Headers returns all HTTP headers as a slice.
// Lazily parsed from raw bytes on first access.
func (r *HttpResponse) Headers() []HttpHeader {
	r.ensureParsed()
	return r.headers
}

// Header returns the value of a specific header (case-insensitive).
// Returns empty string if not found.
func (r *HttpResponse) Header(name string) string {
	r.ensureParsed()
	val, _ := FindHttpHeader(r.headers, name)
	return val
}

// HasHeader checks if a header exists (case-insensitive).
func (r *HttpResponse) HasHeader(name string) bool {
	r.ensureParsed()
	return HttpHeadersContain(r.headers, name)
}

// Body returns the response body as bytes.
func (r *HttpResponse) Body() []byte {
	r.ensureParsed()
	if r.bodyOffset >= len(r.raw) {
		return nil
	}
	return r.raw[r.bodyOffset:]
}

// BodyOffset returns the byte offset where body starts.
func (r *HttpResponse) BodyOffset() int {
	r.ensureParsed()
	return r.bodyOffset
}

// Head returns the response head — the status line and headers up to and
// including the blank-line separator, without the body. Returns nil when the
// body offset can't be determined (e.g. an empty or unparsable response).
func (r *HttpResponse) Head() []byte {
	r.ensureParsed()
	if r.bodyOffset <= 0 || r.bodyOffset > len(r.raw) {
		return nil
	}
	return r.raw[:r.bodyOffset]
}

// BodyToString returns the body as a string. The conversion is memoized: every
// caller for this response shares one allocation, so a wide passive-module
// fan-out over the same record doesn't re-copy the body per module.
func (r *HttpResponse) BodyToString() string {
	r.ensureParsed()
	r.mu.RLock()
	if r.bodyStringOK {
		s := r.bodyString
		r.mu.RUnlock()
		return s
	}
	r.mu.RUnlock()

	s := string(r.Body())
	r.mu.Lock()
	r.bodyString = s
	r.bodyStringOK = true
	r.mu.Unlock()
	return s
}

// BodyLowerString returns the lowercased body as a string, memoized and shared.
// Prefer this over strings.ToLower(resp.BodyToString()) in passive detectors so
// the lowercased body is computed once per response, not once per module. It
// reuses the memoized BodyToString so it adds a single lowered-string allocation.
func (r *HttpResponse) BodyLowerString() string {
	r.ensureParsed()
	r.mu.RLock()
	if r.bodyLowerStrOK {
		s := r.bodyLowerString
		r.mu.RUnlock()
		return s
	}
	r.mu.RUnlock()

	s := strings.ToLower(r.BodyToString())
	r.mu.Lock()
	r.bodyLowerString = s
	r.bodyLowerStrOK = true
	r.mu.Unlock()
	return s
}

// Cookies parses and returns cookies from Set-Cookie headers.
// This is NOT cached as it involves parsing.
func (r *HttpResponse) Cookies() []*Cookie {
	r.ensureParsed()
	// Convert headers to string slice for existing parser
	headerStrings := make([]string, 0, len(r.headers)+1)
	// Add dummy status line (parser expects it at index 0)
	headerStrings = append(headerStrings, "")
	for _, h := range r.headers {
		headerStrings = append(headerStrings, h.String())
	}
	return parseSetCookieHeaders(headerStrings)
}

// ID returns a unique hash identifier for this response.
func (r *HttpResponse) ID() string {
	if len(r.raw) == 0 {
		return ""
	}
	val := sha256.Sum256(r.raw)
	return hex.EncodeToString(val[:])
}

// ensureParsed lazily parses the raw response into cached fields.
// Thread-safe via mutex.
func (r *HttpResponse) ensureParsed() {
	r.mu.RLock()
	if r.parsed {
		r.mu.RUnlock()
		return
	}
	r.mu.RUnlock()

	r.mu.Lock()
	defer r.mu.Unlock()

	// Double-check after acquiring write lock
	if r.parsed {
		return
	}

	if len(r.raw) == 0 {
		r.parsed = true
		return
	}

	// Parse headers and find body offset
	headerStrings, _, bodyOffset, _ := ExtractAllHeaders(r.raw)
	r.bodyOffset = bodyOffset

	// Parse status line (first header is status line)
	if len(headerStrings) > 0 {
		r.statusCode = int(parseStatusLine(headerStrings[0]))
	}

	// Convert header strings to HttpHeader slice
	r.headers = ParseHeadersFromStrings(headerStrings)

	r.parsed = true
}

// TruncateBody truncates the response body to maxSize bytes.
// Headers are preserved. No-op if body is already within limit.
func (r *HttpResponse) TruncateBody(maxSize int) {
	r.ensureParsed()
	bodyLen := len(r.raw) - r.bodyOffset
	if bodyLen <= maxSize || maxSize < 0 {
		return
	}
	r.mu.Lock()
	r.raw = r.raw[:r.bodyOffset+maxSize]
	// The body shrank — drop the memoized derivations so later reads recompute
	// against the truncated body instead of returning the pre-truncation copy.
	r.bodyString, r.bodyStringOK = "", false
	r.bodyLowerString, r.bodyLowerStrOK = "", false
	r.mu.Unlock()
}

// ============== Immutable Builder Methods ==============

// WithStatusCode returns a new HttpResponse with the status code replaced.
func (r *HttpResponse) WithStatusCode(code int) *HttpResponse {
	r.ensureParsed()

	// Build new status line
	statusText := getStatusText(code)
	statusLine := "HTTP/1.1 " + intToString(code) + " " + statusText

	// Build headers list
	var headerLines []string
	headerLines = append(headerLines, statusLine)
	headerLines = append(headerLines, HeadersToStrings(r.headers)...)

	// Get body
	var body []byte
	if r.bodyOffset < len(r.raw) {
		body = r.raw[r.bodyOffset:]
	}

	newRaw := BuildHttpMessage(headerLines, body)
	return &HttpResponse{
		raw: newRaw,
	}
}

// WithHeader returns a new HttpResponse with the header set (add or update).
func (r *HttpResponse) WithHeader(name, value string) *HttpResponse {
	newRaw, _ := ReplaceHeader(r.raw, name, value)
	return &HttpResponse{
		raw: newRaw,
	}
}

// WithAddedHeader returns a new HttpResponse with a header added.
func (r *HttpResponse) WithAddedHeader(name, value string) *HttpResponse {
	newRaw, _ := AddHeader(r.raw, name, value)
	return &HttpResponse{
		raw: newRaw,
	}
}

// WithRemovedHeader returns a new HttpResponse with the header removed.
func (r *HttpResponse) WithRemovedHeader(name string) *HttpResponse {
	newRaw, _ := RemoveHeader(r.raw, name)
	return &HttpResponse{
		raw: newRaw,
	}
}

// WithBody returns a new HttpResponse with the body replaced.
// Updates Content-Length header automatically.
func (r *HttpResponse) WithBody(body []byte) *HttpResponse {
	r.ensureParsed()

	// Build status line
	statusText := getStatusText(r.statusCode)
	statusLine := "HTTP/1.1 " + intToString(r.statusCode) + " " + statusText

	// Build new response with updated body
	var headerLines []string
	headerLines = append(headerLines, statusLine)
	headerLines = append(headerLines, HeadersToStrings(r.headers)...)

	newRaw := BuildHttpMessage(headerLines, body)
	newRaw, _ = UpdateContentLength(newRaw)

	return &HttpResponse{
		raw: newRaw,
	}
}

// Clone creates a deep copy of the HttpResponse.
func (r *HttpResponse) Clone() *HttpResponse {
	rawCopy := make([]byte, len(r.raw))
	copy(rawCopy, r.raw)

	return &HttpResponse{
		raw: rawCopy,
	}
}

// ============== Helper Functions ==============

// getStatusText returns the standard HTTP status text for a code.
func getStatusText(code int) string {
	switch code {
	case 100:
		return "Continue"
	case 101:
		return "Switching Protocols"
	case 200:
		return "OK"
	case 201:
		return "Created"
	case 202:
		return "Accepted"
	case 204:
		return "No Content"
	case 301:
		return "Moved Permanently"
	case 302:
		return "Found"
	case 303:
		return "See Other"
	case 304:
		return "Not Modified"
	case 307:
		return "Temporary Redirect"
	case 308:
		return "Permanent Redirect"
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 405:
		return "Method Not Allowed"
	case 406:
		return "Not Acceptable"
	case 408:
		return "Request Timeout"
	case 409:
		return "Conflict"
	case 410:
		return "Gone"
	case 413:
		return "Payload Too Large"
	case 414:
		return "URI Too Long"
	case 415:
		return "Unsupported Media Type"
	case 429:
		return "Too Many Requests"
	case 500:
		return "Internal Server Error"
	case 501:
		return "Not Implemented"
	case 502:
		return "Bad Gateway"
	case 503:
		return "Service Unavailable"
	case 504:
		return "Gateway Timeout"
	default:
		return "Unknown"
	}
}

// BuildRawResponse creates raw HTTP response bytes from components.
// This is useful for building responses from parsed data (e.g., parquet records).
func BuildRawResponse(statusCode int, headers map[string]string, body string) []byte {
	if statusCode == 0 {
		statusCode = 200
	}

	statusText := getStatusText(statusCode)
	statusLine := "HTTP/1.1 " + intToString(statusCode) + " " + statusText

	var headerLines []string
	headerLines = append(headerLines, statusLine)

	for name, value := range headers {
		headerLines = append(headerLines, name+": "+value)
	}

	return BuildHttpMessage(headerLines, []byte(body))
}
