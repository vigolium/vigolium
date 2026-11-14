package httpmsg

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"golang.org/x/net/html"
	"strings"
	"sync"
	"time"
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

	// Opaque, memoized token-similarity signature for this response's body. The
	// signature type lives in modkit (which depends on httpmsg), so it is held as
	// an any here to avoid an import cycle; modkit computes it once per response
	// via RatioSignature. The catch-all-shell guard (ResemblesObservedPage) reuses
	// it across a module's whole probe loop instead of re-tokenizing the constant
	// baseline per probe. Guarded by mu; invalidated by TruncateBody.
	ratioSig   any
	ratioSigOK bool

	// Memoized parsed HTML document (HTMLDocument). Parsed once per response
	// and shared, read-only, by the anomaly fingerprint and the HTML-walking
	// passive modules (ECON-14). Guarded by mu; invalidated by TruncateBody.
	htmlDoc   *html.Node
	htmlErr   error
	htmlDocOK bool

	// duration is how long this response took to arrive, measured by whoever
	// sent the request. Zero means NOT MEASURED, not "took no time": most
	// responses in this process are reconstructed from stored bytes (DB
	// hydration, HAR/Burp import, agent parsers) and have no timing to report.
	//
	// Written exactly once, at construction, and never again — that is why it
	// needs no mutex despite the ~90 passive modules that share one *HttpResponse
	// concurrently. mu guards the lazily-computed memos above, which are a
	// different problem; an immutable field published before the fan-out is
	// already safe under the Go memory model. Keep it that way: do not add a
	// setter.
	duration time.Duration

	mu sync.RWMutex
}

// NewHttpResponse creates a new HttpResponse from raw bytes, with no timing
// information. Use NewHttpResponseWithDuration when the response was actually
// sent and timed.
func NewHttpResponse(raw []byte) *HttpResponse {
	return &HttpResponse{
		raw: raw,
	}
}

// NewHttpResponseWithDuration creates a new HttpResponse from raw bytes and the
// measured round-trip duration. Only callers that performed a real network send
// should use it — a response rebuilt from stored bytes has no duration to report
// and must keep the zero that means "unknown".
func NewHttpResponseWithDuration(raw []byte, d time.Duration) *HttpResponse {
	if d < 0 {
		d = 0
	}
	return &HttpResponse{
		raw:      raw,
		duration: d,
	}
}

// Duration returns the measured round-trip duration for this response, or zero
// when it was never measured (see the field comment: zero is "unknown", never
// "instant"). Deliberately NOT carried by the With* builders — those return a
// synthesized copy, and stamping it with the original's timing would report a
// measurement that never happened.
func (r *HttpResponse) Duration() time.Duration {
	return r.duration
}

// MeasuredMillis converts a measured duration to the milliseconds stored in
// http_records.response_time_ms (and the equivalent columns the discovery and
// browser stores carry it through).
//
// It owns the one invariant the whole timing feature rests on. Those columns are
// INTEGER DEFAULT 0 with no NULL to express "never measured", and most responses
// in this process are rebuilt from stored bytes and genuinely have no timing —
// so a MEASURED value is floored at 1ms, and only an unmeasured one is allowed
// to be 0. Without the floor a loopback probe and an un-timed import are the
// same value, which is what made db stats' p50/p95/p99 a percentile over a
// column of zeros.
//
// Every path that writes one of those columns must go through here. Three
// hand-written copies of this rule had already drifted into three shapes before
// it was centralized.
func MeasuredMillis(d time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	return max(1, d.Milliseconds())
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
//
// The miss is resolved under the write lock, not outside it. Computing outside
// and publishing after is the cheaper shape for an uncontended cache, but this
// cache is contended by construction: the dynamic-assessment phase defaults to
// ParallelPassive, which fans every eligible per-request module out over ONE
// shared response, and 93 of them call this method. Per-host modules are claimed
// once per origin, so from the second record of a host onward nothing warms the
// cache first and the whole fan-out arrives cold together — each goroutine
// copying the same body, for one winner's worth of result. Serializing the miss
// makes the herd pay for a single copy; the hit path below is unchanged and
// still takes only the read lock.
func (r *HttpResponse) BodyToString() string {
	r.ensureParsed()
	r.mu.RLock()
	if r.bodyStringOK {
		s := r.bodyString
		r.mu.RUnlock()
		return s
	}
	r.mu.RUnlock()

	r.mu.Lock()
	defer r.mu.Unlock()
	return r.bodyStringLocked()
}

// bodyStringLocked returns the memoized body string, computing it if this is the
// first ask. The caller must hold r.mu for writing.
//
// It reads r.raw directly instead of calling Body(): Body() calls ensureParsed,
// which takes r.mu, and a sync.RWMutex is not reentrant — so calling it here
// would deadlock. Every caller has already run ensureParsed, so bodyOffset is
// settled.
func (r *HttpResponse) bodyStringLocked() string {
	if r.bodyStringOK {
		return r.bodyString
	}
	var s string
	if r.bodyOffset < len(r.raw) {
		s = string(r.raw[r.bodyOffset:])
	}
	r.bodyString = s
	r.bodyStringOK = true
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

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.bodyLowerStrOK {
		return r.bodyLowerString
	}
	// bodyStringLocked, not BodyToString: taking r.mu again from under it would
	// deadlock. Going through it still shares the body copy with BodyToString's
	// callers, so a cold lowercased read costs one body copy plus one lowering,
	// not two copies.
	s := strings.ToLower(r.bodyStringLocked())
	r.bodyLowerString = s
	r.bodyLowerStrOK = true
	return s
}

// RatioSignature returns an opaque, memoized token-similarity signature for this
// response's body, computed by compute on first access and shared across callers.
// compute receives the memoized body string. The signature type lives in the
// modkit package (which imports httpmsg), so httpmsg keeps it opaque to avoid an
// import cycle. Invalidated by TruncateBody.
//
// Unlike BodyToString this deliberately keeps the compute-outside-the-lock
// shape, so concurrent cold callers can each run compute and all but one throw
// the result away. Two reasons it stays that way: compute is caller-supplied, so
// holding r.mu across it would let a callback that touches this response
// deadlock the whole record; and the herd BodyToString guards against is a
// passive-fan-out effect, while this cache exists for an active module reusing
// one baseline across its own sequential probe loop, where there is no herd to
// collapse.
func (r *HttpResponse) RatioSignature(compute func(body string) any) any {
	r.mu.RLock()
	if r.ratioSigOK {
		v := r.ratioSig
		r.mu.RUnlock()
		return v
	}
	r.mu.RUnlock()

	// Compute outside the lock (BodyToString takes the lock itself).
	v := compute(r.BodyToString())

	r.mu.Lock()
	if r.ratioSigOK {
		v = r.ratioSig // another goroutine won the race; keep its value
	} else {
		r.ratioSig = v
		r.ratioSigOK = true
	}
	r.mu.Unlock()
	return v
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
	r.htmlDoc, r.htmlErr, r.htmlDocOK = nil, nil, false
	r.bodyString, r.bodyStringOK = "", false
	r.bodyLowerString, r.bodyLowerStrOK = "", false
	r.ratioSig, r.ratioSigOK = nil, false
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

// HTMLDocument returns the response body parsed as HTML (golang.org/x/net/html),
// parsed on first use and memoised for the life of the response. The node tree
// is SHARED: callers must treat it as read-only. Several passive modules and
// the anomaly fingerprint parse the same response; this turns N parses into one.
func (r *HttpResponse) HTMLDocument() (*html.Node, error) {
	if r == nil {
		return nil, nil
	}
	r.mu.RLock()
	if r.htmlDocOK {
		doc, err := r.htmlDoc, r.htmlErr
		r.mu.RUnlock()
		return doc, err
	}
	r.mu.RUnlock()

	doc, err := html.Parse(bytes.NewReader(r.Body()))

	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.htmlDocOK {
		r.htmlDoc, r.htmlErr, r.htmlDocOK = doc, err, true
	}
	return r.htmlDoc, r.htmlErr
}
