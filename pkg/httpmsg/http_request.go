package httpmsg

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"sync"

	urlutil "github.com/projectdiscovery/utils/url"
	"go.uber.org/zap"

	"github.com/vigolium/vigolium/pkg/utils"
)

// HttpRequest represents an HTTP request with raw bytes as source of truth.
//
// Design:
//   - Raw bytes are the source of truth
//   - Parsed fields (method, path, headers) are cached on first access
//   - With* methods return new instances (immutable pattern)
//   - Service contains host, port, protocol info
type HttpRequest struct {
	raw     []byte   // Source of truth - complete raw HTTP request
	service *Service // HTTP service (host, port, protocol)

	// Cached parsed fields (populated on first access via ensureParsed)
	method     string
	path       string
	headers    []HttpHeader
	bodyOffset int
	parsed     bool
	cachedID   string // Cached SHA-256 hash (computed once by ID())

	// Cached URL (computed once by URL()). Invalidated when the service
	// changes via HttpRequestResponse.WithService.
	cachedURL    *urlutil.URL
	cachedURLErr error
	urlComputed  bool

	// Cached media/JS-path classification (computed once by IsMediaPath()).
	// Derived from the URL path, which comes from the immutable raw request
	// line and is independent of the service, so it never needs invalidation.
	mediaPath         bool
	mediaPathComputed bool

	mu sync.RWMutex
}

// NewHttpRequest creates a new HttpRequest from raw bytes.
func NewHttpRequest(raw []byte) *HttpRequest {
	return &HttpRequest{
		raw: raw,
	}
}

// NewHttpRequestWithService creates a new HttpRequest with service info.
func NewHttpRequestWithService(service *Service, raw []byte) *HttpRequest {
	return &HttpRequest{
		raw:     raw,
		service: service,
	}
}

// Raw returns the raw HTTP request bytes.
func (r *HttpRequest) Raw() []byte {
	return r.raw
}

// Service returns the HTTP service (host, port, protocol).
func (r *HttpRequest) Service() *Service {
	return r.service
}

// Method returns the HTTP method (GET, POST, etc.).
// Lazily parsed from raw bytes on first access.
func (r *HttpRequest) Method() string {
	r.ensureParsed()
	return r.method
}

// Path returns the request path including query string.
// Lazily parsed from raw bytes on first access.
func (r *HttpRequest) Path() string {
	r.ensureParsed()
	return r.path
}

// Headers returns all HTTP headers as a slice.
// Lazily parsed from raw bytes on first access.
func (r *HttpRequest) Headers() []HttpHeader {
	r.ensureParsed()
	return r.headers
}

// Header returns the value of a specific header (case-insensitive).
// Returns empty string if not found.
func (r *HttpRequest) Header(name string) string {
	r.ensureParsed()
	val, _ := FindHttpHeader(r.headers, name)
	return val
}

// HasHeader checks if a header exists (case-insensitive).
func (r *HttpRequest) HasHeader(name string) bool {
	r.ensureParsed()
	return HttpHeadersContain(r.headers, name)
}

// Body returns the request body as bytes.
func (r *HttpRequest) Body() []byte {
	r.ensureParsed()
	if r.bodyOffset >= len(r.raw) {
		return nil
	}
	return r.raw[r.bodyOffset:]
}

// BodyOffset returns the byte offset where body starts.
func (r *HttpRequest) BodyOffset() int {
	r.ensureParsed()
	return r.bodyOffset
}

// BodyToString returns the body as a string.
func (r *HttpRequest) BodyToString() string {
	body := r.Body()
	if body == nil {
		return ""
	}
	return string(body)
}

// URL constructs and returns the full URL.
//
// The parsed URL is computed once and cached for subsequent calls (raw bytes
// are immutable; the cache is invalidated when the service changes via
// HttpRequestResponse.WithService). The returned *urlutil.URL is SHARED across
// callers and MUST be treated as read-only — callers that need to mutate it
// (e.g. rewrite the path or params) must Clone() it first, as
// BuildRetryableRequest already does.
func (r *HttpRequest) URL() (*urlutil.URL, error) {
	if r.service == nil {
		return nil, ErrNilService
	}

	r.mu.RLock()
	if r.urlComputed {
		u, err := r.cachedURL, r.cachedURLErr
		r.mu.RUnlock()
		return u, err
	}
	r.mu.RUnlock()

	// GetURLFromService now extracts the path via a cheap first-line scan
	// (GetPath no longer parses the whole header block), so this no longer pays
	// a full ExtractAllHeaders pass per probe on top of the one ensureParsed
	// does for the headers/body accessors. We deliberately go through GetPath
	// (parseRequestLineString) rather than the cached r.path: the two request-
	// line parsers disagree on malformed empty-path request lines, and GetPath's
	// is the one that yields the correct ("" -> "/") result for any raw source.
	u, err := GetURLFromService(r.raw, r.service)

	r.mu.Lock()
	r.cachedURL = u
	r.cachedURLErr = err
	r.urlComputed = true
	r.mu.Unlock()
	return u, err
}

// IsMediaPath reports whether the request targets a media or JS/static asset
// (the default-skip set used by active-module eligibility). The result is
// computed once from the cached URL path and memoized, so the regex is not
// re-run for every module's CanProcess on the dispatch hot path. A request
// whose URL cannot be parsed is treated as not media (false); callers that must
// reject unparseable URLs check URL() separately.
func (r *HttpRequest) IsMediaPath() bool {
	r.mu.RLock()
	if r.mediaPathComputed {
		v := r.mediaPath
		r.mu.RUnlock()
		return v
	}
	r.mu.RUnlock()

	// Compute outside the lock: URL() takes r.mu itself.
	var res bool
	if u, err := r.URL(); err == nil && u != nil {
		res = utils.IsMediaAndJSURL(u.Path)
	}

	r.mu.Lock()
	r.mediaPath = res
	r.mediaPathComputed = true
	r.mu.Unlock()
	return res
}

// Parameters analyzes the request and returns all parameters.
// This is NOT cached as it involves deep parsing.
func (r *HttpRequest) Parameters() ([]*Param, error) {
	info, err := AnalyzeRequest(r.raw)
	if err != nil {
		return nil, err
	}
	return info.Parameters, nil
}

// ID returns a unique hash identifier for this request.
// The hash is computed once and cached for subsequent calls. Thread-safe.
func (r *HttpRequest) ID() string {
	r.mu.RLock()
	if r.cachedID != "" {
		r.mu.RUnlock()
		return r.cachedID
	}
	r.mu.RUnlock()

	if len(r.raw) == 0 {
		return ""
	}

	val := sha256.Sum256(r.raw)
	id := hex.EncodeToString(val[:])

	r.mu.Lock()
	r.cachedID = id
	r.mu.Unlock()
	return id
}

// ensureParsed lazily parses the raw request into cached fields.
// Thread-safe via mutex.
func (r *HttpRequest) ensureParsed() {
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

	// Parse request line (first header is request line)
	if len(headerStrings) > 0 {
		r.method, r.path, _ = parseRequestLine(headerStrings[0])
	}

	// Convert header strings to HttpHeader slice
	r.headers = ParseHeadersFromStrings(headerStrings)

	r.parsed = true
}

// TruncateBody truncates the request body to maxSize bytes.
// Headers are preserved. No-op if body is already within limit.
func (r *HttpRequest) TruncateBody(maxSize int) {
	r.ensureParsed()
	bodyLen := len(r.raw) - r.bodyOffset
	if bodyLen <= maxSize || maxSize < 0 {
		return
	}
	r.raw = r.raw[:r.bodyOffset+maxSize]
}

// ============== Immutable Builder Methods ==============

// WithService returns a new HttpRequest with the given service.
func (r *HttpRequest) WithService(service *Service) *HttpRequest {
	return &HttpRequest{
		raw:     r.raw,
		service: service,
	}
}

// WithMethod returns a new HttpRequest with the method replaced.
func (r *HttpRequest) WithMethod(method string) *HttpRequest {
	newRaw, _ := SetMethod(r.raw, method)
	return &HttpRequest{
		raw:     newRaw,
		service: r.service,
	}
}

// WithPath returns a new HttpRequest with the path replaced.
func (r *HttpRequest) WithPath(path string) *HttpRequest {
	newRaw, _ := SetPath(r.raw, path)
	return &HttpRequest{
		raw:     newRaw,
		service: r.service,
	}
}

// WithHeader returns a new HttpRequest with the header set (add or update).
func (r *HttpRequest) WithHeader(name, value string) *HttpRequest {
	newRaw, _ := ReplaceHeader(r.raw, name, value)
	return &HttpRequest{
		raw:     newRaw,
		service: r.service,
	}
}

// WithAddedHeader returns a new HttpRequest with a header added.
// Does not check for duplicates.
func (r *HttpRequest) WithAddedHeader(name, value string) *HttpRequest {
	newRaw, _ := AddHeader(r.raw, name, value)
	return &HttpRequest{
		raw:     newRaw,
		service: r.service,
	}
}

// WithRemovedHeader returns a new HttpRequest with the header removed.
func (r *HttpRequest) WithRemovedHeader(name string) *HttpRequest {
	newRaw, _ := RemoveHeader(r.raw, name)
	return &HttpRequest{
		raw:     newRaw,
		service: r.service,
	}
}

// WithBody returns a new HttpRequest with the body replaced.
// Updates Content-Length header automatically.
func (r *HttpRequest) WithBody(body []byte) *HttpRequest {
	r.ensureParsed()

	// Build new request with updated body
	var headerLines []string
	// Add request line
	headerLines = append(headerLines, r.method+" "+r.path+" HTTP/1.1")
	// Add headers
	headerLines = append(headerLines, HeadersToStrings(r.headers)...)

	newRaw := BuildHttpMessage(headerLines, body)
	newRaw, _ = UpdateContentLength(newRaw)

	return &HttpRequest{
		raw:     newRaw,
		service: r.service,
	}
}

// Clone creates a deep copy of the HttpRequest.
func (r *HttpRequest) Clone() *HttpRequest {
	rawCopy := make([]byte, len(r.raw))
	copy(rawCopy, r.raw)

	var serviceCopy *Service
	if r.service != nil {
		serviceCopy = NewServiceSecure(r.service.Host(), r.service.Port(), r.service.Protocol() == "https")
	}

	return &HttpRequest{
		raw:     rawCopy,
		service: serviceCopy,
	}
}

// ============== Factory Functions ==============

// HttpRequestFromURL creates a basic GET request from a URL string.
// Uses DefaultBrowserHeaders to mimic a real Chrome browser.
func HttpRequestFromURL(urlStr string) (*HttpRequest, error) {
	urlx, err := urlutil.ParseAbsoluteURL(urlStr, false)
	if err != nil {
		return nil, err
	}

	// Build raw request
	var buf bytes.Buffer
	buf.WriteString("GET ")
	buf.WriteString(urlx.GetRelativePath())
	buf.WriteString(" HTTP/1.1\r\n")
	buf.WriteString("Host: ")
	buf.WriteString(urlx.Host)
	buf.WriteString("\r\n")

	// Apply default browser headers in canonical order
	for _, name := range DefaultBrowserHeadersOrder {
		if value, ok := DefaultBrowserHeaders[name]; ok {
			buf.WriteString(name)
			buf.WriteString(": ")
			buf.WriteString(value)
			buf.WriteString("\r\n")
		}
	}

	// buf.WriteString("Connection: close\r\n")
	buf.WriteString("\r\n")

	// Create service
	port := 80
	if urlx.Scheme == "https" {
		port = 443
	}
	if urlx.Port() != "" {
		port = parsePort(urlx.Port())
	}
	service := NewServiceSecure(urlx.Host, port, urlx.Scheme == "https")

	return &HttpRequest{
		raw:     buf.Bytes(),
		service: service,
	}, nil
}

// parsePort converts port string to int with error handling.
func parsePort(portStr string) int {
	if portStr == "" {
		return 0
	}
	port := 0
	for i := 0; i < len(portStr); i++ {
		if portStr[i] < '0' || portStr[i] > '9' {
			return 0
		}
		port = port*10 + int(portStr[i]-'0')
	}
	return port
}

// ============== RequestOption Pattern ==============

// RequestOption is a functional option for building requests efficiently.
// Use with Apply() to batch multiple modifications in a single rebuild.
//
// Example:
//
//	req = req.Apply(
//	    WithOptMethod("POST"),
//	    WithOptHeader("Content-Type", "application/json"),
//	    WithOptHeader("X-Custom", "value"),
//	    WithOptBody(jsonBody),
//	)
type RequestOption func(*requestBuilder)

// headerPair represents a header name-value pair for additions.
type headerPair struct {
	name  string
	value string
}

// requestBuilder accumulates options for efficient batch modification.
type requestBuilder struct {
	method         string
	path           string
	headers        map[string]string // headers to set/replace
	headersToAdd   []headerPair      // headers to add (supports duplicates)
	headersRemove  []string          // headers to remove
	body           []byte
	bodySet        bool
	service        *Service
	serviceChanged bool
}

// WithOptMethod returns an option that sets the HTTP method.
func WithOptMethod(method string) RequestOption {
	return func(b *requestBuilder) {
		b.method = method
	}
}

// WithOptPath returns an option that sets the request path.
func WithOptPath(path string) RequestOption {
	return func(b *requestBuilder) {
		b.path = path
	}
}

// WithOptHeader returns an option that sets or replaces a header.
func WithOptHeader(name, value string) RequestOption {
	return func(b *requestBuilder) {
		if b.headers == nil {
			b.headers = make(map[string]string)
		}
		b.headers[name] = value
	}
}

// WithOptAddHeader returns an option that adds a header (may create duplicates).
func WithOptAddHeader(name, value string) RequestOption {
	return func(b *requestBuilder) {
		b.headersToAdd = append(b.headersToAdd, headerPair{name, value})
	}
}

// WithOptRemoveHeader returns an option that removes a header.
func WithOptRemoveHeader(name string) RequestOption {
	return func(b *requestBuilder) {
		b.headersRemove = append(b.headersRemove, name)
	}
}

// WithOptBody returns an option that sets the request body.
// Content-Length is updated automatically.
func WithOptBody(body []byte) RequestOption {
	return func(b *requestBuilder) {
		b.body = body
		b.bodySet = true
	}
}

// WithOptService returns an option that sets the service.
func WithOptService(service *Service) RequestOption {
	return func(b *requestBuilder) {
		b.service = service
		b.serviceChanged = true
	}
}

// Apply applies multiple options to the request in a single operation.
// This is more efficient than chaining multiple With* methods because
// it only rebuilds the request once at the end.
//
// Example:
//
//	// Inefficient - rebuilds 3 times:
//	req = req.WithMethod("POST").WithHeader("X-A", "1").WithHeader("X-B", "2")
//
//	// Efficient - rebuilds once:
//	req = req.Apply(
//	    WithOptMethod("POST"),
//	    WithOptHeader("X-A", "1"),
//	    WithOptHeader("X-B", "2"),
//	)
func (r *HttpRequest) Apply(opts ...RequestOption) *HttpRequest {
	if len(opts) == 0 {
		return r
	}

	r.ensureParsed()

	// Hold read lock while copying state to avoid data race
	r.mu.RLock()
	builder := &requestBuilder{
		method:  r.method,
		path:    r.path,
		service: r.service,
	}
	r.mu.RUnlock()

	// Apply all options
	for _, opt := range opts {
		opt(builder)
	}

	// Rebuild request with accumulated changes
	return builder.build(r)
}

// build constructs the new HttpRequest from accumulated options.
func (b *requestBuilder) build(original *HttpRequest) *HttpRequest {
	raw := original.raw
	var err error

	// Apply method change
	if b.method != "" && b.method != original.method {
		raw, err = SetMethod(raw, b.method)
		if err != nil {
			zap.L().Debug("Apply: failed to set method",
				zap.String("method", b.method),
				zap.Error(err))
		}
	}

	// Apply path change
	if b.path != "" && b.path != original.path {
		raw, err = SetPath(raw, b.path)
		if err != nil {
			zap.L().Debug("Apply: failed to set path",
				zap.String("path", b.path),
				zap.Error(err))
		}
	}

	// Apply header removals first
	for _, name := range b.headersRemove {
		raw, err = RemoveHeader(raw, name)
		if err != nil {
			zap.L().Debug("Apply: failed to remove header",
				zap.String("name", name),
				zap.Error(err))
		}
	}

	// Apply header replacements
	for name, value := range b.headers {
		raw, err = ReplaceHeader(raw, name, value)
		if err != nil {
			zap.L().Debug("Apply: failed to replace header",
				zap.String("name", name),
				zap.Error(err))
		}
	}

	// Apply header additions (slice supports duplicates)
	for _, h := range b.headersToAdd {
		raw, err = AddHeader(raw, h.name, h.value)
		if err != nil {
			zap.L().Debug("Apply: failed to add header",
				zap.String("name", h.name),
				zap.Error(err))
		}
	}

	// Apply body change. Fast path: when the request has a clean header block with
	// exactly one Content-Length whose value precedes the body, splice the new body
	// and patch Content-Length in a single allocation — no header re-parse, no
	// full message rebuild. This is the common shape for body fuzzers / method-CT
	// swaps, which previously paid ExtractAllHeaders twice plus a BuildHttpMessage
	// rebuild per call.
	if b.bodySet {
		if newRaw, ok := replaceBodyWithCL(raw, b.body); ok {
			raw = newRaw
		} else {
			// Slow path: locate the body offset, splice, then rebuild Content-Length
			// (covers absent/duplicate Content-Length and unparseable headers).
			original.ensureParsed()
			original.mu.RLock()
			bodyOffset := original.bodyOffset
			original.mu.RUnlock()

			// Find current body offset in potentially modified raw
			_, _, currentBodyOffset, _ := ExtractAllHeaders(raw)

			if currentBodyOffset > 0 && currentBodyOffset <= len(raw) {
				// Allocate exact size needed and replace body directly
				newSize := currentBodyOffset + len(b.body)
				newRaw := make([]byte, newSize)
				copy(newRaw, raw[:currentBodyOffset])
				copy(newRaw[currentBodyOffset:], b.body)
				raw = newRaw
			} else if bodyOffset > 0 {
				// Fallback: use original body offset if current parse failed
				newSize := bodyOffset + len(b.body)
				newRaw := make([]byte, newSize)
				copy(newRaw, raw[:bodyOffset])
				copy(newRaw[bodyOffset:], b.body)
				raw = newRaw
			}

			// Update Content-Length header
			raw, err = UpdateContentLength(raw)
			if err != nil {
				zap.L().Debug("Apply: failed to update content-length", zap.Error(err))
			}
		}
	}

	// Determine service
	service := original.service
	if b.serviceChanged {
		service = b.service
	}

	return &HttpRequest{
		raw:     raw,
		service: service,
	}
}

// replaceBodyWithCL replaces the request body with newBody and rewrites the
// Content-Length value in place, in a single allocation and with no header
// re-parse or message rebuild. It mirrors ParameterInsertionPoint.buildWithContentLength.
//
// It succeeds (ok==true) only when raw has a parseable header block with exactly
// one Content-Length header whose value lies before the body — the common case.
// Otherwise it returns ok==false so the caller can fall back to the
// splice + UpdateContentLength slow path (absent/duplicate Content-Length, or
// headers that don't parse). The eligibility check is shared with the
// insertion-point fast path via computeCLRewriteRaw.
func replaceBodyWithCL(raw, newBody []byte) ([]byte, bool) {
	cl := computeCLRewriteRaw(raw)
	if !cl.fast {
		return nil, false
	}

	clStr := intToString(len(newBody))
	resultSize := cl.valueStart + len(clStr) + (cl.bodyOffset - cl.valueEnd) + len(newBody)
	result := make([]byte, resultSize)
	n := copy(result, raw[:cl.valueStart])                // headers up to old Content-Length value
	n += copy(result[n:], clStr)                          // new Content-Length value
	n += copy(result[n:], raw[cl.valueEnd:cl.bodyOffset]) // rest of headers + blank line
	copy(result[n:], newBody)                             // new body
	return result, true
}

// Sentinel error
var ErrNilService = &nilServiceError{}

type nilServiceError struct{}

func (e *nilServiceError) Error() string {
	return "service is nil"
}
