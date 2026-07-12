package httpmsg

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/textproto"
	"net/url"
	"sort"
	"strconv"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/retryablehttp-go"
	urlutil "github.com/projectdiscovery/utils/url"
)

// HttpRequestResponse is a unified struct containing HTTP request and response.
//
// Design:
//   - Contains HttpRequest (required) and HttpResponse (optional)
//   - Service info is delegated to the request
//   - Provides convenience methods for common operations
type HttpRequestResponse struct {
	request  *HttpRequest
	response *HttpResponse
}

// NewHttpRequestResponse creates a new HttpRequestResponse from request and optional response.
func NewHttpRequestResponse(request *HttpRequest, response *HttpResponse) *HttpRequestResponse {
	return &HttpRequestResponse{
		request:  request,
		response: response,
	}
}

// Request returns the HTTP request.
func (h *HttpRequestResponse) Request() *HttpRequest {
	return h.request
}

// Response returns the HTTP response (may be nil).
func (h *HttpRequestResponse) Response() *HttpResponse {
	return h.response
}

// Service returns the HTTP service info (delegated to request).
func (h *HttpRequestResponse) Service() *Service {
	if h.request == nil {
		return nil
	}
	return h.request.Service()
}

// HasResponse returns true if there is an HTTP response.
func (h *HttpRequestResponse) HasResponse() bool {
	return h.response != nil
}

// URL returns the URL by delegating to Request.URL().
func (h *HttpRequestResponse) URL() (*urlutil.URL, error) {
	if h.request == nil {
		return nil, fmt.Errorf("request is nil")
	}
	return h.request.URL()
}

// Target returns the target URL as a string.
func (h *HttpRequestResponse) Target() string {
	urlx, err := h.URL()
	if err != nil {
		return ""
	}
	return urlx.String()
}

// ID returns a unique identifier for host-based tracking.
// Returns FNV-1a hash of host:port:method for efficient cache key usage.
func (h *HttpRequestResponse) ID() string {
	service := h.Service()
	if service == nil {
		return ""
	}
	method := ""
	if h.request != nil {
		method = h.request.Method()
	}
	hash := fnv.New64a()
	hash.Write([]byte(service.Host()))
	hash.Write([]byte{':'})
	hash.Write([]byte(strconv.Itoa(service.Port())))
	hash.Write([]byte{':'})
	hash.Write([]byte(method))
	return strconv.FormatUint(hash.Sum64(), 16)
}

// GetScanHash returns a unique hash that represents a scan by hashing (URL + templateId).
func (h *HttpRequestResponse) GetScanHash(templateId string) string {
	urlx, err := h.URL()
	if err != nil {
		return ""
	}
	var rawRequest string
	if h.request != nil {
		rawRequest = h.request.ID()
	}
	data := templateId + ":" + urlx.String() + rawRequest
	bin := md5.Sum([]byte(data))
	return string(bin[:])
}

// Clone creates a deep copy of the HttpRequestResponse.
func (h *HttpRequestResponse) Clone() *HttpRequestResponse {
	cloned := &HttpRequestResponse{}
	if h.request != nil {
		cloned.request = h.request.Clone()
	}
	if h.response != nil {
		cloned.response = h.response.Clone()
	}
	return cloned
}

// WithService sets the service on the request and returns the same HttpRequestResponse.
// This is a mutating method for convenience when building requests.
func (h *HttpRequestResponse) WithService(service *Service) *HttpRequestResponse {
	if h.request != nil {
		h.request.mu.Lock()
		h.request.service = service
		// Invalidate the cached URL since it depends on the service.
		h.request.cachedURL = nil
		h.request.cachedURLErr = nil
		h.request.urlComputed = false
		h.request.mu.Unlock()
	}
	return h
}

// WithResponse returns a new HttpRequestResponse with the given response.
// This allows setting a response on a request-only HttpRequestResponse.
func (h *HttpRequestResponse) WithResponse(response *HttpResponse) *HttpRequestResponse {
	return &HttpRequestResponse{
		request:  h.request,
		response: response,
	}
}

// BuildRetryableRequest builds a retryablehttp request from the request response.
// Note: This method builds a fresh request every time (no caching).
func (h *HttpRequestResponse) BuildRetryableRequest() (*retryablehttp.Request, error) {
	urlx, err := h.URL()
	if err != nil {
		return nil, fmt.Errorf("failed to get URL: %w", err)
	}
	urlClone := urlx.Clone()
	body := h.request.Body()
	var bodyReader io.Reader = nil
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}
	req, err := retryablehttp.NewRequestFromURL(h.request.Method(), urlClone, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("could not create request: %w", err)
	}
	for _, header := range h.request.Headers() {
		req.Header.Add(header.Name, header.Value)
	}
	return req, nil
}

// BuildRetryableRequestWithContext is BuildRetryableRequest with ctx attached to
// the underlying *http.Request, so cancelling ctx aborts the in-flight request
// (and its retry loop). Like the stdlib, ctx must be non-nil; pass
// context.Background() when there is nothing to cancel against.
func (h *HttpRequestResponse) BuildRetryableRequestWithContext(ctx context.Context) (*retryablehttp.Request, error) {
	req, err := h.BuildRetryableRequest()
	if err != nil {
		return nil, err
	}
	return req.WithContext(ctx), nil
}

// CreateInsertionPoints creates insertion points from the request.
// Convenience method that wraps CreateAllInsertionPoints.
func (h *HttpRequestResponse) CreateInsertionPoints(includeNested bool) ([]InsertionPoint, error) {
	if h.request == nil {
		return nil, fmt.Errorf("request is nil")
	}
	return CreateAllInsertionPoints(h.request.Raw(), includeNested)
}

// PrettyPrint returns a formatted string for display.
func (h *HttpRequestResponse) PrettyPrint() string {
	urlx, err := h.URL()
	if err != nil {
		return ""
	}
	if h.request != nil {
		return fmt.Sprintf("%s [%s]", urlx.String(), h.request.Method())
	}
	return urlx.String()
}

// ============== JSON Serialization ==============

var (
	_ json.Marshaler   = &HttpRequestResponse{}
	_ json.Unmarshaler = &HttpRequestResponse{}
)

// jsonFast is the fastest jsoniter config — no HTML escaping, no sorting of map keys.
var jsonFast = jsoniter.ConfigFastest

// MarshalJSON marshals the request response to JSON.
// Uses jsoniter with shadow structs for single-pass serialization,
// eliminating the previous triple-marshal pattern.
func (h *HttpRequestResponse) MarshalJSON() ([]byte, error) {
	urlx, err := h.URL()
	if err != nil {
		return nil, fmt.Errorf("failed to get URL for marshaling: %w", err)
	}

	type requestPayload struct {
		Method  string       `json:"method"`
		Headers []HttpHeader `json:"headers"`
		Raw     []byte       `json:"raw"`
	}
	type responsePayload struct {
		StatusCode int          `json:"status_code"`
		Headers    []HttpHeader `json:"headers"`
		Raw        string       `json:"raw"`
		// Note: the body is intentionally not serialized separately — Raw already
		// contains it verbatim, and UnmarshalJSON reconstructs the response from
		// Raw alone. Emitting a redundant "body" field meant a second full
		// JSON-escape pass over the body and ~doubled the serialized body size.
	}
	type envelope struct {
		URL      string           `json:"url"`
		Request  requestPayload   `json:"request"`
		Response *responsePayload `json:"response,omitempty"`
	}

	env := envelope{
		URL: urlx.String(),
		Request: requestPayload{
			Method:  h.request.Method(),
			Headers: h.request.Headers(),
			Raw:     h.request.Raw(),
		},
	}

	if h.response != nil {
		env.Response = &responsePayload{
			StatusCode: h.response.StatusCode(),
			Headers:    h.response.Headers(),
			Raw:        string(h.response.Raw()),
		}
	}

	return jsonFast.Marshal(env)
}

// UnmarshalJSON unmarshals the request response from JSON.
func (h *HttpRequestResponse) UnmarshalJSON(data []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	urlStr, ok := m["url"]
	if !ok {
		return fmt.Errorf("missing url in request response")
	}
	// Remove quotes from JSON string
	var urlString string
	if err := json.Unmarshal(urlStr, &urlString); err != nil {
		return err
	}
	parsed, err := urlutil.ParseAbsoluteURL(urlString, false)
	if err != nil {
		return err
	}

	// Unmarshal request
	reqBin, ok := m["request"]
	if ok {
		var reqData struct {
			Method  string       `json:"method"`
			Headers []HttpHeader `json:"headers"`
			Raw     []byte       `json:"raw"`
		}
		if err := json.Unmarshal(reqBin, &reqData); err != nil {
			return err
		}

		// Create service from URL
		port := 80
		protocol := "http"
		if parsed.Scheme == "https" {
			protocol = "https"
			port = 443
		}
		urlPort := parsed.Port()
		if urlPort != "" {
			port = parsePort(urlPort)
		}
		service, _ := NewService(parsed.Host, port, protocol)

		h.request = &HttpRequest{
			raw:     reqData.Raw,
			service: service,
		}
	}

	// Unmarshal response if present
	respBin, ok := m["response"]
	if ok {
		var respData struct {
			StatusCode int          `json:"status_code"`
			Headers    []HttpHeader `json:"headers"`
			Raw        string       `json:"raw"`
		}
		if err := json.Unmarshal(respBin, &respData); err != nil {
			return err
		}
		h.response = &HttpResponse{
			raw: []byte(respData.Raw),
		}
	}
	return nil
}

// MarshalString marshals to JSON string.
func (h *HttpRequestResponse) MarshalString() (string, error) {
	b, err := h.marshalToBuffer()
	return b.String(), err
}

// MustMarshalString marshals to JSON string (ignores error).
func (h *HttpRequestResponse) MustMarshalString() string {
	marshaled, _ := h.MarshalString()
	return marshaled
}

// MarshalBytes marshals to JSON bytes.
func (h *HttpRequestResponse) MarshalBytes() ([]byte, error) {
	b, err := h.marshalToBuffer()
	return b.Bytes(), err
}

// MustMarshalBytes marshals to JSON bytes (ignores error).
func (h *HttpRequestResponse) MustMarshalBytes() []byte {
	marshaled, _ := h.MarshalBytes()
	return marshaled
}

func (h *HttpRequestResponse) marshalToBuffer() (bytes.Buffer, error) {
	var b bytes.Buffer
	err := jsoniter.NewEncoder(&b).Encode(h)
	return b, err
}

// ============== Factory Functions ==============

// NewRequestResponseRaw wraps already-built raw request bytes and a known service
// into an HttpRequestResponse WITHOUT re-parsing them. It is the fast-path
// replacement for the `ParseRawRequest(string(builtBytes)).WithService(svc)`
// idiom on the per-payload hot path: the raw produced by InsertionPoint.BuildRequest
// / SetMethod / AddHeader / SetPath / SetBody is already well-formed, so the
// textproto re-parse, the throwaway Service construction, and the []byte→string→
// []byte round-trip that ParseRawRequest performs are pure overhead. The request
// parses its fields lazily (HttpRequest.ensureParsed) only if a caller reads them.
//
// Use this only with TRUSTED, internally-built raw bytes. For untrusted external
// input that must be validated, use ParseRawRequest (it returns a parse error).
func NewRequestResponseRaw(raw []byte, service *Service) *HttpRequestResponse {
	return NewHttpRequestResponse(NewHttpRequestWithService(service, raw), nil)
}

// ParseRawRequest parses a raw HTTP request from a string.
// Note: Response field is optional and should be added manually if needed.
func ParseRawRequest(raw string) (rr *HttpRequestResponse, err error) {
	defer func() {
		// panic handle (recover from panic)
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	protoReader := textproto.NewReader(bufio.NewReader(strings.NewReader(raw)))
	methodLine, err := protoReader.ReadLine()
	if err != nil {
		return nil, fmt.Errorf("failed to read method line: %w", err)
	}
	rr = &HttpRequestResponse{
		request: &HttpRequest{},
	}
	/// must contain at least 3 parts
	parts := strings.Split(methodLine, " ")
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid method line: %s", methodLine)
	}

	// parse relative url to determine scheme (http/https)
	urlx, err := urlutil.ParseRawRelativePath(parts[1], true)
	if err != nil {
		return nil, fmt.Errorf("failed to parse url: %w", err)
	}

	// parse host line
	hostLine, err := protoReader.ReadLine()
	if err != nil {
		return nil, fmt.Errorf("failed to read host line: %w", err)
	}
	sep := strings.Index(hostLine, ":")
	if sep <= 0 || sep >= len(hostLine)-1 {
		return nil, fmt.Errorf("invalid host line: %s", hostLine)
	}
	hostValue := hostLine[sep+2:]

	// Build raw request with all headers
	rr.request.raw = []byte(raw)

	// Populate Service from host and URL scheme.
	// Raw HTTP request lines use origin-form (no scheme), so we infer the scheme
	// in priority order: an explicit scheme on the request line (absolute-form) >
	// a well-known Host port (80/443) > a same-origin Origin/Referer header > the
	// https default. The default is https because modern web is TLS by default;
	// callers that need http explicitly can still pass it via the URL field or
	// override the service with WithService.
	if hostValue != "" {
		protocol := "https"
		schemeKnown := false
		portExplicit := false
		port := 0

		// Absolute-form request lines (e.g. CONNECT, proxy form) may carry a scheme.
		switch urlx.Scheme {
		case "http":
			protocol, schemeKnown = "http", true
		case "https":
			protocol, schemeKnown = "https", true
		}
		// Extract port from Host header value (e.g. "127.0.0.1:3000").
		if h, p, splitErr := net.SplitHostPort(hostValue); splitErr == nil {
			hostValue = h
			if parsed := parsePort(p); parsed > 0 {
				port, portExplicit = parsed, true
				// Infer scheme from a well-known port only when none was explicit.
				if !schemeKnown {
					switch parsed {
					case 80:
						protocol, schemeKnown = "http", true
					case 443:
						protocol, schemeKnown = "https", true
					}
				}
			}
		}
		// When neither the request line nor a well-known port pins the scheme,
		// fall back to the scheme declared by a same-origin Origin/Referer header.
		// Browser/proxy-captured requests to an http service on a non-standard port
		// (e.g. "Host: localhost:3000" with "Referer: http://localhost:3000/")
		// would otherwise be silently upgraded to https by the default below.
		if !schemeKnown {
			// Thread the already-computed target port (from the Host header, 0 when
			// none) so a same-host Origin/Referer on a DIFFERENT port is not treated
			// as same-origin and cannot flip the scheme (e.g. a :3000 frontend Origin
			// on a request to an :8443 API must not infer http for the TLS service).
			if s, _, ok := originRefererScheme(raw, hostValue, port); ok {
				protocol = s
			}
		}
		// Also try the port from the URL path (absolute-form lines like CONNECT).
		if urlPort := urlx.Port(); urlPort != "" {
			if parsed := parsePort(urlPort); parsed > 0 {
				port, portExplicit = parsed, true
			}
		}
		// Default the port from the resolved scheme when the Host carried none.
		if !portExplicit {
			if protocol == "http" {
				port = 80
			} else {
				port = 443
			}
		}
		service, _ := NewService(hostValue, port, protocol)
		rr.request.service = service
	}

	return rr, nil
}

// OriginRefererScheme returns the URL scheme ("http" or "https") declared by the
// request's Origin or Referer header, but only when that header names the same
// host we are about to connect to. It lets raw requests captured from a
// browser/proxy keep their real scheme when the request line is origin-form (no
// scheme) and the port is non-standard — e.g. an http service on :3000. A
// cross-origin Origin/Referer (a different host, as in a CORS request or an
// external referrer) is ignored so it cannot mislead scheme inference; Origin is
// preferred over Referer as it is the exact origin the browser attached. host
// must be the bare hostname (no port). header names which header supplied the
// scheme ("Origin"/"Referer"), which callers can surface to the user. Returns
// ok=false when neither header yields a same-host http/https scheme.
func OriginRefererScheme(raw, host string) (scheme, header string, ok bool) {
	// Derive the target port from the request's own Host header so external callers
	// get the same cross-port safety as the parse path (0 when the Host carried no
	// explicit port, which preserves host-only matching).
	return originRefererScheme(raw, host, hostHeaderPort(raw))
}

// originRefererScheme is the port-aware core of OriginRefererScheme. targetPort is
// the port of the service being connected to (0 when unknown); when > 0 an
// Origin/Referer must match both host and port to be treated as same-origin.
func originRefererScheme(raw, host string, targetPort int) (scheme, header string, ok bool) {
	if host == "" {
		return "", "", false
	}
	sc := bufio.NewScanner(strings.NewReader(raw))
	sc.Buffer(make([]byte, 0, 8*1024), 1024*1024)
	refererScheme := ""
	first := true
	for sc.Scan() {
		line := sc.Text()
		if first { // request line
			first = false
			continue
		}
		if line == "" { // blank line terminates the header block
			break
		}
		name, value, cut := strings.Cut(line, ":")
		if !cut {
			continue
		}
		if strings.EqualFold(name, "Origin") {
			if s := sameHostScheme(value, host, targetPort); s != "" {
				return s, "Origin", true
			}
		} else if refererScheme == "" && strings.EqualFold(name, "Referer") {
			refererScheme = sameHostScheme(value, host, targetPort)
		}
	}
	if refererScheme != "" {
		return refererScheme, "Referer", true
	}
	return "", "", false
}

// sameHostScheme parses an absolute URL (an Origin or Referer value) and returns
// its scheme only when it is http/https and its hostname case-insensitively
// equals host. When targetPort > 0 the URL's authority port (an empty port
// normalizes to the scheme default 80/443) must also equal targetPort — this
// stops a same-host, different-port Origin/Referer from being treated as
// same-origin. Returns "" otherwise (parse failure, opaque origin, non-http(s)
// scheme, a cross-origin host, or a cross-port authority when targetPort is set).
func sameHostScheme(rawURL, host string, targetPort int) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return ""
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	if !strings.EqualFold(u.Hostname(), host) {
		return ""
	}
	if targetPort > 0 && originURLPort(u) != targetPort {
		return ""
	}
	return u.Scheme
}

// originURLPort returns the authority port of u, normalizing an empty port to the
// scheme's default (80 for http, 443 for https/other).
func originURLPort(u *url.URL) int {
	if p := u.Port(); p != "" {
		return parsePort(p)
	}
	if u.Scheme == "http" {
		return 80
	}
	return 443
}

// hostHeaderPort returns the port declared in the request's Host header, or 0
// when the Host header is absent or carries no explicit port.
func hostHeaderPort(raw string) int {
	sc := bufio.NewScanner(strings.NewReader(raw))
	sc.Buffer(make([]byte, 0, 8*1024), 1024*1024)
	first := true
	for sc.Scan() {
		line := sc.Text()
		if first { // request line
			first = false
			continue
		}
		if line == "" { // blank line terminates the header block
			break
		}
		name, value, cut := strings.Cut(line, ":")
		if !cut {
			continue
		}
		if strings.EqualFold(name, "Host") {
			if _, p, err := net.SplitHostPort(strings.TrimSpace(value)); err == nil {
				return parsePort(p)
			}
			return 0
		}
	}
	return 0
}

// ParseRawRequestWithURL parses a raw HTTP request with explicit URL override.
func ParseRawRequestWithURL(raw, url string) (*HttpRequestResponse, error) {
	rr, err := ParseRawRequest(raw)
	if err != nil {
		return nil, err
	}
	urlx, err := urlutil.ParseAbsoluteURL(url, false)
	if err != nil {
		return nil, err
	}

	// Update Service with the overridden URL
	if rr.request != nil {
		port := 80
		protocol := "http"
		if urlx.Scheme == "https" {
			protocol = "https"
			port = 443
		}
		urlPort := urlx.Port()
		if urlPort != "" {
			port = parsePort(urlPort)
		}
		service, _ := NewService(urlx.Host, port, protocol)
		rr.request.service = service
	}

	return rr, nil
}

// GetRawRequestFromURL creates a basic GET request from a URL.
// Default browser headers will be applied by the HTTP client at request time.
func GetRawRequestFromURL(url string) (*HttpRequestResponse, error) {
	urlx, err := urlutil.ParseAbsoluteURL(url, false)
	if err != nil {
		return nil, err
	}
	raw := fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\n\r\n",
		escapedRequestTarget(urlx),
		urlx.Host,
	)
	rr, err := ParseRawRequest(raw)
	if err != nil {
		return nil, err
	}

	// Update Service with the correct URL
	if rr.request != nil {
		port := 80
		protocol := "http"
		if urlx.Scheme == "https" {
			protocol = "https"
			port = 443
		}
		urlPort := urlx.Port()
		if urlPort != "" {
			port = parsePort(urlPort)
		}
		service, _ := NewService(urlx.Host, port, protocol)
		rr.request.service = service
	}

	return rr, nil
}

// GetRawRequestFromURLWithMethod creates a request from a URL while preserving
// the discovered HTTP method, request headers, and body. This is the
// method/body-aware counterpart to GetRawRequestFromURL: it lets non-GET
// discoveries (form POSTs, JS-derived API calls) be imported without being
// flattened to a bodyless GET, which would silently lose API and form coverage.
//
// When method is empty/GET and body is empty it delegates to
// GetRawRequestFromURL for identical behavior. Header values containing CR/LF
// are dropped to avoid request smuggling from malformed stored headers; Host and
// Content-Length are always managed here (never taken from the stored map).
func GetRawRequestFromURLWithMethod(rawURL, method string, headers map[string]string, body []byte) (*HttpRequestResponse, error) {
	method = strings.ToUpper(strings.TrimSpace(method))
	if (method == "" || method == "GET") && len(body) == 0 {
		return GetRawRequestFromURL(rawURL)
	}
	if method == "" {
		method = "GET"
	}

	urlx, err := urlutil.ParseAbsoluteURL(rawURL, false)
	if err != nil {
		return nil, err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", method, escapedRequestTarget(urlx))
	fmt.Fprintf(&b, "Host: %s\r\n", urlx.Host)

	// Emit stored headers deterministically, skipping ones we manage (Host is set
	// above; Content-Length is derived from body) and any with control chars.
	keys := make([]string, 0, len(headers))
	for k := range headers {
		switch http.CanonicalHeaderKey(k) {
		case "Host", "Content-Length":
			continue
		}
		if strings.ContainsAny(k, "\r\n") || strings.ContainsAny(headers[k], "\r\n") {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "%s: %s\r\n", k, headers[k])
	}

	if len(body) > 0 {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	}
	b.WriteString("\r\n")
	if len(body) > 0 {
		b.Write(body)
	}

	// The raw is internally built and trusted, so skip the ParseRawRequest
	// re-parse + throwaway Service and wrap it directly with the correct service.
	port := 80
	protocol := "http"
	if urlx.Scheme == "https" {
		protocol = "https"
		port = 443
	}
	if urlPort := urlx.Port(); urlPort != "" {
		port = parsePort(urlPort)
	}
	service, _ := NewService(urlx.Host, port, protocol)
	return NewRequestResponseRaw([]byte(b.String()), service), nil
}

// FromStdRequest creates HttpRequestResponse from a standard http.Request.
func FromStdRequest(req *http.Request) (*HttpRequestResponse, error) {
	// Check if original request has User-Agent BEFORE dumping
	// (DumpRequestOut auto-adds "User-Agent: Go-http-client/1.1")
	hasOriginalUA := req.Header.Get("User-Agent") != ""

	// DumpRequestOut will automatically add the scheme and host to the request
	dumpRequest, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		return nil, fmt.Errorf("failed to dump request: %w", err)
	}
	rr, err := ParseRawRequest(string(dumpRequest))
	if err != nil {
		return nil, fmt.Errorf("failed to parse raw request: %w", err)
	}

	// Remove Go's auto-added User-Agent if original didn't have one
	if !hasOriginalUA && rr.request != nil {
		rr.request = rr.request.WithRemovedHeader("User-Agent")
	}

	// Update Service with correct scheme and port from original request URL
	if rr.request != nil && req.URL != nil {
		port := 80
		isHTTPS := req.URL.Scheme == "https"
		if isHTTPS {
			port = 443
		}
		// Get port from original URL (not from parsed service which may be wrong)
		if urlPort := req.URL.Port(); urlPort != "" {
			port = parsePort(urlPort)
		}
		host := req.URL.Hostname()
		rr.request.service = NewServiceSecure(host, port, isHTTPS)
	}

	return rr, nil
}
