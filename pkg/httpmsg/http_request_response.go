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
		Body       string       `json:"body,omitempty"`
		Raw        string       `json:"raw"`
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
			Body:       h.response.BodyToString(),
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
			Body       string       `json:"body"`
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
	// Raw HTTP request lines use origin-form (no scheme), so absent an explicit
	// signal we default to https — modern web is TLS by default, and downstream
	// callers that need http explicitly should pass it via the URL field or
	// override the service with WithService.
	if hostValue != "" {
		port := 443
		protocol := "https"
		// Absolute-form request lines (e.g. CONNECT, proxy form) may carry a scheme.
		switch urlx.Scheme {
		case "http":
			protocol = "http"
			port = 80
		case "https":
			protocol = "https"
			port = 443
		}
		// Extract port from Host header value (e.g. "127.0.0.1:3000")
		if h, p, splitErr := net.SplitHostPort(hostValue); splitErr == nil {
			hostValue = h
			if parsed := parsePort(p); parsed > 0 {
				port = parsed
				// Infer scheme from well-known port only when no explicit scheme was present.
				if urlx.Scheme == "" {
					switch parsed {
					case 80:
						protocol = "http"
					case 443:
						protocol = "https"
					}
				}
			}
		}
		// Also try from URL path (for absolute-form request lines like CONNECT)
		urlPort := urlx.Port()
		if urlPort != "" {
			port = parsePort(urlPort)
		}
		service, _ := NewService(hostValue, port, protocol)
		rr.request.service = service
	}

	return rr, nil
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
		urlx.GetRelativePath(),
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
