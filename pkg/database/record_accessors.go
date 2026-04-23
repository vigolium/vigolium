package database

import (
	"encoding/json"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// ParsedRequest parses RawRequest into an httpmsg.HttpRequest. Returns nil
// when there is no raw request. Parsing is a cheap byte-scan — we skip
// memoization to avoid unbounded retention of record objects in long scans.
func (r *HTTPRecord) ParsedRequest() *httpmsg.HttpRequest {
	if r == nil || len(r.RawRequest) == 0 {
		return nil
	}
	return httpmsg.NewHttpRequest(r.RawRequest)
}

// ParsedResponse parses RawResponse into an httpmsg.HttpResponse, or nil when
// no raw response is present.
func (r *HTTPRecord) ParsedResponse() *httpmsg.HttpResponse {
	if r == nil || !r.HasResponse || len(r.RawResponse) == 0 {
		return nil
	}
	return httpmsg.NewHttpResponse(r.RawResponse)
}

// RequestBodyBytes returns the request body bytes parsed from RawRequest.
func (r *HTTPRecord) RequestBodyBytes() []byte {
	req := r.ParsedRequest()
	if req == nil {
		return nil
	}
	return req.Body()
}

// ResponseBodyBytes returns the response body bytes parsed from RawResponse.
func (r *HTTPRecord) ResponseBodyBytes() []byte {
	resp := r.ParsedResponse()
	if resp == nil {
		return nil
	}
	return resp.Body()
}

// RequestHeadersMap returns request headers as a map[name][]values.
func (r *HTTPRecord) RequestHeadersMap() map[string][]string {
	req := r.ParsedRequest()
	if req == nil {
		return nil
	}
	return headersToMap(req.Headers())
}

// ResponseHeadersMap returns response headers as a map[name][]values.
func (r *HTTPRecord) ResponseHeadersMap() map[string][]string {
	resp := r.ParsedResponse()
	if resp == nil {
		return nil
	}
	return headersToMap(resp.Headers())
}

func headersToMap(hdrs []httpmsg.HttpHeader) map[string][]string {
	if len(hdrs) == 0 {
		return nil
	}
	m := make(map[string][]string, len(hdrs))
	for _, h := range hdrs {
		m[h.Name] = append(m[h.Name], h.Value)
	}
	return m
}

// MarshalJSON preserves the external contract for JSON consumers by injecting
// the four derived fields (request_headers, request_body, response_headers,
// response_body) alongside the stored struct fields. Consumed by jsext
// `vigolium.db` query result and any REST API client expecting these fields.
func (r *HTTPRecord) MarshalJSON() ([]byte, error) {
	type alias HTTPRecord
	return json.Marshal(&struct {
		*alias
		RequestHeaders  map[string][]string `json:"request_headers,omitempty"`
		RequestBody     []byte              `json:"request_body,omitempty"`
		ResponseHeaders map[string][]string `json:"response_headers,omitempty"`
		ResponseBody    []byte              `json:"response_body,omitempty"`
	}{
		alias:           (*alias)(r),
		RequestHeaders:  r.RequestHeadersMap(),
		RequestBody:     r.RequestBodyBytes(),
		ResponseHeaders: r.ResponseHeadersMap(),
		ResponseBody:    r.ResponseBodyBytes(),
	})
}
