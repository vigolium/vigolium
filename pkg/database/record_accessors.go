package database

import (
	"encoding/json"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// ParsedRequest parses RawRequest into an httpmsg.HttpRequest. Returns nil
// when there is no raw request. Each call constructs a new parser; callers
// that need multiple fields should hoist the result into a local, or use
// parsedView for the standard four-field expansion.
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

// ParsedView decodes RawRequest and RawResponse exactly once each and returns
// the four derived fields. Use this whenever a caller needs more than one
// derived field — calling individual accessors for each field re-parses.
//
// When raw bytes are absent (e.g., list endpoints exclude raw_* columns),
// returned values are nil — that is what makes the JSON projection in
// HandleListRecords drop the four derived fields.
func (r *HTTPRecord) ParsedView() (reqHdrs, respHdrs map[string][]string, reqBody, respBody []byte) {
	if req := r.ParsedRequest(); req != nil {
		reqHdrs = headersToMap(req.Headers())
		reqBody = req.Body()
	}
	if resp := r.ParsedResponse(); resp != nil {
		respHdrs = headersToMap(resp.Headers())
		respBody = resp.Body()
	}
	return
}

// MarshalJSON preserves the external JSON contract by injecting four derived
// fields (request_headers, request_body, response_headers, response_body)
// alongside the stored struct fields.
func (r *HTTPRecord) MarshalJSON() ([]byte, error) {
	type alias HTTPRecord
	reqHeaders, respHeaders, reqBody, respBody := r.ParsedView()

	return json.Marshal(&struct {
		*alias
		RequestHeaders  map[string][]string `json:"request_headers,omitempty"`
		RequestBody     []byte              `json:"request_body,omitempty"`
		ResponseHeaders map[string][]string `json:"response_headers,omitempty"`
		ResponseBody    []byte              `json:"response_body,omitempty"`
	}{
		alias:           (*alias)(r),
		RequestHeaders:  reqHeaders,
		RequestBody:     reqBody,
		ResponseHeaders: respHeaders,
		ResponseBody:    respBody,
	})
}
