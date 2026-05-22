package database

import (
	"bytes"
	"reflect"
	"testing"
)

// These tests complement record_accessors_test.go by focusing on multi-valued
// header accumulation, repeated-call idempotency, and ParsedView — behaviors
// the existing single-value tests don't exercise.

const (
	accRawRequest = "POST /submit HTTP/1.1\r\n" +
		"Host: api.example.com\r\n" +
		"Content-Type: application/json\r\n" +
		"X-Custom: a\r\n" +
		"X-Custom: b\r\n" +
		"Content-Length: 12\r\n" +
		"\r\n" +
		`{"name":"x"}`
	accRawResponse = "HTTP/1.1 201 Created\r\n" +
		"Content-Type: application/json\r\n" +
		"Set-Cookie: a=1\r\n" +
		"Set-Cookie: b=2\r\n" +
		"\r\n" +
		`{"ok":true}`
)

func newAccessorRecord() *HTTPRecord {
	return &HTTPRecord{
		HasResponse: true,
		RawRequest:  []byte(accRawRequest),
		RawResponse: []byte(accRawResponse),
	}
}

func TestParsedAccessors_Idempotent(t *testing.T) {
	rec := newAccessorRecord()

	// ParsedRequest is re-parsed each call but must be content-stable.
	req1 := rec.ParsedRequest()
	req2 := rec.ParsedRequest()
	if req1 == nil || req2 == nil {
		t.Fatal("ParsedRequest returned nil")
	}
	if req1.Method() != req2.Method() || req1.Path() != req2.Path() {
		t.Error("ParsedRequest inconsistent across calls")
	}

	resp1 := rec.ParsedResponse()
	resp2 := rec.ParsedResponse()
	if resp1 == nil || resp2 == nil {
		t.Fatal("ParsedResponse returned nil")
	}
	if resp1.StatusCode() != 201 || resp2.StatusCode() != 201 {
		t.Errorf("StatusCode inconsistent: %d vs %d", resp1.StatusCode(), resp2.StatusCode())
	}

	if !bytes.Equal(rec.RequestBodyBytes(), rec.RequestBodyBytes()) {
		t.Error("RequestBodyBytes not stable across calls")
	}
	if !bytes.Equal(rec.ResponseBodyBytes(), rec.ResponseBodyBytes()) {
		t.Error("ResponseBodyBytes not stable across calls")
	}
}

func TestRequestHeadersMap_MultiValued(t *testing.T) {
	rec := newAccessorRecord()
	m := rec.RequestHeadersMap()
	if m == nil {
		t.Fatal("RequestHeadersMap returned nil")
	}
	// Repeated request headers must accumulate into the slice in order.
	if custom := m["X-Custom"]; len(custom) != 2 || custom[0] != "a" || custom[1] != "b" {
		t.Errorf("X-Custom = %v, want [a b]", custom)
	}
	// Idempotent.
	if !reflect.DeepEqual(m, rec.RequestHeadersMap()) {
		t.Error("RequestHeadersMap not stable across calls")
	}
}

func TestResponseHeadersMap_MultiValued(t *testing.T) {
	rec := newAccessorRecord()
	m := rec.ResponseHeadersMap()
	if m == nil {
		t.Fatal("ResponseHeadersMap returned nil")
	}
	// Two Set-Cookie headers must both be preserved.
	if cookies := m["Set-Cookie"]; len(cookies) != 2 || cookies[0] != "a=1" || cookies[1] != "b=2" {
		t.Errorf("Set-Cookie = %v, want [a=1 b=2]", cookies)
	}
	if !reflect.DeepEqual(m, rec.ResponseHeadersMap()) {
		t.Error("ResponseHeadersMap not stable across calls")
	}
}

func TestParsedView_PopulatesAllFields(t *testing.T) {
	rec := newAccessorRecord()
	reqHdrs, respHdrs, reqBody, respBody := rec.ParsedView()
	if reqHdrs == nil || respHdrs == nil {
		t.Fatal("ParsedView returned nil header maps")
	}
	if !bytes.Equal(reqBody, []byte(`{"name":"x"}`)) {
		t.Errorf("reqBody = %q", reqBody)
	}
	if !bytes.Equal(respBody, []byte(`{"ok":true}`)) {
		t.Errorf("respBody = %q", respBody)
	}
	if reqHdrs["Content-Type"][0] != "application/json" {
		t.Errorf("reqHdrs Content-Type = %v", reqHdrs["Content-Type"])
	}
}

func TestParsedView_EmptyRecordAllNil(t *testing.T) {
	// With no raw bytes every derived field is nil — this is what makes the JSON
	// projection drop the four derived fields for list endpoints.
	rh, sh, rb, sb := (&HTTPRecord{}).ParsedView()
	if rh != nil || sh != nil || rb != nil || sb != nil {
		t.Error("ParsedView on empty record should return all-nil")
	}
}

func TestParsedView_RequestOnly(t *testing.T) {
	// Request present, no response → response halves nil.
	rec := &HTTPRecord{RawRequest: []byte(accRawRequest)}
	reqHdrs, respHdrs, reqBody, respBody := rec.ParsedView()
	if reqHdrs == nil || reqBody == nil {
		t.Error("expected request halves populated")
	}
	if respHdrs != nil || respBody != nil {
		t.Error("expected response halves nil when no response")
	}
}
