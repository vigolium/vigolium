package database

import (
	"encoding/json"
	"sync"
	"testing"
)

const sampleRawRequest = "POST /api/login HTTP/1.1\r\n" +
	"Host: example.com\r\n" +
	"Content-Type: application/json\r\n" +
	"Content-Length: 27\r\n" +
	"\r\n" +
	`{"user":"alice","p":"x"}`

const sampleRawResponse = "HTTP/1.1 200 OK\r\n" +
	"Content-Type: application/json\r\n" +
	"Content-Length: 15\r\n" +
	"Set-Cookie: sid=abc\r\n" +
	"\r\n" +
	`{"ok":true}`

func newSampleRecord() *HTTPRecord {
	return &HTTPRecord{
		UUID:        "rec-1",
		RawRequest:  []byte(sampleRawRequest),
		RawResponse: []byte(sampleRawResponse),
		HasResponse: true,
	}
}

func TestParsedRequestResponse(t *testing.T) {
	r := newSampleRecord()

	req := r.ParsedRequest()
	if req == nil {
		t.Fatalf("ParsedRequest is nil")
	}
	if got := req.Method(); got != "POST" {
		t.Errorf("method: want POST, got %q", got)
	}

	resp := r.ParsedResponse()
	if resp == nil {
		t.Fatalf("ParsedResponse is nil")
	}
	if got := resp.StatusCode(); got != 200 {
		t.Errorf("status: want 200, got %d", got)
	}
}

func TestRequestBodyBytes(t *testing.T) {
	r := newSampleRecord()
	body := r.RequestBodyBytes()
	want := `{"user":"alice","p":"x"}`
	if string(body) != want {
		t.Errorf("body: want %q, got %q", want, string(body))
	}
}

func TestResponseBodyBytes(t *testing.T) {
	r := newSampleRecord()
	body := r.ResponseBodyBytes()
	want := `{"ok":true}`
	if string(body) != want {
		t.Errorf("body: want %q, got %q", want, string(body))
	}
}

func TestHeaderMaps(t *testing.T) {
	r := newSampleRecord()

	reqH := r.RequestHeadersMap()
	if vals := reqH["Content-Type"]; len(vals) != 1 || vals[0] != "application/json" {
		t.Errorf("req Content-Type: got %v", vals)
	}
	if vals := reqH["Host"]; len(vals) != 1 || vals[0] != "example.com" {
		t.Errorf("req Host: got %v", vals)
	}

	respH := r.ResponseHeadersMap()
	if vals := respH["Set-Cookie"]; len(vals) != 1 || vals[0] != "sid=abc" {
		t.Errorf("resp Set-Cookie: got %v", vals)
	}
}

func TestNilSafety(t *testing.T) {
	r := &HTTPRecord{}
	if r.ParsedRequest() != nil {
		t.Error("ParsedRequest on empty record: want nil")
	}
	if r.ParsedResponse() != nil {
		t.Error("ParsedResponse on empty record: want nil")
	}
	if b := r.RequestBodyBytes(); b != nil {
		t.Errorf("RequestBodyBytes on empty: want nil, got %v", b)
	}
	if b := r.ResponseBodyBytes(); b != nil {
		t.Errorf("ResponseBodyBytes on empty: want nil, got %v", b)
	}
	if m := r.RequestHeadersMap(); m != nil {
		t.Errorf("RequestHeadersMap on empty: want nil, got %v", m)
	}
	if m := r.ResponseHeadersMap(); m != nil {
		t.Errorf("ResponseHeadersMap on empty: want nil, got %v", m)
	}

	// HasResponse true but no raw bytes.
	r2 := &HTTPRecord{HasResponse: true}
	if r2.ParsedResponse() != nil {
		t.Error("ParsedResponse with HasResponse=true but no raw: want nil")
	}

	// Nil receiver path.
	var rn *HTTPRecord
	if rn.ParsedRequest() != nil || rn.ParsedResponse() != nil {
		t.Error("nil receiver: want nil parsed objects")
	}
}

func TestMarshalJSONContract(t *testing.T) {
	r := newSampleRecord()
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, key := range []string{"request_headers", "request_body", "response_headers", "response_body"} {
		if _, ok := got[key]; !ok {
			t.Errorf("missing key %q in JSON output", key)
		}
	}
}

func TestConcurrentReads(t *testing.T) {
	r := newSampleRecord()

	const n = 64
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_ = r.ParsedRequest()
			_ = r.ParsedResponse()
			_ = r.RequestBodyBytes()
			_ = r.ResponseBodyBytes()
			_ = r.RequestHeadersMap()
			_ = r.ResponseHeadersMap()
		}()
	}
	wg.Wait()
}
