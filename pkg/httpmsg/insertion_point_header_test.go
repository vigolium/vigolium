package httpmsg

import (
	"bytes"
	"testing"
)

func TestHeaderInsertionPoint_ExistingHeader(t *testing.T) {
	request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n")

	ip := &HeaderInsertionPoint{
		headerName:  "User-Agent",
		baseValue:   "Mozilla/5.0",
		baseRequest: request,
	}

	if ip.Name() != "User-Agent" {
		t.Errorf("Name() = %q, want %q", ip.Name(), "User-Agent")
	}
	if ip.BaseValue() != "Mozilla/5.0" {
		t.Errorf("BaseValue() = %q, want %q", ip.BaseValue(), "Mozilla/5.0")
	}

	built := ip.BuildRequest([]byte("EvilBot/1.0"))
	if !bytes.Contains(built, []byte("User-Agent: EvilBot/1.0")) {
		t.Errorf("Expected User-Agent replaced, got: %s", string(built))
	}
	// Original value should NOT be present
	if bytes.Contains(built, []byte("Mozilla/5.0")) {
		t.Errorf("Original User-Agent value should be replaced, got: %s", string(built))
	}
}

func TestHeaderInsertionPoint_SyntheticHeader(t *testing.T) {
	request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	ip := &HeaderInsertionPoint{
		headerName:  "X-Forwarded-For",
		baseValue:   "127.0.0.1",
		baseRequest: request,
	}

	built := ip.BuildRequest([]byte("' OR 1=1--"))
	if !bytes.Contains(built, []byte("X-Forwarded-For: ' OR 1=1--")) {
		t.Errorf("Expected X-Forwarded-For added, got: %s", string(built))
	}
	// Should still have original headers
	if !bytes.Contains(built, []byte("Host: example.com")) {
		t.Errorf("Expected Host preserved, got: %s", string(built))
	}
}

func TestHeaderInsertionPoint_Type(t *testing.T) {
	ip := &HeaderInsertionPoint{
		headerName:  "Referer",
		baseValue:   "http://example.com/",
		baseRequest: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	}

	if ip.Type() != INS_HEADER {
		t.Errorf("Type() = %d, want INS_HEADER (%d)", ip.Type(), INS_HEADER)
	}
}

func TestHeaderInsertionPoint_PayloadOffsets(t *testing.T) {
	request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	ip := &HeaderInsertionPoint{
		headerName:  "X-Forwarded-For",
		baseValue:   "127.0.0.1",
		baseRequest: request,
	}

	payload := []byte("PAYLOAD_VALUE")
	offsets := ip.PayloadOffsets(payload)

	if len(offsets) != 2 {
		t.Fatalf("Expected 2 offsets, got %d", len(offsets))
	}

	start, end := offsets[0], offsets[1]
	if start < 0 || end < 0 {
		t.Fatalf("Expected valid offsets, got [%d, %d]", start, end)
	}

	built := ip.BuildRequest(payload)
	if start >= end || end > len(built) {
		t.Fatalf("Invalid offset range [%d, %d] for request length %d", start, end, len(built))
	}

	extracted := string(built[start:end])
	if extracted != "PAYLOAD_VALUE" {
		t.Errorf("Payload at offsets [%d:%d] = %q, want %q", start, end, extracted, "PAYLOAD_VALUE")
	}
}

func TestCreateAllInsertionPoints_BareURL(t *testing.T) {
	// Bare URL with no params, body, cookies, or path segments
	request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	points, err := CreateAllInsertionPoints(request, false)
	if err != nil {
		t.Fatalf("CreateAllInsertionPoints() error = %v", err)
	}

	// Should have at least synthetic header IPs
	headerIPs := 0
	for _, ip := range points {
		if ip.Type() == INS_HEADER {
			headerIPs++
		}
	}

	if headerIPs == 0 {
		t.Error("Expected header insertion points for bare URL, got 0")
	}

	// Check that synthetic headers are present
	expectedSynthetic := []string{"X-Forwarded-For", "X-Forwarded-Host", "Referer", "True-Client-IP", "X-Real-IP"}
	for _, name := range expectedSynthetic {
		found := false
		for _, ip := range points {
			if ip.Name() == name && ip.Type() == INS_HEADER {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected synthetic header IP for %q, not found", name)
		}
	}
}

func TestCreateAllInsertionPoints_SkipProtocolHeaders(t *testing.T) {
	request := []byte("GET / HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Content-Type: text/html\r\n" +
		"Cookie: session=abc\r\n" +
		"Connection: keep-alive\r\n" +
		"Accept-Encoding: gzip\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"\r\n")

	points, err := CreateAllInsertionPoints(request, false)
	if err != nil {
		t.Fatalf("CreateAllInsertionPoints() error = %v", err)
	}

	// Protocol headers should NOT appear as header IPs
	protocolNames := []string{"Host", "Content-Type", "Cookie", "Connection", "Accept-Encoding", "Transfer-Encoding"}
	for _, name := range protocolNames {
		for _, ip := range points {
			if ip.Type() == INS_HEADER && EqualsCaseInsensitive(ip.Name(), name) {
				t.Errorf("Protocol header %q should not be a header insertion point", name)
			}
		}
	}
}

func TestCreateAllInsertionPoints_NoDuplicateSynthetic(t *testing.T) {
	// Request already has X-Forwarded-For — should NOT get a synthetic duplicate
	request := []byte("GET / HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"X-Forwarded-For: 10.0.0.1\r\n" +
		"\r\n")

	points, err := CreateAllInsertionPoints(request, false)
	if err != nil {
		t.Fatalf("CreateAllInsertionPoints() error = %v", err)
	}

	// Count X-Forwarded-For header IPs
	count := 0
	for _, ip := range points {
		if ip.Type() == INS_HEADER && EqualsCaseInsensitive(ip.Name(), "X-Forwarded-For") {
			count++
		}
	}

	if count != 1 {
		t.Errorf("Expected exactly 1 X-Forwarded-For header IP, got %d", count)
	}

	// The existing one should have the original value
	for _, ip := range points {
		if ip.Type() == INS_HEADER && EqualsCaseInsensitive(ip.Name(), "X-Forwarded-For") {
			if ip.BaseValue() != "10.0.0.1" {
				t.Errorf("X-Forwarded-For BaseValue() = %q, want %q", ip.BaseValue(), "10.0.0.1")
			}
		}
	}
}

func TestCreateAllInsertionPoints_ExistingInjectableHeaders(t *testing.T) {
	request := []byte("GET / HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"User-Agent: Mozilla/5.0\r\n" +
		"Authorization: Bearer token123\r\n" +
		"\r\n")

	points, err := CreateAllInsertionPoints(request, false)
	if err != nil {
		t.Fatalf("CreateAllInsertionPoints() error = %v", err)
	}

	// User-Agent and Authorization should be header IPs
	for _, name := range []string{"User-Agent", "Authorization"} {
		found := false
		for _, ip := range points {
			if ip.Type() == INS_HEADER && ip.Name() == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected header IP for %q, not found", name)
		}
	}
}

func TestHeaderInsertionPoint_BuildRequest_PreservesBody(t *testing.T) {
	request := []byte("POST /api HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: 13\r\n" +
		"\r\n" +
		`{"key":"val"}`)

	ip := &HeaderInsertionPoint{
		headerName:  "X-Forwarded-For",
		baseValue:   "127.0.0.1",
		baseRequest: request,
	}

	built := ip.BuildRequest([]byte("INJECTED"))
	if !bytes.Contains(built, []byte(`{"key":"val"}`)) {
		t.Errorf("Body should be preserved, got: %s", string(built))
	}
	if !bytes.Contains(built, []byte("X-Forwarded-For: INJECTED")) {
		t.Errorf("Header should be added, got: %s", string(built))
	}
}
