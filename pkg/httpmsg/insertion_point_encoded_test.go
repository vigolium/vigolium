package httpmsg

// insertion_point_encoded_test.go - Comprehensive tests for EncodedInsertionPoint
// Tests cover all encoder types and edge cases as specified

import (
	"bytes"
	"testing"
)

// TestEncodedInsertionPoint_Basic tests basic functionality
func TestEncodedInsertionPoint_Basic(t *testing.T) {
	request := []byte("GET /api?param=value HTTP/1.1\r\nHost: example.com\r\n\r\n")
	encoder := &NoopEncoder{}

	// Create insertion point for "value" (offset 15-20)
	ip := NewEncodedInsertionPoint(
		"param",
		request,
		15, 20,
		encoder,
		nil,
		INS_PARAM_URL,
	)

	// Verify basic properties
	if ip.Name() != "param" {
		t.Errorf("GetName: got %q, expected %q", ip.Name(), "param")
	}

	if ip.BaseValue() != "value" {
		t.Errorf("GetBaseValue: got %q, expected %q", ip.BaseValue(), "value")
	}

	if ip.Type() != INS_PARAM_URL {
		t.Errorf("GetInsertionPointType: got %d, expected %d", ip.Type(), INS_PARAM_URL)
	}

	// Test BuildRequest with simple payload
	payload := []byte("test123")
	newRequest := ip.BuildRequest(payload)
	expected := "GET /api?param=test123 HTTP/1.1\r\nHost: example.com\r\n\r\n"

	if string(newRequest) != expected {
		t.Errorf("BuildRequest:\ngot:      %q\nexpected: %q", string(newRequest), expected)
	}

	// Test PayloadOffsets
	offsets := ip.PayloadOffsets(payload)
	if len(offsets) != 2 {
		t.Fatalf("PayloadOffsets: expected 2 offsets, got %d", len(offsets))
	}
	if offsets[0] != 15 || offsets[1] != 22 {
		t.Errorf("PayloadOffsets: got [%d, %d], expected [15, 22]", offsets[0], offsets[1])
	}
}

// TestEncodedInsertionPoint_URLEncoder tests with URL percent encoding
func TestEncodedInsertionPoint_URLEncoder(t *testing.T) {
	request := []byte("GET /api?param=value HTTP/1.1\r\n\r\n")
	encoder := NewURLEncoder()

	ip := NewEncodedInsertionPoint(
		"param",
		request,
		15, 20,
		encoder,
		nil,
		INS_PARAM_URL,
	)

	// Test with payload containing special characters
	payload := []byte("hello world")
	newRequest := ip.BuildRequest(payload)

	// "hello world" should become "hello%20world"
	expected := "GET /api?param=hello%20world HTTP/1.1\r\n\r\n"
	if string(newRequest) != expected {
		t.Errorf("BuildRequest with URL encoding:\ngot:      %q\nexpected: %q", string(newRequest), expected)
	}

	// Test with more special characters
	payload = []byte("a=b&c")
	newRequest = ip.BuildRequest(payload)

	// "a=b&c" should become "a%3Db%26c"
	expected = "GET /api?param=a%3Db%26c HTTP/1.1\r\n\r\n"
	if string(newRequest) != expected {
		t.Errorf("BuildRequest with special chars:\ngot:      %q\nexpected: %q", string(newRequest), expected)
	}

	// Verify offset tracking with encoding expansion
	payload = []byte("test=123")
	offsets := ip.PayloadOffsets(payload)

	// Payload "test=123" encodes to "test%3D123" (10 chars)
	// Should start at offset 15
	if offsets[0] != 15 {
		t.Errorf("Start offset: got %d, expected 15", offsets[0])
	}
	// Length of encoded is 10, so end should be 15+10=25
	if offsets[1] != 25 {
		t.Errorf("End offset: got %d, expected 25", offsets[1])
	}
}

// TestEncodedInsertionPoint_Base64Encoder tests with Base64 encoding
func TestEncodedInsertionPoint_Base64Encoder(t *testing.T) {
	request := []byte("POST /api HTTP/1.1\r\n\r\n{\"data\":\"value\"}")
	encoder := NewBase64Encoder()

	// JSON value starts at offset 31 ("value")
	ip := NewEncodedInsertionPoint(
		"data",
		request,
		31, 36,
		encoder,
		nil,
		INS_PARAM_JSON,
	)

	// Test with simple payload
	payload := []byte("hello")
	newRequest := ip.BuildRequest(payload)

	// "hello" in Base64 is "aGVsbG8="
	// Body length is 19 bytes: {"data":"aGVsbG8="}
	expected := "POST /api HTTP/1.1\r\nContent-Length: 19\r\n\r\n{\"data\":\"aGVsbG8=\"}"
	if string(newRequest) != expected {
		t.Errorf("BuildRequest with Base64:\ngot:      %q\nexpected: %q", string(newRequest), expected)
	}

	// Test Base64 decoding of base value
	if ip.BaseValue() != "value" {
		t.Errorf("GetBaseValue after Base64 decode: got %q, expected %q", ip.BaseValue(), "value")
	}

	// Test with binary data
	payload = []byte{0x01, 0x02, 0x03}
	newRequest = ip.BuildRequest(payload)

	// Binary {1,2,3} in Base64 is "AQID"
	// Body length is 15 bytes: {"data":"AQID"}
	expected = "POST /api HTTP/1.1\r\nContent-Length: 15\r\n\r\n{\"data\":\"AQID\"}"
	if string(newRequest) != expected {
		t.Errorf("BuildRequest with binary:\ngot:      %q\nexpected: %q", string(newRequest), expected)
	}
}

// TestEncodedInsertionPoint_JSONStringEncoder tests with JSON escaping
func TestEncodedInsertionPoint_JSONStringEncoder(t *testing.T) {
	request := []byte("{\"key\":\"value\"}")
	encoder := &JSONStringEncoder{}

	ip := NewEncodedInsertionPoint(
		"key",
		request,
		8, 13,
		encoder,
		nil,
		INS_PARAM_JSON,
	)

	// Test with quotes that need escaping
	payload := []byte("test\"quote")
	newRequest := ip.BuildRequest(payload)

	// Quotes should be escaped: test"quote -> test\"quote
	expected := "{\"key\":\"test\\\"quote\"}"
	if string(newRequest) != expected {
		t.Errorf("BuildRequest with JSON escaping:\ngot:      %q\nexpected: %q", string(newRequest), expected)
	}

	// Test with multiple quotes
	payload = []byte("\"hello\" \"world\"")
	newRequest = ip.BuildRequest(payload)

	expected = "{\"key\":\"\\\"hello\\\" \\\"world\\\"\"}"
	if string(newRequest) != expected {
		t.Errorf("BuildRequest with multiple quotes:\ngot:      %q\nexpected: %q", string(newRequest), expected)
	}
}

// TestEncodedInsertionPoint_GzipEncoder tests with Gzip compression
func TestEncodedInsertionPoint_GzipEncoder(t *testing.T) {
	request := []byte("POST /api HTTP/1.1\r\nContent-Encoding: gzip\r\n\r\noriginal")
	encoder := NewGzipEncoder()

	// Body "original" starts at offset 46, ends at 54
	ip := NewEncodedInsertionPoint(
		"body",
		request,
		46, 54,
		encoder,
		nil,
		INS_ENTIRE_BODY,
	)

	// Test with compressible payload
	payload := []byte("test data test data test data")
	newRequest := ip.BuildRequest(payload)

	// Verify the request structure is correct (has headers and compressed body)
	if !bytes.HasPrefix(newRequest, []byte("POST /api HTTP/1.1")) {
		t.Error("BuildRequest with Gzip: request should start with HTTP line")
	}

	// Extract the compressed portion
	headerEnd := bytes.Index(newRequest, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		t.Fatal("BuildRequest with Gzip: no header/body separator found")
	}
	compressedBody := newRequest[headerEnd+4:]

	// Decompress to verify
	decompressed := encoder.Decode(compressedBody)
	if string(decompressed) != string(payload) {
		t.Errorf("Gzip decompression: got %q, expected %q", string(decompressed), string(payload))
	}

	// Test offset tracking (should reset to 0 and length)
	offsets := ip.PayloadOffsets(payload)
	if offsets[0] != 46 {
		t.Errorf("Gzip start offset: got %d, expected 46", offsets[0])
	}
	// End offset should be start + compressed length
	expectedEnd := 46 + len(compressedBody)
	if offsets[1] != expectedEnd {
		t.Errorf("Gzip end offset: got %d, expected %d", offsets[1], expectedEnd)
	}
}

// TestEncodedInsertionPoint_NoopEncoder tests with passthrough encoder
func TestEncodedInsertionPoint_NoopEncoder(t *testing.T) {
	request := []byte("GET /test?p=original HTTP/1.1\r\n\r\n")
	encoder := &NoopEncoder{}

	ip := NewEncodedInsertionPoint(
		"p",
		request,
		12, 20,
		encoder,
		nil,
		INS_PARAM_URL,
	)

	// Test that payload passes through unchanged
	payload := []byte("new value")
	newRequest := ip.BuildRequest(payload)

	expected := "GET /test?p=new value HTTP/1.1\r\n\r\n"
	if string(newRequest) != expected {
		t.Errorf("BuildRequest with noop:\ngot:      %q\nexpected: %q", string(newRequest), expected)
	}

	// Test with special characters (should not be encoded)
	payload = []byte("a=b&c")
	newRequest = ip.BuildRequest(payload)

	expected = "GET /test?p=a=b&c HTTP/1.1\r\n\r\n"
	if string(newRequest) != expected {
		t.Errorf("BuildRequest with special chars:\ngot:      %q\nexpected: %q", string(newRequest), expected)
	}
}

// TestEncodedInsertionPoint_OffsetTracking verifies offset accuracy
func TestEncodedInsertionPoint_OffsetTracking(t *testing.T) {
	request := []byte("POST /api HTTP/1.1\r\n\r\ndata=value")
	encoder := NewURLEncoder()

	ip := NewEncodedInsertionPoint(
		"data",
		request,
		27, 32,
		encoder,
		nil,
		INS_PARAM_BODY,
	)

	// Test payload that expands during encoding
	// "a=b" -> "a%3Db" (3 chars -> 5 chars)
	payload := []byte("a=b")
	offsets := ip.PayloadOffsets(payload)

	// Should start at 27
	if offsets[0] != 27 {
		t.Errorf("Start offset: got %d, expected 27", offsets[0])
	}

	// "a=b" encodes to "a%3Db" (5 bytes), so end is 27+5=32
	if offsets[1] != 32 {
		t.Errorf("End offset: got %d, expected 32", offsets[1])
	}

	// Test with payload that doesn't expand
	payload = []byte("abc")
	offsets = ip.PayloadOffsets(payload)

	if offsets[0] != 27 || offsets[1] != 30 {
		t.Errorf("Offsets for 'abc': got [%d, %d], expected [27, 30]", offsets[0], offsets[1])
	}
}

// TestEncodedInsertionPoint_SetEncoder tests dynamic encoder change
func TestEncodedInsertionPoint_SetEncoder(t *testing.T) {
	request := []byte("GET /api?p=value HTTP/1.1\r\n\r\n")

	// Start with noop encoder
	ip := NewEncodedInsertionPoint(
		"p",
		request,
		11, 16,
		&NoopEncoder{},
		nil,
		INS_PARAM_URL,
	)

	// Test with noop
	payload := []byte("a=b")
	result := ip.BuildRequest(payload)
	expected := "GET /api?p=a=b HTTP/1.1\r\n\r\n"

	if string(result) != expected {
		t.Errorf("BuildRequest with noop:\ngot:      %q\nexpected: %q", string(result), expected)
	}

	// Change to URL encoder
	ip.SetEncoder(NewURLEncoder())

	// Same payload should now be encoded
	result = ip.BuildRequest(payload)
	expected = "GET /api?p=a%3Db HTTP/1.1\r\n\r\n"

	if string(result) != expected {
		t.Errorf("BuildRequest after SetEncoder:\ngot:      %q\nexpected: %q", string(result), expected)
	}

	// Verify GetEncoder returns the new encoder
	encoder := ip.GetEncoder()
	if _, ok := encoder.(*URLEncoder); !ok {
		t.Error("GetEncoder: should return URLEncoder after SetEncoder")
	}

	// Test panic on nil encoder
	defer func() {
		if r := recover(); r == nil {
			t.Error("SetEncoder(nil) should panic")
		}
	}()
	ip.SetEncoder(nil)
}

// TestEncodedInsertionPoint_WithPrefix tests prefix bytes functionality
func TestEncodedInsertionPoint_WithPrefix(t *testing.T) {
	request := []byte("GET /api?token=value HTTP/1.1\r\n\r\n")
	encoder := NewURLEncoder()
	prefix := []byte("PREFIX:")

	ip := NewEncodedInsertionPoint(
		"token",
		request,
		15, 20,
		encoder,
		prefix,
		INS_PARAM_URL,
	)

	// Test that prefix is prepended to payload
	payload := []byte("test")
	newRequest := ip.BuildRequest(payload)

	// Prefix + payload should be encoded together
	// "PREFIX:test" should be URL encoded (colon is encoded as %3A)
	expected := "GET /api?token=PREFIX%3Atest HTTP/1.1\r\n\r\n"
	if string(newRequest) != expected {
		t.Errorf("BuildRequest with prefix:\ngot:      %q\nexpected: %q", string(newRequest), expected)
	}

	// Test offset tracking with prefix
	offsets := ip.PayloadOffsets(payload)

	// Start should still be at 15
	if offsets[0] != 15 {
		t.Errorf("Start offset with prefix: got %d, expected 15", offsets[0])
	}

	// "PREFIX:test" -> "PREFIX%3Atest" (13 chars)
	// End should be 15 + 13 = 28
	if offsets[1] != 28 {
		t.Errorf("End offset with prefix: got %d, expected 28", offsets[1])
	}
}

// TestEncodedInsertionPoint_BuildRequest tests full request building
func TestEncodedInsertionPoint_BuildRequest(t *testing.T) {
	// Test building request with payload at different positions

	t.Run("BeginningOfRequest", func(t *testing.T) {
		request := []byte("value rest of request")
		ip := NewEncodedInsertionPoint(
			"test",
			request,
			0, 5,
			NewURLEncoder(),
			nil,
			INS_USER_PROVIDED,
		)

		payload := []byte("a=b")
		result := ip.BuildRequest(payload)
		expected := "a%3Db rest of request"

		if string(result) != expected {
			t.Errorf("got %q, expected %q", string(result), expected)
		}
	})

	t.Run("EndOfRequest", func(t *testing.T) {
		request := []byte("request ends with value")
		ip := NewEncodedInsertionPoint(
			"test",
			request,
			18, 23,
			NewURLEncoder(),
			nil,
			INS_USER_PROVIDED,
		)

		payload := []byte("a=b")
		result := ip.BuildRequest(payload)
		expected := "request ends with a%3Db"

		if string(result) != expected {
			t.Errorf("got %q, expected %q", string(result), expected)
		}
	})

	t.Run("MiddleOfRequest", func(t *testing.T) {
		request := []byte("before value after")
		ip := NewEncodedInsertionPoint(
			"test",
			request,
			7, 12,
			NewURLEncoder(),
			nil,
			INS_USER_PROVIDED,
		)

		payload := []byte("new")
		result := ip.BuildRequest(payload)
		expected := "before new after"

		if string(result) != expected {
			t.Errorf("got %q, expected %q", string(result), expected)
		}
	})
}

// TestEncodedInsertionPoint_PayloadOffsets tests offset calculation
func TestEncodedInsertionPoint_PayloadOffsets(t *testing.T) {
	request := []byte("GET /api?p=original HTTP/1.1\r\n\r\n")

	t.Run("NoExpansion", func(t *testing.T) {
		ip := NewEncodedInsertionPoint(
			"p",
			request,
			11, 19,
			&NoopEncoder{},
			nil,
			INS_PARAM_URL,
		)

		payload := []byte("test")
		offsets := ip.PayloadOffsets(payload)

		// Should be [11, 15] (start + length)
		if offsets[0] != 11 || offsets[1] != 15 {
			t.Errorf("got [%d, %d], expected [11, 15]", offsets[0], offsets[1])
		}
	})

	t.Run("WithExpansion", func(t *testing.T) {
		ip := NewEncodedInsertionPoint(
			"p",
			request,
			11, 19,
			NewURLEncoder(),
			nil,
			INS_PARAM_URL,
		)

		// "===" encodes to "%3D%3D%3D" (9 chars)
		payload := []byte("===")
		offsets := ip.PayloadOffsets(payload)

		if offsets[0] != 11 {
			t.Errorf("start: got %d, expected 11", offsets[0])
		}
		if offsets[1] != 20 {
			t.Errorf("end: got %d, expected 20", offsets[1])
		}
	})

	t.Run("WithPrefix", func(t *testing.T) {
		prefix := []byte("PRE:")
		ip := NewEncodedInsertionPoint(
			"p",
			request,
			11, 19,
			&NoopEncoder{},
			prefix,
			INS_PARAM_URL,
		)

		payload := []byte("test")
		offsets := ip.PayloadOffsets(payload)

		// "PRE:test" = 8 chars, so [11, 19]
		if offsets[0] != 11 || offsets[1] != 19 {
			t.Errorf("got [%d, %d], expected [11, 19]", offsets[0], offsets[1])
		}
	})
}

// TestEncodedInsertionPoint_SpecialCharacters tests edge cases
func TestEncodedInsertionPoint_SpecialCharacters(t *testing.T) {
	request := []byte("POST /api HTTP/1.1\r\n\r\ndata=value")

	t.Run("NullBytes", func(t *testing.T) {
		ip := NewEncodedInsertionPoint(
			"data",
			request,
			27, 32,
			NewURLEncoder(),
			nil,
			INS_PARAM_BODY,
		)

		// Payload with null bytes
		payload := []byte{'a', 0x00, 'b'}
		result := ip.BuildRequest(payload)

		// Null byte should be encoded as %00
		// Body length is 10 bytes: data=a%00b
		expected := "POST /api HTTP/1.1\r\nContent-Length: 10\r\n\r\ndata=a%00b"
		if string(result) != expected {
			t.Errorf("got %q, expected %q", string(result), expected)
		}
	})

	t.Run("HighByteValues", func(t *testing.T) {
		ip := NewEncodedInsertionPoint(
			"data",
			request,
			27, 32,
			NewURLEncoder(),
			nil,
			INS_PARAM_BODY,
		)

		// Payload with high byte values (non-ASCII)
		payload := []byte{0xFF, 0xFE}
		result := ip.BuildRequest(payload)

		// Should be percent-encoded
		// Body length is 11 bytes: data=%FF%FE
		expected := "POST /api HTTP/1.1\r\nContent-Length: 11\r\n\r\ndata=%FF%FE"
		if string(result) != expected {
			t.Errorf("got %q, expected %q", string(result), expected)
		}
	})

	t.Run("EmptyPayload", func(t *testing.T) {
		ip := NewEncodedInsertionPoint(
			"data",
			request,
			27, 32,
			&NoopEncoder{},
			nil,
			INS_PARAM_BODY,
		)

		payload := []byte("")
		result := ip.BuildRequest(payload)

		// Body length is 5 bytes: data=
		expected := "POST /api HTTP/1.1\r\nContent-Length: 5\r\n\r\ndata="
		if string(result) != expected {
			t.Errorf("got %q, expected %q", string(result), expected)
		}
	})

	t.Run("LargePayload", func(t *testing.T) {
		ip := NewEncodedInsertionPoint(
			"data",
			request,
			27, 32,
			&NoopEncoder{},
			nil,
			INS_PARAM_BODY,
		)

		// Create large payload
		payload := bytes.Repeat([]byte("X"), 10000)
		result := ip.BuildRequest(payload)

		// Verify structure - with Content-Length header
		// Body is data= + 10000 X's = 10005 bytes
		if !bytes.HasPrefix(result, []byte("POST /api HTTP/1.1\r\nContent-Length: 10005\r\n\r\ndata=")) {
			t.Error("Large payload: request structure incorrect")
		}

		// Verify payload is present
		dataStart := bytes.Index(result, []byte("data="))
		if dataStart == -1 {
			t.Fatal("Large payload: data= not found")
		}

		payloadInRequest := result[dataStart+5:]
		if len(payloadInRequest) != 10000 {
			t.Errorf("Large payload: got %d bytes, expected 10000", len(payloadInRequest))
		}
	})

	t.Run("Unicode", func(t *testing.T) {
		ip := NewEncodedInsertionPoint(
			"data",
			request,
			27, 32,
			NewURLEncoder(),
			nil,
			INS_PARAM_BODY,
		)

		// UTF-8 encoded unicode
		payload := []byte("hello世界")
		result := ip.BuildRequest(payload)

		// Non-ASCII bytes should be percent-encoded
		// "世界" in UTF-8 is E4 B8 96 E7 95 8C
		// Body length is 28 bytes: data=hello%E4%B8%96%E7%95%8C
		expected := "POST /api HTTP/1.1\r\nContent-Length: 28\r\n\r\ndata=hello%E4%B8%96%E7%95%8C"
		if string(result) != expected {
			t.Errorf("got %q, expected %q", string(result), expected)
		}
	})
}

// TestEncodedInsertionPoint_ValidationPanics tests constructor validation
func TestEncodedInsertionPoint_ValidationPanics(t *testing.T) {
	request := []byte("GET /test HTTP/1.1\r\n\r\n")
	encoder := &NoopEncoder{}

	t.Run("EmptyName", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for empty name")
			}
		}()
		NewEncodedInsertionPoint("", request, 0, 4, encoder, nil, INS_PARAM_URL)
	})

	t.Run("NilRequest", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for nil request")
			}
		}()
		NewEncodedInsertionPoint("test", nil, 0, 4, encoder, nil, INS_PARAM_URL)
	})

	t.Run("InvalidOffsets", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for invalid offsets")
			}
		}()
		// End before start
		NewEncodedInsertionPoint("test", request, 10, 5, encoder, nil, INS_PARAM_URL)
	})

	t.Run("NegativeOffset", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for negative offset")
			}
		}()
		NewEncodedInsertionPoint("test", request, -1, 5, encoder, nil, INS_PARAM_URL)
	})

	t.Run("OffsetOutOfBounds", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for offset out of bounds")
			}
		}()
		NewEncodedInsertionPoint("test", request, 0, 1000, encoder, nil, INS_PARAM_URL)
	})

	t.Run("NilEncoder", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for nil encoder")
			}
		}()
		NewEncodedInsertionPoint("test", request, 0, 4, nil, nil, INS_PARAM_URL)
	})

	t.Run("NilPayloadBuildRequest", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for nil payload in BuildRequest")
			}
		}()
		ip := NewEncodedInsertionPoint("test", request, 0, 4, encoder, nil, INS_PARAM_URL)
		ip.BuildRequest(nil)
	})

	t.Run("NilPayloadGetOffsets", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for nil payload in PayloadOffsets")
			}
		}()
		ip := NewEncodedInsertionPoint("test", request, 0, 4, encoder, nil, INS_PARAM_URL)
		ip.PayloadOffsets(nil)
	})
}

// TestEncodedInsertionPoint_RequestImmutability tests that original request is not modified
func TestEncodedInsertionPoint_RequestImmutability(t *testing.T) {
	originalRequest := []byte("GET /api?p=value HTTP/1.1\r\n\r\n")
	requestCopy := make([]byte, len(originalRequest))
	copy(requestCopy, originalRequest)

	ip := NewEncodedInsertionPoint(
		"p",
		originalRequest,
		11, 16,
		NewURLEncoder(),
		nil,
		INS_PARAM_URL,
	)

	// Build several requests
	ip.BuildRequest([]byte("test1"))
	ip.BuildRequest([]byte("test2"))
	ip.PayloadOffsets([]byte("test3"))

	// Original request should be unchanged
	if !bytes.Equal(originalRequest, requestCopy) {
		t.Error("Original request was modified")
	}
}

// TestEncodedInsertionPoint_PrefixImmutability tests that prefix is not modified
func TestEncodedInsertionPoint_PrefixImmutability(t *testing.T) {
	request := []byte("GET /api?p=value HTTP/1.1\r\n\r\n")
	originalPrefix := []byte("PREFIX:")
	prefixCopy := make([]byte, len(originalPrefix))
	copy(prefixCopy, originalPrefix)

	ip := NewEncodedInsertionPoint(
		"p",
		request,
		11, 16,
		&NoopEncoder{},
		originalPrefix,
		INS_PARAM_URL,
	)

	// Build requests
	ip.BuildRequest([]byte("test"))

	// Original prefix should be unchanged
	if !bytes.Equal(originalPrefix, prefixCopy) {
		t.Error("Original prefix was modified")
	}
}

// TestEncodedInsertionPoint_MultipleEncoders tests switching between different encoder types
func TestEncodedInsertionPoint_MultipleEncoders(t *testing.T) {
	request := []byte("POST /api HTTP/1.1\r\n\r\ndata=value")

	ip := NewEncodedInsertionPoint(
		"data",
		request,
		27, 32,
		&NoopEncoder{},
		nil,
		INS_PARAM_BODY,
	)

	payload := []byte("test data")

	// Test with each encoder type
	encoders := []struct {
		name     string
		encoder  Encoder
		expected string
	}{
		{"Noop", &NoopEncoder{}, "POST /api HTTP/1.1\r\nContent-Length: 14\r\n\r\ndata=test data"},
		{"URL", NewURLEncoder(), "POST /api HTTP/1.1\r\nContent-Length: 16\r\n\r\ndata=test%20data"},
		{"JSONString", &JSONStringEncoder{}, "POST /api HTTP/1.1\r\nContent-Length: 14\r\n\r\ndata=test data"},
		{"Base64", NewBase64Encoder(), "POST /api HTTP/1.1\r\nContent-Length: 17\r\n\r\ndata=dGVzdCBkYXRh"},
	}

	for _, enc := range encoders {
		t.Run(enc.name, func(t *testing.T) {
			ip.SetEncoder(enc.encoder)
			result := ip.BuildRequest(payload)

			if string(result) != enc.expected {
				t.Errorf("got %q, expected %q", string(result), enc.expected)
			}
		})
	}
}

// TestEncodedInsertionPoint_ComplexScenario tests a realistic multi-step scenario
func TestEncodedInsertionPoint_ComplexScenario(t *testing.T) {
	// Simulate testing a JSON API with Base64-encoded data
	// Include Content-Length header to avoid offset shifts
	request := []byte("POST /api/v1/submit HTTP/1.1\r\n" +
		"Host: api.example.com\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: 63\r\n" +
		"\r\n" +
		"{\"userId\":123,\"data\":\"aGVsbG8=\",\"signature\":\"abc123\"}")

	// The "data" field contains Base64 encoded payload
	// Find the position of the Base64 value
	dataStart := bytes.Index(request, []byte("\"aGVsbG8=\""))
	if dataStart == -1 {
		t.Fatal("Could not find data field")
	}
	dataStart += 1           // Skip opening quote
	dataEnd := dataStart + 8 // Length of "aGVsbG8="

	ip := NewEncodedInsertionPoint(
		"data",
		request,
		dataStart, dataEnd,
		NewBase64Encoder(),
		nil,
		INS_PARAM_JSON,
	)

	// Verify base value decodes correctly
	if ip.BaseValue() != "hello" {
		t.Errorf("Base value: got %q, expected %q", ip.BaseValue(), "hello")
	}

	// Test injection with SQL payload
	sqlPayload := []byte("' OR 1=1--")
	newRequest := ip.BuildRequest(sqlPayload)

	// Verify SQL payload is Base64 encoded in the request
	expectedEncoded := "JyBPUiAxPTEtLQ==" // Base64 of "' OR 1=1--"
	if !bytes.Contains(newRequest, []byte(expectedEncoded)) {
		t.Errorf("Request does not contain expected Base64 encoded payload: %s", expectedEncoded)
	}

	// Verify request structure is maintained
	if !bytes.Contains(newRequest, []byte("POST /api/v1/submit HTTP/1.1")) {
		t.Error("HTTP request line corrupted")
	}
	if !bytes.Contains(newRequest, []byte("\"userId\":123")) {
		t.Error("Other JSON fields corrupted")
	}

	// Get payload offsets
	offsets := ip.PayloadOffsets(sqlPayload)

	// Verify offsets point to the encoded payload
	if offsets[0] != dataStart {
		t.Errorf("Start offset: got %d, expected %d", offsets[0], dataStart)
	}

	// Extract payload from built request using offsets
	payloadInRequest := newRequest[offsets[0]:offsets[1]]
	if string(payloadInRequest) != expectedEncoded {
		t.Errorf("Payload at offsets: got %q, expected %q", string(payloadInRequest), expectedEncoded)
	}
}
