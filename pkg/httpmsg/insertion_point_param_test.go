package httpmsg

import (
	"bytes"
	"testing"
)

// TestParameterInsertionPoint_URLEncoding tests URL parameter encoding.
// Ported from: ggd.java with URL parameter type
func TestParameterInsertionPoint_URLEncoding(t *testing.T) {
	request := []byte("GET /search?q=test HTTP/1.1\r\nHost: example.com\r\n\r\n")

	// Create parameter for "q=test"
	// Position 12: 'q', Position 13: '=', Position 14-18: 'test'
	param := NewParsedParam(ParamURL, "q", "test", 12, 13, 14, 18)

	ip := NewParameterInsertionPoint(request, param)

	tests := []struct {
		name     string
		payload  []byte
		expected string // Expected request after injection
	}{
		{
			name:     "alphanumeric payload",
			payload:  []byte("hello123"),
			expected: "GET /search?q=hello123 HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name:     "special characters",
			payload:  []byte("hello world"),
			expected: "GET /search?q=hello+world HTTP/1.1\r\nHost: example.com\r\n\r\n", // Note: EncodeQueryValue uses '+' for spaces
		},
		{
			name:     "symbols",
			payload:  []byte("a&b=c"),
			expected: "GET /search?q=a%26b%3Dc HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ip.BuildRequest(tt.payload)
			if string(result) != tt.expected {
				t.Errorf("BuildRequest() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestParameterInsertionPoint_JSONNoEncoding tests JSON parameter (no URL encoding).
// JSON string payloads should be escaped but not URL-encoded.
// Ported from: ggd.java with JSON parameter type
func TestParameterInsertionPoint_JSONNoEncoding(t *testing.T) {
	request := []byte("POST /api HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"name\":\"test\"}")
	// Positions: {"name":"test"}
	//            01234567890123456
	// Body starts at 54, "test" content is at positions 9-13 within body

	bodyOffset := 54
	// "test" content starts at position 9 in body (after opening quote)
	valueStart := bodyOffset + 9 // position of 't' in "test"
	valueEnd := bodyOffset + 13  // position after 't' in "test"
	param := NewParsedParam(ParamJSON, "name", "test", bodyOffset+2, bodyOffset+6, valueStart, valueEnd).WithJSONType(JSONTypeString)

	ip := NewParameterInsertionPoint(request, param)

	// JSON string payloads should NOT be URL-encoded, just escaped if needed
	payload := []byte("hello world")
	result := ip.BuildRequest(payload)

	// Body length is 22 bytes: {"name":"hello world"}
	expected := []byte("POST /api HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 22\r\n\r\n{\"name\":\"hello world\"}")
	if !bytes.Equal(result, expected) {
		t.Errorf("BuildRequest() = %q, want %q", result, expected)
	}
}

// TestParameterInsertionPoint_BodyEncoding tests body parameter encoding.
// Ported from: ggd.java with BODY parameter type
func TestParameterInsertionPoint_BodyEncoding(t *testing.T) {
	request := []byte("POST /api HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 9\r\n\r\nkey=value")
	// Body "key=value" starts at position 90
	// k:90, e:91, y:92, =:93, v:94, a:95, l:96, u:97, e:98

	bodyOffset := 90
	param := NewParsedParam(ParamBody, "key", "value", bodyOffset, bodyOffset+3, bodyOffset+4, bodyOffset+9)

	ip := NewParameterInsertionPoint(request, param)

	// Test special characters get URL-encoded
	payload := []byte("a b&c")
	result := ip.BuildRequest(payload)

	// Verify payload is URL-encoded (space becomes '+', & becomes %26)
	if !bytes.Contains(result, []byte("key=a+b%26c")) {
		t.Errorf("BuildRequest() did not properly encode payload: %q", result)
	}
}

// TestParameterInsertionPoint_CookieEncoding tests cookie parameter encoding.
// Ported from: ggd.java with COOKIE parameter type
func TestParameterInsertionPoint_CookieEncoding(t *testing.T) {
	request := []byte("GET / HTTP/1.1\r\nCookie: session=abc123\r\n\r\n")
	// "Cookie: session=abc123"
	// Position 24: 's' in session, Position 31: '=', Position 32-38: 'abc123'

	// Cookie parameter
	param := NewParsedParam(ParamCookie, "session", "abc123", 24, 31, 32, 38)

	ip := NewParameterInsertionPoint(request, param)

	// Cookies should be URL-encoded (space becomes '+')
	payload := []byte("test value")
	result := ip.BuildRequest(payload)

	if !bytes.Contains(result, []byte("session=test+value")) {
		t.Errorf("BuildRequest() did not properly encode cookie: %q", result)
	}
}

// TestParameterInsertionPoint_PathFolderEncoding tests path folder parameter encoding.
// Ported from: ggd.java with PATH_FOLDER_PARAM parameter type
func TestParameterInsertionPoint_PathFolderEncoding(t *testing.T) {
	request := []byte("GET /api/users/123 HTTP/1.1\r\nHost: example.com\r\n\r\n")
	// Path: /api/users/123
	// Position 5-8: "api" (folder)
	// Position 9-14: "users" (folder)
	// Position 15-18: "123" (filename)

	// Test path folder parameter "users"
	param := NewParsedParam(ParamPathFolder, "2", "users", -1, -1, 9, 14)

	ip := NewParameterInsertionPoint(request, param)

	tests := []struct {
		name     string
		payload  []byte
		expected string
	}{
		{
			name:     "alphanumeric payload",
			payload:  []byte("admin"),
			expected: "GET /api/admin/123 HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name:     "special characters with space",
			payload:  []byte("hello world"),
			expected: "GET /api/hello%20world/123 HTTP/1.1\r\nHost: example.com\r\n\r\n", // RFC 3986: space → %20 (not +)
		},
		{
			name:     "symbols requiring encoding",
			payload:  []byte("a&b=c"),
			expected: "GET /api/a%26b%3Dc/123 HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name:     "slash should be encoded",
			payload:  []byte("test/path"),
			expected: "GET /api/test%2Fpath/123 HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ip.BuildRequest(tt.payload)
			if string(result) != tt.expected {
				t.Errorf("BuildRequest() = %q, want %q", result, tt.expected)
			}

			// Verify Content-Length was NOT added (path params don't require it)
			if bytes.Contains(result, []byte("Content-Length:")) {
				t.Errorf("BuildRequest() incorrectly added Content-Length header for path parameter")
			}
		})
	}
}

// TestParameterInsertionPoint_PathFilenameEncoding tests path filename parameter encoding.
// Ported from: ggd.java with PATH_FILENAME_PARAM parameter type
func TestParameterInsertionPoint_PathFilenameEncoding(t *testing.T) {
	request := []byte("GET /api/users/profile.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
	// Path: /api/users/profile.html
	// Position 5-8: "api" (folder)
	// Position 9-14: "users" (folder)
	// Position 15-27: "profile.html" (filename)

	// Test path filename parameter "profile.html"
	param := NewParsedParam(ParamPathFilename, "3", "profile.html", -1, -1, 15, 27)

	ip := NewParameterInsertionPoint(request, param)

	tests := []struct {
		name     string
		payload  []byte
		expected string
	}{
		{
			name:     "simple filename",
			payload:  []byte("index.html"),
			expected: "GET /api/users/index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name:     "filename with spaces",
			payload:  []byte("my file.txt"),
			expected: "GET /api/users/my%20file.txt HTTP/1.1\r\nHost: example.com\r\n\r\n", // RFC 3986: space → %20 (not +)
		},
		{
			name:     "filename with special chars",
			payload:  []byte("data&report.csv"),
			expected: "GET /api/users/data%26report.csv HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name:     "path traversal attempt encoded",
			payload:  []byte("../../../etc/passwd"),
			expected: "GET /api/users/..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ip.BuildRequest(tt.payload)
			if string(result) != tt.expected {
				t.Errorf("BuildRequest() = %q, want %q", result, tt.expected)
			}

			// Verify Content-Length was NOT added (path params don't require it)
			if bytes.Contains(result, []byte("Content-Length:")) {
				t.Errorf("BuildRequest() incorrectly added Content-Length header for path parameter")
			}
		})
	}
}

// TestParameterInsertionPoint_PathParameterOffsets tests PayloadOffsets with path parameters.
// Verifies that offset calculation accounts for URL encoding.
func TestParameterInsertionPoint_PathParameterOffsets(t *testing.T) {
	request := []byte("GET /api/users/123 HTTP/1.1\r\n\r\n")
	// "users" is at position 9-14

	param := NewParsedParam(ParamPathFolder, "2", "users", -1, -1, 9, 14)
	ip := NewParameterInsertionPoint(request, param)

	tests := []struct {
		name          string
		payload       []byte
		expectedStart int
		expectedLen   int // Expected length after encoding
	}{
		{
			name:          "no encoding needed",
			payload:       []byte("admin"),
			expectedStart: 9,
			expectedLen:   5,
		},
		{
			name:          "space encoded as percent20",
			payload:       []byte("a b"),
			expectedStart: 9,
			expectedLen:   5, // "a%20b" - RFC 3986 path encoding (not + like query)
		},
		{
			name:          "encoding increases length",
			payload:       []byte("a&b"),
			expectedStart: 9,
			expectedLen:   5, // "a%26b"
		},
		{
			name:          "multiple special chars",
			payload:       []byte("a&b=c"),
			expectedStart: 9,
			expectedLen:   9, // "a%26b%3Dc"
		},
		{
			name:          "slash encoded",
			payload:       []byte("a/b"),
			expectedStart: 9,
			expectedLen:   5, // "a%2Fb"
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			offsets := ip.PayloadOffsets(tt.payload)

			if offsets[0] != tt.expectedStart {
				t.Errorf("Offset start = %d, want %d", offsets[0], tt.expectedStart)
			}

			actualLen := offsets[1] - offsets[0]
			if actualLen != tt.expectedLen {
				t.Errorf("Payload length = %d, want %d", actualLen, tt.expectedLen)
			}
		})
	}
}

// TestParameterInsertionPoint_Types tests type mapping.
// Ported from: ggd.getInsertionPointType() switch statement (lines 68-108)
func TestParameterInsertionPoint_Types(t *testing.T) {
	request := []byte("GET / HTTP/1.1\r\n\r\n")

	tests := []struct {
		name         string
		paramType    ParamType
		expectedType InsertionPointType
	}{
		{"URL param", ParamURL, INS_PARAM_URL},
		{"Body param", ParamBody, INS_PARAM_BODY},
		{"Cookie", ParamCookie, INS_PARAM_COOKIE},
		{"XML", ParamXML, INS_PARAM_XML},
		{"XML attr", ParamXMLAttr, INS_PARAM_XML_ATTR},
		{"JSON", ParamJSON, INS_PARAM_JSON},
		{"Multipart attr", ParamMultipartAttr, INS_PARAM_MULTIPART_ATTR},
		{"Path folder", ParamPathFolder, INS_URL_PATH_FOLDER},
		{"Path filename", ParamPathFilename, INS_URL_PATH_FILENAME},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			param := NewParsedParam(tt.paramType, "test", "value", 4, 8, 9, 14)
			ip := NewParameterInsertionPoint(request, param)

			if ip.Type() != tt.expectedType {
				t.Errorf("GetInsertionPointType() = %d, want %d", ip.Type(), tt.expectedType)
			}
		})
	}
}

// TestParameterInsertionPoint_PayloadOffsets tests offset tracking through encoding.
// Ported from: ggd.getPayloadOffsets() (lines 35-65)
func TestParameterInsertionPoint_PayloadOffsets(t *testing.T) {
	request := []byte("GET /api?id=123 HTTP/1.1\r\n\r\n")
	param := NewParsedParam(ParamURL, "id", "123", 9, 11, 12, 15)
	ip := NewParameterInsertionPoint(request, param)

	tests := []struct {
		name          string
		payload       []byte
		expectedStart int
		expectedLen   int // Expected length after encoding
	}{
		{
			name:          "no encoding needed",
			payload:       []byte("456"),
			expectedStart: 12,
			expectedLen:   3,
		},
		{
			name:          "encoding increases length",
			payload:       []byte("a&b"),
			expectedStart: 12,
			expectedLen:   5, // "a%26b"
		},
		{
			name:          "space encoded",
			payload:       []byte("a b"),
			expectedStart: 12,
			expectedLen:   3, // "a+b"
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			offsets := ip.PayloadOffsets(tt.payload)
			if offsets[0] != tt.expectedStart {
				t.Errorf("Offset start = %d, want %d", offsets[0], tt.expectedStart)
			}

			actualLen := offsets[1] - offsets[0]
			if actualLen != tt.expectedLen {
				t.Errorf("Payload length = %d, want %d", actualLen, tt.expectedLen)
			}
		})
	}
}

// TestParameterInsertionPoint_ThreadSafety tests that base request is cloned.
func TestParameterInsertionPoint_ThreadSafety(t *testing.T) {
	request := []byte("GET /api?id=123 HTTP/1.1\r\n\r\n")
	param := NewParsedParam(ParamURL, "id", "123", 9, 11, 12, 15)

	ip := NewParameterInsertionPoint(request, param)

	// Modify original request
	request[12] = 'X'

	// Build request should use cloned copy
	result := ip.BuildRequest([]byte("456"))

	expected := []byte("GET /api?id=456 HTTP/1.1\r\n\r\n")
	if !bytes.Equal(result, expected) {
		t.Errorf("BuildRequest() = %q, want %q (original request modification affected insertion point)", result, expected)
	}
}

// TestParameterInsertionPoint_Validation tests constructor validation.
func TestParameterInsertionPoint_Validation(t *testing.T) {
	request := []byte("GET / HTTP/1.1\r\n\r\n")

	t.Run("nil parameter", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("NewParameterInsertionPoint(nil) should panic")
			}
		}()
		NewParameterInsertionPoint(request, nil)
	})

	t.Run("nil request", func(t *testing.T) {
		param := NewParam(ParamURL, "test", "value")
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("NewParameterInsertionPoint with nil request should panic")
			}
		}()
		NewParameterInsertionPoint(nil, param)
	})
}

// TestParameterInsertionPoint_BuildRequestNilPayload tests nil payload handling.
func TestParameterInsertionPoint_BuildRequestNilPayload(t *testing.T) {
	request := []byte("GET /api?id=123 HTTP/1.1\r\n\r\n")
	param := NewParsedParam(ParamURL, "id", "123", 9, 11, 12, 15)
	ip := NewParameterInsertionPoint(request, param)

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("BuildRequest(nil) should panic")
		}
	}()

	ip.BuildRequest(nil)
}

// TestParameterInsertionPoint_PayloadOffsetsNilPayload tests nil payload in offset calculation.
func TestParameterInsertionPoint_PayloadOffsetsNilPayload(t *testing.T) {
	request := []byte("GET /api?id=123 HTTP/1.1\r\n\r\n")
	param := NewParsedParam(ParamURL, "id", "123", 9, 11, 12, 15)
	ip := NewParameterInsertionPoint(request, param)

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("PayloadOffsets(nil) should panic")
		}
	}()

	ip.PayloadOffsets(nil)
}

// TestParameterInsertionPoint_XMLNoEncoding tests XML parameter without encoding.
func TestParameterInsertionPoint_XMLNoEncoding(t *testing.T) {
	request := []byte("POST /api HTTP/1.1\r\n\r\n<user>test</user>")
	// "POST /api HTTP/1.1\r\n\r\n<user>test</user>"
	//  0         1         2         3
	//  012345678901234567890123456789012345678
	// Body starts at 22: "<user>test</user>"
	// Name "user" at [23:27], Value "test" at [28:32]

	nameStart := 23  // 'u' in <user>
	nameEnd := 27    // '>' after user
	valueStart := 28 // 't' in test
	valueEnd := 32   // '<' in </user>

	param := NewParsedParam(ParamXML, "user", "test", nameStart, nameEnd, valueStart, valueEnd)
	ip := NewParameterInsertionPoint(request, param)

	// XML payloads should NOT be URL-encoded
	payload := []byte("admin")
	result := ip.BuildRequest(payload)

	// Body length is 18 bytes: <user>admin</user>
	expected := []byte("POST /api HTTP/1.1\r\nContent-Length: 18\r\n\r\n<user>admin</user>")
	if !bytes.Equal(result, expected) {
		t.Errorf("BuildRequest() = %q, want %q", result, expected)
	}
}

// TestParameterInsertionPoint_MultipartNoEncoding tests multipart parameters.
func TestParameterInsertionPoint_MultipartNoEncoding(t *testing.T) {
	request := []byte("POST /upload HTTP/1.1\r\nContent-Type: multipart/form-data\r\n\r\nfilename=test.txt")
	// "POST /upload HTTP/1.1\r\nContent-Type: multipart/form-data\r\n\r\nfilename=test.txt"
	//  0         1         2         3         4         5         6         7
	//  0123456789012345678901234567890123456789012345678901234567890123456789012345
	// Headers end at 59, body starts at 60
	// Body: "filename=test.txt" (length 17, total request 77 bytes)
	// Name "filename" at [60:68], Value "test.txt" at [69:77]

	nameStart := 60  // 'f' in filename
	nameEnd := 68    // '=' after filename
	valueStart := 69 // 't' in test.txt
	valueEnd := 77   // end of request

	param := NewParsedParam(ParamMultipartAttr, "filename", "test.txt", nameStart, nameEnd, valueStart, valueEnd)
	ip := NewParameterInsertionPoint(request, param)

	payload := []byte("bad.exe")
	result := ip.BuildRequest(payload)

	// Multipart attributes should NOT be URL-encoded
	if !bytes.Contains(result, []byte("filename=bad.exe")) {
		t.Errorf("BuildRequest() incorrectly encoded multipart attribute: %q", result)
	}
}

// TestParamTypeToInsertionPointType tests the mapping function.
// Ported from: ggd.getInsertionPointType() switch statement
func TestParamTypeToInsertionPointType(t *testing.T) {
	tests := []struct {
		paramType ParamType
		wantType  InsertionPointType
	}{
		{ParamURL, INS_PARAM_URL},
		{ParamBody, INS_PARAM_BODY},
		{ParamCookie, INS_PARAM_COOKIE},
		{ParamXML, INS_PARAM_XML},
		{ParamXMLAttr, INS_PARAM_XML_ATTR},
		{ParamMultipartAttr, INS_PARAM_MULTIPART_ATTR},
		{ParamBodyMultipart, INS_PARAM_BODY}, // ggd.java case 3 -> return 1
		{ParamPathFolder, INS_URL_PATH_FOLDER},
		{ParamPathFilename, INS_URL_PATH_FILENAME},
		{ParamJSON, INS_PARAM_JSON},
		{ParamNone, INS_UNKNOWN},
	}

	for _, tt := range tests {
		t.Run(tt.paramType.String(), func(t *testing.T) {
			got := tt.paramType.ToInsertionPointType()
			if got != tt.wantType {
				t.Errorf("ParamType.ToInsertionPointType(%d) = %d, want %d", tt.paramType, got, tt.wantType)
			}
		})
	}
}

// TestUpdateContentLength tests Content-Length header update.
// This test now uses the proper UpdateContentLength from request_builder.go
// Ported from: glo.java d(bi9) method (lines 295-312)
func TestUpdateContentLength(t *testing.T) {
	tests := []struct {
		name     string
		request  []byte
		expected string // Expected Content-Length value
	}{
		{
			name:     "update to smaller",
			request:  []byte("POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\nabc"),
			expected: "3",
		},
		{
			name:     "update to larger",
			request:  []byte("POST / HTTP/1.1\r\nContent-Length: 1\r\n\r\nabcdefghij"),
			expected: "10",
		},
		{
			name:     "no body",
			request:  []byte("POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\n"),
			expected: "0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := UpdateContentLength(tt.request)
			if err != nil {
				t.Fatalf("UpdateContentLength() error = %v", err)
			}

			// Find Content-Length in result
			if !bytes.Contains(result, []byte("Content-Length: "+tt.expected)) {
				t.Errorf("UpdateContentLength() did not set Content-Length to %s: %q", tt.expected, result)
			}
		})
	}
}

// TestParameterInsertionPoint_ContentLengthUpdate tests automatic Content-Length update.
func TestParameterInsertionPoint_ContentLengthUpdate(t *testing.T) {
	request := []byte("POST /api HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 9\r\n\r\nkey=value")

	bodyOffset := 90
	param := NewParsedParam(ParamBody, "key", "value", bodyOffset, bodyOffset+3, bodyOffset+4, bodyOffset+9)

	ip := NewParameterInsertionPoint(request, param)

	// Inject different length payload
	payload := []byte("newvalue")
	result := ip.BuildRequest(payload)

	// Content-Length should be updated to 12 (len("key=newvalue"))
	if !bytes.Contains(result, []byte("Content-Length: 12")) {
		t.Errorf("BuildRequest() did not update Content-Length: %q", result)
	}
}

// TestParameterInsertionPoint_BinaryPayload tests binary payloads.
// Binary payloads with control characters are escaped when injected into JSON string fields.
func TestParameterInsertionPoint_BinaryPayload(t *testing.T) {
	request := []byte("POST /api HTTP/1.1\r\n\r\n{\"data\":\"test\"}")
	bodyOffset := 22 // Length of "POST /api HTTP/1.1\r\n\r\n"
	// {"data":"test"} - "test" content starts at position 9 in body
	valueStart := bodyOffset + 9
	valueEnd := bodyOffset + 13

	param := NewParsedParam(ParamJSON, "data", "test", bodyOffset+2, bodyOffset+6, valueStart, valueEnd)
	// Mark as string type for type-aware encoding
	param = param.WithJSONType(JSONTypeString)
	ip := NewParameterInsertionPoint(request, param)

	// Binary payload with control characters
	payload := []byte{0x00, 0x01}
	result := ip.BuildRequest(payload)

	// Control characters (< 32) should be escaped as \u00xx
	// 0x00 -> \u0000, 0x01 -> \u0001
	expectedEscaped := []byte(`\u0000\u0001`)
	if !bytes.Contains(result, expectedEscaped) {
		t.Errorf("BuildRequest() did not escape binary payload correctly. Got: %q", result)
	}
}

// Benchmark tests

// BenchmarkParameterInsertionPoint_BuildRequest benchmarks request building.
func BenchmarkParameterInsertionPoint_BuildRequest(b *testing.B) {
	request := []byte("GET /api?id=123&name=test HTTP/1.1\r\n\r\n")
	param := NewParsedParam(ParamURL, "id", "123", 9, 11, 12, 15)
	ip := NewParameterInsertionPoint(request, param)
	payload := []byte("test payload")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ip.BuildRequest(payload)
	}
}

// BenchmarkParameterInsertionPoint_BuildRequestWithEncoding benchmarks with encoding.
func BenchmarkParameterInsertionPoint_BuildRequestWithEncoding(b *testing.B) {
	request := []byte("GET /api?q=test HTTP/1.1\r\n\r\n")
	param := NewParsedParam(ParamURL, "q", "test", 9, 10, 11, 15)
	ip := NewParameterInsertionPoint(request, param)
	payload := []byte("hello world & special chars")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ip.BuildRequest(payload)
	}
}

// BenchmarkParameterInsertionPoint_PayloadOffsets benchmarks offset calculation.
func BenchmarkParameterInsertionPoint_PayloadOffsets(b *testing.B) {
	request := []byte("GET /api?id=123 HTTP/1.1\r\n\r\n")
	param := NewParsedParam(ParamURL, "id", "123", 9, 11, 12, 15)
	ip := NewParameterInsertionPoint(request, param)
	payload := []byte("test")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ip.PayloadOffsets(payload)
	}
}

// TestParameterInsertionPoint_JSONTypeAwareInjection tests type-aware JSON payload injection.
// This verifies the core feature: auto-quoting strings when injecting into non-string fields.
func TestParameterInsertionPoint_JSONTypeAwareInjection(t *testing.T) {
	tests := []struct {
		name         string
		json         string
		paramName    string
		origType     JSONValueType
		valueStart   int // Offset of value in body
		valueEnd     int
		payload      []byte
		expectedBody string
	}{
		// Inject string into boolean → wrap with quotes
		{
			name:         "string into boolean",
			json:         `{"active":true}`,
			paramName:    "active",
			origType:     JSONTypeBool,
			valueStart:   10,
			valueEnd:     14,
			payload:      []byte("evil"),
			expectedBody: `{"active":"evil"}`,
		},
		// Inject false into boolean → keep raw
		{
			name:         "false into boolean",
			json:         `{"active":true}`,
			paramName:    "active",
			origType:     JSONTypeBool,
			valueStart:   10,
			valueEnd:     14,
			payload:      []byte("false"),
			expectedBody: `{"active":false}`,
		},
		// Inject true into boolean → keep raw
		{
			name:         "true into boolean",
			json:         `{"active":false}`,
			paramName:    "active",
			origType:     JSONTypeBool,
			valueStart:   10,
			valueEnd:     15,
			payload:      []byte("true"),
			expectedBody: `{"active":true}`,
		},
		// Inject number into number → keep raw
		{
			name:         "number into number",
			json:         `{"count":42}`,
			paramName:    "count",
			origType:     JSONTypeNumber,
			valueStart:   9,
			valueEnd:     11,
			payload:      []byte("999"),
			expectedBody: `{"count":999}`,
		},
		// Inject string into number → wrap with quotes
		{
			name:         "string into number",
			json:         `{"count":42}`,
			paramName:    "count",
			origType:     JSONTypeNumber,
			valueStart:   9,
			valueEnd:     11,
			payload:      []byte("not a number"),
			expectedBody: `{"count":"not a number"}`,
		},
		// Inject into string → escape only (no extra quotes added)
		// {"name":"john"} - "john" content is at [9:13]
		{
			name:         "simple string into string",
			json:         `{"name":"john"}`,
			paramName:    "name",
			origType:     JSONTypeString,
			valueStart:   9,
			valueEnd:     13,
			payload:      []byte("alice"),
			expectedBody: `{"name":"alice"}`,
		},
		// Inject string with quote into string → escape the quote
		{
			name:         "string with quote into string",
			json:         `{"name":"john"}`,
			paramName:    "name",
			origType:     JSONTypeString,
			valueStart:   9,
			valueEnd:     13,
			payload:      []byte(`test"quote`),
			expectedBody: `{"name":"test\"quote"}`,
		},
		// Inject quoted payload into string → treat as literal, escape quotes
		{
			name:         "quoted payload into string",
			json:         `{"name":"john"}`,
			paramName:    "name",
			origType:     JSONTypeString,
			valueStart:   9,
			valueEnd:     13,
			payload:      []byte(`"already quoted"`),
			expectedBody: `{"name":"\"already quoted\""}`,
		},
		// Inject null into null → keep raw
		{
			name:         "null into null",
			json:         `{"value":null}`,
			paramName:    "value",
			origType:     JSONTypeNull,
			valueStart:   9,
			valueEnd:     13,
			payload:      []byte("null"),
			expectedBody: `{"value":null}`,
		},
		// Inject string into null → wrap with quotes
		{
			name:         "string into null",
			json:         `{"value":null}`,
			paramName:    "value",
			origType:     JSONTypeNull,
			valueStart:   9,
			valueEnd:     13,
			payload:      []byte("something"),
			expectedBody: `{"value":"something"}`,
		},
		// Inject number into null → keep raw (valid JSON primitive)
		{
			name:         "number into null",
			json:         `{"value":null}`,
			paramName:    "value",
			origType:     JSONTypeNull,
			valueStart:   9,
			valueEnd:     13,
			payload:      []byte("123"),
			expectedBody: `{"value":123}`,
		},
		// Inject string with backslash into string → escape backslash
		// {"path":"test"} - "test" content is at [9:13]
		{
			name:         "string with backslash",
			json:         `{"path":"test"}`,
			paramName:    "path",
			origType:     JSONTypeString,
			valueStart:   9,
			valueEnd:     13,
			payload:      []byte(`C:\Users`),
			expectedBody: `{"path":"C:\\Users"}`,
		},
		// Inject string with newline into string → escape newline
		// {"text":"test"} - "test" content is at [9:13]
		{
			name:         "string with newline",
			json:         `{"text":"test"}`,
			paramName:    "text",
			origType:     JSONTypeString,
			valueStart:   9,
			valueEnd:     13,
			payload:      []byte("line1\nline2"),
			expectedBody: `{"text":"line1\nline2"}`,
		},
		// Inject float into number → keep raw
		{
			name:         "float into number",
			json:         `{"pi":3}`,
			paramName:    "pi",
			origType:     JSONTypeNumber,
			valueStart:   6,
			valueEnd:     7,
			payload:      []byte("3.14159"),
			expectedBody: `{"pi":3.14159}`,
		},
		// Inject scientific notation → keep raw
		{
			name:         "scientific into number",
			json:         `{"big":0}`,
			paramName:    "big",
			origType:     JSONTypeNumber,
			valueStart:   7,
			valueEnd:     8,
			payload:      []byte("1.5e10"),
			expectedBody: `{"big":1.5e10}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build request with JSON body
			headers := "POST /api HTTP/1.1\r\nContent-Type: application/json\r\n\r\n"
			request := []byte(headers + tt.json)
			bodyOffset := len(headers) // 54 bytes

			// Create parameter with correct offsets and type
			param := NewParsedParam(
				ParamJSON,
				tt.paramName,
				"", // value doesn't matter for this test
				0, 0,
				bodyOffset+tt.valueStart,
				bodyOffset+tt.valueEnd,
			)
			param = param.WithJSONType(tt.origType)

			ip := NewParameterInsertionPoint(request, param)
			result := ip.BuildRequest(tt.payload)

			// Extract body from result
			bodyStart := bytes.Index(result, []byte("\r\n\r\n"))
			if bodyStart == -1 {
				t.Fatalf("Could not find body in result")
			}
			resultBody := string(result[bodyStart+4:])

			// Compare ignoring Content-Length header differences
			if resultBody != tt.expectedBody {
				t.Errorf("Body = %q, want %q", resultBody, tt.expectedBody)
			}
		})
	}
}

// TestParameterInsertionPoint_JSONEscapeSpecialChars tests escaping of special characters.
func TestParameterInsertionPoint_JSONEscapeSpecialChars(t *testing.T) {
	tests := []struct {
		name     string
		payload  []byte
		expected string // Expected escaped content (without surrounding quotes)
	}{
		{"double quote", []byte(`"`), `\"`},
		{"backslash", []byte(`\`), `\\`},
		{"newline", []byte("\n"), `\n`},
		{"carriage return", []byte("\r"), `\r`},
		{"tab", []byte("\t"), `\t`},
		{"backspace", []byte("\b"), `\b`},
		{"form feed", []byte("\f"), `\f`},
		{"mixed", []byte("test\"quote\nline"), `test\"quote\nline`},
		{"path", []byte(`C:\Users\test`), `C:\\Users\\test`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := escapeJSONStringContent(tt.payload)
			if string(result) != tt.expected {
				t.Errorf("escapeJSONStringContent(%q) = %q, want %q", tt.payload, result, tt.expected)
			}
		})
	}
}

// TestParameterInsertionPoint_IsValidJSONPrimitive tests primitive detection.
func TestParameterInsertionPoint_IsValidJSONPrimitive(t *testing.T) {
	tests := []struct {
		payload  []byte
		expected bool
	}{
		{[]byte("true"), true},
		{[]byte("false"), true},
		{[]byte("null"), true},
		{[]byte("123"), true},
		{[]byte("0"), true},
		{[]byte("-5"), true},
		{[]byte("3.14"), true},
		{[]byte("1.5e10"), true},
		{[]byte("-3.14e-5"), true},
		{[]byte("hello"), false},
		{[]byte("TRUE"), false}, // JSON is case-sensitive
		{[]byte("False"), false},
		{[]byte("NULL"), false},
		{[]byte(`"string"`), false}, // Quoted string is not a primitive
		{[]byte(""), false},
		{[]byte("  true  "), true}, // Whitespace should be trimmed
	}

	for _, tt := range tests {
		t.Run(string(tt.payload), func(t *testing.T) {
			result := isValidJSONPrimitive(tt.payload)
			if result != tt.expected {
				t.Errorf("isValidJSONPrimitive(%q) = %v, want %v", tt.payload, result, tt.expected)
			}
		})
	}
}

// TestParameterInsertionPoint_WrapAsJSONString tests string wrapping.
func TestParameterInsertionPoint_WrapAsJSONString(t *testing.T) {
	tests := []struct {
		payload  []byte
		expected string
	}{
		{[]byte("hello"), `"hello"`},
		{[]byte("test\"quote"), `"test\"quote"`},
		{[]byte(`C:\Users`), `"C:\\Users"`},
		{[]byte("line1\nline2"), `"line1\nline2"`},
		{[]byte(""), `""`},
	}

	for _, tt := range tests {
		t.Run(string(tt.payload), func(t *testing.T) {
			result := wrapAsJSONString(tt.payload)
			if string(result) != tt.expected {
				t.Errorf("wrapAsJSONString(%q) = %q, want %q", tt.payload, result, tt.expected)
			}
		})
	}
}
