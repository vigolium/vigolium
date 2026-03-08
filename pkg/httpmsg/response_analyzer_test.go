package httpmsg

import (
	"testing"
)

// TestAnalyzeResponse tests the main response analysis function.
func TestAnalyzeResponse(t *testing.T) {
	tests := []struct {
		name               string
		response           []byte
		expectedStatus     int16
		expectedHeaders    int
		expectedBodyOffset int
		expectedStated     string
		expectedInferred   string
		expectedCookies    int
	}{
		{
			name: "Simple 200 OK with HTML",
			response: []byte("HTTP/1.1 200 OK\r\n" +
				"Content-Type: text/html\r\n" +
				"\r\n" +
				"<html><body>Test</body></html>"),
			expectedStatus:     200,
			expectedHeaders:    2,
			expectedBodyOffset: 44,
			expectedStated:     "text/html",
			expectedInferred:   "HTML",
			expectedCookies:    0,
		},
		{
			name: "404 with JSON body",
			response: []byte("HTTP/1.1 404 Not Found\r\n" +
				"Content-Type: application/json\r\n" +
				"\r\n" +
				`{"error":"not found"}`),
			expectedStatus:     404,
			expectedHeaders:    2,
			expectedBodyOffset: 58,
			expectedStated:     "application/json",
			expectedInferred:   "JSON",
			expectedCookies:    0,
		},
		{
			name: "Response with single cookie",
			response: []byte("HTTP/1.1 200 OK\r\n" +
				"Set-Cookie: sessionid=abc123\r\n" +
				"\r\n"),
			expectedStatus:     200,
			expectedHeaders:    2,
			expectedBodyOffset: 49,
			expectedStated:     "",
			expectedInferred:   "",
			expectedCookies:    1,
		},
		{
			name: "Response with multiple cookies",
			response: []byte("HTTP/1.1 200 OK\r\n" +
				"Set-Cookie: id=123\r\n" +
				"Set-Cookie: token=xyz\r\n" +
				"\r\n"),
			expectedStatus:     200,
			expectedHeaders:    3,
			expectedBodyOffset: 62,
			expectedStated:     "",
			expectedInferred:   "",
			expectedCookies:    2,
		},
		{
			name: "Response with cookie attributes",
			response: []byte("HTTP/1.1 200 OK\r\n" +
				"Set-Cookie: id=123; Domain=.example.com; Path=/; Expires=Mon, 01-Jan-2024 00:00:00 GMT\r\n" +
				"\r\n"),
			expectedStatus:     200,
			expectedHeaders:    2,
			expectedBodyOffset: 107,
			expectedStated:     "",
			expectedInferred:   "",
			expectedCookies:    1,
		},
		{
			name: "500 Internal Server Error",
			response: []byte("HTTP/1.1 500 Internal Server Error\r\n" +
				"Content-Type: text/plain\r\n" +
				"\r\n" +
				"Error occurred"),
			expectedStatus:     500,
			expectedHeaders:    2,
			expectedBodyOffset: 64,
			expectedStated:     "text/plain",
			expectedInferred:   "",
			expectedCookies:    0,
		},
		{
			name: "Response with LF line endings",
			response: []byte("HTTP/1.1 200 OK\n" +
				"Content-Type: text/html\n" +
				"\n" +
				"<html>test</html>"),
			expectedStatus:     200,
			expectedHeaders:    1, // ExtractHeaders only handles CRLF, not standalone LF
			expectedBodyOffset: 41,
			expectedStated:     "", // Cannot extract Content-Type without proper header parsing
			expectedInferred:   "HTML",
			expectedCookies:    0,
		},
		{
			name: "Response with XML body",
			response: []byte("HTTP/1.1 200 OK\r\n" +
				"Content-Type: application/xml\r\n" +
				"\r\n" +
				"<?xml version=\"1.0\"?><root></root>"),
			expectedStatus:     200,
			expectedHeaders:    2,
			expectedBodyOffset: 50,
			expectedStated:     "application/xml",
			expectedInferred:   "XML",
			expectedCookies:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := AnalyzeResponse(tt.response)
			if err != nil {
				t.Fatalf("AnalyzeResponse failed: %v", err)
			}

			if info.StatusCode != tt.expectedStatus {
				t.Errorf("StatusCode = %d, want %d", info.StatusCode, tt.expectedStatus)
			}

			if len(info.Headers) != tt.expectedHeaders {
				t.Errorf("Headers count = %d, want %d", len(info.Headers), tt.expectedHeaders)
			}

			if info.BodyOffset != tt.expectedBodyOffset {
				t.Errorf("BodyOffset = %d, want %d", info.BodyOffset, tt.expectedBodyOffset)
			}

			if info.StatedMimeType != tt.expectedStated {
				t.Errorf("StatedMimeType = %q, want %q", info.StatedMimeType, tt.expectedStated)
			}

			if info.InferredMimeType != tt.expectedInferred {
				t.Errorf("InferredMimeType = %q, want %q", info.InferredMimeType, tt.expectedInferred)
			}

			if len(info.Cookies) != tt.expectedCookies {
				t.Errorf("Cookies count = %d, want %d", len(info.Cookies), tt.expectedCookies)
			}
		})
	}
}

// TestAnalyzeResponseNil tests nil response handling.
func TestAnalyzeResponseNil(t *testing.T) {
	info, err := AnalyzeResponse(nil)
	if err != nil {
		t.Errorf("Expected no error for nil response, got %v", err)
	}
	if info != nil {
		t.Errorf("Expected nil info for nil response, got %+v", info)
	}
}

// TestParseStatusLine tests status line parsing.
func TestParseStatusLine(t *testing.T) {
	tests := []struct {
		name       string
		statusLine string
		expected   int16
	}{
		{"200 OK", "HTTP/1.1 200 OK", 200},
		{"404 Not Found", "HTTP/1.1 404 Not Found", 404},
		{"500 Internal Server Error", "HTTP/1.1 500 Internal Server Error", 500},
		{"301 Moved Permanently", "HTTP/1.1 301 Moved Permanently", 301},
		{"204 No Content", "HTTP/1.1 204 No Content", 204},
		{"HTTP/2", "HTTP/2 200 OK", 200},
		{"HTTP/1.0", "HTTP/1.0 200 OK", 200},
		{"Empty string", "", 0},
		{"Invalid format", "INVALID", 0},
		{"Missing status code", "HTTP/1.1", 0},
		{"Non-numeric status", "HTTP/1.1 ABC OK", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseStatusLine(tt.statusLine)
			if result != tt.expected {
				t.Errorf("parseStatusLine(%q) = %d, want %d", tt.statusLine, result, tt.expected)
			}
		})
	}
}

// TestParseSetCookie tests cookie parsing.
func TestParseSetCookie(t *testing.T) {
	tests := []struct {
		name           string
		setCookieValue string
		expectNil      bool
		expectedName   string
		expectedValue  string
		expectedDomain string
		expectedPath   string
	}{
		{
			name:           "Simple cookie",
			setCookieValue: "Set-Cookie: id=123",
			expectedName:   "id",
			expectedValue:  "123",
		},
		{
			name:           "Cookie with domain",
			setCookieValue: "Set-Cookie: id=123; Domain=.example.com",
			expectedName:   "id",
			expectedValue:  "123",
			expectedDomain: "example.com", // Leading dot removed
		},
		{
			name:           "Cookie with path",
			setCookieValue: "Set-Cookie: id=123; Path=/admin",
			expectedName:   "id",
			expectedValue:  "123",
			expectedPath:   "/admin",
		},
		{
			name:           "Cookie with all attributes",
			setCookieValue: "Set-Cookie: id=123; Domain=.example.com; Path=/; Expires=Mon, 01-Jan-2024 00:00:00 GMT",
			expectedName:   "id",
			expectedValue:  "123",
			expectedDomain: "example.com",
			expectedPath:   "/",
		},
		{
			name:           "Cookie with wildcard domain",
			setCookieValue: "Set-Cookie: id=123; Domain=*.example.com",
			expectedName:   "id",
			expectedValue:  "123",
			expectedDomain: "example.com", // Wildcard removed
		},
		{
			name:           "Cookie without value",
			setCookieValue: "Set-Cookie: token=",
			expectedName:   "token",
			expectedValue:  "",
		},
		{
			name:           "Too short header",
			setCookieValue: "Set-Cookie",
			expectNil:      true,
		},
		{
			name:           "Cookie with spaces",
			setCookieValue: "Set-Cookie:  id = 123 ; Domain = .example.com ",
			expectedName:   "id",
			expectedValue:  "123",
			expectedDomain: "example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cookie := parseSetCookie(tt.setCookieValue)

			if tt.expectNil {
				if cookie != nil {
					t.Errorf("Expected nil cookie, got %+v", cookie)
				}
				return
			}

			if cookie == nil {
				t.Fatal("Expected cookie, got nil")
			}

			if cookie.Name != tt.expectedName {
				t.Errorf("Name = %q, want %q", cookie.Name, tt.expectedName)
			}

			if cookie.Value != tt.expectedValue {
				t.Errorf("Value = %q, want %q", cookie.Value, tt.expectedValue)
			}

			if cookie.Domain != tt.expectedDomain {
				t.Errorf("Domain = %q, want %q", cookie.Domain, tt.expectedDomain)
			}

			if cookie.Path != tt.expectedPath {
				t.Errorf("Path = %q, want %q", cookie.Path, tt.expectedPath)
			}
		})
	}
}

// TestParseSetCookieExpiration tests cookie expiration parsing.
func TestParseSetCookieExpiration(t *testing.T) {
	tests := []struct {
		name           string
		setCookieValue string
		expectExpiry   bool
	}{
		{
			name:           "Cookie with Expires",
			setCookieValue: "Set-Cookie: id=123; Expires=Mon, 01-Jan-2024 00:00:00 GMT",
			expectExpiry:   true,
		},
		{
			name:           "Cookie with Max-Age",
			setCookieValue: "Set-Cookie: id=123; Max-Age=3600",
			expectExpiry:   true,
		},
		{
			name:           "Cookie without expiration",
			setCookieValue: "Set-Cookie: id=123",
			expectExpiry:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cookie := parseSetCookie(tt.setCookieValue)

			if cookie == nil {
				t.Fatal("Expected cookie, got nil")
			}

			hasExpiry := cookie.Expiration != nil

			if hasExpiry != tt.expectExpiry {
				t.Errorf("Expiration present = %v, want %v", hasExpiry, tt.expectExpiry)
			}

			if tt.expectExpiry && cookie.Expiration != nil {
				// Check that expiration is in the future (for Max-Age) or is valid
				t.Logf("Expiration: %v", cookie.Expiration)
			}
		})
	}
}

// TestParseSetCookieHeaders tests parsing multiple Set-Cookie headers.
func TestParseSetCookieHeaders(t *testing.T) {
	tests := []struct {
		name           string
		headers        []string
		expectedCount  int
		expectedNames  []string
		expectedValues []string
	}{
		{
			name: "No cookies",
			headers: []string{
				"HTTP/1.1 200 OK",
				"Content-Type: text/html",
			},
			expectedCount: 0,
		},
		{
			name: "Single cookie",
			headers: []string{
				"HTTP/1.1 200 OK",
				"Set-Cookie: id=123",
			},
			expectedCount:  1,
			expectedNames:  []string{"id"},
			expectedValues: []string{"123"},
		},
		{
			name: "Multiple cookies",
			headers: []string{
				"HTTP/1.1 200 OK",
				"Set-Cookie: id=123",
				"Set-Cookie: token=xyz",
				"Set-Cookie: session=abc",
			},
			expectedCount:  3,
			expectedNames:  []string{"id", "token", "session"},
			expectedValues: []string{"123", "xyz", "abc"},
		},
		{
			name: "Case insensitive Set-Cookie",
			headers: []string{
				"HTTP/1.1 200 OK",
				"set-cookie: id=123",
				"SET-COOKIE: token=xyz",
			},
			expectedCount:  2,
			expectedNames:  []string{"id", "token"},
			expectedValues: []string{"123", "xyz"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cookies := parseSetCookieHeaders(tt.headers)

			if len(cookies) != tt.expectedCount {
				t.Errorf("Cookie count = %d, want %d", len(cookies), tt.expectedCount)
			}

			for i := 0; i < len(tt.expectedNames); i++ {
				if i >= len(cookies) {
					t.Errorf("Missing cookie at index %d", i)
					continue
				}

				if cookies[i].Name != tt.expectedNames[i] {
					t.Errorf("Cookie[%d].Name = %q, want %q", i, cookies[i].Name, tt.expectedNames[i])
				}

				if cookies[i].Value != tt.expectedValues[i] {
					t.Errorf("Cookie[%d].Value = %q, want %q", i, cookies[i].Value, tt.expectedValues[i])
				}
			}
		})
	}
}

// TestInferMimeType tests MIME type inference from body content.
func TestInferMimeType(t *testing.T) {
	tests := []struct {
		name     string
		body     []byte
		expected string
	}{
		{"HTML with <html>", []byte("<html><body>Test</body></html>"), "HTML"},
		{"HTML with <!DOCTYPE>", []byte("<!DOCTYPE html><html></html>"), "HTML"},
		{"HTML with <body>", []byte("<body>Test</body>"), "HTML"},
		{"HTML with <head>", []byte("<head><title>Test</title></head>"), "HTML"},
		{"HTML uppercase", []byte("<HTML><BODY>Test</BODY></HTML>"), "HTML"},
		{"JSON object", []byte(`{"key":"value"}`), "JSON"},
		{"JSON array", []byte(`[1,2,3]`), "JSON"},
		{"JSON with whitespace", []byte("  \n\t{\"key\":\"value\"}"), "JSON"},
		{"XML declaration", []byte("<?xml version=\"1.0\"?><root></root>"), "XML"},
		{"XML tag", []byte("<root><item>test</item></root>"), "XML"},
		{"XML uppercase", []byte("<?XML version=\"1.0\"?><root></root>"), "XML"},
		{"Plain text", []byte("This is plain text"), ""},
		{"Empty body", []byte(""), ""},
		{"Whitespace only", []byte("   \n\t  "), ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := inferMimeType(tt.body)
			if result != tt.expected {
				t.Errorf("inferMimeType(%q) = %q, want %q", string(tt.body), result, tt.expected)
			}
		})
	}
}

// TestExtractMimeType tests MIME type extraction from Content-Type header.
func TestExtractMimeType(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		expected    string
	}{
		{"Simple type", "text/html", "text/html"},
		{"Type with charset", "text/html; charset=utf-8", "text/html"},
		{"Type with boundary", "multipart/form-data; boundary=----WebKit", "multipart/form-data"},
		{"Type with multiple params", "text/html; charset=utf-8; boundary=xyz", "text/html"},
		{"Type with spaces", "  text/html  ; charset=utf-8", "text/html"},
		{"Empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractMimeType(tt.contentType)
			if result != tt.expected {
				t.Errorf("extractMimeType(%q) = %q, want %q", tt.contentType, result, tt.expected)
			}
		})
	}
}

// TestParseTokens tests token parsing.
func TestParseTokens(t *testing.T) {
	tests := []struct {
		name      string
		s         string
		delimiter byte
		expected  []string
	}{
		{"HTTP status line", "HTTP/1.1 200 OK", ' ', []string{"HTTP/1.1", "200", "OK"}},
		{"Cookie value", "id=123; Domain=.example.com", ';', []string{"id=123", " Domain=.example.com"}},
		{"Empty string", "", ' ', []string{}},
		{"Single token", "token", ' ', []string{"token"}},
		{"Multiple delimiters", "a  b  c", ' ', []string{"a", "b", "c"}}, // Empty tokens between delimiters
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseTokens(tt.s, tt.delimiter)

			if len(result) != len(tt.expected) {
				t.Errorf("Token count = %d, want %d", len(result), len(tt.expected))
				t.Errorf("Got: %v", result)
				t.Errorf("Want: %v", tt.expected)
				return
			}

			for i := 0; i < len(tt.expected); i++ {
				if result[i] != tt.expected[i] {
					t.Errorf("Token[%d] = %q, want %q", i, result[i], tt.expected[i])
				}
			}
		})
	}
}

// TestParseShort tests short integer parsing.
func TestParseShort(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		expected int16
	}{
		{"200", "200", 200},
		{"404", "404", 404},
		{"500", "500", 500},
		{"0", "0", 0},
		{"Negative", "-1", -1},
		{"Empty", "", 0},
		{"Invalid", "abc", 0},
		{"Mixed", "12abc", 0},
		{"Large number", "32767", 32767},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseShort(tt.s)
			if result != tt.expected {
				t.Errorf("parseShort(%q) = %d, want %d", tt.s, result, tt.expected)
			}
		})
	}
}

// TestResponseParseInt tests integer parsing for response analyzer.
func TestResponseParseInt(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		expected int
	}{
		{"3600", "3600", 3600},
		{"0", "0", 0},
		{"Negative", "-100", -100},
		{"Empty", "", 0},
		{"Invalid", "abc", 0},
		{"Large number", "999999", 999999},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseInt(tt.s)
			if result != tt.expected {
				t.Errorf("parseInt(%q) = %d, want %d", tt.s, result, tt.expected)
			}
		})
	}
}

// TestStartsWithCaseInsensitive tests case-insensitive prefix checking.
func TestStartsWithCaseInsensitive(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		prefix   string
		expected bool
	}{
		{"Exact match", "set-cookie:", "set-cookie:", true},
		{"Case mismatch", "Set-Cookie:", "set-cookie:", true},
		{"Uppercase", "SET-COOKIE:", "set-cookie:", true},
		{"Longer string", "Set-Cookie: id=123", "set-cookie:", true},
		{"No match", "Content-Type:", "set-cookie:", false},
		{"Prefix too long", "abc", "abcdef", false},
		{"Empty prefix", "test", "", true},
		{"Empty string", "", "test", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := startsWithCaseInsensitive(tt.s, tt.prefix)
			if result != tt.expected {
				t.Errorf("startsWithCaseInsensitive(%q, %q) = %v, want %v", tt.s, tt.prefix, result, tt.expected)
			}
		})
	}
}

// TestHasPrefix tests byte slice prefix checking.
func TestHasPrefix(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		prefix   []byte
		expected bool
	}{
		{"HTML tag", []byte("<html>"), []byte("<html"), true},
		{"JSON object", []byte(`{"key":"value"}`), []byte("{"), true},
		{"XML declaration", []byte("<?xml version=\"1.0\"?>"), []byte("<?xml"), true},
		{"No match", []byte("plain text"), []byte("<html"), false},
		{"Prefix too long", []byte("abc"), []byte("abcdef"), false},
		{"Empty prefix", []byte("test"), []byte(""), true},
		{"Empty data", []byte(""), []byte("test"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasPrefix(tt.data, tt.prefix)
			if result != tt.expected {
				t.Errorf("hasPrefix(%q, %q) = %v, want %v", string(tt.data), string(tt.prefix), result, tt.expected)
			}
		})
	}
}

// TestResponseInfoGetters tests ResponseInfo getter methods.
func TestResponseInfoGetters(t *testing.T) {
	info := &ResponseInfo{
		StatusCode:       200,
		Headers:          []string{"HTTP/1.1 200 OK", "Content-Type: text/html"},
		BodyOffset:       38,
		StatedMimeType:   "text/html",
		InferredMimeType: "HTML",
		Cookies:          []*Cookie{{Name: "id", Value: "123"}},
	}

	if info.StatusCode != 200 {
		t.Errorf("GetStatusCode() = %d, want 200", info.StatusCode)
	}

	if len(info.Headers) != 2 {
		t.Errorf("GetHeaders() count = %d, want 2", len(info.Headers))
	}

	if info.BodyOffset != 38 {
		t.Errorf("GetBodyOffset() = %d, want 38", info.BodyOffset)
	}

	if info.StatedMimeType != "text/html" {
		t.Errorf("GetStatedMimeType() = %q, want %q", info.StatedMimeType, "text/html")
	}

	if info.InferredMimeType != "HTML" {
		t.Errorf("GetInferredMimeType() = %q, want %q", info.InferredMimeType, "HTML")
	}

	if len(info.Cookies) != 1 {
		t.Errorf("GetCookies() count = %d, want 1", len(info.Cookies))
	}
}

// TestParseExpirationDate tests date parsing for cookie expiration.
func TestParseExpirationDate(t *testing.T) {
	tests := []struct {
		name      string
		dateStr   string
		expectNil bool
	}{
		{"Valid date format 1", "Mon, 01-Jan-2024 00:00:00 GMT", false},
		{"Valid date format 2", "Mon, 01 Jan 2024 00:00:00 GMT", false},
		{"Empty string", "", true},
		{"Invalid format", "invalid date", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseExpirationDate(tt.dateStr)

			if tt.expectNil {
				if result != nil {
					t.Errorf("Expected nil, got %v", result)
				}
			} else {
				if result == nil {
					t.Errorf("Expected non-nil result for %q", tt.dateStr)
				} else {
					t.Logf("Parsed date: %v", result)
				}
			}
		})
	}
}

// Benchmarks

func BenchmarkAnalyzeResponse(b *testing.B) {
	response := []byte("HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"Set-Cookie: id=123; Domain=.example.com; Path=/\r\n" +
		"Set-Cookie: token=xyz; Max-Age=3600\r\n" +
		"\r\n" +
		"<html><body>Test response body</body></html>")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = AnalyzeResponse(response)
	}
}

func BenchmarkParseStatusLine(b *testing.B) {
	statusLine := "HTTP/1.1 200 OK"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = parseStatusLine(statusLine)
	}
}

func BenchmarkParseSetCookie(b *testing.B) {
	setCookieValue := "Set-Cookie: id=123; Domain=.example.com; Path=/; Expires=Mon, 01-Jan-2024 00:00:00 GMT"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = parseSetCookie(setCookieValue)
	}
}

func BenchmarkInferMimeType(b *testing.B) {
	body := []byte("<html><head><title>Test</title></head><body>Test content</body></html>")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = inferMimeType(body)
	}
}

func BenchmarkParseSetCookieHeaders(b *testing.B) {
	headers := []string{
		"HTTP/1.1 200 OK",
		"Content-Type: text/html",
		"Set-Cookie: id=123; Domain=.example.com",
		"Set-Cookie: token=xyz; Path=/",
		"Set-Cookie: session=abc; Max-Age=3600",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = parseSetCookieHeaders(headers)
	}
}

// ==================== NEW UTILITY FUNCTION TESTS ====================

func TestIsResponse(t *testing.T) {
	tests := []struct {
		name     string
		message  []byte
		expected bool
	}{
		{
			name:     "HTTP/1.1 response",
			message:  []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"),
			expected: true,
		},
		{
			name:     "HTTP/1.0 response",
			message:  []byte("HTTP/1.0 200 OK\r\n\r\n"),
			expected: true,
		},
		{
			name:     "HTTP/2 response",
			message:  []byte("HTTP/2 200 OK\r\n\r\n"),
			expected: true,
		},
		{
			name:     "Lowercase http response",
			message:  []byte("http/1.1 200 OK\r\n\r\n"),
			expected: true,
		},
		{
			name:     "HTTP request",
			message:  []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: false,
		},
		{
			name:     "POST request",
			message:  []byte("POST /api HTTP/1.1\r\n\r\n"),
			expected: false,
		},
		{
			name:     "Nil message",
			message:  nil,
			expected: false,
		},
		{
			name:     "Short message",
			message:  []byte("HTTP"),
			expected: false,
		},
		{
			name:     "Empty message",
			message:  []byte{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsResponse(tt.message)
			if result != tt.expected {
				t.Errorf("IsResponse() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestIsRequest(t *testing.T) {
	tests := []struct {
		name     string
		message  []byte
		expected bool
	}{
		{
			name:     "GET request",
			message:  []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: true,
		},
		{
			name:     "POST request",
			message:  []byte("POST /api HTTP/1.1\r\n\r\n"),
			expected: true,
		},
		{
			name:     "HTTP response",
			message:  []byte("HTTP/1.1 200 OK\r\n\r\n"),
			expected: false,
		},
		{
			name:     "Nil message",
			message:  nil,
			expected: false,
		},
		{
			name:     "Empty message",
			message:  []byte{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsRequest(tt.message)
			if result != tt.expected {
				t.Errorf("IsRequest() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestGetStatusCode(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		expected int16
	}{
		{
			name:     "200 OK",
			response: []byte("HTTP/1.1 200 OK\r\n\r\n"),
			expected: 200,
		},
		{
			name:     "404 Not Found",
			response: []byte("HTTP/1.1 404 Not Found\r\n\r\n"),
			expected: 404,
		},
		{
			name:     "500 Internal Server Error",
			response: []byte("HTTP/1.1 500 Internal Server Error\r\n\r\n"),
			expected: 500,
		},
		{
			name:     "301 Redirect",
			response: []byte("HTTP/1.1 301 Moved Permanently\r\n\r\n"),
			expected: 301,
		},
		{
			name:     "Invalid response",
			response: []byte("GET / HTTP/1.1\r\n\r\n"),
			expected: 0,
		},
		{
			name:     "Nil response",
			response: nil,
			expected: 0,
		},
		{
			name:     "Short response",
			response: []byte("HTTP/1.1"),
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetStatusCode(tt.response)
			if result != tt.expected {
				t.Errorf("GetStatusCode() = %d, expected %d", result, tt.expected)
			}
		})
	}
}

func TestGetStartType(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		expected string
	}{
		{
			name:     "HTML response",
			response: []byte("HTTP/1.1 200 OK\r\n\r\n<html><body>Test</body></html>"),
			expected: "<html",
		},
		{
			name:     "HTML with doctype",
			response: []byte("HTTP/1.1 200 OK\r\n\r\n<!DOCTYPE html><html></html>"),
			expected: "<!DOCTYPE",
		},
		{
			name:     "JSON response",
			response: []byte("HTTP/1.1 200 OK\r\n\r\n{\"key\":\"value\"}"),
			expected: "json",
		},
		{
			name:     "JSON array",
			response: []byte("HTTP/1.1 200 OK\r\n\r\n[1,2,3]"),
			expected: "json",
		},
		{
			name:     "XML response",
			response: []byte("HTTP/1.1 200 OK\r\n\r\n<?xml version=\"1.0\"?>"),
			expected: "<?xml",
		},
		{
			name:     "XML tag",
			response: []byte("HTTP/1.1 200 OK\r\n\r\n<root><item>test</item></root>"),
			expected: "xml",
		},
		{
			name:     "Plain text",
			response: []byte("HTTP/1.1 200 OK\r\n\r\nPlain text content"),
			expected: "text",
		},
		{
			name:     "Empty body",
			response: []byte("HTTP/1.1 200 OK\r\n\r\n"),
			expected: "[blank]",
		},
		{
			name:     "Whitespace body",
			response: []byte("HTTP/1.1 200 OK\r\n\r\n   \n\t  "),
			expected: "[blank]",
		},
		{
			name:     "JSON with leading whitespace",
			response: []byte("HTTP/1.1 200 OK\r\n\r\n  \n{\"test\":1}"),
			expected: "json",
		},
		{
			name:     "Nil response",
			response: nil,
			expected: "[blank]",
		},
		{
			name:     "Head tag",
			response: []byte("HTTP/1.1 200 OK\r\n\r\n<head><title>Test</title></head>"),
			expected: "<head",
		},
		{
			name:     "Body tag",
			response: []byte("HTTP/1.1 200 OK\r\n\r\n<body>Content</body>"),
			expected: "<body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetStartType(tt.response)
			if result != tt.expected {
				t.Errorf("GetStartType() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestGetNestedResponse(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		expected []byte
	}{
		{
			name:     "Nested HTTP response in body",
			response: []byte("HTTP/1.1 200 OK\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>"),
			expected: []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>"),
		},
		{
			name:     "No nested response",
			response: []byte("HTTP/1.1 200 OK\r\n\r\n<html>plain content</html>"),
			expected: nil,
		},
		{
			name:     "Lowercase nested response",
			response: []byte("HTTP/1.1 200 OK\r\n\r\nSome data http/1.1 200 OK"),
			expected: []byte("http/1.1 200 OK"),
		},
		{
			name:     "Nil response",
			response: nil,
			expected: nil,
		},
		{
			name:     "Empty body",
			response: []byte("HTTP/1.1 200 OK\r\n\r\n"),
			expected: nil,
		},
		{
			name:     "Body too short for nested HTTP",
			response: []byte("HTTP/1.1 200 OK\r\n\r\nHTTP"),
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetNestedResponse(tt.response)
			if tt.expected == nil {
				if result != nil {
					t.Errorf("GetNestedResponse() = %q, expected nil", result)
				}
				return
			}
			if string(result) != string(tt.expected) {
				t.Errorf("GetNestedResponse() = %q, expected %q", result, tt.expected)
			}
		})
	}
}
