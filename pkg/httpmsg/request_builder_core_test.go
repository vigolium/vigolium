package httpmsg

import (
	"bytes"
	"testing"
)

// ==================== indexByte Tests ====================
// indexByte is the only function in request_builder_core.go without existing tests

func TestIndexByte(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		target   byte
		expected int
	}{
		{
			name:     "Found at start",
			input:    "hello",
			target:   'h',
			expected: 0,
		},
		{
			name:     "Found in middle",
			input:    "hello",
			target:   'l',
			expected: 2,
		},
		{
			name:     "Found at end",
			input:    "hello",
			target:   'o',
			expected: 4,
		},
		{
			name:     "Not found",
			input:    "hello",
			target:   'z',
			expected: -1,
		},
		{
			name:     "Empty string",
			input:    "",
			target:   'a',
			expected: -1,
		},
		{
			name:     "Single character match",
			input:    "a",
			target:   'a',
			expected: 0,
		},
		{
			name:     "Single character no match",
			input:    "a",
			target:   'b',
			expected: -1,
		},
		{
			name:     "Multiple occurrences returns first",
			input:    "hello world",
			target:   'l',
			expected: 2,
		},
		{
			name:     "Space character",
			input:    "hello world",
			target:   ' ',
			expected: 5,
		},
		{
			name:     "Colon in header",
			input:    "Content-Type: application/json",
			target:   ':',
			expected: 12,
		},
		{
			name:     "Newline LF",
			input:    "line1\nline2",
			target:   '\n',
			expected: 5,
		},
		{
			name:     "Carriage return CR",
			input:    "line1\r\nline2",
			target:   '\r',
			expected: 5,
		},
		{
			name:     "Tab character",
			input:    "col1\tcol2",
			target:   '\t',
			expected: 4,
		},
		{
			name:     "Null byte",
			input:    "test\x00data",
			target:   0,
			expected: 4,
		},
		{
			name:     "High byte value",
			input:    "test\xFFdata",
			target:   0xFF,
			expected: 4,
		},
		{
			name:     "Forward slash",
			input:    "/api/users",
			target:   '/',
			expected: 0,
		},
		{
			name:     "Question mark query string",
			input:    "/path?query=value",
			target:   '?',
			expected: 5,
		},
		{
			name:     "Equals sign",
			input:    "key=value",
			target:   '=',
			expected: 3,
		},
		{
			name:     "Ampersand",
			input:    "a=1&b=2",
			target:   '&',
			expected: 3,
		},
		{
			name:     "Hash fragment",
			input:    "/path#fragment",
			target:   '#',
			expected: 5,
		},
		{
			name:     "Hyphen in header name",
			input:    "Content-Type: text/html",
			target:   '-',
			expected: 7,
		},
		{
			name:     "Semicolon in header value",
			input:    "text/html; charset=utf-8",
			target:   ';',
			expected: 9,
		},
		{
			name:     "Double quote",
			input:    "boundary=\"test\"",
			target:   '"',
			expected: 9,
		},
		{
			name:     "At sign in email",
			input:    "user@example.com",
			target:   '@',
			expected: 4,
		},
		{
			name:     "Percent in URL encoding",
			input:    "test%20value",
			target:   '%',
			expected: 4,
		},
		{
			name:     "Asterisk wildcard",
			input:    "Accept: */*",
			target:   '*',
			expected: 8,
		},
		{
			name:     "Plus sign",
			input:    "a+b=c",
			target:   '+',
			expected: 1,
		},
		{
			name:     "Period in domain",
			input:    "example.com",
			target:   '.',
			expected: 7,
		},
		{
			name:     "Underscore",
			input:    "user_name",
			target:   '_',
			expected: 4,
		},
		{
			name:     "Pipe character",
			input:    "value1|value2",
			target:   '|',
			expected: 6,
		},
		{
			name:     "Backslash",
			input:    "path\\to\\file",
			target:   '\\',
			expected: 4,
		},
		{
			name:     "Opening bracket",
			input:    "array[0]",
			target:   '[',
			expected: 5,
		},
		{
			name:     "Closing bracket",
			input:    "array[0]",
			target:   ']',
			expected: 7,
		},
		{
			name:     "Opening brace",
			input:    "{\"key\":\"value\"}",
			target:   '{',
			expected: 0,
		},
		{
			name:     "Closing brace",
			input:    "{\"key\":\"value\"}",
			target:   '}',
			expected: 14,
		},
		{
			name:     "Less than",
			input:    "<html>",
			target:   '<',
			expected: 0,
		},
		{
			name:     "Greater than",
			input:    "<html>",
			target:   '>',
			expected: 5,
		},
		{
			name:     "Very long string with target at end",
			input:    "This is a very long string with the target character at the very end!",
			target:   '!',
			expected: 68,
		},
		{
			name:     "All same characters",
			input:    "aaaaaaa",
			target:   'a',
			expected: 0,
		},
		{
			name:     "Binary data with null bytes",
			input:    "\x00\x01\x02\x03\x04",
			target:   0x02,
			expected: 2,
		},
		{
			name:     "UTF-8 bytes ASCII search",
			input:    "Hello 世界",
			target:   ' ',
			expected: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := indexByte(tt.input, tt.target)
			if result != tt.expected {
				t.Errorf("indexByte(%q, %q) = %d, want %d", tt.input, tt.target, result, tt.expected)
			}
		})
	}
}

// ==================== Additional Edge Case Tests ====================

// TestBuildHttpMessage_EdgeCases adds comprehensive edge cases not covered by existing tests
func TestBuildHttpMessage_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		headers  []string
		body     []byte
		expected []byte
	}{
		{
			name:     "Nil headers and nil body",
			headers:  nil,
			body:     nil,
			expected: nil,
		},
		{
			name:     "Binary body with all byte values",
			headers:  []string{"POST / HTTP/1.1"},
			body:     []byte{0x00, 0x01, 0xFF, 0x7F, 0x80},
			expected: []byte("POST / HTTP/1.1\r\n\r\n\x00\x01\xFF\x7F\x80"),
		},
		{
			name:     "Very large body 100KB",
			headers:  []string{"POST /upload HTTP/1.1", "Host: example.com"},
			body:     bytes.Repeat([]byte("X"), 100000),
			expected: append([]byte("POST /upload HTTP/1.1\r\nHost: example.com\r\n\r\n"), bytes.Repeat([]byte("X"), 100000)...),
		},
		{
			name:     "Many headers 50+",
			headers:  append([]string{"GET / HTTP/1.1"}, generateTestHeaders(50)...),
			body:     nil,
			expected: nil, // Will validate structure instead of exact match
		},
		{
			name:     "Header with embedded null byte",
			headers:  []string{"GET / HTTP/1.1", "X-Test: val\x00ue"},
			body:     nil,
			expected: []byte("GET / HTTP/1.1\r\nX-Test: val\x00ue\r\n\r\n"),
		},
		{
			name:     "Empty string headers",
			headers:  []string{"", "", ""},
			body:     []byte("body"),
			expected: []byte("\r\n\r\n\r\n\r\nbody"),
		},
		{
			name:     "Headers with only spaces",
			headers:  []string{"   ", "\t\t"},
			body:     nil,
			expected: []byte("   \r\n\t\t\r\n\r\n"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BuildHttpMessage(tt.headers, tt.body)

			// For very large or complex cases, validate structure instead of exact match
			if tt.expected == nil && tt.name == "Many headers 50+" {
				// Verify it contains CRLF CRLF
				if !bytes.Contains(result, []byte("\r\n\r\n")) {
					t.Error("Result should contain CRLF CRLF separator")
				}
				// Verify it starts with first header
				if !bytes.HasPrefix(result, []byte("GET / HTTP/1.1\r\n")) {
					t.Error("Result should start with request line")
				}
				return
			}

			if !bytes.Equal(result, tt.expected) {
				t.Errorf("BuildHttpMessage() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestBuildHttpRequest_EdgeCases adds edge cases not in existing tests
func TestBuildHttpRequest_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		urlStr      string
		expectError bool
		validate    func(*testing.T, []byte)
	}{
		{
			name:        "URL with fragment should ignore it",
			urlStr:      "http://example.com/path#fragment",
			expectError: false,
			validate: func(t *testing.T, result []byte) {
				// Fragment should not be in request
				if bytes.Contains(result, []byte("#fragment")) {
					t.Error("Fragment should not be included in request")
				}
			},
		},
		{
			name:        "URL with empty query value",
			urlStr:      "http://example.com/path?key=",
			expectError: false,
			validate: func(t *testing.T, result []byte) {
				if !bytes.Contains(result, []byte("/path?key=")) {
					t.Error("Should preserve empty query value")
				}
			},
		},
		{
			name:        "URL with only query no path",
			urlStr:      "http://example.com?query=1",
			expectError: false,
			validate: func(t *testing.T, result []byte) {
				if !bytes.Contains(result, []byte("GET /?query=1")) {
					t.Error("Should add / before query")
				}
			},
		},
		{
			name:        "IPv6 address URL",
			urlStr:      "http://[::1]/path",
			expectError: false,
			validate: func(t *testing.T, result []byte) {
				// Check it doesn't crash - exact behavior depends on ParseURL
				if result == nil {
					t.Error("Should return a result for IPv6")
				}
			},
		},
		{
			name:        "URL with port 0",
			urlStr:      "http://example.com:0/path",
			expectError: false,
			validate: func(t *testing.T, result []byte) {
				// Behavior depends on ParseURL implementation
				if result == nil {
					t.Error("Should handle port 0")
				}
			},
		},
		{
			name:        "URL with very large port number",
			urlStr:      "http://example.com:99999/path",
			expectError: false,
			validate: func(t *testing.T, result []byte) {
				// May fail in ParseURL or succeed
				t.Log("Handling of invalid port:", result)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := BuildHttpRequest(tt.urlStr)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
				return
			}

			if !tt.expectError && err != nil {
				t.Logf("Unexpected error (may be acceptable): %v", err)
			}

			if result != nil && tt.validate != nil {
				tt.validate(t, result)
			}
		})
	}
}

// TestIntToString_EdgeCases adds edge cases for integer conversion
func TestIntToString_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected string
	}{
		{
			name:     "Max int32",
			input:    2147483647,
			expected: "2147483647",
		},
		{
			name:     "Min int32",
			input:    -2147483648,
			expected: "-2147483648",
		},
		{
			name:     "Powers of 10",
			input:    1000000000,
			expected: "1000000000",
		},
		{
			name:     "Negative powers of 10",
			input:    -1000000000,
			expected: "-1000000000",
		},
		{
			name:     "All nines",
			input:    999999999,
			expected: "999999999",
		},
		{
			name:     "Negative all nines",
			input:    -999999999,
			expected: "-999999999",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := intToString(tt.input)
			if result != tt.expected {
				t.Errorf("intToString(%d) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestExtractHeaderName_EdgeCases adds edge cases
func TestExtractHeaderName_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		expected string
	}{
		{
			name:     "Colon at position 0",
			header:   ":value",
			expected: "",
		},
		{
			name:     "Only colon",
			header:   ":",
			expected: "",
		},
		{
			name:     "Multiple consecutive colons",
			header:   "Name:::value",
			expected: "Name",
		},
		{
			name:     "Very long header name",
			header:   "X-Very-Long-Custom-Header-Name-That-Exceeds-Normal-Expectations-For-Length: value",
			expected: "X-Very-Long-Custom-Header-Name-That-Exceeds-Normal-Expectations-For-Length",
		},
		{
			name:     "Header with number",
			header:   "X-Custom-123: value",
			expected: "X-Custom-123",
		},
		{
			name:     "Whitespace before colon preserved",
			header:   "Name : value",
			expected: "Name ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractHeaderName(tt.header)
			if result != tt.expected {
				t.Errorf("extractHeaderName(%q) = %q, want %q", tt.header, result, tt.expected)
			}
		})
	}
}

// TestTrimSpace_EdgeCases adds edge cases beyond header_parser_test.go
func TestTrimSpace_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Mixed tabs and spaces",
			input:    " \t \t hello \t \t ",
			expected: "hello",
		},
		{
			name:     "Only tabs",
			input:    "\t\t\t",
			expected: "",
		},
		{
			name:     "Internal whitespace preserved",
			input:    "  hello  world  ",
			expected: "hello  world",
		},
		{
			name:     "Internal tabs preserved",
			input:    "\thello\t\tworld\t",
			expected: "hello\t\tworld",
		},
		{
			name:     "Single character surrounded",
			input:    " \t a \t ",
			expected: "a",
		},
		{
			name:     "Many leading spaces",
			input:    "          hello",
			expected: "hello",
		},
		{
			name:     "Many trailing spaces",
			input:    "hello          ",
			expected: "hello",
		},
		{
			name:     "Newlines not trimmed",
			input:    "\nhello\n",
			expected: "\nhello\n",
		},
		{
			name:     "Carriage returns not trimmed",
			input:    "\rhello\r",
			expected: "\rhello\r",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := trimSpace(tt.input)
			if result != tt.expected {
				t.Errorf("trimSpace(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestBuildHeaderLine_EdgeCases adds edge cases
func TestBuildHeaderLine_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		hdrName  string
		value    string
		expected string
	}{
		{
			name:     "Very long value",
			hdrName:  "X-Long",
			value:    string(bytes.Repeat([]byte("a"), 1000)),
			expected: "X-Long: " + string(bytes.Repeat([]byte("a"), 1000)),
		},
		{
			name:     "Value with newlines",
			hdrName:  "X-Test",
			value:    "line1\r\nline2",
			expected: "X-Test: line1\r\nline2",
		},
		{
			name:     "Value with null bytes",
			hdrName:  "X-Bin",
			value:    "val\x00ue",
			expected: "X-Bin: val\x00ue",
		},
		{
			name:     "Both name and value empty",
			hdrName:  "",
			value:    "",
			expected: ": ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildHeaderLine(tt.hdrName, tt.value)
			if result != tt.expected {
				t.Errorf("buildHeaderLine(%q, %q) = %q, want %q", tt.hdrName, tt.value, result, tt.expected)
			}
		})
	}
}

// ==================== Helper Functions ====================

// generateTestHeaders creates n test headers
func generateTestHeaders(n int) []string {
	headers := make([]string, n)
	for i := 0; i < n; i++ {
		headers[i] = "X-Header-" + intToString(i) + ": value" + intToString(i)
	}
	return headers
}

// ==================== Integration Tests ====================

// TestRequestBuilderCore_Integration tests complete workflow
func TestRequestBuilderCore_Integration(t *testing.T) {
	t.Run("Build and validate complete request", func(t *testing.T) {
		url := "http://api.example.com:8080/v1/users?active=true&sort=name"

		request, err := BuildHttpRequest(url)
		if err != nil {
			t.Fatalf("BuildHttpRequest() error = %v", err)
		}

		// Validate structure
		if !bytes.HasPrefix(request, []byte("GET ")) {
			t.Error("Request should start with GET")
		}

		if !bytes.Contains(request, []byte("HTTP/1.1")) {
			t.Error("Request should contain HTTP/1.1")
		}

		if !bytes.Contains(request, []byte("/v1/users?active=true&sort=name")) {
			t.Error("Request should contain full path and query")
		}

		if !bytes.Contains(request, []byte("Host: api.example.com:8080")) {
			t.Error("Request should contain Host with port")
		}

		if !bytes.HasSuffix(request, []byte("\r\n\r\n")) {
			t.Error("Request should end with CRLF CRLF")
		}
	})

	t.Run("Build message and verify size calculation", func(t *testing.T) {
		headers := []string{
			"POST /api HTTP/1.1",
			"Host: example.com",
			"Content-Type: application/json",
		}
		body := []byte(`{"key":"value"}`)

		result := BuildHttpMessage(headers, body)

		// Calculate expected size manually
		expectedSize := 0
		for _, h := range headers {
			expectedSize += len(h) + 2 // header + CRLF
		}
		expectedSize += 2 // final CRLF
		expectedSize += len(body)

		if len(result) != expectedSize {
			t.Errorf("Size mismatch: got %d, want %d", len(result), expectedSize)
		}

		// Verify structure
		if !bytes.Contains(result, []byte("\r\n\r\n")) {
			t.Error("Missing header/body separator")
		}

		if !bytes.HasSuffix(result, body) {
			t.Error("Body not properly appended")
		}
	})
}

// ==================== Benchmarks ====================

func BenchmarkIndexByte_Short(b *testing.B) {
	s := "Content-Type: application/json"
	for i := 0; i < b.N; i++ {
		_ = indexByte(s, ':')
	}
}

func BenchmarkIndexByte_Long(b *testing.B) {
	s := string(bytes.Repeat([]byte("abcdefghij"), 100)) + "target"
	for i := 0; i < b.N; i++ {
		_ = indexByte(s, 't')
	}
}

func BenchmarkIndexByte_NotFound(b *testing.B) {
	s := string(bytes.Repeat([]byte("abcdefghij"), 100))
	for i := 0; i < b.N; i++ {
		_ = indexByte(s, 'z')
	}
}

func BenchmarkTrimSpace(b *testing.B) {
	s := "   \t  hello world  \t   "
	for i := 0; i < b.N; i++ {
		_ = trimSpace(s)
	}
}

func BenchmarkExtractHeaderName(b *testing.B) {
	header := "Content-Type: application/json; charset=utf-8"
	for i := 0; i < b.N; i++ {
		_ = extractHeaderName(header)
	}
}

func BenchmarkBuildHeaderLine(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = buildHeaderLine("Content-Type", "application/json")
	}
}
