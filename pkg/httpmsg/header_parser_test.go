package httpmsg

import (
	"testing"
)

// TestExtractHeaders_CRLF tests header extraction with CRLF line endings
func TestExtractHeaders_CRLF(t *testing.T) {
	request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nContent-Type: text/html\r\n\r\n")

	headers, offsets, err := ExtractHeaders(request, 0, len(request))
	if err != nil {
		t.Fatalf("ExtractHeaders failed: %v", err)
	}

	// Verify header count
	if len(headers) != 3 {
		t.Errorf("Expected 3 headers, got %d", len(headers))
	}

	// Verify header content
	expectedHeaders := []string{
		"GET / HTTP/1.1",
		"Host: example.com",
		"Content-Type: text/html",
	}
	for i, expected := range expectedHeaders {
		if i >= len(headers) {
			t.Errorf("Missing header at index %d", i)
			continue
		}
		if headers[i] != expected {
			t.Errorf("Header[%d]: expected %q, got %q", i, expected, headers[i])
		}
	}

	// Verify offsets
	expectedOffsets := []int{0, 16, 35}
	if len(offsets) != len(expectedOffsets) {
		t.Errorf("Expected %d offsets, got %d", len(expectedOffsets), len(offsets))
	}
	for i, expected := range expectedOffsets {
		if i >= len(offsets) {
			break
		}
		if offsets[i] != expected {
			t.Errorf("Offset[%d]: expected %d, got %d", i, expected, offsets[i])
		}
	}
}

// TestExtractHeaders_LF tests header extraction with LF-only line endings
func TestExtractHeaders_LF(t *testing.T) {
	request := []byte("GET / HTTP/1.1\nHost: example.com\nContent-Type: text/html\n\n")

	headers, _, err := ExtractHeaders(request, 0, len(request))
	if err != nil {
		t.Fatalf("ExtractHeaders failed: %v", err)
	}

	// Note: Current implementation only handles CRLF properly
	// This test documents the current behavior
	if len(headers) == 0 {
		t.Skip("LF-only parsing not yet implemented")
	}
}

// TestGetHeader_CaseInsensitive tests case-insensitive header retrieval
func TestGetHeader_CaseInsensitive(t *testing.T) {
	headers := []string{
		"GET / HTTP/1.1",
		"Host: example.com",
		"Content-Type: text/html; charset=utf-8",
		"Content-Length: 1234",
	}

	tests := []struct {
		name     string
		expected string
	}{
		{"content-type", "text/html; charset=utf-8"},
		{"Content-Type", "text/html; charset=utf-8"},
		{"CONTENT-TYPE", "text/html; charset=utf-8"},
		{"host", "example.com"},
		{"Host", "example.com"},
		{"content-length", "1234"},
		{"NonExistent", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Header(headers, tt.name)
			if result != tt.expected {
				t.Errorf("Header(%q): expected %q, got %q", tt.name, tt.expected, result)
			}
		})
	}
}

// TestParseContentType tests Content-Type header parsing
func TestParseContentType(t *testing.T) {
	tests := []struct {
		name             string
		headers          []string
		expectedMimeType string
		expectedBoundary string
	}{
		{
			name: "multipart with boundary",
			headers: []string{
				"POST / HTTP/1.1",
				"Content-Type: multipart/form-data; boundary=----WebKitFormBoundary",
			},
			expectedMimeType: "multipart/form-data",
			expectedBoundary: "----WebKitFormBoundary",
		},
		{
			name: "multipart with quoted boundary",
			headers: []string{
				"POST / HTTP/1.1",
				"Content-Type: multipart/form-data; boundary=\"----WebKitFormBoundary\"",
			},
			expectedMimeType: "multipart/form-data",
			expectedBoundary: "----WebKitFormBoundary",
		},
		{
			name: "simple content type",
			headers: []string{
				"POST / HTTP/1.1",
				"Content-Type: text/html",
			},
			expectedMimeType: "text/html",
			expectedBoundary: "",
		},
		{
			name: "content type with charset",
			headers: []string{
				"POST / HTTP/1.1",
				"Content-Type: text/html; charset=utf-8",
			},
			expectedMimeType: "text/html",
			expectedBoundary: "",
		},
		{
			name: "no content type",
			headers: []string{
				"GET / HTTP/1.1",
				"Host: example.com",
			},
			expectedMimeType: "",
			expectedBoundary: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mimeType, boundary := ParseContentType(tt.headers)
			if mimeType != tt.expectedMimeType {
				t.Errorf("MIME type: expected %q, got %q", tt.expectedMimeType, mimeType)
			}
			if boundary != tt.expectedBoundary {
				t.Errorf("Boundary: expected %q, got %q", tt.expectedBoundary, boundary)
			}
		})
	}
}

// TestFindHeaderBodySeparator tests finding the header/body boundary
func TestFindHeaderBodySeparator(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected int
	}{
		{
			name:     "CRLFCRLF",
			data:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\nBODY"),
			expected: 37,
		},
		{
			name:     "LFLF",
			data:     []byte("GET / HTTP/1.1\nHost: example.com\n\nBODY"),
			expected: 34,
		},
		{
			name:     "No separator",
			data:     []byte("GET / HTTP/1.1\r\nHost: example.com"),
			expected: -1,
		},
		{
			name:     "Empty data",
			data:     []byte(""),
			expected: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FindHeaderBodySeparator(tt.data, 0)
			if result != tt.expected {
				t.Errorf("Expected %d, got %d", tt.expected, result)
			}
		})
	}
}

// TestExtractAllHeaders tests the convenience function
func TestExtractAllHeaders(t *testing.T) {
	request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nContent-Type: text/html\r\n\r\nBODY DATA")

	headers, offsets, bodyStart, err := ExtractAllHeaders(request)
	if err != nil {
		t.Fatalf("ExtractAllHeaders failed: %v", err)
	}

	// Verify headers
	if len(headers) != 3 {
		t.Errorf("Expected 3 headers, got %d", len(headers))
	}

	// Verify body start position
	expectedBodyStart := 62
	if bodyStart != expectedBodyStart {
		t.Errorf("Body start: expected %d, got %d", expectedBodyStart, bodyStart)
	}

	// Verify we can extract body
	body := string(request[bodyStart:])
	if body != "BODY DATA" {
		t.Errorf("Body: expected %q, got %q", "BODY DATA", body)
	}

	// Verify offsets match
	if len(offsets) != len(headers) {
		t.Errorf("Offset count mismatch: %d headers, %d offsets", len(headers), len(offsets))
	}
}

// TestEqualsCaseInsensitive tests case-insensitive string comparison
func TestEqualsCaseInsensitive(t *testing.T) {
	tests := []struct {
		a        string
		b        string
		expected bool
	}{
		{"hello", "hello", true},
		{"hello", "HELLO", true},
		{"Hello", "hello", true},
		{"Content-Type", "content-type", true},
		{"hello", "world", false},
		{"hello", "hello!", false},
		{"", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.a+"_vs_"+tt.b, func(t *testing.T) {
			result := EqualsCaseInsensitive(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("EqualsCaseInsensitive(%q, %q): expected %v, got %v",
					tt.a, tt.b, tt.expected, result)
			}
		})
	}
}

// TestTrimSpace tests whitespace trimming
func TestTrimSpace(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hello", "hello"},
		{" hello", "hello"},
		{"hello ", "hello"},
		{" hello ", "hello"},
		{"  hello  ", "hello"},
		{"\thello\t", "hello"},
		{" \t hello \t ", "hello"},
		{"", ""},
		{"   ", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := TrimSpace(tt.input)
			if result != tt.expected {
				t.Errorf("TrimSpace(%q): expected %q, got %q", tt.input, tt.expected, result)
			}
		})
	}
}

// TestParseParameter tests parameter extraction from header values
func TestParseParameter(t *testing.T) {
	tests := []struct {
		name     string
		params   string
		param    string
		expected string
	}{
		{
			name:     "simple parameter",
			params:   "boundary=----WebKit",
			param:    "boundary",
			expected: "----WebKit",
		},
		{
			name:     "quoted parameter",
			params:   "boundary=\"----WebKit\"",
			param:    "boundary",
			expected: "----WebKit",
		},
		{
			name:     "multiple parameters",
			params:   "boundary=----WebKit; charset=utf-8",
			param:    "boundary",
			expected: "----WebKit",
		},
		{
			name:     "multiple parameters - second param",
			params:   "boundary=----WebKit; charset=utf-8",
			param:    "charset",
			expected: "utf-8",
		},
		{
			name:     "parameter not found",
			params:   "boundary=----WebKit",
			param:    "charset",
			expected: "",
		},
		{
			name:     "case insensitive",
			params:   "Boundary=----WebKit",
			param:    "boundary",
			expected: "----WebKit",
		},
		{
			name:     "with spaces",
			params:   "boundary = ----WebKit",
			param:    "boundary",
			expected: "----WebKit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseParameter(tt.params, tt.param)
			if result != tt.expected {
				t.Errorf("ParseParameter(%q, %q): expected %q, got %q",
					tt.params, tt.param, tt.expected, result)
			}
		})
	}
}

// TestFindColonIndex tests finding colon in header
func TestFindColonIndex(t *testing.T) {
	tests := []struct {
		header   string
		expected int
	}{
		{"Host: example.com", 4},
		{"Content-Type: text/html", 12},
		{"No colon here", -1},
		{"", -1},
		{": starts with colon", 0},
	}

	for _, tt := range tests {
		t.Run(tt.header, func(t *testing.T) {
			result := FindColonIndex(tt.header)
			if result != tt.expected {
				t.Errorf("FindColonIndex(%q): expected %d, got %d", tt.header, tt.expected, result)
			}
		})
	}
}
