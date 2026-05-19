package httpmsg

import (
	"bytes"
	"testing"
)

// ==================== HELPER FUNCTION TESTS ====================
// Tests for helper functions: findHeaderEndPosition, findBodyOffsetStrict, removeHeaderFromList

// TestFindHeaderEndPosition tests finding header end position
func TestFindHeaderEndPosition(t *testing.T) {
	tests := []struct {
		name        string
		message     []byte
		startOffset int
		expected    int
	}{
		{
			name:        "CRLF CRLF separator",
			message:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\nBODY"),
			startOffset: 0,
			expected:    35, // Position after first CRLF, before second (i+2 where i=33)
		},
		{
			name:        "LF LF separator",
			message:     []byte("GET / HTTP/1.1\nHost: example.com\n\nBODY"),
			startOffset: 0,
			expected:    33, // Position after first LF, before second (i+1 where i=32)
		},
		{
			name:        "No separator",
			message:     []byte("GET / HTTP/1.1\r\nHost: example.com"),
			startOffset: 0,
			expected:    -1,
		},
		{
			name:        "Nil message",
			message:     nil,
			startOffset: 0,
			expected:    -1,
		},
		{
			name:        "Empty message",
			message:     []byte{},
			startOffset: 0,
			expected:    -1,
		},
		{
			name:        "Start offset beyond message",
			message:     []byte("GET / HTTP/1.1\r\n\r\n"),
			startOffset: 100,
			expected:    -1,
		},
		{
			name:        "CRLF CRLF at beginning",
			message:     []byte("\r\n\r\nBODY"),
			startOffset: 0,
			expected:    2,
		},
		{
			name:        "LF LF at end",
			message:     []byte("GET / HTTP/1.1\n\n"),
			startOffset: 0,
			expected:    15,
		},
		{
			name:        "Mixed CRLF and LF",
			message:     []byte("GET / HTTP/1.1\r\nHost: example.com\n\nBODY"),
			startOffset: 0,
			expected:    34, // First LF LF found (i+1 where i=33)
		},
		{
			name:        "Start offset after first CRLF",
			message:     []byte("GET / HTTP/1.1\r\n\r\nBODY"),
			startOffset: 16,
			expected:    -1, // No complete separator after offset
		},
		{
			name:        "Single CRLF only",
			message:     []byte("GET / HTTP/1.1\r\n"),
			startOffset: 0,
			expected:    -1,
		},
		{
			name:        "LF LF in last 3 bytes edge case",
			message:     []byte("GET / HTTP/1.1\nHost: test\n\n"),
			startOffset: 0,
			expected:    26, // i+1 where i=25
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := findHeaderEndPosition(tt.message, tt.startOffset)
			if result != tt.expected {
				t.Errorf("findHeaderEndPosition() = %d, want %d", result, tt.expected)
			}
		})
	}
}

// TestFindBodyOffsetStrict tests strict body offset finding
func TestFindBodyOffsetStrict(t *testing.T) {
	tests := []struct {
		name        string
		message     []byte
		startOffset int
		expected    int
	}{
		{
			name:        "CRLF CRLF separator",
			message:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\nBODY"),
			startOffset: 0,
			expected:    37, // Position after CRLF CRLF (i+4 where i=33)
		},
		{
			name:        "LF LF separator rejected",
			message:     []byte("GET / HTTP/1.1\nHost: example.com\n\nBODY"),
			startOffset: 0,
			expected:    -1, // Strict mode requires CRLF CRLF
		},
		{
			name:        "No separator",
			message:     []byte("GET / HTTP/1.1\r\nHost: example.com"),
			startOffset: 0,
			expected:    -1,
		},
		{
			name:        "Nil message",
			message:     nil,
			startOffset: 0,
			expected:    -1,
		},
		{
			name:        "Empty message",
			message:     []byte{},
			startOffset: 0,
			expected:    -1,
		},
		{
			name:        "CRLF CRLF at beginning",
			message:     []byte("\r\n\r\nBODY"),
			startOffset: 0,
			expected:    4,
		},
		{
			name:        "Start offset in middle",
			message:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\nBODY"),
			startOffset: 16,
			expected:    37, // Still finds separator
		},
		{
			name:        "Message too short",
			message:     []byte("GET"),
			startOffset: 0,
			expected:    -1,
		},
		{
			name:        "Only CRLF CR LF (not CRLF CRLF)",
			message:     []byte("GET / HTTP/1.1\r\n\r \nBODY"),
			startOffset: 0,
			expected:    -1,
		},
		{
			name:        "LF CRLF LF not accepted",
			message:     []byte("GET / HTTP/1.1\n\r\n\nBODY"),
			startOffset: 0,
			expected:    -1,
		},
		{
			name:        "Multiple CRLF CRLF sequences - find first",
			message:     []byte("GET / HTTP/1.1\r\n\r\nBODY\r\n\r\nMORE"),
			startOffset: 0,
			expected:    18, // First CRLF CRLF at positions 14-17, return 18
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := findBodyOffsetStrict(tt.message, tt.startOffset)
			if result != tt.expected {
				t.Errorf("findBodyOffsetStrict() = %d, want %d", result, tt.expected)
			}
		})
	}
}

// TestRemoveHeaderFromList tests removing header from string list
func TestRemoveHeaderFromList(t *testing.T) {
	tests := []struct {
		name     string
		headers  []string
		hdrName  string
		expected []string
	}{
		{
			name:     "Remove existing header",
			headers:  []string{"GET / HTTP/1.1", "Host: example.com", "User-Agent: test"},
			hdrName:  "User-Agent",
			expected: []string{"GET / HTTP/1.1", "Host: example.com"},
		},
		{
			name:     "Remove non-existent header",
			headers:  []string{"GET / HTTP/1.1", "Host: example.com"},
			hdrName:  "User-Agent",
			expected: []string{"GET / HTTP/1.1", "Host: example.com"},
		},
		{
			name:     "Remove case-insensitive",
			headers:  []string{"GET / HTTP/1.1", "Content-Type: text/html"},
			hdrName:  "content-type",
			expected: []string{"GET / HTTP/1.1"},
		},
		{
			name:     "Remove multiple occurrences",
			headers:  []string{"GET / HTTP/1.1", "Cookie: a=1", "Host: example.com", "Cookie: b=2"},
			hdrName:  "Cookie",
			expected: []string{"GET / HTTP/1.1", "Host: example.com"},
		},
		{
			name:     "Empty list",
			headers:  []string{},
			hdrName:  "Host",
			expected: []string{},
		},
		{
			name:     "Nil list",
			headers:  nil,
			hdrName:  "Host",
			expected: []string{},
		},
		{
			name:     "Empty header name",
			headers:  []string{"GET / HTTP/1.1", "Host: example.com"},
			hdrName:  "",
			expected: []string{"GET / HTTP/1.1", "Host: example.com"},
		},
		{
			name:     "Remove all but request line",
			headers:  []string{"GET / HTTP/1.1", "Host: example.com"},
			hdrName:  "Host",
			expected: []string{"GET / HTTP/1.1"},
		},
		{
			name:     "Mixed case headers",
			headers:  []string{"GET / HTTP/1.1", "host: example.com", "HOST: test.com"},
			hdrName:  "Host",
			expected: []string{"GET / HTTP/1.1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := removeHeaderFromList(tt.headers, tt.hdrName)
			if !stringSliceEqual(result, tt.expected) {
				t.Errorf("removeHeaderFromList() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// ==================== EXTENSION API TESTS ====================
// Tests for extension functions: ReplaceHeader, AddOrReplaceHeader, AddHeaderIfNotExists,
// GetHeaderValue, HasHeader, GetAllHeaderValues, GetHeadersByPrefix, GetContentType, SetContentType, GetHost

// TestReplaceHeader tests atomic header replacement
func TestReplaceHeader(t *testing.T) {
	tests := []struct {
		name     string
		message  []byte
		hdrName  string
		hdrValue string
		expected []byte
		wantErr  bool
	}{
		{
			name:     "Replace existing header",
			message:  []byte("GET / HTTP/1.1\r\nHost: old.com\r\n\r\n"),
			hdrName:  "Host",
			hdrValue: "new.com",
			expected: []byte("GET / HTTP/1.1\r\nHost: new.com\r\n\r\n"),
			wantErr:  false,
		},
		{
			name:     "Add non-existent header",
			message:  []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			hdrName:  "User-Agent",
			hdrValue: "TestAgent",
			expected: []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: TestAgent\r\n\r\n"),
			wantErr:  false,
		},
		{
			name:     "Replace case-insensitive",
			message:  []byte("GET / HTTP/1.1\r\nhost: old.com\r\n\r\n"),
			hdrName:  "HOST",
			hdrValue: "new.com",
			expected: []byte("GET / HTTP/1.1\r\nHOST: new.com\r\n\r\n"),
			wantErr:  false,
		},
		{
			name:     "Replace with empty value",
			message:  []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			hdrName:  "Host",
			hdrValue: "",
			expected: []byte("GET / HTTP/1.1\r\nHost: \r\n\r\n"),
			wantErr:  false,
		},
		{
			name:     "Replace duplicate headers",
			message:  []byte("GET / HTTP/1.1\r\nCookie: a=1\r\nCookie: b=2\r\n\r\n"),
			hdrName:  "Cookie",
			hdrValue: "c=3",
			expected: []byte("GET / HTTP/1.1\r\nCookie: c=3\r\n\r\n"),
			wantErr:  false,
		},
		{
			name:     "Replace header with body preserved",
			message:  []byte("POST / HTTP/1.1\r\nHost: old.com\r\n\r\ntest body"),
			hdrName:  "Host",
			hdrValue: "new.com",
			expected: []byte("POST / HTTP/1.1\r\nHost: new.com\r\n\r\ntest body"),
			wantErr:  false,
		},
		{
			name:     "Replace middle header",
			message:  []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: old\r\nAccept: */*\r\n\r\n"),
			hdrName:  "User-Agent",
			hdrValue: "new",
			expected: []byte("GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\nUser-Agent: new\r\n\r\n"),
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ReplaceHeader(tt.message, tt.hdrName, tt.hdrValue)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReplaceHeader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("ReplaceHeader() failed\nExpected: %q\nGot:      %q", tt.expected, result)
			}
		})
	}
}

// TestAddOrReplaceHeader tests conditional header operation
func TestAddOrReplaceHeader(t *testing.T) {
	tests := []struct {
		name     string
		message  []byte
		hdrName  string
		hdrValue string
		expected []byte
		wantErr  bool
	}{
		{
			name:     "Add new header",
			message:  []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			hdrName:  "Authorization",
			hdrValue: "Bearer token",
			expected: []byte("GET / HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer token\r\n\r\n"),
			wantErr:  false,
		},
		{
			name:     "Replace existing header",
			message:  []byte("GET / HTTP/1.1\r\nAuthorization: Bearer old\r\n\r\n"),
			hdrName:  "Authorization",
			hdrValue: "Bearer new",
			expected: []byte("GET / HTTP/1.1\r\nAuthorization: Bearer new\r\n\r\n"),
			wantErr:  false,
		},
		{
			name:     "Add header with special characters",
			message:  []byte("GET / HTTP/1.1\r\n\r\n"),
			hdrName:  "Cookie",
			hdrValue: "session=abc123; path=/; secure",
			expected: []byte("GET / HTTP/1.1\r\nCookie: session=abc123; path=/; secure\r\n\r\n"),
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := AddOrReplaceHeader(tt.message, tt.hdrName, tt.hdrValue)
			if (err != nil) != tt.wantErr {
				t.Errorf("AddOrReplaceHeader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("AddOrReplaceHeader() failed\nExpected: %q\nGot:      %q", tt.expected, result)
			}
		})
	}
}

// TestAddHeaderIfNotExists tests conditional add operation
func TestAddHeaderIfNotExists(t *testing.T) {
	tests := []struct {
		name     string
		message  []byte
		hdrName  string
		hdrValue string
		expected []byte
		wantErr  bool
	}{
		{
			name:     "Add header when not exists",
			message:  []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			hdrName:  "Accept",
			hdrValue: "application/json",
			expected: []byte("GET / HTTP/1.1\r\nHost: example.com\r\nAccept: application/json\r\n\r\n"),
			wantErr:  false,
		},
		{
			name:     "Do not add when exists",
			message:  []byte("GET / HTTP/1.1\r\nHost: example.com\r\nAccept: text/html\r\n\r\n"),
			hdrName:  "Accept",
			hdrValue: "application/json",
			expected: []byte("GET / HTTP/1.1\r\nHost: example.com\r\nAccept: text/html\r\n\r\n"),
			wantErr:  false,
		},
		{
			name:     "Case-insensitive existence check",
			message:  []byte("GET / HTTP/1.1\r\nhost: example.com\r\n\r\n"),
			hdrName:  "HOST",
			hdrValue: "another.com",
			expected: []byte("GET / HTTP/1.1\r\nhost: example.com\r\n\r\n"),
			wantErr:  false,
		},
		{
			name:     "Add when empty value exists",
			message:  []byte("GET / HTTP/1.1\r\nX-Custom:\r\n\r\n"),
			hdrName:  "X-Custom",
			hdrValue: "value",
			expected: []byte("GET / HTTP/1.1\r\nX-Custom:\r\nX-Custom: value\r\n\r\n"),
			wantErr:  false,
		},
		{
			name:     "Multiple headers - keep original",
			message:  []byte("GET / HTTP/1.1\r\nCookie: a=1\r\nCookie: b=2\r\n\r\n"),
			hdrName:  "Cookie",
			hdrValue: "c=3",
			expected: []byte("GET / HTTP/1.1\r\nCookie: a=1\r\nCookie: b=2\r\n\r\n"),
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := AddHeaderIfNotExists(tt.message, tt.hdrName, tt.hdrValue)
			if (err != nil) != tt.wantErr {
				t.Errorf("AddHeaderIfNotExists() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("AddHeaderIfNotExists() failed\nExpected: %q\nGot:      %q", tt.expected, result)
			}
		})
	}
}

// TestGetHeaderValue tests extracting header value from request bytes
func TestGetHeaderValue(t *testing.T) {
	tests := []struct {
		name     string
		message  []byte
		hdrName  string
		expected string
		wantErr  bool
	}{
		{
			name:     "Get existing header",
			message:  []byte("GET / HTTP/1.1\r\nHost: example.com\r\nContent-Type: text/html\r\n\r\n"),
			hdrName:  "Content-Type",
			expected: "text/html",
			wantErr:  false,
		},
		{
			name:     "Get non-existent header",
			message:  []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			hdrName:  "User-Agent",
			expected: "",
			wantErr:  false,
		},
		{
			name:     "Get header case-insensitive",
			message:  []byte("GET / HTTP/1.1\r\nContent-Type: text/html\r\n\r\n"),
			hdrName:  "content-type",
			expected: "text/html",
			wantErr:  false,
		},
		{
			name:     "Get header with spaces",
			message:  []byte("GET / HTTP/1.1\r\nContent-Type:   text/html   \r\n\r\n"),
			hdrName:  "Content-Type",
			expected: "text/html",
			wantErr:  false,
		},
		{
			name:     "Get empty header value",
			message:  []byte("GET / HTTP/1.1\r\nX-Custom:\r\n\r\n"),
			hdrName:  "X-Custom",
			expected: "",
			wantErr:  false,
		},
		{
			name:     "Get first of duplicate headers",
			message:  []byte("GET / HTTP/1.1\r\nCookie: a=1\r\nCookie: b=2\r\n\r\n"),
			hdrName:  "Cookie",
			expected: "a=1",
			wantErr:  false,
		},
		{
			name:     "Get header with complex value",
			message:  []byte("GET / HTTP/1.1\r\nSet-Cookie: session=abc; path=/; secure; HttpOnly\r\n\r\n"),
			hdrName:  "Set-Cookie",
			expected: "session=abc; path=/; secure; HttpOnly",
			wantErr:  false,
		},
		{
			name:     "Get header from request with body",
			message:  []byte("POST / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"test\":1}"),
			hdrName:  "Content-Type",
			expected: "application/json",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := GetHeaderValue(tt.message, tt.hdrName)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetHeaderValue() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if result != tt.expected {
				t.Errorf("GetHeaderValue() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestHasHeader tests header existence check
func TestHasHeader(t *testing.T) {
	tests := []struct {
		name     string
		message  []byte
		hdrName  string
		expected bool
		wantErr  bool
	}{
		{
			name:     "Header exists",
			message:  []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			hdrName:  "Host",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "Header does not exist",
			message:  []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			hdrName:  "User-Agent",
			expected: false,
			wantErr:  false,
		},
		{
			name:     "Case-insensitive check",
			message:  []byte("GET / HTTP/1.1\r\nContent-Type: text/html\r\n\r\n"),
			hdrName:  "content-type",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "Empty header value still exists",
			message:  []byte("GET / HTTP/1.1\r\nX-Custom:\r\n\r\n"),
			hdrName:  "X-Custom",
			expected: false, // TrimSpace makes it empty
			wantErr:  false,
		},
		{
			name:     "Header with whitespace value",
			message:  []byte("GET / HTTP/1.1\r\nX-Custom:   \r\n\r\n"),
			hdrName:  "X-Custom",
			expected: false,
			wantErr:  false,
		},
		{
			name:     "Header with non-empty value",
			message:  []byte("GET / HTTP/1.1\r\nX-Custom: value\r\n\r\n"),
			hdrName:  "X-Custom",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "Check for duplicate header",
			message:  []byte("GET / HTTP/1.1\r\nCookie: a=1\r\nCookie: b=2\r\n\r\n"),
			hdrName:  "Cookie",
			expected: true,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := HasHeader(tt.message, tt.hdrName)
			if (err != nil) != tt.wantErr {
				t.Errorf("HasHeader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if result != tt.expected {
				t.Errorf("HasHeader() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestGetAllHeaderValues tests getting all values for multi-value headers
func TestGetAllHeaderValues(t *testing.T) {
	tests := []struct {
		name     string
		message  []byte
		hdrName  string
		expected []string
		wantErr  bool
	}{
		{
			name:     "Single header value",
			message:  []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			hdrName:  "Host",
			expected: []string{"example.com"},
			wantErr:  false,
		},
		{
			name:     "Multiple header values",
			message:  []byte("GET / HTTP/1.1\r\nCookie: a=1\r\nCookie: b=2\r\nCookie: c=3\r\n\r\n"),
			hdrName:  "Cookie",
			expected: []string{"a=1", "b=2", "c=3"},
			wantErr:  false,
		},
		{
			name:     "No matching header",
			message:  []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			hdrName:  "Cookie",
			expected: []string(nil),
			wantErr:  false,
		},
		{
			name:     "Case-insensitive match",
			message:  []byte("GET / HTTP/1.1\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n"),
			hdrName:  "set-cookie",
			expected: []string{"a=1", "b=2"},
			wantErr:  false,
		},
		{
			name:     "Header with spaces",
			message:  []byte("GET / HTTP/1.1\r\nX-Custom:  value1  \r\nX-Custom:  value2  \r\n\r\n"),
			hdrName:  "X-Custom",
			expected: []string{" value1  ", " value2  "},
			wantErr:  false,
		},
		{
			name:     "Mixed with other headers",
			message:  []byte("GET / HTTP/1.1\r\nHost: example.com\r\nCookie: a=1\r\nUser-Agent: test\r\nCookie: b=2\r\n\r\n"),
			hdrName:  "Cookie",
			expected: []string{"a=1", "b=2"},
			wantErr:  false,
		},
		{
			name:     "Empty values",
			message:  []byte("GET / HTTP/1.1\r\nX-Custom:\r\nX-Custom:\r\n\r\n"),
			hdrName:  "X-Custom",
			expected: []string{"", ""},
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := GetAllHeaderValues(tt.message, tt.hdrName)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAllHeaderValues() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !stringSliceEqual(result, tt.expected) {
				t.Errorf("GetAllHeaderValues() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestGetHeadersByPrefix tests getting headers by prefix
func TestGetHeadersByPrefix(t *testing.T) {
	tests := []struct {
		name     string
		message  []byte
		prefix   string
		expected []string
		wantErr  bool
	}{
		{
			name:     "Get X- headers",
			message:  []byte("GET / HTTP/1.1\r\nHost: example.com\r\nX-Custom: value1\r\nX-Another: value2\r\n\r\n"),
			prefix:   "X-",
			expected: []string{"X-Custom: value1", "X-Another: value2"},
			wantErr:  false,
		},
		{
			name:     "No matching headers",
			message:  []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			prefix:   "X-",
			expected: []string(nil),
			wantErr:  false,
		},
		{
			name:     "Case-insensitive prefix match",
			message:  []byte("GET / HTTP/1.1\r\nContent-Type: text/html\r\nContent-Length: 100\r\n\r\n"),
			prefix:   "content-",
			expected: []string{"Content-Type: text/html", "Content-Length: 100"},
			wantErr:  false,
		},
		{
			name:     "Empty prefix matches all",
			message:  []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n"),
			prefix:   "",
			expected: []string{"Host: example.com", "User-Agent: test"},
			wantErr:  false,
		},
		{
			name:     "Partial name match",
			message:  []byte("GET / HTTP/1.1\r\nAccept: text/html\r\nAccept-Encoding: gzip\r\n\r\n"),
			prefix:   "Accept",
			expected: []string{"Accept: text/html", "Accept-Encoding: gzip"},
			wantErr:  false,
		},
		{
			name:     "Single character prefix",
			message:  []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n"),
			prefix:   "H",
			expected: []string{"Host: example.com"},
			wantErr:  false,
		},
		{
			name:     "Prefix matches request line is skipped",
			message:  []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			prefix:   "GET",
			expected: []string(nil),
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := GetHeadersByPrefix(tt.message, tt.prefix)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetHeadersByPrefix() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !stringSliceEqual(result, tt.expected) {
				t.Errorf("GetHeadersByPrefix() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestGetContentType tests Content-Type convenience getter
func TestGetContentType(t *testing.T) {
	tests := []struct {
		name     string
		message  []byte
		expected string
		wantErr  bool
	}{
		{
			name:     "Get Content-Type",
			message:  []byte("POST / HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n"),
			expected: "application/json",
			wantErr:  false,
		},
		{
			name:     "No Content-Type",
			message:  []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: "",
			wantErr:  false,
		},
		{
			name:     "Content-Type with charset",
			message:  []byte("POST / HTTP/1.1\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"),
			expected: "text/html; charset=utf-8",
			wantErr:  false,
		},
		{
			name:     "Content-Type case-insensitive",
			message:  []byte("POST / HTTP/1.1\r\ncontent-type: application/xml\r\n\r\n"),
			expected: "application/xml",
			wantErr:  false,
		},
		{
			name:     "Content-Type with boundary",
			message:  []byte("POST / HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=----WebKitFormBoundary\r\n\r\n"),
			expected: "multipart/form-data; boundary=----WebKitFormBoundary",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := GetContentType(tt.message)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetContentType() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if result != tt.expected {
				t.Errorf("GetContentType() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestSetContentType tests Content-Type convenience setter
func TestSetContentType(t *testing.T) {
	tests := []struct {
		name        string
		message     []byte
		contentType string
		expected    []byte
		wantErr     bool
	}{
		{
			name:        "Set Content-Type on request without it",
			message:     []byte("POST / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			contentType: "application/json",
			expected:    []byte("POST / HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n"),
			wantErr:     false,
		},
		{
			name:        "Replace existing Content-Type",
			message:     []byte("POST / HTTP/1.1\r\nContent-Type: text/plain\r\n\r\n"),
			contentType: "application/json",
			expected:    []byte("POST / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n"),
			wantErr:     false,
		},
		{
			name:        "Set Content-Type with charset",
			message:     []byte("POST / HTTP/1.1\r\n\r\n"),
			contentType: "text/html; charset=utf-8",
			expected:    []byte("POST / HTTP/1.1\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"),
			wantErr:     false,
		},
		{
			name:        "Replace Content-Type preserving body",
			message:     []byte("POST / HTTP/1.1\r\nContent-Type: text/plain\r\n\r\ntest body"),
			contentType: "application/json",
			expected:    []byte("POST / HTTP/1.1\r\nContent-Type: application/json\r\n\r\ntest body"),
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := SetContentType(tt.message, tt.contentType)
			if (err != nil) != tt.wantErr {
				t.Errorf("SetContentType() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("SetContentType() failed\nExpected: %q\nGot:      %q", tt.expected, result)
			}
		})
	}
}

// TestGetHost tests Host convenience getter
func TestGetHost(t *testing.T) {
	tests := []struct {
		name     string
		message  []byte
		expected string
		wantErr  bool
	}{
		{
			name:     "Get Host header",
			message:  []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: "example.com",
			wantErr:  false,
		},
		{
			name:     "Get Host with port",
			message:  []byte("GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n"),
			expected: "example.com:8080",
			wantErr:  false,
		},
		{
			name:     "No Host header",
			message:  []byte("GET / HTTP/1.1\r\n\r\n"),
			expected: "",
			wantErr:  false,
		},
		{
			name:     "Case-insensitive Host",
			message:  []byte("GET / HTTP/1.1\r\nhost: example.com\r\n\r\n"),
			expected: "example.com",
			wantErr:  false,
		},
		{
			name:     "Host with IPv4",
			message:  []byte("GET / HTTP/1.1\r\nHost: 192.168.1.1\r\n\r\n"),
			expected: "192.168.1.1",
			wantErr:  false,
		},
		{
			name:     "Host with IPv4 and port",
			message:  []byte("GET / HTTP/1.1\r\nHost: 192.168.1.1:8080\r\n\r\n"),
			expected: "192.168.1.1:8080",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := GetHost(tt.message)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetHost() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if result != tt.expected {
				t.Errorf("GetHost() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// ==================== EDGE CASE TESTS ====================

// TestHeaderManipulationEdgeCases tests edge cases across all functions
func TestHeaderManipulationEdgeCases(t *testing.T) {
	t.Run("Malformed headers without colon", func(t *testing.T) {
		message := []byte("GET / HTTP/1.1\r\nMalformedHeader\r\n\r\n")

		// Should not crash
		_, err := GetHeaderValue(message, "MalformedHeader")
		if err != nil {
			t.Errorf("GetHeaderValue() should handle malformed headers gracefully, got error: %v", err)
		}
	})

	t.Run("Very long header value", func(t *testing.T) {
		longValue := string(make([]byte, 10000))
		message := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

		result, err := ReplaceHeader(message, "X-Long", longValue)
		if err != nil {
			t.Errorf("ReplaceHeader() should handle long values, got error: %v", err)
		}

		// Verify it was added
		value, _ := GetHeaderValue(result, "X-Long")
		if len(value) != len(longValue) {
			t.Errorf("Long header value length = %d, want %d", len(value), len(longValue))
		}
	})

	t.Run("Headers with special characters", func(t *testing.T) {
		message := []byte("GET / HTTP/1.1\r\n\r\n")

		// Test various special characters
		specialValues := []string{
			"value\twith\ttabs",
			"value with    spaces",
			"value;with;semicolons",
			"value=with=equals",
			"value\"with\"quotes",
		}

		for _, val := range specialValues {
			result, err := ReplaceHeader(message, "X-Special", val)
			if err != nil {
				t.Errorf("ReplaceHeader() failed with special value %q: %v", val, err)
			}

			got, _ := GetHeaderValue(result, "X-Special")
			if got != val {
				t.Errorf("Special value = %q, want %q", got, val)
			}
		}
	})

	t.Run("Request line not affected by header operations", func(t *testing.T) {
		message := []byte("POST /path?query=value HTTP/1.1\r\nHost: example.com\r\n\r\n")

		result, _ := ReplaceHeader(message, "X-Test", "value")

		// Request line should be unchanged
		headers, _, _, _ := ExtractAllHeaders(result)
		if headers[0] != "POST /path?query=value HTTP/1.1" {
			t.Errorf("Request line changed: %q", headers[0])
		}
	})

	t.Run("Consistent CRLF line endings", func(t *testing.T) {
		// Test with proper CRLF separators
		message := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\nBODY")

		result, _ := RemoveHeader(message, "User-Agent")

		// Should properly remove User-Agent
		value, _ := GetHeaderValue(result, "Host")
		if value != "example.com" {
			t.Errorf("Header removal failed, got Host = %q", value)
		}

		// Verify User-Agent was removed
		userAgent, _ := GetHeaderValue(result, "User-Agent")
		if userAgent != "" {
			t.Errorf("User-Agent should be removed, got %q", userAgent)
		}
	})

	t.Run("Nil message handling across all functions", func(t *testing.T) {
		var nilMsg []byte

		// Test all functions with nil message
		_, err := ReplaceHeader(nilMsg, "Test", "value")
		if err != nil {
			t.Errorf("ReplaceHeader(nil) should not error, got: %v", err)
		}

		_, err = AddOrReplaceHeader(nilMsg, "Test", "value")
		if err != nil {
			t.Errorf("AddOrReplaceHeader(nil) should not error, got: %v", err)
		}

		_, err = AddHeaderIfNotExists(nilMsg, "Test", "value")
		if err != nil {
			t.Errorf("AddHeaderIfNotExists(nil) should not error, got: %v", err)
		}

		_, err = GetHeaderValue(nilMsg, "Test")
		if err != nil {
			t.Errorf("GetHeaderValue(nil) should not error, got: %v", err)
		}

		_, err = HasHeader(nilMsg, "Test")
		if err != nil {
			t.Errorf("HasHeader(nil) should not error, got: %v", err)
		}
	})

	t.Run("Header names with unusual characters", func(t *testing.T) {
		message := []byte("GET / HTTP/1.1\r\n\r\n")

		// Test header names with numbers, dashes, underscores
		unusualNames := []string{
			"X-Test-123",
			"X_Custom_Header",
			"X-Multi-Part-Name-Header",
			"X1",
		}

		for _, name := range unusualNames {
			result, err := ReplaceHeader(message, name, "test")
			if err != nil {
				t.Errorf("ReplaceHeader() failed with header name %q: %v", name, err)
			}

			value, _ := GetHeaderValue(result, name)
			if value != "test" {
				t.Errorf("Header name %q: got value %q, want %q", name, value, "test")
			}
		}
	})
}

// ==================== HELPER FUNCTIONS ====================

// stringSliceEqual compares two string slices for equality
func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ==================== NEW UTILITY FUNCTION TESTS ====================

// TestAppendToHeader tests appending values to existing headers
func TestAppendToHeader(t *testing.T) {
	tests := []struct {
		name        string
		request     []byte
		headerName  string
		appendValue string
		expected    []byte
		wantErr     bool
	}{
		{
			name:        "Append to existing Accept header",
			request:     []byte("GET / HTTP/1.1\r\nAccept: text/plain\r\n\r\n"),
			headerName:  "Accept",
			appendValue: ", text/html",
			expected:    []byte("GET / HTTP/1.1\r\nAccept: text/plain, text/html\r\n\r\n"),
			wantErr:     false,
		},
		{
			name:        "Append to Host header",
			request:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			headerName:  "Host",
			appendValue: ":8080",
			expected:    []byte("GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n"),
			wantErr:     false,
		},
		{
			name:        "Header not found - unchanged",
			request:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			headerName:  "Accept",
			appendValue: ", text/html",
			expected:    []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			wantErr:     false,
		},
		{
			name:        "Case-insensitive header match",
			request:     []byte("GET / HTTP/1.1\r\naccept: text/plain\r\n\r\n"),
			headerName:  "ACCEPT",
			appendValue: ", application/json",
			expected:    []byte("GET / HTTP/1.1\r\naccept: text/plain, application/json\r\n\r\n"),
			wantErr:     false,
		},
		{
			name:        "Nil request",
			request:     nil,
			headerName:  "Accept",
			appendValue: ", text/html",
			expected:    nil,
			wantErr:     false,
		},
		{
			name:        "Empty header name",
			request:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			headerName:  "",
			appendValue: "test",
			expected:    []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			wantErr:     false,
		},
		{
			name:        "Preserve body when appending",
			request:     []byte("POST / HTTP/1.1\r\nHost: example.com\r\n\r\nbody content"),
			headerName:  "Host",
			appendValue: ":443",
			expected:    []byte("POST / HTTP/1.1\r\nHost: example.com:443\r\n\r\nbody content"),
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := AppendToHeader(tt.request, tt.headerName, tt.appendValue)
			if (err != nil) != tt.wantErr {
				t.Errorf("AppendToHeader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("AppendToHeader() failed\nExpected: %q\nGot:      %q", tt.expected, result)
			}
		})
	}
}

// TestGetHeaderOffsets tests getting header line offsets
func TestGetHeaderOffsets(t *testing.T) {
	tests := []struct {
		name       string
		request    []byte
		headerName string
		expected   []int // [lineStart, valueStart, valueEnd] or nil
	}{
		{
			name:       "Get Host header offsets",
			request:    []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			headerName: "Host",
			expected:   []int{16, 22, 33}, // lineStart=16, valueStart=22, valueEnd=33
		},
		{
			name:       "Header not found",
			request:    []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			headerName: "Accept",
			expected:   nil,
		},
		{
			name:       "Case-insensitive match",
			request:    []byte("GET / HTTP/1.1\r\nhost: example.com\r\n\r\n"),
			headerName: "HOST",
			expected:   []int{16, 22, 33},
		},
		{
			name:       "Second header",
			request:    []byte("GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n"),
			headerName: "Accept",
			expected:   []int{35, 43, 46}, // After "Accept: "
		},
		{
			name:       "Nil request",
			request:    nil,
			headerName: "Host",
			expected:   nil,
		},
		{
			name:       "Empty header name",
			request:    []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			headerName: "",
			expected:   nil,
		},
		{
			name:       "Header with no space after colon",
			request:    []byte("GET / HTTP/1.1\r\nHost:example.com\r\n\r\n"),
			headerName: "Host",
			expected:   []int{16, 21, 32}, // valueStart is right after colon
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetHeaderOffsets(tt.request, tt.headerName)
			if tt.expected == nil {
				if result != nil {
					t.Errorf("GetHeaderOffsets() = %v, expected nil", result)
				}
				return
			}
			if result == nil {
				t.Errorf("GetHeaderOffsets() = nil, expected %v", tt.expected)
				return
			}
			if len(result) != 3 {
				t.Errorf("GetHeaderOffsets() returned %d elements, expected 3", len(result))
				return
			}
			for i := 0; i < 3; i++ {
				if result[i] != tt.expected[i] {
					t.Errorf("GetHeaderOffsets()[%d] = %d, expected %d", i, result[i], tt.expected[i])
				}
			}
		})
	}
}
