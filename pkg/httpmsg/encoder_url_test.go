package httpmsg

import (
	"bytes"
	"testing"
)

// TestURLEncoder_BasicEncoding tests basic URL percent-encoding
func TestURLEncoder_BasicEncoding(t *testing.T) {
	encoder := NewURLEncoder()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Space encoding",
			input:    "hello world",
			expected: "hello%20world",
		},
		{
			name:     "Special characters",
			input:    "a=b&c=d",
			expected: "a%3Db%26c%3Dd",
		},
		{
			name:     "URL path",
			input:    "/path/to/file",
			expected: "%2Fpath%2Fto%2Ffile",
		},
		{
			name:     "Query string special chars",
			input:    "key=value&foo=bar",
			expected: "key%3Dvalue%26foo%3Dbar",
		},
		{
			name:     "Quotes and symbols",
			input:    `"hello" <world>`,
			expected: "%22hello%22%20%3Cworld%3E",
		},
		{
			name:     "Hash and percent",
			input:    "foo#bar%baz",
			expected: "foo%23bar%25baz",
		},
		{
			name:     "Colons and semicolons",
			input:    "scheme://host;param",
			expected: "scheme%3A%2F%2Fhost%3Bparam",
		},
		{
			name:     "Backtick and braces",
			input:    "`{foo|bar}`",
			expected: "%60%7Bfoo%7Cbar%7D%60",
		},
		{
			name:     "Unreserved characters (should not encode)",
			input:    "ABCabc123-_.~",
			expected: "ABCabc123-_.~",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			offsets := []int{0, 0}
			result := encoder.Encode([]byte(tt.input), offsets)
			if string(result) != tt.expected {
				t.Errorf("Encode(%q) = %q, expected %q", tt.input, string(result), tt.expected)
			}
		})
	}
}

// TestURLEncoder_NonPrintableCharacters tests encoding of non-printable bytes
func TestURLEncoder_NonPrintableCharacters(t *testing.T) {
	encoder := NewURLEncoder()

	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "Null byte",
			input:    []byte{0x00},
			expected: "%00",
		},
		{
			name:     "Tab character",
			input:    []byte{0x09},
			expected: "%09",
		},
		{
			name:     "Newline character",
			input:    []byte{0x0A},
			expected: "%0A",
		},
		{
			name:     "Carriage return",
			input:    []byte{0x0D},
			expected: "%0D",
		},
		{
			name:     "Control characters",
			input:    []byte{0x01, 0x02, 0x1F},
			expected: "%01%02%1F",
		},
		{
			name:     "High bytes (>= 127)",
			input:    []byte{0x80, 0xFF},
			expected: "%80%FF",
		},
		{
			name:     "Mixed printable and non-printable",
			input:    []byte("hello\x00world\xFF"),
			expected: "hello%00world%FF",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			offsets := []int{0, 0}
			result := encoder.Encode(tt.input, offsets)
			if string(result) != tt.expected {
				t.Errorf("Encode(%v) = %q, expected %q", tt.input, string(result), tt.expected)
			}
		})
	}
}

// TestURLEncoder_OffsetTracking tests that offsets are tracked correctly
func TestURLEncoder_OffsetTracking(t *testing.T) {
	encoder := NewURLEncoder()

	tests := []struct {
		name           string
		input          string
		startOffset    int
		endOffset      int
		expectedStart  int
		expectedEnd    int
		expectedOutput string
	}{
		{
			name:           "Simple expansion",
			input:          "a=b",
			startOffset:    1,
			endOffset:      2,
			expectedStart:  1,
			expectedEnd:    4,
			expectedOutput: "a%3Db",
		},
		{
			name:           "Multiple expansions",
			input:          "a&b&c",
			startOffset:    2,
			endOffset:      4,
			expectedStart:  4,
			expectedEnd:    8, // Position after 'b' at start of '&' → after '%26'
			expectedOutput: "a%26b%26c",
		},
		{
			name:           "No expansion in range",
			input:          "abc=def",
			startOffset:    0,
			endOffset:      3,
			expectedStart:  0,
			expectedEnd:    3,
			expectedOutput: "abc%3Ddef",
		},
		{
			name:           "Offset at boundary",
			input:          "foo bar",
			startOffset:    4,
			endOffset:      7,
			expectedStart:  6, // Position where 'b' starts after encoding space
			expectedEnd:    9, // Position after 'r' (end of string)
			expectedOutput: "foo%20bar",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			offsets := []int{tt.startOffset, tt.endOffset}
			result := encoder.Encode([]byte(tt.input), offsets)

			if string(result) != tt.expectedOutput {
				t.Errorf("Encode(%q) = %q, expected %q", tt.input, string(result), tt.expectedOutput)
			}

			if offsets[0] != tt.expectedStart {
				t.Errorf("Start offset = %d, expected %d", offsets[0], tt.expectedStart)
			}

			if offsets[1] != tt.expectedEnd {
				t.Errorf("End offset = %d, expected %d", offsets[1], tt.expectedEnd)
			}
		})
	}
}

// TestURLEncoder_CustomAllowedChars tests custom allowed character set
func TestURLEncoder_CustomAllowedChars(t *testing.T) {
	encoder := NewURLEncoder()

	// Allow forward slash to pass through
	encoder.AddAllowedChar('/')

	input := "/path/to/file"
	offsets := []int{0, 0}
	result := encoder.Encode([]byte(input), offsets)
	expected := "/path/to/file"

	if string(result) != expected {
		t.Errorf("With '/' allowed: got %q, expected %q", string(result), expected)
	}

	// Remove forward slash from allowed set
	encoder.RemoveAllowedChar('/')

	offsets = []int{0, 0}
	result = encoder.Encode([]byte(input), offsets)
	expected = "%2Fpath%2Fto%2Ffile"

	if string(result) != expected {
		t.Errorf("With '/' removed: got %q, expected %q", string(result), expected)
	}
}

// TestURLEncoder_AllowedCharsVariations tests various allowed char scenarios
func TestURLEncoder_AllowedCharsVariations(t *testing.T) {
	tests := []struct {
		name         string
		allowedChars []byte
		input        string
		expected     string
	}{
		{
			name:         "Allow equals sign",
			allowedChars: []byte{'='},
			input:        "a=b&c=d",
			expected:     "a=b%26c=d",
		},
		{
			name:         "Allow ampersand",
			allowedChars: []byte{'&'},
			input:        "a=b&c=d",
			expected:     "a%3Db&c%3Dd",
		},
		{
			name:         "Allow multiple special chars",
			allowedChars: []byte{'/', ':', '?', '&', '='},
			input:        "http://host?a=b&c=d",
			expected:     "http://host?a=b&c=d",
		},
		{
			name:         "Allow space",
			allowedChars: []byte{' '},
			input:        "hello world",
			expected:     "hello world",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoder := NewURLEncoder()

			// Add allowed characters
			for _, c := range tt.allowedChars {
				encoder.AddAllowedChar(c)
			}

			offsets := []int{0, 0}
			result := encoder.Encode([]byte(tt.input), offsets)

			if string(result) != tt.expected {
				t.Errorf("got %q, expected %q", string(result), tt.expected)
			}
		})
	}
}

// TestURLEncoder_Decode tests URL decoding
func TestURLEncoder_Decode(t *testing.T) {
	encoder := NewURLEncoder()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Percent-encoded space",
			input:    "hello%20world",
			expected: "hello world",
		},
		{
			name:     "Plus-encoded space (from existing UrlDecode)",
			input:    "hello+world",
			expected: "hello world",
		},
		{
			name:     "Special characters",
			input:    "a%3Db%26c%3Dd",
			expected: "a=b&c=d",
		},
		{
			name:     "URL path",
			input:    "%2Fpath%2Fto%2Ffile",
			expected: "/path/to/file",
		},
		{
			name:     "Mixed encoding",
			input:    "foo%3Dbar%26baz%3Dqux",
			expected: "foo=bar&baz=qux",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := encoder.Decode([]byte(tt.input))
			if string(result) != tt.expected {
				t.Errorf("Decode(%q) = %q, expected %q", tt.input, string(result), tt.expected)
			}
		})
	}
}

// TestURLEncoder_RoundTrip tests encode/decode round-trip
func TestURLEncoder_RoundTrip(t *testing.T) {
	encoder := NewURLEncoder()

	tests := []string{
		"hello world",
		"a=b&c=d",
		"/path/to/file",
		"special!@#$%^&*()",
		"unicode-safe-ascii",
		"",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			offsets := []int{0, 0}
			encoded := encoder.Encode([]byte(input), offsets)
			decoded := encoder.Decode(encoded)

			if string(decoded) != input {
				t.Errorf("Round-trip failed: input=%q, decoded=%q", input, string(decoded))
			}
		})
	}
}

// TestURLEncoder_NilAndEmptyInput tests nil and empty input handling
func TestURLEncoder_NilAndEmptyInput(t *testing.T) {
	encoder := NewURLEncoder()

	// Test nil input
	offsets := []int{0, 0}
	result := encoder.Encode(nil, offsets)
	if result != nil {
		t.Errorf("Encode(nil) should return nil, got %v", result)
	}

	// Test empty input
	offsets = []int{0, 0}
	result = encoder.Encode([]byte{}, offsets)
	if len(result) != 0 {
		t.Errorf("Encode([]) should return empty slice, got %v", result)
	}

	// Test decode nil
	result = encoder.Decode(nil)
	if result != nil {
		t.Errorf("Decode(nil) should return nil, got %v", result)
	}
}

// TestURLEncoder_ReservedVsUnreserved tests RFC 3986 character classes
func TestURLEncoder_ReservedVsUnreserved(t *testing.T) {
	encoder := NewURLEncoder()

	// Unreserved characters (RFC 3986 section 2.3)
	// ALPHA / DIGIT / "-" / "." / "_" / "~"
	unreserved := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	offsets := []int{0, 0}
	result := encoder.Encode([]byte(unreserved), offsets)

	if string(result) != unreserved {
		t.Errorf("Unreserved characters should not be encoded: got %q", string(result))
	}

	// Reserved characters that should be encoded
	reserved := " \"#%&+,/:;<=>\\"
	offsets = []int{0, 0}
	result = encoder.Encode([]byte(reserved), offsets)

	// All should be percent-encoded
	if !bytes.Contains(result, []byte("%")) {
		t.Errorf("Reserved characters should be percent-encoded: got %q", string(result))
	}
}

// TestURLEncoder_SpecialCharacterCoverage tests all special chars from switch statement
func TestURLEncoder_SpecialCharacterCoverage(t *testing.T) {
	encoder := NewURLEncoder()

	// Characters from the switch statement in encoder_url.go
	specialChars := []struct {
		char     byte
		expected string
	}{
		{' ', "%20"},
		{'"', "%22"},
		{'#', "%23"},
		{'%', "%25"},
		{'&', "%26"},
		{'+', "%2B"},
		{',', "%2C"},
		{'/', "%2F"},
		{':', "%3A"},
		{';', "%3B"},
		{'<', "%3C"},
		{'=', "%3D"},
		{'>', "%3E"},
		{'?', "%3F"},
		{'\\', "%5C"},
		{'^', "%5E"},
		{'`', "%60"},
		{'{', "%7B"},
		{'|', "%7C"},
		{'}', "%7D"},
	}

	for _, tc := range specialChars {
		t.Run(string(tc.char), func(t *testing.T) {
			offsets := []int{0, 0}
			result := encoder.Encode([]byte{tc.char}, offsets)
			if string(result) != tc.expected {
				t.Errorf("Encode(%q) = %q, expected %q", tc.char, string(result), tc.expected)
			}
		})
	}
}

// BenchmarkURLEncoder_Encode benchmarks encoding performance
func BenchmarkURLEncoder_Encode(b *testing.B) {
	encoder := NewURLEncoder()
	input := []byte("hello world! this is a test string with special chars: &=?#")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		offsets := []int{0, 0}
		encoder.Encode(input, offsets)
	}
}

// BenchmarkURLEncoder_Decode benchmarks decoding performance
func BenchmarkURLEncoder_Decode(b *testing.B) {
	encoder := NewURLEncoder()
	input := []byte("hello%20world%21%20this%20is%20a%20test%20string%20with%20special%20chars%3A%20%26%3D%3F%23")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoder.Decode(input)
	}
}
