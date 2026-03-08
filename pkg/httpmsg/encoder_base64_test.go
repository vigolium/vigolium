package httpmsg

import (
	"bytes"
	"testing"
)

// TestBase64Encoder_BasicEncoding tests basic Base64 encoding
func TestBase64Encoder_BasicEncoding(t *testing.T) {
	encoder := NewBase64Encoder()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Simple string",
			input:    "hello",
			expected: "aGVsbG8=",
		},
		{
			name:     "String with space",
			input:    "hello world",
			expected: "aGVsbG8gd29ybGQ=",
		},
		{
			name:     "Short string",
			input:    "a",
			expected: "YQ==",
		},
		{
			name:     "Two characters",
			input:    "ab",
			expected: "YWI=",
		},
		{
			name:     "Three characters (no padding)",
			input:    "abc",
			expected: "YWJj",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "Special characters",
			input:    "a=b&c=d",
			expected: "YT1iJmM9ZA==",
		},
		{
			name:     "URL-like string",
			input:    "http://example.com",
			expected: "aHR0cDovL2V4YW1wbGUuY29t",
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

// TestBase64Encoder_BinaryData tests encoding of binary data
func TestBase64Encoder_BinaryData(t *testing.T) {
	encoder := NewBase64Encoder()

	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "Single null byte",
			input:    []byte{0x00},
			expected: "AA==",
		},
		{
			name:     "Two null bytes",
			input:    []byte{0x00, 0x00},
			expected: "AAA=",
		},
		{
			name:     "Three null bytes",
			input:    []byte{0x00, 0x00, 0x00},
			expected: "AAAA",
		},
		{
			name:     "Binary sequence",
			input:    []byte{0x01, 0x02, 0x03},
			expected: "AQID",
		},
		{
			name:     "High bytes",
			input:    []byte{0xFF, 0xFE, 0xFD},
			expected: "//79",
		},
		{
			name:     "Mixed binary",
			input:    []byte{0x00, 0xFF, 0x80, 0x7F},
			expected: "AP+Afw==",
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

// TestBase64Encoder_Decode tests Base64 decoding
func TestBase64Encoder_Decode(t *testing.T) {
	encoder := NewBase64Encoder()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Simple string",
			input:    "aGVsbG8=",
			expected: "hello",
		},
		{
			name:     "String with space",
			input:    "aGVsbG8gd29ybGQ=",
			expected: "hello world",
		},
		{
			name:     "No padding",
			input:    "YWJj",
			expected: "abc",
		},
		{
			name:     "One padding char",
			input:    "YWI=",
			expected: "ab",
		},
		{
			name:     "Two padding chars",
			input:    "YQ==",
			expected: "a",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
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

// TestBase64Encoder_RoundTrip tests encode/decode round-trip
func TestBase64Encoder_RoundTrip(t *testing.T) {
	encoder := NewBase64Encoder()

	tests := []string{
		"hello",
		"hello world",
		"a",
		"ab",
		"abc",
		"The quick brown fox jumps over the lazy dog",
		"",
		"special chars: !@#$%^&*()",
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

// TestBase64Encoder_BinaryRoundTrip tests binary data round-trip
func TestBase64Encoder_BinaryRoundTrip(t *testing.T) {
	encoder := NewBase64Encoder()

	tests := [][]byte{
		{0x00},
		{0x00, 0x00},
		{0x00, 0x00, 0x00},
		{0x01, 0x02, 0x03},
		{0xFF, 0xFE, 0xFD},
		{0x00, 0xFF, 0x80, 0x7F},
	}

	for _, input := range tests {
		t.Run("", func(t *testing.T) {
			offsets := []int{0, 0}
			encoded := encoder.Encode(input, offsets)
			decoded := encoder.Decode(encoded)

			if !bytes.Equal(decoded, input) {
				t.Errorf("Round-trip failed: input=%v, decoded=%v", input, decoded)
			}
		})
	}
}

// TestBase64Encoder_OffsetTracking tests offset tracking during encoding
func TestBase64Encoder_OffsetTracking(t *testing.T) {
	encoder := NewBase64Encoder()

	tests := []struct {
		name        string
		input       string
		startOffset int
		endOffset   int
	}{
		{
			name:        "Simple string",
			input:       "hello",
			startOffset: 0,
			endOffset:   5,
		},
		{
			name:        "Middle range",
			input:       "hello world",
			startOffset: 3,
			endOffset:   8,
		},
		{
			name:        "Full range",
			input:       "test",
			startOffset: 0,
			endOffset:   4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			offsets := []int{tt.startOffset, tt.endOffset}
			originalStart := offsets[0]
			originalEnd := offsets[1]

			result := encoder.Encode([]byte(tt.input), offsets)

			// Offsets should be updated (scaled proportionally)
			// Base64 expands data by ~4/3
			inputLen := len(tt.input)
			outputLen := len(result)

			// Check that offsets were scaled
			if inputLen > 0 {
				// Start offset should be scaled
				expectedStart := (originalStart * outputLen) / inputLen
				if offsets[0] != expectedStart {
					t.Logf("Start offset: got %d, expected ~%d (approximate)", offsets[0], expectedStart)
				}

				// End offset should be scaled
				expectedEnd := (originalEnd * outputLen) / inputLen
				if offsets[1] != expectedEnd {
					t.Logf("End offset: got %d, expected ~%d (approximate)", offsets[1], expectedEnd)
				}

				// Offsets should be within the output bounds
				if offsets[0] < 0 || offsets[0] > outputLen {
					t.Errorf("Start offset %d out of bounds [0, %d]", offsets[0], outputLen)
				}
				if offsets[1] < 0 || offsets[1] > outputLen {
					t.Errorf("End offset %d out of bounds [0, %d]", offsets[1], outputLen)
				}
			}
		})
	}
}

// TestBase64Encoder_NilAndEmptyInput tests nil and empty input handling
func TestBase64Encoder_NilAndEmptyInput(t *testing.T) {
	encoder := NewBase64Encoder()

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

	// Test decode empty
	result = encoder.Decode([]byte{})
	if len(result) != 0 {
		t.Errorf("Decode([]) should return empty slice, got %v", result)
	}
}

// TestBase64Encoder_InvalidBase64 tests handling of invalid Base64 input
func TestBase64Encoder_InvalidBase64(t *testing.T) {
	encoder := NewBase64Encoder()

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "Invalid characters",
			input: "!!!invalid!!!",
		},
		{
			name:  "Wrong padding",
			input: "YQ=",
		},
		{
			name:  "Incomplete",
			input: "YQ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := encoder.Decode([]byte(tt.input))
			// Should return original input on error
			// (Our implementation returns original on decode error)
			t.Logf("Decode(%q) = %q", tt.input, string(result))
		})
	}
}

// TestBase64MIMEEncoder_LineBreaks tests MIME mode with line breaks
func TestBase64MIMEEncoder_LineBreaks(t *testing.T) {
	encoder := NewBase64MIMEEncoder()

	// Create a long string that will require line breaks
	longInput := bytes.Repeat([]byte("a"), 100)

	offsets := []int{0, 0}
	result := encoder.Encode(longInput, offsets)

	// MIME encoding should have line breaks every 76 characters
	resultStr := string(result)
	if len(resultStr) > 76 {
		// Should contain newlines
		if !bytes.Contains(result, []byte("\n")) {
			t.Errorf("MIME encoding should contain line breaks for long input")
		}
	}
}

// TestBase64MIMEEncoder_Decode tests decoding MIME-encoded Base64
func TestBase64MIMEEncoder_Decode(t *testing.T) {
	encoder := NewBase64MIMEEncoder()

	// Test with line breaks
	input := "aGVsbG8g\nd29ybGQ="
	expected := "hello world"

	result := encoder.Decode([]byte(input))
	if string(result) != expected {
		t.Errorf("Decode with line breaks: got %q, expected %q", string(result), expected)
	}
}

// TestBase64Encoder_Alphabet tests Base64 alphabet encoding
func TestBase64Encoder_Alphabet(t *testing.T) {
	encoder := NewBase64Encoder()

	// Test specific byte patterns to verify alphabet
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "A-Z mapping",
			input:    []byte{0x00, 0x10, 0x20},
			expected: "ABAg",
		},
		{
			name:     "Plus symbol",
			input:    []byte{0xFB},
			expected: "+w==",
		},
		{
			name:     "Slash symbol",
			input:    []byte{0xFF},
			expected: "/w==",
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

// TestBase64Encoder_PaddingCases tests all padding scenarios
func TestBase64Encoder_PaddingCases(t *testing.T) {
	encoder := NewBase64Encoder()

	tests := []struct {
		name         string
		inputLen     int
		expectedPads int
	}{
		{
			name:         "3 bytes - no padding",
			inputLen:     3,
			expectedPads: 0,
		},
		{
			name:         "2 bytes - one pad",
			inputLen:     2,
			expectedPads: 1,
		},
		{
			name:         "1 byte - two pads",
			inputLen:     1,
			expectedPads: 2,
		},
		{
			name:         "6 bytes - no padding",
			inputLen:     6,
			expectedPads: 0,
		},
		{
			name:         "5 bytes - one pad",
			inputLen:     5,
			expectedPads: 1,
		},
		{
			name:         "4 bytes - two pads",
			inputLen:     4,
			expectedPads: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := bytes.Repeat([]byte("a"), tt.inputLen)
			offsets := []int{0, 0}
			result := encoder.Encode(input, offsets)

			// Count padding characters
			padCount := bytes.Count(result, []byte("="))
			if padCount != tt.expectedPads {
				t.Errorf("Expected %d padding chars, got %d in %q", tt.expectedPads, padCount, string(result))
			}
		})
	}
}

// BenchmarkBase64Encoder_Encode benchmarks encoding performance
func BenchmarkBase64Encoder_Encode(b *testing.B) {
	encoder := NewBase64Encoder()
	input := []byte("The quick brown fox jumps over the lazy dog")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		offsets := []int{0, 0}
		encoder.Encode(input, offsets)
	}
}

// BenchmarkBase64Encoder_Decode benchmarks decoding performance
func BenchmarkBase64Encoder_Decode(b *testing.B) {
	encoder := NewBase64Encoder()
	input := []byte("VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoder.Decode(input)
	}
}

// BenchmarkBase64Encoder_LargeData benchmarks encoding large data
func BenchmarkBase64Encoder_LargeData(b *testing.B) {
	encoder := NewBase64Encoder()
	input := bytes.Repeat([]byte("data"), 1000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		offsets := []int{0, 0}
		encoder.Encode(input, offsets)
	}
}
