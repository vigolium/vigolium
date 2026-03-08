package httpmsg

import (
	"bytes"
	"testing"
)

// TestCloneRequest tests the CloneRequest function
func TestCloneRequest(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{
			name:     "nil input",
			input:    nil,
			expected: nil,
		},
		{
			name:     "empty slice",
			input:    []byte{},
			expected: []byte{},
		},
		{
			name:     "simple request",
			input:    []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		},
		{
			name:     "request with body",
			input:    []byte("POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\ntest"),
			expected: []byte("POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\ntest"),
		},
		{
			name:     "request with binary data",
			input:    []byte{0x00, 0xFF, 0x0D, 0x0A, 0xDE, 0xAD, 0xBE, 0xEF},
			expected: []byte{0x00, 0xFF, 0x0D, 0x0A, 0xDE, 0xAD, 0xBE, 0xEF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CloneRequest(tt.input)

			// Check if result matches expected
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("CloneRequest() = %v, want %v", result, tt.expected)
			}

			// Check that nil input returns nil (not empty slice)
			if tt.input == nil && result != nil {
				t.Errorf("CloneRequest(nil) should return nil, got %v", result)
			}

			// Check deep copy: modifying result shouldn't affect input
			if len(tt.input) > 0 {
				original := make([]byte, len(tt.input))
				copy(original, tt.input)

				result[0] = 0xFF // Modify clone

				if !bytes.Equal(tt.input, original) {
					t.Errorf("Modifying clone affected original: got %v, want %v", tt.input, original)
				}
			}
		})
	}
}

// TestCloneRequestDeepCopy specifically tests that modifications don't affect original
func TestCloneRequestDeepCopy(t *testing.T) {
	original := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	clone := CloneRequest(original)

	// Modify clone
	clone[0] = 'P'
	clone[1] = 'O'
	clone[2] = 'S'
	clone[3] = 'T'

	// Verify original unchanged
	if original[0] != 'G' || original[1] != 'E' || original[2] != 'T' {
		t.Errorf("Original was modified: %s", original)
	}

	// Verify clone was modified
	if clone[0] != 'P' || clone[1] != 'O' || clone[2] != 'S' || clone[3] != 'T' {
		t.Errorf("Clone was not modified: %s", clone)
	}
}

// TestNormalizeLineEndings tests the NormalizeLineEndings function
func TestNormalizeLineEndings(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{
			name:     "nil input",
			input:    nil,
			expected: nil,
		},
		{
			name:     "empty slice",
			input:    []byte{},
			expected: []byte{},
		},
		{
			name:     "already CRLF",
			input:    []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		},
		{
			name:     "LF only",
			input:    []byte("GET / HTTP/1.1\nHost: example.com\n\n"),
			expected: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		},
		{
			name:     "CR only",
			input:    []byte("GET / HTTP/1.1\rHost: example.com\r\r"),
			expected: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		},
		{
			name:     "mixed line endings - CRLF and LF",
			input:    []byte("GET / HTTP/1.1\r\nHost: example.com\nUser-Agent: test\r\n\r\n"),
			expected: []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n"),
		},
		{
			name:     "mixed line endings - CRLF and CR",
			input:    []byte("GET / HTTP/1.1\r\nHost: example.com\rUser-Agent: test\r\n\r\n"),
			expected: []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n"),
		},
		{
			name:     "mixed line endings - all types",
			input:    []byte("GET / HTTP/1.1\r\nHost: example.com\nContent-Type: text/plain\rContent-Length: 4\r\n\r\ntest"),
			expected: []byte("GET / HTTP/1.1\r\nHost: example.com\r\nContent-Type: text/plain\r\nContent-Length: 4\r\n\r\ntest"),
		},
		{
			name:     "LF at start",
			input:    []byte("\nGET / HTTP/1.1\r\n"),
			expected: []byte("\r\nGET / HTTP/1.1\r\n"),
		},
		{
			name:     "CR at start",
			input:    []byte("\rGET / HTTP/1.1\r\n"),
			expected: []byte("\r\nGET / HTTP/1.1\r\n"),
		},
		{
			name:     "LF at end",
			input:    []byte("GET / HTTP/1.1\r\nHost: example.com\n"),
			expected: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n"),
		},
		{
			name:     "CR at end",
			input:    []byte("GET / HTTP/1.1\r\nHost: example.com\r"),
			expected: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n"),
		},
		{
			name:     "consecutive LF",
			input:    []byte("GET / HTTP/1.1\n\nHost: example.com\n"),
			expected: []byte("GET / HTTP/1.1\r\n\r\nHost: example.com\r\n"),
		},
		{
			name:     "consecutive CR",
			input:    []byte("GET / HTTP/1.1\r\rHost: example.com\r"),
			expected: []byte("GET / HTTP/1.1\r\n\r\nHost: example.com\r\n"),
		},
		{
			name:     "no line endings",
			input:    []byte("GET / HTTP/1.1"),
			expected: []byte("GET / HTTP/1.1"),
		},
		{
			name:     "body with LF",
			input:    []byte("POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nline1\nline2"),
			expected: []byte("POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nline1\r\nline2"),
		},
		{
			name:     "only CRLF",
			input:    []byte("\r\n"),
			expected: []byte("\r\n"),
		},
		{
			name:     "only LF",
			input:    []byte("\n"),
			expected: []byte("\r\n"),
		},
		{
			name:     "only CR",
			input:    []byte("\r"),
			expected: []byte("\r\n"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeLineEndings(tt.input)

			if !bytes.Equal(result, tt.expected) {
				t.Errorf("NormalizeLineEndings() = %q, want %q", result, tt.expected)
			}

			// Check that nil input returns nil (not empty slice)
			if tt.input == nil && result != nil {
				t.Errorf("NormalizeLineEndings(nil) should return nil, got %v", result)
			}
		})
	}
}

// TestStripTrailingData tests the StripTrailingData function
func TestStripTrailingData(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{
			name:     "nil input",
			input:    nil,
			expected: nil,
		},
		{
			name:     "empty slice",
			input:    []byte{},
			expected: []byte{},
		},
		{
			name:     "simple request",
			input:    []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		},
		{
			name:     "request with body",
			input:    []byte("POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\ntest"),
			expected: []byte("POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\ntest"),
		},
		{
			name:     "request with trailing data",
			input:    []byte("POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\ntestGARBAGE"),
			expected: []byte("POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\ntestGARBAGE"),
		},
		{
			name:     "request with binary trailing data",
			input:    []byte("GET / HTTP/1.1\r\n\r\n\x00\xFF\xDE\xAD"),
			expected: []byte("GET / HTTP/1.1\r\n\r\n\x00\xFF\xDE\xAD"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := StripTrailingData(tt.input)

			if !bytes.Equal(result, tt.expected) {
				t.Errorf("StripTrailingData() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestRequestsEqual tests the RequestsEqual function
func TestRequestsEqual(t *testing.T) {
	tests := []struct {
		name     string
		req1     []byte
		req2     []byte
		expected bool
	}{
		{
			name:     "both nil",
			req1:     nil,
			req2:     nil,
			expected: true,
		},
		{
			name:     "both empty",
			req1:     []byte{},
			req2:     []byte{},
			expected: true,
		},
		{
			name:     "nil vs empty",
			req1:     nil,
			req2:     []byte{},
			expected: true, // Both have length 0, so they're equal
		},
		{
			name:     "identical requests",
			req1:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			req2:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: true,
		},
		{
			name:     "different methods",
			req1:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			req2:     []byte("POST / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: false,
		},
		{
			name:     "different lengths",
			req1:     []byte("GET / HTTP/1.1\r\n"),
			req2:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: false,
		},
		{
			name:     "different line endings - CRLF vs LF",
			req1:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			req2:     []byte("GET / HTTP/1.1\nHost: example.com\n\n"),
			expected: false,
		},
		{
			name:     "different case",
			req1:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			req2:     []byte("get / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: false,
		},
		{
			name:     "different at end",
			req1:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			req2:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\nX"),
			expected: false,
		},
		{
			name:     "different in middle",
			req1:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			req2:     []byte("GET / HTTP/1.1\r\nHost: example.org\r\n\r\n"),
			expected: false,
		},
		{
			name:     "binary data equal",
			req1:     []byte{0x00, 0xFF, 0xDE, 0xAD, 0xBE, 0xEF},
			req2:     []byte{0x00, 0xFF, 0xDE, 0xAD, 0xBE, 0xEF},
			expected: true,
		},
		{
			name:     "binary data different",
			req1:     []byte{0x00, 0xFF, 0xDE, 0xAD, 0xBE, 0xEF},
			req2:     []byte{0x00, 0xFF, 0xDE, 0xAD, 0xBE, 0xEE},
			expected: false,
		},
		{
			name:     "first longer",
			req1:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\nBODY"),
			req2:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: false,
		},
		{
			name:     "second longer",
			req1:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			req2:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\nBODY"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RequestsEqual(tt.req1, tt.req2)

			if result != tt.expected {
				t.Errorf("RequestsEqual() = %v, want %v", result, tt.expected)
			}

			// Test symmetry: RequestsEqual(a, b) == RequestsEqual(b, a)
			resultReverse := RequestsEqual(tt.req2, tt.req1)
			if result != resultReverse {
				t.Errorf("RequestsEqual() not symmetric: RequestsEqual(req1, req2)=%v, RequestsEqual(req2, req1)=%v",
					result, resultReverse)
			}
		})
	}
}

// TestRequestsEqualNormalized tests the RequestsEqualNormalized function
func TestRequestsEqualNormalized(t *testing.T) {
	tests := []struct {
		name     string
		req1     []byte
		req2     []byte
		expected bool
	}{
		{
			name:     "both nil",
			req1:     nil,
			req2:     nil,
			expected: true,
		},
		{
			name:     "both empty",
			req1:     []byte{},
			req2:     []byte{},
			expected: true,
		},
		{
			name:     "nil vs empty",
			req1:     nil,
			req2:     []byte{},
			expected: true, // Both have length 0, so they're equal
		},
		{
			name:     "identical requests",
			req1:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			req2:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: true,
		},
		{
			name:     "CRLF vs LF - functionally equal",
			req1:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			req2:     []byte("GET / HTTP/1.1\nHost: example.com\n\n"),
			expected: true,
		},
		{
			name:     "CRLF vs CR - functionally equal",
			req1:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			req2:     []byte("GET / HTTP/1.1\rHost: example.com\r\r"),
			expected: true,
		},
		{
			name:     "LF vs CR - functionally equal",
			req1:     []byte("GET / HTTP/1.1\nHost: example.com\n\n"),
			req2:     []byte("GET / HTTP/1.1\rHost: example.com\r\r"),
			expected: true,
		},
		{
			name:     "mixed line endings - all functionally equal",
			req1:     []byte("GET / HTTP/1.1\r\nHost: example.com\nUser-Agent: test\r\n\r\n"),
			req2:     []byte("GET / HTTP/1.1\nHost: example.com\rUser-Agent: test\r\r"),
			expected: true,
		},
		{
			name:     "different content - different methods",
			req1:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			req2:     []byte("POST / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: false,
		},
		{
			name:     "different content with same line endings",
			req1:     []byte("GET / HTTP/1.1\nHost: example.com\n\n"),
			req2:     []byte("POST / HTTP/1.1\nHost: example.com\n\n"),
			expected: false,
		},
		{
			name:     "different content with different line endings",
			req1:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			req2:     []byte("POST / HTTP/1.1\nHost: example.com\n\n"),
			expected: false,
		},
		{
			name:     "different lengths after normalization",
			req1:     []byte("GET / HTTP/1.1\r\n"),
			req2:     []byte("GET / HTTP/1.1\nHost: example.com\n"),
			expected: false,
		},
		{
			name:     "body with different line endings - functionally equal",
			req1:     []byte("POST / HTTP/1.1\r\nContent-Length: 11\r\n\r\nline1\r\nline2"),
			req2:     []byte("POST / HTTP/1.1\nContent-Length: 11\n\nline1\nline2"),
			expected: true,
		},
		{
			name:     "different hosts - different even after normalization",
			req1:     []byte("GET / HTTP/1.1\nHost: example.com\n\n"),
			req2:     []byte("GET / HTTP/1.1\rHost: example.org\r\r"),
			expected: false,
		},
		{
			name:     "complex mixed line endings - functionally equal",
			req1:     []byte("GET / HTTP/1.1\r\nHost: example.com\nUser-Agent: test\rAccept: */*\r\n\r\n"),
			req2:     []byte("GET / HTTP/1.1\nHost: example.com\rUser-Agent: test\nAccept: */*\n\n"),
			expected: true,
		},
		{
			name:     "only line ending differences at start",
			req1:     []byte("\r\nGET / HTTP/1.1\r\n"),
			req2:     []byte("\nGET / HTTP/1.1\n"),
			expected: true,
		},
		{
			name:     "only line ending differences at end",
			req1:     []byte("GET / HTTP/1.1\r\n"),
			req2:     []byte("GET / HTTP/1.1\n"),
			expected: true,
		},
		{
			name:     "consecutive line endings - CRLF vs LF",
			req1:     []byte("GET / HTTP/1.1\r\n\r\nHost: example.com\r\n"),
			req2:     []byte("GET / HTTP/1.1\n\nHost: example.com\n"),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RequestsEqualNormalized(tt.req1, tt.req2)

			if result != tt.expected {
				t.Errorf("RequestsEqualNormalized() = %v, want %v", result, tt.expected)
				// Debug: show what the normalized versions look like
				norm1 := NormalizeLineEndings(tt.req1)
				norm2 := NormalizeLineEndings(tt.req2)
				t.Logf("Normalized req1: %q", norm1)
				t.Logf("Normalized req2: %q", norm2)
			}

			// Test symmetry: RequestsEqualNormalized(a, b) == RequestsEqualNormalized(b, a)
			resultReverse := RequestsEqualNormalized(tt.req2, tt.req1)
			if result != resultReverse {
				t.Errorf("RequestsEqualNormalized() not symmetric: RequestsEqualNormalized(req1, req2)=%v, RequestsEqualNormalized(req2, req1)=%v",
					result, resultReverse)
			}
		})
	}
}

// TestRequestsEqualVsNormalized compares byte-level equality with functional equality
func TestRequestsEqualVsNormalized(t *testing.T) {
	tests := []struct {
		name               string
		req1               []byte
		req2               []byte
		equalExpected      bool
		normalizedExpected bool
		description        string
	}{
		{
			name:               "same bytes, same normalized",
			req1:               []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			req2:               []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			equalExpected:      true,
			normalizedExpected: true,
			description:        "Identical requests should be equal both ways",
		},
		{
			name:               "different bytes, same normalized",
			req1:               []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			req2:               []byte("GET / HTTP/1.1\nHost: example.com\n\n"),
			equalExpected:      false,
			normalizedExpected: true,
			description:        "Different line endings should differ in byte equality but not normalized",
		},
		{
			name:               "different bytes, different normalized",
			req1:               []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			req2:               []byte("POST / HTTP/1.1\nHost: example.com\n\n"),
			equalExpected:      false,
			normalizedExpected: false,
			description:        "Different content should differ both ways",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			equal := RequestsEqual(tt.req1, tt.req2)
			normalized := RequestsEqualNormalized(tt.req1, tt.req2)

			if equal != tt.equalExpected {
				t.Errorf("RequestsEqual() = %v, want %v - %s", equal, tt.equalExpected, tt.description)
			}

			if normalized != tt.normalizedExpected {
				t.Errorf("RequestsEqualNormalized() = %v, want %v - %s", normalized, tt.normalizedExpected, tt.description)
			}

			// Invariant: if RequestsEqual is true, RequestsEqualNormalized must also be true
			if equal && !normalized {
				t.Error("Invariant violated: byte-equal requests should also be normalized-equal")
			}
		})
	}
}

// TestNormalizeLineEndingsIdempotent tests that normalizing twice gives the same result
func TestNormalizeLineEndingsIdempotent(t *testing.T) {
	inputs := [][]byte{
		[]byte("GET / HTTP/1.1\nHost: example.com\n\n"),
		[]byte("GET / HTTP/1.1\rHost: example.com\r\r"),
		[]byte("GET / HTTP/1.1\r\nHost: example.com\nUser-Agent: test\r\r\n"),
		[]byte("\ntest\r\ndata\rmixed\n"),
	}

	for i, input := range inputs {
		t.Run(string(rune('A'+i)), func(t *testing.T) {
			once := NormalizeLineEndings(input)
			twice := NormalizeLineEndings(once)

			if !bytes.Equal(once, twice) {
				t.Errorf("NormalizeLineEndings is not idempotent:\nOnce:  %q\nTwice: %q", once, twice)
			}
		})
	}
}

// TestRequestBuilderUtilsEdgeCases tests various edge cases across all functions
func TestRequestBuilderUtilsEdgeCases(t *testing.T) {
	t.Run("single byte requests", func(t *testing.T) {
		single := []byte("A")
		clone := CloneRequest(single)
		if !bytes.Equal(clone, single) {
			t.Errorf("CloneRequest failed on single byte")
		}

		normalized := NormalizeLineEndings(single)
		if !bytes.Equal(normalized, single) {
			t.Errorf("NormalizeLineEndings changed single non-newline byte")
		}

		if !RequestsEqual(single, single) {
			t.Errorf("RequestsEqual failed on identical single byte")
		}
	})

	t.Run("large request", func(t *testing.T) {
		// Create a large request with mixed line endings
		large := bytes.Repeat([]byte("GET / HTTP/1.1\nHost: example.com\r\n"), 1000)
		clone := CloneRequest(large)

		if !bytes.Equal(clone, large) {
			t.Errorf("CloneRequest failed on large request")
		}

		normalized := NormalizeLineEndings(large)
		if bytes.Contains(normalized, []byte("\n")) && !bytes.Contains(normalized, []byte("\r\n")) {
			t.Errorf("NormalizeLineEndings failed to normalize large request")
		}
	})

	t.Run("all possible byte values", func(t *testing.T) {
		// Test with all possible byte values
		allBytes := make([]byte, 256)
		for i := 0; i < 256; i++ {
			allBytes[i] = byte(i)
		}

		clone := CloneRequest(allBytes)
		if !bytes.Equal(clone, allBytes) {
			t.Errorf("CloneRequest failed on all byte values")
		}

		// Normalize should only affect CR and LF
		normalized := NormalizeLineEndings(allBytes)
		// Count CR and LF in result
		crlfCount := bytes.Count(normalized, []byte{CR, LF})
		if crlfCount == 0 {
			t.Errorf("NormalizeLineEndings didn't create any CRLF sequences")
		}
	})
}
