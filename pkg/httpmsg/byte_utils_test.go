package httpmsg

import (
	"bytes"
	"testing"
)

func TestFindBodyOffset(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected int
	}{
		{
			name:     "CRLF line endings with body",
			input:    []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\nBODY"),
			expected: 37,
		},
		{
			name:     "LF line endings with body",
			input:    []byte("GET / HTTP/1.1\nHost: example.com\n\nBODY"),
			expected: 34,
		},
		{
			name:     "CRLF line endings no body",
			input:    []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: 37,
		},
		{
			name:     "LF line endings no body",
			input:    []byte("GET / HTTP/1.1\nHost: example.com\n\n"),
			expected: 34,
		},
		{
			name:     "No separator - headers only",
			input:    []byte("GET / HTTP/1.1\r\nHost: example.com"),
			expected: 33,
		},
		{
			name:     "Empty input",
			input:    []byte(""),
			expected: 0,
		},
		{
			name:     "Nil input",
			input:    nil,
			expected: -1,
		},
		{
			name:     "Only CRLF CRLF",
			input:    []byte("\r\n\r\n"),
			expected: 4,
		},
		{
			name:     "Only LF LF",
			input:    []byte("\n\n"),
			expected: 2,
		},
		{
			name:     "CRLF CRLF at start",
			input:    []byte("\r\n\r\nBODY"),
			expected: 4,
		},
		{
			name:     "LF LF at start",
			input:    []byte("\n\nBODY"),
			expected: 2,
		},
		{
			name:     "HTTP response with CRLF",
			input:    []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>"),
			expected: 44,
		},
		{
			name:     "HTTP response with LF",
			input:    []byte("HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html>"),
			expected: 41,
		},
		{
			name:     "Mixed CRLF and LF - CRLF separator",
			input:    []byte("GET / HTTP/1.1\nHost: example.com\r\n\r\nBODY"),
			expected: 36,
		},
		{
			name:     "Edge case: LF LF near end",
			input:    []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\n"),
			expected: 36,
		},
		{
			name:     "Body with CRLF CRLF inside",
			input:    []byte("GET / HTTP/1.1\r\n\r\nBODY\r\n\r\nMORE"),
			expected: 18,
		},
		{
			name:     "Very short input",
			input:    []byte("AB"),
			expected: 2,
		},
		{
			name:     "Three bytes",
			input:    []byte("ABC"),
			expected: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FindBodyOffset(tt.input)
			if result != tt.expected {
				t.Errorf("FindBodyOffset() = %d, expected %d\nInput: %q", result, tt.expected, tt.input)
			}
		})
	}
}

func TestFindBodyEnd(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		startOffset int
		expected    int
	}{
		{
			name:        "Trailing CRLF CRLF",
			input:       []byte("HTTP/1.1 200 OK\r\n\r\nBODY\r\n\r\n"),
			startOffset: 19,
			expected:    23,
		},
		{
			name:        "Trailing LF LF",
			input:       []byte("HTTP/1.1 200 OK\n\nBODY\n\n"),
			startOffset: 17,
			expected:    21,
		},
		{
			name:        "No trailing separator",
			input:       []byte("HTTP/1.1 200 OK\r\n\r\nBODY"),
			startOffset: 19,
			expected:    23,
		},
		{
			name:        "Empty body with trailing separator",
			input:       []byte("HTTP/1.1 200 OK\r\n\r\n\r\n\r\n"),
			startOffset: 19,
			expected:    19,
		},
		{
			name:        "Body is entire input",
			input:       []byte("BODY"),
			startOffset: 0,
			expected:    4,
		},
		{
			name:        "Nil input",
			input:       nil,
			startOffset: 0,
			expected:    -1,
		},
		{
			name:        "Start offset at end",
			input:       []byte("HTTP/1.1 200 OK\r\n\r\nBODY"),
			startOffset: 23,
			expected:    23,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FindBodyEnd(tt.input, tt.startOffset)
			if result != tt.expected {
				t.Errorf("FindBodyEnd() = %d, expected %d\nInput: %q, startOffset: %d", result, tt.expected, tt.input, tt.startOffset)
			}
		})
	}
}

func TestSliceBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		start    int
		end      int
		expected []byte
	}{
		{
			name:     "Normal slice",
			input:    []byte("hello world"),
			start:    0,
			end:      5,
			expected: []byte("hello"),
		},
		{
			name:     "Slice from middle",
			input:    []byte("hello world"),
			start:    6,
			end:      11,
			expected: []byte("world"),
		},
		{
			name:     "End beyond length - should cap",
			input:    []byte("hello"),
			start:    0,
			end:      100,
			expected: []byte("hello"),
		},
		{
			name:     "Start beyond length - should return empty",
			input:    []byte("hello"),
			start:    10,
			end:      20,
			expected: []byte{},
		},
		{
			name:     "Negative start - should use 0",
			input:    []byte("hello"),
			start:    -5,
			end:      3,
			expected: []byte("hel"),
		},
		{
			name:     "Start equals end",
			input:    []byte("hello"),
			start:    2,
			end:      2,
			expected: []byte{},
		},
		{
			name:     "End before start",
			input:    []byte("hello"),
			start:    5,
			end:      2,
			expected: []byte{},
		},
		{
			name:     "Empty input",
			input:    []byte(""),
			start:    0,
			end:      0,
			expected: []byte{},
		},
		{
			name:     "Nil input",
			input:    nil,
			start:    0,
			end:      5,
			expected: nil,
		},
		{
			name:     "Full slice",
			input:    []byte("hello"),
			start:    0,
			end:      5,
			expected: []byte("hello"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SliceBytes(tt.input, tt.start, tt.end)
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("SliceBytes() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestIndexOfByte(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		target      byte
		startOffset int
		expected    int
	}{
		{
			name:        "Find first occurrence",
			input:       []byte("hello"),
			target:      'l',
			startOffset: 0,
			expected:    2,
		},
		{
			name:        "Find second occurrence",
			input:       []byte("hello"),
			target:      'l',
			startOffset: 3,
			expected:    3,
		},
		{
			name:        "Not found",
			input:       []byte("hello"),
			target:      'x',
			startOffset: 0,
			expected:    -1,
		},
		{
			name:        "Find at start",
			input:       []byte("hello"),
			target:      'h',
			startOffset: 0,
			expected:    0,
		},
		{
			name:        "Find at end",
			input:       []byte("hello"),
			target:      'o',
			startOffset: 0,
			expected:    4,
		},
		{
			name:        "Empty input",
			input:       []byte(""),
			target:      'x',
			startOffset: 0,
			expected:    -1,
		},
		{
			name:        "Nil input",
			input:       nil,
			target:      'x',
			startOffset: 0,
			expected:    -1,
		},
		{
			name:        "Negative start offset - should use 0",
			input:       []byte("hello"),
			target:      'h',
			startOffset: -5,
			expected:    0,
		},
		{
			name:        "Start offset beyond length",
			input:       []byte("hello"),
			target:      'h',
			startOffset: 10,
			expected:    -1,
		},
		{
			name:        "Find CR byte",
			input:       []byte("hello\r\nworld"),
			target:      CR,
			startOffset: 0,
			expected:    5,
		},
		{
			name:        "Find LF byte",
			input:       []byte("hello\r\nworld"),
			target:      LF,
			startOffset: 0,
			expected:    6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IndexOfByte(tt.input, tt.target, tt.startOffset)
			if result != tt.expected {
				t.Errorf("IndexOfByte() = %d, expected %d", result, tt.expected)
			}
		})
	}
}

func TestIndexOfBytes(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		target      []byte
		startOffset int
		expected    int
	}{
		{
			name:        "Find substring",
			input:       []byte("hello world"),
			target:      []byte("wor"),
			startOffset: 0,
			expected:    6,
		},
		{
			name:        "Not found",
			input:       []byte("hello world"),
			target:      []byte("xyz"),
			startOffset: 0,
			expected:    -1,
		},
		{
			name:        "Find at start",
			input:       []byte("hello world"),
			target:      []byte("hel"),
			startOffset: 0,
			expected:    0,
		},
		{
			name:        "Find at end",
			input:       []byte("hello world"),
			target:      []byte("rld"),
			startOffset: 0,
			expected:    8,
		},
		{
			name:        "Find with start offset",
			input:       []byte("hello hello"),
			target:      []byte("hello"),
			startOffset: 1,
			expected:    6,
		},
		{
			name:        "Empty target",
			input:       []byte("hello"),
			target:      []byte(""),
			startOffset: 3,
			expected:    3,
		},
		{
			name:        "Empty input",
			input:       []byte(""),
			target:      []byte("hello"),
			startOffset: 0,
			expected:    -1,
		},
		{
			name:        "Nil input",
			input:       nil,
			target:      []byte("hello"),
			startOffset: 0,
			expected:    -1,
		},
		{
			name:        "Nil target",
			input:       []byte("hello"),
			target:      nil,
			startOffset: 0,
			expected:    -1,
		},
		{
			name:        "Target longer than input",
			input:       []byte("hi"),
			target:      []byte("hello"),
			startOffset: 0,
			expected:    -1,
		},
		{
			name:        "Find CRLF CRLF",
			input:       []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\nBODY"),
			target:      []byte("\r\n\r\n"),
			startOffset: 0,
			expected:    33,
		},
		{
			name:        "Find LF LF",
			input:       []byte("GET / HTTP/1.1\nHost: example.com\n\nBODY"),
			target:      []byte("\n\n"),
			startOffset: 0,
			expected:    32,
		},
		{
			name:        "Negative start offset - should use 0",
			input:       []byte("hello world"),
			target:      []byte("wor"),
			startOffset: -5,
			expected:    6,
		},
		{
			name:        "Start offset beyond valid range",
			input:       []byte("hello"),
			target:      []byte("hello"),
			startOffset: 1,
			expected:    -1,
		},
		{
			name:        "Exact match",
			input:       []byte("hello"),
			target:      []byte("hello"),
			startOffset: 0,
			expected:    0,
		},
		{
			name:        "Single byte target",
			input:       []byte("hello"),
			target:      []byte("l"),
			startOffset: 0,
			expected:    2,
		},
		{
			name:        "Overlapping pattern",
			input:       []byte("aaaa"),
			target:      []byte("aa"),
			startOffset: 0,
			expected:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IndexOfBytes(tt.input, tt.target, tt.startOffset)
			if result != tt.expected {
				t.Errorf("IndexOfBytes() = %d, expected %d\nInput: %q, Target: %q", result, tt.expected, tt.input, tt.target)
			}
		})
	}
}

// Benchmark tests to verify performance
func BenchmarkFindBodyOffset_CRLF(b *testing.B) {
	data := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\nBODY")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FindBodyOffset(data)
	}
}

func BenchmarkFindBodyOffset_LF(b *testing.B) {
	data := []byte("GET / HTTP/1.1\nHost: example.com\nUser-Agent: test\n\nBODY")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FindBodyOffset(data)
	}
}

func BenchmarkIndexOfBytes(b *testing.B) {
	data := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\nBODY")
	target := []byte("\r\n\r\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IndexOfBytes(data, target, 0)
	}
}

func BenchmarkSliceBytes(b *testing.B) {
	data := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\nBODY")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SliceBytes(data, 0, 20)
	}
}

// ==================== NEW UTILITY FUNCTION TESTS ====================

func TestIsHTTP2(t *testing.T) {
	tests := []struct {
		name     string
		request  []byte
		expected bool
	}{
		{
			name:     "HTTP/2 request",
			request:  []byte("GET / HTTP/2\r\nHost: example.com\r\n\r\n"),
			expected: true,
		},
		{
			name:     "HTTP/1.1 request",
			request:  []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: false,
		},
		{
			name:     "HTTP/1.0 request",
			request:  []byte("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"),
			expected: false,
		},
		{
			name:     "Lowercase http/2",
			request:  []byte("GET / http/2\r\nHost: example.com\r\n\r\n"),
			expected: true,
		},
		{
			name:     "Mixed case HTTP/2",
			request:  []byte("GET / HtTp/2\r\nHost: example.com\r\n\r\n"),
			expected: true,
		},
		{
			name:     "HTTP/2 pseudo-header",
			request:  []byte(":method GET\r\n:path /\r\n\r\n"),
			expected: true,
		},
		{
			name:     "Short request",
			request:  []byte("GET"),
			expected: false,
		},
		{
			name:     "Nil request",
			request:  nil,
			expected: false,
		},
		{
			name:     "Empty request",
			request:  []byte{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsHTTP2(tt.request)
			if result != tt.expected {
				t.Errorf("IsHTTP2() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestConvertToHTTP1(t *testing.T) {
	tests := []struct {
		name     string
		request  []byte
		expected []byte
	}{
		{
			name:     "Convert HTTP/2 to HTTP/1.1",
			request:  []byte("GET / HTTP/2\r\nHost: example.com\r\n\r\n"),
			expected: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		},
		{
			name:     "HTTP/1.1 unchanged",
			request:  []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		},
		{
			name:     "Lowercase http/2",
			request:  []byte("GET / http/2\r\nHost: example.com\r\n\r\n"),
			expected: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		},
		{
			name:     "Nil request",
			request:  nil,
			expected: nil,
		},
		{
			name:     "No line ending",
			request:  []byte("GET / HTTP/2"),
			expected: []byte("GET / HTTP/1.1"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ConvertToHTTP1(tt.request)
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("ConvertToHTTP1() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestGetHeaders(t *testing.T) {
	tests := []struct {
		name     string
		message  []byte
		expected string
	}{
		{
			name:     "Request with multiple headers",
			message:  []byte("GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n"),
			expected: "Host: example.com\r\nAccept: */*\r\n",
		},
		{
			name:     "Request with single header",
			message:  []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: "Host: example.com\r\n",
		},
		{
			name:     "Request with no headers",
			message:  []byte("GET / HTTP/1.1\r\n\r\n"),
			expected: "",
		},
		{
			name:     "Nil message",
			message:  nil,
			expected: "",
		},
		{
			name:     "Response message",
			message:  []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>"),
			expected: "Content-Type: text/html\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetHeaders(tt.message)
			if result != tt.expected {
				t.Errorf("GetHeaders() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestGetHeadersBytes(t *testing.T) {
	tests := []struct {
		name     string
		message  []byte
		expected []byte
	}{
		{
			name:     "Request with headers",
			message:  []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: []byte("Host: example.com\r\n"),
		},
		{
			name:     "Empty headers",
			message:  []byte("GET / HTTP/1.1\r\n\r\n"),
			expected: []byte{},
		},
		{
			name:     "Nil message",
			message:  nil,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetHeadersBytes(tt.message)
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("GetHeadersBytes() = %q, expected %q", result, tt.expected)
			}
		})
	}
}
