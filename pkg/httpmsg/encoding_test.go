package httpmsg

import (
	"bytes"
	"testing"
)

// TestUrlEncode tests URL encoding of strings
func TestUrlEncode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple text",
			input:    "hello",
			expected: "hello",
		},
		{
			name:     "text with space",
			input:    "hello world",
			expected: "hello+world",
		},
		{
			name:     "text with special chars",
			input:    "a=b&c=d",
			expected: "a%3Db%26c%3Dd",
		},
		{
			name:     "text with plus",
			input:    "hello+world",
			expected: "hello%2Bworld",
		},
		{
			name:     "text with question mark",
			input:    "what?where",
			expected: "what%3Fwhere",
		},
		{
			name:     "text with hash",
			input:    "item#123",
			expected: "item%23123",
		},
		{
			name:     "text with at sign",
			input:    "user@domain",
			expected: "user%40domain",
		},
		{
			name:     "text with colon",
			input:    "http://example.com",
			expected: "http%3A%2F%2Fexample.com",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "alphanumeric",
			input:    "abc123XYZ",
			expected: "abc123XYZ",
		},
		{
			name:     "safe characters",
			input:    "test-file_name.txt~",
			expected: "test-file_name.txt~",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := UrlEncode(tt.input)
			if result != tt.expected {
				t.Errorf("UrlEncode(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestUrlDecode tests URL decoding of strings
func TestUrlDecode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple text",
			input:    "hello",
			expected: "hello",
		},
		{
			name:     "text with plus",
			input:    "hello+world",
			expected: "hello world",
		},
		{
			name:     "text with percent encoding",
			input:    "a%3Db%26c%3Dd",
			expected: "a=b&c=d",
		},
		{
			name:     "text with encoded plus",
			input:    "hello%2Bworld",
			expected: "hello+world",
		},
		{
			name:     "text with question mark",
			input:    "what%3Fwhere",
			expected: "what?where",
		},
		{
			name:     "text with hash",
			input:    "item%23123",
			expected: "item#123",
		},
		{
			name:     "text with at sign",
			input:    "user%40domain",
			expected: "user@domain",
		},
		{
			name:     "text with URL",
			input:    "http%3A%2F%2Fexample.com",
			expected: "http://example.com",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "alphanumeric unchanged",
			input:    "abc123XYZ",
			expected: "abc123XYZ",
		},
		{
			name:     "lowercase hex",
			input:    "test%2fpath",
			expected: "test/path",
		},
		{
			name:     "uppercase hex",
			input:    "test%2Fpath",
			expected: "test/path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := UrlDecode(tt.input)
			if result != tt.expected {
				t.Errorf("UrlDecode(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestUrlEncodeDecodeRoundTrip tests that encoding then decoding returns original
func TestUrlEncodeDecodeRoundTrip(t *testing.T) {
	tests := []string{
		"hello world",
		"a=b&c=d",
		"test+value",
		"http://example.com?foo=bar",
		"special!@#$%^&*()",
		"unicode test 你好",
		"",
		"simple",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			encoded := UrlEncode(input)
			decoded := UrlDecode(encoded)
			if decoded != input {
				t.Errorf("Round trip failed: original=%q, encoded=%q, decoded=%q", input, encoded, decoded)
			}
		})
	}
}

// TestUrlEncodeBytes tests URL encoding of byte arrays
func TestUrlEncodeBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{
			name:     "simple text",
			input:    []byte("hello"),
			expected: []byte("hello"),
		},
		{
			name:     "text with space",
			input:    []byte("hello world"),
			expected: []byte("hello+world"),
		},
		{
			name:     "text with special chars",
			input:    []byte("a=b&c=d"),
			expected: []byte("a%3Db%26c%3Dd"),
		},
		{
			name:     "nil input",
			input:    nil,
			expected: nil,
		},
		{
			name:     "empty bytes",
			input:    []byte{},
			expected: []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := UrlEncodeBytes(tt.input)
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("UrlEncodeBytes(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestUrlDecodeBytes tests URL decoding of byte arrays
func TestUrlDecodeBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{
			name:     "simple text",
			input:    []byte("hello"),
			expected: []byte("hello"),
		},
		{
			name:     "text with plus",
			input:    []byte("hello+world"),
			expected: []byte("hello world"),
		},
		{
			name:     "text with percent encoding",
			input:    []byte("a%3Db%26c%3Dd"),
			expected: []byte("a=b&c=d"),
		},
		{
			name:     "nil input",
			input:    nil,
			expected: nil,
		},
		{
			name:     "empty bytes",
			input:    []byte{},
			expected: []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := UrlDecodeBytes(tt.input)
			if err != nil {
				t.Errorf("UrlDecodeBytes(%q) returned error: %v", tt.input, err)
			}
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("UrlDecodeBytes(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestBase64Encode tests Base64 encoding of strings
func TestBase64Encode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple text",
			input:    "hello",
			expected: "aGVsbG8=",
		},
		{
			name:     "text with space",
			input:    "hello world",
			expected: "aGVsbG8gd29ybGQ=",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "single char",
			input:    "a",
			expected: "YQ==",
		},
		{
			name:     "two chars",
			input:    "ab",
			expected: "YWI=",
		},
		{
			name:     "three chars",
			input:    "abc",
			expected: "YWJj",
		},
		{
			name:     "four chars",
			input:    "abcd",
			expected: "YWJjZA==",
		},
		{
			name:     "special characters",
			input:    "a=b&c=d",
			expected: "YT1iJmM9ZA==",
		},
		{
			name:     "numbers",
			input:    "1234567890",
			expected: "MTIzNDU2Nzg5MA==",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Base64Encode(tt.input)
			if result != tt.expected {
				t.Errorf("Base64Encode(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestBase64EncodeBytes tests Base64 encoding of byte arrays
func TestBase64EncodeBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "simple text",
			input:    []byte("hello"),
			expected: "aGVsbG8=",
		},
		{
			name:     "binary data",
			input:    []byte{0x01, 0x02, 0x03},
			expected: "AQID",
		},
		{
			name:     "nil input",
			input:    nil,
			expected: "",
		},
		{
			name:     "empty bytes",
			input:    []byte{},
			expected: "",
		},
		{
			name:     "zero byte",
			input:    []byte{0x00},
			expected: "AA==",
		},
		{
			name:     "all bytes",
			input:    []byte{0xFF, 0xFE, 0xFD},
			expected: "//79",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Base64EncodeBytes(tt.input)
			if result != tt.expected {
				t.Errorf("Base64EncodeBytes(%v) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestBase64Decode tests Base64 decoding of strings
func TestBase64Decode(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  []byte
		expectErr bool
	}{
		{
			name:      "simple text",
			input:     "aGVsbG8=",
			expected:  []byte("hello"),
			expectErr: false,
		},
		{
			name:      "text with space",
			input:     "aGVsbG8gd29ybGQ=",
			expected:  []byte("hello world"),
			expectErr: false,
		},
		{
			name:      "empty string",
			input:     "",
			expected:  []byte{},
			expectErr: false,
		},
		{
			name:      "binary data",
			input:     "AQID",
			expected:  []byte{0x01, 0x02, 0x03},
			expectErr: false,
		},
		{
			name:      "zero byte",
			input:     "AA==",
			expected:  []byte{0x00},
			expectErr: false,
		},
		{
			name:      "all bytes",
			input:     "//79",
			expected:  []byte{0xFF, 0xFE, 0xFD},
			expectErr: false,
		},
		{
			name:      "invalid base64",
			input:     "invalid!@#",
			expected:  nil,
			expectErr: true,
		},
		{
			name:      "incomplete padding - errors in strict mode",
			input:     "YQ",
			expected:  nil,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Base64Decode(tt.input)
			if tt.expectErr {
				if err == nil {
					t.Errorf("Base64Decode(%q) expected error, got nil", tt.input)
				}
			} else {
				if err != nil {
					t.Errorf("Base64Decode(%q) unexpected error: %v", tt.input, err)
				}
				if !bytes.Equal(result, tt.expected) {
					t.Errorf("Base64Decode(%q) = %v, want %v", tt.input, result, tt.expected)
				}
			}
		})
	}
}

// TestBase64DecodeBytes tests Base64 decoding of byte arrays
func TestBase64DecodeBytes(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		expected  []byte
		expectErr bool
	}{
		{
			name:      "simple text",
			input:     []byte("aGVsbG8="),
			expected:  []byte("hello"),
			expectErr: false,
		},
		{
			name:      "binary data",
			input:     []byte("AQID"),
			expected:  []byte{0x01, 0x02, 0x03},
			expectErr: false,
		},
		{
			name:      "nil input",
			input:     nil,
			expected:  nil,
			expectErr: false,
		},
		{
			name:      "empty bytes",
			input:     []byte{},
			expected:  []byte{},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Base64DecodeBytes(tt.input)
			if tt.expectErr {
				if err == nil {
					t.Errorf("Base64DecodeBytes(%q) expected error, got nil", tt.input)
				}
			} else {
				if err != nil {
					t.Errorf("Base64DecodeBytes(%q) unexpected error: %v", tt.input, err)
				}
				if !bytes.Equal(result, tt.expected) {
					t.Errorf("Base64DecodeBytes(%q) = %v, want %v", tt.input, result, tt.expected)
				}
			}
		})
	}
}

// TestBase64EncodeDecodeRoundTrip tests that encoding then decoding returns original
func TestBase64EncodeDecodeRoundTrip(t *testing.T) {
	tests := []string{
		"hello",
		"hello world",
		"",
		"a",
		"ab",
		"abc",
		"special!@#$%^&*()",
		"unicode 你好",
		"The quick brown fox jumps over the lazy dog",
		"1234567890",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			encoded := Base64Encode(input)
			decoded, err := Base64Decode(encoded)
			if err != nil {
				t.Errorf("Base64Decode failed: %v", err)
			}
			if string(decoded) != input {
				t.Errorf("Round trip failed: original=%q, encoded=%q, decoded=%q", input, encoded, string(decoded))
			}
		})
	}
}

// TestStringToBytes tests string to byte array conversion
func TestStringToBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []byte
	}{
		{
			name:     "simple text",
			input:    "hello",
			expected: []byte{104, 101, 108, 108, 111},
		},
		{
			name:     "empty string",
			input:    "",
			expected: []byte{},
		},
		{
			name:     "single char",
			input:    "a",
			expected: []byte{97},
		},
		{
			name:     "numbers",
			input:    "123",
			expected: []byte{49, 50, 51},
		},
		{
			name:     "special chars",
			input:    "!@#",
			expected: []byte{33, 64, 35},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := StringToBytes(tt.input)
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("StringToBytes(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

// TestBytesToString tests byte array to string conversion
func TestBytesToString(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "simple text",
			input:    []byte{104, 101, 108, 108, 111},
			expected: "hello",
		},
		{
			name:     "nil input",
			input:    nil,
			expected: "",
		},
		{
			name:     "empty bytes",
			input:    []byte{},
			expected: "",
		},
		{
			name:     "single byte",
			input:    []byte{97},
			expected: "a",
		},
		{
			name:     "numbers",
			input:    []byte{49, 50, 51},
			expected: "123",
		},
		{
			name:     "special chars",
			input:    []byte{33, 64, 35},
			expected: "!@#",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BytesToString(tt.input)
			if result != tt.expected {
				t.Errorf("BytesToString(%v) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestStringBytesRoundTrip tests that converting string->bytes->string returns original
func TestStringBytesRoundTrip(t *testing.T) {
	tests := []string{
		"hello",
		"",
		"a",
		"abc123",
		"special!@#",
		"The quick brown fox",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			bytes := StringToBytes(input)
			result := BytesToString(bytes)
			if result != input {
				t.Errorf("Round trip failed: original=%q, bytes=%v, result=%q", input, bytes, result)
			}
		})
	}
}

// Benchmarks

func BenchmarkUrlEncode(b *testing.B) {
	input := "hello world this is a test string with spaces"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = UrlEncode(input)
	}
}

func BenchmarkUrlDecode(b *testing.B) {
	input := "hello+world+this+is+a+test+string+with+spaces"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = UrlDecode(input)
	}
}

func BenchmarkUrlEncodeBytes(b *testing.B) {
	input := []byte("hello world this is a test string with spaces")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = UrlEncodeBytes(input)
	}
}

func BenchmarkUrlDecodeBytes(b *testing.B) {
	input := []byte("hello+world+this+is+a+test+string+with+spaces")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = UrlDecodeBytes(input)
	}
}

func BenchmarkBase64Encode(b *testing.B) {
	input := "The quick brown fox jumps over the lazy dog"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Base64Encode(input)
	}
}

func BenchmarkBase64EncodeBytes(b *testing.B) {
	input := []byte("The quick brown fox jumps over the lazy dog")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Base64EncodeBytes(input)
	}
}

func BenchmarkBase64Decode(b *testing.B) {
	input := "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw=="
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Base64Decode(input)
	}
}

func BenchmarkBase64DecodeBytes(b *testing.B) {
	input := []byte("VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Base64DecodeBytes(input)
	}
}

func BenchmarkStringToBytes(b *testing.B) {
	input := "The quick brown fox jumps over the lazy dog"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = StringToBytes(input)
	}
}

func BenchmarkBytesToString(b *testing.B) {
	input := []byte("The quick brown fox jumps over the lazy dog")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = BytesToString(input)
	}
}
