package httpmsg

import (
	"testing"
)

func TestBytesToHexString(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name:     "ASCII string",
			data:     []byte("Hello"),
			expected: "48 65 6c 6c 6f",
		},
		{
			name:     "single byte",
			data:     []byte{0xFF},
			expected: "ff",
		},
		{
			name:     "mixed bytes",
			data:     []byte{0x00, 0x7F, 0x80, 0xFF},
			expected: "00 7f 80 ff",
		},
		{
			name:     "empty data",
			data:     []byte{},
			expected: "",
		},
		{
			name:     "nil data",
			data:     nil,
			expected: "",
		},
		{
			name:     "HTTP request line",
			data:     []byte("GET"),
			expected: "47 45 54",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BytesToHexString(tt.data)
			if result != tt.expected {
				t.Errorf("BytesToHexString() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestFilterString(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		safeChars string
		expected  string
	}{
		{
			name:      "filter to letters only",
			input:     "abc123!@#def",
			safeChars: "abcdefghijklmnopqrstuvwxyz",
			expected:  "abcdef",
		},
		{
			name:      "filter to digits only",
			input:     "abc123def456",
			safeChars: "0123456789",
			expected:  "123456",
		},
		{
			name:      "all chars safe",
			input:     "hello",
			safeChars: "abcdefghijklmnopqrstuvwxyz",
			expected:  "hello",
		},
		{
			name:      "no chars safe",
			input:     "hello",
			safeChars: "0123456789",
			expected:  "",
		},
		{
			name:      "empty input",
			input:     "",
			safeChars: "abc",
			expected:  "",
		},
		{
			name:      "empty safe chars",
			input:     "hello",
			safeChars: "",
			expected:  "",
		},
		{
			name:      "alphanumeric filter",
			input:     "user@example.com",
			safeChars: "abcdefghijklmnopqrstuvwxyz0123456789",
			expected:  "userexamplecom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FilterString(tt.input, tt.safeChars)
			if result != tt.expected {
				t.Errorf("FilterString() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestEncodeBytesAbove7F(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "ASCII only",
			input:    "hello",
			expected: "hello",
		},
		{
			name:     "single high byte",
			input:    "hello\x80world",
			expected: "hello%80world",
		},
		{
			name:     "multiple high bytes",
			input:    "\x80\x81\x82",
			expected: "%80%81%82",
		},
		{
			name:     "max byte value",
			input:    "test\xFFend",
			expected: "test%FFend",
		},
		{
			name:     "boundary byte 0x7F",
			input:    "test\x7Fend",
			expected: "test\x7Fend", // 0x7F is NOT > 0x7F
		},
		{
			name:     "empty input",
			input:    "",
			expected: "",
		},
		{
			name:     "mixed ASCII and high bytes",
			input:    "a\x90b\xA0c",
			expected: "a%90b%A0c",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EncodeBytesAbove7F(tt.input)
			if result != tt.expected {
				t.Errorf("EncodeBytesAbove7F() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestRandomString(t *testing.T) {
	t.Run("generates correct length", func(t *testing.T) {
		lengths := []int{1, 5, 10, 20, 100}
		for _, length := range lengths {
			result := randomString(length)
			if len(result) != length {
				t.Errorf("randomString(%d) length = %d, expected %d", length, len(result), length)
			}
		}
	})

	t.Run("zero length returns empty", func(t *testing.T) {
		result := randomString(0)
		if result != "" {
			t.Errorf("randomString(0) = %q, expected empty string", result)
		}
	})

	t.Run("negative length returns empty", func(t *testing.T) {
		result := randomString(-5)
		if result != "" {
			t.Errorf("randomString(-5) = %q, expected empty string", result)
		}
	})

	t.Run("contains only alphanumeric", func(t *testing.T) {
		alphanumeric := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		for i := 0; i < 10; i++ {
			result := randomString(50)
			for _, c := range result {
				found := false
				for _, a := range alphanumeric {
					if c == a {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("randomString() contains non-alphanumeric character: %c", c)
				}
			}
		}
	})
}

func TestGenerateCanary(t *testing.T) {
	t.Run("has correct format", func(t *testing.T) {
		canary := generateCanary()

		// Should be "zxcv" + 4 chars + "bnm" = 11 chars
		if len(canary) != 11 {
			t.Errorf("generateCanary() length = %d, expected 11", len(canary))
		}

		// Check prefix
		if canary[:4] != "zxcv" {
			t.Errorf("generateCanary() prefix = %q, expected 'zxcv'", canary[:4])
		}

		// Check suffix (index 8 because: 4 prefix + 4 random = 8)
		if canary[8:] != "bnm" {
			t.Errorf("generateCanary() suffix = %q, expected 'bnm'", canary[8:])
		}
	})

	t.Run("generates different values", func(t *testing.T) {
		canaries := make(map[string]bool)
		for i := 0; i < 100; i++ {
			canary := generateCanary()
			canaries[canary] = true
		}
		// With 4 random alphanumeric chars, duplicates should be rare
		if len(canaries) < 50 {
			t.Errorf("generateCanary() generated too many duplicates: %d unique out of 100", len(canaries))
		}
	})
}

func TestMangle(t *testing.T) {
	t.Run("deterministic output", func(t *testing.T) {
		// Same input should produce same output
		result1 := mangle("test")
		result2 := mangle("test")
		if result1 != result2 {
			t.Errorf("mangle() not deterministic: %q != %q", result1, result2)
		}
	})

	t.Run("different inputs produce different outputs", func(t *testing.T) {
		result1 := mangle("test1")
		result2 := mangle("test2")
		if result1 == result2 {
			t.Errorf("mangle() produced same output for different inputs: %q", result1)
		}
	})

	t.Run("same length as input", func(t *testing.T) {
		inputs := []string{"a", "test", "hello world", "1234567890"}
		for _, input := range inputs {
			result := mangle(input)
			if len(result) != len(input) {
				t.Errorf("mangle(%q) length = %d, expected %d", input, len(result), len(input))
			}
		}
	})

	t.Run("empty input returns empty", func(t *testing.T) {
		result := mangle("")
		if result != "" {
			t.Errorf("mangle(\"\") = %q, expected empty string", result)
		}
	})

	t.Run("output is alphanumeric", func(t *testing.T) {
		alphanumeric := "abcdefghijklmnopqrstuvwxyz0123456789"
		result := mangle("test input string")
		for _, c := range result {
			found := false
			for _, a := range alphanumeric {
				if c == a {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("mangle() contains non-alphanumeric character: %c", c)
			}
		}
	})
}
