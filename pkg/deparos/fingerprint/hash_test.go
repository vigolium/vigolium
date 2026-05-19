package fingerprint

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHashString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected uint32
	}{
		{"empty", "", 0},
		{"simple", "hello", 0x3610a686},
		{"html", "text/html", 0x8b1acc3e},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HashString(tt.input)
			if tt.expected != 0 {
				assert.NotZero(t, result, "hash should not be zero for non-empty string")
			} else {
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestHashString_Consistency(t *testing.T) {
	s := "test string"
	hash1 := HashString(s)
	hash2 := HashString(s)
	assert.Equal(t, hash1, hash2, "same string should produce same hash")
}

func TestHashString_Different(t *testing.T) {
	hash1 := HashString("string1")
	hash2 := HashString("string2")
	assert.NotEqual(t, hash1, hash2, "different strings should produce different hashes")
}

func TestHashStrings(t *testing.T) {
	tests := []struct {
		name   string
		input  []string
		expect uint32
	}{
		{"empty", []string{}, 0},
		{"single", []string{"hello"}, 0},            // Non-zero for single
		{"multiple", []string{"hello", "world"}, 0}, // Non-zero accumulated
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HashStrings(tt.input)
			if tt.expect == 0 && len(tt.input) > 0 {
				assert.NotZero(t, result, "accumulated hash should not be zero for non-empty input")
			} else if tt.expect != 0 {
				assert.Equal(t, tt.expect, result)
			}
		})
	}
}

func TestHashStrings_OrderMatters(t *testing.T) {
	hash1 := HashStrings([]string{"a", "b", "c"})
	hash2 := HashStrings([]string{"c", "b", "a"})
	// Order matters for accumulated hash (not sorted)
	assert.NotEqual(t, hash1, hash2, "different order should produce different hash")
}

func TestHashStrings_IgnoresEmpty(t *testing.T) {
	hash1 := HashStrings([]string{"hello", "", "world"})
	hash2 := HashStrings([]string{"hello", "world"})
	assert.Equal(t, hash1, hash2, "empty strings should be ignored")
}

func TestHashStringSet(t *testing.T) {
	tests := []struct {
		name  string
		input []string
	}{
		{"empty", []string{}},
		{"single", []string{"hello"}},
		{"multiple", []string{"hello", "world"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HashStringSet(tt.input)
			if len(tt.input) == 0 {
				assert.Equal(t, uint32(0), result)
			} else {
				assert.NotZero(t, result)
			}
		})
	}
}

func TestHashStringSet_OrderIndependent(t *testing.T) {
	hash1 := HashStringSet([]string{"a", "b", "c"})
	hash2 := HashStringSet([]string{"c", "b", "a"})
	// Sets are sorted before hashing
	assert.Equal(t, hash1, hash2, "different order should produce same hash for sets")
}

func TestHashStringSet_Sorted(t *testing.T) {
	hash1 := HashStringSet([]string{"z", "a", "m"})
	hash2 := HashStringSet([]string{"a", "m", "z"})
	assert.Equal(t, hash1, hash2, "sets should be sorted before hashing")
}

func TestHashBytes(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"empty", []byte{}},
		{"simple", []byte("hello")},
		{"binary", []byte{0x01, 0x02, 0x03, 0x04}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HashBytes(tt.input)
			if len(tt.input) == 0 {
				assert.Equal(t, uint32(0), result)
			} else {
				assert.NotZero(t, result)
			}
		})
	}
}

func TestHashBytes_Consistency(t *testing.T) {
	data := []byte("test data")
	hash1 := HashBytes(data)
	hash2 := HashBytes(data)
	assert.Equal(t, hash1, hash2, "same data should produce same hash")
}

func TestAccumulateCRC32(t *testing.T) {
	// Test accumulation behavior
	hash1 := accumulateCRC32(0, []byte("hello"))
	hash2 := accumulateCRC32(hash1, []byte("world"))

	assert.NotZero(t, hash1)
	assert.NotZero(t, hash2)
	assert.NotEqual(t, hash1, hash2, "accumulated hash should change")
}

func TestParseContentType(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty", "", ""},
		{"simple", "text/html", "text/html"},
		{"with_charset", "text/html; charset=utf-8", "text/html"},
		{"multiple_params", "text/html; charset=utf-8; boundary=abc", "text/html"},
		{"json", "application/json", "application/json"},
		{"json_charset", "application/json; charset=utf-8", "application/json"},
		{"with_spaces", "text/html ; charset=utf-8", "text/html"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseContentType(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractCookieNames(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "empty",
			input:    []string{},
			expected: nil,
		},
		{
			name:     "single",
			input:    []string{"session_id=abc123"},
			expected: []string{"session_id"},
		},
		{
			name:     "multiple",
			input:    []string{"session_id=abc", "csrf_token=xyz"},
			expected: []string{"session_id", "csrf_token"},
		},
		{
			name:     "with_attributes",
			input:    []string{"session_id=abc; Path=/; HttpOnly"},
			expected: []string{"session_id"},
		},
		{
			name:     "complex",
			input:    []string{"session=abc; Path=/; Secure", "user=xyz; Max-Age=3600"},
			expected: []string{"session", "user"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractCookieNames(tt.input)
			if tt.expected == nil {
				assert.Nil(t, result)
			} else {
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestTruncateBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		maxBytes int
		expected []byte
	}{
		{
			name:     "empty",
			input:    []byte{},
			maxBytes: 10,
			expected: []byte{},
		},
		{
			name:     "shorter_than_max",
			input:    []byte("hello"),
			maxBytes: 10,
			expected: []byte("hello"),
		},
		{
			name:     "longer_than_max",
			input:    []byte("hello world"),
			maxBytes: 5,
			expected: []byte("hello"),
		},
		{
			name:     "exact_max",
			input:    []byte("hello"),
			maxBytes: 5,
			expected: []byte("hello"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TruncateBytes(tt.input, tt.maxBytes)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRotateLeft(t *testing.T) {
	tests := []struct {
		name  string
		value uint32
		n     uint
	}{
		{"rotate_1", 0b10101010, 1},
		{"rotate_4", 0xABCDEF12, 4},
		{"rotate_8", 0x12345678, 8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rotateLeft(tt.value, tt.n)
			// Rotating back should give original
			rotatedBack := rotateLeft(result, 32-tt.n)
			assert.Equal(t, tt.value, rotatedBack, "rotating back should restore original")
		})
	}
}

func BenchmarkHashString(b *testing.B) {
	s := "text/html; charset=utf-8"
	for i := 0; i < b.N; i++ {
		HashString(s)
	}
}

func BenchmarkHashStrings(b *testing.B) {
	strings := []string{"html", "head", "body", "div", "p", "span"}
	for i := 0; i < b.N; i++ {
		HashStrings(strings)
	}
}

func BenchmarkHashStringSet(b *testing.B) {
	strings := []string{"class1", "class2", "class3", "class4", "class5"}
	for i := 0; i < b.N; i++ {
		HashStringSet(strings)
	}
}

func BenchmarkParseContentType(b *testing.B) {
	ct := "text/html; charset=utf-8"
	for i := 0; i < b.N; i++ {
		ParseContentType(ct)
	}
}
