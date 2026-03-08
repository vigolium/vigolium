package httpmsg

import (
	"testing"
)

func TestContainsBytes(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		pattern  []byte
		expected bool
	}{
		{
			name:     "pattern found at start",
			data:     []byte("hello world"),
			pattern:  []byte("hello"),
			expected: true,
		},
		{
			name:     "pattern found in middle",
			data:     []byte("hello world"),
			pattern:  []byte("lo wo"),
			expected: true,
		},
		{
			name:     "pattern found at end",
			data:     []byte("hello world"),
			pattern:  []byte("world"),
			expected: true,
		},
		{
			name:     "pattern not found",
			data:     []byte("hello world"),
			pattern:  []byte("xyz"),
			expected: false,
		},
		{
			name:     "empty pattern",
			data:     []byte("hello"),
			pattern:  []byte{},
			expected: false,
		},
		{
			name:     "nil data",
			data:     nil,
			pattern:  []byte("test"),
			expected: false,
		},
		{
			name:     "nil pattern",
			data:     []byte("test"),
			pattern:  nil,
			expected: false,
		},
		{
			name:     "pattern longer than data",
			data:     []byte("hi"),
			pattern:  []byte("hello"),
			expected: false,
		},
		{
			name:     "exact match",
			data:     []byte("test"),
			pattern:  []byte("test"),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ContainsBytes(tt.data, tt.pattern)
			if result != tt.expected {
				t.Errorf("ContainsBytes() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestCountMatches(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		pattern  []byte
		expected int
	}{
		{
			name:     "multiple matches",
			data:     []byte("abcabcabc"),
			pattern:  []byte("abc"),
			expected: 3,
		},
		{
			name:     "single match",
			data:     []byte("hello world"),
			pattern:  []byte("world"),
			expected: 1,
		},
		{
			name:     "no matches",
			data:     []byte("hello world"),
			pattern:  []byte("xyz"),
			expected: 0,
		},
		{
			name:     "overlapping potential matches",
			data:     []byte("aaaa"),
			pattern:  []byte("aa"),
			expected: 2, // "aa" at 0, "aa" at 2 (non-overlapping)
		},
		{
			name:     "empty pattern",
			data:     []byte("test"),
			pattern:  []byte{},
			expected: 0,
		},
		{
			name:     "nil data",
			data:     nil,
			pattern:  []byte("test"),
			expected: 0,
		},
		{
			name:     "single byte pattern",
			data:     []byte("abcabc"),
			pattern:  []byte("a"),
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CountMatches(tt.data, tt.pattern)
			if result != tt.expected {
				t.Errorf("CountMatches() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestGetMatches(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		pattern  []byte
		limit    int
		expected [][2]int
	}{
		{
			name:     "multiple matches unlimited",
			data:     []byte("abcabcabc"),
			pattern:  []byte("abc"),
			limit:    -1,
			expected: [][2]int{{0, 3}, {3, 6}, {6, 9}},
		},
		{
			name:     "multiple matches with limit",
			data:     []byte("abcabcabc"),
			pattern:  []byte("abc"),
			limit:    2,
			expected: [][2]int{{0, 3}, {3, 6}},
		},
		{
			name:     "single match",
			data:     []byte("hello world"),
			pattern:  []byte("world"),
			limit:    -1,
			expected: [][2]int{{6, 11}},
		},
		{
			name:     "no matches",
			data:     []byte("hello"),
			pattern:  []byte("xyz"),
			limit:    -1,
			expected: nil,
		},
		{
			name:     "empty pattern",
			data:     []byte("test"),
			pattern:  []byte{},
			limit:    -1,
			expected: nil,
		},
		{
			name:     "limit zero",
			data:     []byte("abcabc"),
			pattern:  []byte("abc"),
			limit:    0,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetMatches(tt.data, tt.pattern, tt.limit)
			if len(result) != len(tt.expected) {
				t.Errorf("GetMatches() returned %d matches, expected %d", len(result), len(tt.expected))
				return
			}
			for i := range result {
				if result[i] != tt.expected[i] {
					t.Errorf("GetMatches()[%d] = %v, expected %v", i, result[i], tt.expected[i])
				}
			}
		})
	}
}

func TestReplaceBytesN(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		find     []byte
		replace  []byte
		limit    int
		expected []byte
	}{
		{
			name:     "replace all occurrences",
			data:     []byte("abcabcabc"),
			find:     []byte("abc"),
			replace:  []byte("XYZ"),
			limit:    -1,
			expected: []byte("XYZXYZXYZ"),
		},
		{
			name:     "replace first only",
			data:     []byte("abcabcabc"),
			find:     []byte("abc"),
			replace:  []byte("XYZ"),
			limit:    1,
			expected: []byte("XYZabcabc"),
		},
		{
			name:     "replace with shorter",
			data:     []byte("hello world"),
			find:     []byte("world"),
			replace:  []byte("W"),
			limit:    -1,
			expected: []byte("hello W"),
		},
		{
			name:     "replace with longer",
			data:     []byte("hi"),
			find:     []byte("hi"),
			replace:  []byte("hello"),
			limit:    -1,
			expected: []byte("hello"),
		},
		{
			name:     "no matches",
			data:     []byte("hello"),
			find:     []byte("xyz"),
			replace:  []byte("ABC"),
			limit:    -1,
			expected: []byte("hello"),
		},
		{
			name:     "limit zero",
			data:     []byte("abcabc"),
			find:     []byte("abc"),
			replace:  []byte("XYZ"),
			limit:    0,
			expected: []byte("abcabc"),
		},
		{
			name:     "empty find",
			data:     []byte("test"),
			find:     []byte{},
			replace:  []byte("X"),
			limit:    -1,
			expected: []byte("test"),
		},
		{
			name:     "nil data",
			data:     nil,
			find:     []byte("abc"),
			replace:  []byte("XYZ"),
			limit:    -1,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := replaceBytesN(tt.data, tt.find, tt.replace, tt.limit)
			if tt.expected == nil {
				if result != nil {
					t.Errorf("replaceBytesN() = %v, expected nil", result)
				}
				return
			}
			if string(result) != string(tt.expected) {
				t.Errorf("replaceBytesN() = %q, expected %q", result, tt.expected)
			}
		})
	}
}
