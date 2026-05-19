package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigolium/vigolium/pkg/deparos/internal/dedup"
)

func TestDedup_NormalizeURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "basic URL",
			input:    "https://example.com/path",
			expected: "https://example.com/path",
		},
		{
			name:     "uppercase scheme and host",
			input:    "HTTPS://EXAMPLE.COM/path",
			expected: "https://example.com/path",
		},
		{
			name:     "mixed case path preserved",
			input:    "https://example.com/API/v1/Users",
			expected: "https://example.com/API/v1/Users",
		},
		{
			name:     "double slash collapsed",
			input:    "https://example.com//api//v1",
			expected: "https://example.com/api/v1",
		},
		{
			name:     "trailing slash preserved",
			input:    "https://example.com/api/",
			expected: "https://example.com/api/",
		},
		{
			name:     "port included",
			input:    "https://example.com:8080/api",
			expected: "https://example.com:8080/api",
		},
		{
			name:     "default http port removed",
			input:    "http://example.com:80/api",
			expected: "http://example.com/api",
		},
		{
			name:     "default https port removed",
			input:    "https://example.com:443/api",
			expected: "https://example.com/api",
		},
		{
			name:     "repeating segments collapsed",
			input:    "https://example.com/a/b/a/b/",
			expected: "https://example.com/a/b/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dedup.NormalizeURL(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPathDepth(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"empty path", "", 0},
		{"root path", "/", 0},
		{"single segment", "/api", 1},
		{"two segments", "/api/v1", 2},
		{"three segments", "/api/v1/users", 3},
		{"trailing slash", "/api/v1/", 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pathDepth(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
