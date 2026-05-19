package casesense

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFlipCase(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple lowercase",
			input:    "/admin/",
			expected: "/ADMIN/",
		},
		{
			name:     "simple uppercase",
			input:    "/ADMIN/",
			expected: "/admin/",
		},
		{
			name:     "mixed case",
			input:    "/Admin/Config/",
			expected: "/aDMIN/cONFIG/",
		},
		{
			name:     "with numbers",
			input:    "/admin123/",
			expected: "/ADMIN123/",
		},
		{
			name:     "no alpha chars",
			input:    "/123/456/",
			expected: "/123/456/",
		},
		{
			name:     "empty path",
			input:    "/",
			expected: "/",
		},
		{
			name:     "file with extension",
			input:    "/Admin/config.php",
			expected: "/aDMIN/CONFIG.PHP",
		},
		{
			name:     "unicode letters",
			input:    "/Admin/Üser/",
			expected: "/aDMIN/üSER/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := flipCase(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHasAlphaChars(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "has alpha",
			input:    "/admin/",
			expected: true,
		},
		{
			name:     "only numbers",
			input:    "/123/456/",
			expected: false,
		},
		{
			name:     "empty",
			input:    "/",
			expected: false,
		},
		{
			name:     "special chars only",
			input:    "/-_./",
			expected: false,
		},
		{
			name:     "mixed",
			input:    "/123/abc/",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasAlphaChars(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractTestableSegment(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple path",
			input:    "/admin/",
			expected: "admin",
		},
		{
			name:     "nested path",
			input:    "/api/v1/Users/",
			expected: "Users",
		},
		{
			name:     "path with numbers only at end",
			input:    "/api/v1/123/",
			expected: "v1",
		},
		{
			name:     "file path",
			input:    "/admin/config.php",
			expected: "config.php",
		},
		{
			name:     "no alpha segments",
			input:    "/123/456/",
			expected: "",
		},
		{
			name:     "root only",
			input:    "/",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractTestableSegment(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
