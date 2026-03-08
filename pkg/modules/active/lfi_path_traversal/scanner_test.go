package lfi_path_traversal

import (
	"testing"
)

func TestMatchFileParams(t *testing.T) {
	tests := []struct {
		name     string
		param    string
		expected bool
	}{
		{"exact match", "file", true},
		{"contains file", "filename", true},
		{"contains path", "basepath", true},
		{"download", "download", true},
		{"unrelated", "username", false},
		{"empty", "", false},
		{"camelCase", "filePath", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchFileParams(tt.param)
			if got != tt.expected {
				t.Errorf("matchFileParams(%q) = %v, want %v", tt.param, got, tt.expected)
			}
		})
	}
}

func TestLooksLikeFilePath(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected bool
	}{
		{"relative path", "../config.xml", true},
		{"absolute path", "/etc/passwd", true},
		{"dot-slash", "./page.html", true},
		{"html extension", "index.html", true},
		{"txt extension", "readme.txt", true},
		{"no path", "hello", false},
		{"numeric", "12345", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := looksLikeFilePath(tt.value)
			if got != tt.expected {
				t.Errorf("looksLikeFilePath(%q) = %v, want %v", tt.value, got, tt.expected)
			}
		})
	}
}

func TestCountNewMarkers(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		baseline string
		markers  []string
		expected int
	}{
		{
			name:     "all markers new",
			data:     "root:x:0:0:root:/root:/bin/bash",
			baseline: "nothing here",
			markers:  []string{"root:", ":0:0:", "/bin/"},
			expected: 3,
		},
		{
			name:     "markers already in baseline",
			data:     "root:x:0:0:root:/root:/bin/bash",
			baseline: "root:x:0:0:root:/root:/bin/bash",
			markers:  []string{"root:", ":0:0:", "/bin/"},
			expected: 0,
		},
		{
			name:     "partial new markers",
			data:     "root:x:0:0:root:/root:/bin/bash",
			baseline: "root: is a user",
			markers:  []string{"root:", ":0:0:", "/bin/"},
			expected: 2,
		},
		{
			name:     "empty baseline",
			data:     "root:x:0:0:root:/root:/bin/bash",
			baseline: "",
			markers:  []string{"root:", ":0:0:", "/bin/"},
			expected: 3,
		},
		{
			name:     "no markers match",
			data:     "nothing relevant",
			baseline: "",
			markers:  []string{"root:", ":0:0:", "/bin/"},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := countNewMarkers(tt.data, tt.baseline, tt.markers)
			if got != tt.expected {
				t.Errorf("countNewMarkers() = %v, want %v", got, tt.expected)
			}
		})
	}
}
