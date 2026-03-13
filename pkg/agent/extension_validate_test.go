package agent

import (
	"testing"
)

func TestValidateExtensionSyntax(t *testing.T) {
	tests := []struct {
		name  string
		input []GeneratedExtension
		want  int
	}{
		{
			name: "valid JS passes",
			input: []GeneratedExtension{
				{Filename: "good.js", Code: "var x = 1;"},
			},
			want: 1,
		},
		{
			name: "invalid JS is dropped",
			input: []GeneratedExtension{
				{Filename: "bad.js", Code: "function(}{"},
			},
			want: 0,
		},
		{
			name: "empty code is dropped",
			input: []GeneratedExtension{
				{Filename: "empty.js", Code: "   "},
			},
			want: 0,
		},
		{
			name: "mix of valid and invalid",
			input: []GeneratedExtension{
				{Filename: "a.js", Code: "var a = 1;"},
				{Filename: "b.js", Code: "???"},
				{Filename: "c.js", Code: "var c = 2;"},
			},
			want: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateExtensionSyntax(tt.input)
			if len(got) != tt.want {
				t.Errorf("ValidateExtensionSyntax() returned %d extensions, want %d", len(got), tt.want)
			}
		})
	}
}

func TestDeduplicateExtensionFilename(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		existing map[string]bool
		want     string
	}{
		{
			name:     "no collision",
			input:    "check.js",
			existing: map[string]bool{},
			want:     "check.js",
		},
		{
			name:     "single collision",
			input:    "check.js",
			existing: map[string]bool{"check.js": true},
			want:     "check-2.js",
		},
		{
			name:  "multiple collisions",
			input: "check.js",
			existing: map[string]bool{
				"check.js":   true,
				"check-2.js": true,
				"check-3.js": true,
			},
			want: "check-4.js",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deduplicateExtensionFilename(tt.input, tt.existing)
			if got != tt.want {
				t.Errorf("deduplicateExtensionFilename() = %q, want %q", got, tt.want)
			}
		})
	}
}
