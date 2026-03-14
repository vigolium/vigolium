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
			got, _ := ValidateExtensionSyntax(tt.input)
			if len(got) != tt.want {
				t.Errorf("ValidateExtensionSyntax() returned %d extensions, want %d", len(got), tt.want)
			}
		})
	}
}

func TestSanitizeExtensionFilename(t *testing.T) {
	tests := []struct {
		name  string
		input string
		index int
		want  string
	}{
		{"normal filename", "agent-sqli-check.js", 0, "agent-sqli-check.js"},
		{"colon in name", ": .js", 0, "extension-0.js"},
		{"SAST-verified colon", "SAST-verified:agent-sast-nosqli.js", 0, "sast-verified-agent-sast-nosqli.js"},
		{"spaces in name", "my extension file.js", 0, "my-extension-file.js"},
		{"special chars", "agent@b2b#rce!.js", 0, "agent-b2b-rce.js"},
		{"uppercase", "Agent-SQLi-Check.js", 0, "agent-sqli-check.js"},
		{"path traversal", "../../../etc/passwd.js", 0, "passwd.js"},
		{"empty name", "", 3, "extension-3.js"},
		{"dot only", ".", 1, "extension-1.js"},
		{"no extension", "agent-check", 0, "agent-check.js"},
		{"consecutive special", "a---b___c.js", 0, "a-b-c.js"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeExtensionFilename(tt.input, tt.index)
			if got != tt.want {
				t.Errorf("sanitizeExtensionFilename(%q, %d) = %q, want %q", tt.input, tt.index, got, tt.want)
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
