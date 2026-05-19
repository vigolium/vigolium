package ssr_data_exposure

import (
	"testing"
)

func TestNew(t *testing.T) {
	m := New()
	if m == nil {
		t.Fatal("New() returned nil")
	}
	if m.ID() != ModuleID {
		t.Errorf("ID = %q, want %q", m.ID(), ModuleID)
	}
	if m.Name() != ModuleName {
		t.Errorf("Name = %q, want %q", m.Name(), ModuleName)
	}
}

func TestExtractState(t *testing.T) {
	tests := []struct {
		name string
		body string
		blob ssrStateBlob
		want string
	}{
		{
			name: "NEXT_DATA",
			body: `<script id="__NEXT_DATA__" type="application/json">{"buildId":"abc"}</script>`,
			blob: stateBlobs[0],
			want: `{"buildId":"abc"}`,
		},
		{
			name: "no match",
			body: `<html><body>hello</body></html>`,
			blob: stateBlobs[0],
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractState(tt.body, tt.blob)
			if got != tt.want {
				t.Errorf("extractState() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSensitivePatterns(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "API key",
			input: `"api_key": "abcdefghijklmnopqrstuvwxyz1234567890"`,
			want:  true,
		},
		{
			name:  "Admin flag",
			input: `"isAdmin": true`,
			want:  true,
		},
		{
			name:  "Email",
			input: `"email": "user@example.com"`,
			want:  true,
		},
		{
			name:  "No match",
			input: `"name": "John"`,
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := false
			for _, sp := range sensitivePatterns {
				if sp.pattern.MatchString(tt.input) {
					matched = true
					break
				}
			}
			if matched != tt.want {
				t.Errorf("pattern match = %v, want %v", matched, tt.want)
			}
		})
	}
}

func TestIsPlaceholder(t *testing.T) {
	if !isPlaceholder(`"api_key": "YOUR_API_KEY"`) {
		t.Error("expected YOUR_API_KEY to be a placeholder")
	}
	if isPlaceholder(`"api_key": "sk-abc123def456ghi789"`) {
		t.Error("expected real key to not be a placeholder")
	}
}
