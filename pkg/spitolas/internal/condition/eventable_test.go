package condition

import (
	"testing"
)

// TestNormalizeXPath verifies XPath normalization.
func TestNormalizeXPath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"/html/body/div", "html/body/div"},
		{"//html/body/div", "html/body/div"},
		{"/HTML/BODY/DIV", "html/body/div"},
		{"//HTML/BODY/DIV", "html/body/div"},
		{"html/body/div", "html/body/div"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeXPath(tt.input)
			if got != tt.want {
				t.Errorf("normalizeXPath(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
