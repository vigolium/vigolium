package runner

import "testing"

func TestNormalizeNativePhase_Aliases(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"deparos", "discovery"},
		{"discover", "discovery"},
		{"spitolas", "spidering"},
		{"ext", "extension"},
		{"audit", "dynamic-assessment"},
		{"dast", "dynamic-assessment"},
		{"assessment", "dynamic-assessment"},
		{"dynamic-assessment", "dynamic-assessment"},
		{"discovery", "discovery"},
		{"unknown", "unknown"},
	}
	for _, tt := range tests {
		if got := NormalizeNativePhase(tt.input); got != tt.want {
			t.Errorf("NormalizeNativePhase(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
