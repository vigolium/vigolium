package csti_detection

import (
	"strings"
	"testing"
)

func TestBuildCSTIProbe(t *testing.T) {
	probe, markers := buildCSTIProbe()

	// Probe should contain {{ and }}
	if !strings.Contains(probe, "{{") || !strings.Contains(probe, "}}") {
		t.Errorf("probe should contain template expression, got: %s", probe)
	}

	// Should have at least 2 markers
	if len(markers) < 2 {
		t.Errorf("expected at least 2 markers, got %d", len(markers))
	}

	// First marker should match the probe exactly
	if markers[0] != probe {
		t.Errorf("first marker should equal probe:\n  probe:  %s\n  marker: %s", probe, markers[0])
	}

	// Second marker should be spaced version
	if !strings.Contains(markers[1], "{{ ") || !strings.Contains(markers[1], " }}") {
		t.Errorf("second marker should contain spaced expression, got: %s", markers[1])
	}

	// Probe should have random anchors (length > expression)
	if len(probe) < 20 {
		t.Errorf("probe should include random anchors, got length %d: %s", len(probe), probe)
	}

	// Two calls should produce different probes (random)
	probe2, _ := buildCSTIProbe()
	if probe == probe2 {
		t.Error("two consecutive calls should produce different probes (random anchors)")
	}
}

func TestIsHTMLEncoded(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		marker string
		want   bool
	}{
		{
			name:   "not encoded",
			body:   `<div>abc123{{1970*2024}}def456</div>`,
			marker: "abc123{{1970*2024}}def456",
			want:   false,
		},
		{
			name:   "HTML entity encoded",
			body:   `<div>abc123&#123;&#123;1970*2024&#125;&#125;def456</div>`,
			marker: "abc123{{1970*2024}}def456",
			want:   true,
		},
		{
			name:   "named entity encoded",
			body:   `<div>abc123&lcub;&lcub;1970*2024&rcub;&rcub;def456</div>`,
			marker: "abc123{{1970*2024}}def456",
			want:   true,
		},
		{
			name:   "no curly braces in marker",
			body:   `<div>test</div>`,
			marker: "noccurlies",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isHTMLEncoded(tt.body, tt.marker)
			if got != tt.want {
				t.Errorf("isHTMLEncoded() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRandomString(t *testing.T) {
	s := randomString(6)
	if len(s) != 6 {
		t.Errorf("expected length 6, got %d", len(s))
	}

	// Should be alphanumeric
	for _, c := range s {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			t.Errorf("unexpected character in random string: %c", c)
		}
	}

	// Two calls should produce different strings (with overwhelming probability)
	s2 := randomString(6)
	if s == s2 {
		t.Error("two consecutive randomString calls produced identical results")
	}
}
