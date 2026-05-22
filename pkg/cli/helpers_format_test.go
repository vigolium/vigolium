package cli

import (
	"testing"

	"github.com/vigolium/vigolium/pkg/types/severity"
)

func TestSplitFocusArea(t *testing.T) {
	tests := []struct {
		name       string
		in         string
		wantTitle  string
		wantDetail string
	}{
		{"markdown bold colon", "**SQL Injection**: in login form", "SQL Injection", "in login form"},
		{"markdown bold emdash", "**XSS** — reflected in search", "XSS", "reflected in search"},
		{"plain colon", "Auth Bypass: missing check", "Auth Bypass", "missing check"},
		{"no separator", "just a title", "just a title", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			title, detail := splitFocusArea(tt.in)
			if title != tt.wantTitle || detail != tt.wantDetail {
				t.Errorf("splitFocusArea(%q) = (%q,%q), want (%q,%q)", tt.in, title, detail, tt.wantTitle, tt.wantDetail)
			}
		})
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		in   string
		want severity.Severity
	}{
		{"critical", severity.Critical},
		{"HIGH", severity.High}, // case-insensitive
		{"medium", severity.Medium},
		{"low", severity.Low},
		{"info", severity.Info},
		{"bogus", severity.Info}, // unknown defaults to Info
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := parseSeverity(tt.in); got != tt.want {
				t.Errorf("parseSeverity(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
