package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/types/severity"
)

func TestFormatTokenCount(t *testing.T) {
	tests := []struct {
		name string
		in   interface{}
		want string
	}{
		{"small int", 42, "42"},
		{"thousands float", float64(1500), "1.5K"},
		{"millions int64", int64(2_300_000), "2.3M"},
		{"exact thousand", 1000, "1.0K"},
		{"non-numeric falls back", "n/a", "n/a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatTokenCount(tt.in); got != tt.want {
				t.Errorf("formatTokenCount(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestFormatFileSize(t *testing.T) {
	tests := []struct {
		bytes int64
		want  string
	}{
		{512, "512 B"},
		{2048, "2.0 KB"},
		{3 * 1 << 20, "3.0 MB"},
		{0, "0 B"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := formatFileSize(tt.bytes); got != tt.want {
				t.Errorf("formatFileSize(%d) = %q, want %q", tt.bytes, got, tt.want)
			}
		})
	}
}

func TestPluralSuffix(t *testing.T) {
	if pluralSuffix(1) != "" {
		t.Error("pluralSuffix(1) should be empty")
	}
	if pluralSuffix(0) != "s" {
		t.Error("pluralSuffix(0) should be s")
	}
	if pluralSuffix(2) != "s" {
		t.Error("pluralSuffix(2) should be s")
	}
}

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

func TestFormatSeverityWithSymbols(t *testing.T) {
	t.Run("empty map yields empty string", func(t *testing.T) {
		if got := formatSeverityWithSymbols(map[string]int{}); got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})
	t.Run("includes nonzero, excludes zero, joins with comma", func(t *testing.T) {
		got := formatSeverityWithSymbols(map[string]int{"critical": 1, "high": 2, "medium": 0})
		if !strings.Contains(got, "1 critical") {
			t.Errorf("missing critical entry: %q", got)
		}
		if !strings.Contains(got, "2 high") {
			t.Errorf("missing high entry: %q", got)
		}
		if strings.Contains(got, "medium") {
			t.Errorf("zero-count medium should be excluded: %q", got)
		}
		if !strings.Contains(got, ", ") {
			t.Errorf("expected comma-separated entries: %q", got)
		}
	})
}

func TestSplitCSV(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"a,b,c", []string{"a", "b", "c"}},
		{" a , b ,c ", []string{"a", "b", "c"}}, // trims
		{"a,,b", []string{"a", "b"}},            // drops empties
		{"  ", nil},                             // all-blank -> nil
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got := splitCSV(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("splitCSV(%q) = %v, want %v", tt.in, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("splitCSV(%q)[%d] = %q, want %q", tt.in, i, got[i], tt.want[i])
				}
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

func TestCSVEscape(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"plain", "plain"},
		{"has,comma", `"has,comma"`},
		{`has"quote`, `"has""quote"`},
		{"line\nbreak", "\"line\nbreak\""},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := csvEscape(tt.in); got != tt.want {
				t.Errorf("csvEscape(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseDate(t *testing.T) {
	t.Run("date only", func(t *testing.T) {
		got, err := parseDate("2024-01-15")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Year() != 2024 || got.Month() != time.January || got.Day() != 15 {
			t.Errorf("parsed wrong date: %v", got)
		}
	})
	t.Run("rfc3339", func(t *testing.T) {
		if _, err := parseDate("2024-01-15T10:30:00Z"); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		if _, err := parseDate("not-a-date"); err == nil {
			t.Error("expected error for invalid date")
		}
	})
}
