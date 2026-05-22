package clicommon

import (
	"strings"
	"testing"
	"time"
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
			if got := FormatTokenCount(tt.in); got != tt.want {
				t.Errorf("FormatTokenCount(%v) = %q, want %q", tt.in, got, tt.want)
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
			if got := FormatFileSize(tt.bytes); got != tt.want {
				t.Errorf("FormatFileSize(%d) = %q, want %q", tt.bytes, got, tt.want)
			}
		})
	}
}

func TestPluralSuffix(t *testing.T) {
	if PluralSuffix(1) != "" {
		t.Error("PluralSuffix(1) should be empty")
	}
	if PluralSuffix(0) != "s" {
		t.Error("PluralSuffix(0) should be s")
	}
	if PluralSuffix(2) != "s" {
		t.Error("PluralSuffix(2) should be s")
	}
}

func TestFormatSeverityWithSymbols(t *testing.T) {
	t.Run("empty map yields empty string", func(t *testing.T) {
		if got := FormatSeverityWithSymbols(map[string]int{}); got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})
	t.Run("includes nonzero, excludes zero, joins with comma", func(t *testing.T) {
		got := FormatSeverityWithSymbols(map[string]int{"critical": 1, "high": 2, "medium": 0})
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
			got := SplitCSV(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("SplitCSV(%q) = %v, want %v", tt.in, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("SplitCSV(%q)[%d] = %q, want %q", tt.in, i, got[i], tt.want[i])
				}
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
			if got := CSVEscape(tt.in); got != tt.want {
				t.Errorf("CSVEscape(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseDate(t *testing.T) {
	t.Run("date only", func(t *testing.T) {
		got, err := ParseDate("2024-01-15")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Year() != 2024 || got.Month() != time.January || got.Day() != 15 {
			t.Errorf("parsed wrong date: %v", got)
		}
	})
	t.Run("rfc3339", func(t *testing.T) {
		if _, err := ParseDate("2024-01-15T10:30:00Z"); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		if _, err := ParseDate("not-a-date"); err == nil {
			t.Error("expected error for invalid date")
		}
	})
}
