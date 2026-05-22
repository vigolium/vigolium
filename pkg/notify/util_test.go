package notify

import (
	"strings"
	"testing"
)

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"plain", "plain"},
		{"a/b", "a_b"},
		{"a\\b", "a_b"},
		{"host:8080", "host_8080"},
		{`a*b?c"d<e>f|g`, "a_b_c_d_e_f_g"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := SanitizeFilename(tt.in); got != tt.want {
				t.Errorf("SanitizeFilename(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestGenerateFilename(t *testing.T) {
	got := GenerateFilename("sql/injection", "host:8080", "txt")
	// moduleID and host must be sanitized; extension preserved.
	if strings.ContainsAny(got, "/:") {
		t.Errorf("GenerateFilename did not sanitize separators: %q", got)
	}
	if !strings.HasPrefix(got, "sql_injection_host_8080_") {
		t.Errorf("unexpected prefix: %q", got)
	}
	if !strings.HasSuffix(got, ".txt") {
		t.Errorf("missing extension: %q", got)
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		maxLen int
		want   string
	}{
		{"under limit", "hello", 10, "hello"},
		{"exact limit", "hello", 5, "hello"},
		{"normal truncation", "hello world", 8, "hello..."},
		{"tiny limit no ellipsis", "hello", 3, "hel"},
		{"tiny limit 2", "hello", 2, "he"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Truncate(tt.in, tt.maxLen)
			if got != tt.want {
				t.Errorf("Truncate(%q,%d) = %q, want %q", tt.in, tt.maxLen, got, tt.want)
			}
			if len(got) > tt.maxLen && len(tt.in) > tt.maxLen {
				t.Errorf("Truncate(%q,%d) returned %q exceeding maxLen", tt.in, tt.maxLen, got)
			}
		})
	}
}

func TestTruncateWithIndicator(t *testing.T) {
	t.Run("under limit unchanged", func(t *testing.T) {
		if got := TruncateWithIndicator("short", 100); got != "short" {
			t.Errorf("got %q, want short", got)
		}
	})
	t.Run("appends indicator", func(t *testing.T) {
		got := TruncateWithIndicator(strings.Repeat("x", 100), 40)
		if !strings.HasSuffix(got, " [see attachment]") {
			t.Errorf("missing indicator suffix: %q", got)
		}
		if len(got) > 40 {
			t.Errorf("result %d chars exceeds maxLen 40: %q", len(got), got)
		}
	})
	t.Run("indicator longer than maxLen", func(t *testing.T) {
		got := TruncateWithIndicator(strings.Repeat("x", 100), 5)
		if got != " [see attachment]" {
			t.Errorf("got %q, want bare indicator", got)
		}
	})
}
