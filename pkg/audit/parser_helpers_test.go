package audit

import (
	"strings"
	"testing"
)

func TestExtractLocations(t *testing.T) {
	t.Run("file and code locations, deduplicated", func(t *testing.T) {
		content := "**File**: `src/auth.go`\n" +
			"see `handler.go:42-50` -- the sink\n" +
			"**File**: `src/auth.go`\n" // duplicate
		locs := extractLocations(content)
		if len(locs) != 2 {
			t.Fatalf("expected 2 deduplicated locations, got %v", locs)
		}
		if locs[0] != "src/auth.go" {
			t.Errorf("first location = %q, want src/auth.go", locs[0])
		}
		if locs[1] != "handler.go:42-50" {
			t.Errorf("second location = %q, want handler.go:42-50", locs[1])
		}
	})
	t.Run("no locations", func(t *testing.T) {
		if locs := extractLocations("nothing here"); len(locs) != 0 {
			t.Errorf("expected no locations, got %v", locs)
		}
	})
}

func TestSanitizeTrailingFences(t *testing.T) {
	t.Run("balanced fences unchanged", func(t *testing.T) {
		in := "```\ncode\n```"
		if got := sanitizeTrailingFences(in); got != in {
			t.Errorf("balanced input changed: %q", got)
		}
	})
	t.Run("orphaned trailing fence stripped", func(t *testing.T) {
		in := "```\ncode\n```\n```"
		got := sanitizeTrailingFences(in)
		if got != "```\ncode\n```" {
			t.Errorf("got %q, want balanced block", got)
		}
		// Result must now be balanced (even number of fence lines).
		if strings.Count(got, "```") != 2 {
			t.Errorf("result is not balanced: %q", got)
		}
	})
}

func TestExtractTitleFromBody(t *testing.T) {
	t.Run("first non-empty line of Summary", func(t *testing.T) {
		content := "## Summary\n\nReflected XSS in search box\n\nmore details"
		if got := extractTitleFromBody(content, "ignored-slug"); got != "Reflected XSS in search box" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("falls back to humanized slug", func(t *testing.T) {
		if got := extractTitleFromBody("no summary here", "sql-injection-login"); got != "sql injection login" {
			t.Errorf("got %q, want humanized slug", got)
		}
	})
	t.Run("truncates long titles", func(t *testing.T) {
		long := strings.Repeat("x", 300)
		got := extractTitleFromBody("## Summary\n"+long, "slug")
		if len(got) != 200 {
			t.Errorf("title length = %d, want 200", len(got))
		}
	})
}

func TestSeverityFromLetter(t *testing.T) {
	tests := map[string]string{
		"C": "Critical", "H": "High", "M": "Medium", "L": "Low",
		"X": "", "": "",
	}
	for in, want := range tests {
		if got := severityFromLetter(in); got != want {
			t.Errorf("severityFromLetter(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPromotedSortKey(t *testing.T) {
	// Rank prefix encodes severity: Critical < High < Medium < Low < unknown,
	// so lexicographic ordering of the keys matches severity ordering.
	crit := promotedSortKey(&Finding{FindingID: "C1", Sequence: "1"})
	high := promotedSortKey(&Finding{FindingID: "H1", Sequence: "1"})
	med := promotedSortKey(&Finding{FindingID: "M1", Sequence: "1"})
	unknown := promotedSortKey(&Finding{FindingID: "", Sequence: "1"})

	if crit[0] != '0' {
		t.Errorf("critical rank prefix = %q, want 0", crit[0])
	}
	if unknown[0] != '9' {
		t.Errorf("unknown rank prefix = %q, want 9", unknown[0])
	}
	if !(crit < high && high < med && med < unknown) {
		t.Errorf("sort keys not ordered by severity: crit=%q high=%q med=%q unknown=%q", crit, high, med, unknown)
	}
}
