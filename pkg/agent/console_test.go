package agent

import (
	"strings"
	"testing"
)

// stripANSI removes ANSI escape sequences so we can assert on the underlying
// text content regardless of whether color is active in the test environment.
func stripANSI(s string) string {
	return reANSI.ReplaceAllString(s, "")
}

func TestColorizeMessage_TextOnly(t *testing.T) {
	// A purely descriptive message (no double-space KV section) round-trips
	// its text content unchanged after stripping color codes.
	got := stripANSI(colorizeMessage("starting scan"))
	if got != "starting scan" {
		t.Errorf("text content = %q, want %q", got, "starting scan")
	}
}

func TestColorizeMessage_KeyValueSection(t *testing.T) {
	// "desc  key=value" — double space separates desc from KV pairs.
	got := stripANSI(colorizeMessage("ingested records  count=37 source=agent"))
	for _, want := range []string{"ingested records", "count=37", "source=agent"} {
		if !strings.Contains(got, want) {
			t.Errorf("colorized output missing %q; got %q", want, got)
		}
	}
}

func TestColorizeMessage_NonKVToken(t *testing.T) {
	// A trailing parenthesized status token has no '=' and must still appear.
	got := stripANSI(colorizeMessage("scan done  (3 blocked)"))
	if !strings.Contains(got, "(3") || !strings.Contains(got, "blocked)") {
		t.Errorf("non-KV token dropped: %q", got)
	}
}

func TestHighlightNumbersPlain(t *testing.T) {
	// All digit runs and surrounding text must survive after stripping color.
	got := stripANSI(highlightNumbersPlain("found 39 of 100 routes"))
	if got != "found 39 of 100 routes" {
		t.Errorf("text content = %q, want unchanged", got)
	}
	// No numbers → still returns full text.
	got2 := stripANSI(highlightNumbersPlain("no digits here"))
	if got2 != "no digits here" {
		t.Errorf("text content = %q, want unchanged", got2)
	}
}

func TestHighlightNumbers_PreservesEmbeddedANSI(t *testing.T) {
	// Pre-colored segments must pass through untouched while plain segments
	// still get number highlighting. Strip-and-compare proves no content loss.
	input := "prefix \x1b[31mRED\x1b[0m 42 suffix"
	got := stripANSI(highlightNumbers(input))
	if got != "prefix RED 42 suffix" {
		t.Errorf("text content = %q, want %q", got, "prefix RED 42 suffix")
	}
}
