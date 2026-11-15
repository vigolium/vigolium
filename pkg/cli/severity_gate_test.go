package cli

import (
	"reflect"
	"testing"
)

func TestNormalizeSeverity(t *testing.T) {
	cases := map[string]string{
		// exact canonical names pass through
		"critical": "critical",
		"medium":   "medium",
		"info":     "info",
		// trimming + case folding
		"  HIGH ": "high",
		"Low":     "low",
		// single-letter shorthands
		"c": "critical",
		"h": "high",
		"m": "medium",
		"l": "low",
		"s": "suspect",
		"i": "info",
		// fuzzy unambiguous prefixes
		"me":   "medium",
		"med":  "medium",
		"crit": "critical",
		"cr":   "critical",
		"hi":   "high",
		"sus":  "suspect",
		"su":   "suspect",
		"lo":   "low",
		"in":   "info",
		// unknown label passes through lowercased
		"bogus": "bogus",
		"":      "",
	}
	for in, want := range cases {
		if got := normalizeSeverity(in); got != want {
			t.Errorf("normalizeSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseSeverityListFuzzy(t *testing.T) {
	cases := []struct {
		raw  string
		want []string
	}{
		{"me,info", []string{"medium", "info"}},
		{"h,c", []string{"high", "critical"}},
		{"crit, hi , med", []string{"critical", "high", "medium"}},
		// de-dup while preserving first-seen order (medium reached two ways)
		{"me,medium,m", []string{"medium"}},
		{"", nil},
		{" , ", nil},
	}
	for _, tc := range cases {
		if got, err := parseSeverityList(tc.raw); err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("parseSeverityList(%q) = %v, %v, want %v", tc.raw, got, err, tc.want)
		}
	}
	// An unknown item is a usage error, not a filter that matches nothing.
	if _, err := parseSeverityList("high,bogus"); err == nil || classifyExitCode(err) != ExitUsageError {
		t.Errorf("parseSeverityList(high,bogus) = %v, want a usage error", err)
	}
}
