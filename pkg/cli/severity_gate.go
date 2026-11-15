package cli

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/utils/textutil"
)

// severityRanks orders severities from least to most severe, mirroring
// pkg/types/severity (Info < Suspect < Low < Medium < High < Critical).
// Higher rank = more severe. Unknown severities rank 0.
var severityRanks = map[string]int{
	"info":     1,
	"suspect":  2,
	"low":      3,
	"medium":   4,
	"high":     5,
	"critical": 6,
}

// severityOrder lists severities ascending by rank, for deterministic expansion.
var severityOrder = []string{"info", "suspect", "low", "medium", "high", "critical"}

// failOnUsage builds the --fail-on help text from severityOrder, so the listed
// choices are exactly the values the gate accepts (a hand-written list dropped
// "suspect"). suffix carries the per-command tail after the choices.
func failOnUsage(suffix string) string {
	return "Exit non-zero if a finding at or above this severity is present (" +
		strings.Join(severityOrder, "|") + "); findings marked false_positive/accepted_risk do not count — " + suffix
}

// severityAliases maps single-letter shorthands to canonical severity names so
// filters accept 'h,c' as well as 'high,critical'.
var severityAliases = map[string]string{
	"c": "critical",
	"h": "high",
	"m": "medium",
	"l": "low",
	"s": "suspect",
	"i": "info",
}

// normalizeSeverity canonicalizes a single severity token: trims, lowercases,
// expands a single-letter shorthand (h→high, c→critical, …), and fuzzy-matches
// any unambiguous prefix of a canonical name (me→medium, crit→critical, sus→
// suspect). Unknown values pass through lowercased so callers can still match
// custom labels.
func normalizeSeverity(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return s
	}
	if full, ok := severityAliases[s]; ok {
		return full
	}
	if full, ok := severityByPrefix(s); ok {
		return full
	}
	return s
}

// severityByPrefix expands a token that is a prefix of exactly one canonical
// severity name (e.g. "me"→medium, "crit"→critical). The canonical names all
// start with distinct letters, so any non-empty prefix resolves to at most one
// name; an exact name matches itself. Returns ok=false when nothing (or, in
// principle, more than one thing) matches, so callers fall back to the raw token.
func severityByPrefix(s string) (string, bool) {
	match := ""
	for _, name := range severityOrder {
		if strings.HasPrefix(name, s) {
			if match != "" {
				return "", false
			}
			match = name
		}
	}
	if match == "" {
		return "", false
	}
	return match, true
}

// parseSeverityList splits a comma-separated severity filter (e.g.
// "high,critical" or "h,c") into canonical severity names, expanding shorthands,
// dropping blanks, and de-duplicating while preserving first-seen order.
//
// An item that names no severity is a usage error: dropped silently, it turned
// the filter into one that matches nothing and answered "total: 0".
func parseSeverityList(raw string) ([]string, error) {
	var out []string
	seen := make(map[string]bool)
	for _, tok := range strings.Split(raw, ",") {
		s := normalizeSeverity(tok)
		if s == "" || seen[s] {
			continue
		}
		if severityRank(s) == 0 {
			return nil, clicommon.CLIError{
				Err:        fmt.Errorf("unknown severity %q: must be one of: %s", strings.TrimSpace(tok), strings.Join(severityOrder, ", ")),
				DidYouMean: textutil.Closest(s, severityOrder),
			}
		}
		seen[s] = true
		out = append(out, s)
	}
	return out, nil
}

// severityRank returns the numeric rank of a severity name (0 if unknown).
func severityRank(s string) int {
	return severityRanks[strings.TrimSpace(strings.ToLower(s))]
}

// severitiesAtOrAbove returns every severity name with rank >= threshold, in
// ascending order. Returns nil when the threshold name is unknown. Used by
// --min-severity (finding) and --fail-on (scan) so an agent can say "high and
// up" instead of enumerating each level.
func severitiesAtOrAbove(threshold string) []string {
	r := severityRank(threshold)
	if r == 0 {
		return nil
	}
	var out []string
	for _, name := range severityOrder {
		if severityRanks[name] >= r {
			out = append(out, name)
		}
	}
	return out
}
