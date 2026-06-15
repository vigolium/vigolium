package cli

import "strings"

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
