package smart_behavior_detection

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/modules/shared/diffscan"
)

// attackPair represents a break/escape attack pair for reporting.
type attackPair struct {
	ProbeName     string
	BreakPayload  string
	BreakStatus   int
	BreakLength   int
	EscapePayload string
	EscapeStatus  int
	EscapeLength  int
}

// generateMarkdownReport creates a markdown table report from attack results.
func generateMarkdownReport(attacks []*diffscan.Attack, paramName string) string {
	if len(attacks) == 0 {
		return ""
	}

	pairs := extractAttackPairs(attacks)
	if len(pairs) == 0 {
		return ""
	}

	var sb strings.Builder

	// Header
	fmt.Fprintf(&sb, "## Smart Behavior Detection - %s\n\n", paramName)

	// Group by probe name
	probeGroups := groupByProbeName(pairs)

	for probeName, groupedPairs := range probeGroups {
		fmt.Fprintf(&sb, "### %s\n\n", probeName)
		sb.WriteString("| Type | Payload | Status | Content Length |\n")
		sb.WriteString("|------|---------|--------|----------------|\n")

		for i, pair := range groupedPairs {
			// Break row
			fmt.Fprintf(&sb,
				"| break %d | `%s` | %d | %d |\n",
				i+1,
				escapeMarkdown(pair.BreakPayload),
				pair.BreakStatus,
				pair.BreakLength,
			)
			// Escape row
			fmt.Fprintf(&sb,
				"| escape %d | `%s` | %d | %d |\n",
				i+1,
				escapeMarkdown(pair.EscapePayload),
				pair.EscapeStatus,
				pair.EscapeLength,
			)
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// extractAttackPairs converts attack list to pairs (break, escape).
func extractAttackPairs(attacks []*diffscan.Attack) []attackPair {
	var pairs []attackPair

	for i := 0; i < len(attacks); i += 2 {
		breakAttack := attacks[i]
		if i+1 >= len(attacks) {
			break
		}
		escapeAttack := attacks[i+1]

		if breakAttack == nil || escapeAttack == nil {
			continue
		}

		// Skip WAF-blocked attacks
		if breakAttack.FirstSnapshot != nil && breakAttack.FirstSnapshot.WafBlocked() {
			continue
		}
		if escapeAttack.FirstSnapshot != nil && escapeAttack.FirstSnapshot.WafBlocked() {
			continue
		}

		pair := attackPair{
			ProbeName:     breakAttack.Probe.Name,
			BreakPayload:  breakAttack.Payload,
			EscapePayload: escapeAttack.Payload,
		}

		if breakAttack.FirstSnapshot != nil {
			pair.BreakStatus = breakAttack.FirstSnapshot.StatusCode
			pair.BreakLength = breakAttack.FirstSnapshot.ContentLength
		}
		if escapeAttack.FirstSnapshot != nil {
			pair.EscapeStatus = escapeAttack.FirstSnapshot.StatusCode
			pair.EscapeLength = escapeAttack.FirstSnapshot.ContentLength
		}

		pairs = append(pairs, pair)
	}

	return pairs
}

// groupByProbeName groups attack pairs by probe name.
func groupByProbeName(pairs []attackPair) map[string][]attackPair {
	groups := make(map[string][]attackPair)
	for _, pair := range pairs {
		groups[pair.ProbeName] = append(groups[pair.ProbeName], pair)
	}
	return groups
}

// escapeMarkdown escapes markdown special characters.
func escapeMarkdown(s string) string {
	s = strings.ReplaceAll(s, "`", "\\`")
	s = strings.ReplaceAll(s, "|", "\\|")
	return s
}

// getBestSeverity finds the highest severity from attack results.
func getBestSeverity(attacks []*diffscan.Attack) int {
	bestSeverity := 0
	for _, att := range attacks {
		if att != nil && att.Probe != nil && att.Probe.Severity > bestSeverity {
			bestSeverity = att.Probe.Severity
		}
	}
	return bestSeverity
}
