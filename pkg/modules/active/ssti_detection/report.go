package ssti_detection

import (
	"fmt"
	"sort"
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
	// DiffSignal lists the response-fingerprint attribute(s) that actually
	// differed between the break and escape responses — i.e. the evidence the
	// detection fired on. Surfacing it lets a triager see why the finding was
	// raised even when the visible columns (status, length) look identical.
	DiffSignal string
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
	fmt.Fprintf(&sb, "## SSTI Detection - %s\n\n", paramName)

	// Group by probe name
	probeGroups := groupByProbeName(pairs)

	for probeName, groupedPairs := range probeGroups {
		fmt.Fprintf(&sb, "### %s\n\n", probeName)
		sb.WriteString("| Type | Payload | Status | Content Length | Diff Signal |\n")
		sb.WriteString("|------|---------|--------|----------------|-------------|\n")

		for i, pair := range groupedPairs {
			signal := pair.DiffSignal
			if signal == "" {
				signal = "—"
			}
			// Break row
			fmt.Fprintf(&sb,
				"| break %d | `%s` | %d | %d | %s |\n",
				i+1,
				escapeMarkdown(pair.BreakPayload),
				pair.BreakStatus,
				pair.BreakLength,
				signal,
			)
			// Escape row
			fmt.Fprintf(&sb,
				"| escape %d | `%s` | %d | %d | %s |\n",
				i+1,
				escapeMarkdown(pair.EscapePayload),
				pair.EscapeStatus,
				pair.EscapeLength,
				signal,
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
		pair.DiffSignal = diffSignal(breakAttack, escapeAttack)

		pairs = append(pairs, pair)
	}

	return pairs
}

// diffSignal returns a sorted, comma-joined list of the response-fingerprint
// attributes that differed between the break and escape responses. This is the
// concrete evidence the detection fired on (e.g. "status_code, whole_body_content").
//
// It compares the merged (stable) fingerprints rather than the last single
// sample, so the reported signal is the one that actually survived every
// confirmation and drove the decision — not a transient last-request artifact
// (e.g. a header that only jittered on the final probe).
func diffSignal(breakAttack, escapeAttack *diffscan.Attack) string {
	keys := diffscan.GetMergedNonMatchingFingerprints(breakAttack, escapeAttack)
	if len(keys) == 0 {
		return ""
	}
	names := make([]string, 0, len(keys))
	for k := range keys {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
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
