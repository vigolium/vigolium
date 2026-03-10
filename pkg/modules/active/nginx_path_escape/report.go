package nginx_path_escape

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/modules/shared/diffscan"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// finding represents a detected Nginx path escape vulnerability.
type finding struct {
	ProbeInfo    *ProbeInfo
	BreakAttack  *diffscan.Attack
	EscapeAttack *diffscan.Attack
	SegmentPath  string // Path segment where vulnerability was found (e.g., "/static")
	SegmentIndex int    // Index of segment (0 = first segment)
}

// generateReport creates a markdown report from findings.
func generateReport(findings []*finding, urlPath string) string {
	if len(findings) == 0 {
		return ""
	}

	var sb strings.Builder

	fmt.Fprintf(&sb, "## Nginx Path Escape Detection - %s\n\n", urlPath)

	sb.WriteString("| ID | Probe | Segment | Break Payload | Status | Length | Escape Payload | Status | Length |\n")
	sb.WriteString("|-----|-------|---------|---------------|--------|--------|----------------|--------|--------|\n")

	for _, f := range findings {
		breakStatus, breakLength := getResponseInfo(f.BreakAttack)
		escapeStatus, escapeLength := getResponseInfo(f.EscapeAttack)

		segmentDisplay := f.SegmentPath
		if segmentDisplay == "" {
			segmentDisplay = urlPath
		}

		fmt.Fprintf(&sb,
			"| %s | %s | `%s` | `%s` | %d | %d | `%s` | %d | %d |\n",
			f.ProbeInfo.ID,
			f.ProbeInfo.Name,
			escapeMarkdown(segmentDisplay),
			escapeMarkdown(f.BreakAttack.Payload),
			breakStatus,
			breakLength,
			escapeMarkdown(f.EscapeAttack.Payload),
			escapeStatus,
			escapeLength,
		)
	}
	sb.WriteString("\n")

	sb.WriteString("**Findings:**\n\n")
	for _, f := range findings {
		segmentInfo := ""
		if f.SegmentPath != "" {
			segmentInfo = fmt.Sprintf(" at segment `%s`", f.SegmentPath)
		}
		fmt.Fprintf(&sb, "- **%s (%s)%s**: %s\n", f.ProbeInfo.ID, f.ProbeInfo.Name, segmentInfo, f.ProbeInfo.Description)
	}
	sb.WriteString("\n")

	return sb.String()
}

// getResponseInfo extracts status code and content length from an attack.
func getResponseInfo(attack *diffscan.Attack) (int, int) {
	if attack == nil || attack.FirstSnapshot == nil {
		return 0, 0
	}
	return attack.FirstSnapshot.StatusCode, attack.FirstSnapshot.ContentLength
}

// escapeMarkdown escapes markdown special characters.
func escapeMarkdown(s string) string {
	s = strings.ReplaceAll(s, "`", "\\`")
	s = strings.ReplaceAll(s, "|", "\\|")
	return s
}

// getBestSeverity returns the highest severity from findings.
func getBestSeverity(findings []*finding) severity.Severity {
	bestSeverity := 0
	for _, f := range findings {
		if f.ProbeInfo.Probe != nil && f.ProbeInfo.Probe.Severity > bestSeverity {
			bestSeverity = f.ProbeInfo.Probe.Severity
		}
	}
	return intToSeverity(bestSeverity)
}

// intToSeverity converts probe severity int to severity.Severity.
// Capped at medium to match the module's declared severity.
func intToSeverity(sev int) severity.Severity {
	switch {
	case sev >= 4:
		return severity.Medium
	default:
		return severity.Low
	}
}
