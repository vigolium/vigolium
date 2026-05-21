package cli

import (
	"fmt"
	"os"

	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// printAuditDriverCostSummary writes a one-line cost summary of an audit run
// to stderr. Backend-specific detail (main+subagents vs just model) is
// encoded in the Note field so this renderer stays backend-agnostic.
func printAuditDriverCostSummary(c agent.ScanCost) {
	if c.IsZero() {
		return
	}
	dot := terminal.Purple(terminal.SymbolInfo)
	fmt.Fprintf(os.Stderr, "%s Cost: %s %s\n",
		dot,
		terminal.HiTeal(fmt.Sprintf("~$%.2f", c.CostUSD)),
		terminal.Gray(c.Note))
}

// printFindingStats writes a severity breakdown of the imported findings
// to stderr. When the repo is nil, only parse counts are shown (no "imported"
// line) since nothing was persisted. When on-disk parsing yields nothing but
// the audit binary reported findings on its NDJSON stream, falls back to those
// reported counts so the summary mirrors the streamer's `[result]` line.
func printFindingStats(stats agent.FindingStats, persisted bool) {
	flag := terminal.Purple(terminal.SymbolBowtie)

	if stats.Parsed == 0 && stats.Reported > 0 {
		fmt.Fprintf(os.Stderr, "%s Findings: %s reported by audit %s\n",
			flag,
			terminal.HiTeal(fmt.Sprintf("%d", stats.Reported)),
			terminal.Gray("(not imported — findings folder empty)"))
		if breakdown := stats.SeverityBreakdownString(); breakdown != "" {
			fmt.Fprintf(os.Stderr, "  %s %s\n", terminal.Gray(terminal.SymbolDot), breakdown)
		}
		return
	}

	if stats.Parsed == 0 {
		fmt.Fprintf(os.Stderr, "%s Findings: %s\n", flag, terminal.Gray("none parsed"))
		return
	}

	fmt.Fprintf(os.Stderr, "%s Findings: %s parsed%s\n",
		flag,
		terminal.HiTeal(fmt.Sprintf("%d", stats.Parsed)),
		auditSavedSuffix(stats, persisted))

	breakdown := stats.SeverityBreakdownString()
	if breakdown != "" {
		fmt.Fprintf(os.Stderr, "  %s %s\n", terminal.Gray(terminal.SymbolDot), breakdown)
	}
}

func auditSavedSuffix(stats agent.FindingStats, persisted bool) string {
	if !persisted {
		return terminal.Gray(" (db unavailable — not persisted)")
	}
	if stats.Saved == stats.Parsed {
		return terminal.Gray(fmt.Sprintf(", %d imported", stats.Saved))
	}
	return terminal.Yellow(fmt.Sprintf(", %d/%d imported", stats.Saved, stats.Parsed))
}
