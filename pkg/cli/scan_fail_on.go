package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// scanFailOn is the --fail-on threshold. When non-empty, a scan exits non-zero
// if it produced a finding at or above this severity — for CI / coding-agent
// gating. The gate only affects the exit code; all reports and JSON are still
// written first.
var scanFailOn string

// failOnGateTriggered records whether the current scan tripped --fail-on. It is
// set while the findings are in hand (DB still open, or in-memory result) and is
// converted into a non-zero exit at the top-level RunE — after output is written
// — so a tripped gate never suppresses the very findings the agent asked for.
var failOnGateTriggered bool

// resetFailOnGate clears the per-run gate state and validates the threshold,
// returning an error for an unknown severity name. Call once at RunE entry.
func resetFailOnGate() error {
	failOnGateTriggered = false
	if scanFailOn == "" {
		return nil
	}
	scanFailOn = strings.ToLower(strings.TrimSpace(scanFailOn))
	if severitiesAtOrAbove(scanFailOn) == nil {
		return fmt.Errorf("invalid --fail-on %q (want one of: %s)", scanFailOn, strings.Join(severityOrder, ", "))
	}
	return nil
}

// evaluateFailOnGate (DB path) counts findings at or above the threshold for the
// completed scan, scoped to scanUUID when known (precise even on a shared DB)
// and otherwise to the project. Used by the full native-scan pipeline.
func evaluateFailOnGate(repo *database.Repository, projectUUID, scanUUID string, silent bool) {
	if scanFailOn == "" || repo == nil {
		return
	}
	wanted := severitiesAtOrAbove(scanFailOn)
	if wanted == nil {
		return
	}
	n, err := database.NewFindingsQueryBuilder(repo.DB(), database.QueryFilters{
		ProjectUUID: projectUUID,
		ScanUUID:    scanUUID,
		Severity:    wanted,
	}).Count(context.Background())
	if err != nil || n == 0 {
		return
	}
	markFailOnTriggered(int(n), silent)
}

// failOnGateFromEvents (in-memory path) trips the gate when any result event is
// at or above the threshold. Used by the lightweight scan-url / scan-request
// direct path, which holds findings in memory rather than a database.
func failOnGateFromEvents(findings []*output.ResultEvent, silent bool) {
	if scanFailOn == "" {
		return
	}
	threshold := severityRank(scanFailOn)
	if threshold == 0 {
		return
	}
	n := 0
	for _, f := range findings {
		if f != nil && severityRank(f.Info.Severity.String()) >= threshold {
			n++
		}
	}
	if n > 0 {
		markFailOnTriggered(n, silent)
	}
}

func markFailOnTriggered(n int, silent bool) {
	failOnGateTriggered = true
	if !silent {
		fmt.Fprintf(os.Stderr, "  %s Fail-on: %s\n",
			terminal.Purple(terminal.SymbolInfo),
			terminal.BoldRed(fmt.Sprintf("%d finding(s) at or above %q", n, scanFailOn)))
	}
}

// failOnGateError returns a non-nil error when --fail-on tripped, so the scan
// exits non-zero. --soft-fail still forces exit 0 (handled in Execute).
func failOnGateError() error {
	if failOnGateTriggered {
		return fmt.Errorf("--fail-on %s: matching findings were found", scanFailOn)
	}
	return nil
}

// withFailOnGate returns the prior error if non-nil, otherwise the fail-on gate
// result. Lets a RunE that aggregates per-target errors layer the gate on top.
func withFailOnGate(prior error) error {
	if prior != nil {
		return prior
	}
	return failOnGateError()
}
