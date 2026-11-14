package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/vigolium/vigolium/pkg/apicontract"
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

// scanFailOnPartial is --fail-on-partial: exit 5 (incomplete) when the scan's
// coverage was partial. --fail-on implies it: a CI gate that goes green on a
// scan that never ran half its phases is not a gate.
var scanFailOnPartial bool

// partialGateReason is set, per run, when the finished scan's coverage was
// partial (its reasons, comma-joined); "" when complete or unknown.
var partialGateReason string

// notePartialCompletion records a partial completion for the partial gate.
func notePartialCompletion(scanUUID string, reasons []string) {
	reason := strings.Join(reasons, ", ")
	if reason == "" {
		reason = "partial coverage"
	}
	if scanUUID != "" {
		reason = scanUUID + ": " + reason
	}
	if partialGateReason == "" {
		partialGateReason = reason
	} else if !strings.Contains(partialGateReason, reason) {
		partialGateReason += "; " + reason
	}
}

// partialGateArmed reports whether a partial completion fails the run.
func partialGateArmed() bool { return scanFailOnPartial || scanFailOn != "" }

// evaluatePartialGate reads the finished scan row's completeness (DB path).
func evaluatePartialGate(repo *database.Repository, scanUUID string) {
	if !partialGateArmed() || repo == nil || scanUUID == "" {
		return
	}
	scan, err := repo.GetScanByUUID(context.Background(), scanUUID)
	if err != nil || scan == nil || scan.Completeness != database.CompletenessPartial {
		return
	}
	notePartialCompletion(scanUUID, unionPhaseReasons(scan.PhaseOutcomes))
}

// resetFailOnGate clears the per-run gate state and validates the threshold,
// returning an error for an unknown severity name. Call once at RunE entry.
func resetFailOnGate() error {
	failOnGateTriggered = false
	partialGateReason = ""
	if scanFailOn == "" {
		return nil
	}
	scanFailOn = strings.ToLower(strings.TrimSpace(scanFailOn))
	if severitiesAtOrAbove(scanFailOn) == nil {
		return usageErrorf("invalid --fail-on %q (want one of: %s)", scanFailOn, strings.Join(severityOrder, ", "))
	}
	return nil
}

// evaluateFailOnGate (DB path) counts findings at or above the threshold for the
// completed scan, scoped to scanUUID when known (precise even on a shared DB)
// and otherwise to the project. Used by the full native-scan pipeline.
//
// Findings an operator or agent dismissed (`finding mark --as false_positive`
// or accepted_risk) do not count: a re-detection keeps its verdict, and a CI
// gate that keeps failing on a finding someone already ruled out teaches people
// to ignore the gate.
func evaluateFailOnGate(repo *database.Repository, projectUUID, scanUUID string, silent bool) {
	if scanFailOn == "" || repo == nil {
		return
	}
	wanted := severitiesAtOrAbove(scanFailOn)
	if wanted == nil {
		return
	}
	n, err := database.NewFindingsQueryBuilder(repo.DB(), database.QueryFilters{
		ProjectUUID:     projectUUID,
		ObservedInScan:  scanUUID,
		Severity:        wanted,
		ExcludeStatuses: database.DismissedFindingStatuses,
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

// withoutDismissed drops the events whose stored finding carries a dismissed
// verdict, so the in-memory gate agrees with the DB gate: a re-detection of a
// finding marked false_positive/accepted_risk keeps its verdict and does not
// trip --fail-on. With no store (or a failed lookup) the events pass through
// unchanged — the gate errs toward failing, never toward a silent pass.
func withoutDismissed(ctx context.Context, repo *database.Repository, projectUUID string, events []*output.ResultEvent) []*output.ResultEvent {
	if scanFailOn == "" || repo == nil || len(events) == 0 {
		return events
	}
	hashes := make([]string, 0, len(events))
	for _, e := range events {
		if e != nil {
			hashes = append(hashes, e.ID())
		}
	}
	// By live hash or by alias (a pre-identity-v2 hash, or a merged duplicate's).
	skip, err := repo.DismissedFindingHashes(ctx, projectUUID, hashes)
	if err != nil || len(skip) == 0 {
		return events
	}
	kept := make([]*output.ResultEvent, 0, len(events))
	for _, e := range events {
		if e != nil && !skip[e.ID()] {
			kept = append(kept, e)
		}
	}
	return kept
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
//
// Wrapped as a gateError so Execute exits 4 rather than 1: a scan that ran
// cleanly and found a high-severity finding is the OPPOSITE outcome from a scan
// that failed to start, and a consumer that cannot tell them apart either
// ignores real breakage or treats every finding as an outage.
func failOnGateError() error {
	if failOnGateTriggered {
		//vigolium:not-usage gate result (exit 4), not a usage error
		return gateError{err: fmt.Errorf("--fail-on %s: matching findings were found", scanFailOn)}
	}
	return nil
}

// withFailOnGate returns the prior error if non-nil, otherwise the fail-on gate
// result, otherwise the partial gate's. Lets a RunE that aggregates per-target
// errors layer the gates on top. Precedence: error (1) > --fail-on gate (4) >
// incomplete (5): a crash outranks findings, and findings outrank a coverage
// gap, because each is the more actionable answer.
func withFailOnGate(prior error) error {
	if prior != nil {
		return prior
	}
	if err := failOnGateError(); err != nil {
		return err
	}
	if partialGateArmed() && partialGateReason != "" {
		return incompleteErrorf(apicontract.CodePartial, "scan coverage was partial (%s); --fail-on-partial", partialGateReason)
	}
	return nil
}
