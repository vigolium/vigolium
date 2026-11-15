package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/piolium"
	"github.com/vigolium/vigolium/pkg/scanevents"
	"go.uber.org/zap"
)

// The agent run document: what `agent autopilot`, `agent swarm` and
// `agent audit` (`audit`) print under -j.
//
// It replaces a bare summary map that was written only when the run had a
// database (a `-S`-less run whose store failed to open printed nothing at all),
// hard-coded swarm's status to "completed", and reported a timed-out autopilot
// as "timed_out" while the agentic_scans row said "failed". Now:
//
//   - it is an envelope of kind "scan" with the scan document's spine (status,
//     completeness, stop_reason, counts_by_severity, total, items, persisted,
//     errors, query), so a driver reads an agent run the way it reads a scan;
//   - it is always written once the run started: with no store it says
//     persisted:false and reports what it holds in memory, and a session dir
//     that could not be created is listed in errors[];
//   - the database status and the JSON status come from one function,
//     agentRunStatus, so they cannot disagree;
//   - a run that ran but stopped short exits 5 (timed_out, budget_exhausted,
//     partial) after the document is written — see agentRunExitError.
//
// Status vocabulary (documented once, in docs/coding-agent.md):
//
//	DB status                JSON status              completeness  stop_reason       exit
//	completed                completed                complete      -                 0
//	completed_with_warnings  completed_with_warnings  complete      -                 0
//	completed_with_errors    completed_with_errors    partial       partial           5
//	timeout                  timed_out                partial       timed_out         5
//	budget_exhausted         budget_exhausted         partial       budget_exhausted  5
//	cancelled                cancelled                partial       interrupted       1
//	failed                   failed                   partial       -                 1

const (
	agentRunTopFindings = 20  // findings embedded in items
	agentRunScanCap     = 500 // rows fetched to rank them
)

// agentStreamSink returns the writer for an agent run's live output: stderr
// under --json (stdout is reserved for the run document), otherwise stdout.
// Every agent command routes its stream through here; a test walks pkg/cli
// and rejects any other StreamWriter assignment (TestAgentStreamSinkUsedEverywhere).
func agentStreamSink() io.Writer { return humanOut() }

// agentRunStatus maps how a run ended to its agentic_scans.status and to the
// status the run document reports. They differ in one spelling only: the
// database's "timeout" is the document's "timed_out", the exit-5 code name.
func agentRunStatus(end database.AgenticRunEnd) (dbStatus, jsonStatus string) {
	dbStatus = database.AgenticRunStatus(end)
	return dbStatus, agentRunJSONStatus(dbStatus)
}

// agentRunJSONStatus is the document spelling of a database status.
func agentRunJSONStatus(dbStatus string) string {
	if dbStatus == database.AgenticScanStatusTimeout {
		return string(apicontract.CodeTimedOut)
	}
	return dbStatus
}

// agentRunStopReason is the document's stop_reason for a JSON status, "" for a
// run that finished or failed outright.
func agentRunStopReason(jsonStatus string) string {
	switch jsonStatus {
	case string(apicontract.CodeTimedOut), string(apicontract.CodeBudgetExhausted):
		return jsonStatus
	case "completed_with_errors":
		return string(apicontract.CodePartial)
	case database.AgenticScanStatusCancelled:
		return scanevents.StatusInterrupted
	}
	return ""
}

// agentRunCompleteness is complete for a run that ran to its end.
func agentRunCompleteness(jsonStatus string) string {
	for _, s := range database.CompletedAgenticScanStatuses {
		if s == jsonStatus && s != "completed_with_errors" {
			return database.CompletenessComplete
		}
	}
	return database.CompletenessPartial
}

// agentRunExitError is the exit-5 result for a run that ran but stopped short,
// nil otherwise. Returned AFTER the document (or human summary) is written:
// like the --fail-on gate it is a completed result, not a failure.
func agentRunExitError(jsonStatus, uuid, detail string) error {
	var code apicontract.ErrorCode
	switch jsonStatus {
	case string(apicontract.CodeTimedOut):
		code = apicontract.CodeTimedOut
	case string(apicontract.CodeBudgetExhausted):
		code = apicontract.CodeBudgetExhausted
	case "completed_with_errors":
		code = apicontract.CodePartial
	default:
		return nil
	}
	if detail == "" {
		detail = jsonStatus
	}
	return incompleteErrorf(code, "agent run %s stopped short: %s", uuid, detail)
}

// agentRunBudget is the document's budget{}: the caps the run was given and
// whether one of them stopped it.
type agentRunBudget struct {
	MaxCommands   int     `json:"max_commands"`
	TokenBudget   int64   `json:"token_budget"`
	MaxCostUSD    float64 `json:"max_cost_usd"`
	MaxDurationMS int64   `json:"max_duration_ms"`
	Exhausted     bool    `json:"exhausted"`
	// Stop names the cap that fired: commands, tokens, cost or wall_time.
	Stop string `json:"stop,omitempty"`
}

// agentRunUsage is the document's usage{}.
type agentRunUsage struct {
	InputTokens  int64   `json:"input_tokens"`
	OutputTokens int64   `json:"output_tokens"`
	CostUSD      float64 `json:"cost_usd"`
}

// agentRunError is one entry of errors[].
type agentRunError struct {
	Code    apicontract.ErrorCode `json:"code"`
	Message string                `json:"message"`
}

// agentAuditHarness echoes which nested audit harness the run launched
// (autopilot / swarm --audit, --piolium): mode "off" when none did. Harness
// and AgentCLI are set only when one ran: harness "audit" or "piolium", and
// agent_cli the coding-agent CLI it launched (claude, codex or pi).
type agentAuditHarness struct {
	Mode     string `json:"mode"`
	Piolium  string `json:"piolium,omitempty"`
	Harness  string `json:"harness,omitempty"`
	AgentCLI string `json:"agent_cli,omitempty"`
}

// newAgentAuditHarness builds the run document's audit_harness echo from the
// resolved --audit / --piolium modes and the harness that was picked (zero
// HarnessSpec when none runs).
func newAgentAuditHarness(auditMode, pioliumMode string, cfg *config.AuditAgentConfig, harness agent.HarnessSpec) *agentAuditHarness {
	if pioliumMode == "off" {
		pioliumMode = ""
	}
	doc := &agentAuditHarness{Mode: firstNonEmptyString(auditMode, "off"), Piolium: pioliumMode}
	if cfg == nil {
		return doc
	}
	doc.Harness = harness.Name
	doc.AgentCLI = auditHarnessAgentCLI(harness)
	return doc
}

// auditHarnessAgentCLI names the coding-agent CLI a nested harness launches:
// pi for piolium; claude for vigolium-audit, whose default --agent is used
// when the run passes no driver invocation (autopilot and swarm never do).
func auditHarnessAgentCLI(harness agent.HarnessSpec) string {
	if harness.Name == piolium.HarnessName {
		return "pi"
	}
	return string(agent.AuditDriverAgentClaude)
}

// agentRunOutcome is everything the run document reports.
type agentRunOutcome struct {
	Command         string // cobra path without root, e.g. "agent autopilot"
	Mode            string // autopilot | swarm | audit
	AgenticScanUUID string
	ProjectUUID     string
	SessionDir      string
	Provider        string
	Model           string
	Repo            *database.Repository
	End             database.AgenticRunEnd
	HaltReason      string
	Usage           agentRunUsage
	Budget          agentRunBudget
	AuditHarness    *agentAuditHarness
	// FindingCount is the in-memory finding total, reported when there is no
	// store to count from.
	FindingCount int64
	Errors       []agentRunError
	Warnings     []string
	StartedAt    time.Time
}

// addError appends an errors[] entry classified like the root's error envelope.
func (o *agentRunOutcome) addError(err error) {
	if o == nil || err == nil {
		return
	}
	o.Errors = append(o.Errors, agentRunError{Code: classifyErrorCode(err, classifyExitCode(err)), Message: err.Error()})
}

// emitAgentRunDocument writes the run document under -j (a no-op otherwise)
// and returns the run's exit-5 result, if any, for the caller to return. The
// document is written at most once per invocation (writeAgentJSON latches).
func emitAgentRunDocument(o *agentRunOutcome) error {
	_, jsonStatus := agentRunStatus(o.End)
	if globalJSON && !jsonResultEmitted {
		if err := writeAgentJSON(agentRunEnvelope(o)); err != nil {
			return err
		}
	}
	detail := o.Budget.Stop
	if o.HaltReason != "" {
		detail = o.HaltReason
	}
	return agentRunExitError(jsonStatus, o.AgenticScanUUID, detail)
}

// agentRunEnvelope builds the document.
func agentRunEnvelope(o *agentRunOutcome) *agentEnvelope {
	_, jsonStatus := agentRunStatus(o.End)
	ctx := context.Background()

	counts := map[string]int64{}
	for _, sev := range severityOrder {
		counts[sev] = 0
	}
	total := o.FindingCount
	items := []map[string]any{}
	persisted := o.Repo != nil && o.AgenticScanUUID != "" && !globalStateless
	if o.Repo != nil && o.AgenticScanUUID != "" {
		db := o.Repo.DB()
		uuids := resolveAgenticScanTree(ctx, db, o.AgenticScanUUID)
		if byScan, err := database.CountFindingsByAgenticScans(ctx, db, uuids); err == nil {
			total = 0
			for sev, n := range byScan {
				counts[sev] += n
				total += n
			}
		} else {
			o.addError(fmt.Errorf("count findings: %w", err))
		}
		findings, err := database.NewFindingsQueryBuilder(db, database.QueryFilters{
			ProjectUUID:      o.ProjectUUID,
			AgenticScanUUIDs: uuids,
			Limit:            agentRunScanCap,
			SortBy:           "found_at",
		}).Execute(ctx)
		if err != nil {
			o.addError(fmt.Errorf("read findings: %w", err))
		}
		sort.SliceStable(findings, func(i, j int) bool {
			return severityRank(findings[i].Severity) > severityRank(findings[j].Severity)
		})
		if len(findings) > agentRunTopFindings {
			findings = findings[:agentRunTopFindings]
		}
		for _, f := range findings {
			items = append(items, compactFindingView(f, nil, agentViewOptions{redact: jsonRedactOn}))
		}
	}

	command := o.Command
	if command == "" {
		command = "agent " + o.Mode
	}
	env := newAgentEnvelope(command, "top_findings", items, total, 0, agentRunTopFindings)
	env.Kind = string(kindScan)
	env.WithProjectScope(o.ProjectUUID)
	if persisted {
		env.WithQuery("finding", "--agentic-scan", o.AgenticScanUUID, "-j")
		env.DBPath = resolvedReadDBPath()
	}

	errs := o.Errors
	if errs == nil {
		errs = []agentRunError{}
	}
	warnings := o.Warnings
	if warnings == nil {
		warnings = []string{}
	}
	now := time.Now()
	started := o.StartedAt
	if started.IsZero() {
		started = now
	}
	env.With("agentic_scan_uuid", o.AgenticScanUUID).
		With("mode", o.Mode).
		With("session_dir", o.SessionDir).
		With("status", jsonStatus).
		With("completeness", agentRunCompleteness(jsonStatus)).
		With("persisted", persisted).
		With("stateless", globalStateless).
		With("provider", o.Provider).
		With("model", o.Model).
		With("usage", o.Usage).
		With("budget", o.Budget).
		With("counts_by_severity", counts).
		With("items_truncated", total > int64(len(items))).
		With("errors", errs).
		With("warnings", warnings).
		With("duration_ms", now.Sub(started).Milliseconds()).
		With("started_at", agentTimestamp(started)).
		With("finished_at", agentTimestamp(now))
	if sr := agentRunStopReason(jsonStatus); sr != "" {
		env.With("stop_reason", sr)
	}
	if o.HaltReason != "" {
		env.With("halt_reason", o.HaltReason)
	}
	if o.AuditHarness != nil {
		env.With("audit_harness", o.AuditHarness)
	}
	return env
}

// resolveAgenticScanTree returns the root agentic-scan UUID plus any direct
// child runs (audit driver legs, swarm sub-runs link via parent_run_uuid), so a
// single root UUID resolves every finding the run produced regardless of which
// leaf scan recorded it.
func resolveAgenticScanTree(ctx context.Context, db *database.DB, root string) []string {
	uuids := []string{root}
	if db == nil || root == "" {
		return uuids
	}
	var children []string
	_ = db.NewSelect().Model((*database.AgenticScan)(nil)).
		Column("uuid").
		Where("parent_run_uuid = ?", root).
		Scan(ctx, &children)
	return append(uuids, children...)
}

// startAgenticScanRow inserts the "running" agentic_scans row a run is tracked
// by (`agent session`, `log ls`, `finding --agentic-scan`). A nil repo or empty
// UUID is a no-op; a failed insert is logged, never fatal — the run itself
// does not depend on its bookkeeping row.
func startAgenticScanRow(ctx context.Context, repo *database.Repository, row *database.AgenticScan) {
	if row != nil {
		noteAgentRun(row.UUID)
	}
	if repo == nil || row == nil || row.UUID == "" {
		return
	}
	if row.Status == "" {
		row.Status = "running"
	}
	if row.StartedAt.IsZero() {
		row.StartedAt = time.Now()
	}
	if row.SourceType == "" && row.SourcePath != "" {
		row.SourceType = database.InferSourceType(row.SourcePath)
	}
	if err := repo.CreateAgenticScan(context.WithoutCancel(ctx), row); err != nil {
		zap.L().Debug("Failed to create AgenticScan row", zap.String("mode", row.Mode), zap.Error(err))
	}
}

// agenticScanRowFinish carries the closing columns of a run's row.
type agenticScanRowFinish struct {
	Status       string
	ErrorMessage string
	FindingCount int
	SavedCount   int
	Usage        agentRunUsage
}

// finishAgenticScanRow closes a row started by startAgenticScanRow with its
// final status (from agentRunStatus), duration, counts and usage.
func finishAgenticScanRow(repo *database.Repository, uuid string, startedAt time.Time, f agenticScanRowFinish) {
	if repo == nil || uuid == "" {
		return
	}
	now := time.Now()
	q := repo.DB().NewUpdate().Model((*database.AgenticScan)(nil)).
		Set("status = ?", f.Status).
		Set("completed_at = ?", now).
		Set("duration_ms = ?", now.Sub(startedAt).Milliseconds()).
		Set("finding_count = ?", f.FindingCount).
		Set("saved_count = ?", f.SavedCount).
		Where("uuid = ?", uuid)
	if f.ErrorMessage != "" {
		q = q.Set("error_message = ?", f.ErrorMessage)
	}
	if f.Usage.InputTokens > 0 || f.Usage.OutputTokens > 0 {
		q = q.Set("total_input_tokens = ?", f.Usage.InputTokens).
			Set("total_output_tokens = ?", f.Usage.OutputTokens).
			Set("estimated_cost_usd = ?", f.Usage.CostUSD)
	}
	if _, err := q.Exec(context.Background()); err != nil {
		zap.L().Debug("Failed to finalize AgenticScan row", zap.String("uuid", uuid), zap.Error(err))
	}
}

// printAgentRunHandle prints a run's UUID and session dir to stderr, so a run
// that has no human summary of its own (query, triage) can still be found
// with `agent session <uuid>` and `log <uuid>`.
func printAgentRunHandle(uuid, sessionDir string) {
	if uuid == "" || globalSilent {
		return
	}
	if sessionDir != "" {
		fmt.Fprintf(os.Stderr, "agentic_scan_uuid=%s session_dir=%s (vigolium log %s)\n", uuid, sessionDir, uuid)
		return
	}
	fmt.Fprintf(os.Stderr, "agentic_scan_uuid=%s (vigolium agent session %s)\n", uuid, uuid)
}
