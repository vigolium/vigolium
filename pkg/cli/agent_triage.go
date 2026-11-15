package cli

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// Maximum bytes of a single captured request or response body embedded into
// the triage prompt. Anything longer is truncated with a marker so the agent
// still sees the start of the message. Matches the swarm triage budget
// (pkg/agent/swarm.go buildSmartHTTPContext) so the two flows stay comparable.
const triageMaxArtifactBytes = 4096

var (
	agentTriageMaxDuration time.Duration
	agentTriageShowPrompt  bool
	agentTriageVerbose     bool
	agentTriageDryRun      bool
	agentTriageNoWrite     bool
	agentTriageNoProbe     bool
	agentTriageOliumFlags  oliumOverrides
	agentTriagePreflight   agentPreflightFlags
)

var agentTriageCmd = &cobra.Command{
	Use:   "triage [finding-id]",
	Short: "Confirm a single finding with an AI triager: confirmed, false_positive or inconclusive",
	Long: `Pick one stored finding and ask an AI agent whether it is a real vulnerability.
The agent reads the finding's description and captured HTTP request/response,
may re-probe the live target using its HTTP tool (not with --no-probe), and
returns a verdict plus reasoning:

  confirmed       status → confirmed; severity unchanged
  false_positive  status → false_positive; severity unchanged (the finding drops
                  out of --fail-on gates and diffs, nothing is lost); the
                  reasoning is appended to the description
  inconclusive    nothing is written: the evidence settled neither way

Every write is recorded in the finding's status history (actor agent-triage)
with the reasoning as its note.

  --no-write     report the verdict, write nothing (alias --report-only)
  --no-probe     offline: no HTTP, browser or shell tools; decide from the capture
  --dry-run      render the prompt only; no LLM call, nothing written

Selection:
  vigolium agent triage 42        # triage finding ID 42
  vigolium agent triage           # open finding picker (TUI), pick one, triage it`,
	Args: cobra.MaximumNArgs(1),
	RunE: runAgentTriage,
}

func init() {
	agentCmd.AddCommand(agentTriageCmd)

	f := agentTriageCmd.Flags()
	f.DurationVar(&agentTriageMaxDuration, "max-duration", 5*time.Minute, "Maximum wall-clock time for the triage run (0 = no limit)")
	f.BoolVar(&agentTriageShowPrompt, "show-prompt", false, "Print rendered prompt to stderr before executing")
	f.BoolVarP(&agentTriageVerbose, "verbose", "v", false, "Show a per-tool head/tail preview of each tool result")
	f.BoolVar(&agentTriageDryRun, "dry-run", false, "Render the triage prompt and exit without calling the agent or writing to DB")
	f.BoolVar(&agentTriageNoWrite, "no-write", false, "Report the verdict without writing it to the finding (no status, description or history change)")
	f.BoolVar(&agentTriageNoWrite, "report-only", false, "Alias for --no-write")
	f.BoolVar(&agentTriageNoProbe, "no-probe", false, "Do not contact the target: the agent gets no HTTP, browser or shell tools and decides from the captured traffic (inconclusive when that cannot settle it)")
	registerOliumOverrideFlags(agentTriageCmd, &agentTriageOliumFlags)
	registerAgentPreflightFlags(agentTriageCmd, &agentTriagePreflight)
}

func runAgentTriage(cmd *cobra.Command, args []string) error {
	// The bash tool's children run against this process's binary, database,
	// project and config (agent_child_env.go).
	installAgentChildEnv()
	defer syncLogger()
	defer closeDatabaseOnExit()

	// The picker is a TUI; a machine caller names the finding.
	if len(args) == 0 {
		if err := requireInteractiveTTY("the agent triage finding picker", "vigolium agent triage <finding-id>"); err != nil {
			return err
		}
	}

	settings, err := clicommon.LoadSettings(globalConfig)
	if err != nil {
		return err
	}
	applyOliumOverrides(settings, &agentTriageOliumFlags)
	agentTriagePreflight.apply(settings)

	db, err := getDBFor(clicommon.IntentWrite)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	ctx := context.Background()
	if cmd != nil && cmd.Context() != nil {
		ctx = cmd.Context()
	}
	repo := database.NewRepository(db)

	projectUUID, _ := resolveProjectUUID()
	finding, err := resolveTriageFinding(ctx, db, repo, projectUUID, args)
	if err != nil {
		return err
	}
	if finding == nil {
		return nil
	}

	records := loadFindingRecords(ctx, repo, finding)

	engine := agent.NewEngine(settings, repo)
	if !agentTriageDryRun {
		if err := agent.ProviderDialCheck(ctx, &settings.Agent.Olium); err != nil {
			return err
		}
	}
	if !agentTriageDryRun && !agentTriagePreflight.skip {
		if err := engine.Preflight(ctx); err != nil {
			return err
		}
	}

	extra := buildTriageExtra(finding, records)
	if agentTriageNoProbe {
		extra["NoProbe"] = "true"
	}
	opts := agent.Options{
		PromptTemplate: agent.TriageConfirmTemplateID,
		TargetURL:      finding.URL,
		Hostname:       finding.Hostname,
		ProjectUUID:    finding.ProjectUUID,
		ShowPrompt:     agentTriageShowPrompt,
		Verbose:        agentTriageVerbose,
		DryRun:         agentTriageDryRun,
		OfflineTools:   agentTriageNoProbe,
		Extra:          extra,
	}

	// Session artifacts and the run row only make sense for a real run;
	// --dry-run is meant to be cheap and side-effect free.
	var sessionDir, runUUID string
	startedAt := time.Now()
	if !agentTriageDryRun {
		runUUID = pinnedOrNewUUID(globalScanUUID)
		var sdErr error
		sessionDir, sdErr = agent.EnsureSessionDir(settings.Agent.EffectiveSessionsDir(), runUUID)
		if sdErr != nil {
			zap.L().Warn("Failed to create session dir", zap.Error(sdErr))
		}
		opts.SessionDir = sessionDir
		if settings.Agent.StreamEnabled() {
			opts.StreamWriter = agentStreamSink()
		}
		if tee, closer := teeToRuntimeLog(opts.StreamWriter, sessionDir); closer != nil {
			opts.StreamWriter = tee
			defer func() { _ = closer.Close() }()
		}
		_, model := settings.Agent.BackendMeta()
		startAgenticScanRow(ctx, repo, &database.AgenticScan{
			UUID:        runUUID,
			ProjectUUID: finding.ProjectUUID,
			ScanUUID:    finding.ScanUUID,
			Mode:        "triage",
			AgentName:   "olium",
			Protocol:    config.AgentProtocolLabel,
			Model:       model,
			TemplateID:  agent.TriageConfirmTemplateID,
			TargetURL:   finding.URL,
			SessionDir:  sessionDir,
			StartedAt:   startedAt,
		})
		printAgentRunHandle(runUUID, sessionDir)
		var stopCancelWatch func()
		ctx, stopCancelWatch = watchAgentCancel(ctx, repo, sessionDir, runUUID)
		defer stopCancelWatch()
	}

	runCtx := ctx
	if agentTriageMaxDuration > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, agentTriageMaxDuration)
		defer cancel()
	}

	result, err := engine.Run(runCtx, opts)
	if err != nil {
		timedOut := errors.Is(err, context.DeadlineExceeded) || errors.Is(runCtx.Err(), context.DeadlineExceeded)
		finishTriageRow(repo, runUUID, startedAt, result, err, timedOut, 0, errors.Is(runCtx.Err(), context.Canceled))
		if timedOut {
			return incompleteErrorf(apicontract.CodeTimedOut, "agent timed out after %s (use --max-duration to adjust or set to 0 to disable)", agentTriageMaxDuration)
		}
		return agentRunFailure(runCtx, err)
	}

	if sessionDir != "" && result.RawOutput != "" {
		if err := os.WriteFile(filepath.Join(sessionDir, "output.md"), []byte(result.RawOutput), 0o644); err != nil {
			zap.L().Debug("failed to write triage output.md", zap.Error(err))
		}
	}

	if agentTriageDryRun {
		if globalJSON {
			return emitMutation(cmd, "", mutationResult{
				Action: "triage",
				DryRun: true,
				Items:  []map[string]any{{"finding_id": finding.ID, "prompt": result.RawOutput}},
			}, withProjectScope(projectUUID))
		}
		fmt.Print(result.RawOutput)
		return nil
	}

	verdict, err := agent.ParseTriageConfirmResult(result.RawOutput)
	if err != nil {
		finishTriageRow(repo, runUUID, startedAt, result, err, false, 0)
		return fmt.Errorf("failed to parse triage verdict from agent output: %w\n\n%s", err, result.RawOutput)
	}

	outcome := planTriageWrite(finding, verdict, agentTriageNoWrite)
	if outcome.Written {
		if err := applyTriageVerdict(ctx, repo, projectUUID, finding, verdict); err != nil {
			finishTriageRow(repo, runUUID, startedAt, result, err, false, 0)
			return fmt.Errorf("failed to persist triage verdict: %w", err)
		}
	}
	finishTriageRow(repo, runUUID, startedAt, result, nil, false, 1)
	outcome.AgenticScanUUID = runUUID

	if globalJSON {
		return emitMutation(cmd, "", mutationResult{
			Changed: outcome.Written,
			Action:  "triage",
			Items:   []triageWriteOutcome{outcome},
			Extra:   map[string]any{"agentic_scan_uuid": runUUID, "session_dir": sessionDir},
			Query:   []string{"finding", "--id", strconv.FormatInt(finding.ID, 10), "-j"},
		}, withProjectScope(projectUUID))
	}
	printTriageVerdict(finding, verdict, outcome)
	return nil
}

// triageWriteOutcome is one row of `agent triage -j`: the verdict and what it
// did (or, under --no-write / for inconclusive, would not do) to the finding.
type triageWriteOutcome struct {
	FindingID       int64  `json:"finding_id"`
	Verdict         string `json:"verdict"`
	Reasoning       string `json:"reasoning"`
	Notes           string `json:"notes,omitempty"`
	OldSeverity     string `json:"old_severity"`
	NewSeverity     string `json:"new_severity"`
	OldStatus       string `json:"old_status"`
	NewStatus       string `json:"new_status"`
	Written         bool   `json:"written"`
	AgenticScanUUID string `json:"agentic_scan_uuid,omitempty"`
}

// triageVerdictStatus is the status a verdict writes; "" for inconclusive,
// which writes nothing.
func triageVerdictStatus(verdict string) string {
	switch verdict {
	case agent.TriageVerdictConfirmed:
		return database.StatusConfirmed
	case agent.TriageVerdictFalsePositive:
		return database.StatusFalsePositive
	}
	return ""
}

// planTriageWrite decides what a verdict changes. Severity never changes: a
// false positive keeps the severity it was reported with, and its status is
// what takes it out of gates and diffs.
func planTriageWrite(finding *database.Finding, verdict *agent.TriageConfirmResult, noWrite bool) triageWriteOutcome {
	out := triageWriteOutcome{
		FindingID:   finding.ID,
		Verdict:     verdict.Verdict,
		Reasoning:   strings.TrimSpace(verdict.Reasoning),
		Notes:       strings.TrimSpace(verdict.Notes),
		OldSeverity: finding.Severity,
		NewSeverity: finding.Severity,
		OldStatus:   finding.Status,
		NewStatus:   finding.Status,
	}
	newStatus := triageVerdictStatus(verdict.Verdict)
	if newStatus == "" || noWrite {
		return out
	}
	out.NewStatus = newStatus
	out.Written = true
	return out
}

// finishTriageRow closes the triage run's agentic_scans row.
func finishTriageRow(repo *database.Repository, uuid string, startedAt time.Time, result *agent.Result, runErr error, timedOut bool, findings int, cancelled ...bool) {
	if uuid == "" {
		return
	}
	end := database.AgenticRunEnd{Err: runErr, TimedOut: timedOut, Cancelled: len(cancelled) > 0 && cancelled[0] && runErr != nil && !timedOut}
	if timedOut {
		end.Err = nil
	}
	dbStatus, _ := agentRunStatus(end)
	fin := agenticScanRowFinish{Status: dbStatus, FindingCount: findings}
	if runErr != nil {
		fin.ErrorMessage = runErr.Error()
	}
	if result != nil {
		fin.Usage = agentRunUsage{InputTokens: int64(result.TokenUsage.InputTokens), OutputTokens: int64(result.TokenUsage.OutputTokens)}
	}
	finishAgenticScanRow(repo, uuid, startedAt, fin)
}

func resolveTriageFinding(ctx context.Context, db *database.DB, repo *database.Repository, projectUUID string, args []string) (*database.Finding, error) {
	if len(args) == 1 {
		id, err := strconv.ParseInt(strings.TrimSpace(args[0]), 10, 64)
		if err != nil {
			return nil, usageErrorf("invalid finding id %q: %w", args[0], err)
		}
		f, err := repo.GetFindingByID(ctx, id)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, codedErrorf(apicontract.CodeFindingNotFound, "no finding with id %d", id)
			}
			return nil, fmt.Errorf("failed to load finding %d: %w", id, err)
		}
		if projectUUID != "" && f.ProjectUUID != projectUUID {
			return nil, fmt.Errorf("finding %d belongs to project %s, not the active project", id, f.ProjectUUID)
		}
		return f, nil
	}

	findings, err := database.NewFindingsQueryBuilder(db, database.QueryFilters{
		ProjectUUID: projectUUID,
		Status:      []string{database.StatusDraft, database.StatusTriaged},
		Limit:       200,
	}).Execute(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list findings: %w", err)
	}
	if len(findings) == 0 {
		fmt.Fprintf(os.Stderr, "%s No findings to triage. Run a scan first, or pass a finding id explicitly.\n", terminal.InfoSymbol())
		return nil, nil
	}

	picked, err := selectFindingFromList(fmt.Sprintf("Select a finding to triage (%d shown)", len(findings)), findings)
	if err != nil || picked == nil {
		return picked, err
	}

	// FindingsQueryBuilder.Execute strips request/response/additional_evidence
	// for table-render performance. Re-fetch the full row so the agent sees
	// the captured HTTP traffic the inline-fallback branch in
	// renderFindingHTTPArtifacts depends on.
	full, err := repo.GetFindingByID(ctx, picked.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to load full finding %d: %w", picked.ID, err)
	}
	return full, nil
}

func buildTriageExtra(finding *database.Finding, records []*database.HTTPRecord) map[string]string {
	extra := map[string]string{
		"FindingID":     strconv.FormatInt(finding.ID, 10),
		"ModuleID":      finding.ModuleID,
		"ModuleName":    finding.ModuleName,
		"Severity":      finding.Severity,
		"Confidence":    finding.Confidence,
		"FindingSource": finding.FindingSource,
		"Description":   strings.TrimSpace(finding.Description),
		"CWE":           finding.CWEID,
		"MatchedAt":     strings.Join(finding.MatchedAt, ", "),
		"HTTPArtifacts": renderFindingHTTPArtifacts(finding, records),
	}
	if len(finding.ExtractedResults) > 0 {
		extra["ExtractedResults"] = strings.Join(finding.ExtractedResults, "\n")
	}
	return extra
}

// renderFindingHTTPArtifacts produces a readable block of the request/response
// pairs associated with a finding. Linked HTTPRecord rows are preferred; we
// fall back to the inline Request/Response strings on the finding itself for
// older / agent-imported findings that never linked records. Bodies are
// truncated to triageMaxArtifactBytes so a chatty target can't blow the
// prompt token budget.
func renderFindingHTTPArtifacts(finding *database.Finding, records []*database.HTTPRecord) string {
	var b strings.Builder
	if len(records) > 0 {
		for i, rec := range records {
			fmt.Fprintf(&b, "### Captured exchange %d/%d\n\n", i+1, len(records))
			writeArtifactBlock(&b, rec.RawRequest)
			if rec.HasResponse && len(rec.RawResponse) > 0 {
				fmt.Fprintf(&b, "Response status: %d (%dms)\n\n", rec.StatusCode, rec.ResponseTimeMs)
				writeArtifactBlock(&b, rec.RawResponse)
			} else {
				b.WriteString("_(no response captured for this exchange)_\n\n")
			}
		}
		return strings.TrimRight(b.String(), "\n")
	}

	if finding.Request == "" && finding.Response == "" {
		return "_(no HTTP request/response captured for this finding)_"
	}
	b.WriteString("### Inline request/response on finding\n\n")
	if finding.Request != "" {
		writeArtifactBlock(&b, []byte(finding.Request))
	}
	if finding.Response != "" {
		writeArtifactBlock(&b, []byte(finding.Response))
	}
	return strings.TrimRight(b.String(), "\n")
}

func writeArtifactBlock(b *strings.Builder, body []byte) {
	if len(body) == 0 {
		return
	}
	b.WriteString("```http\n")
	if len(body) > triageMaxArtifactBytes {
		b.Write(body[:triageMaxArtifactBytes])
		fmt.Fprintf(b, "\n... (truncated, %d more bytes)\n", len(body)-triageMaxArtifactBytes)
	} else {
		b.Write(body)
		if !bytes.HasSuffix(body, []byte{'\n'}) {
			b.WriteByte('\n')
		}
	}
	b.WriteString("```\n\n")
}

// applyTriageVerdict writes the verdict inside projectUUID (the active project;
// "" only when scoping is off), so the write itself carries the project
// predicate rather than relying on the earlier lookup check.
//
// Severity is never changed. A false positive used to be downgraded to info,
// which destroyed the reported severity (nothing could restore it); now its
// status says false_positive — which is what keeps it out of --fail-on gates,
// scan diff and --new-since — and its severity stays as reported. Inconclusive
// writes nothing.
func applyTriageVerdict(ctx context.Context, repo *database.Repository, projectUUID string, finding *database.Finding, verdict *agent.TriageConfirmResult) error {
	// The status write goes through the scoped writer like every other status
	// change, so the verdict carries its actor and reasoning and lands in
	// finding_status_events.
	note := triageStatusNote(verdict)
	switch verdict.Verdict {
	case agent.TriageVerdictFalsePositive:
		newDesc := appendTriageReasoning(finding.Description, verdict)
		if err := repo.UpdateFindingTriage(ctx, projectUUID, finding.ID, finding.Severity, newDesc); err != nil {
			return fmt.Errorf("update triage: %w", err)
		}
		if err := repo.SetFindingStatus(ctx, projectUUID, finding.ID, database.StatusFalsePositive, note, triageStatusActor); err != nil {
			return fmt.Errorf("update status: %w", err)
		}
	case agent.TriageVerdictConfirmed:
		if err := repo.SetFindingStatus(ctx, projectUUID, finding.ID, database.StatusConfirmed, note, triageStatusActor); err != nil {
			return fmt.Errorf("update status: %w", err)
		}
	case agent.TriageVerdictInconclusive:
		return nil
	default:
		return fmt.Errorf("unexpected verdict %q", verdict.Verdict)
	}
	return nil
}

// triageStatusActor is the actor recorded on status changes `agent triage`
// makes.
const triageStatusActor = "agent-triage"

// triageStatusNoteMax bounds the reasoning copied into findings.status_note;
// the full text stays in the description (false positives) and the transcript.
const triageStatusNoteMax = 500

// triageStatusNote is the one-paragraph note stored with a triage verdict.
func triageStatusNote(verdict *agent.TriageConfirmResult) string {
	note := strings.TrimSpace(verdict.Reasoning)
	if note == "" {
		note = strings.TrimSpace(verdict.Notes)
	}
	return clicommon.Truncate(note, triageStatusNoteMax)
}

func appendTriageReasoning(existing string, verdict *agent.TriageConfirmResult) string {
	ts := time.Now().UTC().Format("2006-01-02 15:04 UTC")
	var b strings.Builder
	b.Grow(len(existing) + 256)
	b.WriteString(strings.TrimRight(existing, "\n"))
	b.WriteString("\n\n---\n## Agent Triage (")
	b.WriteString(ts)
	b.WriteString(")\n\nVerdict: false_positive (severity kept as reported).\n\n")
	if reasoning := strings.TrimSpace(verdict.Reasoning); reasoning != "" {
		b.WriteString(reasoning)
		b.WriteByte('\n')
	}
	if notes := strings.TrimSpace(verdict.Notes); notes != "" {
		b.WriteString("\nNotes: ")
		b.WriteString(notes)
		b.WriteByte('\n')
	}
	return b.String()
}

func printTriageVerdict(finding *database.Finding, verdict *agent.TriageConfirmResult, outcome triageWriteOutcome) {
	fmt.Println()
	fmt.Printf("%s Finding #%d — %s\n", terminal.InfoSymbol(), finding.ID, finding.ModuleName)

	switch verdict.Verdict {
	case agent.TriageVerdictFalsePositive:
		fmt.Printf("  Verdict:  %s\n", terminal.BoldYellow(agent.TriageVerdictFalsePositive))
	case agent.TriageVerdictConfirmed:
		fmt.Printf("  Verdict:  %s\n", terminal.BoldRed(agent.TriageVerdictConfirmed))
	case agent.TriageVerdictInconclusive:
		fmt.Printf("  Verdict:  %s\n", terminal.Gray(agent.TriageVerdictInconclusive))
	}
	fmt.Printf("  Severity: %s (unchanged)\n", clicommon.ColorSeverity(finding.Severity))
	switch {
	case outcome.Written:
		fmt.Printf("  Status:   %s → %s\n", clicommon.ValueOrNone(outcome.OldStatus), terminal.BoldGreen(outcome.NewStatus))
	case verdict.Verdict == agent.TriageVerdictInconclusive:
		fmt.Printf("  Status:   %s (inconclusive: nothing written)\n", clicommon.ValueOrNone(outcome.OldStatus))
	default:
		fmt.Printf("  Status:   %s (--no-write: would be %s)\n", clicommon.ValueOrNone(outcome.OldStatus), triageVerdictStatus(verdict.Verdict))
	}

	if reasoning := strings.TrimSpace(verdict.Reasoning); reasoning != "" {
		fmt.Println()
		fmt.Println(terminal.Gray("  Reasoning:"))
		for _, line := range strings.Split(reasoning, "\n") {
			fmt.Printf("    %s\n", line)
		}
	}
	if notes := strings.TrimSpace(verdict.Notes); notes != "" {
		fmt.Println()
		fmt.Println(terminal.Gray("  Notes:"))
		for _, line := range strings.Split(notes, "\n") {
			fmt.Printf("    %s\n", line)
		}
	}
	fmt.Println()
}
