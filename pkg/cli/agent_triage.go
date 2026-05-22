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

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
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
	agentTriageOliumFlags  oliumOverrides
)

var agentTriageCmd = &cobra.Command{
	Use:   "triage [finding-id]",
	Short: "Confirm a single finding with an AI triager; downgrade severity to info on false_positive",
	Long: `Pick one stored finding and ask an AI agent to confirm whether it is a real
vulnerability or a false positive. The agent reads the finding's description and
captured HTTP request/response, may re-probe the live target using its HTTP tool,
and returns a verdict plus reasoning.

If the verdict is false_positive, the finding's severity is downgraded to "info"
and the reasoning is appended to its description so the original detection
context is preserved.

If the verdict is confirmed, the finding's status is set to "triaged"; severity
is left untouched.

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
	registerOliumOverrideFlags(agentTriageCmd, &agentTriageOliumFlags)
}

func runAgentTriage(cmd *cobra.Command, args []string) error {
	defer syncLogger()
	defer closeDatabaseOnExit()

	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		zap.L().Warn("Failed to load settings, using defaults", zap.Error(err))
		settings = config.DefaultSettings()
	}
	applyOliumOverrides(settings, &agentTriageOliumFlags)

	db, err := getDB()
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	ctx := context.Background()
	if schemaErr := db.CreateSchema(ctx); schemaErr != nil {
		zap.L().Warn("Failed to ensure schema", zap.Error(schemaErr))
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
		if err := engine.Preflight(""); err != nil {
			return fmt.Errorf("agent preflight failed: %w", err)
		}
	}

	opts := agent.Options{
		PromptTemplate: agent.TriageConfirmTemplateID,
		TargetURL:      finding.URL,
		Hostname:       finding.Hostname,
		ProjectUUID:    finding.ProjectUUID,
		ShowPrompt:     agentTriageShowPrompt,
		Verbose:        agentTriageVerbose,
		DryRun:         agentTriageDryRun,
		Extra:          buildTriageExtra(finding, records),
	}

	// Session artifacts only make sense for a real run; --dry-run is meant to
	// be cheap and side-effect free, so skip the session-dir machinery.
	var sessionDir string
	if !agentTriageDryRun {
		triageRunUUID := uuid.New().String()
		var sdErr error
		sessionDir, sdErr = agent.EnsureSessionDir(settings.Agent.EffectiveSessionsDir(), triageRunUUID)
		if sdErr != nil {
			zap.L().Warn("Failed to create session dir", zap.Error(sdErr))
		}
		opts.SessionDir = sessionDir
		if settings.Agent.StreamEnabled() {
			opts.StreamWriter = os.Stdout
		}
		if tee, closer := teeToRuntimeLog(opts.StreamWriter, sessionDir); closer != nil {
			opts.StreamWriter = tee
			defer func() { _ = closer.Close() }()
		}
	}

	runCtx := ctx
	if agentTriageMaxDuration > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, agentTriageMaxDuration)
		defer cancel()
	}

	result, err := engine.Run(runCtx, opts)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("agent timed out after %s (use --max-duration to adjust or set to 0 to disable)", agentTriageMaxDuration)
		}
		return fmt.Errorf("agent run failed: %w", err)
	}

	if sessionDir != "" && result.RawOutput != "" {
		if err := os.WriteFile(filepath.Join(sessionDir, "output.md"), []byte(result.RawOutput), 0o644); err != nil {
			zap.L().Debug("failed to write triage output.md", zap.Error(err))
		}
	}

	if agentTriageDryRun {
		fmt.Print(result.RawOutput)
		return nil
	}

	verdict, err := agent.ParseTriageConfirmResult(result.RawOutput)
	if err != nil {
		return fmt.Errorf("failed to parse triage verdict from agent output: %w\n\n%s", err, result.RawOutput)
	}

	if err := applyTriageVerdict(ctx, repo, finding, verdict); err != nil {
		return fmt.Errorf("failed to persist triage verdict: %w", err)
	}

	printTriageVerdict(finding, verdict)
	return nil
}

func resolveTriageFinding(ctx context.Context, db *database.DB, repo *database.Repository, projectUUID string, args []string) (*database.Finding, error) {
	if len(args) == 1 {
		id, err := strconv.ParseInt(strings.TrimSpace(args[0]), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid finding id %q: %w", args[0], err)
		}
		f, err := repo.GetFindingByID(ctx, id)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, fmt.Errorf("no finding with id %d", id)
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
		fmt.Printf("%s No findings to triage. Run a scan first, or pass a finding id explicitly.\n", terminal.InfoSymbol())
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

func applyTriageVerdict(ctx context.Context, repo *database.Repository, finding *database.Finding, verdict *agent.TriageConfirmResult) error {
	switch verdict.Verdict {
	case agent.TriageVerdictFalsePositive:
		newDesc := appendTriageReasoning(finding.Description, verdict)
		if err := repo.UpdateFindingTriage(ctx, finding.ID, database.SeverityInfo, newDesc); err != nil {
			return fmt.Errorf("update triage: %w", err)
		}
	case agent.TriageVerdictConfirmed:
		if err := repo.UpdateFindingStatus(ctx, finding.ID, database.StatusTriaged); err != nil {
			return fmt.Errorf("update status: %w", err)
		}
	default:
		return fmt.Errorf("unexpected verdict %q", verdict.Verdict)
	}
	return nil
}

func appendTriageReasoning(existing string, verdict *agent.TriageConfirmResult) string {
	ts := time.Now().UTC().Format("2006-01-02 15:04 UTC")
	var b strings.Builder
	b.Grow(len(existing) + 256)
	b.WriteString(strings.TrimRight(existing, "\n"))
	b.WriteString("\n\n---\n## Agent Triage (")
	b.WriteString(ts)
	b.WriteString(")\n\nVerdict: false_positive — severity downgraded to info.\n\n")
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

func printTriageVerdict(finding *database.Finding, verdict *agent.TriageConfirmResult) {
	fmt.Println()
	fmt.Printf("%s Finding #%d — %s\n", terminal.InfoSymbol(), finding.ID, finding.ModuleName)

	switch verdict.Verdict {
	case agent.TriageVerdictFalsePositive:
		fmt.Printf("  Verdict:  %s\n", terminal.BoldYellow(agent.TriageVerdictFalsePositive))
		fmt.Printf("  Severity: %s → %s\n", colorSeverity(finding.Severity), colorSeverity(database.SeverityInfo))
		fmt.Printf("  Description: updated with agent reasoning\n")
	case agent.TriageVerdictConfirmed:
		fmt.Printf("  Verdict:  %s\n", terminal.BoldRed(agent.TriageVerdictConfirmed))
		fmt.Printf("  Severity: %s (unchanged)\n", colorSeverity(finding.Severity))
		fmt.Printf("  Status:   %s\n", terminal.BoldGreen(database.StatusTriaged))
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
