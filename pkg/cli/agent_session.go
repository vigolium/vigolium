package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/archon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var (
	sessionMode   string
	sessionLimit  int
	sessionOffset int
	sessionTail   int
	sessionFull   bool
)

var agentSessionCmd = &cobra.Command{
	Use:     "session [uuid]",
	Aliases: []string{"sessions", "sess"},
	Short:   "List agent run sessions or show session details",
	Long:    "Without arguments, lists all agent run sessions. With a UUID argument, shows detailed session information.",
	RunE:    runAgentSession,
}

func init() {
	agentCmd.AddCommand(agentSessionCmd)

	agentSessionCmd.Flags().StringVar(&sessionMode, "mode", "", "Filter by mode (query, autopilot, pipeline, swarm)")
	agentSessionCmd.Flags().IntVarP(&sessionLimit, "limit", "n", 50, "Maximum number of records to display")
	agentSessionCmd.Flags().IntVarP(&sessionOffset, "offset", "o", 0, "Number of records to skip")
	agentSessionCmd.Flags().IntVar(&sessionTail, "tail", 50, "Number of raw output lines to show (0=none, -1=all)")
	agentSessionCmd.Flags().BoolVar(&sessionFull, "full", false, "Show full raw output (shortcut for --tail -1)")
}

func runAgentSession(cmd *cobra.Command, args []string) error {
	defer syncLogger()
	defer closeDatabaseOnExit()

	db, err := getDB()
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	ctx := context.Background()
	if schemaErr := db.CreateSchema(ctx); schemaErr != nil {
		return fmt.Errorf("failed to create schema: %w", schemaErr)
	}

	repo := database.NewRepository(db)

	// Detail view: if a UUID argument is provided, show session details
	if len(args) > 0 {
		return showAgentSessionDetail(ctx, repo, args[0])
	}

	// List view
	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return err
	}

	runs, total, err := repo.ListAgentRuns(ctx, projectUUID, sessionMode, sessionLimit, sessionOffset)
	if err != nil {
		return fmt.Errorf("failed to list agent sessions: %w", err)
	}

	if globalJSON {
		output := map[string]interface{}{
			"total":    total,
			"offset":   sessionOffset,
			"limit":    sessionLimit,
			"sessions": runs,
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(output)
	}

	if len(runs) == 0 {
		fmt.Printf("%s No agent sessions found.\n", terminal.InfoSymbol())
		return nil
	}

	fmt.Printf("Showing %d-%d of %d agent sessions\n\n",
		sessionOffset+1,
		min(sessionOffset+len(runs), int(total)),
		total)

	// Build a child-run lookup: parent UUID → child modes
	childModes := make(map[string][]string)
	for _, r := range runs {
		if children, err := repo.GetChildAgentRuns(ctx, r.UUID); err == nil {
			for _, child := range children {
				childModes[r.UUID] = append(childModes[r.UUID], child.Mode)
			}
		}
	}

	tbl := terminal.NewTableWithMaxWidth(globalWidth, "UUID", "MODE", "STATUS", "TARGET", "FINDINGS", "RECORDS", "PHASE", "DURATION", "CREATED")
	for _, r := range runs {
		status := r.Status
		switch status {
		case "completed":
			status = terminal.Green(status)
		case "running":
			status = terminal.Cyan(status)
		case "failed":
			status = terminal.Red(status)
		case "cancelled":
			status = terminal.Yellow(status)
		case "pending":
			status = terminal.Gray(status)
		}

		duration := ""
		if r.DurationMs > 0 {
			duration = fmt.Sprintf("%.1fs", float64(r.DurationMs)/1000)
		} else if !r.StartedAt.IsZero() && r.CompletedAt.IsZero() {
			duration = fmt.Sprintf("%.1fs…", time.Since(r.StartedAt).Seconds())
		}

		target := r.TargetURL
		if target == "" && r.SourcePath != "" {
			target = terminal.ShortenHome(r.SourcePath)
		}
		if len(target) > 40 {
			target = target[:37] + "..."
		}

		uuid := r.UUID

		mode := terminal.Cyan(r.Mode)
		if modes, ok := childModes[r.UUID]; ok && len(modes) > 0 {
			mode += terminal.Gray(" +") + terminal.Gray(strings.Join(modes, ","))
		}

		phase := r.CurrentPhase
		if phase == "" && len(r.PhasesRun) > 0 {
			phase = strings.Join(r.PhasesRun, " → ")
		}
		if len(phase) > 30 {
			phase = phase[:27] + "..."
		}

		created := r.CreatedAt.Format("2006-01-02 15:04")

		tbl.AddRow(
			terminal.Gray(uuid),
			mode,
			status,
			target,
			fmt.Sprintf("%d", r.FindingCount),
			fmt.Sprintf("%d", r.RecordCount),
			phase,
			duration,
			terminal.Gray(created),
		)
	}
	tbl.Print()

	// Show tip for viewing session details.
	if len(runs) > 0 {
		fmt.Fprintf(os.Stderr, "  %s run %s to view session details\n\n",
			terminal.TipPrefix(),
			terminal.HiCyan("vigolium agent session <session-uuid>"))
	}

	return nil
}

func showAgentSessionDetail(ctx context.Context, repo *database.Repository, uuid string) error {
	run, err := repo.GetAgentRun(ctx, uuid)
	if err != nil {
		return fmt.Errorf("session not found: %w", err)
	}

	if globalJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(run)
	}

	tailLines := sessionTail
	if sessionFull {
		tailLines = -1
	}

	// Header
	status := colorRunStatus(run.Status)

	fmt.Fprintf(os.Stderr, "\n%s %s\n",
		terminal.Aqua(terminal.SymbolSparkle),
		terminal.BoldAqua("Agent Session Detail"))

	// Basic info
	fmt.Fprintf(os.Stderr, "  %-19s %s\n", terminal.Gray("UUID:"), run.UUID)
	fmt.Fprintf(os.Stderr, "  %-19s %s\n", terminal.Gray("Mode:"), terminal.Cyan(run.Mode))
	fmt.Fprintf(os.Stderr, "  %-19s %s\n", terminal.Gray("Agent:"), run.AgentName)
	fmt.Fprintf(os.Stderr, "  %-19s %s\n", terminal.Gray("Status:"), status)
	if run.TargetURL != "" {
		fmt.Fprintf(os.Stderr, "  %-19s %s\n", terminal.Gray("Target:"), run.TargetURL)
	}
	if run.TemplateID != "" {
		fmt.Fprintf(os.Stderr, "  %-19s %s\n", terminal.Gray("Template:"), terminal.Cyan(run.TemplateID))
	}
	if run.SessionID != "" {
		fmt.Fprintf(os.Stderr, "  %-19s %s\n", terminal.Gray("Session ID:"), terminal.Gray(run.SessionID))
	}
	if run.ScanUUID != "" {
		fmt.Fprintf(os.Stderr, "  %-19s %s\n", terminal.Gray("Scan UUID:"), terminal.Gray(run.ScanUUID))
	}
	if run.SourcePath != "" {
		fmt.Fprintf(os.Stderr, "  %-19s %s\n", terminal.Gray("Source:"), terminal.ShortenHome(run.SourcePath))
	}
	if run.ParentRunUUID != "" {
		fmt.Fprintf(os.Stderr, "  %-19s %s\n", terminal.Gray("Parent run:"), terminal.Gray(run.ParentRunUUID))
	}
	if run.VulnType != "" {
		fmt.Fprintf(os.Stderr, "  %-19s %s\n", terminal.Gray("Vuln type:"), terminal.Cyan(run.VulnType))
	}
	if run.RetryCount > 0 {
		fmt.Fprintf(os.Stderr, "  %-19s %d\n", terminal.Gray("Retries:"), run.RetryCount)
	}

	// Timing
	fmt.Fprintf(os.Stderr, "\n  %s %s\n", terminal.Aqua(terminal.SymbolInfo), terminal.BoldAqua("Timing"))
	fmt.Fprintf(os.Stderr, "    %-17s %s\n", terminal.Gray("Created:"), run.CreatedAt.Format("2006-01-02 15:04:05"))
	if !run.StartedAt.IsZero() {
		fmt.Fprintf(os.Stderr, "    %-17s %s\n", terminal.Gray("Started:"), run.StartedAt.Format("2006-01-02 15:04:05"))
	}
	if !run.CompletedAt.IsZero() {
		fmt.Fprintf(os.Stderr, "    %-17s %s\n", terminal.Gray("Completed:"), run.CompletedAt.Format("2006-01-02 15:04:05"))
	}
	if run.DurationMs > 0 {
		d := time.Duration(run.DurationMs) * time.Millisecond
		fmt.Fprintf(os.Stderr, "    %-17s %s\n", terminal.Gray("Duration:"), d.Round(time.Second).String())
	}

	// Results
	fmt.Fprintf(os.Stderr, "\n  %s %s\n", terminal.Aqua(terminal.SymbolInfo), terminal.BoldAqua("Results"))
	fmt.Fprintf(os.Stderr, "    %-17s %s\n", terminal.Gray("Findings:"), colorFindingCount(run.FindingCount))
	fmt.Fprintf(os.Stderr, "    %-17s %s\n", terminal.Gray("HTTP records:"), terminal.BoldCyan(fmt.Sprintf("%d", run.RecordCount)))
	if run.InputRecordCount > 0 {
		fmt.Fprintf(os.Stderr, "    %-17s %d\n", terminal.Gray("Input records:"), run.InputRecordCount)
	}
	if run.SavedCount > 0 {
		fmt.Fprintf(os.Stderr, "    %-17s %d\n", terminal.Gray("Saved:"), run.SavedCount)
	}
	if run.CurrentPhase != "" {
		fmt.Fprintf(os.Stderr, "    %-17s %s\n", terminal.Gray("Current phase:"), terminal.Cyan(run.CurrentPhase))
	}
	if len(run.PhasesRun) > 0 {
		coloredPhases := make([]string, len(run.PhasesRun))
		for i, p := range run.PhasesRun {
			coloredPhases[i] = terminal.Cyan(p)
		}
		fmt.Fprintf(os.Stderr, "    %-17s %s\n", terminal.Gray("Phases run:"), strings.Join(coloredPhases, terminal.Gray(" → ")))
	}

	// Input
	if run.InputRaw != "" {
		fmt.Fprintf(os.Stderr, "\n  %s %s\n", terminal.Aqua(terminal.SymbolInfo), terminal.BoldAqua("Input"))
		if run.InputType != "" {
			fmt.Fprintf(os.Stderr, "    %-17s %s\n", terminal.Gray("Type:"), terminal.Cyan(run.InputType))
		}
		inputDisplay := run.InputRaw
		if len(inputDisplay) > 500 {
			inputDisplay = inputDisplay[:500] + "…"
		}
		for _, line := range strings.Split(inputDisplay, "\n") {
			fmt.Fprintf(os.Stderr, "    %s\n", terminal.Gray(line))
		}
	}

	// Prompt sent
	if run.PromptSent != "" {
		fmt.Fprintf(os.Stderr, "\n  %s %s\n", terminal.Aqua(terminal.SymbolInfo), terminal.BoldAqua("Prompt"))
		prompt := run.PromptSent
		if strings.HasPrefix(prompt, "\"") {
			var unquoted string
			if json.Unmarshal([]byte(prompt), &unquoted) == nil {
				prompt = unquoted
			}
		}
		if len(prompt) > 500 {
			prompt = prompt[:500] + "…"
		}
		for _, line := range strings.Split(prompt, "\n") {
			fmt.Fprintf(os.Stderr, "    %s\n", terminal.Gray(line))
		}
	}

	// Archon audit stats (direct archon run)
	if run.Mode == "archon" {
		printArchonAuditStats(run)
	}

	// Attack plan (pipeline/swarm)
	if run.AttackPlan != "" {
		printSessionPlan(run.AttackPlan, run.Mode)
	}

	// Session auth (from session_hostnames table)
	printSessionAuth(ctx, repo, run)

	// Token usage
	if len(run.TokenUsage) > 0 {
		fmt.Fprintf(os.Stderr, "\n  %s %s\n", terminal.Aqua(terminal.SymbolInfo), terminal.BoldAqua("Token Usage"))
		for phase, usage := range run.TokenUsage {
			if usageMap, ok := usage.(map[string]interface{}); ok {
				inputTokens := usageMap["input_tokens"]
				outputTokens := usageMap["output_tokens"]
				fmt.Fprintf(os.Stderr, "    %-17s %s input, %s output\n",
					terminal.Gray(phase+":"),
					terminal.Cyan(formatTokenCount(inputTokens)),
					terminal.Cyan(formatTokenCount(outputTokens)))
			} else {
				fmt.Fprintf(os.Stderr, "    %-17s %v\n", terminal.Gray(phase+":"), usage)
			}
		}
	}

	// Triage result
	if run.TriageResult != "" {
		var triage agent.TriageResult
		if json.Unmarshal([]byte(run.TriageResult), &triage) == nil {
			fmt.Fprintf(os.Stderr, "\n  %s %s\n", terminal.Aqua(terminal.SymbolInfo), terminal.BoldAqua("Triage"))
			fmt.Fprintf(os.Stderr, "    %-17s %s\n", terminal.Gray("Verdict:"), terminal.BoldCyan(triage.Verdict))
			fmt.Fprintf(os.Stderr, "    %-17s %s\n", terminal.Gray("Confirmed:"), terminal.BoldGreen(fmt.Sprintf("%d", len(triage.Confirmed))))
			fmt.Fprintf(os.Stderr, "    %-17s %s\n", terminal.Gray("False positives:"), terminal.Gray(fmt.Sprintf("%d", len(triage.FalsePositives))))
			if len(triage.FollowUps) > 0 {
				fmt.Fprintf(os.Stderr, "    %-17s %d\n", terminal.Gray("Follow-up scans:"), len(triage.FollowUps))
			}
		}
	}

	// Error message
	if run.ErrorMessage != "" {
		fmt.Fprintf(os.Stderr, "\n  %s %s\n", terminal.Red(terminal.SymbolError), terminal.BoldRed("Error"))
		fmt.Fprintf(os.Stderr, "    %s\n", run.ErrorMessage)
	}

	// Module names
	if len(run.ModuleNames) > 0 {
		fmt.Fprintf(os.Stderr, "\n  %s %s\n", terminal.Aqua(terminal.SymbolInfo), terminal.BoldAqua("Modules"))
		for _, m := range run.ModuleNames {
			fmt.Fprintf(os.Stderr, "    %s %s\n", terminal.Gray("-"), terminal.Cyan(m))
		}
	}

	// Session directory listing
	sessionDir := resolveSessionDir(run)
	printSessionDirListing(sessionDir)

	// Extensions (from session directory)
	printSessionExtensions(run)

	// Raw output
	printSessionRawOutput(run, sessionDir, tailLines)

	// Child runs (e.g. archon sub-runs spawned by autopilot)
	if children, childErr := repo.GetChildAgentRuns(ctx, run.UUID); childErr == nil && len(children) > 0 {
		for _, child := range children {
			printChildRunDetail(child, tailLines)
		}
	}

	fmt.Fprintln(os.Stderr)
	return nil
}

// colorRunStatus returns a colored agent run status string.
func colorRunStatus(status string) string {
	switch status {
	case "completed":
		return terminal.Green(status)
	case "running":
		return terminal.Cyan(status)
	case "failed":
		return terminal.Red(status)
	case "cancelled":
		return terminal.Yellow(status)
	case "pending":
		return terminal.Gray(status)
	default:
		return status
	}
}

// printChildRunDetail renders a child run's details inline within its parent's detail view.
func printChildRunDetail(child *database.AgentRun, tailLines int) {
	uuidShort := child.UUID
	if len(uuidShort) > 8 {
		uuidShort = uuidShort[:8] + "…"
	}

	fmt.Fprintf(os.Stderr, "\n  %s %s %s\n",
		terminal.Aqua(terminal.SymbolSparkle2),
		terminal.BoldAqua("Child Run: "+child.Mode),
		terminal.Gray("("+uuidShort+")"))

	fmt.Fprintf(os.Stderr, "    %-17s %s\n", terminal.Gray("UUID:"), terminal.Gray(child.UUID))
	fmt.Fprintf(os.Stderr, "    %-17s %s\n", terminal.Gray("Agent:"), child.AgentName)
	fmt.Fprintf(os.Stderr, "    %-17s %s\n", terminal.Gray("Status:"), colorRunStatus(child.Status))
	if child.SourcePath != "" {
		fmt.Fprintf(os.Stderr, "    %-17s %s\n", terminal.Gray("Source:"), terminal.ShortenHome(child.SourcePath))
	}

	// Timing
	if !child.StartedAt.IsZero() {
		fmt.Fprintf(os.Stderr, "    %-17s %s\n", terminal.Gray("Started:"), child.StartedAt.Format("2006-01-02 15:04:05"))
	}
	if !child.CompletedAt.IsZero() {
		fmt.Fprintf(os.Stderr, "    %-17s %s\n", terminal.Gray("Completed:"), child.CompletedAt.Format("2006-01-02 15:04:05"))
	}
	if child.DurationMs > 0 {
		d := time.Duration(child.DurationMs) * time.Millisecond
		fmt.Fprintf(os.Stderr, "    %-17s %s\n", terminal.Gray("Duration:"), d.Round(time.Second).String())
	}

	// Results
	fmt.Fprintf(os.Stderr, "    %-17s %s\n", terminal.Gray("Findings:"), colorFindingCount(child.FindingCount))
	if child.CurrentPhase != "" {
		fmt.Fprintf(os.Stderr, "    %-17s %s\n", terminal.Gray("Current phase:"), terminal.Cyan(child.CurrentPhase))
	}
	if len(child.PhasesRun) > 0 {
		coloredPhases := make([]string, len(child.PhasesRun))
		for i, p := range child.PhasesRun {
			coloredPhases[i] = terminal.Cyan(p)
		}
		fmt.Fprintf(os.Stderr, "    %-17s %s\n", terminal.Gray("Phases run:"), strings.Join(coloredPhases, terminal.Gray(" → ")))
	}

	// Archon-specific stats
	if child.Mode == "archon" {
		printArchonAuditStats(child)
	}

	// Error
	if child.ErrorMessage != "" {
		fmt.Fprintf(os.Stderr, "    %-17s %s\n", terminal.Gray("Error:"), terminal.Red(child.ErrorMessage))
	}

	// Session directory listing
	childSessionDir := resolveSessionDir(child)
	printSessionDirListing(childSessionDir)

	// Raw output
	printSessionRawOutput(child, childSessionDir, tailLines)
}

// resolveSessionDir returns the session directory path for a run,
// preferring the DB-stored path and falling back to convention.
func resolveSessionDir(run *database.AgentRun) string {
	if run.SessionDir != "" {
		return run.SessionDir
	}
	sessionsDir := resolveSessionsDir()
	if sessionsDir == "" {
		return ""
	}
	return filepath.Join(sessionsDir, run.UUID)
}

// printSessionDirListing lists all files in the session directory with sizes.
func printSessionDirListing(sessionDir string) {
	if sessionDir == "" {
		return
	}
	info, err := os.Stat(sessionDir)
	if err != nil || !info.IsDir() {
		return
	}

	type fileEntry struct {
		relPath string
		size    int64
	}

	var files []fileEntry
	_ = filepath.WalkDir(sessionDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(sessionDir, path)
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		files = append(files, fileEntry{relPath: rel, size: fi.Size()})
		return nil
	})

	if len(files) == 0 {
		return
	}

	fmt.Fprintf(os.Stderr, "\n  %s %s %s\n",
		terminal.Aqua(terminal.SymbolInfo),
		terminal.BoldAqua("Session Directory"),
		terminal.Gray(fmt.Sprintf("(%d file%s)", len(files), pluralSuffix(len(files)))))
	fmt.Fprintf(os.Stderr, "    %-17s %s\n", terminal.Gray("Path:"), terminal.Gray(terminal.ShortenHome(sessionDir)))

	for _, f := range files {
		fmt.Fprintf(os.Stderr, "    %s %-50s %s\n",
			terminal.Gray("-"),
			terminal.Cyan(f.relPath),
			terminal.Gray(formatFileSize(f.size)))
	}
}

// printSessionRawOutput shows the tail of the agent's raw output.
func printSessionRawOutput(run *database.AgentRun, sessionDir string, tailLines int) {
	if tailLines == 0 {
		return
	}

	// Try multiple sources for raw output
	var content string

	// 1. DB field
	if run.AgentRawOutput != "" {
		content = run.AgentRawOutput
	}

	// 2. Session directory files (prefer these as they may be more complete)
	if sessionDir != "" {
		for _, name := range []string{"output.md", "output.txt", "archon-audit-output.md"} {
			if data, err := os.ReadFile(filepath.Join(sessionDir, name)); err == nil && len(data) > 0 {
				content = string(data)
				break
			}
		}
	}

	if content == "" {
		return
	}

	lines := strings.Split(content, "\n")
	// Trim trailing empty lines
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) == 0 {
		return
	}

	totalLines := len(lines)
	truncated := false
	if tailLines > 0 && totalLines > tailLines {
		lines = lines[totalLines-tailLines:]
		truncated = true
	}

	fmt.Fprintf(os.Stderr, "\n  %s %s %s\n",
		terminal.Aqua(terminal.SymbolInfo),
		terminal.BoldAqua("Raw Output"),
		terminal.Gray(fmt.Sprintf("(%d line%s total)", totalLines, pluralSuffix(totalLines))))

	if truncated {
		fmt.Fprintf(os.Stderr, "    %s\n", terminal.Gray(fmt.Sprintf("… showing last %d lines (use --full for all) …", tailLines)))
	}
	for _, line := range lines {
		fmt.Fprintf(os.Stderr, "    %s\n", terminal.Gray(line))
	}
}

// printArchonAuditStats parses and displays archon audit state from ResultJSON.
func printArchonAuditStats(run *database.AgentRun) {
	if run.ResultJSON == "" {
		return
	}

	var state archon.AuditState
	if err := json.Unmarshal([]byte(run.ResultJSON), &state); err != nil || len(state.Audits) == 0 {
		return
	}

	audit := state.Audits[0]

	fmt.Fprintf(os.Stderr, "\n  %s %s\n",
		terminal.Aqua(terminal.SymbolInfo),
		terminal.BoldAqua("Archon Audit"))

	// Metadata
	if audit.Commit != "" {
		commitShort := audit.Commit
		if len(commitShort) > 7 {
			commitShort = commitShort[:7]
		}
		commitDisplay := terminal.Cyan(commitShort)
		if audit.Branch != "" {
			commitDisplay += terminal.Gray(" (") + terminal.Cyan(audit.Branch) + terminal.Gray(")")
		}
		fmt.Fprintf(os.Stderr, "    %-17s %s\n", terminal.Gray("Commit:"), commitDisplay)
	}
	if repo := audit.EffectiveRepo(); repo != "" {
		fmt.Fprintf(os.Stderr, "    %-17s %s\n", terminal.Gray("Repo:"), terminal.Cyan(repo))
	}
	if audit.Mode != "" {
		fmt.Fprintf(os.Stderr, "    %-17s %s\n", terminal.Gray("Audit mode:"), terminal.HiTeal(audit.Mode))
	}
	fmt.Fprintf(os.Stderr, "    %-17s %s\n", terminal.Gray("Audit status:"), colorRunStatus(audit.Status))

	if !audit.CompletedAt.IsZero() && !audit.StartedAt.IsZero() {
		d := audit.CompletedAt.Sub(audit.StartedAt.Time).Round(time.Second)
		fmt.Fprintf(os.Stderr, "    %-17s %s\n", terminal.Gray("Audit duration:"), d.String())
	}

	// Phase breakdown
	if len(audit.Phases) > 0 {
		fmt.Fprintf(os.Stderr, "\n    %s\n", terminal.Gray("Phases:"))

		var phaseKeys []string
		for k := range audit.Phases {
			phaseKeys = append(phaseKeys, k)
		}
		sort.Strings(phaseKeys)

		for _, k := range phaseKeys {
			p := audit.Phases[k]
			phaseStatus := p.Status
			var statusColor func(string) string
			switch phaseStatus {
			case "complete":
				statusColor = terminal.Green
			case "in_progress":
				statusColor = terminal.Cyan
			case "failed":
				statusColor = terminal.Red
			default:
				statusColor = terminal.Gray
			}

			dur := ""
			if !p.CompletedAt.IsZero() && !audit.StartedAt.IsZero() {
				dur = terminal.Gray(fmt.Sprintf(" %s", p.CompletedAt.Format("15:04:05")))
			}

			fmt.Fprintf(os.Stderr, "      %-12s %s%s\n",
				terminal.Gray(k),
				statusColor(phaseStatus),
				dur)
		}
	}

	// Finding severity breakdown from session directory
	sessionDir := resolveSessionDir(run)
	if sessionDir != "" {
		archonDir := filepath.Join(sessionDir, "archon-audit")
		if imp, err := archon.ParseAuditFolder(archonDir); err == nil && len(imp.RawFindings) > 0 {
			bySev := make(map[string]int)
			for _, f := range imp.RawFindings {
				sev := strings.ToLower(f.Severity)
				if sev == "" {
					sev = "info"
				}
				bySev[sev]++
			}

			stats := agent.FindingStats{
				Parsed:     len(imp.RawFindings),
				BySeverity: bySev,
			}

			fmt.Fprintf(os.Stderr, "\n    %s %s\n",
				terminal.Purple(terminal.SymbolFlag),
				fmt.Sprintf("Findings: %s parsed", terminal.HiTeal(fmt.Sprintf("%d", stats.Parsed))))

			if breakdown := stats.SeverityBreakdownString(); breakdown != "" {
				fmt.Fprintf(os.Stderr, "      %s %s\n", terminal.Gray(terminal.SymbolDot), breakdown)
			}
		}
	}

	// Notable reports present
	if sessionDir != "" {
		archonDir := filepath.Join(sessionDir, "archon-audit")
		var reports []string
		for _, name := range []string{"knowledge-base-report.md", "final-audit-report.md", "commit-recon-report.md", "attack-pattern-registry.json"} {
			if _, err := os.Stat(filepath.Join(archonDir, name)); err == nil {
				reports = append(reports, name)
			}
		}
		if len(reports) > 0 {
			fmt.Fprintf(os.Stderr, "\n    %s\n", terminal.Gray("Reports:"))
			for _, r := range reports {
				fmt.Fprintf(os.Stderr, "      %s %s\n", terminal.Gray("-"), terminal.Cyan(r))
			}
		}
	}
}

// printSessionPlan parses and displays the attack plan / swarm plan from JSON.
func printSessionPlan(planJSON string, mode string) {
	// Try SwarmPlan first (swarm mode)
	if mode == "swarm" {
		var swarmPlan agent.SwarmPlan
		if json.Unmarshal([]byte(planJSON), &swarmPlan) == nil && (len(swarmPlan.ModuleTags) > 0 || len(swarmPlan.Extensions) > 0 || len(swarmPlan.FocusAreas) > 0) {
			fmt.Fprintf(os.Stderr, "\n  %s %s\n", terminal.Aqua(terminal.SymbolInfo), terminal.BoldAqua("Swarm Plan"))
			if len(swarmPlan.ModuleTags) > 0 {
				coloredTags := make([]string, len(swarmPlan.ModuleTags))
				for i, tag := range swarmPlan.ModuleTags {
					coloredTags[i] = terminal.Cyan(tag)
				}
				fmt.Fprintf(os.Stderr, "    %-15s %s\n", terminal.Gray("Module tags:"), strings.Join(coloredTags, terminal.Gray(", ")))
			}
			if len(swarmPlan.ModuleIDs) > 0 {
				coloredIDs := make([]string, len(swarmPlan.ModuleIDs))
				for i, id := range swarmPlan.ModuleIDs {
					coloredIDs[i] = terminal.Cyan(id)
				}
				fmt.Fprintf(os.Stderr, "    %-15s %s\n", terminal.Gray("Module IDs:"), strings.Join(coloredIDs, terminal.Gray(", ")))
			}
			if len(swarmPlan.Extensions) > 0 {
				fmt.Fprintf(os.Stderr, "    %-15s %s\n", terminal.Gray("Extensions:"), terminal.BoldYellow(fmt.Sprintf("%d generated", len(swarmPlan.Extensions))))
				for _, ext := range swarmPlan.Extensions {
					fmt.Fprintf(os.Stderr, "      %s %s %s\n", terminal.Gray("-"), terminal.BoldCyan(ext.Filename+":"), ext.Reason)
				}
			}
			if len(swarmPlan.FocusAreas) > 0 {
				fmt.Fprintf(os.Stderr, "    %-15s %s\n", terminal.Gray("Focus areas:"), terminal.Orange(fmt.Sprintf("%d", len(swarmPlan.FocusAreas))))
				for _, area := range swarmPlan.FocusAreas {
					title, detail := splitFocusArea(area)
					if detail != "" {
						fmt.Fprintf(os.Stderr, "      %s %s %s\n", terminal.Gray("-"), terminal.BoldCyan(title+":"), terminal.Muted(detail))
					} else {
						fmt.Fprintf(os.Stderr, "      %s %s\n", terminal.Gray("-"), terminal.BoldCyan(area))
					}
				}
			}
			if swarmPlan.Notes != "" {
				fmt.Fprintf(os.Stderr, "    %s\n", terminal.Gray("Notes:"))
				for _, line := range strings.Split(swarmPlan.Notes, "\n") {
					line = strings.TrimSpace(line)
					if line == "" {
						continue
					}
					line = strings.TrimPrefix(line, "- ")
					fmt.Fprintf(os.Stderr, "      %s %s\n", terminal.Gray("-"), terminal.Muted(line))
				}
			}
			return
		}
	}

	// Try AttackPlan (pipeline mode)
	var plan agent.AttackPlan
	if json.Unmarshal([]byte(planJSON), &plan) == nil && (len(plan.ModuleTags) > 0 || len(plan.FocusAreas) > 0 || len(plan.Endpoints) > 0) {
		fmt.Fprintf(os.Stderr, "\n  %s %s\n", terminal.Aqua(terminal.SymbolInfo), terminal.BoldAqua("Attack Plan"))
		if len(plan.ModuleTags) > 0 {
			coloredTags := make([]string, len(plan.ModuleTags))
			for i, tag := range plan.ModuleTags {
				coloredTags[i] = terminal.Cyan(tag)
			}
			fmt.Fprintf(os.Stderr, "    %-15s %s\n", terminal.Gray("Module tags:"), strings.Join(coloredTags, terminal.Gray(", ")))
		}
		if len(plan.ModuleIDs) > 0 {
			coloredIDs := make([]string, len(plan.ModuleIDs))
			for i, id := range plan.ModuleIDs {
				coloredIDs[i] = terminal.Cyan(id)
			}
			fmt.Fprintf(os.Stderr, "    %-15s %s\n", terminal.Gray("Module IDs:"), strings.Join(coloredIDs, terminal.Gray(", ")))
		}
		if len(plan.FocusAreas) > 0 {
			fmt.Fprintf(os.Stderr, "    %-15s %s\n", terminal.Gray("Focus areas:"), terminal.Orange(fmt.Sprintf("%d", len(plan.FocusAreas))))
			for _, area := range plan.FocusAreas {
				title, detail := splitFocusArea(area)
				if detail != "" {
					fmt.Fprintf(os.Stderr, "      %s %s %s\n", terminal.Gray("-"), terminal.BoldCyan(title+":"), terminal.Muted(detail))
				} else {
					fmt.Fprintf(os.Stderr, "      %s %s\n", terminal.Gray("-"), terminal.BoldCyan(area))
				}
			}
		}
		if len(plan.Endpoints) > 0 {
			fmt.Fprintf(os.Stderr, "    %-15s %d\n", terminal.Gray("Endpoints:"), len(plan.Endpoints))
			for _, ep := range plan.Endpoints {
				method := ep.Method
				if method == "" {
					method = "GET"
				}
				priority := ep.Priority
				switch priority {
				case "high":
					priority = terminal.Red(priority)
				case "medium":
					priority = terminal.Yellow(priority)
				case "low":
					priority = terminal.Gray(priority)
				}
				fmt.Fprintf(os.Stderr, "      %s %s %s [%s]\n",
					terminal.Gray("-"),
					terminal.BoldCyan(method),
					ep.URL,
					priority)
			}
		}
		if plan.Notes != "" {
			fmt.Fprintf(os.Stderr, "    %s\n", terminal.Gray("Notes:"))
			for _, line := range strings.Split(plan.Notes, "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				line = strings.TrimPrefix(line, "- ")
				fmt.Fprintf(os.Stderr, "      %s %s\n", terminal.Gray("-"), terminal.Muted(line))
			}
		}
	}
}

// printSessionAuth displays session auth configs associated with this agent run.
func printSessionAuth(ctx context.Context, repo *database.Repository, run *database.AgentRun) {
	if run.ScanUUID == "" {
		return
	}
	rows, err := repo.GetSessionHostnamesByScan(ctx, run.ProjectUUID, run.ScanUUID)
	if err != nil || len(rows) == 0 {
		return
	}

	fmt.Fprintf(os.Stderr, "\n  %s %s %s\n",
		terminal.Aqua(terminal.SymbolInfo),
		terminal.BoldAqua("Session Auth"),
		terminal.Gray(fmt.Sprintf("(%d config%s)", len(rows), pluralSuffix(len(rows)))))

	for _, sh := range rows {
		role := sh.SessionRole
		switch role {
		case "primary":
			role = terminal.Green(role)
		case "compare":
			role = terminal.Yellow(role)
		}

		fmt.Fprintf(os.Stderr, "    %s %s %s %s\n",
			terminal.Gray("-"),
			terminal.BoldCyan(sh.SessionName),
			terminal.Gray("@"),
			terminal.Cyan(sh.Hostname))

		if sh.SessionRole != "" {
			fmt.Fprintf(os.Stderr, "      %-15s %s\n", terminal.Gray("Role:"), role)
		}
		if sh.SessionToken != "" {
			tok := sh.SessionToken
			if len(tok) > 60 {
				tok = tok[:57] + "..."
			}
			fmt.Fprintf(os.Stderr, "      %-15s %s\n", terminal.Gray("Token:"), terminal.Gray(tok))
		}
		if len(sh.Headers) > 0 {
			headerKeys := make([]string, 0, len(sh.Headers))
			for k := range sh.Headers {
				headerKeys = append(headerKeys, k)
			}
			fmt.Fprintf(os.Stderr, "      %-15s %s\n", terminal.Gray("Headers:"), terminal.Gray(strings.Join(headerKeys, ", ")))
		}
		if sh.HydratedAt != nil {
			fmt.Fprintf(os.Stderr, "      %-15s %s\n", terminal.Gray("Hydrated:"), terminal.Gray(sh.HydratedAt.Format("2006-01-02 15:04:05")))
		}
		if sh.LoginURL != "" {
			fmt.Fprintf(os.Stderr, "      %-15s %s %s\n", terminal.Gray("Login:"), terminal.Gray(sh.LoginMethod), sh.LoginURL)
		}
		if sh.ExtractRules != "" {
			rules := sh.ExtractRules
			if len(rules) > 80 {
				rules = rules[:77] + "..."
			}
			fmt.Fprintf(os.Stderr, "      %-15s %s\n", terminal.Gray("Extract:"), terminal.Gray(rules))
		}
	}
}

// printSessionExtensions discovers and displays extensions from the session directory.
func printSessionExtensions(run *database.AgentRun) {
	// Resolve session dir from the run UUID
	sessionsDir := resolveSessionsDir()
	if sessionsDir == "" {
		return
	}
	sessionDir := filepath.Join(sessionsDir, run.UUID)
	extDir := filepath.Join(sessionDir, "extensions")

	entries, err := os.ReadDir(extDir)
	if err != nil || len(entries) == 0 {
		return
	}

	var jsFiles []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".js") {
			jsFiles = append(jsFiles, e.Name())
		}
	}

	if len(jsFiles) == 0 {
		return
	}

	fmt.Fprintf(os.Stderr, "\n  %s %s %s\n",
		terminal.Aqua(terminal.SymbolInfo),
		terminal.BoldAqua("Extensions"),
		terminal.Gray(fmt.Sprintf("(%d file%s)", len(jsFiles), pluralSuffix(len(jsFiles)))))
	fmt.Fprintf(os.Stderr, "    %-17s %s\n", terminal.Gray("Directory:"), terminal.Gray(terminal.ShortenHome(extDir)))
	for _, f := range jsFiles {
		fmt.Fprintf(os.Stderr, "    %s %s\n", terminal.Gray("-"), terminal.BoldCyan(f))
	}
}

// resolveSessionsDir returns the agent sessions directory path.
func resolveSessionsDir() string {
	// Use the config helper which handles defaults and ~ expansion
	ac := config.AgentConfig{}
	return ac.EffectiveSessionsDir()
}

// formatTokenCount formats a token count from interface{} to a human-readable string.
func formatTokenCount(v interface{}) string {
	switch n := v.(type) {
	case float64:
		if n >= 1_000_000 {
			return fmt.Sprintf("%.1fM", n/1_000_000)
		}
		if n >= 1_000 {
			return fmt.Sprintf("%.1fK", n/1_000)
		}
		return fmt.Sprintf("%d", int(n))
	case int:
		return fmt.Sprintf("%d", n)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// pluralSuffix returns "s" if count != 1, "" otherwise.
func pluralSuffix(count int) string {
	if count == 1 {
		return ""
	}
	return "s"
}

// formatFileSize returns a human-readable file size string.
func formatFileSize(bytes int64) string {
	switch {
	case bytes >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(bytes)/float64(1<<20))
	case bytes >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(bytes)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
