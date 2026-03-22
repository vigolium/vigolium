package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var (
	sessionMode   string
	sessionLimit  int
	sessionOffset int
)

var agentSessionCmd = &cobra.Command{
	Use:     "session [uuid]",
	Aliases: []string{"sessions"},
	Short:   "List agent run sessions or show session details",
	Long:    "Without arguments, lists all agent run sessions. With a UUID argument, shows detailed session information.",
	RunE:    runAgentSession,
}

func init() {
	agentCmd.AddCommand(agentSessionCmd)

	agentSessionCmd.Flags().StringVar(&sessionMode, "mode", "", "Filter by mode (query, autopilot, pipeline, swarm)")
	agentSessionCmd.Flags().IntVarP(&sessionLimit, "limit", "n", 50, "Maximum number of records to display")
	agentSessionCmd.Flags().IntVarP(&sessionOffset, "offset", "o", 0, "Number of records to skip")
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
		if len(target) > 40 {
			target = target[:37] + "..."
		}

		uuid := r.UUID

		phase := r.CurrentPhase

		created := r.CreatedAt.Format("2006-01-02 15:04")

		tbl.AddRow(
			terminal.Gray(uuid),
			terminal.Cyan(r.Mode),
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

	// Header
	status := run.Status
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

	// Prompt sent
	if run.PromptSent != "" {
		fmt.Fprintf(os.Stderr, "\n  %s %s\n", terminal.Aqua(terminal.SymbolInfo), terminal.BoldAqua("Prompt"))
		prompt := run.PromptSent
		// Trim outer JSON quotes if stored as JSON string
		if strings.HasPrefix(prompt, "\"") {
			var unquoted string
			if json.Unmarshal([]byte(prompt), &unquoted) == nil {
				prompt = unquoted
			}
		}
		// Show first 500 chars with truncation
		if len(prompt) > 500 {
			prompt = prompt[:500] + "…"
		}
		for _, line := range strings.Split(prompt, "\n") {
			fmt.Fprintf(os.Stderr, "    %s\n", terminal.Gray(line))
		}
	}

	// Attack plan (pipeline/swarm)
	if run.AttackPlan != "" {
		printSessionPlan(run.AttackPlan, run.Mode)
	}

	// Session auth (from session_hostnames table)
	printSessionAuth(ctx, repo, run)

	// Extensions (from session directory)
	printSessionExtensions(run)

	// Token usage
	if len(run.TokenUsage) > 0 {
		fmt.Fprintf(os.Stderr, "\n  %s %s\n", terminal.Aqua(terminal.SymbolInfo), terminal.BoldAqua("Token Usage"))
		for phase, usage := range run.TokenUsage {
			if usageMap, ok := usage.(map[string]interface{}); ok {
				inputTokens, _ := usageMap["input_tokens"]
				outputTokens, _ := usageMap["output_tokens"]
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

	fmt.Fprintln(os.Stderr)
	return nil
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
