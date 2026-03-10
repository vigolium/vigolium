package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/vigolium/vigolium/pkg/types"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// agent swarm command flags
var (
	swarmTarget        string
	swarmInput         string
	swarmRecordUUID    string
	swarmSource        string
	swarmFiles         []string
	swarmVulnType      string
	swarmModules       []string
	swarmMaxIterations int
	swarmAgentName     string
	swarmDryRun        bool
	swarmTimeout       time.Duration
	swarmProfile       string
)

var agentSwarmCmd = &cobra.Command{
	Use:   "swarm",
	Short: "AI-guided targeted vulnerability swarm",
	Long: `Run an AI-guided targeted vulnerability swarm against a specific input.

The master agent analyzes the target, selects appropriate scanner modules,
generates custom attack payloads as JavaScript extensions, executes the scan,
and triages the results.

Supported input types (auto-detected):
  - URL:         https://example.com/api/login
  - Curl:        curl -X POST https://example.com/api -d '{"user":"admin"}'
  - Raw HTTP:    POST /api HTTP/1.1\r\nHost: example.com\r\n...
  - Burp XML:    <?xml...><items><item>...</item></items>
  - Base64:      Base64-encoded raw HTTP request (Burp base64 export)
  - Record UUID: abc123-... (from http_records table)

When input is piped via stdin, it is automatically read (no --input needed).`,
	RunE: runAgentSwarm,
}

func init() {
	agentCmd.AddCommand(agentSwarmCmd)
	f := agentSwarmCmd.Flags()

	f.StringVarP(&swarmTarget, "target", "t", "", "Target URL (required when --source is used)")
	f.StringVar(&swarmInput, "input", "", "Raw input (curl command, raw HTTP, Burp XML, URL). Reads from stdin if piped")
	f.StringVar(&swarmRecordUUID, "record-uuid", "", "HTTP record UUID from database")
	f.StringVar(&swarmSource, "source", "", "Path to application source code for route discovery")
	f.StringSliceVar(&swarmFiles, "files", nil, "Specific source files to include (relative to --source)")
	f.StringVar(&swarmVulnType, "vuln-type", "", "Vulnerability type focus (e.g. sqli, xss, ssrf)")
	f.StringSliceVarP(&swarmModules, "modules", "m", nil, "Explicit module names to include")
	f.IntVar(&swarmMaxIterations, "max-iterations", 3, "Maximum triage-rescan iterations")
	f.StringVar(&swarmAgentName, "agent", "", "Agent backend to use (default from config)")
	f.BoolVar(&swarmDryRun, "dry-run", false, "Render prompts without executing")
	f.DurationVar(&swarmTimeout, "timeout", 15*time.Minute, "Maximum swarm duration")
	f.StringVar(&swarmProfile, "profile", "", "Scanning profile to use")
}

func runAgentSwarm(_ *cobra.Command, _ []string) error {
	defer syncLogger()
	defer closeDatabaseOnExit()

	// Validate: at least one input source (stdin is checked later in buildSwarmInputs)
	if swarmTarget == "" && swarmInput == "" && swarmRecordUUID == "" && swarmSource == "" && !stdinIsPiped() {
		return fmt.Errorf("at least one input is required: --target, --input, --record-uuid, --source, or pipe via stdin")
	}

	// --source requires --target for hostname mapping
	if swarmSource != "" && swarmTarget == "" && swarmInput == "" && swarmRecordUUID == "" && !stdinIsPiped() {
		return fmt.Errorf("--target is required when using --source (used to filter discovered routes by hostname)")
	}

	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		zap.L().Warn("Failed to load settings, using defaults", zap.Error(err))
		settings = config.DefaultSettings()
	}

	// Override SQLite path if --db flag is set
	if globalDB != "" {
		settings.Database.Driver = "sqlite"
		settings.Database.SQLite.Path = globalDB
	}

	// Apply scanning profile
	if swarmProfile != "" {
		profilePath := settings.ScanningStrategy.ResolveProfilePath(swarmProfile)
		profile, profileErr := config.LoadProfile(profilePath)
		if profileErr != nil {
			return fmt.Errorf("failed to load scanning profile %q: %w", swarmProfile, profileErr)
		}
		if err := config.ApplyProfile(settings, profile); err != nil {
			return fmt.Errorf("failed to apply scanning profile %q: %w", swarmProfile, err)
		}
	}

	// Open DB
	db, err := database.NewDB(&settings.Database)
	if err != nil {
		return fmt.Errorf("failed to create database: %w", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	if err := db.CreateSchema(ctx); err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}
	repo := database.NewRepository(db)

	// Create agent engine
	engine := agent.NewEngine(settings, repo)
	defer engine.Close()

	// Resolve project UUID
	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return err
	}

	// Build inputs list
	inputs, err := buildSwarmInputs()
	if err != nil {
		return err
	}

	// Build swarm config
	cfg := agent.SwarmConfig{
		Inputs:        inputs,
		SourcePath:    swarmSource,
		Files:         swarmFiles,
		VulnType:      swarmVulnType,
		ModuleNames:   swarmModules,
		MaxIterations: swarmMaxIterations,
		AgentName:     swarmAgentName,
		DryRun:        swarmDryRun,
		SessionsDir:   settings.Agent.EffectiveSessionsDir(),
		ProjectUUID:   projectUUID,
		ScanUUID:      globalScanID,
	}

	if settings.Agent.StreamEnabled() {
		cfg.StreamWriter = os.Stdout
	}

	// Wire scan callback
	cfg.ScanFunc = buildAgentSwarmScanFunc(settings, repo)

	// Set up timeout
	if swarmTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, swarmTimeout)
		defer cancel()
	}

	// Print banner
	inputDesc := swarmTarget
	if inputDesc == "" && swarmInput != "" {
		inputDesc = truncateSwarmInput(swarmInput, 80)
	}
	if inputDesc == "" && swarmRecordUUID != "" {
		inputDesc = "record:" + swarmRecordUUID
	}
	fmt.Fprintf(os.Stderr, "%s Starting agent swarm: %s\n",
		terminal.InfoSymbol(), terminal.Cyan(inputDesc))
	if swarmSource != "" {
		fmt.Fprintf(os.Stderr, "%s Source code: %s\n",
			terminal.InfoSymbol(), swarmSource)
	}
	if swarmVulnType != "" {
		fmt.Fprintf(os.Stderr, "%s Vulnerability focus: %s\n",
			terminal.InfoSymbol(), swarmVulnType)
	}

	// Run swarm
	swarmRunner := agent.NewSwarmRunner(engine, repo)
	result, err := swarmRunner.Run(ctx, cfg)
	if err != nil {
		return fmt.Errorf("agent swarm failed: %w", err)
	}

	printSwarmResult(result)
	return nil
}

func buildSwarmInputs() ([]string, error) {
	var inputs []string

	if swarmTarget != "" {
		inputs = append(inputs, swarmTarget)
	}

	if swarmInput != "" {
		if swarmInput == "-" {
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				return nil, fmt.Errorf("failed to read from stdin: %w", err)
			}
			inputs = append(inputs, string(data))
		} else {
			inputs = append(inputs, swarmInput)
		}
	}

	if swarmRecordUUID != "" {
		inputs = append(inputs, swarmRecordUUID)
	}

	// Auto-detect stdin when no explicit input is provided
	if len(inputs) == 0 {
		if data, ok := readStdinIfPiped(); ok {
			inputs = append(inputs, data)
		}
	}

	return inputs, nil
}

// buildAgentSwarmScanFunc creates a callback that runs dynamic assessment with specified modules and extensions.
func buildAgentSwarmScanFunc(settings *config.Settings, repo *database.Repository) func(ctx context.Context, moduleTags []string, moduleIDs []string, extensionDir string) error {
	return func(ctx context.Context, moduleTags []string, moduleIDs []string, extensionDir string) error {
		opts := types.DefaultOptions()
		opts.Targets = []string{swarmTarget}
		opts.ScanUUID = globalScanID
		projectUUID, err := resolveProjectUUID()
		if err != nil {
			return err
		}
		opts.ProjectUUID = projectUUID
		opts.ConfigPath = globalConfig
		opts.OnlyPhase = "dynamic-assessment"
		opts.SkipIngestion = true
		opts.HeuristicsCheck = "none"
		opts.Modules = agent.ResolveModulesFromPlan(moduleTags, moduleIDs)
		opts.PassiveModules = []string{"all"}
		opts.Silent = true
		opts.ScanConfigPrinted = true

		// Clone settings to avoid mutating shared config
		settingsCopy := *settings
		if extensionDir != "" {
			settingsCopy.DynamicAssessment.Extensions.Enabled = true
			settingsCopy.DynamicAssessment.Extensions.CustomDir = append(
				settingsCopy.DynamicAssessment.Extensions.CustomDir,
				filepath.Join(extensionDir, "*.js"),
			)
		}

		fmt.Fprintf(os.Stderr, "\n%s Scanning with modules: %s\n",
			terminal.Aqua(terminal.SymbolSparkle),
			summarizeModules(opts.Modules))

		scanRunner, runErr := runner.New(opts)
		if runErr != nil {
			return runErr
		}
		defer scanRunner.Close()

		scanRunner.SetSettings(&settingsCopy)
		scanRunner.SetRepository(repo)
		return scanRunner.RunEnumeration()
	}
}

func printSwarmResult(result *agent.SwarmResult) {
	if globalJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(result)
		return
	}

	fmt.Fprintf(os.Stderr, "\n%s %s\n",
		terminal.Aqua(terminal.SymbolSparkle),
		terminal.BoldAqua("Agent swarm completed"))

	fmt.Fprintf(os.Stderr, "  %-17s %s\n", terminal.Gray("Duration:"), result.Duration.Round(time.Second))
	fmt.Fprintf(os.Stderr, "  %-17s %s\n", terminal.Gray("Agent run:"), terminal.Gray(result.AgentRunUUID))
	if result.SessionID != "" {
		fmt.Fprintf(os.Stderr, "  %-17s %s\n", terminal.Gray("Session ID:"), terminal.Gray(result.SessionID))
	}

	// Records summary
	if result.TotalRecords > 0 {
		fmt.Fprintf(os.Stderr, "  %s %s %s\n",
			terminal.Aqua(terminal.SymbolInfo),
			terminal.BoldAqua("Records:"),
			fmt.Sprintf("%s http records ingested", terminal.BoldCyan(fmt.Sprintf("%d", result.TotalRecords))))
	}

	// Findings summary with severity breakdown
	fmt.Fprintf(os.Stderr, "  %s %s %s",
		terminal.Aqua(terminal.SymbolInfo),
		terminal.BoldAqua("Findings:"),
		fmt.Sprintf("%s issues found", colorFindingCount(result.TotalFindings)))
	if len(result.SeverityCounts) > 0 && result.TotalFindings > 0 {
		fmt.Fprintf(os.Stderr, " — %s", formatSeverityWithSymbols(result.SeverityCounts))
	}
	fmt.Fprintln(os.Stderr)

	if result.SwarmPlan != nil {
		fmt.Fprintf(os.Stderr, "\n  %s %s\n", terminal.Aqua(terminal.SymbolInfo), terminal.BoldAqua("Swarm Plan:"))
		if len(result.SwarmPlan.ModuleTags) > 0 {
			coloredTags := make([]string, len(result.SwarmPlan.ModuleTags))
			for i, tag := range result.SwarmPlan.ModuleTags {
				coloredTags[i] = terminal.Cyan(tag)
			}
			fmt.Fprintf(os.Stderr, "    %-15s %s\n", terminal.Gray("Module tags:"), strings.Join(coloredTags, terminal.Gray(", ")))
		}
		if len(result.SwarmPlan.Extensions) > 0 {
			fmt.Fprintf(os.Stderr, "    %-15s %s\n", terminal.Gray("Extensions:"), terminal.BoldYellow(fmt.Sprintf("%d generated", len(result.SwarmPlan.Extensions))))
			for _, ext := range result.SwarmPlan.Extensions {
				fmt.Fprintf(os.Stderr, "      %s %s %s\n", terminal.Gray("-"), terminal.BoldCyan(ext.Filename+":"), ext.Reason)
			}
		}
		if len(result.SwarmPlan.FocusAreas) > 0 {
			fmt.Fprintf(os.Stderr, "    %-15s %s\n", terminal.Gray("Focus areas:"), strings.Join(result.SwarmPlan.FocusAreas, ", "))
		}
		if result.SwarmPlan.Notes != "" {
			fmt.Fprintf(os.Stderr, "    %-15s %s\n", terminal.Gray("Notes:"), result.SwarmPlan.Notes)
		}
	}

	if len(result.TriageResults) > 0 {
		fmt.Fprintf(os.Stderr, "\n  %s %s\n", terminal.Aqua(terminal.SymbolInfo), terminal.BoldAqua("Triage:"))
		fmt.Fprintf(os.Stderr, "    %-17s %s\n", terminal.Gray("Confirmed:"), terminal.BoldGreen(fmt.Sprintf("%d", result.Confirmed)))
		fmt.Fprintf(os.Stderr, "    %-17s %s\n", terminal.Gray("False positives:"), terminal.Gray(fmt.Sprintf("%d", result.FalsePositives)))
		fmt.Fprintf(os.Stderr, "    %-17s %d\n", terminal.Gray("Iterations:"), result.Iterations)
	}
}

// colorFindingCount returns a colored finding count based on severity.
func colorFindingCount(count int) string {
	s := fmt.Sprintf("%d", count)
	if count == 0 {
		return terminal.Green(s)
	}
	return terminal.BoldYellow(s)
}

// formatSeverityWithSymbols formats severity counts with colored symbols.
// Example: ❖ 2 high, ◆ 2 medium, • 4 low, ? 1 suspect, ◇ 2 info
func formatSeverityWithSymbols(counts map[string]int) string {
	type sevEntry struct {
		symbol string
		count  int
		label  string
	}
	entries := []sevEntry{
		{terminal.CriticalSymbol(), counts["critical"], "critical"},
		{terminal.HighSymbol(), counts["high"], "high"},
		{terminal.MediumSymbol(), counts["medium"], "medium"},
		{terminal.LowSymbol(), counts["low"], "low"},
		{terminal.SuspectSymbol(), counts["suspect"], "suspect"},
		{terminal.InfoSeveritySymbol(), counts["info"], "info"},
	}

	var parts []string
	for _, e := range entries {
		if e.count > 0 {
			parts = append(parts, fmt.Sprintf("%s %d %s", e.symbol, e.count, e.label))
		}
	}
	return strings.Join(parts, ", ")
}

func truncateSwarmInput(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
