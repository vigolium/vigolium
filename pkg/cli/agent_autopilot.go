package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// agent autopilot flags
var (
	autopilotTarget       string
	autopilotAgent        string
	autopilotRepo         string
	autopilotFiles        []string
	autopilotFocus        string
	autopilotSystemPrompt string
	autopilotTimeout      time.Duration
	autopilotDryRun       bool
	autopilotMaxCommands  int
)

var agentAutopilotCmd = &cobra.Command{
	Use:   "autopilot",
	Short: "Autonomous AI-driven vulnerability scanning",
	Long: `Launch an AI agent that autonomously discovers, scans, and triages
vulnerabilities using vigolium CLI commands.

The agent runs commands like scan-url, finding, traffic via its terminal
capabilities to discover endpoints, scan for vulnerabilities, review
results, and iterate until done.`,
	RunE: runAgentAutopilot,
}

func init() {
	agentCmd.AddCommand(agentAutopilotCmd)
	f := agentAutopilotCmd.Flags()

	f.StringVarP(&autopilotTarget, "target", "t", "", "Target URL (required)")
	f.StringVar(&autopilotAgent, "agent", "", "Agent backend to use (default from config)")
	f.StringVar(&autopilotRepo, "repo", "", "Path to source code repository")
	f.StringSliceVar(&autopilotFiles, "files", nil, "Specific files to include (relative to --repo)")
	f.StringVar(&autopilotFocus, "focus", "", "Focus area hint (e.g. 'API injection', 'auth bypass')")
	f.StringVar(&autopilotSystemPrompt, "system-prompt", "", "Custom system prompt file (overrides default)")
	f.DurationVar(&autopilotTimeout, "timeout", 30*time.Minute, "Maximum duration for the autopilot session")
	f.BoolVar(&autopilotDryRun, "dry-run", false, "Render the system prompt without launching the agent")
	f.IntVar(&autopilotMaxCommands, "max-commands", 100, "Maximum number of CLI commands the agent can execute")
	_ = agentAutopilotCmd.MarkFlagRequired("target")
}

func runAgentAutopilot(_ *cobra.Command, _ []string) error {
	defer syncLogger()
	defer closeDatabaseOnExit()

	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		zap.L().Warn("Failed to load settings, using defaults", zap.Error(err))
		settings = config.DefaultSettings()
	}

	// Open DB for context enrichment
	var repo *database.Repository
	db, dbErr := getDB()
	if dbErr == nil {
		ctx := context.Background()
		if schemaErr := db.CreateSchema(ctx); schemaErr != nil {
			zap.L().Warn("Failed to create schema", zap.Error(schemaErr))
		}
		repo = database.NewRepository(db)
	}

	engine := agent.NewEngine(settings, repo)
	defer engine.Close()

	// Build agent options
	opts := agent.Options{
		AgentName:      autopilotAgent,
		PromptTemplate: "autopilot-system",
		RepoPath:       autopilotRepo,
		Files:          autopilotFiles,
		TargetURL:      autopilotTarget,
		Source:         "autopilot",
		DryRun:         autopilotDryRun,
		ScanUUID:       globalScanID,
		Autopilot:      true,
		MaxCommands:    autopilotMaxCommands,
	}

	// Custom system prompt overrides default template
	if autopilotSystemPrompt != "" {
		opts.PromptTemplate = ""
		opts.PromptFile = autopilotSystemPrompt
	}

	// Append focus area if provided
	if autopilotFocus != "" {
		opts.Append = fmt.Sprintf("## Focus Area\n\n%s", autopilotFocus)
	}

	if settings.Agent.StreamEnabled() {
		opts.StreamWriter = os.Stdout
	}

	ctx := context.Background()
	if autopilotTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, autopilotTimeout)
		defer cancel()
	}

	fmt.Fprintf(os.Stderr, "%s Starting autopilot scan against %s\n",
		terminal.InfoSymbol(), terminal.Cyan(autopilotTarget))

	result, err := engine.Run(ctx, opts)
	if err != nil {
		if result != nil && result.Stderr != "" {
			fmt.Fprintf(os.Stderr, "%s Agent stderr:\n%s\n", terminal.WarningSymbol(), result.Stderr)
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("autopilot timed out after %s (use --timeout to adjust)", autopilotTimeout)
		}
		return fmt.Errorf("autopilot failed: %w", err)
	}

	if result.DryRun {
		fmt.Print(result.RawOutput)
		return nil
	}

	printAgentResult(result)
	return nil
}
