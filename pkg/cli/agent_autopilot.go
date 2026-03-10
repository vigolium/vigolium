package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/uuid"
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
	autopilotInput        string
	autopilotAgent        string
	autopilotSource       string
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
results, and iterate until done.

When --source is provided, the agent will also analyze the application
source code to discover routes, understand auth flows, and identify
potential vulnerability sinks before scanning.

Supported input types for --input (auto-detected):
  - URL:         https://example.com/api/login
  - Curl:        curl -X POST https://example.com/api -d '{"user":"admin"}'
  - Raw HTTP:    POST /api HTTP/1.1\r\nHost: example.com\r\n...
  - Burp XML:    <?xml...><items><item>...</item></items>
  - Base64:      Base64-encoded raw HTTP request (Burp base64 export)

When input is piped via stdin, it is automatically read (no --input needed).
The target URL is extracted from the input when --target is not provided.`,
	RunE: runAgentAutopilot,
}

func init() {
	agentCmd.AddCommand(agentAutopilotCmd)
	f := agentAutopilotCmd.Flags()

	f.StringVarP(&autopilotTarget, "target", "t", "", "Target URL (derived from --input if not set)")
	f.StringVar(&autopilotInput, "input", "", "Raw input (curl command, raw HTTP, Burp XML, URL). Reads from stdin if piped")
	f.StringVar(&autopilotAgent, "agent", "", "Agent backend to use (default from config)")
	f.StringVar(&autopilotSource, "source", "", "Path to application source code for source-aware scanning")
	f.StringSliceVar(&autopilotFiles, "files", nil, "Specific files to include (relative to --source)")
	f.StringVar(&autopilotFocus, "focus", "", "Focus area hint (e.g. 'API injection', 'auth bypass')")
	f.StringVar(&autopilotSystemPrompt, "system-prompt", "", "Custom system prompt file (overrides default)")
	f.DurationVar(&autopilotTimeout, "timeout", 30*time.Minute, "Maximum duration for the autopilot session")
	f.BoolVar(&autopilotDryRun, "dry-run", false, "Render the system prompt without launching the agent")
	f.IntVar(&autopilotMaxCommands, "max-commands", 100, "Maximum number of CLI commands the agent can execute")
}

func runAgentAutopilot(_ *cobra.Command, _ []string) error {
	defer syncLogger()
	defer closeDatabaseOnExit()

	// Resolve input: explicit --input, stdin pipe, or --input -
	inputData := autopilotInput
	if inputData == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed to read from stdin: %w", err)
		}
		inputData = string(data)
	} else if inputData == "" && autopilotTarget == "" {
		if data, ok := readStdinIfPiped(); ok {
			inputData = data
		}
	}

	// Derive target from input when --target is not provided
	if autopilotTarget == "" && inputData != "" {
		ctx := context.Background()
		targetURL, err := resolveTargetFromInput(ctx, inputData, nil)
		if err != nil {
			return fmt.Errorf("could not derive target from input: %w\nUse --target to specify explicitly", err)
		}
		autopilotTarget = targetURL
	}

	if autopilotTarget == "" {
		return fmt.Errorf("target is required: use --target, --input, or pipe via stdin")
	}

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
		SourcePath:     autopilotSource,
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

	// Create session directory for agent artifacts
	autopilotRunID := "agt-" + uuid.New().String()
	sessionDir, sdErr := agent.EnsureSessionDir(settings.Agent.EffectiveSessionsDir(), autopilotRunID)
	if sdErr != nil {
		zap.L().Warn("Failed to create session dir", zap.Error(sdErr))
	}

	fmt.Fprintf(os.Stderr, "%s Starting autopilot scan against %s\n",
		terminal.InfoSymbol(), terminal.Cyan(autopilotTarget))
	if autopilotSource != "" {
		fmt.Fprintf(os.Stderr, "%s Source code: %s\n",
			terminal.InfoSymbol(), autopilotSource)
	}
	if sessionDir != "" {
		fmt.Fprintf(os.Stderr, "%s Session: %s\n",
			terminal.InfoSymbol(), terminal.Gray(sessionDir))
	}

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

	// Save raw output to session directory
	if sessionDir != "" && result.RawOutput != "" {
		_ = os.WriteFile(sessionDir+"/output.txt", []byte(result.RawOutput), 0644)
	}

	if result.DryRun {
		fmt.Print(result.RawOutput)
		return nil
	}

	printAgentResult(result)
	return nil
}
