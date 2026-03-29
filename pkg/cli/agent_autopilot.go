package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
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

// agent autopilot flags
var (
	autopilotTarget          string
	autopilotInput           string
	autopilotAgent           string
	autopilotSource          string
	autopilotFiles           []string
	autopilotFocus           string
	autopilotTimeout         time.Duration
	autopilotACPCmd          string
	autopilotDryRun          bool
	autopilotShowPrompt      bool
	autopilotMaxCommands     int
	autopilotInstruction     string
	autopilotInstructionFile string
	autopilotMcpServers      []string
	autopilotMcpEnabled  bool
	autopilotSpecialists []string
	autopilotResume      string
	autopilotBrowser     bool
	autopilotAuditAgent  string
)

var agentAutopilotCmd = &cobra.Command{
	Use:   "autopilot [prompt]",
	Short: "Agentic scan: autonomous AI-driven vulnerability scanning",
	Long: `Launch an agentic scan that autonomously discovers, scans, and triages
vulnerabilities using vigolium CLI commands.

The agent runs commands like scan-url, finding, traffic via its terminal
capabilities to discover endpoints, scan for vulnerabilities, review
results, and iterate until done.

When --source is provided, the agent will also analyze the application
source code to discover routes, understand auth flows, and identify
potential vulnerability sinks before scanning.

Supports natural language prompts as a positional argument:
  vigolium agent autopilot "scan VAmPI source at ~/src/VAmPI on localhost:3005"
  vigolium agent autopilot "scan all source code from ~/src/crAPI, ~/src/DVWA"

The prompt is parsed by an AI to extract target URLs, source paths, and focus areas.
Use --dry-run to preview what the parser extracts without executing.

Supported input types for --input (auto-detected):
  - URL:         https://example.com/api/login
  - Curl:        curl -X POST https://example.com/api -d '{"user":"admin"}'
  - Raw HTTP:    POST /api HTTP/1.1\r\nHost: example.com\r\n...
  - Burp XML:    <?xml...><items><item>...</item></items>
  - Base64:      Base64-encoded raw HTTP request (Burp base64 export)

When input is piped via stdin, it is automatically read (no --input needed).
The target URL is extracted from the input when --target is not provided.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runAgentAutopilot,
}

func init() {
	agentCmd.AddCommand(agentAutopilotCmd)
	f := agentAutopilotCmd.Flags()

	f.StringVarP(&autopilotTarget, "target", "t", "", "Target URL (derived from --input if not set)")
	f.StringVar(&autopilotInput, "input", "", "Raw input (curl command, raw HTTP, Burp XML, URL). Reads from stdin if piped")
	f.StringVar(&autopilotAgent, "agent", "", "Agent backend to use (default from config)")
	f.StringVar(&autopilotACPCmd, "agent-acp-cmd", "", "Custom ACP agent command (e.g. 'traecli acp'), overrides --agent")
	f.StringVar(&autopilotSource, "source", "", "Path to application source code for source-aware scanning")
	f.StringSliceVar(&autopilotFiles, "files", nil, "Specific files to include (relative to --source)")
	f.StringVar(&autopilotFocus, "focus", "", "Focus area hint (e.g. 'API injection', 'auth bypass')")
	f.DurationVar(&autopilotTimeout, "timeout", 6*time.Hour, "Maximum duration for the autopilot session")
	f.BoolVar(&autopilotDryRun, "dry-run", false, "Render the system prompt without launching the agent")
	f.BoolVar(&autopilotShowPrompt, "show-prompt", false, "Print rendered prompt to stderr before executing")
	f.IntVar(&autopilotMaxCommands, "max-commands", 100, "Maximum number of CLI commands the agent can execute")
	f.StringVar(&autopilotInstruction, "instruction", "", "Custom instruction to guide the agent (appended to prompt)")
	f.StringVar(&autopilotInstructionFile, "instruction-file", "", "Path to a file containing custom instructions")
	f.StringSliceVar(&autopilotMcpServers, "mcp-server", nil, "MCP servers to attach (format: name=command,arg1,arg2 or name=http://url)")
	f.BoolVar(&autopilotMcpEnabled, "mcp-enabled", false, "Enable MCP server passthrough to ACP sessions")
	f.StringSliceVar(&autopilotSpecialists, "specialists", nil, "Vulnerability classes for specialist pipeline (injection, xss, auth, ssrf, authz)")
	f.StringVar(&autopilotResume, "resume", "", "Resume from a previous session directory")
	f.BoolVar(&autopilotBrowser, "browser", false, "Enable agent-browser for browser-based interactions")
	f.StringVar(&autopilotAuditAgent, "audit-agent", "", "Run background vig-audit-agent for parallel security auditing: 'lite' (6-phase, default) or 'full' (11-phase). Requires --source")
	agentAutopilotCmd.Flag("audit-agent").NoOptDefVal = "lite" // bare --audit-agent defaults to lite
}

func runAgentAutopilot(_ *cobra.Command, args []string) error {
	defer syncLogger()
	defer closeDatabaseOnExit()

	// Natural language prompt: positional arg takes precedence when no explicit flags are set
	hasExplicitFlags := autopilotTarget != "" || autopilotInput != "" || autopilotSource != ""
	if len(args) > 0 && !hasExplicitFlags {
		return runAutopilotFromPrompt(args[0])
	}

	// Resolve input and target
	resolved, err := resolveInputAndTarget(autopilotTarget, autopilotInput)
	if err != nil {
		return err
	}
	autopilotTarget = resolved.Target

	if autopilotTarget == "" && autopilotSource == "" {
		return fmt.Errorf("target is required: use --target, --input, --source, or pipe via stdin\n\nOr use a natural language prompt:\n  vigolium agent autopilot \"scan source at ~/src/app on localhost:3005\"")
	}
	if autopilotTarget == "" {
		fmt.Fprintf(os.Stderr, "%s No --target specified. Running source-only analysis; dynamic testing will be skipped.\n",
			terminal.WarningSymbol())
	}

	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		zap.L().Warn("Failed to load settings, using defaults", zap.Error(err))
		settings = config.DefaultSettings()
	}

	// --mcp-enabled flag overrides config
	if autopilotMcpEnabled {
		enabled := true
		settings.Agent.McpEnabled = &enabled
	}

	// --browser flag overrides config
	if autopilotBrowser {
		enabled := true
		settings.Agent.Browser.Enable = &enabled
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

	instruction, err := resolveInstruction(autopilotInstruction, autopilotInstructionFile)
	if err != nil {
		return err
	}

	// Parse --mcp-server flags into config and merge with YAML-defined servers
	cliMcpServers := parseMcpServerFlags(autopilotMcpServers)

	engine := agent.NewEngine(settings, repo)
	defer engine.Close()

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

	if autopilotTarget != "" {
		fmt.Fprintf(os.Stderr, "%s Starting agentic scan (autopilot) against %s\n",
			terminal.InfoSymbol(), terminal.Cyan(autopilotTarget))
	} else {
		fmt.Fprintf(os.Stderr, "%s Starting source-only agentic scan (autopilot)\n",
			terminal.InfoSymbol())
	}
	if autopilotSource != "" {
		fmt.Fprintf(os.Stderr, "%s Source code: %s\n",
			terminal.InfoSymbol(), terminal.ShortenHome(autopilotSource))
	}
	if sessionDir != "" {
		fmt.Fprintf(os.Stderr, "%s Session: %s\n",
			terminal.InfoSymbol(), terminal.Gray(terminal.ShortenHome(sessionDir)))
	}

	// Merge CLI MCP servers onto the resolved agent definition
	mergeAgentMcpServers(settings, autopilotAgent, cliMcpServers)

	// Detect agent protocol: SDK gets fully autonomous mode, others get legacy pipeline
	protocol := engine.ResolveAgentProtocol(autopilotAgent)
	if protocol == "sdk" {
		return runAutopilotAutonomous(ctx, engine, settings, repo, sessionDir, instruction)
	}

	// Non-SDK backends fall back to the legacy 5-phase pipeline
	fmt.Fprintf(os.Stderr, "%s Autopilot works best with the Agent SDK backend (protocol: sdk). "+
		"Current backend uses %q protocol.\n"+
		"%s For full autonomy, configure an SDK agent: agent.default_agent: claude-sdk\n"+
		"%s Falling back to legacy specialist pipeline.\n",
		terminal.WarningSymbol(), protocol,
		terminal.WarningSymbol(),
		terminal.WarningSymbol())

	return runAutopilotPipeline(ctx, engine, settings, repo, sessionDir, instruction)
}

// parseMcpServerFlags parses --mcp-server flag values into McpServerConfig.
// Format: "name=command,arg1,arg2" (stdio) or "name=http://url" (HTTP).
func parseMcpServerFlags(flags []string) []config.McpServerConfig {
	var servers []config.McpServerConfig
	for _, flag := range flags {
		parts := strings.SplitN(flag, "=", 2)
		if len(parts) != 2 {
			continue
		}
		name := parts[0]
		value := parts[1]

		if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
			servers = append(servers, config.McpServerConfig{
				Name: name,
				URL:  value,
			})
		} else {
			// Stdio: command,arg1,arg2
			cmdParts := strings.Split(value, ",")
			servers = append(servers, config.McpServerConfig{
				Name:    name,
				Command: cmdParts[0],
				Args:    cmdParts[1:],
			})
		}
	}
	return servers
}

// mergeAgentMcpServers merges CLI MCP servers onto the agent definition in settings.
// CLI servers win on name collision with YAML-defined servers.
// Works on a copy of the agent definition to avoid mutating shared state.
func mergeAgentMcpServers(settings *config.Settings, agentName string, cliServers []config.McpServerConfig) {
	if len(cliServers) == 0 {
		return
	}
	if agentName == "" {
		agentName = settings.Agent.DefaultAgent
	}
	agentDef, ok := settings.Agent.Backends[agentName]
	if !ok {
		return
	}

	// Build set of CLI server names for collision detection
	cliNames := make(map[string]struct{}, len(cliServers))
	for _, s := range cliServers {
		cliNames[s.Name] = struct{}{}
	}

	// Start fresh: keep YAML servers that don't collide, then append CLI servers
	merged := make([]config.McpServerConfig, 0, len(agentDef.McpServers)+len(cliServers))
	for _, s := range agentDef.McpServers {
		if _, collision := cliNames[s.Name]; !collision {
			merged = append(merged, s)
		}
	}
	merged = append(merged, cliServers...)

	// Write back a copy with the new slice (agentDef is already a value copy from the map)
	agentDef.McpServers = merged
	settings.Agent.Backends[agentName] = agentDef
}

// runAutopilotAutonomous runs a fully autonomous agent session using the Agent SDK.
// The agent has full tool access and decides its own workflow — no fixed phases.
func runAutopilotAutonomous(ctx context.Context, engine *agent.Engine, settings *config.Settings, repo *database.Repository, sessionDir, instruction string) error {
	var streamWriter io.Writer
	if settings.Agent.StreamEnabled() {
		streamWriter = os.Stdout
	}

	projectUUID, _ := resolveProjectUUID()

	cfg := agent.AutopilotPipelineConfig{
		TargetURL:    autopilotTarget,
		SourcePath:   autopilotSource,
		Files:        autopilotFiles,
		Instruction:  instruction,
		Focus:        autopilotFocus,
		AgentName:    autopilotAgent,
		MaxCommands:  autopilotMaxCommands,
		DryRun:       autopilotDryRun,
		ShowPrompt:   autopilotShowPrompt,
		SessionsDir:  settings.Agent.EffectiveSessionsDir(),
		SessionDir:   sessionDir,
		ProjectUUID:  projectUUID,
		ScanUUID:     globalScanID,
		StreamWriter: streamWriter,
	}

	// Wire audit agent
	if auditCfg := agent.ResolveAuditAgentConfig(autopilotAuditAgent, settings.Agent.AuditAgent); auditCfg != nil {
		cfg.AuditAgent = auditCfg
	}

	runner := agent.NewAutopilotPipelineRunner(engine, repo)
	result, err := runner.RunAutonomous(ctx, cfg)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("autopilot session timed out after %s", autopilotTimeout)
		}
		return fmt.Errorf("autopilot session failed: %w", err)
	}

	fmt.Fprintf(os.Stderr, "\n%s Autonomous autopilot session complete (%s)\n",
		terminal.SuccessSymbol(),
		result.Duration.Round(time.Second))

	return nil
}

// runAutopilotPipeline runs the multi-agent specialist pipeline.
func runAutopilotPipeline(ctx context.Context, engine *agent.Engine, settings *config.Settings, repo *database.Repository, sessionDir, instruction string) error {
	// Resolve specialists
	specialists := autopilotSpecialists
	if len(specialists) == 0 {
		specialists = []string{"injection", "xss", "auth", "ssrf", "authz"}
	}

	var streamWriter io.Writer
	if settings.Agent.StreamEnabled() {
		streamWriter = os.Stdout
	}

	projectUUID, _ := resolveProjectUUID()

	cfg := agent.AutopilotPipelineConfig{
		TargetURL:   autopilotTarget,
		SourcePath:  autopilotSource,
		Files:       autopilotFiles,
		Instruction: instruction,
		Focus:       autopilotFocus,
		Specialists: agent.ToVulnClasses(specialists),
		AgentName:   autopilotAgent,
		AgentACPCmd: autopilotACPCmd,
		MaxCommands: autopilotMaxCommands,
		DryRun:      autopilotDryRun,
		ShowPrompt:  autopilotShowPrompt,
		SessionsDir: settings.Agent.EffectiveSessionsDir(),
		SessionDir:  sessionDir,
		ResumeDir:   autopilotResume,
		ProjectUUID: projectUUID,
		ScanUUID:    globalScanID,
		StreamWriter: streamWriter,
		ScanFunc:    buildAgentSwarmScanFunc(settings, repo, "", nil, new(string)),
	}

	// Wire audit agent
	if auditCfg := agent.ResolveAuditAgentConfig(autopilotAuditAgent, settings.Agent.AuditAgent); auditCfg != nil {
		cfg.AuditAgent = auditCfg
	}

	runner := agent.NewAutopilotPipelineRunner(engine, repo)
	result, err := runner.Run(ctx, cfg)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("autopilot pipeline timed out after %s", autopilotTimeout)
		}
		return fmt.Errorf("autopilot pipeline failed: %w", err)
	}

	fmt.Fprintf(os.Stderr, "\n%s Autopilot pipeline complete: %d findings, %d confirmed, %d false positives (%s)\n",
		terminal.SuccessSymbol(),
		result.TotalFindings, result.Confirmed, result.FalsePositives,
		result.Duration.Round(time.Second))

	return nil
}

// runAutopilotFromPrompt parses a natural language prompt and runs autopilot for each extracted app.
func runAutopilotFromPrompt(prompt string) error {
	intent, engine, settings, repo, err := parsePromptIntent(prompt)
	if err != nil {
		return err
	}
	defer engine.Close()

	if autopilotDryRun {
		return printIntentDryRun(intent)
	}

	// Single app: populate flags and re-enter the main flow.
	// Close the intent-parsing engine first so runAgentAutopilot creates its own cleanly.
	if len(intent.Apps) == 1 {
		applyIntentToAutopilotFlags(intent.Apps[0])
		engine.Close()
		return runAgentAutopilot(nil, nil)
	}

	// Multi-app: fan-out parallel runs using the already-created engine
	fmt.Fprintf(os.Stderr, "%s Parsed %d apps from prompt, running in parallel\n",
		terminal.InfoSymbol(), len(intent.Apps))
	return runMultiAppAutopilot(context.Background(), engine, settings, repo, intent)
}

// applyIntentToAutopilotFlags populates autopilot package-level flags from an AppIntent.
func applyIntentToAutopilotFlags(app agent.AppIntent) {
	autopilotTarget = app.Target
	autopilotSource = app.SourcePath
	if app.Focus != "" && autopilotFocus == "" {
		autopilotFocus = app.Focus
	}
	if app.Instruction != "" && autopilotInstruction == "" {
		autopilotInstruction = app.Instruction
	}
	fmt.Fprintf(os.Stderr, "%s Resolved: target=%s source=%s\n",
		terminal.SuccessSymbol(),
		valueOrNone(autopilotTarget),
		valueOrNone(terminal.ShortenHome(autopilotSource)))
}

// runMultiAppAutopilot fans out parallel autopilot runs for multiple apps.
func runMultiAppAutopilot(ctx context.Context, engine *agent.Engine, settings *config.Settings, repo *database.Repository, intent *agent.ScanIntent) error {
	if autopilotTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, autopilotTimeout)
		defer cancel()
	}

	return runMultiAppFanOut(ctx, intent, func(ctx context.Context, idx int, app agent.AppIntent) error {
		runID := "agt-" + uuid.New().String()
		sessionDir, _ := agent.EnsureSessionDir(settings.Agent.EffectiveSessionsDir(), runID)

		instruction := mergeIntentInstruction(autopilotInstruction, autopilotInstructionFile, app)
		focus := autopilotFocus
		if app.Focus != "" {
			focus = app.Focus
		}

		fmt.Fprintf(os.Stderr, "%s [%d/%d] Starting autopilot: target=%s source=%s\n",
			terminal.InfoSymbol(), idx+1, len(intent.Apps),
			valueOrNone(app.Target),
			valueOrNone(terminal.ShortenHome(app.SourcePath)))

		var streamWriter io.Writer
		if settings.Agent.StreamEnabled() {
			streamWriter = os.Stdout
		}

		projectUUID, _ := resolveProjectUUID()

		cfg := agent.AutopilotPipelineConfig{
			TargetURL:    app.Target,
			SourcePath:   app.SourcePath,
			Instruction:  instruction,
			Focus:        focus,
			AgentName:    autopilotAgent,
			MaxCommands:  autopilotMaxCommands,
			SessionsDir:  settings.Agent.EffectiveSessionsDir(),
			SessionDir:   sessionDir,
			ProjectUUID:  projectUUID,
			ScanUUID:     globalScanID,
			StreamWriter: streamWriter,
		}

		protocol := engine.ResolveAgentProtocol(autopilotAgent)
		runner := agent.NewAutopilotPipelineRunner(engine, repo)
		if protocol == "sdk" {
			_, err := runner.RunAutonomous(ctx, cfg)
			return err
		}
		_, err := runner.Run(ctx, cfg)
		return err
	})
}
