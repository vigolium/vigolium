package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

const defaultAutopilotMaxCommands = 100

// agent autopilot flags
var (
	autopilotTarget          string
	autopilotInput           string
	autopilotAgent           string
	autopilotSource          string
	autopilotFiles           []string
	autopilotFocus           string
	autopilotTimeout         time.Duration
	autopilotDryRun          bool
	autopilotShowPrompt      bool
	autopilotMaxCommands     int
	autopilotInstruction     string
	autopilotInstructionFile string
	autopilotMcpServers      []string
	autopilotMcpEnabled      bool
	autopilotBrowser         bool
	autopilotCredentials     string
	autopilotAuthRequired    bool
	autopilotRequiresBrowser bool
	autopilotBrowserStartURL string
	autopilotFocusRoutes     []string
	autopilotNoArchon        bool
	autopilotArchonMode      string
	autopilotDiff            string
	autopilotLastCommits     int
	autopilotIntensity       string
	autopilotUploadResults   bool
)

var agentAutopilotCmd = &cobra.Command{
	Use:   "autopilot [prompt]",
	Short: "Agentic scan: autonomous AI-driven vulnerability scanning",
	Long: `Launch an agentic scan that autonomously discovers, scans, and triages
vulnerabilities using vigolium CLI commands.

The agent runs commands like scan-url, finding, traffic via its terminal
capabilities to discover endpoints, scan for vulnerabilities, review
results, and iterate until done.

When --source is provided, archon-audit runs before the autonomous agent.
Autopilot prepares the source audit into a stable context bundle and native
plan, then launches the operator against that prepared context.
Use --no-archon to disable this behavior.

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
The target URL is extracted from the input when --target is not provided.

Intensity presets (--intensity) bundle multiple settings into a single flag:
  quick     — Fast CI/PR scans: 30 commands, 1h timeout, lite archon
  balanced  — Standard assessment (default): 100 commands, 6h timeout, scan archon
  deep      — Thorough pentest: 300 commands, 12h timeout, deep archon, browser enabled

Explicit flags always override intensity presets.`,
	Args: cobra.MaximumNArgs(1),
	Example: `  # Natural language prompt — target, source, and focus are auto-extracted
  vigolium agent autopilot "scan VAmPI source at ~/src/VAmPI on localhost:3005"
  vigolium agent autopilot "test auth bypass on https://app.example.com"

  # Scan a target URL
  vigolium agent autopilot -t https://example.com/api

  # Scan with application source code (triggers archon-audit automatically)
  vigolium agent autopilot -t https://example.com --source ./src

  # Pipe a curl command or raw HTTP request via stdin
  curl -s https://example.com/api/users | vigolium agent autopilot
  cat request.txt | vigolium agent autopilot -t https://example.com

  # Pass a curl command or raw HTTP as input
  vigolium agent autopilot --input "curl -X POST -H 'Content-Type: application/json' -d '{\"user\":\"admin\"}' https://example.com/api/login"

  # Focus on specific vulnerability types
  vigolium agent autopilot -t https://example.com --focus "auth bypass and IDOR"

  # Deep scan with browser and extended limits
  vigolium agent autopilot -t https://example.com --intensity deep

  # Quick CI/PR scan with short timeout
  vigolium agent autopilot -t https://example.com --source ./src --intensity quick

  # Source-aware scan with specific files and custom instructions
  vigolium agent autopilot -t https://example.com --source ./src --files "routes/api.js,controllers/auth.js" --instruction "Focus on the new payment endpoint"

  # Scan a PR diff for security regressions
  vigolium agent autopilot -t https://example.com --source ./src --diff "main...feature-branch"
  vigolium agent autopilot -t https://example.com --source ./src --last-commits 3

  # Use a specific agent backend
  vigolium agent autopilot -t https://example.com --agent gemini

  # Enable browser-based auth flow
  vigolium agent autopilot -t https://example.com --browser --credentials "admin/admin123"

  # Preview the rendered prompt without executing
  vigolium agent autopilot -t https://example.com --source ./src --dry-run

  # Disable archon-audit when using --source
  vigolium agent autopilot -t https://example.com --source ./src --no-archon`,
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
	f.DurationVar(&autopilotTimeout, "timeout", 6*time.Hour, "Maximum duration for the autopilot session")
	f.BoolVar(&autopilotDryRun, "dry-run", false, "Render the system prompt without launching the agent")
	f.BoolVar(&autopilotShowPrompt, "show-prompt", false, "Print rendered prompt to stderr before executing")
	f.IntVar(&autopilotMaxCommands, "max-commands", defaultAutopilotMaxCommands, "Maximum number of CLI commands the agent can execute")
	f.StringVar(&autopilotInstruction, "instruction", "", "Custom instruction to guide the agent (appended to prompt)")
	f.StringVar(&autopilotInstructionFile, "instruction-file", "", "Path to a file containing custom instructions")
	f.StringSliceVar(&autopilotMcpServers, "mcp-server", nil, "MCP servers to attach (format: name=command,arg1,arg2 or name=http://url)")
	f.BoolVar(&autopilotMcpEnabled, "mcp-enabled", false, "Enable MCP server passthrough to agent sessions")
	f.BoolVar(&autopilotBrowser, "browser", false, "Enable agent-browser for browser-based interactions")
	f.StringVar(&autopilotCredentials, "credentials", "", "Credentials for auth preflight (e.g. 'admin/admin123, compare user/user123')")
	f.BoolVar(&autopilotAuthRequired, "auth-required", false, "Require auth/session preparation before the autonomous operator starts")
	f.BoolVar(&autopilotRequiresBrowser, "requires-browser", false, "Require browser-assisted auth/setup instead of HTTP-only preflight")
	f.StringVar(&autopilotBrowserStartURL, "browser-start-url", "", "Explicit browser/login start URL for auth preflight")
	f.StringSliceVar(&autopilotFocusRoutes, "focus-routes", nil, "Protected or browser-focused routes to prioritize after auth")
	f.BoolVar(&autopilotNoArchon, "no-archon", false, "Disable automatic archon-audit (enabled by default when --source is set)")
	f.StringVar(&autopilotArchonMode, "archon-mode", "lite", "Archon audit mode: lite (3-phase), balanced (6-phase), deep (10-phase), or mock (sample output, no agent)")
	f.StringVar(&autopilotDiff, "diff", "", "Focus on changed code: PR URL (github.com/.../pull/123), git ref range (main...branch), or HEAD~N")
	f.IntVar(&autopilotLastCommits, "last-commits", 0, "Focus on last N commits (shorthand for --diff HEAD~N)")
	f.StringVar(&autopilotIntensity, "intensity", "balanced", "Scan intensity preset: quick, balanced, or deep")

	f.BoolVar(&autopilotUploadResults, "upload-results", false, "Upload scan results to cloud storage after completion (requires storage config)")
}

func runAgentAutopilot(cmd *cobra.Command, args []string) error {
	defer syncLogger()
	defer closeDatabaseOnExit()

	// Natural language prompt: positional arg takes precedence when no explicit flags are set
	hasExplicitFlags := autopilotTarget != "" || autopilotInput != "" || autopilotSource != ""
	if len(args) > 0 && !hasExplicitFlags {
		return runAutopilotFromPrompt(args[0])
	}

	// Resolve intensity preset — apply before other flag processing
	intensity, err := agent.ValidateIntensity(autopilotIntensity)
	if err != nil {
		return err
	}
	if cmd != nil {
		changed := map[string]bool{
			"max-commands": cmd.Flags().Changed("max-commands"),
			"timeout":      cmd.Flags().Changed("timeout"),
			"archon-mode":  cmd.Flags().Changed("archon-mode"),
			"no-archon":    cmd.Flags().Changed("no-archon"),
			"browser":      cmd.Flags().Changed("browser"),
		}
		intensityResult := agent.ResolveAutopilotIntensity(intensity, agent.AutopilotIntensityPreset{
			MaxCommands: autopilotMaxCommands,
			Timeout:     autopilotTimeout,
			ArchonMode:  autopilotArchonMode,
			Browser:     autopilotBrowser,
		}, changed)
		autopilotMaxCommands = intensityResult.MaxCommands
		autopilotTimeout = intensityResult.Timeout
		autopilotArchonMode = intensityResult.ArchonMode
		autopilotBrowser = intensityResult.Browser
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

	// Resolve effective agent name
	effectiveAgent := autopilotAgent
	if effectiveAgent == "" {
		effectiveAgent = settings.Agent.DefaultAgent
	}

	engine := agent.NewEngine(settings, repo)
	defer engine.Close()

	// Auto-cleanup orphaned processes, stale temp dirs, and old sessions
	sessionsDir := settings.Agent.EffectiveSessionsDir()
	if n := agent.CleanupOrphanedProcesses(sessionsDir); n > 0 {
		zap.L().Info("Cleaned up orphaned autopilot processes", zap.Int("count", n))
	}
	agent.CleanupStaleTempDirs()
	if n, err := agent.CleanupSessionDirs(sessionsDir, 48*time.Hour); err == nil && n > 0 {
		zap.L().Debug("Cleaned up stale session directories", zap.Int("count", n))
	}

	// Context with cancellation and signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if autopilotTimeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, autopilotTimeout)
		defer cancel()
	}
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		zap.L().Info("Signal received, shutting down autopilot")
		cancel()
	}()

	// Create session directory for agent artifacts
	autopilotRunID := uuid.New().String()
	sessionDir, sdErr := agent.EnsureSessionDir(sessionsDir, autopilotRunID)
	if sdErr != nil {
		zap.L().Warn("Failed to create session dir", zap.Error(sdErr))
	}

	// Write PID file for orphan detection on future startups
	if sessionDir != "" {
		if pidErr := agent.WriteRunPID(sessionDir); pidErr != nil {
			zap.L().Warn("Failed to write PID file", zap.Error(pidErr))
		}
		defer agent.RemoveRunPID(sessionDir)
	}

	if looksLikeGCSPath(autopilotSource) {
		extractedPath, cleanup, gcsErr := resolveGCSSource(&settings.Storage, autopilotSource, "")
		if gcsErr != nil {
			return fmt.Errorf("failed to resolve gs:// source: %w", gcsErr)
		}
		defer cleanup()
		autopilotSource = extractedPath
	}

	// Resolve source (git URL, archive, local path) and diff context
	var diffCtx *agenttypes.DiffContext
	if autopilotSource != "" || autopilotDiff != "" || autopilotLastCommits > 0 {
		var err error
		autopilotSource, autopilotFiles, diffCtx, err = agent.ResolveSourceAndDiff(
			autopilotSource, autopilotDiff, autopilotLastCommits, autopilotFiles, sessionDir)
		if err != nil {
			return err
		}
	}

	sourceOnly := autopilotTarget == "" && autopilotSource != ""

	fmt.Fprintf(os.Stderr, "%s %s\n", terminal.HiBlue(terminal.SymbolSparkle), terminal.BoldHiBlue("Agent Configuration"))

	// Mode + Agent + Model
	mode := "autopilot"
	if sourceOnly {
		mode = "autopilot (source-only)"
	}
	effectiveModel := ""
	if def, ok := settings.Agent.Backends[effectiveAgent]; ok && def.Model != "" {
		effectiveModel = def.Model
	}
	modeLine := fmt.Sprintf("  %s Mode: %s | Agent: %s",
		terminal.Purple(terminal.SymbolInfo),
		terminal.HiTeal(mode),
		terminal.HiTeal(effectiveAgent))
	if effectiveModel != "" {
		modeLine += fmt.Sprintf(" | Model: %s", terminal.HiTeal(effectiveModel))
	}
	fmt.Fprintln(os.Stderr, modeLine)

	// Intensity
	fmt.Fprintf(os.Stderr, "  %s Intensity: %s\n", terminal.Purple(terminal.SymbolInfo), terminal.HiTeal(autopilotIntensity))

	// Target
	if autopilotTarget != "" {
		fmt.Fprintf(os.Stderr, "  %s Target: %s\n", terminal.Purple(terminal.SymbolTarget), terminal.Orange(autopilotTarget))
	} else {
		fmt.Fprintf(os.Stderr, "  %s Target: %s\n", terminal.Purple(terminal.SymbolTarget),
			terminal.Red("none (no dynamic testing)"))
	}

	// Source
	if autopilotSource != "" {
		fmt.Fprintf(os.Stderr, "  %s Source: %s\n", terminal.Purple(terminal.SymbolInfo), terminal.HiTeal(terminal.ShortenHome(autopilotSource)))
	}

	// Diff
	if diffCtx != nil {
		fmt.Fprintf(os.Stderr, "  %s Diff: %s (%d changed files)\n",
			terminal.Purple(terminal.SymbolInfo),
			terminal.HiTeal(diffCtx.DiffRef),
			len(diffCtx.ChangedFiles))
	}

	// Archon
	if !autopilotNoArchon && autopilotSource != "" {
		fmt.Fprintf(os.Stderr, "  %s Archon: %s %s\n", terminal.Purple(terminal.SymbolInfo),
			terminal.HiGreen(autopilotArchonMode+" mode"), terminal.Muted("(source audit first)"))
	} else if autopilotNoArchon && autopilotSource != "" {
		fmt.Fprintf(os.Stderr, "  %s Archon: %s\n", terminal.Purple(terminal.SymbolInfo),
			terminal.Muted("disabled (--no-archon)"))
	}

	// Focus / instruction
	if autopilotFocus != "" {
		fmt.Fprintf(os.Stderr, "  %s Focus: %s\n", terminal.Purple(terminal.SymbolInfo), terminal.Orange(autopilotFocus))
	}

	// Limits
	durationStr := "unlimited"
	if autopilotTimeout > 0 {
		durationStr = autopilotTimeout.String()
	}
	fmt.Fprintf(os.Stderr, "  %s Limits: max-commands=%s | duration=%s\n",
		terminal.Purple(terminal.SymbolInfo),
		terminal.HiBlue(fmt.Sprintf("%d", autopilotMaxCommands)),
		terminal.HiBlue(durationStr))

	// Session
	if sessionDir != "" {
		fmt.Fprintf(os.Stderr, "  %s Session: %s\n", terminal.Purple(terminal.SymbolInfo),
			terminal.Muted(terminal.ShortenHome(sessionDir)))
	}

	// Merge CLI MCP servers onto the resolved agent definition
	mergeAgentMcpServers(settings, autopilotAgent, cliMcpServers)

	// Warn if protocol is not SDK (autopilot requires SDK for full tool access)
	protocol := engine.ResolveAgentProtocol(autopilotAgent)
	if protocol != "sdk" {
		fmt.Fprintf(os.Stderr, "%s Autopilot requires SDK protocol for full tool access. "+
			"Current backend uses %q. Consider using: vigolium agent swarm\n",
			terminal.WarningSymbol(), protocol)
	}

	return runAutopilotAutonomous(ctx, engine, settings, repo, sessionDir, instruction, diffCtx)
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
func runAutopilotAutonomous(ctx context.Context, engine *agent.Engine, settings *config.Settings, repo *database.Repository, sessionDir, instruction string, diffCtx *agenttypes.DiffContext) error {
	var streamWriter io.Writer
	if settings.Agent.StreamEnabled() {
		streamWriter = os.Stdout
	}
	// Persist the stream to {sessionDir}/runtime.log so `vigolium log <uuid>`
	// can replay it later, regardless of StreamEnabled.
	if tee, closer := teeToRuntimeLog(streamWriter, sessionDir); closer != nil {
		streamWriter = tee
		defer func() { _ = closer.Close() }()
	}

	projectUUID, _ := resolveProjectUUID()

	cfg := agent.AutopilotPipelineConfig{
		TargetURL:        autopilotTarget,
		SourcePath:       autopilotSource,
		Files:            autopilotFiles,
		Instruction:      instruction,
		Focus:            autopilotFocus,
		AgentName:        autopilotAgent,
		MaxCommands:      autopilotMaxCommands,
		DryRun:           autopilotDryRun,
		ShowPrompt:       autopilotShowPrompt,
		SessionsDir:      settings.Agent.EffectiveSessionsDir(),
		SessionDir:       sessionDir,
		ProjectUUID:      projectUUID,
		ScanUUID:         globalScanID,
		StreamWriter:     streamWriter,
		DiffContext:      diffCtx,
		Credentials:      autopilotCredentials,
		AuthRequired:     autopilotAuthRequired,
		BrowserRequested: autopilotBrowser || autopilotRequiresBrowser,
		RequiresBrowser:  autopilotRequiresBrowser,
		BrowserStartURL:  autopilotBrowserStartURL,
		FocusRoutes:      append([]string(nil), autopilotFocusRoutes...),
	}

	// Wire archon (enabled by default when source is provided)
	if auditCfg := agent.ResolveAuditAgentConfig(autopilotNoArchon, autopilotArchonMode, autopilotSource, settings.Agent.Archon); auditCfg != nil {
		cfg.Archon = auditCfg
	}

	// Wire browser
	cfg.BrowserEnabled = settings.Agent.Browser.IsEnabled()

	// Persist a parent autopilot AgenticScan row whose UUID matches the session
	// dir basename, so `vigolium agent sessions` lists the run with a UUID
	// that resolves directly to ~/.vigolium/agent-sessions/<uuid>/.
	startedAt := time.Now()
	parentRunUUID := ""
	if sessionDir != "" {
		parentRunUUID = filepath.Base(sessionDir)
	}
	if repo != nil && parentRunUUID != "" {
		effectiveAutopilotAgent := autopilotAgent
		if effectiveAutopilotAgent == "" {
			effectiveAutopilotAgent = settings.Agent.DefaultAgent
		}
		parentProtocol, parentModel := settings.Agent.BackendMeta(effectiveAutopilotAgent)
		parentRun := &database.AgenticScan{
			UUID:        parentRunUUID,
			ProjectUUID: projectUUID,
			ScanUUID:    globalScanID,
			Mode:        "autopilot",
			AgentName:   autopilotAgent,
			Protocol:    parentProtocol,
			Model:       parentModel,
			TargetURL:   autopilotTarget,
			SourcePath:  autopilotSource,
			SourceType:  database.InferSourceType(autopilotSource),
			SessionDir:  sessionDir,
			Status:      "running",
			StartedAt:   startedAt,
		}
		if err := repo.CreateAgenticScan(ctx, parentRun); err != nil {
			zap.L().Debug("Failed to create parent autopilot AgenticScan", zap.Error(err))
		}
	}

	cfg.ParentRunUUID = parentRunUUID

	runner := agent.NewAutopilotPipelineRunner(engine, repo)
	result, err := runner.RunAutonomous(ctx, cfg)
	finalizeAutopilotParentRun(repo, parentRunUUID, sessionDir, startedAt, result, err)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("autopilot session timed out after %s", autopilotTimeout)
		}
		return fmt.Errorf("autopilot session failed: %w", err)
	}

	printAutopilotSummary(result, cfg.SessionDir)

	if autopilotUploadResults {
		uploadAgenticScanResults(settings, projectUUID, parentRunUUID, sessionDir, repo)
	}

	return nil
}

// finalizeAutopilotParentRun reads the existing parent AgenticScan row and updates
// it with completion state — status, duration, finding count, raw output. The
// Get/mutate/Update pattern preserves any fields the archon child runner may
// have written between create and finalize.
func finalizeAutopilotParentRun(repo *database.Repository, runUUID, sessionDir string, startedAt time.Time, result *agent.AutopilotPipelineResult, runErr error) {
	if repo == nil || runUUID == "" {
		return
	}
	ctx := context.Background()
	run, err := repo.GetAgenticScan(ctx, runUUID)
	if err != nil || run == nil {
		zap.L().Debug("finalizeAutopilotParentRun: run not found", zap.String("uuid", runUUID), zap.Error(err))
		return
	}
	now := time.Now()
	run.CompletedAt = now
	run.DurationMs = now.Sub(startedAt).Milliseconds()
	if runErr != nil {
		run.Status = "failed"
		run.ErrorMessage = runErr.Error()
	} else {
		run.Status = "completed"
	}
	if result != nil {
		run.FindingCount = result.ArchonFindingsCount
		if result.VerifiedFindingCount > 0 {
			run.FindingCount = result.VerifiedFindingCount
		}
		if result.SessionDir != "" {
			run.SessionDir = result.SessionDir
		}
		if len(result.Warnings) > 0 {
			run.ErrorMessage = strings.Join(result.Warnings, "\n")
		}
	}
	if sessionDir != "" {
		if data, readErr := os.ReadFile(filepath.Join(sessionDir, "output.md")); readErr == nil {
			run.AgentRawOutput = string(data)
		}
	}
	if err := repo.UpdateAgenticScan(ctx, run); err != nil {
		zap.L().Debug("finalizeAutopilotParentRun: update failed", zap.String("uuid", runUUID), zap.Error(err))
	}
}

// printAutopilotSummary renders the final block shown after an autopilot run:
// duration, session dir, target, source, and (when present) the archon findings
// breakdown with colored severity counts.
func printAutopilotSummary(result *agent.AutopilotPipelineResult, fallbackSessionDir string) {
	fmt.Fprintf(os.Stderr, "\n%s Autonomous autopilot session complete (%s)\n",
		terminal.SuccessSymbol(),
		result.Duration.Round(time.Second))

	bullet := terminal.Purple(terminal.SymbolInfo)

	sessionDir := result.SessionDir
	if sessionDir == "" {
		sessionDir = fallbackSessionDir
	}
	if sessionDir != "" {
		fmt.Fprintf(os.Stderr, "  %s Session: %s\n", bullet, terminal.Cyan(sessionDir))
	}

	if autopilotTarget != "" {
		fmt.Fprintf(os.Stderr, "  %s Target:  %s\n", bullet, terminal.Orange(autopilotTarget))
	} else {
		fmt.Fprintf(os.Stderr, "  %s Target:  %s\n", bullet, terminal.Gray("none (source-only)"))
	}

	if autopilotSource != "" {
		fmt.Fprintf(os.Stderr, "  %s Source:  %s\n", bullet, terminal.Orange(autopilotSource))
	}

	if result.ArchonFindingsCount > 0 {
		flag := terminal.Purple(terminal.SymbolFlag)
		fmt.Fprintf(os.Stderr, "  %s Findings: %s parsed, %s imported\n",
			flag,
			terminal.HiTeal(fmt.Sprintf("%d", result.ArchonFindingsCount)),
			terminal.HiTeal(fmt.Sprintf("%d", result.ArchonFindingsSaved)))
		stats := agent.FindingStats{BySeverity: result.ArchonFindingsBySeverity}
		if breakdown := stats.SeverityBreakdownString(); breakdown != "" {
			fmt.Fprintf(os.Stderr, "    %s %s\n", terminal.Gray(terminal.SymbolDot), breakdown)
		}
	}
	if result.VerifiedFindingCount > 0 {
		fmt.Fprintf(os.Stderr, "  %s Verified: %s\n", bullet, terminal.HiTeal(fmt.Sprintf("%d", result.VerifiedFindingCount)))
	}
	if result.BrowserDecision != "" {
		fmt.Fprintf(os.Stderr, "  %s Browser: %s\n", bullet, terminal.HiBlue(result.BrowserDecision))
	}
	if len(result.Warnings) > 0 {
		fmt.Fprintf(os.Stderr, "  %s Warnings: %d\n", bullet, len(result.Warnings))
		for _, w := range result.Warnings {
			fmt.Fprintf(os.Stderr, "    %s %s\n", terminal.WarningSymbol(), w)
		}
	}
}

// runAutopilotFromPrompt parses a natural language prompt and runs autopilot for each extracted app.
func runAutopilotFromPrompt(prompt string) error {
	intent, engine, settings, repo, err := parsePromptIntent(prompt)
	if err != nil {
		return err
	}
	defer engine.Close()
	if intent.Cleanup != nil {
		defer intent.Cleanup.Cleanup()
	}

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
	if app.Archon == "off" {
		autopilotNoArchon = true
	} else if app.Archon != "" {
		autopilotArchonMode = app.Archon
	}
	if app.Diff != "" && autopilotDiff == "" {
		autopilotDiff = app.Diff
	}
	if len(app.Files) > 0 && len(autopilotFiles) == 0 {
		autopilotFiles = app.Files
	}
	if app.Browser {
		autopilotBrowser = true
	}
	if app.Credentials != "" && autopilotCredentials == "" {
		autopilotCredentials = app.Credentials
	}
	if app.AuthRequired {
		autopilotAuthRequired = true
	}
	if app.RequiresBrowser {
		autopilotRequiresBrowser = true
	}
	if app.BrowserStartURL != "" && autopilotBrowserStartURL == "" {
		autopilotBrowserStartURL = app.BrowserStartURL
	}
	if len(app.FocusRoutes) > 0 && len(autopilotFocusRoutes) == 0 {
		autopilotFocusRoutes = append([]string(nil), app.FocusRoutes...)
	}
	if app.MaxCommands > 0 && autopilotMaxCommands == defaultAutopilotMaxCommands {
		autopilotMaxCommands = app.MaxCommands
	}
	if app.Timeout != "" {
		if d, err := time.ParseDuration(app.Timeout); err == nil {
			autopilotTimeout = d
		}
	}
	if app.Intensity != "" && autopilotIntensity == "balanced" {
		autopilotIntensity = app.Intensity
	}
	fmt.Fprintf(os.Stderr, "%s Resolved: target=%s source=%s\n",
		terminal.SuccessSymbol(),
		valueOrNone(autopilotTarget),
		valueOrNone(terminal.ShortenHome(autopilotSource)))
}

// runMultiAppAutopilot fans out parallel autopilot runs for multiple apps.
func runMultiAppAutopilot(ctx context.Context, engine *agent.Engine, settings *config.Settings, repo *database.Repository, intent *agent.ScanIntent) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if autopilotTimeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, autopilotTimeout)
		defer cancel()
	}
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		zap.L().Info("Signal received, shutting down multi-app autopilot")
		cancel()
	}()

	return runMultiAppFanOut(ctx, intent, func(ctx context.Context, idx int, app agent.AppIntent) error {
		runID := uuid.New().String()
		sessionDir, _ := agent.EnsureSessionDir(settings.Agent.EffectiveSessionsDir(), runID)

		// Write PID file for orphan detection
		if sessionDir != "" {
			if pidErr := agent.WriteRunPID(sessionDir); pidErr != nil {
				zap.L().Warn("Failed to write PID file", zap.Error(pidErr))
			}
			defer agent.RemoveRunPID(sessionDir)
		}

		instruction := mergeIntentInstruction(autopilotInstruction, autopilotInstructionFile, app)
		focus := autopilotFocus
		if app.Focus != "" {
			focus = app.Focus
		}

		// Resolve per-app max-commands: app intent overrides if non-zero, else use CLI flag
		maxCmds := autopilotMaxCommands
		if app.MaxCommands > 0 {
			maxCmds = app.MaxCommands
		}

		// Resolve per-app files: app intent overrides if non-empty
		files := autopilotFiles
		if len(app.Files) > 0 {
			files = app.Files
		}

		fmt.Fprintf(os.Stderr, "%s [%d/%d] Starting autopilot: target=%s source=%s\n",
			terminal.InfoSymbol(), idx+1, len(intent.Apps),
			valueOrNone(app.Target),
			valueOrNone(terminal.ShortenHome(app.SourcePath)))

		var streamWriter io.Writer
		if settings.Agent.StreamEnabled() {
			streamWriter = os.Stdout
		}
		// Persist the stream to {sessionDir}/runtime.log so `vigolium log <uuid>`
		// can replay it later.
		if tee, closer := teeToRuntimeLog(streamWriter, sessionDir); closer != nil {
			streamWriter = tee
			defer func() { _ = closer.Close() }()
		}

		projectUUID, _ := resolveProjectUUID()

		// Resolve per-app source and diff context
		sourcePath := app.SourcePath
		diffRef := app.Diff
		if diffRef == "" {
			diffRef = autopilotDiff
		}
		var diffCtx *agenttypes.DiffContext
		if sourcePath != "" || diffRef != "" {
			var err error
			sourcePath, files, diffCtx, err = agent.ResolveSourceAndDiff(
				sourcePath, diffRef, 0, files, sessionDir)
			if err != nil {
				return fmt.Errorf("failed to resolve source/diff: %w", err)
			}
		}

		cfg := agent.AutopilotPipelineConfig{
			TargetURL:        app.Target,
			SourcePath:       sourcePath,
			Files:            files,
			Instruction:      instruction,
			Focus:            focus,
			AgentName:        autopilotAgent,
			MaxCommands:      maxCmds,
			SessionsDir:      settings.Agent.EffectiveSessionsDir(),
			SessionDir:       sessionDir,
			ProjectUUID:      projectUUID,
			ScanUUID:         globalScanID,
			StreamWriter:     streamWriter,
			DiffContext:      diffCtx,
			Credentials:      firstNonEmptyString(app.Credentials, autopilotCredentials),
			AuthRequired:     app.AuthRequired || autopilotAuthRequired,
			BrowserRequested: app.Browser || autopilotBrowser || app.RequiresBrowser || autopilotRequiresBrowser,
			RequiresBrowser:  app.RequiresBrowser || autopilotRequiresBrowser,
			BrowserStartURL:  firstNonEmptyString(app.BrowserStartURL, autopilotBrowserStartURL),
			FocusRoutes:      firstNonEmptySlice(app.FocusRoutes, autopilotFocusRoutes),
		}

		// Wire archon per-app
		archonMode := autopilotArchonMode
		noArchon := autopilotNoArchon
		if app.Archon == "off" {
			noArchon = true
		} else if app.Archon != "" {
			archonMode = app.Archon
		}
		if auditCfg := agent.ResolveAuditAgentConfig(noArchon, archonMode, sourcePath, settings.Agent.Archon); auditCfg != nil {
			cfg.Archon = auditCfg
		}

		// Wire browser per-app
		browserEnabled := settings.Agent.Browser.IsEnabled() || autopilotBrowser || app.Browser
		cfg.BrowserEnabled = browserEnabled

		runner := agent.NewAutopilotPipelineRunner(engine, repo)
		_, err := runner.RunAutonomous(ctx, cfg)
		return err
	})
}

func firstNonEmptyString(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func firstNonEmptySlice(values ...[]string) []string {
	for _, v := range values {
		if len(v) > 0 {
			return append([]string(nil), v...)
		}
	}
	return nil
}
