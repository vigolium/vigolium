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
	autopilotSystemPrompt    string
	autopilotTimeout         time.Duration
	autopilotACPCmd          string
	autopilotDryRun          bool
	autopilotShowPrompt      bool
	autopilotMaxCommands     int
	autopilotInstruction     string
	autopilotInstructionFile string
	autopilotMcpServers      []string
	autopilotMcpEnabled      bool
	autopilotParallel        bool
	autopilotSpecialists     []string
	autopilotResume          string
)

var agentAutopilotCmd = &cobra.Command{
	Use:   "autopilot",
	Short: "Agentic scan: autonomous AI-driven vulnerability scanning",
	Long: `Launch an agentic scan that autonomously discovers, scans, and triages
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
	f.StringVar(&autopilotACPCmd, "agent-acp-cmd", "", "Custom ACP agent command (e.g. 'traecli acp'), overrides --agent")
	f.StringVar(&autopilotSource, "source", "", "Path to application source code for source-aware scanning")
	f.StringSliceVar(&autopilotFiles, "files", nil, "Specific files to include (relative to --source)")
	f.StringVar(&autopilotFocus, "focus", "", "Focus area hint (e.g. 'API injection', 'auth bypass')")
	f.StringVar(&autopilotSystemPrompt, "system-prompt", "", "Custom system prompt file (overrides default)")
	f.DurationVar(&autopilotTimeout, "timeout", 30*time.Minute, "Maximum duration for the autopilot session")
	f.BoolVar(&autopilotDryRun, "dry-run", false, "Render the system prompt without launching the agent")
	f.BoolVar(&autopilotShowPrompt, "show-prompt", false, "Print rendered prompt to stderr before executing")
	f.IntVar(&autopilotMaxCommands, "max-commands", 100, "Maximum number of CLI commands the agent can execute")
	f.StringVar(&autopilotInstruction, "instruction", "", "Custom instruction to guide the agent (appended to prompt)")
	f.StringVar(&autopilotInstructionFile, "instruction-file", "", "Path to a file containing custom instructions")
	f.StringSliceVar(&autopilotMcpServers, "mcp-server", nil, "MCP servers to attach (format: name=command,arg1,arg2 or name=http://url)")
	f.BoolVar(&autopilotMcpEnabled, "mcp-enabled", false, "Enable MCP server passthrough to ACP sessions")
	f.BoolVar(&autopilotParallel, "parallel", false, "Enable v2 multi-agent specialist pipeline")
	f.StringSliceVar(&autopilotSpecialists, "specialists", nil, "Vulnerability classes for parallel pipeline (injection, xss, auth, ssrf, authz)")
	f.StringVar(&autopilotResume, "resume", "", "Resume from a previous session directory")
}

func runAgentAutopilot(_ *cobra.Command, _ []string) error {
	defer syncLogger()
	defer closeDatabaseOnExit()

	// Resolve input and target
	resolved, err := resolveInputAndTarget(autopilotTarget, autopilotInput)
	if err != nil {
		return err
	}
	autopilotTarget = resolved.Target

	if autopilotTarget == "" {
		return fmt.Errorf("target is required: use --target, --input, or pipe via stdin")
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

	fmt.Fprintf(os.Stderr, "%s Starting agentic scan (autopilot) against %s\n",
		terminal.InfoSymbol(), terminal.Cyan(autopilotTarget))
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

	// Parallel pipeline (v2)
	if autopilotParallel {
		return runAutopilotParallel(ctx, engine, settings, repo, sessionDir, instruction)
	}

	// Build agent options (single-agent v1 path)
	opts := agent.Options{
		AgentName:      autopilotAgent,
		AgentACPCmd:    autopilotACPCmd,
		PromptTemplate: "autopilot-system",
		SourcePath:     autopilotSource,
		Files:          autopilotFiles,
		TargetURL:      autopilotTarget,
		Source:         "autopilot",
		DryRun:         autopilotDryRun,
		ShowPrompt:     autopilotShowPrompt,
		ScanUUID:       globalScanID,
		Autopilot:      true,
		MaxCommands:    autopilotMaxCommands,
		Instruction:    instruction,
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
		_ = os.WriteFile(sessionDir+"/output.md", []byte(result.RawOutput), 0644)
	}

	if result.DryRun {
		fmt.Print(result.RawOutput)
		return nil
	}

	printAgentResult(result)
	return nil
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

// runAutopilotParallel runs the v2 multi-agent specialist pipeline.
func runAutopilotParallel(ctx context.Context, engine *agent.Engine, settings *config.Settings, repo *database.Repository, sessionDir, instruction string) error {
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
