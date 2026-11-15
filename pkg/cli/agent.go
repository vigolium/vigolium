package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/apicontract"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/olium"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// oliumProviderFlagUsage is the shared --provider help text for every agent
// subcommand, generated from olium.ProviderNames so the advertised provider set
// always matches exactly what the runtime accepts (no per-command drift).
var oliumProviderFlagUsage = "Olium provider override: " + olium.ProviderNamesString(" | ") + " (default: agent.olium.provider; auto-detected when unset)"

// Agent command flags
var (
	agentLabel           string
	agentPromptTemplate  string
	agentPromptFile      string
	agentSourcePath      string
	agentFiles           []string
	agentAppend          string
	agentOutput          string
	agentSourceLabel     string
	agentListTemplates   bool
	agentListAgents      bool
	agentDryRun          bool
	agentShowPrompt      bool
	agentVerbose         bool
	agentPromptInline    string
	agentStdin           bool
	agentMaxDuration     time.Duration
	agentInstruction     string
	agentInstructionFile string
	agentUploadResults   bool

	// Olium provider override flags for `agent query` — mirror the set
	// exposed by `agent olium` and `agent autopilot` so a one-shot prompt
	// can pick a different provider without editing the config file.
	agentQueryOliumProvider    string
	agentQueryOliumModel       string
	agentQueryOliumOAuthCred   string
	agentQueryOliumOAuthToken  string
	agentQueryOliumLLMAPIKey   string
	agentQueryOliumGCPProject  string
	agentQueryOliumGCPLocation string
	agentQueryOliumBaseURL     string
	agentQueryPreflight        agentPreflightFlags
)

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Run an agentic scan — AI-driven scanning with native scan support",
	Long: `Run an agentic scan using the in-process olium engine for intelligent vulnerability scanning.

Use a subcommand to select the agentic scan mode:
  query      Single-shot prompt execution (template-based or inline)
  autopilot  Agentic scan: autonomous AI-driven vulnerability scanning
  swarm      Agentic scan: AI-guided targeted vulnerability swarm
  olium      Interactive olium agent (TUI or headless prompt)
  audit      Unified security audit (vigolium-audit and/or piolium)

` + agentSetupHelpLine + `
Docs: https://docs.vigolium.com`,
	RunE: func(cmd *cobra.Command, args []string) error {
		defer syncLogger()

		settings, err := clicommon.LoadSettings(globalConfig)
		if err != nil {
			return err
		}

		// Handle --list-agents
		if agentListAgents {
			return printAgentList(cmd, settings)
		}

		// Handle --list-templates
		if agentListTemplates {
			return printTemplateList(cmd, settings)
		}

		// Help is text; under -j it would be the one thing on stdout that is
		// not a document.
		if globalJSON {
			return usageErrorf("agent -j needs a subcommand (agent query, agent session, …) or --list-agents / --list-templates")
		}
		return cmd.Help()
	},
}

var agentQueryCmd = &cobra.Command{
	Use:   "query [prompt]",
	Short: "Send a prompt to an AI agent and get a response",
	Long: `Send a prompt to an AI agent (Claude, Codex) and get a response.

Supports two modes:
  - Template mode: use --prompt-template or --prompt-file with --source for code review
  - Inline mode: pass a prompt as argument, via --prompt/-p, or piped through --stdin`,
	Args: cobra.MaximumNArgs(1),
	RunE: runAgentQuery,
}

func init() {
	rootCmd.AddCommand(agentCmd)
	agentCmd.AddCommand(agentQueryCmd)

	// Parent command flags (informational only)
	af := agentCmd.Flags()
	af.BoolVar(&agentListTemplates, "list-templates", false, "List available prompt templates")
	af.BoolVar(&agentListAgents, "list-agents", false, "List the olium providers available for agent runs")

	// Query command flags
	rf := agentQueryCmd.Flags()
	rf.StringVar(&agentLabel, "agent-label", "", "Label recorded on the AgenticScan DB row; agent dispatch always uses olium")
	rf.StringVar(&agentLabel, "agent", "", "")
	markFlagDeprecated(rf, "agent", "agent-label")
	rf.StringVar(&agentPromptTemplate, "prompt-template", "", "Prompt template ID (e.g. security-code-review)")
	rf.StringVar(&agentPromptFile, "prompt-file", "", "Path to a prompt template file")
	rf.StringVar(&agentSourcePath, "source", "", "Path to source code repository")
	rf.StringSliceVar(&agentFiles, "files", nil, "Specific files to include (relative to --source)")
	rf.StringVar(&agentAppend, "append", "", "Append extra text to the rendered prompt")
	rf.StringVarP(&agentPromptInline, "prompt", "p", "", "Prompt text to send to the agent")
	rf.BoolVar(&agentStdin, "stdin", false, "Read prompt from stdin")
	rf.StringVar(&agentOutput, "output", "", "Write agent output to this file")
	rf.StringVar(&agentSourceLabel, "source-label", "", "Label for records ingested from agent output (e.g. 'agent-review')")
	rf.BoolVar(&agentDryRun, "dry-run", false, "Print the rendered prompt without executing")
	rf.BoolVar(&agentShowPrompt, "show-prompt", false, "Print rendered prompt to stderr before executing")
	rf.BoolVarP(&agentVerbose, "verbose", "v", false, "Show a per-tool head/tail preview of each tool result alongside the standard one-liner")
	rf.DurationVar(&agentMaxDuration, "max-duration", 5*time.Minute, "Maximum wall-clock time for agent execution (0 = no limit)")
	rf.DurationVar(&agentMaxDuration, "agent-timeout", 5*time.Minute, "")
	markFlagDeprecated(rf, "agent-timeout", "max-duration")
	rf.StringVar(&agentInstruction, "instruction", "", "Custom instruction to guide the agent (appended to prompt)")
	rf.StringVar(&agentInstructionFile, "instruction-file", "", "Path to a file containing custom instructions")
	rf.BoolVar(&agentUploadResults, "upload-results", false, "Upload session bundle to cloud storage after completion (requires storage config)")
	rf.StringVar(&agentQueryOliumProvider, "provider", "", oliumProviderFlagUsage)
	rf.StringVar(&agentQueryOliumModel, "model", "", "Olium model id override (falls back to agent.olium.model)")
	rf.StringVar(&agentQueryOliumOAuthCred, "oauth-cred", "", "Olium OAuth/SA credential file (openai-codex-oauth, anthropic-vertex, or google-vertex; falls back to agent.olium.oauth_cred_path or $GOOGLE_APPLICATION_CREDENTIALS)")
	rf.StringVar(&agentQueryOliumOAuthToken, "oauth-token", "", "Olium Anthropic OAuth bearer token (anthropic-oauth provider; falls back to agent.olium.oauth_token or $ANTHROPIC_API_KEY)")
	rf.StringVar(&agentQueryOliumLLMAPIKey, "llm-api-key", "", "Olium API key for key-based providers (falls back to agent.olium.llm_api_key or provider env var)")
	rf.StringVar(&agentQueryOliumGCPProject, "gcp-project", "", "GCP project for Vertex providers (else $GOOGLE_CLOUD_PROJECT, then YAML, then SA file's project_id)")
	rf.StringVar(&agentQueryOliumGCPLocation, "gcp-location", "", "GCP region for Vertex providers (else $GOOGLE_CLOUD_LOCATION, then YAML, then us-central1)")
	registerAgentPreflightFlags(agentQueryCmd, &agentQueryPreflight)
	rf.StringVar(&agentQueryOliumBaseURL, "base-url", "", "Endpoint URL for openai-compatible provider (e.g. http://localhost:11434/v1); falls back to agent.olium.custom_provider.base_url")
}

func runAgentQuery(cmd *cobra.Command, args []string) error {
	// The bash tool's children run against this process's binary, database,
	// project and config (agent_child_env.go).
	installAgentChildEnv()
	defer syncLogger()
	defer closeDatabaseOnExit()

	// Accept first positional arg as the prompt if --prompt wasn't given
	if agentPromptInline == "" && len(args) > 0 {
		agentPromptInline = args[0]
	}

	// Determine mode: template-based or inline
	hasTemplate := agentPromptTemplate != "" || agentPromptFile != ""
	hasInline := agentPromptInline != "" || agentStdin

	if !hasTemplate && !hasInline {
		return usageErrorf("either a prompt (argument, --prompt/-p, --stdin) or a template (--prompt-template, --prompt-file) is required")
	}

	settings, err := clicommon.LoadSettings(globalConfig)
	if err != nil {
		return err
	}

	// Per-run olium overrides — only applied when the operator passed an
	// explicit flag so the saved config keeps its precedence otherwise.
	// Engine.Run reads settings.Agent.Olium directly, so mutating it here
	// is the simplest way to plumb the overrides through.
	if agentQueryOliumProvider != "" {
		settings.Agent.Olium.Provider = agentQueryOliumProvider
	}
	if agentQueryOliumModel != "" {
		settings.Agent.Olium.Model = agentQueryOliumModel
	}
	if agentQueryOliumOAuthCred != "" {
		settings.Agent.Olium.OAuthCredPath = agentQueryOliumOAuthCred
	}
	if agentQueryOliumOAuthToken != "" {
		settings.Agent.Olium.OAuthToken = agentQueryOliumOAuthToken
	}
	if agentQueryOliumLLMAPIKey != "" {
		settings.Agent.Olium.LLMAPIKey = agentQueryOliumLLMAPIKey
	}
	if agentQueryOliumGCPProject != "" {
		settings.Agent.Olium.GoogleCloudProject = agentQueryOliumGCPProject
	}
	if agentQueryOliumGCPLocation != "" {
		settings.Agent.Olium.GoogleCloudLocation = agentQueryOliumGCPLocation
	}
	if agentQueryOliumBaseURL != "" {
		settings.Agent.Olium.CustomProvider.BaseURL = agentQueryOliumBaseURL
	}
	agentQueryPreflight.apply(settings)

	// Open DB for ingestion (optional)
	var repo *database.Repository
	// Write intent: the opener makes the schema ready, so no CreateSchema here.
	db, dbErr := getDBFor(clicommon.IntentWrite)
	if dbErr == nil {
		repo = database.NewRepository(db)
	} else {
		zap.L().Warn("Database unavailable; continuing without persistence", zap.Error(dbErr))
	}

	instruction, err := resolveInstruction(agentInstruction, agentInstructionFile)
	if err != nil {
		return err
	}

	engine := agent.NewEngine(settings, repo)

	ctx := context.Background()
	if cmd != nil && cmd.Context() != nil {
		ctx = cmd.Context()
	}

	// Preflight: validate the provider before building prompts. A dry run
	// renders the prompt only and never calls the provider.
	if !agentDryRun && !agentQueryPreflight.skip {
		if err := engine.Preflight(ctx); err != nil {
			return err
		}
	}

	opts := agent.Options{
		AgentName: agentLabel,

		PromptTemplate: agentPromptTemplate,
		PromptFile:     agentPromptFile,
		PromptInline:   agentPromptInline,
		Stdin:          agentStdin,
		SourcePath:     agentSourcePath,
		Files:          agentFiles,
		Append:         agentAppend,
		Instruction:    instruction,
		OutputPath:     agentOutput,
		Source:         agentSourceLabel,
		DryRun:         agentDryRun,
		ShowPrompt:     agentShowPrompt,
		ScanUUID:       globalScanUUID,
		Verbose:        agentVerbose,
	}
	if settings.Agent.StreamEnabled() {
		opts.StreamWriter = agentStreamSink()
	}

	if agentMaxDuration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, agentMaxDuration)
		defer cancel()
	}

	// Create session directory for agent artifacts. Created before engine.Run
	// so we can tee the stream into {sessionDir}/runtime.log for `vigolium log`.
	queryAgenticScanUUID := pinnedOrNewUUID(globalScanUUID)
	var sessionDir string
	if !agentDryRun {
		var sdErr error
		sessionDir, sdErr = agent.EnsureSessionDir(settings.Agent.EffectiveSessionsDir(), queryAgenticScanUUID)
		if sdErr != nil {
			zap.L().Warn("Failed to create session dir", zap.Error(sdErr))
		}
		opts.SessionDir = sessionDir
	}
	if tee, closer := teeToRuntimeLog(opts.StreamWriter, sessionDir); closer != nil {
		opts.StreamWriter = tee
		defer func() { _ = closer.Close() }()
	}

	// The query's own agentic_scans row, so `agent session`, `log ls` and
	// `finding --agentic-scan` find it like any other agent run. A dry run
	// renders a prompt only and records nothing.
	projectUUID, _ := resolveProjectUUID()
	startedAt := time.Now()
	if !agentDryRun {
		_, model := settings.Agent.BackendMeta()
		startAgenticScanRow(ctx, repo, &database.AgenticScan{
			UUID:        queryAgenticScanUUID,
			ProjectUUID: projectUUID,
			ScanUUID:    globalScanUUID,
			Mode:        "query",
			AgentName:   firstNonEmptyString(agentLabel, "olium"),
			Protocol:    config.AgentProtocolLabel,
			Model:       model,
			TemplateID:  agentPromptTemplate,
			SourcePath:  agentSourcePath,
			SessionDir:  sessionDir,
			StartedAt:   startedAt,
		})
		printAgentRunHandle(queryAgenticScanUUID, sessionDir)
		var stopCancelWatch func()
		ctx, stopCancelWatch = watchAgentCancel(ctx, repo, sessionDir, queryAgenticScanUUID)
		defer stopCancelWatch()
	}

	result, err := engine.Run(ctx, opts)
	if !agentDryRun {
		end := database.AgenticRunEnd{
			Err:       err,
			TimedOut:  err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded),
			Cancelled: err != nil && errors.Is(ctx.Err(), context.Canceled),
		}
		if end.TimedOut {
			end.Err = nil
		}
		dbStatus, _ := agentRunStatus(end)
		fin := agenticScanRowFinish{Status: dbStatus}
		if err != nil {
			fin.ErrorMessage = err.Error()
		}
		if result != nil {
			fin.FindingCount = len(result.Findings)
			fin.SavedCount = result.SavedCount
			fin.Usage = agentRunUsage{InputTokens: int64(result.TokenUsage.InputTokens), OutputTokens: int64(result.TokenUsage.OutputTokens)}
		}
		finishAgenticScanRow(repo, queryAgenticScanUUID, startedAt, fin)
	}
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return incompleteErrorf(apicontract.CodeTimedOut, "agent timed out after %s (use --max-duration to adjust or set to 0 to disable)", agentMaxDuration)
		}
		return agentRunFailure(ctx, err)
	}

	// Save raw output to session directory
	if sessionDir != "" && result.RawOutput != "" {
		if err := os.WriteFile(sessionDir+"/output.md", []byte(result.RawOutput), 0644); err != nil {
			zap.L().Debug("failed to write agent output.md", zap.Error(err))
		}
	}

	if agentUploadResults && sessionDir != "" {
		uploadAgenticScanResults(settings, projectUUID, queryAgenticScanUUID, sessionDir, repo)
	}

	// -j: one read envelope carrying the result (items[0]) and the run's
	// handle. The streamed text went to stderr (or nowhere), never stdout.
	if globalJSON {
		var runUUID string
		if !agentDryRun {
			runUUID = queryAgenticScanUUID
		}
		return emitObject(cmd, ".", result,
			withExtra("agentic_scan_uuid", runUUID),
			withExtra("session_dir", sessionDir),
			withProjectScope(projectUUID))
	}

	// For inline runs without a template, print raw output (skip if already streamed)
	if !hasTemplate && opts.StreamWriter == nil {
		fmt.Print(result.RawOutput)
		return nil
	}

	printAgentResult(result)
	return nil
}

// printAgentList prints the olium providers the runtime accepts and which one
// a run would use: agent.olium.provider when set, else the auto-detected one
// (decision D25: "auto-detect; set agent.olium.provider", the same words the
// README and the preflight error use).
func printAgentList(cmd *cobra.Command, settings *config.Settings) error {
	type providerEntry struct {
		Name        string
		Model       string
		Auth        string
		Description string
	}
	// Display metadata keyed by provider name. The rendered list is driven by
	// olium.ProviderNames (the runtime's source of truth), so every accepted
	// provider always appears — a provider added to the runtime without metadata
	// here still shows up with a generic row rather than silently disappearing.
	meta := map[string]providerEntry{
		"openai-codex-oauth":          {Model: olium.DefaultOpenAIModel, Auth: "~/.codex/auth.json", Description: "OpenAI Codex via ChatGPT OAuth (the auto-detect fallback)"},
		"openai-api-key":              {Model: olium.DefaultOpenAIModel, Auth: "$OPENAI_API_KEY", Description: "OpenAI chat API via API key"},
		"openai-responses":            {Model: olium.DefaultOpenAIModel, Auth: "$OPENAI_API_KEY", Description: "OpenAI Responses API (/v1/responses) via API key"},
		"anthropic-api-key":           {Model: olium.DefaultAnthropicModel, Auth: "$ANTHROPIC_API_KEY", Description: "Anthropic Claude via API key"},
		"anthropic-oauth":             {Model: olium.DefaultAnthropicModel, Auth: "$ANTHROPIC_API_KEY", Description: "Anthropic Claude via OAuth bearer token (claude setup-token)"},
		"anthropic-cli":               {Model: olium.DefaultAnthropicModel, Auth: "claude binary in PATH", Description: "Anthropic Claude via local claude CLI (alias: anthropic-claude-cli)"},
		"anthropic-claude-sdk-bridge": {Model: "(claude default)", Auth: "Claude Code subscription", Description: "Claude Code via Agent SDK (vigolium-audit bridge)"},
		"anthropic-vertex":            {Model: olium.DefaultAnthropicModel, Auth: "GCP service-account JSON", Description: "Anthropic Claude on Google Vertex AI"},
		"google-vertex":               {Model: olium.DefaultGoogleModel, Auth: "GCP service-account JSON", Description: "Google Gemini on Vertex AI"},
		"openai-compatible":           {Model: "custom_provider.model_id", Auth: "custom_provider.base_url", Description: "OpenAI-compatible endpoint (local Ollama/vLLM/gateway)"},
		"anthropic-compatible":        {Model: "custom_provider.model_id", Auth: "custom_provider.base_url", Description: "Anthropic Messages-compatible gateway"},
	}
	defaults := make([]providerEntry, 0, len(olium.ProviderNames))
	for _, name := range olium.ProviderNames {
		e := meta[name]
		e.Name = name
		defaults = append(defaults, e)
	}

	activeProvider, activeSource := activeOliumProvider(settings)

	if globalJSON {
		type apiEntry struct {
			Name        string `json:"name"`
			Model       string `json:"model,omitempty"`
			Auth        string `json:"auth,omitempty"`
			Description string `json:"description,omitempty"`
			IsActive    bool   `json:"is_active"`
		}
		entries := make([]apiEntry, 0, len(defaults))
		for _, p := range defaults {
			entries = append(entries, apiEntry{
				Name:        p.Name,
				Model:       p.Model,
				Auth:        p.Auth,
				Description: p.Description,
				IsActive:    p.Name == activeProvider,
			})
		}
		return emitRead(cmd, "providers", entries, int64(len(entries)), 0, len(entries),
			withExtra("active", activeProvider),
			withExtra("active_source", activeSource),
			withExtra("setup_hint", agent.ProviderSetupHint))
	}

	tbl := terminal.NewTableWithMaxWidth(globalWidth, "PROVIDER", "MODEL", "AUTH", "DESCRIPTION", "ACTIVE")
	for _, p := range defaults {
		active := ""
		if p.Name == activeProvider {
			active = terminal.BoldGreen("*")
		}
		tbl.AddRow(terminal.Cyan(p.Name), p.Model, p.Auth, p.Description, active)
	}
	tbl.Print()
	// The AUTH column names *what* each provider needs; the guide explains how
	// to obtain and wire it. Printed only on the human table (the JSON branch
	// above returns early) so machine consumers stay unaffected.
	if activeSource == "auto-detect" {
		fmt.Printf("\n%s Active: %s (auto-detected; agent.olium.provider is unset)\n", terminal.InfoSymbol(), terminal.Cyan(activeProvider))
	} else {
		fmt.Printf("\n%s Active: %s (agent.olium.provider)\n", terminal.InfoSymbol(), terminal.Cyan(activeProvider))
	}
	fmt.Printf("%s Provider: auto-detected unless agent.olium.provider is set — %s\n", terminal.InfoSymbol(),
		terminal.Cyan("vigolium config set agent.olium.provider <name>"))
	fmt.Printf("%s Setup guide: %s\n", terminal.InfoSymbol(), terminal.Cyan(olium.SetupDocsURL))
	return nil
}

// activeOliumProvider is the provider a run would use and where that answer
// comes from: "config" (agent.olium.provider, or --provider folded into it) or
// "auto-detect" (unset: the runtime picks, see olium.AutoDetectedProvider).
func activeOliumProvider(settings *config.Settings) (name, source string) {
	if p := olium.CanonicalProviderName(settings.Agent.Olium.Provider); p != "" {
		return p, "config"
	}
	return olium.AutoDetectedProvider(), "auto-detect"
}

func printTemplateList(cmd *cobra.Command, settings *config.Settings) error {
	templates, err := agent.ListTemplates(settings.Agent.TemplatesDir)
	if err != nil {
		return fmt.Errorf("failed to list templates: %w", err)
	}

	if globalJSON {
		return emitRead(cmd, "templates", templates, int64(len(templates)), 0, len(templates))
	}

	if len(templates) == 0 {
		fmt.Printf("%s No prompt templates found.\n", terminal.InfoSymbol())
		return nil
	}

	tbl := terminal.NewTableWithMaxWidth(globalWidth, "ID", "NAME", "OUTPUT", "SOURCE", "DESCRIPTION")
	for _, t := range templates {
		tbl.AddRow(terminal.Cyan(t.ID), t.Name, t.OutputSchema, terminal.Gray(t.Source), t.Description)
	}
	tbl.Print()
	fmt.Printf("\n%s Total: %d template(s)\n", terminal.InfoSymbol(), len(templates))
	return nil
}

func printAgentResult(result *agent.Result) {
	if result.DryRun {
		fmt.Print(result.RawOutput)
		return
	}

	if result.OutputSchema == "" {
		// Inline run — output is already printed
		return
	}

	switch result.OutputSchema {
	case "findings":
		fmt.Printf("\n%s Agent: %s | Template: %s\n",
			terminal.InfoSymbol(),
			terminal.Cyan(result.AgentName),
			terminal.Cyan(result.TemplateID))
		fmt.Printf("%s Findings: %d parsed",
			terminal.InfoSymbol(),
			len(result.Findings))
		if result.SavedCount > 0 || result.SkippedCount > 0 {
			fmt.Printf(", %s saved, %s skipped",
				terminal.BoldGreen(fmt.Sprintf("%d", result.SavedCount)),
				terminal.Gray(fmt.Sprintf("%d", result.SkippedCount)))
		}
		fmt.Println()

		if len(result.Findings) > 0 {
			tbl := terminal.NewTableWithMaxWidth(globalWidth, "SEVERITY", "TITLE", "FILE", "CWE")
			for _, f := range result.Findings {
				tbl.AddRow(
					clicommon.ColorSeverity(f.Severity),
					f.Title,
					f.File,
					f.CWE,
				)
			}
			tbl.Print()
		}

	case "http_records":
		fmt.Printf("\n%s Agent: %s | Template: %s\n",
			terminal.InfoSymbol(),
			terminal.Cyan(result.AgentName),
			terminal.Cyan(result.TemplateID))
		fmt.Printf("%s HTTP Records: %d parsed, %s saved\n",
			terminal.InfoSymbol(),
			len(result.HTTPRecords),
			terminal.BoldGreen(fmt.Sprintf("%d", result.SavedCount)))
	}
}
