package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

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

Docs: https://docs.vigolium.com`,
	RunE: func(cmd *cobra.Command, args []string) error {
		defer syncLogger()

		settings, err := config.LoadSettings(globalConfig)
		if err != nil {
			zap.L().Warn("Failed to load settings, using defaults", zap.Error(err))
			settings = config.DefaultSettings()
		}

		// Handle --list-agents
		if agentListAgents {
			return printAgentList(settings)
		}

		// Handle --list-templates
		if agentListTemplates {
			return printTemplateList(settings)
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
	rf.StringVar(&agentQueryOliumProvider, "provider", "", "Olium provider override: openai-codex-oauth | openai-api-key | anthropic-api-key | anthropic-oauth | anthropic-cli | anthropic-vertex | google-vertex | openai-compatible (falls back to agent.olium.provider config)")
	rf.StringVar(&agentQueryOliumModel, "model", "", "Olium model id override (falls back to agent.olium.model)")
	rf.StringVar(&agentQueryOliumOAuthCred, "oauth-cred", "", "Olium OAuth/SA credential file (openai-codex-oauth, anthropic-vertex, or google-vertex; falls back to agent.olium.oauth_cred_path or $GOOGLE_APPLICATION_CREDENTIALS)")
	rf.StringVar(&agentQueryOliumOAuthToken, "oauth-token", "", "Olium Anthropic OAuth bearer token (anthropic-oauth provider; falls back to agent.olium.oauth_token or $ANTHROPIC_API_KEY)")
	rf.StringVar(&agentQueryOliumLLMAPIKey, "llm-api-key", "", "Olium API key for key-based providers (falls back to agent.olium.llm_api_key or provider env var)")
	rf.StringVar(&agentQueryOliumGCPProject, "gcp-project", "", "GCP project for Vertex providers (else $GOOGLE_CLOUD_PROJECT, then YAML, then SA file's project_id)")
	rf.StringVar(&agentQueryOliumGCPLocation, "gcp-location", "", "GCP region for Vertex providers (else $GOOGLE_CLOUD_LOCATION, then YAML, then us-central1)")
	rf.StringVar(&agentQueryOliumBaseURL, "base-url", "", "Endpoint URL for openai-compatible provider (e.g. http://localhost:11434/v1); falls back to agent.olium.custom_provider.base_url")
}

func runAgentQuery(cmd *cobra.Command, args []string) error {
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
		return fmt.Errorf("either a prompt (argument, --prompt/-p, --stdin) or a template (--prompt-template, --prompt-file) is required")
	}

	settings, err := config.LoadSettings(globalConfig)
	if err != nil {
		zap.L().Warn("Failed to load settings, using defaults", zap.Error(err))
		settings = config.DefaultSettings()
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

	// Open DB for ingestion (optional)
	var repo *database.Repository
	db, dbErr := getDB()
	if dbErr == nil {
		ctx := context.Background()
		if schemaErr := db.CreateSchema(ctx); schemaErr != nil {
			zap.L().Warn("Failed to create schema", zap.Error(schemaErr))
		}
		repo = database.NewRepository(db)
	}

	instruction, err := resolveInstruction(agentInstruction, agentInstructionFile)
	if err != nil {
		return err
	}

	engine := agent.NewEngine(settings, repo)

	// Preflight: validate agent backend is available before building prompts
	if err := engine.Preflight(agentLabel); err != nil {
		return fmt.Errorf("agent preflight failed: %w", err)
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
		opts.StreamWriter = os.Stdout
	}

	ctx := context.Background()
	if agentMaxDuration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, agentMaxDuration)
		defer cancel()
	}

	// Create session directory for agent artifacts. Created before engine.Run
	// so we can tee the stream into {sessionDir}/runtime.log for `vigolium log`.
	queryAgenticScanUUID := uuid.New().String()
	sessionDir, sdErr := agent.EnsureSessionDir(settings.Agent.EffectiveSessionsDir(), queryAgenticScanUUID)
	if sdErr != nil {
		zap.L().Warn("Failed to create session dir", zap.Error(sdErr))
	}
	if tee, closer := teeToRuntimeLog(opts.StreamWriter, sessionDir); closer != nil {
		opts.StreamWriter = tee
		defer func() { _ = closer.Close() }()
	}

	result, err := engine.Run(ctx, opts)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("agent timed out after %s (use --max-duration to adjust or set to 0 to disable)", agentMaxDuration)
		}
		return fmt.Errorf("agent run failed: %w", err)
	}

	// Save raw output to session directory
	if sessionDir != "" && result.RawOutput != "" {
		if err := os.WriteFile(sessionDir+"/output.md", []byte(result.RawOutput), 0644); err != nil {
			zap.L().Debug("failed to write agent output.md", zap.Error(err))
		}
	}

	// For inline runs without a template, print raw output (skip if already streamed)
	if !hasTemplate && opts.StreamWriter == nil {
		fmt.Print(result.RawOutput)
		if agentUploadResults && sessionDir != "" {
			projectUUID, _ := resolveProjectUUID()
			uploadAgenticScanResults(settings, projectUUID, queryAgenticScanUUID, sessionDir, repo)
		}
		return nil
	}

	printAgentResult(result)

	if agentUploadResults && sessionDir != "" {
		projectUUID, _ := resolveProjectUUID()
		uploadAgenticScanResults(settings, projectUUID, queryAgenticScanUUID, sessionDir, repo)
	}
	return nil
}

// printAgentList prints the olium providers configured for this install.
// With the subprocess backend system removed, the "list" now reflects the
// four olium providers plus the active default from agent.olium.provider.
func printAgentList(settings *config.Settings) error {
	type providerEntry struct {
		Name        string
		Model       string
		Auth        string
		Description string
	}
	defaults := []providerEntry{
		{"openai-codex-oauth", "gpt-5.5", "~/.codex/auth.json", "OpenAI Codex via ChatGPT OAuth (default)"},
		{"openai-api-key", "gpt-5.5", "$OPENAI_API_KEY", "OpenAI chat API via API key"},
		{"anthropic-api-key", "claude-opus-4-7", "$ANTHROPIC_API_KEY", "Anthropic Claude via API key"},
		{"anthropic-oauth", "claude-opus-4-7", "$ANTHROPIC_API_KEY", "Anthropic Claude via OAuth bearer token (claude setup-token)"},
		{"anthropic-cli", "claude-opus-4-7", "claude binary in PATH", "Anthropic Claude via local claude CLI"},
		{"anthropic-vertex", "claude-opus-4-6", "GCP service-account JSON", "Anthropic Claude on Google Vertex AI"},
		{"google-vertex", "gemini-2.5-pro", "GCP service-account JSON", "Google Gemini on Vertex AI"},
	}

	activeProvider := settings.Agent.Olium.Provider
	if activeProvider == "" {
		activeProvider = "openai-codex-oauth"
	}

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
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(map[string]interface{}{
			"providers": entries,
			"total":     len(entries),
			"active":    activeProvider,
		})
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
	return nil
}

func printTemplateList(settings *config.Settings) error {
	templates, err := agent.ListTemplates(settings.Agent.TemplatesDir)
	if err != nil {
		return fmt.Errorf("failed to list templates: %w", err)
	}

	if globalJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(map[string]interface{}{
			"templates": templates,
			"total":     len(templates),
		})
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
	if globalJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		_ = encoder.Encode(result)
		return
	}

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
