package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
	"go.uber.org/zap"
)

// Agent command flags
var (
	agentName            string
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
	agentPromptInline    string
	agentStdin           bool
	agentACPCmd          string
	agentTimeout         time.Duration
	agentInstruction     string
	agentInstructionFile string
)

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Run an agentic scan — AI-driven scanning with native scan support",
	Long: `Run an agentic scan using AI agents (Claude, OpenCode, Gemini) for intelligent vulnerability scanning with native scan support.

Use a subcommand to select the agentic scan mode:
  query      Single-shot prompt execution (template-based or inline)
  autopilot  Agentic scan: autonomous AI-driven vulnerability scanning
  pipeline   Agentic scan: multi-phase pipeline with native scan phases
  swarm      Agentic scan: AI-guided targeted vulnerability swarm

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
	Long: `Send a prompt to an AI agent (Claude, OpenCode, Gemini) and get a response.

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
	af.BoolVar(&agentListAgents, "list-agents", false, "List configured agent backends")

	// Query command flags
	rf := agentQueryCmd.Flags()
	rf.StringVar(&agentName, "agent", "", "Agent backend to use (default from config)")
	rf.StringVar(&agentPromptTemplate, "prompt-template", "", "Prompt template ID (e.g. security-code-review)")
	rf.StringVar(&agentPromptFile, "prompt-file", "", "Path to a prompt template file")
	rf.StringVar(&agentSourcePath, "source", "", "Path to source code repository")
	rf.StringSliceVar(&agentFiles, "files", nil, "Specific files to include (relative to --source)")
	rf.StringVar(&agentAppend, "append", "", "Append extra text to the rendered prompt")
	rf.StringVarP(&agentPromptInline, "prompt", "p", "", "Prompt text to send to the agent")
	rf.BoolVar(&agentStdin, "stdin", false, "Read prompt from stdin")
	rf.StringVar(&agentOutput, "output", "", "Write agent output to this file")
	rf.StringVar(&agentSourceLabel, "source-label", "", "Label for records ingested from agent output (e.g. 'agent-review')")
	rf.StringVar(&agentACPCmd, "agent-acp-cmd", "", "Custom ACP agent command (e.g. 'traecli acp'), overrides --agent")
	rf.BoolVar(&agentDryRun, "dry-run", false, "Print the rendered prompt without executing")
	rf.BoolVar(&agentShowPrompt, "show-prompt", false, "Print rendered prompt to stderr before executing")
	rf.DurationVar(&agentTimeout, "agent-timeout", 5*time.Minute, "Maximum time for agent execution (0 = no limit)")
	rf.StringVar(&agentInstruction, "instruction", "", "Custom instruction to guide the agent (appended to prompt)")
	rf.StringVar(&agentInstructionFile, "instruction-file", "", "Path to a file containing custom instructions")
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
	defer engine.Close()

	// Preflight: validate agent backend is available before building prompts
	if err := engine.Preflight(agentName); err != nil {
		return fmt.Errorf("agent preflight failed: %w", err)
	}

	opts := agent.Options{
		AgentName:      agentName,
		AgentACPCmd:    agentACPCmd,
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
		ScanUUID:       globalScanID,
	}
	if settings.Agent.StreamEnabled() {
		opts.StreamWriter = os.Stdout
	}

	ctx := context.Background()
	if agentTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, agentTimeout)
		defer cancel()
	}

	// Create session directory for agent artifacts
	queryRunID := "agt-" + uuid.New().String()
	sessionDir, sdErr := agent.EnsureSessionDir(settings.Agent.EffectiveSessionsDir(), queryRunID)
	if sdErr != nil {
		zap.L().Warn("Failed to create session dir", zap.Error(sdErr))
	}

	result, err := engine.Run(ctx, opts)
	if err != nil {
		if result != nil && result.Stderr != "" {
			fmt.Fprintf(os.Stderr, "%s Agent stderr:\n%s\n", terminal.WarningSymbol(), result.Stderr)
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("agent timed out after %s (use --agent-timeout to adjust or set to 0 to disable)", agentTimeout)
		}
		return fmt.Errorf("agent run failed: %w", err)
	}

	// Save raw output to session directory
	if sessionDir != "" && result.RawOutput != "" {
		_ = os.WriteFile(sessionDir+"/output.md", []byte(result.RawOutput), 0644)
	}

	// For inline runs without a template, print raw output (skip if already streamed)
	if !hasTemplate && opts.StreamWriter == nil {
		fmt.Print(result.RawOutput)
		return nil
	}

	printAgentResult(result)
	return nil
}

func printAgentList(settings *config.Settings) error {
	if globalJSON {
		type agentEntry struct {
			Name        string `json:"name"`
			Command     string `json:"command"`
			Protocol    string `json:"protocol"`
			Description string `json:"description"`
			IsDefault   bool   `json:"is_default"`
		}
		var entries []agentEntry
		for name, def := range settings.Agent.Backends {
			cmdStr := def.Command
			if len(def.Args) > 0 {
				cmdStr += " " + fmt.Sprintf("%v", def.Args)
			}
			entries = append(entries, agentEntry{
				Name:        name,
				Command:     cmdStr,
				Protocol:    def.EffectiveProtocol(),
				Description: def.Description,
				IsDefault:   name == settings.Agent.DefaultAgent,
			})
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(map[string]interface{}{
			"agents": entries,
			"total":  len(entries),
		})
	}

	tbl := terminal.NewTableWithMaxWidth(globalWidth, "NAME", "COMMAND", "PROTOCOL", "DESCRIPTION", "DEFAULT")
	names := make([]string, 0, len(settings.Agent.Backends))
	for name := range settings.Agent.Backends {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		def := settings.Agent.Backends[name]
		isDefault := ""
		if name == settings.Agent.DefaultAgent {
			isDefault = terminal.BoldGreen("*")
		}
		cmdStr := def.Command
		if len(def.Args) > 0 {
			cmdStr += " " + fmt.Sprintf("%v", def.Args)
		}
		tbl.AddRow(terminal.Cyan(name), cmdStr, def.EffectiveProtocol(), def.Description, isDefault)
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

	if result.SessionID != "" {
		fmt.Fprintf(os.Stderr, "%s Session ID: %s\n", terminal.InfoSymbol(), result.SessionID)
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
					colorSeverity(f.Severity),
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
