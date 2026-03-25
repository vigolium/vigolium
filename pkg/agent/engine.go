package agent

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent/codexsdk"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"go.uber.org/zap"
)

// safeWriter wraps an io.Writer with a mutex so concurrent writes don't interleave.
// Used when parallel ACP sessions share the same StreamWriter for real-time display.
type safeWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *safeWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// Engine orchestrates AI agent runs: context gathering, prompt rendering,
// agent execution, output parsing, and result ingestion.
type Engine struct {
	settings     *config.Settings
	repo         *database.Repository
	pool         *ACPPool      // nil when warm sessions disabled
	sdkPool      *SDKPool      // nil when warm sessions disabled
	codexPool    *CodexPool    // nil when warm sessions disabled
	opencodePool *OpenCodePool // nil when warm sessions disabled

	// Caches for context gathering (populated lazily, thread-safe)
	dirTreeCacheMu   sync.RWMutex
	dirTreeCache     map[string]string // sourcePath → tree listing
	skipGuidanceOnce sync.Once
	skipGuidanceText string

	// contextCache caches DB enrichment results within a swarm run.
	// Set via SetContextCache before swarm execution; nil for non-swarm modes.
	contextCache *ContextCache
}

// NewEngine creates a new agent engine.
// If warm sessions are enabled in settings, session pools are created automatically.
func NewEngine(settings *config.Settings, repo *database.Repository) *Engine {
	e := &Engine{
		settings: settings,
		repo:     repo,
	}
	if settings != nil && settings.Agent.WarmSession.IsEnabled() {
		e.pool = NewACPPool(settings.Agent.WarmSession, settings.Agent.Backends)
		e.sdkPool = NewSDKPool(settings.Agent.WarmSession, settings.Agent.Backends)
		e.codexPool = NewCodexPool(settings.Agent.WarmSession, settings.Agent.Backends)
		e.opencodePool = NewOpenCodePool(settings.Agent.WarmSession, settings.Agent.Backends)
	}
	return e
}

// Close shuts down the engine's session pools.
// Safe to call multiple times or on nil pools.
func (e *Engine) Close() {
	if e.pool != nil {
		e.pool.Close()
	}
	if e.sdkPool != nil {
		e.sdkPool.Close()
	}
	if e.codexPool != nil {
		e.codexPool.Close()
	}
	if e.opencodePool != nil {
		e.opencodePool.Close()
	}
}

// mergeGlobalMcpServers merges global MCP servers from AgentConfig into a copy
// of the agent definition. Per-backend servers take precedence on name collision.
func (e *Engine) mergeGlobalMcpServers(agentDef *config.AgentDef) *config.AgentDef {
	// Work on a copy to avoid mutating the config map
	merged := *agentDef
	// Explicitly copy the slice to avoid shared backing array corruption on append
	merged.McpServers = append([]config.McpServerConfig(nil), agentDef.McpServers...)

	// Build set of per-backend server names
	backendNames := make(map[string]struct{}, len(merged.McpServers))
	for _, s := range merged.McpServers {
		backendNames[s.Name] = struct{}{}
	}

	// Append global servers that don't collide
	for _, s := range e.settings.Agent.McpServers {
		if _, exists := backendNames[s.Name]; !exists {
			merged.McpServers = append(merged.McpServers, s)
		}
	}

	return &merged
}

// EnsureWarmSessions activates ACP session pooling if it is not already enabled.
// This is useful for modes like swarm that make multiple agent calls and benefit
// from subprocess reuse even when warm sessions are not explicitly configured.
func (e *Engine) EnsureWarmSessions() {
	if e.pool != nil && e.sdkPool != nil && e.codexPool != nil && e.opencodePool != nil {
		return // already active
	}
	if e.settings == nil {
		return
	}
	cfg := e.settings.Agent.WarmSession
	if !cfg.IsEnabled() {
		enabled := true
		cfg.Enable = &enabled
	}
	if e.pool == nil {
		e.pool = NewACPPool(cfg, e.settings.Agent.Backends)
	}
	if e.sdkPool == nil {
		e.sdkPool = NewSDKPool(cfg, e.settings.Agent.Backends)
	}
	if e.codexPool == nil {
		e.codexPool = NewCodexPool(cfg, e.settings.Agent.Backends)
	}
	if e.opencodePool == nil {
		e.opencodePool = NewOpenCodePool(cfg, e.settings.Agent.Backends)
	}
	zap.L().Debug("warm session pools auto-enabled for multi-call mode")
}

// Run executes a full agent pipeline: resolve prompt → render → execute → parse → ingest.
func (e *Engine) Run(ctx context.Context, opts Options) (*Result, error) {
	// Resolve agent name to default if empty
	if opts.AgentName == "" {
		opts.AgentName = e.settings.Agent.DefaultAgent
	}

	// Resolve agent definition: --agent-acp-cmd override takes precedence
	var agentDef *config.AgentDef
	if opts.AgentACPCmd != "" {
		agentDef = ParseACPCmd(opts.AgentACPCmd)
		if opts.AgentName == "" {
			opts.AgentName = "custom-acp"
		}
	} else {
		var resolveErr error
		agentDef, resolveErr = e.resolveAgent(opts.AgentName)
		if resolveErr != nil {
			return nil, resolveErr
		}
	}

	zap.L().Debug("resolved agent definition",
		zap.String("agent", opts.AgentName),
		zap.String("command", agentDef.Command),
		zap.Strings("args", agentDef.Args),
		zap.String("protocol", agentDef.EffectiveProtocol()))

	// Build the prompt
	prompt, outputSchema, templateID, err := e.buildPrompt(ctx, opts)
	if err != nil {
		return nil, err
	}

	zap.L().Debug("prompt built",
		zap.String("templateID", templateID),
		zap.String("outputSchema", outputSchema),
		zap.Int("promptLength", len(prompt)))

	// Dry run: just return the rendered prompt
	if opts.DryRun {
		return &Result{
			AgentName:    opts.AgentName,
			TemplateID:   templateID,
			RawOutput:    prompt,
			OutputSchema: outputSchema,
			DryRun:       true,
		}, nil
	}

	// Show rendered prompt on stderr when --show-prompt is active
	if opts.ShowPrompt {
		fmt.Fprintf(os.Stderr, "\n── rendered prompt (%s) ──\n\n%s\n\n── end prompt ──\n\n", templateID, prompt)
	}

	if zap.L().Core().Enabled(zap.DebugLevel) {
		fmt.Fprintf(os.Stderr, "\n── prompt sent to agent (%s) ──\n\n%s\n\n── end prompt ──\n\n", templateID, prompt)
	}

	// Merge global MCP servers into agentDef when mcp_enabled is true
	if e.settings != nil && e.settings.Agent.IsMcpEnabled() && len(e.settings.Agent.McpServers) > 0 {
		agentDef = e.mergeGlobalMcpServers(agentDef)
	}

	// Execute the agent using the configured protocol, with optional retry.
	retryCfg := DefaultRetryConfig()
	if opts.Retry != nil {
		retryCfg = *opts.Retry
	}

	type execResult struct {
		stdout, stderr, sessionID string
	}
	er, err := retryAgentCall(ctx, retryCfg, func(ctx context.Context, attempt int) (execResult, error) {
		var stdout, stderr, sessionID string
		var runErr error

		runPrompt := prompt
		if attempt > 0 {
			// On retry, nudge the agent to respond
			runPrompt = "Please provide your full response.\n\n" + prompt
		}

	switch agentDef.EffectiveProtocol() {
	case "acp":
		var acpOpts []acpClientOption
		if opts.SourcePath != "" {
			acpOpts = append(acpOpts, withAllowedPaths(opts.SourcePath))
		}
		if opts.StreamWriter != nil {
			acpOpts = append(acpOpts, withStreamWriter(opts.StreamWriter))
		}
		if opts.SessionWeight > 0 {
			acpOpts = append(acpOpts, withSessionWeight(opts.SessionWeight))
		}
		if opts.SessionKey != "" {
			acpOpts = append(acpOpts, withSessionKey(opts.SessionKey))
		}

		// Resolve working directory once for all ACP paths
		cwd := "."
		if opts.SourcePath != "" {
			cwd = opts.SourcePath
		}

		// Enable terminal when slash commands or custom agents are configured (swarm mode).
		if len(opts.SlashCommands) > 0 || len(opts.CustomAgents) > 0 {
			maxCmds := opts.MaxCommands
			if maxCmds <= 0 {
				maxCmds = 50
			}
			acpOpts = append(acpOpts, withTerminal(cwd, maxCmds, opts.SlashCommands...))
		}

		var ar acpResult
		if opts.Autopilot {
			// Autopilot mode: use terminal-enabled ACP runner
			ar, runErr = RunAgenticAutopilot(ctx, *agentDef, runPrompt, cwd, opts.MaxCommands, acpOpts...)
		} else if e.pool != nil && opts.AgentACPCmd == "" {
			// Warm session pooling — skip for ad-hoc ACP commands (no stable name to key on)
			ar, runErr = e.pool.Prompt(ctx, opts.AgentName, runPrompt, cwd, acpOpts...)
		} else {
			ar, runErr = RunAgenticACP(ctx, *agentDef, runPrompt, acpOpts...)
		}
		stdout, stderr, sessionID = ar.Stdout, ar.Stderr, ar.SessionID
	case "sdk":
		// SDK protocol: full Claude Code CLI tools via JSON-lines protocol.
		// Provides Read, Grep, Glob, Bash, Edit — unlike ACP's ReadTextFile-only.
		cwd := "."
		if opts.SourcePath != "" {
			cwd = opts.SourcePath
		}
		sdkCfg := sdkRunConfig{
			Cwd:          cwd,
			StreamWriter: opts.StreamWriter,
			McpServers:   agentDef.McpServers,
			Model:        agentDef.Model,
			SessionID:    opts.SessionID,
			SessionDir:   opts.SessionDir,
		}
		if e.settings != nil {
			sdkCfg.Guardrails = e.settings.Agent.Guardrails
		}

		// Autopilot: SDK agent runs vigolium commands via unrestricted Bash
		// (no ACP sandboxed terminal). Set MaxTurns high for multi-step execution.
		if opts.Autopilot {
			sdkCfg.MaxTurns = opts.MaxCommands * 3
			if sdkCfg.MaxTurns <= 0 {
				sdkCfg.MaxTurns = 300
			}
			sdkCfg.Effort = "high"

			// Inject vigolium toolkit reference — written to CLAUDE.md/AGENTS.md in
			// session dir to avoid passing multi-KB --append-system-prompt CLI arg.
			sysPrompt, promptSource := LoadSDKAutopilotSystemPrompt()
			if opts.SourcePath != "" {
				sysPrompt += "\n\nApplication source code is available at: " + opts.SourcePath
			}
			sdkCfg.AppendSystemPrompt = sysPrompt
			sdkCfg.SystemPromptSource = promptSource

			// Use session dir for the prompt file when available
			if opts.SessionDir != "" {
				sdkCfg.SystemPromptDir = opts.SessionDir
			}
		}

		// Additional directories for source path access (non-autopilot or fallback)
		if opts.SourcePath != "" {
			sdkCfg.AdditionalDirs = append(sdkCfg.AdditionalDirs, opts.SourcePath)
			if !opts.Autopilot {
				if sdkCfg.AppendSystemPrompt != "" {
					sdkCfg.AppendSystemPrompt += "\n\n"
				}
				sdkCfg.AppendSystemPrompt += "Application source code is available at: " + opts.SourcePath
			}
		}

		// Warn about ACP-only terminal features
		if len(opts.SlashCommands) > 0 || len(opts.CustomAgents) > 0 {
			zap.L().Warn("SDK protocol does not support ACP terminal features; SlashCommands and CustomAgents will be ignored",
				zap.Strings("slashCommands", opts.SlashCommands),
				zap.Strings("customAgents", opts.CustomAgents))
		}

		var ar acpResult
		if e.sdkPool != nil && opts.AgentACPCmd == "" {
			poolKey := opts.AgentName
			if opts.SessionKey != "" {
				poolKey = opts.SessionKey
			}
			ar, runErr = e.sdkPool.Prompt(ctx, opts.AgentName, runPrompt, sdkCfg, poolKey, opts.SessionWeight)
		} else {
			ar, runErr = RunAgenticSDK(ctx, *agentDef, runPrompt, sdkCfg)
		}
		stdout, sessionID = ar.Stdout, ar.SessionID
	case "codex-sdk":
		// Codex SDK protocol: native JSON-RPC v2 over stdio via `codex app-server`.
		cwd := "."
		if opts.SourcePath != "" {
			cwd = opts.SourcePath
		}
		codexCfg := codexRunConfig{
			Cwd:          cwd,
			StreamWriter: opts.StreamWriter,
			Model:        agentDef.Model,
			Sandbox:      codexsdk.SandboxModeDanger_full_access,
		}

		// Source path context in instructions
		if opts.SourcePath != "" {
			codexCfg.DeveloperInstructions = "Application source code is available at: " + opts.SourcePath
		}

		var ar acpResult
		if e.codexPool != nil && opts.AgentACPCmd == "" {
			poolKey := opts.AgentName
			if opts.SessionKey != "" {
				poolKey = opts.SessionKey
			}
			ar, runErr = e.codexPool.Prompt(ctx, opts.AgentName, runPrompt, codexCfg, poolKey, opts.SessionWeight)
		} else {
			ar, runErr = RunCodexSDK(ctx, *agentDef, runPrompt, codexCfg)
		}
		stdout, sessionID = ar.Stdout, ar.SessionID
	case "opencode-sdk":
		// OpenCode SDK protocol: REST API + SSE streaming via local daemon.
		cwd := "."
		if opts.SourcePath != "" {
			cwd = opts.SourcePath
		}
		osCfg := opencodeRunConfig{
			Cwd:          cwd,
			StreamWriter: opts.StreamWriter,
			Model:        agentDef.Model,
		}

		// Source path context in system prompt
		if opts.SourcePath != "" {
			osCfg.SystemPrompt = "Application source code is available at: " + opts.SourcePath
		}

		var ar acpResult
		if e.opencodePool != nil && opts.AgentACPCmd == "" {
			poolKey := opts.AgentName
			if opts.SessionKey != "" {
				poolKey = opts.SessionKey
			}
			ar, runErr = e.opencodePool.Prompt(ctx, opts.AgentName, runPrompt, osCfg, poolKey, opts.SessionWeight)
		} else {
			ar, runErr = RunOpenCodeSDK(ctx, *agentDef, runPrompt, osCfg)
		}
		stdout, sessionID = ar.Stdout, ar.SessionID
	default:
		stdout, stderr, runErr = RunAgent(ctx, *agentDef, runPrompt, opts.StreamWriter)
	}

		if runErr != nil {
			return execResult{stdout, stderr, sessionID}, runErr
		}

		// Detect empty output — treat as retryable error
		if strings.TrimSpace(stdout) == "" {
			zap.L().Warn("agent returned empty output, treating as retryable",
				zap.String("agent", opts.AgentName),
				zap.String("protocol", agentDef.EffectiveProtocol()))
			return execResult{stdout, stderr, sessionID}, errEmptyAgentOutput
		}

		return execResult{stdout, stderr, sessionID}, nil
	})

	stdout, stderr, sessionID := er.stdout, er.stderr, er.sessionID

	// Ensure streamed output ends with a newline so subsequent console lines
	// (e.g. session dir, phase banners) don't start on the same line.
	if opts.StreamWriter != nil && stdout != "" && !strings.HasSuffix(stdout, "\n") {
		_, _ = io.WriteString(opts.StreamWriter, "\n")
	}

	if err != nil {
		return &Result{
			AgentName:      opts.AgentName,
			TemplateID:     templateID,
			SessionID:      sessionID,
			RawOutput:      stdout,
			RenderedPrompt: prompt,
			Stderr:         stderr,
		}, fmt.Errorf("agent execution failed: %w", err)
	}

	// Write output to file if requested
	if opts.OutputPath != "" {
		if writeErr := os.WriteFile(opts.OutputPath, []byte(stdout), 0644); writeErr != nil {
			zap.L().Warn("Failed to write agent output to file",
				zap.String("path", opts.OutputPath),
				zap.Error(writeErr))
		}
	}

	result := &Result{
		AgentName:      opts.AgentName,
		TemplateID:     templateID,
		SessionID:      sessionID,
		RawOutput:      stdout,
		RenderedPrompt: prompt,
		Stderr:         stderr,
		OutputSchema:   outputSchema,
	}

	// Parse and ingest results based on output schema
	switch outputSchema {
	case "findings":
		findings, parseErr := ParseFindings(stdout)
		if parseErr != nil {
			zap.L().Warn("Failed to parse agent findings", zap.Error(parseErr))
			return result, nil
		}
		result.Findings = findings
		if e.repo != nil {
			saved, skipped, ingestErr := e.ingestFindings(ctx, findings, opts)
			if ingestErr != nil {
				zap.L().Warn("Failed to ingest some findings", zap.Error(ingestErr))
			}
			result.SavedCount = saved
			result.SkippedCount = skipped
		}

	case "http_records":
		records, parseErr := ParseHTTPRecords(stdout)
		if parseErr != nil {
			zap.L().Warn("Failed to parse agent HTTP records", zap.Error(parseErr))
			return result, nil
		}
		result.HTTPRecords = records
		if e.repo != nil {
			count, ingestErr := e.ingestHTTPRecords(ctx, records, opts)
			if ingestErr != nil {
				zap.L().Warn("Failed to ingest some HTTP records", zap.Error(ingestErr))
			}
			result.SavedCount = count
		}

	case "source_analysis":
		// Parsing and ingestion are handled by the pipeline runner (runSourceAnalysis)
		// to avoid double-ingestion. Engine only stores raw output for the caller.

	case "swarm_plan":
		// Parsing and ingestion are handled by the swarm runner (runMasterAgent)
		// to avoid double-ingestion. Engine only stores raw output for the caller.

	case "recon_deliverable":
		// Parsed by autopilot pipeline runner.

	case "vuln_queue":
		// Parsed by autopilot pipeline runner.

	case "exploitation_evidence":
		// Parsed by autopilot pipeline runner.
	}

	return result, nil
}

// Preflight validates that the agent backend is resolvable and its binary exists
// in $PATH. Call this before starting a multi-phase pipeline to fail fast instead
// of discovering configuration problems mid-run.
func (e *Engine) Preflight(agentName string) error {
	if agentName == "" {
		agentName = e.settings.Agent.DefaultAgent
	}
	agentDef, err := e.resolveAgent(agentName)
	if err != nil {
		return fmt.Errorf("agent %q: %w", agentName, err)
	}

	// Validate the command binary is findable
	cmd := agentDef.Command
	if cmd == "" {
		cmd = "claude" // default for SDK protocol
	}
	if _, lookErr := exec.LookPath(cmd); lookErr != nil {
		return fmt.Errorf("agent %q command %q not found in PATH: %w", agentName, cmd, lookErr)
	}

	return nil
}

// ResolveAgentProtocol returns the effective protocol ("sdk", "acp", or "pipe") for
// the named agent backend. Returns "pipe" if the agent is not found.
func (e *Engine) ResolveAgentProtocol(agentName string) string {
	if agentName == "" {
		agentName = e.settings.Agent.DefaultAgent
	}
	def, ok := e.settings.Agent.Backends[agentName]
	if !ok {
		return "pipe"
	}
	return def.EffectiveProtocol()
}

// RunWithExtra executes an agent run with additional extra template data injected.
// This is used by swarm mode to pass request context and vuln type to the template.
func (e *Engine) RunWithExtra(ctx context.Context, opts Options, extra map[string]string) (*Result, error) {
	if extra != nil {
		if opts.Extra == nil {
			opts.Extra = make(map[string]string)
		}
		for k, v := range extra {
			opts.Extra[k] = v
		}
	}
	return e.Run(ctx, opts)
}

// postProcessSourceAnalysisWithMerged handles DB ingestion and reprobing for a
// pre-parsed, pre-merged SourceAnalysisResult. It skips parsing and LLM repair
// since the caller already parsed each sub-agent's
// output individually.
func (e *Engine) postProcessSourceAnalysisWithMerged(ctx context.Context, cfg SourceAnalysisConfig,
	merged *SourceAnalysisResult, combinedRaw string, combinedPrompt string) (*SourceAnalysisResult, string, string, error) {

	if merged == nil {
		merged = &SourceAnalysisResult{}
	}

	// Fetch session_hostnames for the target hostname and replace hardcoded auth headers.
	var sessionHeaders map[string]string
	hostname := hostnameFromURL(cfg.TargetURL)
	if e.repo != nil && len(merged.HTTPRecords) > 0 && hostname != "" {
		dbRows, dbErr := e.repo.GetSessionHostnamesByHostname(ctx, cfg.ProjectUUID, hostname)
		if dbErr == nil && len(dbRows) > 0 {
			sessionHeaders = AuthHeadersFromSessionHostnames(dbRows)
			if len(sessionHeaders) > 0 {
				merged.HTTPRecords = ReplaceAuthHeadersInRecords(merged.HTTPRecords, sessionHeaders)
			}
		}
	}

	// Ingest discovered HTTP records into the database
	if e.repo != nil && len(merged.HTTPRecords) > 0 {
		ingestOpts := Options{
			Source:      "source-analysis",
			ProjectUUID: cfg.ProjectUUID,
			ScanUUID:    cfg.ScanUUID,
		}
		count, ingestErr := e.ingestHTTPRecords(ctx, merged.HTTPRecords, ingestOpts)
		if ingestErr != nil {
			zap.L().Warn("Failed to ingest source-analysis HTTP records", zap.Error(ingestErr))
		} else {
			printPhaseLine("source-analysis", fmt.Sprintf("ingested HTTP records  count=%d", count))
		}
	}

	// Probe records that were saved without responses to populate status codes and bodies.
	if e.repo != nil && hostname != "" {
		ReprobeUnprobedRecords(ctx, e.repo, cfg.ProjectUUID, hostname, sessionHeaders, "source-analysis")
	}

	return merged, combinedRaw, combinedPrompt, nil
}

// RunSourceAnalysisParallel executes consolidated source analysis in 4 LLM calls
// across 2 waves:
//
//	Wave 1 (single call):
//	  Call 1: swarm-source-explore   (reads source → notes on routes + auth + sinks)
//	Wave 2 (parallel, consumes Wave 1 output):
//	  Call 2a: swarm-source-format-routes     (route notes → JSONL http_records)
//	  Call 2b: swarm-source-format-session    (auth notes → session_config JSON)
//	  Call 3:  swarm-source-extensions         (combined notes → JS scanner extensions)
//
// The single explore call reads the codebase once and produces two labeled sections
// (routes + auth/session) that are split for the format calls. When SDK pool is
// available, format-routes reuses the explore session (multi-turn) for full context.
func (e *Engine) RunSourceAnalysisParallel(ctx context.Context, cfg SourceAnalysisConfig) (saResult *SourceAnalysisResult, rawOutput string, renderedPrompt string, err error) {
	if cfg.SourcePath == "" {
		return nil, "", "", nil
	}

	exploreTemplate := "swarm-source-explore"
	formatRoutesTemplate := "swarm-source-format-routes"
	formatSessionTemplate := "swarm-source-format-session"
	extensionsTemplate := "swarm-source-extensions"

	merged := &SourceAnalysisResult{}
	var allRawOutputs []string
	var allPrompts []string
	var errs []error

	// --- Wave 1: Explore (reads source code once, produces notes for routes + auth) ---
	var exploreOutput string
	var routesExploreOutput, sessionExploreOutput string

	{
		printPhaseLine("source-analysis", "running source exploration (routes + auth)")
		printPhasePromptLine("source-analysis", exploreTemplate, ResolveTemplatePath(exploreTemplate, e.settings.Agent.TemplatesDir))

		exploreSessionID := uuid.New().String()
		opts := Options{
			AgentName:      cfg.AgentName,
			AgentACPCmd:    cfg.AgentACPCmd,
			PromptTemplate: exploreTemplate,
			TargetURL:      cfg.TargetURL,
			SourcePath:     cfg.SourcePath,
			Files:          cfg.Files,
			Instruction:    cfg.Instruction,
			SessionKey:     "sa-explore",
			SessionID:      exploreSessionID,
			DryRun:         cfg.DryRun,
			ShowPrompt:     cfg.ShowPrompt,
			ScanUUID:       cfg.ScanUUID,
			ProjectUUID:    cfg.ProjectUUID,
			Source:         exploreTemplate,
			StreamWriter:   cfg.StreamWriter,
		}
		result, exploreErr := e.Run(ctx, opts)
		WriteSDKSessionEntry(cfg.SessionDir, SDKSessionEntry{
			SessionID: exploreSessionID,
			Phase:     "source-analysis-explore",
			AgentName: cfg.AgentName,
			Timestamp: time.Now(),
		})
		if cfg.SessionDir != "" && result != nil {
			writePromptToSessionDir(cfg.SessionDir, "swarm-source-explore-prompt.md", result.RenderedPrompt)
			writePromptToSessionDir(cfg.SessionDir, "swarm-source-explore-output.md", result.RawOutput)
		}
		if exploreErr != nil {
			var explorePrompt string
			if result != nil {
				explorePrompt = result.RenderedPrompt
			}
			return nil, "", explorePrompt, fmt.Errorf("source exploration failed: %w", exploreErr)
		}

		allRawOutputs = append(allRawOutputs, fmt.Sprintf("--- explore ---\n%s", result.RawOutput))
		allPrompts = append(allPrompts, fmt.Sprintf("--- explore ---\n%s", result.RenderedPrompt))

		exploreOutput = result.RawOutput

		// Split the unified output into route and session sections for Wave 2.
		routesExploreOutput, sessionExploreOutput = splitExploreSections(exploreOutput)
	}

	if cfg.DryRun {
		_, _ = fmt.Fprint(os.Stdout, exploreOutput)
		combinedPrompt := strings.Join(allPrompts, "\n\n")
		return nil, exploreOutput, combinedPrompt, nil
	}

	printPhaseLine("source-analysis", "exploration complete, running format + extensions in parallel")

	// Prepare explore output for appending to downstream calls.
	// Truncate to 64KB to avoid context overflow.
	exploreContext := exploreOutput
	const maxExploreBytes = 64 * 1024
	if len(exploreContext) > maxExploreBytes {
		exploreContext = exploreContext[:maxExploreBytes] + "\n\n... (truncated)"
	}

	// --- Wave 2: Format + Extensions in parallel (3 goroutines) ---
	var safeStreamWriter io.Writer
	if cfg.StreamWriter != nil {
		safeStreamWriter = &safeWriter{w: cfg.StreamWriter}
	}

	// Prepare per-topic explore contexts for format calls (truncated to 48KB each).
	const maxSplitExploreBytes = 48 * 1024
	routesExploreContext := routesExploreOutput
	if len(routesExploreContext) > maxSplitExploreBytes {
		routesExploreContext = routesExploreContext[:maxSplitExploreBytes] + "\n\n... (truncated)"
	}
	sessionExploreContext := sessionExploreOutput
	if len(sessionExploreContext) > maxSplitExploreBytes {
		sessionExploreContext = sessionExploreContext[:maxSplitExploreBytes] + "\n\n... (truncated)"
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	// When SDK pool is available, format-routes reuses the explore session (multi-turn)
	// so the format agent retains full codebase context without truncation.
	// Only format-routes reuses the session; format-session uses appended context
	// to avoid SDK pool contention on the same session key.
	canReuseExploreSession := e.sdkPool != nil

	printPhasePromptLine("source-analysis", formatRoutesTemplate, ResolveTemplatePath(formatRoutesTemplate, e.settings.Agent.TemplatesDir))
	printPhasePromptLine("source-analysis", formatSessionTemplate, ResolveTemplatePath(formatSessionTemplate, e.settings.Agent.TemplatesDir))
	printPhasePromptLine("source-analysis", extensionsTemplate, ResolveTemplatePath(extensionsTemplate, e.settings.Agent.TemplatesDir))

	wg.Add(3)

	// Call 2a: Format routes (route notes → JSONL http_records)
	go func() {
		defer wg.Done()

		// Reuse the unified explore session when SDK pool is available.
		// The format agent gets full codebase context from the explore phase
		// via multi-turn, avoiding 48KB truncation of the appended notes.
		formatRoutesSessionKey := "sa-format-routes"
		formatRoutesAppend := "## Route Analysis Notes\n\n" + routesExploreContext
		if canReuseExploreSession && routesExploreOutput != "" {
			formatRoutesSessionKey = "sa-explore" // reuse explore session
			formatRoutesAppend = ""               // context is in-session
		}

		formatRoutesSessionID := uuid.New().String()
		opts := Options{
			AgentName:      cfg.AgentName,
			AgentACPCmd:    cfg.AgentACPCmd,
			PromptTemplate: formatRoutesTemplate,
			TargetURL:      cfg.TargetURL,
			SourcePath:     cfg.SourcePath,
			SessionKey:     formatRoutesSessionKey,
			SessionID:      formatRoutesSessionID,
			DryRun:         cfg.DryRun,
			ShowPrompt:     cfg.ShowPrompt,
			ScanUUID:       cfg.ScanUUID,
			ProjectUUID:    cfg.ProjectUUID,
			Source:         formatRoutesTemplate,
			StreamWriter:   safeStreamWriter,
			Append:         formatRoutesAppend,
		}

		formatResult, formatErr := e.Run(ctx, opts)
		WriteSDKSessionEntry(cfg.SessionDir, SDKSessionEntry{
			SessionID: formatRoutesSessionID,
			Phase:     "source-analysis-format-routes",
			AgentName: cfg.AgentName,
			Timestamp: time.Now(),
		})

		if cfg.SessionDir != "" && formatResult != nil {
			writePromptToSessionDir(cfg.SessionDir, "swarm-source-format-routes-prompt.md", formatResult.RenderedPrompt)
			writePromptToSessionDir(cfg.SessionDir, "swarm-source-format-routes-output.md", formatResult.RawOutput)
		}

		mu.Lock()
		defer mu.Unlock()

		if formatErr != nil {
			zap.L().Warn("Route format phase failed", zap.Error(formatErr))
			errs = append(errs, fmt.Errorf("format-routes: %w", formatErr))
			return
		}

		allRawOutputs = append(allRawOutputs, fmt.Sprintf("--- format-routes ---\n%s", formatResult.RawOutput))
		allPrompts = append(allPrompts, fmt.Sprintf("--- format-routes ---\n%s", formatResult.RenderedPrompt))

		result, parseErr := ParseSourceAnalysisResult(formatResult.RawOutput)
		if parseErr != nil {
			zap.L().Warn("Failed to parse format-routes output", zap.Error(parseErr))
			errs = append(errs, fmt.Errorf("format-routes parse: %w", parseErr))
			return
		}
		if result != nil {
			merged.HTTPRecords = append(merged.HTTPRecords, result.HTTPRecords...)
		}
	}()

	// Call 2b: Format session (auth notes → session_config JSON)
	go func() {
		defer wg.Done()

		// format-session always uses appended context (does not reuse the explore
		// session) to avoid SDK pool contention with format-routes on "sa-explore".
		formatSessionSessionKey := "sa-format-session"
		formatSessionAppend := "## Authentication & Session Analysis Notes\n\n" + sessionExploreContext

		formatSessionSessionID := uuid.New().String()
		opts := Options{
			AgentName:      cfg.AgentName,
			AgentACPCmd:    cfg.AgentACPCmd,
			PromptTemplate: formatSessionTemplate,
			TargetURL:      cfg.TargetURL,
			SourcePath:     cfg.SourcePath,
			SessionKey:     formatSessionSessionKey,
			SessionID:      formatSessionSessionID,
			DryRun:         cfg.DryRun,
			ShowPrompt:     cfg.ShowPrompt,
			ScanUUID:       cfg.ScanUUID,
			ProjectUUID:    cfg.ProjectUUID,
			Source:         formatSessionTemplate,
			StreamWriter:   safeStreamWriter,
			Append:         formatSessionAppend,
		}

		formatResult, formatErr := e.Run(ctx, opts)
		WriteSDKSessionEntry(cfg.SessionDir, SDKSessionEntry{
			SessionID: formatSessionSessionID,
			Phase:     "source-analysis-format-session",
			AgentName: cfg.AgentName,
			Timestamp: time.Now(),
		})

		if cfg.SessionDir != "" && formatResult != nil {
			writePromptToSessionDir(cfg.SessionDir, "swarm-source-format-session-prompt.md", formatResult.RenderedPrompt)
			writePromptToSessionDir(cfg.SessionDir, "swarm-source-format-session-output.md", formatResult.RawOutput)
		}

		mu.Lock()
		defer mu.Unlock()

		if formatErr != nil {
			zap.L().Warn("Session format phase failed", zap.Error(formatErr))
			errs = append(errs, fmt.Errorf("format-session: %w", formatErr))
			return
		}

		allRawOutputs = append(allRawOutputs, fmt.Sprintf("--- format-session ---\n%s", formatResult.RawOutput))
		allPrompts = append(allPrompts, fmt.Sprintf("--- format-session ---\n%s", formatResult.RenderedPrompt))

		result, parseErr := ParseSourceAnalysisResult(formatResult.RawOutput)
		if parseErr != nil {
			zap.L().Warn("Failed to parse format-session output", zap.Error(parseErr))
			errs = append(errs, fmt.Errorf("format-session parse: %w", parseErr))
			return
		}
		if result != nil {
			if result.SessionConfig != nil && len(result.SessionConfig.Sessions) > 0 {
				merged.SessionConfig = result.SessionConfig
			}
		}
	}()

	// Call 3: Extensions (notes → JS scanner extensions, single call)
	go func() {
		defer wg.Done()

		extSessionID := uuid.New().String()
		extOpts := Options{
			AgentName:      cfg.AgentName,
			AgentACPCmd:    cfg.AgentACPCmd,
			PromptTemplate: extensionsTemplate,
			TargetURL:      cfg.TargetURL,
			SessionKey:     "sa-extensions",
			SessionID:      extSessionID,
			DryRun:         cfg.DryRun,
			ShowPrompt:     cfg.ShowPrompt,
			ScanUUID:       cfg.ScanUUID,
			ProjectUUID:    cfg.ProjectUUID,
			Source:         extensionsTemplate,
			StreamWriter:   safeStreamWriter,
			// Always append explore notes — extensions agent doesn't read source code
			Append: "## Source Code Analysis Notes\n\n" + exploreContext,
		}

		extResult, extErr := e.Run(ctx, extOpts)
		WriteSDKSessionEntry(cfg.SessionDir, SDKSessionEntry{
			SessionID: extSessionID,
			Phase:     "source-analysis-extensions",
			AgentName: cfg.AgentName,
			Timestamp: time.Now(),
		})

		if cfg.SessionDir != "" && extResult != nil {
			writePromptToSessionDir(cfg.SessionDir, "swarm-source-extensions-prompt.md", extResult.RenderedPrompt)
			writePromptToSessionDir(cfg.SessionDir, "swarm-source-extensions-output.md", extResult.RawOutput)
		}

		mu.Lock()
		defer mu.Unlock()

		if extErr != nil {
			errs = append(errs, fmt.Errorf("extensions: %w", extErr))
			return
		}

		allRawOutputs = append(allRawOutputs, fmt.Sprintf("--- extensions ---\n%s", extResult.RawOutput))
		allPrompts = append(allPrompts, fmt.Sprintf("--- extensions ---\n%s", extResult.RenderedPrompt))

		result, parseErr := ParseSourceAnalysisResult(extResult.RawOutput)
		if parseErr != nil {
			zap.L().Warn("Failed to parse extensions output", zap.Error(parseErr))
			errs = append(errs, fmt.Errorf("extensions parse: %w", parseErr))
			return
		}
		if result != nil {
			merged.Extensions = append(merged.Extensions, result.Extensions...)
		}
	}()

	wg.Wait()

	combinedRaw := strings.Join(allRawOutputs, "\n\n")
	combinedPrompt := strings.Join(allPrompts, "\n\n")

	// All 3 calls failed — return error with explore output for diagnostics.
	if len(errs) >= 3 {
		zap.L().Warn("All format + extensions calls failed")
		return nil, combinedRaw, combinedPrompt, fmt.Errorf("source analysis format and extensions all failed: %v", errs)
	}
	if len(errs) > 0 {
		for _, e := range errs {
			zap.L().Warn("Source analysis sub-agent failed (partial results available)", zap.Error(e))
		}
	}

	// Post-process merged results: session header replacement, DB ingestion, reprobing.
	// Build a synthetic raw output that postProcessSourceAnalysis can parse if needed.
	// Since we already parsed format output above, pass the merged result directly
	// by injecting it into the post-processing flow.
	merged.SessionExploreNotes = sessionExploreNotesOrFallback(sessionExploreContext, exploreContext)
	return e.postProcessSourceAnalysisWithMerged(ctx, cfg, merged, combinedRaw, combinedPrompt)
}

// sessionExploreNotesOrFallback returns the session explore context if available,
// otherwise falls back to the combined explore context.
// splitExploreSections splits unified explore output into route and session sections.
// It looks for "## SECTION 1: Application Routes" and "## SECTION 2: Authentication & Session Management"
// headings. If headings are not found, both sections receive the full output as fallback.
func splitExploreSections(output string) (routes, session string) {
	const routesMarker = "## SECTION 1: Application Routes"
	const sessionMarker = "## SECTION 2: Authentication & Session Management"

	routesIdx := strings.Index(output, routesMarker)
	sessionIdx := strings.Index(output, sessionMarker)

	switch {
	case routesIdx >= 0 && sessionIdx > routesIdx:
		routes = strings.TrimSpace(output[routesIdx+len(routesMarker) : sessionIdx])
		session = strings.TrimSpace(output[sessionIdx+len(sessionMarker):])
	case routesIdx >= 0:
		routes = strings.TrimSpace(output[routesIdx+len(routesMarker):])
		session = output // fallback
	case sessionIdx >= 0:
		routes = output // fallback
		session = strings.TrimSpace(output[sessionIdx+len(sessionMarker):])
	default:
		// No section markers found — give full output to both formatters.
		routes = output
		session = output
	}
	return
}

func sessionExploreNotesOrFallback(sessionContext, combinedContext string) string {
	if sessionContext != "" {
		return sessionContext
	}
	return combinedContext
}

// resolveAgent looks up an agent definition by name from settings.
func (e *Engine) resolveAgent(name string) (*config.AgentDef, error) {
	def, ok := e.settings.Agent.Backends[name]
	if !ok {
		return nil, fmt.Errorf("agent %q not found in configuration", name)
	}
	if !def.IsEnabled() {
		return nil, fmt.Errorf("agent %q is disabled", name)
	}
	return &def, nil
}

// enrichContext populates context fields in the template data from database
// and module registry. Only fields declared in the template's variables list are queried.
func (e *Engine) enrichContext(ctx context.Context, data *TemplateData, templateVars []string) {
	var limits config.ContextLimits
	if e.settings != nil {
		limits = e.settings.Agent.ContextLimits
	}
	enrichContextFromDB(ctx, data, e.repo, data.Hostname, templateVars, limits, e.contextCache)
	enrichContextModules(data, templateVars)
	enrichContextCommands(data, templateVars)
}

// SetContextCache sets a context cache for DB enrichment results.
// Used by swarm runs to avoid redundant queries across phases.
func (e *Engine) SetContextCache(cache *ContextCache) {
	e.contextCache = cache
}

// InvalidateContextCache clears the context cache. Call after phases
// that modify scan data (native scan, rescan).
func (e *Engine) InvalidateContextCache() {
	if e.contextCache != nil {
		e.contextCache.Invalidate()
	}
}

// buildPrompt resolves the prompt source and renders it.
// Returns the rendered prompt, output schema, template ID, and any error.
func (e *Engine) buildPrompt(ctx context.Context, opts Options) (prompt string, outputSchema string, templateID string, err error) {
	// Priority: stdin > inline > file > template
	if opts.Stdin {
		data, readErr := io.ReadAll(os.Stdin)
		if readErr != nil {
			return "", "", "", fmt.Errorf("failed to read prompt from stdin: %w", readErr)
		}
		prompt = string(data)
		return prompt, "", "", nil
	}

	if opts.PromptInline != "" {
		return opts.PromptInline, "", "", nil
	}

	if opts.PromptFile != "" {
		tmpl, loadErr := LoadTemplateFromFile(opts.PromptFile)
		if loadErr != nil {
			return "", "", "", fmt.Errorf("failed to load prompt file: %w", loadErr)
		}
		templateData, gatherErr := e.gatherContext(ctx, opts, tmpl.Variables)
		if gatherErr != nil {
			return "", "", "", gatherErr
		}
		e.enrichContext(ctx, &templateData, tmpl.Variables)
		rendered, renderErr := RenderTemplate(tmpl, templateData)
		if renderErr != nil {
			return "", "", "", renderErr
		}
		rendered = appendPromptSuffix(rendered, opts)
		return rendered, tmpl.OutputSchema, tmpl.ID, nil
	}

	if opts.PromptTemplate != "" {
		tmpl, loadErr := LoadTemplate(opts.PromptTemplate, e.settings.Agent.TemplatesDir)
		if loadErr != nil {
			return "", "", "", loadErr
		}
		templateData, gatherErr := e.gatherContext(ctx, opts, tmpl.Variables)
		if gatherErr != nil {
			return "", "", "", gatherErr
		}
		e.enrichContext(ctx, &templateData, tmpl.Variables)
		rendered, renderErr := RenderTemplate(tmpl, templateData)
		if renderErr != nil {
			return "", "", "", renderErr
		}
		rendered = appendPromptSuffix(rendered, opts)
		return rendered, tmpl.OutputSchema, tmpl.ID, nil
	}

	return "", "", "", fmt.Errorf("no prompt source specified (use --prompt-template, --prompt-file, --prompt, or --stdin)")
}

// appendPromptSuffix appends optional Append text and custom instructions to a rendered prompt.
func appendPromptSuffix(rendered string, opts Options) string {
	if opts.Append != "" {
		rendered += "\n\n" + opts.Append
	}
	if opts.Instruction != "" {
		rendered += "\n\n## Custom Instructions\n\n" + opts.Instruction
	}
	return rendered
}

// gatherContext reads source files and prepares template data.
// templateVars controls what gets populated: if "SourceCode" is declared,
// source files are read into the prompt; if only "SourcePath"/"DirectoryTree"
// are declared, just a directory listing is generated (letting the agent
// explore the codebase itself via tool use).
func (e *Engine) gatherContext(ctx context.Context, opts Options, templateVars []string) (TemplateData, error) {
	data := TemplateData{
		SourcePath: opts.SourcePath,
		Extra:      make(map[string]string),
	}

	// Set target context from options (always, regardless of SourcePath)
	if opts.TargetURL != "" {
		data.TargetURL = opts.TargetURL
	}
	if opts.Hostname != "" {
		data.Hostname = opts.Hostname
	} else if opts.TargetURL != "" {
		data.Hostname = hostnameFromURL(opts.TargetURL)
	}

	// Inject extra template data from options
	if opts.Extra != nil {
		for k, v := range opts.Extra {
			data.Extra[k] = v
		}
	}

	if opts.SourcePath == "" {
		return data, nil
	}

	// Check if the template wants embedded source code or just the path
	wantsSourceCode := hasVar(templateVars, "SourceCode")
	wantsDirectoryTree := hasVar(templateVars, "DirectoryTree")

	// Collect file list for language detection and (optionally) source code
	files := opts.Files
	if len(files) == 0 {
		collected, err := collectSourceFiles(ctx, opts.SourcePath)
		if err != nil {
			zap.L().Warn("Failed to collect source files", zap.Error(err))
		}
		files = collected
	}

	data.Language = detectLanguage(files)

	// Generate skip guidance if requested (tells the agent what to avoid, no tree dump).
	// Cached since it returns a static string.
	if hasVar(templateVars, "SkipGuidance") {
		e.skipGuidanceOnce.Do(func() {
			e.skipGuidanceText = generateSkipGuidance()
		})
		data.SkipGuidance = e.skipGuidanceText
	}

	// Generate directory tree listing if requested and SkipGuidance is not used
	// (SkipGuidance replaces the tree — the agent explores on its own).
	// Cached per sourcePath since the tree doesn't change within a run.
	if wantsDirectoryTree && !hasVar(templateVars, "SkipGuidance") {
		tree := e.cachedDirectoryTree(opts.SourcePath)
		if tree != "" {
			data.DirectoryTree = tree
		}
	}

	// Build a source hint summarizing the pre-filtered codebase
	if hasVar(templateVars, "SourceHint") && (data.DirectoryTree != "" || data.SkipGuidance != "" || len(files) > 0) {
		lang := data.Language
		if lang == "" {
			lang = "unknown"
		}
		data.SourceHint = fmt.Sprintf(
			"This directory tree has been pre-filtered to remove build artifacts, "+
				"dependencies, media assets, generated code, and lock files. "+
				"%d source files detected (%s). "+
				"Focus on route definitions, request handlers, authentication logic, "+
				"and input validation code.",
			len(files), lang)
	}

	// Only embed full source code if the template declares SourceCode variable
	if wantsSourceCode {
		data.SourceCode = e.collectSourceCode(opts.SourcePath, files)
	}

	return data, nil
}

// hasVar checks whether a variable name exists in the template variables list.
func hasVar(vars []string, name string) bool {
	for _, v := range vars {
		if v == name {
			return true
		}
	}
	return false
}

// collectSourceCode reads source files and returns concatenated content with file headers.
func (e *Engine) collectSourceCode(sourcePath string, files []string) string {
	var sourceCode strings.Builder

	const maxSourceBytes = 128 * 1024 // 128KB limit for source code context

	var skipped int
	for _, f := range files {
		path := f
		if !filepath.IsAbs(f) {
			path = filepath.Join(sourcePath, f)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			zap.L().Debug("Skipping unreadable file", zap.String("path", path), zap.Error(err))
			continue
		}
		if sourceCode.Len()+len(content) > maxSourceBytes {
			skipped++
			continue
		}
		rel, _ := filepath.Rel(sourcePath, path)
		if rel == "" {
			rel = f
		}
		fmt.Fprintf(&sourceCode, "// --- %s ---\n", rel)
		sourceCode.Write(content)
		sourceCode.WriteString("\n\n")
	}
	if skipped > 0 {
		zap.L().Warn("Source context truncated due to size limit",
			zap.Int("files_included", len(files)-skipped),
			zap.Int("files_skipped", skipped),
			zap.Int("max_bytes", maxSourceBytes))
		fmt.Fprintf(&sourceCode, "\n// --- %d additional files skipped (context limit: %dKB) ---\n", skipped, maxSourceBytes/1024)
	}

	return sourceCode.String()
}

// cachedDirectoryTree returns the directory tree for the given source path,
// caching the result so repeated calls with the same path avoid filesystem walks.
func (e *Engine) cachedDirectoryTree(sourcePath string) string {
	if sourcePath == "" {
		return ""
	}

	e.dirTreeCacheMu.RLock()
	if cached, ok := e.dirTreeCache[sourcePath]; ok {
		e.dirTreeCacheMu.RUnlock()
		return cached
	}
	e.dirTreeCacheMu.RUnlock()

	tree, err := generateDirectoryTree(sourcePath)
	if err != nil {
		zap.L().Warn("Failed to generate directory tree", zap.Error(err))
		return ""
	}

	e.dirTreeCacheMu.Lock()
	if e.dirTreeCache == nil {
		e.dirTreeCache = make(map[string]string)
	}
	e.dirTreeCache[sourcePath] = tree
	e.dirTreeCacheMu.Unlock()
	return tree
}

// generateDirectoryTree produces a compact tree listing of a source directory,
// showing the structure up to 3 levels deep with file counts for deeper directories.
func generateDirectoryTree(root string) (string, error) {
	const maxDepth = 4
	const maxEntries = 500

	var sb strings.Builder
	entries := 0

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entries >= maxEntries {
			return filepath.SkipAll
		}
		// Skip symlinks to avoid cycles
		if d.Type()&os.ModeSymlink != 0 {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		rel, _ := filepath.Rel(root, path)
		if rel == "." {
			return nil
		}

		depth := strings.Count(rel, string(filepath.Separator))

		if d.IsDir() {
			if shouldSkipDir(d.Name()) {
				return filepath.SkipDir
			}
			if depth >= maxDepth {
				return filepath.SkipDir
			}
			indent := strings.Repeat("  ", depth)
			fmt.Fprintf(&sb, "%s%s/\n", indent, d.Name())
			entries++
			return nil
		}

		// Skip non-source files (media, binaries, lock files, minified bundles)
		if shouldSkipFile(d.Name()) {
			return nil
		}

		if depth < maxDepth {
			indent := strings.Repeat("  ", depth)
			fmt.Fprintf(&sb, "%s%s\n", indent, d.Name())
			entries++
		}
		return nil
	})

	if entries >= maxEntries {
		sb.WriteString("... (truncated)\n")
	}

	return sb.String(), err
}

// generateSkipGuidance returns a concise list of file/directory categories
// that the agent should avoid when exploring source code. Instead of dumping
// the full directory tree into the prompt, we let the agent explore on its own
// and just tell it what to skip.
func generateSkipGuidance() string {
	return `Do NOT spend time reading or exploring these categories of files and directories:

1. **Third-party libraries & dependencies** — node_modules/, vendor/, bower_components/, Pods/, .cargo/, .gradle/, .mvn/, .bundle/, .dart_tool/, .pub-cache/, site-packages/
2. **Compiled & generated files** — dist/, build/, out/, .next/, .nuxt/, target/, *.min.js, *.min.css, *.pb.go, *_generated.*, *.d.ts, *.pyc, *.class, *.o, *.so, *.dll
3. **Static media assets** — images (*.png, *.jpg, *.gif, *.svg, *.ico, *.webp), fonts (*.woff, *.woff2, *.ttf, *.eot), audio/video (*.mp4, *.mp3, *.wav)
4. **Database migrations** — migrations/, db/migrate/, alembic/, flyway/, sql/migrations/, schema/
5. **Lock & checksum files** — package-lock.json, yarn.lock, bun.lock, Gemfile.lock, poetry.lock, go.sum, *.lock, *.sum
6. **VCS, IDE & CI/CD config** — .git/, .svn/, .idea/, .vscode/, .github/, .gitlab/, .circleci/, .terraform/
7. **Test fixtures & snapshots** — __snapshots__/, fixtures/ (but DO read test source files — they often contain credentials and auth patterns)`
}

// ingestFindings saves parsed findings to the database.
func (e *Engine) ingestFindings(ctx context.Context, findings []AgentFinding, opts Options) (saved int, skipped int, err error) {
	moduleID := "agent-" + opts.AgentName
	if opts.PromptTemplate != "" {
		moduleID = "agent-" + opts.PromptTemplate
	}

	for _, af := range findings {
		dbFinding := ToDBFinding(af, moduleID, opts.ScanUUID, opts.ProjectUUID)
		if saveErr := e.repo.SaveFindingDirect(ctx, dbFinding); saveErr != nil {
			zap.L().Debug("Failed to save finding",
				zap.String("title", af.Title),
				zap.Error(saveErr))
			skipped++
			continue
		}
		saved++
	}
	return saved, skipped, nil
}

// ingestHTTPRecords saves parsed HTTP records to the database.
// Notes from agent records are preserved as remarks via AppendRemarks.
func (e *Engine) ingestHTTPRecords(ctx context.Context, records []AgentHTTPRecord, opts Options) (int, error) {
	saved := 0
	source := "agent"
	if opts.Source != "" {
		source = opts.Source
	}

	remarksMap := make(map[string][]string)

	for _, rec := range records {
		httpRR, err := ToHTTPRequestResponse(rec)
		if err != nil {
			zap.L().Warn("Skipping invalid HTTP record",
				zap.String("url", rec.URL),
				zap.Error(err))
			continue
		}
		savedUUID, saveErr := e.repo.SaveRecord(ctx, httpRR, source, opts.ProjectUUID)
		if saveErr != nil {
			zap.L().Warn("Failed to save HTTP record",
				zap.String("url", rec.URL),
				zap.Error(saveErr))
			continue
		}
		saved++
		if rec.Notes != "" && savedUUID != "" {
			remarksMap[savedUUID] = []string{rec.Notes}
		}
	}

	// Batch-append notes as remarks
	if len(remarksMap) > 0 {
		if err := e.repo.AppendRemarks(ctx, remarksMap); err != nil {
			zap.L().Warn("Failed to append remarks from agent notes", zap.Error(err))
		}
	}

	return saved, nil
}

// ToHTTPRequestResponse converts an AgentHTTPRecord to an httpmsg.HttpRequestResponse.
func ToHTTPRequestResponse(rec AgentHTTPRecord) (*httpmsg.HttpRequestResponse, error) {
	if rec.URL == "" {
		return nil, fmt.Errorf("URL is required")
	}
	if rec.Method == "" {
		rec.Method = "GET"
	}

	parsedURL, parseErr := url.Parse(rec.URL)
	if parseErr != nil {
		return nil, fmt.Errorf("invalid URL %q: %w", rec.URL, parseErr)
	}

	// Use the relative path in the request line (standard HTTP/1.1 origin-form).
	reqPath := parsedURL.RequestURI()
	if reqPath == "" {
		reqPath = "/"
	}

	rawReq := fmt.Sprintf("%s %s HTTP/1.1\r\n", rec.Method, reqPath)

	// Auto-detect Content-Type from body when not explicitly set.
	if rec.Body != "" {
		hasContentType := false
		for k := range rec.Headers {
			if strings.EqualFold(k, "Content-Type") {
				hasContentType = true
				break
			}
		}
		if !hasContentType {
			if ct := inferContentType(rec.Body); ct != "" {
				if rec.Headers == nil {
					rec.Headers = make(map[string]string)
				}
				rec.Headers["Content-Type"] = ct
			}
		}
	}

	// Ensure a Host header is present (required by HTTP/1.1).
	hasHost := false
	for k, v := range rec.Headers {
		rawReq += fmt.Sprintf("%s: %s\r\n", k, v)
		if strings.EqualFold(k, "Host") {
			hasHost = true
		}
	}
	if !hasHost && parsedURL.Host != "" {
		rawReq += fmt.Sprintf("Host: %s\r\n", parsedURL.Host)
	}

	rawReq += "\r\n"
	if rec.Body != "" {
		rawReq += rec.Body
	}

	return httpmsg.ParseRawRequestWithURL(rawReq, rec.URL)
}

// inferContentType detects the content type from a request body string.
// Returns empty string if the format is unrecognizable.
func inferContentType(body string) string {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return ""
	}

	// JSON: starts with { or [
	if (trimmed[0] == '{' || trimmed[0] == '[') && isJSON(trimmed) {
		return "application/json"
	}

	// XML/HTML: starts with < and has a closing tag
	if trimmed[0] == '<' {
		lower := strings.ToLower(trimmed)
		if strings.Contains(lower, "<?xml") || strings.Contains(lower, "<soap") {
			return "application/xml"
		}
		if strings.Contains(lower, "<html") {
			return "text/html"
		}
		return "application/xml"
	}

	// URL-encoded form: key=value pairs
	if strings.Contains(trimmed, "=") && !strings.Contains(trimmed, "\n") {
		// Heuristic: looks like key=value&key2=value2
		parts := strings.Split(trimmed, "&")
		if len(parts) > 0 {
			allKV := true
			for _, p := range parts {
				if !strings.Contains(p, "=") {
					allKV = false
					break
				}
			}
			if allKV {
				return "application/x-www-form-urlencoded"
			}
		}
	}

	return ""
}

// collectSourceFiles walks a directory and returns paths to common source files.
// The walk is bounded by ctx so that a hung or very large directory tree does not
// block the caller indefinitely. Symlinks are skipped to avoid cycles.
func collectSourceFiles(ctx context.Context, dir string) ([]string, error) {
	sourceExts := map[string]bool{
		".go": true, ".py": true, ".js": true, ".ts": true, ".jsx": true, ".tsx": true,
		".java": true, ".rb": true, ".php": true, ".rs": true, ".c": true, ".cpp": true,
		".cs": true, ".swift": true, ".kt": true, ".scala": true, ".vue": true, ".svelte": true,
	}

	type walkResult struct {
		files []string
		err   error
	}
	ch := make(chan walkResult, 1)

	go func() {
		var files []string
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			// Bail out early if the context has been cancelled.
			select {
			case <-ctx.Done():
				return filepath.SkipAll
			default:
			}
			// Skip symlinks to avoid cycles
			if d.Type()&os.ModeSymlink != 0 {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			// Skip non-source directories (dependencies, build output, etc.)
			if d.IsDir() {
				if shouldSkipDir(d.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			ext := filepath.Ext(d.Name())
			if sourceExts[ext] && !shouldSkipFile(d.Name()) {
				files = append(files, path)
			}
			return nil
		})
		ch <- walkResult{files, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-ch:
		return result.files, result.err
	}
}

// detectLanguage guesses the primary language from file extensions.
func detectLanguage(files []string) string {
	counts := make(map[string]int)
	extLang := map[string]string{
		".go": "Go", ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
		".jsx": "JavaScript", ".tsx": "TypeScript", ".java": "Java", ".rb": "Ruby",
		".php": "PHP", ".rs": "Rust", ".c": "C", ".cpp": "C++",
		".cs": "C#", ".swift": "Swift", ".kt": "Kotlin", ".scala": "Scala",
		".vue": "Vue", ".svelte": "Svelte",
	}
	for _, f := range files {
		ext := filepath.Ext(f)
		if lang, ok := extLang[ext]; ok {
			counts[lang]++
		}
	}
	best := ""
	bestCount := 0
	for lang, count := range counts {
		if count > bestCount {
			best = lang
			bestCount = count
		}
	}
	return best
}

// ParseACPCmd splits a command string into an AgentDef with protocol "acp".
// Example: "traecli acp" → AgentDef{Command: "traecli", Args: ["acp"], Protocol: "acp"}
// Returns nil if cmd is empty or whitespace-only.
func ParseACPCmd(cmd string) *config.AgentDef {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return nil
	}
	var args []string
	if len(parts) > 1 {
		args = parts[1:]
	}
	return &config.AgentDef{
		Command:     parts[0],
		Args:        args,
		Protocol:    "acp",
		Description: "Ad-hoc ACP agent from --agent-acp-cmd",
	}
}
