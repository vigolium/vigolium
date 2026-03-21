package agent

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/vigolium/vigolium/internal/config"
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
	settings *config.Settings
	repo     *database.Repository
	pool     *ACPPool // nil when warm sessions disabled
}

// NewEngine creates a new agent engine.
// If warm sessions are enabled in settings, an ACPPool is created automatically.
func NewEngine(settings *config.Settings, repo *database.Repository) *Engine {
	e := &Engine{
		settings: settings,
		repo:     repo,
	}
	if settings != nil && settings.Agent.WarmSession.IsEnabled() {
		e.pool = NewACPPool(settings.Agent.WarmSession, settings.Agent.Backends)
	}
	return e
}

// Close shuts down the engine's ACP pool if one exists.
// Safe to call multiple times or on a nil pool.
func (e *Engine) Close() {
	if e.pool != nil {
		e.pool.Close()
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
	if e.pool != nil {
		return // already active
	}
	if e.settings == nil {
		return
	}
	// Create a pool with default settings if not explicitly configured
	cfg := e.settings.Agent.WarmSession
	if !cfg.IsEnabled() {
		enabled := true
		cfg.Enable = &enabled
	}
	e.pool = NewACPPool(cfg, e.settings.Agent.Backends)
	zap.L().Debug("warm session pool auto-enabled for multi-call mode")
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

	// Execute the agent using the configured protocol
	var stdout, stderr, sessionID string
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
			ar, err = RunAgenticAutopilot(ctx, *agentDef, prompt, cwd, opts.MaxCommands, acpOpts...)
		} else if e.pool != nil && opts.AgentACPCmd == "" {
			// Warm session pooling — skip for ad-hoc ACP commands (no stable name to key on)
			ar, err = e.pool.Prompt(ctx, opts.AgentName, prompt, cwd, acpOpts...)
		} else {
			ar, err = RunAgenticACP(ctx, *agentDef, prompt, acpOpts...)
		}
		stdout, stderr, sessionID = ar.Stdout, ar.Stderr, ar.SessionID
	default:
		stdout, stderr, err = RunAgent(ctx, *agentDef, prompt, opts.StreamWriter)
	}

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

// RunSourceAnalysis executes the source analysis agent in two phases:
//   - Phase 1 (explore): Agent explores the codebase and produces unstructured notes.
//   - Phase 2 (format): A follow-up call converts those notes into structured output.
//
// This separation improves output format compliance by isolating code understanding
// from JSON/JSONL formatting. The caller is responsible for processing extensions
// and session config via a callback.
func (e *Engine) RunSourceAnalysis(ctx context.Context, cfg SourceAnalysisConfig) (saResult *SourceAnalysisResult, rawOutput string, renderedPrompt string, err error) {
	if cfg.SourcePath == "" {
		return nil, "", "", nil
	}

	templateID := cfg.PromptTemplate
	if templateID == "" {
		templateID = "pipeline-source-analysis"
	}

	exploreTemplateID := templateID + "-explore"
	formatTemplateID := templateID + "-format"

	return e.runSourceAnalysisTwoPhase(ctx, cfg, templateID, exploreTemplateID, formatTemplateID)
}

// runSourceAnalysisTwoPhase runs source analysis in two phases:
//   - Phase 1 (explore): Agent explores the codebase and produces unstructured notes.
//   - Phase 2 (format): A follow-up call converts those notes into structured output.
//
// When warm sessions are enabled, phase 2 reuses the same ACP session (via SessionKey),
// so the agent already has the full codebase context from phase 1. When warm sessions
// are disabled, phase 1's raw output is appended to the phase 2 prompt.
func (e *Engine) runSourceAnalysisTwoPhase(ctx context.Context, cfg SourceAnalysisConfig,
	originalTemplateID, exploreTemplateID, formatTemplateID string) (
	saResult *SourceAnalysisResult, rawOutput string, renderedPrompt string, err error) {

	// --- Phase 1: Explore ---
	printPhaseLine("source-analysis", fmt.Sprintf("starting explore phase  template=%s", exploreTemplateID))
	exploreStart := time.Now()

	exploreOpts := Options{
		AgentName:      cfg.AgentName,
		AgentACPCmd:    cfg.AgentACPCmd,
		PromptTemplate: exploreTemplateID,
		TargetURL:      cfg.TargetURL,
		SourcePath:     cfg.SourcePath,
		Files:          cfg.Files,
		Instruction:    cfg.Instruction,
		SessionKey:     cfg.SessionKey, // same session key for both phases
		DryRun:         cfg.DryRun,
		ShowPrompt:     cfg.ShowPrompt,
		ScanUUID:       cfg.ScanUUID,
		ProjectUUID:    cfg.ProjectUUID,
		Source:         exploreTemplateID,
		StreamWriter:   cfg.StreamWriter,
	}

	exploreResult, exploreRunErr := e.Run(ctx, exploreOpts)

	// Write explore phase artifacts to session dir regardless of success/failure
	if cfg.SessionDir != "" && exploreResult != nil {
		writePromptToSessionDir(cfg.SessionDir, "prompt-"+originalTemplateID+"-explore.md", exploreResult.RenderedPrompt)
		writePromptToSessionDir(cfg.SessionDir, "output-"+originalTemplateID+"-explore.md", exploreResult.RawOutput)
	}

	if exploreRunErr != nil {
		prompt := ""
		if exploreResult != nil {
			prompt = exploreResult.RenderedPrompt
		}
		return nil, "", prompt, fmt.Errorf("source analysis explore phase failed: %w", exploreRunErr)
	}

	renderedPrompt = exploreResult.RenderedPrompt
	zap.L().Info("Source analysis: explore phase completed",
		zap.Duration("elapsed", time.Since(exploreStart)))

	if cfg.DryRun {
		_, _ = fmt.Fprint(os.Stdout, exploreResult.RawOutput)
		return nil, exploreResult.RawOutput, renderedPrompt, nil
	}

	// --- Phase 2: Format ---
	zap.L().Info("Source analysis: starting format phase", zap.String("template", formatTemplateID))
	formatStart := time.Now()

	formatOpts := Options{
		AgentName:      cfg.AgentName,
		AgentACPCmd:    cfg.AgentACPCmd,
		PromptTemplate: formatTemplateID,
		TargetURL:      cfg.TargetURL,
		SourcePath:     cfg.SourcePath,
		SessionKey:     cfg.SessionKey, // SAME key — reuses warm session
		DryRun:         cfg.DryRun,
		ShowPrompt:     cfg.ShowPrompt,
		ScanUUID:       cfg.ScanUUID,
		ProjectUUID:    cfg.ProjectUUID,
		Source:         formatTemplateID,
		StreamWriter:   cfg.StreamWriter,
	}

	// When warm sessions are not available, the format phase starts a cold subprocess
	// that lacks the codebase context from phase 1. Append the explore output so the
	// format agent has the data it needs to produce structured output.
	if e.pool == nil {
		exploreOutput := exploreResult.RawOutput
		// Truncate to 64KB to avoid context overflow in the format phase.
		const maxExploreBytes = 64 * 1024
		if len(exploreOutput) > maxExploreBytes {
			exploreOutput = exploreOutput[:maxExploreBytes] + "\n\n... (truncated)"
		}
		formatOpts.Append = "## Analysis Notes from Exploration Phase\n\n" + exploreOutput
	}

	formatResult, formatRunErr := e.Run(ctx, formatOpts)

	// Write format phase artifacts to session dir regardless of success/failure
	if cfg.SessionDir != "" && formatResult != nil {
		writePromptToSessionDir(cfg.SessionDir, "prompt-"+originalTemplateID+"-format.md", formatResult.RenderedPrompt)
		writePromptToSessionDir(cfg.SessionDir, "output-"+originalTemplateID+"-format.md", formatResult.RawOutput)
	}

	if formatRunErr != nil {
		// Phase 2 failed — fall back to parsing phase 1 output directly.
		zap.L().Warn("Source analysis format phase failed, falling back to explore output",
			zap.Error(formatRunErr))
		rawOutput = exploreResult.RawOutput
	} else {
		rawOutput = formatResult.RawOutput
		printPhaseLine("source-analysis", fmt.Sprintf("format phase completed  elapsed=%s", time.Since(formatStart).Round(time.Millisecond)))
	}

	return e.postProcessSourceAnalysis(ctx, cfg, rawOutput, renderedPrompt)
}

// postProcessSourceAnalysis handles parsing, LLM repair, session header replacement,
// DB ingestion, and reprobing for source analysis output. Shared by both single-phase
// and two-phase execution paths.
func (e *Engine) postProcessSourceAnalysis(ctx context.Context, cfg SourceAnalysisConfig,
	rawOutput string, renderedPrompt string) (*SourceAnalysisResult, string, string, error) {

	saResult, parseErr := ParseSourceAnalysisResult(rawOutput)

	// LLM repair fallback: when parsing fails or yields 0 records but the raw output
	// contains route-like patterns, attempt to repair the garbled JSON via an LLM call.
	// Skip repair when session_config was found without records (auth sub-agent output).
	needsRepair := parseErr != nil || (saResult != nil && len(saResult.HTTPRecords) == 0 && saResult.SessionConfig == nil)
	if needsRepair && strings.Contains(rawOutput, `"method"`) {
		zap.L().Info("Attempting LLM repair for garbled source analysis output")
		repaired := RepairHTTPRecordsWithLLM(ctx, e, rawOutput, repairConfig{
			AgentName:   cfg.AgentName,
			AgentACPCmd: cfg.AgentACPCmd,
			ShowPrompt:  cfg.ShowPrompt,
		})
		if len(repaired) > 0 {
			if saResult == nil {
				saResult = &SourceAnalysisResult{}
			}
			saResult.HTTPRecords = repaired
			parseErr = nil
		}
	}

	// Handle session-config-only raw output (no "method" keyword means HTTP records repair
	// was skipped, but session config keywords may be present in garbled output).
	if saResult == nil && parseErr != nil && !strings.Contains(rawOutput, `"method"`) {
		hasSessionKeywords := strings.Contains(rawOutput, `"session_config"`) ||
			strings.Contains(rawOutput, `"sessions"`) ||
			(strings.Contains(rawOutput, `"login"`) && strings.Contains(rawOutput, `"url"`))
		if hasSessionKeywords {
			saResult = &SourceAnalysisResult{}
			parseErr = nil
		}
	}

	// LLM repair fallback for session config: when session config is missing or
	// incomplete (e.g. extract rules lost during garbled recovery), attempt repair.
	if saResult != nil && sessionConfigNeedsRepair(saResult.SessionConfig, rawOutput) {
		zap.L().Info("Attempting LLM repair for garbled session config")
		repairedCfg := RepairSessionConfigWithLLM(ctx, e, rawOutput, repairConfig{
			AgentName:   cfg.AgentName,
			AgentACPCmd: cfg.AgentACPCmd,
			ShowPrompt:  cfg.ShowPrompt,
		})
		if repairedCfg != nil && len(repairedCfg.Sessions) > 0 {
			saResult.SessionConfig = repairedCfg
		}
	}

	if parseErr != nil {
		return nil, rawOutput, renderedPrompt, fmt.Errorf("failed to parse source analysis result: %w", parseErr)
	}

	// Fetch session_hostnames for the target hostname and replace hardcoded auth headers.
	var sessionHeaders map[string]string
	hostname := hostnameFromURL(cfg.TargetURL) // empty when cfg.TargetURL is ""
	if e.repo != nil && len(saResult.HTTPRecords) > 0 && hostname != "" {
		dbRows, dbErr := e.repo.GetSessionHostnamesByHostname(ctx, cfg.ProjectUUID, hostname)
		if dbErr == nil && len(dbRows) > 0 {
			sessionHeaders = AuthHeadersFromSessionHostnames(dbRows)
			if len(sessionHeaders) > 0 {
				saResult.HTTPRecords = ReplaceAuthHeadersInRecords(saResult.HTTPRecords, sessionHeaders)
			}
		}
	}

	// Ingest discovered HTTP records into the database
	if e.repo != nil && len(saResult.HTTPRecords) > 0 {
		ingestOpts := Options{
			Source:      "source-analysis",
			ProjectUUID: cfg.ProjectUUID,
			ScanUUID:    cfg.ScanUUID,
		}
		count, ingestErr := e.ingestHTTPRecords(ctx, saResult.HTTPRecords, ingestOpts)
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

	return saResult, rawOutput, renderedPrompt, nil
}

// postProcessSourceAnalysisWithMerged handles DB ingestion and reprobing for a
// pre-parsed, pre-merged SourceAnalysisResult. Unlike postProcessSourceAnalysis,
// it skips parsing and LLM repair since the caller already parsed each sub-agent's
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

// RunSourceAnalysisParallel executes consolidated source analysis in up to 4 LLM calls:
// explore-routes + explore-session in parallel, then format + extensions in parallel.
// Falls back to the monolithic RunSourceAnalysis if consolidated templates don't exist.
func (e *Engine) RunSourceAnalysisParallel(ctx context.Context, cfg SourceAnalysisConfig) (saResult *SourceAnalysisResult, rawOutput string, renderedPrompt string, err error) {
	if cfg.SourcePath == "" {
		return nil, "", "", nil
	}

	// Consolidated source analysis: 4 LLM calls in 2 parallel waves.
	//
	//   Wave 1 (parallel):
	//     Call 1a: swarm-source-explore-routes   (reads source → notes on routes + sinks)
	//     Call 1b: swarm-source-explore-session   (reads source → notes on auth + credentials + sessions)
	//   Wave 2 (parallel, consumes combined Wave 1 output):
	//     Call 2: swarm-source-format             (notes → JSONL http_records + session_config JSON)
	//     Call 3: swarm-source-extensions          (notes → JS scanner extensions)
	//
	// Falls back to single-explore flow if split templates don't exist.

	exploreRoutesTemplate := "swarm-source-explore-routes"
	exploreSessionTemplate := "swarm-source-explore-session"
	exploreTemplate := "swarm-source-explore" // fallback if split templates unavailable
	formatTemplate := "swarm-source-format"
	extensionsTemplate := "swarm-source-extensions"

	// Check if the base templates exist (format + extensions are required).
	for _, tmpl := range []string{formatTemplate, extensionsTemplate} {
		if _, err := LoadTemplate(tmpl, e.settings.Agent.TemplatesDir); err != nil {
			zap.L().Debug("Consolidated source analysis templates not found, falling back to monolithic analysis")
			return e.RunSourceAnalysis(ctx, cfg)
		}
	}

	// Determine whether to use split explore (routes + session in parallel) or single explore.
	useSplitExplore := true
	for _, tmpl := range []string{exploreRoutesTemplate, exploreSessionTemplate} {
		if _, err := LoadTemplate(tmpl, e.settings.Agent.TemplatesDir); err != nil {
			useSplitExplore = false
			break
		}
	}
	if !useSplitExplore {
		// Need at least the single explore template as fallback.
		if _, err := LoadTemplate(exploreTemplate, e.settings.Agent.TemplatesDir); err != nil {
			zap.L().Debug("No explore templates found, falling back to monolithic analysis")
			return e.RunSourceAnalysis(ctx, cfg)
		}
	}

	merged := &SourceAnalysisResult{}
	var allRawOutputs []string
	var allPrompts []string
	var errs []error

	// --- Wave 1: Explore (reads source code, produces notes) ---
	var exploreOutput string

	if useSplitExplore {
		// Split explore: routes + session in parallel
		printPhaseLine("source-analysis", "running source exploration (routes + session in parallel)")

		var routesOutput, sessionOutput string
		var routesPrompt, sessionPrompt string
		var routesErr, sessionErr error

		// Wrap StreamWriter for safe concurrent writes.
		var safeStreamWriter io.Writer
		if cfg.StreamWriter != nil {
			safeStreamWriter = &safeWriter{w: cfg.StreamWriter}
		}

		var wgExplore sync.WaitGroup
		wgExplore.Add(2)

		// Call 1a: Explore routes
		go func() {
			defer wgExplore.Done()
			opts := Options{
				AgentName:      cfg.AgentName,
				AgentACPCmd:    cfg.AgentACPCmd,
				PromptTemplate: exploreRoutesTemplate,
				TargetURL:      cfg.TargetURL,
				SourcePath:     cfg.SourcePath,
				Files:          cfg.Files,
				Instruction:    cfg.Instruction,
				SessionKey:     "sa-explore-routes",
				DryRun:         cfg.DryRun,
				ShowPrompt:     cfg.ShowPrompt,
				ScanUUID:       cfg.ScanUUID,
				ProjectUUID:    cfg.ProjectUUID,
				Source:         exploreRoutesTemplate,
				StreamWriter:   safeStreamWriter,
			}
			result, err := e.Run(ctx, opts)
			if cfg.SessionDir != "" && result != nil {
				writePromptToSessionDir(cfg.SessionDir, "prompt-swarm-source-explore-routes.md", result.RenderedPrompt)
				writePromptToSessionDir(cfg.SessionDir, "output-swarm-source-explore-routes.md", result.RawOutput)
			}
			if err != nil {
				routesErr = err
				if result != nil {
					routesPrompt = result.RenderedPrompt
				}
				return
			}
			routesOutput = result.RawOutput
			routesPrompt = result.RenderedPrompt
		}()

		// Call 1b: Explore session/auth
		go func() {
			defer wgExplore.Done()
			opts := Options{
				AgentName:      cfg.AgentName,
				AgentACPCmd:    cfg.AgentACPCmd,
				PromptTemplate: exploreSessionTemplate,
				TargetURL:      cfg.TargetURL,
				SourcePath:     cfg.SourcePath,
				Files:          cfg.Files,
				Instruction:    cfg.Instruction,
				SessionKey:     "sa-explore-session",
				DryRun:         cfg.DryRun,
				ShowPrompt:     cfg.ShowPrompt,
				ScanUUID:       cfg.ScanUUID,
				ProjectUUID:    cfg.ProjectUUID,
				Source:         exploreSessionTemplate,
				StreamWriter:   safeStreamWriter,
			}
			result, err := e.Run(ctx, opts)
			if cfg.SessionDir != "" && result != nil {
				writePromptToSessionDir(cfg.SessionDir, "prompt-swarm-source-explore-session.md", result.RenderedPrompt)
				writePromptToSessionDir(cfg.SessionDir, "output-swarm-source-explore-session.md", result.RawOutput)
			}
			if err != nil {
				sessionErr = err
				if result != nil {
					sessionPrompt = result.RenderedPrompt
				}
				return
			}
			sessionOutput = result.RawOutput
			sessionPrompt = result.RenderedPrompt
		}()

		wgExplore.Wait()

		// Collect outputs and prompts from both explore calls.
		if routesOutput != "" {
			allRawOutputs = append(allRawOutputs, fmt.Sprintf("--- explore-routes ---\n%s", routesOutput))
			allPrompts = append(allPrompts, fmt.Sprintf("--- explore-routes ---\n%s", routesPrompt))
		}
		if sessionOutput != "" {
			allRawOutputs = append(allRawOutputs, fmt.Sprintf("--- explore-session ---\n%s", sessionOutput))
			allPrompts = append(allPrompts, fmt.Sprintf("--- explore-session ---\n%s", sessionPrompt))
		}

		// Both failed — abort.
		if routesErr != nil && sessionErr != nil {
			combinedPrompt := strings.Join(allPrompts, "\n\n")
			return nil, "", combinedPrompt, fmt.Errorf("source exploration failed: routes: %w; session: %v", routesErr, sessionErr)
		}
		if routesErr != nil {
			zap.L().Warn("Route exploration failed, continuing with session results only", zap.Error(routesErr))
		}
		if sessionErr != nil {
			zap.L().Warn("Session exploration failed, continuing with route results only", zap.Error(sessionErr))
		}

		// Combine outputs for downstream calls.
		var parts []string
		if routesOutput != "" {
			parts = append(parts, "## Application Routes\n\n"+routesOutput)
		}
		if sessionOutput != "" {
			parts = append(parts, "## Authentication & Session Management\n\n"+sessionOutput)
		}
		exploreOutput = strings.Join(parts, "\n\n---\n\n")

	} else {
		// Single explore fallback
		printPhaseLine("source-analysis", "running source exploration (routes + auth + sinks)")

		exploreOpts := Options{
			AgentName:      cfg.AgentName,
			AgentACPCmd:    cfg.AgentACPCmd,
			PromptTemplate: exploreTemplate,
			TargetURL:      cfg.TargetURL,
			SourcePath:     cfg.SourcePath,
			Files:          cfg.Files,
			Instruction:    cfg.Instruction,
			SessionKey:     "sa-explore",
			DryRun:         cfg.DryRun,
			ShowPrompt:     cfg.ShowPrompt,
			ScanUUID:       cfg.ScanUUID,
			ProjectUUID:    cfg.ProjectUUID,
			Source:         exploreTemplate,
			StreamWriter:   cfg.StreamWriter,
		}

		exploreResult, exploreErr := e.Run(ctx, exploreOpts)

		if cfg.SessionDir != "" && exploreResult != nil {
			writePromptToSessionDir(cfg.SessionDir, "prompt-swarm-source-explore.md", exploreResult.RenderedPrompt)
			writePromptToSessionDir(cfg.SessionDir, "output-swarm-source-explore.md", exploreResult.RawOutput)
		}

		if exploreErr != nil {
			prompt := ""
			if exploreResult != nil {
				prompt = exploreResult.RenderedPrompt
			}
			return nil, "", prompt, fmt.Errorf("source exploration failed: %w", exploreErr)
		}

		exploreOutput = exploreResult.RawOutput
		allRawOutputs = append(allRawOutputs, fmt.Sprintf("--- explore ---\n%s", exploreOutput))
		allPrompts = append(allPrompts, fmt.Sprintf("--- explore ---\n%s", exploreResult.RenderedPrompt))
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

	// --- Wave 2: Format + Extensions in parallel ---
	// Wrap the shared StreamWriter in a synchronized writer so parallel ACP
	// sessions don't interleave their output on the real-time display.
	var safeStreamWriter io.Writer
	if !useSplitExplore && cfg.StreamWriter != nil {
		safeStreamWriter = &safeWriter{w: cfg.StreamWriter}
	}
	if useSplitExplore && cfg.StreamWriter != nil {
		// Already created in wave 1 for split explore, recreate for wave 2
		safeStreamWriter = &safeWriter{w: cfg.StreamWriter}
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	wg.Add(2)

	// Call 2: Format (notes → JSONL http_records + session_config JSON)
	go func() {
		defer wg.Done()

		formatSessionKey := "sa-explore" // reuse warm session from single explore
		if useSplitExplore {
			formatSessionKey = "sa-format" // no single warm session with split explore
		}

		formatOpts := Options{
			AgentName:      cfg.AgentName,
			AgentACPCmd:    cfg.AgentACPCmd,
			PromptTemplate: formatTemplate,
			TargetURL:      cfg.TargetURL,
			SourcePath:     cfg.SourcePath,
			SessionKey:     formatSessionKey,
			DryRun:         cfg.DryRun,
			ShowPrompt:     cfg.ShowPrompt,
			ScanUUID:       cfg.ScanUUID,
			ProjectUUID:    cfg.ProjectUUID,
			Source:         formatTemplate,
			StreamWriter:   safeStreamWriter,
		}
		// When warm sessions are not available or using split explore,
		// append explore notes so the format agent has the context it needs.
		if e.pool == nil || useSplitExplore {
			formatOpts.Append = "## Analysis Notes from Exploration Phase\n\n" + exploreContext
		}

		formatResult, formatErr := e.Run(ctx, formatOpts)

		if cfg.SessionDir != "" && formatResult != nil {
			writePromptToSessionDir(cfg.SessionDir, "prompt-swarm-source-format.md", formatResult.RenderedPrompt)
			writePromptToSessionDir(cfg.SessionDir, "output-swarm-source-format.md", formatResult.RawOutput)
		}

		mu.Lock()
		defer mu.Unlock()

		if formatErr != nil {
			// Format failed — fall back to parsing explore output directly.
			zap.L().Warn("Source analysis format phase failed, falling back to explore output",
				zap.Error(formatErr))
			errs = append(errs, fmt.Errorf("format: %w", formatErr))
			// Try parsing the raw explore output for any structured data
			if fallbackResult, parseErr := ParseSourceAnalysisResult(exploreOutput); parseErr == nil && fallbackResult != nil {
				merged.HTTPRecords = append(merged.HTTPRecords, fallbackResult.HTTPRecords...)
				if fallbackResult.SessionConfig != nil && len(fallbackResult.SessionConfig.Sessions) > 0 {
					merged.SessionConfig = fallbackResult.SessionConfig
				}
			}
			return
		}

		allRawOutputs = append(allRawOutputs, fmt.Sprintf("--- format ---\n%s", formatResult.RawOutput))
		allPrompts = append(allPrompts, fmt.Sprintf("--- format ---\n%s", formatResult.RenderedPrompt))

		result, parseErr := ParseSourceAnalysisResult(formatResult.RawOutput)
		if parseErr != nil {
			zap.L().Warn("Failed to parse format output", zap.Error(parseErr))
			errs = append(errs, fmt.Errorf("format parse: %w", parseErr))
			return
		}
		if result != nil {
			merged.HTTPRecords = append(merged.HTTPRecords, result.HTTPRecords...)
			if result.SessionConfig != nil && len(result.SessionConfig.Sessions) > 0 {
				merged.SessionConfig = result.SessionConfig
			}
		}
	}()

	// Call 3: Extensions (notes → JS scanner extensions, single call)
	go func() {
		defer wg.Done()

		extOpts := Options{
			AgentName:      cfg.AgentName,
			AgentACPCmd:    cfg.AgentACPCmd,
			PromptTemplate: extensionsTemplate,
			TargetURL:      cfg.TargetURL,
			SessionKey:     "sa-extensions",
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

		if cfg.SessionDir != "" && extResult != nil {
			writePromptToSessionDir(cfg.SessionDir, "prompt-swarm-source-extensions.md", extResult.RenderedPrompt)
			writePromptToSessionDir(cfg.SessionDir, "output-swarm-source-extensions.md", extResult.RawOutput)
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

	// All 3 calls failed (explore succeeded but format + extensions both failed)
	if len(errs) >= 2 {
		// Still try postProcessSourceAnalysis with explore output as fallback
		zap.L().Warn("Format and extensions both failed, falling back to explore output parsing")
		return e.postProcessSourceAnalysis(ctx, cfg, exploreOutput, combinedPrompt)
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
	return e.postProcessSourceAnalysisWithMerged(ctx, cfg, merged, combinedRaw, combinedPrompt)
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
	enrichContextFromDB(ctx, data, e.repo, data.Hostname, templateVars)
	enrichContextModules(data, templateVars)
	enrichContextCommands(data, templateVars)
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

	// Generate skip guidance if requested (tells the agent what to avoid, no tree dump)
	if hasVar(templateVars, "SkipGuidance") {
		data.SkipGuidance = generateSkipGuidance()
	}

	// Generate directory tree listing if requested and SkipGuidance is not used
	// (SkipGuidance replaces the tree — the agent explores on its own)
	if wantsDirectoryTree && !hasVar(templateVars, "SkipGuidance") {
		tree, err := generateDirectoryTree(opts.SourcePath)
		if err != nil {
			zap.L().Warn("Failed to generate directory tree", zap.Error(err))
		} else {
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
