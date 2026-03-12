package agent

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"go.uber.org/zap"
)

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
		fmt.Fprintf(os.Stderr, "\n── rendered prompt (%s) ──\n%s\n── end prompt ──\n\n", templateID, prompt)
	}

	if zap.L().Core().Enabled(zap.DebugLevel) {
		fmt.Fprintf(os.Stderr, "\n── prompt sent to agent (%s) ──\n\n%s\n\n── end prompt ──\n\n", templateID, prompt)
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

		var ar acpResult
		if opts.Autopilot {
			// Autopilot mode: use terminal-enabled ACP runner
			cwd := "."
			if opts.SourcePath != "" {
				cwd = opts.SourcePath
			}
			ar, err = RunAgentAutopilot(ctx, *agentDef, prompt, cwd, opts.MaxCommands, acpOpts...)
		} else if e.pool != nil && opts.AgentACPCmd == "" {
			// Warm session pooling — skip for ad-hoc ACP commands (no stable name to key on)
			cwd := "."
			if opts.SourcePath != "" {
				cwd = opts.SourcePath
			}
			ar, err = e.pool.Prompt(ctx, opts.AgentName, prompt, cwd, acpOpts...)
		} else {
			ar, err = RunAgentACP(ctx, *agentDef, prompt, acpOpts...)
		}
		stdout, stderr, sessionID = ar.Stdout, ar.Stderr, ar.SessionID
	default:
		stdout, stderr, err = RunAgent(ctx, *agentDef, prompt, opts.StreamWriter)
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

// RunSourceAnalysis executes the source analysis agent and returns parsed results
// along with the raw agent output and the rendered prompt that was sent.
// The caller is responsible for processing extensions and session config via a callback.
func (e *Engine) RunSourceAnalysis(ctx context.Context, cfg SourceAnalysisConfig) (saResult *SourceAnalysisResult, rawOutput string, renderedPrompt string, err error) {
	if cfg.SourcePath == "" {
		return nil, "", "", nil
	}

	templateID := cfg.PromptTemplate
	if templateID == "" {
		templateID = "pipeline-source-analysis"
	}

	opts := Options{
		AgentName:      cfg.AgentName,
		AgentACPCmd:    cfg.AgentACPCmd,
		PromptTemplate: templateID,
		TargetURL:      cfg.TargetURL,
		SourcePath:     cfg.SourcePath,
		Files:          cfg.Files,
		DryRun:         cfg.DryRun,
		ShowPrompt:     cfg.ShowPrompt,
		ScanUUID:       cfg.ScanUUID,
		ProjectUUID:    cfg.ProjectUUID,
		Source:         templateID,
		StreamWriter:   cfg.StreamWriter,
	}

	result, runErr := e.Run(ctx, opts)
	if runErr != nil {
		prompt := ""
		if result != nil {
			prompt = result.RenderedPrompt
		}
		return nil, "", prompt, fmt.Errorf("source analysis agent failed: %w", runErr)
	}

	rawOutput = result.RawOutput
	renderedPrompt = result.RenderedPrompt

	if cfg.DryRun {
		fmt.Fprint(os.Stdout, rawOutput)
		return nil, rawOutput, renderedPrompt, nil
	}

	saResult, parseErr := ParseSourceAnalysisResult(rawOutput)
	if parseErr != nil {
		return nil, rawOutput, renderedPrompt, fmt.Errorf("failed to parse source analysis result: %w", parseErr)
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
			zap.L().Info("Ingested source-analysis HTTP records", zap.Int("count", count))
		}
	}

	return saResult, rawOutput, renderedPrompt, nil
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
		templateData, gatherErr := e.gatherContext(opts, tmpl.Variables)
		if gatherErr != nil {
			return "", "", "", gatherErr
		}
		e.enrichContext(ctx, &templateData, tmpl.Variables)
		rendered, renderErr := RenderTemplate(tmpl, templateData)
		if renderErr != nil {
			return "", "", "", renderErr
		}
		if opts.Append != "" {
			rendered += "\n\n" + opts.Append
		}
		return rendered, tmpl.OutputSchema, tmpl.ID, nil
	}

	if opts.PromptTemplate != "" {
		tmpl, loadErr := LoadTemplate(opts.PromptTemplate, e.settings.Agent.TemplatesDir)
		if loadErr != nil {
			return "", "", "", loadErr
		}
		templateData, gatherErr := e.gatherContext(opts, tmpl.Variables)
		if gatherErr != nil {
			return "", "", "", gatherErr
		}
		e.enrichContext(ctx, &templateData, tmpl.Variables)
		rendered, renderErr := RenderTemplate(tmpl, templateData)
		if renderErr != nil {
			return "", "", "", renderErr
		}
		if opts.Append != "" {
			rendered += "\n\n" + opts.Append
		}
		return rendered, tmpl.OutputSchema, tmpl.ID, nil
	}

	return "", "", "", fmt.Errorf("no prompt source specified (use --prompt-template, --prompt-file, --prompt, or --stdin)")
}

// gatherContext reads source files and prepares template data.
// templateVars controls what gets populated: if "SourceCode" is declared,
// source files are read into the prompt; if only "SourcePath"/"DirectoryTree"
// are declared, just a directory listing is generated (letting the agent
// explore the codebase itself via tool use).
func (e *Engine) gatherContext(opts Options, templateVars []string) (TemplateData, error) {
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
		collected, err := collectSourceFiles(opts.SourcePath)
		if err != nil {
			zap.L().Warn("Failed to collect source files", zap.Error(err))
		}
		files = collected
	}

	data.Language = detectLanguage(files)

	// Generate directory tree listing if requested (lightweight context for agent exploration)
	if wantsDirectoryTree {
		tree, err := generateDirectoryTree(opts.SourcePath)
		if err != nil {
			zap.L().Warn("Failed to generate directory tree", zap.Error(err))
		} else {
			data.DirectoryTree = tree
		}
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

	skipDirs := map[string]bool{
		"node_modules": true, ".git": true, "vendor": true, "__pycache__": true,
		".venv": true, "dist": true, "build": true, ".next": true, ".nuxt": true,
		"coverage": true, ".tox": true, ".mypy_cache": true, ".pytest_cache": true,
	}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entries >= maxEntries {
			return filepath.SkipAll
		}

		rel, _ := filepath.Rel(root, path)
		if rel == "." {
			return nil
		}

		depth := strings.Count(rel, string(filepath.Separator))

		if d.IsDir() {
			if skipDirs[d.Name()] {
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
func (e *Engine) ingestHTTPRecords(ctx context.Context, records []AgentHTTPRecord, opts Options) (int, error) {
	saved := 0
	source := "agent"
	if opts.Source != "" {
		source = opts.Source
	}

	for _, rec := range records {
		httpRR, err := ToHTTPRequestResponse(rec)
		if err != nil {
			zap.L().Warn("Skipping invalid HTTP record",
				zap.String("url", rec.URL),
				zap.Error(err))
			continue
		}
		if _, saveErr := e.repo.SaveRecord(ctx, httpRR, source, opts.ProjectUUID); saveErr != nil {
			zap.L().Warn("Failed to save HTTP record",
				zap.String("url", rec.URL),
				zap.Error(saveErr))
			continue
		}
		saved++
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

	rawReq := fmt.Sprintf("%s %s HTTP/1.1\r\n", rec.Method, rec.URL)
	for k, v := range rec.Headers {
		rawReq += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	rawReq += "\r\n"
	if rec.Body != "" {
		rawReq += rec.Body
	}

	return httpmsg.ParseRawRequestWithURL(rawReq, rec.URL)
}

// collectSourceFiles walks a directory and returns paths to common source files.
func collectSourceFiles(dir string) ([]string, error) {
	var files []string
	sourceExts := map[string]bool{
		".go": true, ".py": true, ".js": true, ".ts": true, ".jsx": true, ".tsx": true,
		".java": true, ".rb": true, ".php": true, ".rs": true, ".c": true, ".cpp": true,
		".cs": true, ".swift": true, ".kt": true, ".scala": true, ".vue": true, ".svelte": true,
	}

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		// Skip common non-source directories
		if d.IsDir() {
			name := d.Name()
			if name == "node_modules" || name == ".git" || name == "vendor" || name == "__pycache__" || name == ".venv" {
				return filepath.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(d.Name())
		if sourceExts[ext] {
			files = append(files, path)
		}
		return nil
	})
	return files, err
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
