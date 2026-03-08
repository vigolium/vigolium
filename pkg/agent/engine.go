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
		e.pool = NewACPPool(settings.Agent.WarmSession, settings.Agent.Agents)
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

// Run executes a full agent pipeline: resolve prompt → render → execute → parse → ingest.
func (e *Engine) Run(ctx context.Context, opts Options) (*Result, error) {
	// Resolve agent name to default if empty
	if opts.AgentName == "" {
		opts.AgentName = e.settings.Agent.DefaultAgent
	}

	// Resolve agent definition
	agentDef, err := e.resolveAgent(opts.AgentName)
	if err != nil {
		return nil, err
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

	zap.L().Debug("prompt sent to agent", zap.String("prompt", prompt))

	// Execute the agent using the configured protocol
	var stdout, stderr string
	switch agentDef.EffectiveProtocol() {
	case "acp":
		var acpOpts []acpClientOption
		if opts.RepoPath != "" {
			acpOpts = append(acpOpts, withAllowedPaths(opts.RepoPath))
		}
		if opts.StreamWriter != nil {
			acpOpts = append(acpOpts, withStreamWriter(opts.StreamWriter))
		}

		if opts.Autopilot {
			// Autopilot mode: use terminal-enabled ACP runner
			cwd := "."
			if opts.RepoPath != "" {
				cwd = opts.RepoPath
			}
			stdout, stderr, err = RunAgentAutopilot(ctx, *agentDef, prompt, cwd, opts.MaxCommands, acpOpts...)
		} else if e.pool != nil {
			// Determine cwd for session matching
			cwd := "."
			if opts.RepoPath != "" {
				cwd = opts.RepoPath
			}
			stdout, stderr, err = e.pool.Prompt(ctx, opts.AgentName, prompt, cwd, acpOpts...)
		} else {
			stdout, stderr, err = RunAgentACP(ctx, *agentDef, prompt, acpOpts...)
		}
	default:
		stdout, stderr, err = RunAgent(ctx, *agentDef, prompt, opts.StreamWriter)
	}
	if err != nil {
		return &Result{
			AgentName:  opts.AgentName,
			TemplateID: templateID,
			RawOutput:  stdout,
			Stderr:     stderr,
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
		AgentName:    opts.AgentName,
		TemplateID:   templateID,
		RawOutput:    stdout,
		Stderr:       stderr,
		OutputSchema: outputSchema,
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
	}

	return result, nil
}

// resolveAgent looks up an agent definition by name from settings.
func (e *Engine) resolveAgent(name string) (*config.AgentDef, error) {
	def, ok := e.settings.Agent.Agents[name]
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
		templateData, gatherErr := e.gatherContext(opts)
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
		templateData, gatherErr := e.gatherContext(opts)
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
func (e *Engine) gatherContext(opts Options) (TemplateData, error) {
	data := TemplateData{
		RepoPath: opts.RepoPath,
		Extra:    make(map[string]string),
	}

	if opts.RepoPath == "" {
		return data, nil
	}

	// Collect source code from specified files or all files in repo
	var sourceCode strings.Builder
	files := opts.Files

	if len(files) == 0 {
		// Walk the repo and collect common source files
		collected, err := collectSourceFiles(opts.RepoPath)
		if err != nil {
			zap.L().Warn("Failed to collect source files", zap.Error(err))
		}
		files = collected
	}

	for _, f := range files {
		path := f
		if !filepath.IsAbs(f) {
			path = filepath.Join(opts.RepoPath, f)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			zap.L().Debug("Skipping unreadable file", zap.String("path", path), zap.Error(err))
			continue
		}
		rel, _ := filepath.Rel(opts.RepoPath, path)
		if rel == "" {
			rel = f
		}
		fmt.Fprintf(&sourceCode, "// --- %s ---\n", rel)
		sourceCode.Write(content)
		sourceCode.WriteString("\n\n")
		data.FilePath = rel // last file becomes the primary file path
	}

	data.SourceCode = sourceCode.String()
	data.Language = detectLanguage(files)

	// Set target context from options
	if opts.TargetURL != "" {
		data.TargetURL = opts.TargetURL
	}
	if opts.Hostname != "" {
		data.Hostname = opts.Hostname
	} else if opts.TargetURL != "" {
		data.Hostname = hostnameFromURL(opts.TargetURL)
	}

	return data, nil
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
			zap.L().Debug("Skipping invalid HTTP record",
				zap.String("url", rec.URL),
				zap.Error(err))
			continue
		}
		if _, saveErr := e.repo.SaveRecord(ctx, httpRR, source, opts.ProjectUUID); saveErr != nil {
			zap.L().Debug("Failed to save HTTP record",
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
