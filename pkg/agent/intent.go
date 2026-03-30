package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ScanIntent holds structured parameters extracted from a natural language scan prompt.
type ScanIntent struct {
	Apps    []AppIntent   `json:"apps"`
	Raw     string        `json:"raw"`
	Cleanup *SetupCleanup `json:"cleanup,omitempty"` // resources created during SDK-based setup
}

// SetupCleanup tracks resources created during SDK-based intent setup
// that need to be cleaned up when the scan completes.
type SetupCleanup struct {
	DockerProjects []string `json:"docker_projects,omitempty"`
	Containers     []string `json:"containers,omitempty"`
	CloneDirs      []string `json:"-"` // populated locally, not from JSON
}

// Cleanup stops docker containers/projects created during setup.
// Safe to call on nil receiver.
func (sc *SetupCleanup) Cleanup() {
	if sc == nil {
		return
	}
	ctx := context.Background()
	for _, project := range sc.DockerProjects {
		zap.L().Info("Stopping docker compose project from setup", zap.String("project", project))
		cmd := exec.CommandContext(ctx, "docker", "compose", "-p", project, "down", "--timeout", "10")
		if err := cmd.Run(); err != nil {
			zap.L().Warn("Failed to stop docker project", zap.String("project", project), zap.Error(err))
		}
	}
	for _, container := range sc.Containers {
		cmd := exec.CommandContext(ctx, "docker", "rm", "-f", container)
		_ = cmd.Run()
	}
}

// intentParseConfig holds optional configuration for intent parsing.
type intentParseConfig struct {
	sessionsDir string
}

// IntentParseOption is a functional option for ParseScanIntent.
type IntentParseOption func(*intentParseConfig)

// WithSessionsDir sets the sessions directory used for SDK-based setup (clone targets, etc.).
func WithSessionsDir(dir string) IntentParseOption {
	return func(c *intentParseConfig) { c.sessionsDir = dir }
}

// AppIntent holds parameters for a single application to scan.
type AppIntent struct {
	Target      string `json:"target,omitempty"`      // URL if mentioned
	SourcePath  string `json:"source_path,omitempty"` // filesystem path if mentioned
	Focus       string `json:"focus,omitempty"`       // vulnerability focus if mentioned
	Instruction string `json:"instruction,omitempty"` // leftover context
	Discover    bool   `json:"discover,omitempty"`    // implied by target + source combo
	CodeAudit   bool   `json:"code_audit,omitempty"`  // implied by source-only
	AuditAgent  string `json:"audit_agent,omitempty"` // "lite", "full", or "" (background audit agent)
}

// intentExtractionPrompt is the system prompt for the quick LLM call that parses natural language.
const intentExtractionPrompt = `You are a parameter extraction assistant. Extract structured scan parameters from a natural language request.

Return ONLY valid JSON (no markdown, no explanation). Use this exact schema:

{
  "apps": [
    {
      "target": "http://...",
      "source_path": "/path/to/source",
      "focus": "vulnerability focus area",
      "instruction": "any other guidance",
      "discover": true,
      "code_audit": false,
      "audit_agent": "lite"
    }
  ]
}

Rules:
- "target" is a URL (http:// or https://). If user says "running on localhost:3005", produce "http://localhost:3005".
- "source_path" is a filesystem path (starts with /, ~/, or ./).
- If both target and source_path are present for an app, set "discover" to true.
- If only source_path is present (no target URL), set "code_audit" to true.
- "focus" captures vulnerability type hints (e.g. "auth bypass", "injection", "XSS").
- "audit_agent" is "lite" or "full" when the user mentions an audit agent, security audit agent, or background audit. Default to "lite" if the user mentions audit agent without specifying a level. Leave empty if not mentioned.
- "instruction" captures any remaining guidance that doesn't fit other fields.
- When multiple source paths are listed, create one app entry per source path.
- Expand ~ to the literal "~" character (do not resolve it).
- If a single target applies to multiple sources, duplicate it for each app.
- If no target or source path can be extracted, return {"apps": []}.`

// repoURLPattern matches GitHub, GitLab, and Bitbucket repository URLs.
var repoURLPattern = regexp.MustCompile(`(?i)(github\.com|gitlab\.com|bitbucket\.org)/[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+`)

// setupKeywords are words that suggest environment setup actions are needed.
var setupKeywords = []string{"docker", "compose", "clone", "set up", "set it up", "build and run", "deploy it", "start the app", "run the app"}

// needsSDKSetup returns true when the prompt contains signals suggesting
// the SDK agent is needed to perform side effects (git clone, docker, etc.)
// before intent parameters can be fully resolved.
func needsSDKSetup(prompt string) bool {
	lower := strings.ToLower(prompt)
	if repoURLPattern.MatchString(prompt) {
		return true
	}
	for _, kw := range setupKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// ParseScanIntent uses a quick LLM call to extract structured scan parameters
// from a natural language prompt. Falls back to structured input detection if
// the prompt looks like a URL, curl command, etc.
// When the prompt requires environment setup (git clone, docker) and an SDK agent
// is available, it delegates to ParseScanIntentSDK for full Bash-powered setup.
func ParseScanIntent(ctx context.Context, engine *Engine, prompt string, opts ...IntentParseOption) (*ScanIntent, error) {
	trimmed := strings.TrimSpace(prompt)
	if trimmed == "" {
		return nil, fmt.Errorf("empty scan prompt")
	}

	// Fast path: if input matches a structured format, skip the LLM call
	if intent := tryStructuredFallback(trimmed); intent != nil {
		return intent, nil
	}

	// Apply options
	var cfg intentParseConfig
	for _, o := range opts {
		o(&cfg)
	}

	// SDK path: prompts requiring environment setup (git clone, docker, etc.)
	if needsSDKSetup(trimmed) && cfg.sessionsDir != "" {
		protocol := engine.ResolveAgentProtocol("")
		if protocol == "sdk" {
			intent, err := ParseScanIntentSDK(ctx, engine, trimmed, cfg.sessionsDir)
			if err != nil {
				zap.L().Warn("SDK intent setup failed, falling back to simple LLM",
					zap.Error(err))
				// Fall through to simple LLM extraction
			} else {
				intent.Raw = trimmed
				return intent, nil
			}
		}
	}

	// Use the engine to make a quick LLM call for intent extraction
	runOpts := Options{
		PromptInline: fmt.Sprintf("%s\n\nUser request: %s", intentExtractionPrompt, trimmed),
		DryRun:       false,
	}

	result, err := engine.Run(ctx, runOpts)
	if err != nil {
		return nil, fmt.Errorf("intent extraction LLM call failed: %w", err)
	}

	intent, err := parseIntentJSON(result.RawOutput)
	if err != nil {
		return nil, fmt.Errorf("failed to parse intent from LLM response: %w (raw: %s)", err, truncateForLog(result.RawOutput, 200))
	}

	intent.Raw = trimmed

	// Expand ~ in source paths
	for i := range intent.Apps {
		intent.Apps[i].SourcePath = expandHome(intent.Apps[i].SourcePath)
	}

	return intent, nil
}

// tryStructuredFallback checks if the prompt is already a structured input format
// (URL, curl, etc.) and returns a ScanIntent directly without an LLM call.
func tryStructuredFallback(input string) *ScanIntent {
	inputType := DetectInputType(input)
	if inputType == InputTypeUnknown {
		return nil
	}

	// Structured input detected — wrap in a simple ScanIntent
	app := AppIntent{Discover: false}

	switch inputType {
	case InputTypeURL:
		app.Target = strings.TrimSpace(input)
	case InputTypeCurl, InputTypeRaw, InputTypeBase64, InputTypeBurp, InputTypeRecordUUID:
		// These are valid inputs but we can't easily extract target here.
		// Return nil so they go through normal --input handling, not the intent parser.
		return nil
	default:
		return nil
	}

	return &ScanIntent{
		Apps: []AppIntent{app},
		Raw:  input,
	}
}

// parseIntentJSON extracts the JSON object from the LLM response and unmarshals it.
func parseIntentJSON(raw string) (*ScanIntent, error) {
	// Reuse the existing extractJSON from parser.go which handles markdown fences,
	// brace matching, and other LLM output quirks.
	jsonStr, err := extractJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("no JSON found in response: %w", err)
	}

	var intent ScanIntent
	if err := json.Unmarshal([]byte(jsonStr), &intent); err != nil {
		return nil, fmt.Errorf("JSON unmarshal failed: %w", err)
	}

	return &intent, nil
}

// expandHome expands ~ prefix to the user's home directory.
func expandHome(path string) string {
	if path == "" {
		return ""
	}
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return home + path[1:]
	}
	if path == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return home
	}
	return path
}

// ParseAndResolveIntent is a convenience that calls ParseScanIntent followed by
// ResolveIntentApps. It returns an error if no apps could be extracted.
func ParseAndResolveIntent(ctx context.Context, engine *Engine, prompt string, opts ...IntentParseOption) (*ScanIntent, error) {
	intent, err := ParseScanIntent(ctx, engine, prompt, opts...)
	if err != nil {
		return nil, err
	}
	if len(intent.Apps) == 0 {
		return nil, fmt.Errorf("could not extract any scan targets from prompt: %q", prompt)
	}
	return ResolveIntentApps(intent), nil
}

// setupIntentSystemPrompt is the system prompt for the SDK agent that handles
// environment setup (git clone, docker, target detection) before scanning.
const setupIntentSystemPrompt = `You are a setup assistant for Vigolium, a security scanning tool.
Your job is to prepare the environment so that the scanner can run. You must NOT perform any scanning yourself.

## Your Tasks

1. **Clone repositories**: If the user mentions a GitHub/GitLab/Bitbucket URL, clone it into the directory: %s
2. **Set up the application**: If the user asks to set it up, build it, or run it with Docker:
   - Look for docker-compose.yml, Dockerfile, or similar in the cloned repo
   - Run ` + "`docker compose up -d`" + ` (or the appropriate setup command)
   - Wait for services to become healthy (check with ` + "`docker compose ps`" + ` or curl health endpoints)
   - Timeout after 120 seconds if services don't become ready
3. **Detect the target URL**: Find the running application URL by:
   - Checking exposed ports in docker-compose.yml or Dockerfile
   - Running ` + "`docker compose ps`" + ` to see port mappings
   - Trying common ports (3000, 8080, 8443, 1337, 5000, 4000)
   - Curling candidate URLs to verify they respond
4. **Return structured JSON**: When done, output the marker line followed by valid JSON.

## Output Format

When you have finished setup, output EXACTLY this marker on its own line, followed by the JSON:

INTENT_JSON:
{
  "apps": [
    {
      "target": "http://localhost:<detected_port>",
      "source_path": "/absolute/path/to/cloned/repo",
      "focus": "vulnerability focus if user mentioned one",
      "instruction": "any other user guidance",
      "discover": true,
      "code_audit": false,
      "audit_agent": ""
    }
  ],
  "cleanup": {
    "docker_projects": ["project-name-from-compose"],
    "containers": []
  }
}

## JSON Field Rules
- "target": the live URL (http:// or https://) where the app is running. Empty if you could not start it.
- "source_path": absolute path where you cloned the repo.
- "discover": true when both target and source_path are present.
- "code_audit": true when only source_path is present (no running target).
- "cleanup.docker_projects": docker compose project names you started (for cleanup later).
- "cleanup.containers": individual container IDs if you started containers without compose.
- "focus": extract vulnerability focus hints from the user request (e.g. "auth bypass", "injection").
- "instruction": any remaining user guidance that doesn't fit other fields.
- "audit_agent": "lite" or "full" if user mentions audit agent; empty otherwise.

## Important
- Do NOT start scanning or run vigolium commands.
- Do NOT modify application source code.
- If cloning or docker fails, still output the INTENT_JSON with whatever you managed to set up.
- If the user provides multiple repos, create one app entry per repo.
`

// ParseScanIntentSDK uses an SDK agent with full Bash access to clone repos,
// start containers, and detect running targets before returning structured intent.
func ParseScanIntentSDK(ctx context.Context, engine *Engine, prompt string, sessionsDir string) (*ScanIntent, error) {
	runID := "setup-" + uuid.New().String()[:8]
	cloneDir := filepath.Join(sessionsDir, runID, "repos")
	if err := os.MkdirAll(cloneDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create clone directory %s: %w", cloneDir, err)
	}

	sessionDir := filepath.Join(sessionsDir, runID)

	// Resolve the default SDK agent definition
	defaultAgent := engine.settings.Agent.DefaultAgent
	if defaultAgent == "" {
		return nil, fmt.Errorf("no default agent configured for SDK intent setup")
	}
	agentDef, err := engine.resolveAgent(defaultAgent)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve agent %q: %w", defaultAgent, err)
	}

	systemPrompt := fmt.Sprintf(setupIntentSystemPrompt, cloneDir)

	sdkCfg := sdkRunConfig{
		Cwd:                cloneDir,
		MaxTurns:           30,
		Effort:             "medium",
		AppendSystemPrompt: systemPrompt,
		SystemPromptDir:    sessionDir,
		SessionDir:         sessionDir,
		Model:              agentDef.Model,
	}

	zap.L().Info("Running SDK agent for environment setup",
		zap.String("runID", runID),
		zap.String("cloneDir", cloneDir),
		zap.String("agent", defaultAgent))

	result, err := RunAgenticSDK(ctx, *agentDef, prompt, sdkCfg)
	if err != nil {
		return nil, fmt.Errorf("SDK setup agent failed: %w", err)
	}

	// Parse the structured output
	intent, err := parseSDKIntentOutput(result.Stdout)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SDK setup output: %w", err)
	}

	// Track clone directory for potential cleanup
	if intent.Cleanup == nil {
		intent.Cleanup = &SetupCleanup{}
	}
	intent.Cleanup.CloneDirs = append(intent.Cleanup.CloneDirs, cloneDir)

	return intent, nil
}

// parseSDKIntentOutput extracts ScanIntent JSON from the SDK agent's freeform output.
// It looks for the INTENT_JSON: marker line, falling back to extractJSON() if not found.
func parseSDKIntentOutput(output string) (*ScanIntent, error) {
	// Strategy 1: Look for the INTENT_JSON: marker
	const marker = "INTENT_JSON:"
	if idx := strings.Index(output, marker); idx >= 0 {
		jsonPart := strings.TrimSpace(output[idx+len(marker):])
		if jsonPart != "" {
			intent, err := parseIntentJSONWithCleanup(jsonPart)
			if err == nil {
				return intent, nil
			}
			zap.L().Debug("INTENT_JSON marker found but JSON parse failed, trying extractJSON",
				zap.Error(err))
		}
	}

	// Strategy 2: Use the robust extractJSON fallback on the full output
	intent, err := parseIntentJSONWithCleanup(output)
	if err != nil {
		return nil, fmt.Errorf("no valid intent JSON found in SDK output: %w", err)
	}
	return intent, nil
}

// parseIntentJSONWithCleanup extracts JSON from raw text and unmarshals into ScanIntent
// including the cleanup field.
func parseIntentJSONWithCleanup(raw string) (*ScanIntent, error) {
	jsonStr, err := extractJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("no JSON found: %w", err)
	}

	// Parse into a wrapper that includes cleanup
	var wrapper struct {
		Apps    []AppIntent   `json:"apps"`
		Cleanup *SetupCleanup `json:"cleanup,omitempty"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &wrapper); err != nil {
		return nil, fmt.Errorf("JSON unmarshal failed: %w", err)
	}

	intent := &ScanIntent{
		Apps:    wrapper.Apps,
		Cleanup: wrapper.Cleanup,
	}

	// Expand ~ in source paths
	for i := range intent.Apps {
		intent.Apps[i].SourcePath = expandHome(intent.Apps[i].SourcePath)
	}

	return intent, nil
}

// ResolveIntentApps processes a ScanIntent by auto-detecting targets for apps
// that have source paths but no target. Returns the modified intent.
func ResolveIntentApps(intent *ScanIntent) *ScanIntent {
	for i := range intent.Apps {
		app := &intent.Apps[i]

		// Auto-detect target from source code if missing
		if app.Target == "" && app.SourcePath != "" {
			detected := DetectTargetFromSource(app.SourcePath)
			if detected != "" {
				app.Target = detected
				app.Discover = true
				app.CodeAudit = false
				zap.L().Info("Auto-detected target from source",
					zap.String("source", app.SourcePath),
					zap.String("target", detected))
			}
		}

		// Ensure discover is set when both target and source are present
		if app.Target != "" && app.SourcePath != "" {
			app.Discover = true
		}

		// Ensure code_audit when source-only
		if app.Target == "" && app.SourcePath != "" {
			app.CodeAudit = true
		}
	}
	return intent
}
