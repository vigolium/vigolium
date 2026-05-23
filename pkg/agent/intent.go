package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"github.com/vigolium/vigolium/pkg/agent/authsession"
	agentinput "github.com/vigolium/vigolium/pkg/agent/input"
	"github.com/vigolium/vigolium/pkg/agent/parsing"
	"go.uber.org/zap"
)

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
      "audit": "lite",
      "piolium": "",
      "diff": "",
      "files": [],
      "browser": false,
      "credentials": "",
      "credential_sets": [],
      "auth_required": false,
      "requires_browser": false,
      "browser_start_url": "",
      "focus_routes": [],
      "max_commands": 0,
      "timeout": "",
      "intensity": ""
    }
  ]
}

Rules:
- "target" is a URL (http:// or https://). If user says "running on localhost:3005", produce "http://localhost:3005".
- "source_path" is a filesystem path (starts with /, ~/, or ./) OR a git repository URL (github.com/..., gitlab.com/..., bitbucket.org/...).
- If both target and source_path are present for an app, set "discover" to true.
- If only source_path is present (no target URL), set "code_audit" to true.
- "focus" captures vulnerability type hints (e.g. "auth bypass", "injection", "XSS").
- "audit" is "lite", "balanced", or "deep" when the user mentions audit, audit agent, security audit, or background audit. "deep" for deep/thorough/comprehensive audit. "balanced" for standard audit. Default to "lite" if mentioned without level. Leave empty if not mentioned.
- "piolium" is the piolium audit mode when the user explicitly mentions piolium, pi runtime, pi audit, or a piolium-only mode like "longshot". Valid values: "lite", "balanced", "deep", "longshot", "revisit", "confirm", "merge", "diff". Default to "lite" if piolium is mentioned without a level. Leave empty otherwise — empty triggers auto-pick downstream (piolium when pi is installed, audit otherwise). Do NOT set both "audit" and "piolium" in the same app: when the user explicitly asks for piolium, set "piolium" and leave "audit" empty.
- "diff" captures a diff reference: a PR/MR URL (e.g. "github.com/org/repo/pull/123", "gitlab.com/org/repo/-/merge_requests/45"), a git ref range (e.g. "main...feature-branch"), or HEAD~N. If user says "last N commits", produce "HEAD~N". Leave empty if not mentioned.
- "files" is an array of specific file paths when the user mentions focusing on particular files (e.g. "focus on auth.go and middleware.go"). Paths are relative to the source root. Leave empty if not mentioned.
- "browser" is true when the user mentions browser, browser-based testing, headless browser, or UI testing. Default false.
- "credentials" is a compact credential string when the user gives direct credentials (e.g. "admin/admin123"). Leave empty if not mentioned.
- "credential_sets" is an array of structured credential pairs when the user gives multiple roles/accounts. Use fields: "name", "role", "username", "password". Highest-privilege account should be role "primary", additional accounts role "compare".
- "auth_required" is true when the user explicitly asks to authenticate, log in first, or scan protected/authenticated routes.
- "requires_browser" is true when the user explicitly says the browser must be used for login or auth setup.
- "browser_start_url" is a full URL when the user names a specific login/start page; otherwise leave empty.
- "focus_routes" is an array of route paths when the user names flows or paths to prioritize after login (e.g. "/books", "/users", "/profile").
- "max_commands" is a positive integer when the user mentions a command limit (e.g. "limit 200 commands", "max 50 steps"). Default 0 (meaning use system default).
- "timeout" is a Go duration string when the user mentions a time limit (e.g. "2h", "30m", "1h30m"). Convert natural language: "2 hours" → "2h", "30 minutes" → "30m". Leave empty if not mentioned.
- "intensity" is "quick", "balanced", or "deep" when the user mentions scan intensity. Leave empty if not mentioned.
- "instruction" captures any remaining guidance that doesn't fit other fields.
- When multiple source paths are listed, create one app entry per source path.
- Expand ~ to the literal "~" character (do not resolve it).
- If a single target applies to multiple sources, duplicate it for each app.
- If no target or source path can be extracted, return {"apps": []}.`

// repoURLPattern matches GitHub, GitLab, and Bitbucket repository URLs.
var repoURLPattern = regexp.MustCompile(`(?i)(github\.com|gitlab\.com|bitbucket\.org)/[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+`)

// setupKeywords are words that suggest environment setup actions are needed.
var setupKeywords = []string{"docker", "compose", "clone", "set up", "set it up", "build and run", "deploy it", "start the app", "run the app"}

// needsAgentSetup returns true when the prompt contains signals suggesting
// the olium agent is needed to perform side effects (git clone, docker,
// etc.) before intent parameters can be fully resolved.
func needsAgentSetup(prompt string) bool {
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
// When the prompt requires environment setup (git clone, docker), it delegates
// to ParseScanIntentWithSetup for full Bash-powered olium agent setup.
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
	var cfg IntentParseConfig
	for _, o := range opts {
		o(&cfg)
	}

	// Setup path: prompts requiring environment setup (git clone, docker, etc.)
	// are handed to the olium agent with full tool access so it can prep the
	// environment before returning intent.
	if needsAgentSetup(trimmed) && cfg.SessionsDir != "" {
		intent, err := ParseScanIntentWithSetup(ctx, engine, trimmed, cfg.SessionsDir)
		if err != nil {
			zap.L().Warn("olium intent setup failed, falling back to simple LLM",
				zap.Error(err))
			// Fall through to simple LLM extraction
		} else {
			intent.Raw = trimmed
			return intent, nil
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
		return nil, fmt.Errorf("failed to parse intent from LLM response: %w (raw: %s)", err, authsession.TruncateForLog(result.RawOutput, 200))
	}

	intent.Raw = trimmed

	// Expand ~ in source paths
	for i := range intent.Apps {
		intent.Apps[i].SourcePath = agenttypes.ExpandHome(intent.Apps[i].SourcePath)
	}

	return intent, nil
}

// tryStructuredFallback checks if the prompt is already a structured input format
// (URL, curl, etc.) and returns a ScanIntent directly without an LLM call.
func tryStructuredFallback(input string) *ScanIntent {
	inputType := agentinput.DetectInputType(input)
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
	jsonStr, err := parsing.ExtractJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("no JSON found in response: %w", err)
	}

	var intent ScanIntent
	if err := json.Unmarshal([]byte(jsonStr), &intent); err != nil {
		return nil, fmt.Errorf("JSON unmarshal failed: %w", err)
	}

	return &intent, nil
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
      "audit_agent": "",
      "diff": "",
      "files": [],
      "browser": false,
      "max_commands": 0,
      "timeout": ""
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
- "audit_agent": "lite", "balanced", or "deep" if user mentions audit or audit agent; empty otherwise.
- "diff": PR/MR URL, git ref range, or HEAD~N if user mentions reviewing a diff or PR. Empty otherwise.
- "files": array of specific file paths to focus on. Empty if not mentioned.
- "browser": true if user mentions browser-based testing. Default false.
- "max_commands": positive integer if user specifies command limit. Default 0.
- "timeout": Go duration string (e.g. "2h", "30m") if user specifies time limit. Empty otherwise.

## Important
- Do NOT start scanning or run vigolium commands.
- Do NOT modify application source code.
- If cloning or docker fails, still output the INTENT_JSON with whatever you managed to set up.
- If the user provides multiple repos, create one app entry per repo.
`

// ParseScanIntentWithSetup runs the olium agent with full tool access to
// clone repos, start containers, and detect running targets before returning
// a structured scan intent.
func ParseScanIntentWithSetup(ctx context.Context, engine *Engine, prompt string, sessionsDir string) (*ScanIntent, error) {
	if engine.settings == nil {
		return nil, fmt.Errorf("no settings available for intent setup")
	}

	agenticScanUUID := "setup-" + uuid.New().String()[:8]
	cloneDir := filepath.Join(sessionsDir, agenticScanUUID, "repos")
	if err := os.MkdirAll(cloneDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create clone directory %s: %w", cloneDir, err)
	}

	systemPrompt := fmt.Sprintf(setupIntentSystemPrompt, cloneDir)

	oliumCfg := engine.settings.Agent.Olium
	// Setup agent: full builtin tools (git clone, docker), a custom system
	// prompt, and a longer turn budget. Built and run through the AgentRuntime
	// seam so this carries no direct dependency on the concrete olium engine.
	sess, err := engine.rt().NewSessionWithSpec(&oliumCfg, SessionSpec{
		System:       systemPrompt,
		MaxTurns:     30,
		IncludeTools: true,
	})
	if err != nil {
		return nil, fmt.Errorf("olium provider: %w", err)
	}

	zap.L().Info("Running olium agent for environment setup",
		zap.String("agenticScanUUID", agenticScanUUID),
		zap.String("cloneDir", cloneDir))

	out, err := engine.rt().RunOnSession(ctx, &oliumCfg, sess, prompt, nil, nil, false)
	if err != nil {
		return nil, fmt.Errorf("olium setup agent failed: %w", err)
	}

	intent, err := parseSDKIntentOutput(out.Text)
	if err != nil {
		return nil, fmt.Errorf("failed to parse setup output: %w", err)
	}

	if intent.Cleanup == nil {
		intent.Cleanup = &SetupCleanup{}
	}
	intent.Cleanup.CloneDirs = append(intent.Cleanup.CloneDirs, cloneDir)

	return intent, nil
}

// parseSDKIntentOutput extracts ScanIntent JSON from the SDK agent's freeform output.
// It looks for the INTENT_JSON: marker line, falling back to parsing.ExtractJSON() if not found.
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
	jsonStr, err := parsing.ExtractJSON(raw)
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
		intent.Apps[i].SourcePath = agenttypes.ExpandHome(intent.Apps[i].SourcePath)
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
