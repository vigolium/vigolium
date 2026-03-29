package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"
)

// ScanIntent holds structured parameters extracted from a natural language scan prompt.
type ScanIntent struct {
	Apps []AppIntent `json:"apps"`
	Raw  string      `json:"raw"`
}

// AppIntent holds parameters for a single application to scan.
type AppIntent struct {
	Target      string `json:"target,omitempty"`      // URL if mentioned
	SourcePath  string `json:"source_path,omitempty"` // filesystem path if mentioned
	Focus       string `json:"focus,omitempty"`       // vulnerability focus if mentioned
	Instruction string `json:"instruction,omitempty"` // leftover context
	Discover    bool   `json:"discover,omitempty"`    // implied by target + source combo
	CodeAudit   bool   `json:"code_audit,omitempty"`  // implied by source-only
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
      "code_audit": false
    }
  ]
}

Rules:
- "target" is a URL (http:// or https://). If user says "running on localhost:3005", produce "http://localhost:3005".
- "source_path" is a filesystem path (starts with /, ~/, or ./).
- If both target and source_path are present for an app, set "discover" to true.
- If only source_path is present (no target URL), set "code_audit" to true.
- "focus" captures vulnerability type hints (e.g. "auth bypass", "injection", "XSS").
- "instruction" captures any remaining guidance that doesn't fit other fields.
- When multiple source paths are listed, create one app entry per source path.
- Expand ~ to the literal "~" character (do not resolve it).
- If a single target applies to multiple sources, duplicate it for each app.
- If no target or source path can be extracted, return {"apps": []}.`

// ParseScanIntent uses a quick LLM call to extract structured scan parameters
// from a natural language prompt. Falls back to structured input detection if
// the prompt looks like a URL, curl command, etc.
func ParseScanIntent(ctx context.Context, engine *Engine, prompt string) (*ScanIntent, error) {
	trimmed := strings.TrimSpace(prompt)
	if trimmed == "" {
		return nil, fmt.Errorf("empty scan prompt")
	}

	// Fast path: if input matches a structured format, skip the LLM call
	if intent := tryStructuredFallback(trimmed); intent != nil {
		return intent, nil
	}

	// Use the engine to make a quick LLM call for intent extraction
	opts := Options{
		PromptInline: fmt.Sprintf("%s\n\nUser request: %s", intentExtractionPrompt, trimmed),
		DryRun:       false,
	}

	result, err := engine.Run(ctx, opts)
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
func ParseAndResolveIntent(ctx context.Context, engine *Engine, prompt string) (*ScanIntent, error) {
	intent, err := ParseScanIntent(ctx, engine, prompt)
	if err != nil {
		return nil, err
	}
	if len(intent.Apps) == 0 {
		return nil, fmt.Errorf("could not extract any scan targets from prompt: %q", prompt)
	}
	return ResolveIntentApps(intent), nil
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
