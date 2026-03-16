package agent

import (
	"encoding/json"
	"maps"
	"path/filepath"
	"strings"

	"github.com/vigolium/vigolium/internal/config"
)

// acpProvider identifies the ACP backend type for provider-specific behavior.
type acpProvider int

const (
	providerUnknown  acpProvider = iota
	providerClaude               // model via SetSessionModel; config via ACP _meta
	providerGemini               // model via -m CLI arg
	providerOpenCode             // model + config via OPENCODE_CONFIG_CONTENT env var
	providerCodex                // model via --model CLI arg
	providerCursor               // model via --model CLI arg
)

// inferProvider detects the ACP provider from the agent definition's command and args.
func inferProvider(def config.AgentDef) acpProvider {
	base := filepath.Base(def.Command)
	switch base {
	case "gemini":
		return providerGemini
	case "opencode":
		return providerOpenCode
	case "codex":
		return providerCodex
	case "cursor":
		return providerCursor
	case "claude":
		return providerClaude
	case "npx", "bunx", "pnpx":
		for _, arg := range def.Args {
			if strings.Contains(arg, "claude-agent-acp") {
				return providerClaude
			}
		}
	}
	if strings.Contains(base, "claude") {
		return providerClaude
	}
	return providerUnknown
}

// buildProviderArgs returns the final CLI args with model injected for the provider.
// For Gemini, Cursor, and Codex, the model is injected as a CLI flag.
// For Claude and OpenCode, args are returned unchanged (model is handled elsewhere).
func buildProviderArgs(def config.AgentDef) []string {
	if def.Model == "" {
		return def.Args
	}
	switch inferProvider(def) {
	case providerGemini:
		return injectArgBefore(def.Args, "--experimental-acp", "-m", def.Model)
	case providerCursor:
		return injectArgBefore(def.Args, "acp", "--model", def.Model)
	case providerCodex:
		return injectArgBefore(def.Args, "app-server", "--model", def.Model)
	default:
		return def.Args
	}
}

// buildProviderEnv returns env vars with provider-specific config injected.
// For OpenCode, builds OPENCODE_CONFIG_CONTENT from model and ProviderConfig.
// For other providers, returns def.Env as-is.
func buildProviderEnv(def config.AgentDef) map[string]string {
	if inferProvider(def) != providerOpenCode || (def.Model == "" && def.ProviderConfig == nil) {
		return def.Env
	}
	result := make(map[string]string, len(def.Env)+1)
	maps.Copy(result, def.Env)
	result["OPENCODE_CONFIG_CONTENT"] = buildOpenCodeConfigJSON(def.Model, def.ProviderConfig)
	return result
}

// injectArgBefore inserts flag and value before the first occurrence of target in args.
// If target is not found, flag and value are prepended at position 0.
func injectArgBefore(args []string, target, flag, value string) []string {
	result := make([]string, 0, len(args)+2)
	inserted := false
	for _, arg := range args {
		if arg == target && !inserted {
			result = append(result, flag, value)
			inserted = true
		}
		result = append(result, arg)
	}
	if !inserted {
		result = append([]string{flag, value}, result...)
	}
	return result
}

// buildOpenCodeConfigJSON constructs the OPENCODE_CONFIG_CONTENT JSON string
// from model and provider config. The JSON structure follows OpenCode's expected format:
//
//	{
//	  "config": {"model": "<model>"},
//	  "provider": { ... },  // only when thinking or api_url is set
//	  "agent": { "build": { "permission": { ... } } }
//	}
func buildOpenCodeConfigJSON(model string, pc *config.ProviderConfig) string {
	cfg := make(map[string]any)

	// Config block with model
	if model != "" {
		cfg["config"] = map[string]any{"model": model}
	}

	// Provider block for thinking and custom API
	needsProvider := pc != nil && ((pc.Thinking != nil && pc.Thinking.Enabled) || pc.APIURL != "")
	if needsProvider && model != "" {
		providerID, modelID := splitModelID(model)
		providerBlock := buildProviderBlock(providerID, modelID, pc)
		if providerBlock != nil {
			cfg["provider"] = providerBlock
		}
	}

	// Agent block with permissions
	perm := map[string]any{
		"read": config.PermissionAllow, "edit": config.PermissionAllow,
		"write": config.PermissionAllow, "bash": config.PermissionAllow,
	}
	if pc != nil && pc.Permission != nil {
		p := pc.Permission
		if p.Read != "" {
			perm["read"] = p.Read
		}
		if p.Edit != "" {
			perm["edit"] = p.Edit
		}
		if p.Write != "" {
			perm["write"] = p.Write
		}
		if p.Bash != "" {
			perm["bash"] = p.Bash
		}
	}
	cfg["agent"] = map[string]any{
		"build": map[string]any{
			"permission": perm,
		},
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		return "{}"
	}
	return string(data)
}

// splitModelID splits a model string like "anthropic/claude-sonnet-4-5" into
// provider ID ("anthropic") and model ID ("claude-sonnet-4-5").
// If no slash is found, returns ("custom", model).
func splitModelID(model string) (string, string) {
	if providerID, modelID, ok := strings.Cut(model, "/"); ok {
		return providerID, modelID
	}
	return "custom", model
}

// buildProviderBlock constructs the "provider" section of the OpenCode config JSON.
func buildProviderBlock(providerID, modelID string, pc *config.ProviderConfig) map[string]any {
	modelOpts := make(map[string]any)

	// Thinking config
	if pc.Thinking != nil && pc.Thinking.Enabled {
		modelOpts["thinking"] = map[string]any{
			"type":         "enabled",
			"budgetTokens": pc.Thinking.EffectiveBudgetTokens(),
		}
	}

	modelEntry := map[string]any{"name": modelID}
	if len(modelOpts) > 0 {
		modelEntry["options"] = modelOpts
	}

	providerEntry := map[string]any{
		"models": map[string]any{
			modelID: modelEntry,
		},
	}

	// Custom API URL provider
	if pc.APIURL != "" {
		providerEntry["npm"] = "@ai-sdk/openai-compatible"
		providerEntry["name"] = "Custom"
		apiKey := pc.APIKey
		if apiKey == "" {
			apiKey = "sk-none"
		}
		providerEntry["options"] = map[string]any{
			"baseURL": pc.APIURL,
			"apiKey":  apiKey,
		}
	}

	return map[string]any{providerID: providerEntry}
}
