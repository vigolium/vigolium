package backend

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"github.com/vigolium/vigolium/pkg/agent/opencodesdk"
	"go.uber.org/zap"
)

// OpenCodeRunConfig holds configuration for OpenCode SDK-based agent runs.
type OpenCodeRunConfig struct {
	Cwd          string
	StreamWriter io.Writer
	Model        string
	SystemPrompt string // system prompt to include
}

// RunOpenCodeSDK executes an AI agent using the OpenCode daemon REST/SSE protocol.
// This spawns `opencode serve`, creates a session, sends the prompt, and collects
// the response via SSE streaming.
func RunOpenCodeSDK(ctx context.Context, agentDef config.AgentDef, prompt string, cfg OpenCodeRunConfig) (result agenttypes.RunResult, err error) {
	opts := BuildOpenCodeSDKOptions(agentDef, cfg)

	zap.L().Debug("starting agent via OpenCode SDK",
		zap.String("model", opts.Model),
		zap.String("cwd", opts.Cwd),
		zap.Int("promptLength", len(prompt)),
		zap.Bool("streaming", cfg.StreamWriter != nil))

	client := opencodesdk.NewClient(opts)

	if err := client.Start(ctx); err != nil {
		return agenttypes.RunResult{}, fmt.Errorf("%w: %w", ErrOpenCodeStartFailed, err)
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			zap.L().Debug("failed to close OpenCode client", zap.Error(closeErr))
		}
	}()

	// Create session
	sessionID, err := client.CreateSession(ctx)
	if err != nil {
		return agenttypes.RunResult{}, fmt.Errorf("%w: %w", ErrOpenCodeSessionFailed, err)
	}
	zap.L().Debug("opencode session created", zap.String("sessionId", sessionID))

	// Execute prompt and collect output
	output, err := client.Prompt(ctx, sessionID, prompt, cfg.StreamWriter)
	if err != nil {
		return agenttypes.RunResult{Stdout: output, SessionID: sessionID}, fmt.Errorf("%w: %w", ErrOpenCodePromptFailed, err)
	}

	zap.L().Debug("OpenCode SDK agent completed",
		zap.Int("outputBytes", len(output)),
		zap.String("sessionId", sessionID))

	return agenttypes.RunResult{
		Stdout:    output,
		SessionID: sessionID,
	}, nil
}

// BuildOpenCodeSDKOptions converts vigolium agent config into OpenCode SDK Options.
func BuildOpenCodeSDKOptions(agentDef config.AgentDef, cfg OpenCodeRunConfig) *opencodesdk.Options {
	opts := &opencodesdk.Options{}

	// Custom executable
	if agentDef.Command != "" && agentDef.Command != "opencode" {
		opts.Executable = agentDef.Command
	}

	// Model: cfg override > agentDef
	if cfg.Model != "" {
		opts.Model = cfg.Model
	} else if agentDef.Model != "" {
		opts.Model = agentDef.Model
	}

	// Working directory
	if cfg.Cwd != "" {
		opts.Cwd = cfg.Cwd
	}

	// System prompt
	opts.SystemPrompt = cfg.SystemPrompt

	// Environment variables from agent definition
	env := make(map[string]string, len(agentDef.Env)+1)
	for k, v := range agentDef.Env {
		env[k] = v
	}

	// Inject OPENCODE_CONFIG_CONTENT for model/permissions (reuse existing builder)
	model := opts.Model
	if model != "" || agentDef.ProviderConfig != nil {
		env["OPENCODE_CONFIG_CONTENT"] = buildOpenCodeConfigJSON(model, agentDef.ProviderConfig)
	}

	opts.Env = env

	return opts
}

// buildOpenCodeConfigJSON constructs the OPENCODE_CONFIG_CONTENT JSON string
// from model and provider config.
func buildOpenCodeConfigJSON(model string, pc *config.ProviderConfig) string {
	cfg := make(map[string]any)

	if model != "" {
		cfg["config"] = map[string]any{"model": model}
	}

	needsProvider := pc != nil && ((pc.Thinking != nil && pc.Thinking.Enabled) || pc.APIURL != "")
	if needsProvider && model != "" {
		providerID, modelID := splitModelID(model)
		providerBlock := buildProviderBlock(providerID, modelID, pc)
		if providerBlock != nil {
			cfg["provider"] = providerBlock
		}
	}

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

// splitModelID splits "anthropic/claude-sonnet-4-5" into ("anthropic", "claude-sonnet-4-5").
func splitModelID(model string) (string, string) {
	if providerID, modelID, ok := strings.Cut(model, "/"); ok {
		return providerID, modelID
	}
	return "custom", model
}

// buildProviderBlock constructs the "provider" section of the OpenCode config JSON.
func buildProviderBlock(providerID, modelID string, pc *config.ProviderConfig) map[string]any {
	modelOpts := make(map[string]any)

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
