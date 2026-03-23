package agent

import (
	"context"
	"fmt"
	"io"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent/opencodesdk"
	"go.uber.org/zap"
)

// opencodeRunConfig holds configuration for OpenCode SDK-based agent runs.
type opencodeRunConfig struct {
	Cwd          string
	StreamWriter io.Writer
	Model        string
	SystemPrompt string // system prompt to include
}

// RunOpenCodeSDK executes an AI agent using the OpenCode daemon REST/SSE protocol.
// This spawns `opencode serve`, creates a session, sends the prompt, and collects
// the response via SSE streaming.
func RunOpenCodeSDK(ctx context.Context, agentDef config.AgentDef, prompt string, cfg opencodeRunConfig) (result acpResult, err error) {
	opts := buildOpenCodeSDKOptions(agentDef, cfg)

	zap.L().Debug("starting agent via OpenCode SDK",
		zap.String("model", opts.Model),
		zap.String("cwd", opts.Cwd),
		zap.Int("promptLength", len(prompt)),
		zap.Bool("streaming", cfg.StreamWriter != nil))

	client := opencodesdk.NewClient(opts)

	if err := client.Start(ctx); err != nil {
		return acpResult{}, fmt.Errorf("OpenCode SDK start failed: %w", err)
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			zap.L().Debug("failed to close OpenCode client", zap.Error(closeErr))
		}
	}()

	// Create session
	sessionID, err := client.CreateSession(ctx)
	if err != nil {
		return acpResult{}, fmt.Errorf("OpenCode SDK session creation failed: %w", err)
	}
	zap.L().Debug("opencode session created", zap.String("sessionId", sessionID))

	// Execute prompt and collect output
	output, err := client.Prompt(ctx, sessionID, prompt, cfg.StreamWriter)
	if err != nil {
		return acpResult{Stdout: output, SessionID: sessionID}, fmt.Errorf("OpenCode SDK prompt failed: %w", err)
	}

	zap.L().Debug("OpenCode SDK agent completed",
		zap.Int("outputBytes", len(output)),
		zap.String("sessionId", sessionID))

	return acpResult{
		Stdout:    output,
		SessionID: sessionID,
	}, nil
}

// buildOpenCodeSDKOptions converts vigolium agent config into OpenCode SDK Options.
func buildOpenCodeSDKOptions(agentDef config.AgentDef, cfg opencodeRunConfig) *opencodesdk.Options {
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
