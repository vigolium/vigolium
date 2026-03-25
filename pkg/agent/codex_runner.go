package agent

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent/codexsdk"
	"go.uber.org/zap"
)

// codexRunConfig holds configuration for Codex SDK-based agent runs.
type codexRunConfig struct {
	Cwd                   string
	StreamWriter          io.Writer
	Model                 string
	Sandbox               string // "read-only", "workspace-write", "danger-full-access"
	BaseInstructions      string // system prompt
	DeveloperInstructions string
}

// RunCodexSDK executes an AI agent using the Codex app-server JSON-RPC v2 protocol.
// This spawns `codex app-server --listen stdio://`, creates a thread, sends the prompt,
// and collects the response.
func RunCodexSDK(ctx context.Context, agentDef config.AgentDef, prompt string, cfg codexRunConfig) (result acpResult, err error) {
	opts := buildCodexOptions(agentDef, cfg)

	zap.L().Debug("starting agent via Codex SDK",
		zap.String("model", opts.Model),
		zap.String("cwd", opts.Cwd),
		zap.Int("promptLength", len(prompt)),
		zap.Bool("streaming", cfg.StreamWriter != nil))

	client := codexsdk.NewClient(opts)

	if err := client.Start(ctx); err != nil {
		return acpResult{}, fmt.Errorf("%w: %w", errCodexStartFailed, err)
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			zap.L().Debug("failed to close Codex client", zap.Error(closeErr))
		}
	}()

	// Initialize handshake
	initResp, err := client.Initialize(ctx)
	if err != nil {
		return acpResult{}, fmt.Errorf("%w: %w", errCodexInitFailed, err)
	}
	zap.L().Debug("codex app-server initialized", zap.Any("serverInfo", initResp))

	// Create thread
	threadParams := buildCodexThreadParams(opts, cfg)
	threadResp, err := client.ThreadStart(ctx, threadParams)
	if err != nil {
		return acpResult{}, fmt.Errorf("codex SDK thread/start failed: %w", err)
	}
	threadID := threadResp.Thread.Id
	zap.L().Debug("codex thread created",
		zap.String("threadId", threadID),
		zap.String("model", threadResp.Model))

	// Execute turn and collect output
	output, err := executeCodexTurn(ctx, client, threadID, prompt, cfg.StreamWriter)
	if err != nil {
		return acpResult{Stdout: output}, fmt.Errorf("%w: %w", errCodexTurnFailed, err)
	}

	zap.L().Debug("Codex SDK agent completed",
		zap.Int("outputBytes", len(output)),
		zap.String("threadId", threadID))

	return acpResult{
		Stdout:    output,
		SessionID: threadID,
	}, nil
}

// buildCodexOptions converts vigolium agent config into Codex SDK Options.
func buildCodexOptions(agentDef config.AgentDef, cfg codexRunConfig) *codexsdk.Options {
	opts := &codexsdk.Options{}

	if agentDef.Command != "" && agentDef.Command != "codex" {
		opts.Executable = agentDef.Command
		// Pass through agent-defined args as raw args (custom binary, not codex CLI)
		if len(agentDef.Args) > 0 {
			opts.RawArgs = agentDef.Args
		}
	}

	if cfg.Model != "" {
		opts.Model = cfg.Model
	} else if agentDef.Model != "" {
		opts.Model = agentDef.Model
	}

	if cfg.Cwd != "" {
		opts.Cwd = cfg.Cwd
	}

	if cfg.Sandbox != "" {
		opts.Sandbox = cfg.Sandbox
	} else {
		opts.Sandbox = codexsdk.SandboxModeDanger_full_access
	}

	// Environment variables from agent definition
	if len(agentDef.Env) > 0 {
		opts.Env = make(map[string]string, len(agentDef.Env))
		for k, v := range agentDef.Env {
			opts.Env[k] = v
		}
	}

	// Instructions
	opts.BaseInstructions = cfg.BaseInstructions
	opts.DeveloperInstructions = cfg.DeveloperInstructions

	return opts
}

// buildCodexThreadParams creates thread start params from options.
func buildCodexThreadParams(opts *codexsdk.Options, cfg codexRunConfig) *codexsdk.ThreadStartParams {
	params := &codexsdk.ThreadStartParams{}

	if opts.Model != "" {
		params.Model = &opts.Model
	}

	if opts.Sandbox != "" {
		params.Sandbox = &opts.Sandbox
	}

	if opts.Cwd != "" {
		params.Cwd = &opts.Cwd
	}

	if cfg.BaseInstructions != "" {
		params.BaseInstructions = &cfg.BaseInstructions
	}
	if cfg.DeveloperInstructions != "" {
		params.DeveloperInstructions = &cfg.DeveloperInstructions
	}

	return params
}

// executeCodexTurn sends a prompt and collects the full text response.
func executeCodexTurn(ctx context.Context, client *codexsdk.Client, threadID, prompt string, streamWriter io.Writer) (string, error) {
	if streamWriter != nil {
		// Capture streamed deltas into a buffer as fallback, since turn/completed
		// items may not include the text (depends on codex version).
		var captured strings.Builder
		var w io.Writer = &captured
		if streamWriter != nil {
			w = io.MultiWriter(streamWriter, &captured)
		}

		completed, err := client.StreamText(ctx, threadID, prompt, w)
		if err != nil {
			return captured.String(), err
		}
		// Prefer structured turn items; fall back to captured stream deltas.
		if text := extractTurnText(completed); text != "" {
			return text, nil
		}
		return captured.String(), nil
	}

	output, _, err := client.CollectText(ctx, threadID, prompt)
	return output, err
}

// extractTurnText extracts the text content from a completed turn's items.
func extractTurnText(completed *codexsdk.TurnCompletedNotification) string {
	if completed == nil {
		return ""
	}
	var b strings.Builder
	for _, item := range completed.Turn.Items {
		if item.Type == "message" && item.Text != nil {
			b.WriteString(*item.Text)
		}
	}
	return b.String()
}
