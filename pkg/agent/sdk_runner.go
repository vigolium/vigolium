package agent

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent/claudesdk"
	"go.uber.org/zap"
)

// sdkRunConfig holds configuration for SDK-based agent runs.
type sdkRunConfig struct {
	Cwd                string
	StreamWriter       io.Writer
	McpServers         []config.McpServerConfig
	Model              string   // override model for this run
	MaxTurns           int      // max agentic turns (0 = SDK default); set high for autopilot
	AdditionalDirs     []string // extra directories the agent can access (--add-dir)
	AppendSystemPrompt string   // appended to the default Claude Code system prompt
	Effort             string   // "low", "medium", "high"
}

// RunAgenticSDK executes an AI agent using the Claude Agent SDK (JSON-lines protocol).
// This provides full Claude Code CLI tool access (Read, Grep, Glob, Bash, Edit, etc.)
// unlike ACP which only provides ReadTextFile.
func RunAgenticSDK(ctx context.Context, agentDef config.AgentDef, prompt string, cfg sdkRunConfig) (result acpResult, err error) {
	opts := buildSDKOptions(agentDef, cfg)

	zap.L().Debug("starting agent via SDK",
		zap.String("model", opts.Model),
		zap.String("cwd", opts.Cwd),
		zap.Int("promptLength", len(prompt)),
		zap.Bool("streaming", opts.IncludePartialMessages))

	client := claudesdk.NewClient(opts)
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			zap.L().Debug("failed to close SDK client", zap.Error(closeErr))
		}
	}()

	// Send the prompt
	if err := client.Query(ctx, prompt); err != nil {
		return acpResult{}, fmt.Errorf("SDK query failed: %w", err)
	}

	// Collect output
	output, sessionID, err := collectSDKOutput(ctx, client, cfg.StreamWriter)
	if err != nil {
		return acpResult{Stdout: output, SessionID: sessionID}, fmt.Errorf("SDK output collection failed: %w", err)
	}

	zap.L().Debug("SDK agent completed",
		zap.Int("outputBytes", len(output)),
		zap.String("sessionID", sessionID))

	return acpResult{
		Stdout:    output,
		SessionID: sessionID,
	}, nil
}

// buildSDKOptions converts vigolium agent config into Claude SDK Options.
func buildSDKOptions(agentDef config.AgentDef, cfg sdkRunConfig) *claudesdk.Options {
	opts := &claudesdk.Options{
		PermissionMode:             "bypassPermissions",
		DangerouslySkipPermissions: true,
		IncludePartialMessages:     cfg.StreamWriter != nil,
		NoSessionPersistence:       true,
		DisallowedTools: []string{
			"AskUserQuestion",
			"EnterWorktree",
			"EnterPlanMode",
			"ExitPlanMode",
		},
	}

	// Model: cfg override > agentDef > default
	if cfg.Model != "" {
		opts.Model = cfg.Model
	} else if agentDef.Model != "" {
		opts.Model = agentDef.Model
	}

	// Working directory
	if cfg.Cwd != "" {
		opts.Cwd = cfg.Cwd
	}

	// Environment variables from agent definition
	if len(agentDef.Env) > 0 {
		opts.Env = make(map[string]string, len(agentDef.Env))
		for k, v := range agentDef.Env {
			opts.Env[k] = v
		}
	}

	// Custom executable path
	if agentDef.Command != "" && agentDef.Command != "claude" {
		opts.Executable = agentDef.Command
	}

	// MCP servers: convert from vigolium config to --mcp-config JSON
	mcpJSON := buildMcpConfigFromServers(cfg.McpServers)
	if mcpJSON != "" {
		opts.McpConfigJSON = mcpJSON
	}

	// Max turns for autopilot mode
	if cfg.MaxTurns > 0 {
		opts.MaxTurns = cfg.MaxTurns
	}

	// Additional directories the agent can access
	if len(cfg.AdditionalDirs) > 0 {
		opts.AdditionalDirs = cfg.AdditionalDirs
	}

	// System prompt appended to Claude Code's default
	if cfg.AppendSystemPrompt != "" {
		opts.AppendSystemPrompt = cfg.AppendSystemPrompt
	}

	// Effort level
	if cfg.Effort != "" {
		opts.Effort = cfg.Effort
	}

	return opts
}

// buildMcpConfigFromServers converts vigolium MCP server configs to a JSON string
// for the --mcp-config CLI flag.
func buildMcpConfigFromServers(servers []config.McpServerConfig) string {
	if len(servers) == 0 {
		return ""
	}
	m := make(map[string]any, len(servers))
	for _, s := range servers {
		if s.Command != "" {
			m[s.Name] = claudesdk.McpStdioServer{
				Command: s.Command,
				Args:    s.Args,
				Env:     s.Env,
			}
		} else if s.URL != "" {
			m[s.Name] = claudesdk.McpHTTPServer{
				Type: "http",
				URL:  s.URL,
			}
		}
	}
	j, err := claudesdk.BuildMcpConfigJSON(m)
	if err != nil {
		zap.L().Warn("failed to build MCP config JSON", zap.Error(err))
		return ""
	}
	return j
}

// collectSDKOutput reads all messages from the SDK client, accumulates text output,
// and optionally streams it to a writer in real-time.
func collectSDKOutput(ctx context.Context, client *claudesdk.Client, streamWriter io.Writer) (output string, sessionID string, err error) {
	if streamWriter != nil {
		return collectSDKOutputStreaming(ctx, client, streamWriter)
	}

	var outputBuf strings.Builder

	for msg := range client.ReceiveResponse(ctx) {
		switch m := msg.(type) {
		case *claudesdk.AssistantMessage:
			for _, block := range m.Content {
				if block.Type == "text" {
					outputBuf.WriteString(block.Text)
				}
			}
			sessionID = m.GetSessionID()
		case *claudesdk.ResultMessage:
			sessionID = m.GetSessionID()
			if m.IsError {
				zap.L().Warn("SDK agent returned error result",
					zap.String("subtype", m.Subtype))
			}
			zap.L().Debug("SDK agent result",
				zap.Float64("costUSD", m.TotalCostUSD),
				zap.Int("turns", m.NumTurns),
				zap.Int("inputTokens", m.Usage.InputTokens),
				zap.Int("outputTokens", m.Usage.OutputTokens))
		}
	}

	return outputBuf.String(), sessionID, nil
}

// collectSDKOutputStreaming handles streaming output with real-time writing.
func collectSDKOutputStreaming(ctx context.Context, client *claudesdk.Client, streamWriter io.Writer) (output string, sessionID string, err error) {
	var outputBuf strings.Builder
	msgChan, errChan := client.ReceiveMessages(ctx)

	for {
		select {
		case msg := <-msgChan:
			if msg == nil {
				return outputBuf.String(), sessionID, nil
			}

			switch m := msg.(type) {
			case *claudesdk.StreamEvent:
				if m.Delta != nil {
					outputBuf.WriteString(m.Delta.Text)
					_, _ = io.WriteString(streamWriter, m.Delta.Text)
				}
			case *claudesdk.AssistantMessage:
				// Fallback if no stream data was captured
				if outputBuf.Len() == 0 {
					for _, block := range m.Content {
						if block.Type == "text" {
							outputBuf.WriteString(block.Text)
							_, _ = io.WriteString(streamWriter, block.Text)
						}
					}
				}
				sessionID = m.GetSessionID()
			case *claudesdk.ResultMessage:
				sessionID = m.GetSessionID()
				if m.IsError {
					zap.L().Warn("SDK agent returned error result",
						zap.String("subtype", m.Subtype))
				}
				zap.L().Debug("SDK agent result",
					zap.Float64("costUSD", m.TotalCostUSD),
					zap.Int("turns", m.NumTurns),
					zap.Int("inputTokens", m.Usage.InputTokens),
					zap.Int("outputTokens", m.Usage.OutputTokens))
			}

		case err := <-errChan:
			if err != nil {
				return outputBuf.String(), sessionID, fmt.Errorf("SDK stream error: %w", err)
			}
			return outputBuf.String(), sessionID, nil

		case <-ctx.Done():
			return outputBuf.String(), sessionID, ctx.Err()
		}
	}
}
