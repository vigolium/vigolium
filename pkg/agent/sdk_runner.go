package agent

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent/claudesdk"
	"go.uber.org/zap"
)

// writeStderrToSessionDir writes stderr output to a log file in the session directory.
func writeStderrToSessionDir(sessionDir, stderr string) {
	if sessionDir == "" || stderr == "" {
		return
	}
	path := filepath.Join(sessionDir, "agent-stderr.log")
	if err := os.WriteFile(path, []byte(stderr), 0o644); err != nil {
		zap.L().Debug("failed to write stderr to session dir", zap.Error(err))
	}
}

// sdkRunConfig holds configuration for SDK-based agent runs.
type sdkRunConfig struct {
	Cwd                string
	StreamWriter       io.Writer
	McpServers         []config.McpServerConfig
	Model              string   // override model for this run
	MaxTurns           int      // max agentic turns (0 = SDK default); set high for autopilot
	AdditionalDirs     []string // extra directories the agent can access (--add-dir)
	AppendSystemPrompt string   // appended to the default Claude Code system prompt (inline, use SystemPromptDir to avoid long CLI args)
	SystemPromptSource string   // human-readable source description of where the system prompt was loaded from
	Effort             string   // "low", "medium", "high"
	SessionID          string   // pre-generated UUID for --session-id (enables persistence + resume)
	SystemPromptDir    string   // when set, write system prompt to a file here and use as CWD (avoids huge --append-system-prompt arg)
	Guardrails         config.AutopilotGuardrails // guardrails for SDK autonomous mode
	SessionDir         string   // session directory for saving stderr logs
}

// RunAgenticSDK executes an AI agent using the Claude Agent SDK (JSON-lines protocol).
// This provides full Claude Code CLI tool access (Read, Grep, Glob, Bash, Edit, etc.)
// unlike ACP which only provides ReadTextFile.
func RunAgenticSDK(ctx context.Context, agentDef config.AgentDef, prompt string, cfg sdkRunConfig) (result acpResult, err error) {
	opts := buildSDKOptions(agentDef, cfg)

	logLevel := zap.DebugLevel
	if cfg.Guardrails.LogCommands {
		logLevel = zap.InfoLevel
	}

	if ce := zap.L().Check(logLevel, "starting agent via SDK"); ce != nil {
		ce.Write(
			zap.String("model", opts.Model),
			zap.String("cwd", opts.Cwd),
			zap.Int("promptLength", len(prompt)),
			zap.Bool("streaming", opts.IncludePartialMessages))
	}

	start := time.Now()
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

	if ce := zap.L().Check(logLevel, "SDK agent completed"); ce != nil {
		ce.Write(
			zap.Int("outputBytes", len(output)),
			zap.String("sessionID", sessionID),
			zap.Duration("duration", time.Since(start)))
	}

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

	// Session ID: when provided, enable persistence so the session can be resumed.
	if cfg.SessionID != "" {
		opts.SessionID = cfg.SessionID
		opts.NoSessionPersistence = false
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

	// Guardrails: merge extra disallowed tools and enforce max turns ceiling
	if len(cfg.Guardrails.DisallowedTools) > 0 {
		opts.DisallowedTools = append(opts.DisallowedTools, cfg.Guardrails.DisallowedTools...)
	}
	if cfg.Guardrails.MaxTurns > 0 && (opts.MaxTurns == 0 || opts.MaxTurns > cfg.Guardrails.MaxTurns) {
		opts.MaxTurns = cfg.Guardrails.MaxTurns
	}

	// Additional directories the agent can access
	if len(cfg.AdditionalDirs) > 0 {
		opts.AdditionalDirs = cfg.AdditionalDirs
	}

	// System prompt: prefer writing to a file in SystemPromptDir (avoids
	// passing a multi-KB --append-system-prompt CLI arg).
	//
	// For Claude Code: writes CLAUDE.md (auto-discovered from CWD, no CLI arg needed).
	// For other agents: writes AGENTS.md (reference only) and still passes inline.
	if cfg.AppendSystemPrompt != "" {
		isClaude := isClaudeAgent(agentDef.Command)
		filename := systemPromptFilename(agentDef.Command)

		if cfg.SystemPromptDir != "" {
			writtenPath, writeErr := writeSystemPromptFile(cfg.SystemPromptDir, filename, cfg.AppendSystemPrompt)
			if writeErr != nil {
				zap.L().Warn("failed to write system prompt file, falling back to inline",
					zap.String("filename", filename), zap.Error(writeErr))
				opts.AppendSystemPrompt = cfg.AppendSystemPrompt
			} else {
				printSystemPromptInfo(cfg.SystemPromptSource, writtenPath)

				if isClaude {
					// Claude Code auto-discovers CLAUDE.md — set CWD to prompt dir,
					// move original CWD to --add-dir so agent retains access.
					// Skip if CWD is already in AdditionalDirs (e.g. source path).
					if cfg.Cwd != "" && cfg.Cwd != "." && cfg.Cwd != cfg.SystemPromptDir {
						alreadyAdded := false
						for _, d := range opts.AdditionalDirs {
							if d == cfg.Cwd {
								alreadyAdded = true
								break
							}
						}
						if !alreadyAdded {
							opts.AdditionalDirs = append(opts.AdditionalDirs, cfg.Cwd)
						}
					}
					opts.Cwd = cfg.SystemPromptDir
				} else {
					// Other agents don't auto-discover AGENTS.md — still pass inline.
					opts.AppendSystemPrompt = cfg.AppendSystemPrompt
				}
			}
		} else {
			// No session dir — pass inline
			if cfg.SystemPromptSource != "" {
				printSystemPromptInfo(cfg.SystemPromptSource, "")
			}
			opts.AppendSystemPrompt = cfg.AppendSystemPrompt
		}
	}

	// Effort level
	if cfg.Effort != "" {
		opts.Effort = cfg.Effort
	}

	return opts
}

// writeSystemPromptFile writes the system prompt to a file in the given directory.
// Returns the full path of the written file.
//
// Claude Code auto-discovers CLAUDE.md from CWD. For other agents, AGENTS.md is
// written as a reference artifact (the prompt is still passed via CLI arg).
func writeSystemPromptFile(dir, filename, content string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create directory %s: %w", dir, err)
	}
	path := filepath.Join(dir, filename)
	return path, os.WriteFile(path, []byte(content), 0o644)
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
