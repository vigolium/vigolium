// Package claudesdk provides a minimal Claude Code CLI SDK for vigolium.
// It spawns the claude CLI as a subprocess, communicates via JSON-lines over
// stdin/stdout, and provides full control over all CLI flags.
package claudesdk

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// Options configures a Claude Code CLI session.
type Options struct {
	// Executable path. Defaults to "claude" (resolved via $PATH).
	Executable string

	// Working directory for the CLI process.
	Cwd string

	// Model selection (e.g., "sonnet", "opus", "claude-sonnet-4-5").
	Model string

	// Permission mode (e.g., "bypassPermissions", "plan", "default").
	PermissionMode string

	// Bypass all permission checks. Requires PermissionMode="bypassPermissions".
	DangerouslySkipPermissions bool

	// Enable streaming partial message chunks (ContentBlockDelta events).
	IncludePartialMessages bool

	// Don't save sessions to disk — scanner doesn't need session persistence.
	NoSessionPersistence bool

	// Use a specific session ID for the conversation (must be a valid UUID).
	// When set, NoSessionPersistence is ignored (persistence required for resume).
	SessionID string

	// Minimal mode: skip hooks, LSP, auto-memory, CLAUDE.md discovery.
	Bare bool

	// Tool allow/deny lists (repeatable).
	AllowedTools    []string
	DisallowedTools []string

	// Additional directories the agent can access.
	AdditionalDirs []string

	// System prompt (mutually exclusive — use one or the other).
	SystemPrompt       string // replaces the default system prompt
	AppendSystemPrompt string // appends to the default system prompt

	// MCP server configuration as a JSON string for --mcp-config.
	// Use BuildMcpConfigJSON() to generate this from a server map.
	McpConfigJSON string

	// Max agentic turns (0 = CLI default). Set high for autopilot.
	MaxTurns int

	// Spending limit in USD (0 = no limit).
	MaxBudgetUSD float64

	// Effort level: "low", "medium", "high".
	Effort string

	// Setting sources override. nil = omit flag (use defaults).
	// Empty string = pass empty value (suppress all config loading).
	SettingSources *string

	// Resume a previous session by session ID.
	Resume string

	// Continue the most recent conversation in the working directory.
	Continue bool

	// Custom agents as JSON string for --agents flag.
	// Format: '{"name": {"description": "...", "prompt": "...", "model": "..."}}'
	// Use BuildAgentsJSON() to generate this from an AgentDefinition map.
	AgentsJSON string

	// Plugin directories (repeatable). Each is passed as --plugin-dir <path>.
	PluginDirs []string

	// MCP config files or JSON strings (repeatable). Each is passed as --mcp-config <value>.
	// McpConfigJSON is a convenience for a single inline JSON config.
	// McpConfigs allows multiple --mcp-config entries (files or inline JSON).
	McpConfigs []string

	// Environment variables for the subprocess.
	Env map[string]string
}

// buildArgs constructs CLI arguments from the Options.
func (o *Options) buildArgs() []string {
	args := []string{
		"--print",
		"--output-format=stream-json",
		"--input-format=stream-json",
		"--verbose",
	}

	if o.Model != "" {
		args = append(args, "--model", o.Model)
	}
	if o.PermissionMode != "" {
		args = append(args, "--permission-mode", o.PermissionMode)
	}
	if o.DangerouslySkipPermissions {
		args = append(args, "--dangerously-skip-permissions")
	}
	if o.IncludePartialMessages {
		args = append(args, "--include-partial-messages")
	}
	if o.SessionID != "" {
		// When a session ID is provided, enable persistence so the session can be resumed later.
		args = append(args, "--session-id", o.SessionID)
	} else if o.NoSessionPersistence {
		args = append(args, "--no-session-persistence")
	}
	if o.Bare {
		args = append(args, "--bare")
	}
	for _, tool := range o.AllowedTools {
		args = append(args, "--allowed-tools", tool)
	}
	for _, tool := range o.DisallowedTools {
		args = append(args, "--disallowed-tools", tool)
	}
	for _, dir := range o.AdditionalDirs {
		args = append(args, "--add-dir", dir)
	}
	if o.SystemPrompt != "" {
		args = append(args, "--system-prompt", o.SystemPrompt)
	}
	if o.AppendSystemPrompt != "" {
		args = append(args, "--append-system-prompt", o.AppendSystemPrompt)
	}
	if o.McpConfigJSON != "" {
		args = append(args, "--mcp-config", o.McpConfigJSON)
	}
	for _, mc := range o.McpConfigs {
		args = append(args, "--mcp-config", mc)
	}
	if o.MaxTurns > 0 {
		args = append(args, "--max-turns", strconv.Itoa(o.MaxTurns))
	}
	if o.MaxBudgetUSD > 0 {
		args = append(args, "--max-budget-usd", fmt.Sprintf("%.2f", o.MaxBudgetUSD))
	}
	if o.Effort != "" {
		args = append(args, "--effort", o.Effort)
	}
	if o.SettingSources != nil {
		args = append(args, "--setting-sources", *o.SettingSources)
	}
	if o.Resume != "" {
		args = append(args, "--resume", o.Resume)
	}
	if o.Continue {
		args = append(args, "--continue")
	}
	if o.AgentsJSON != "" {
		args = append(args, "--agents", o.AgentsJSON)
	}
	for _, dir := range o.PluginDirs {
		args = append(args, "--plugin-dir", dir)
	}

	return args
}

// BuildMcpConfigJSON marshals a map of MCP server configs to JSON for --mcp-config.
// The map keys are server names, values should be McpStdioServer or McpHTTPServer structs.
func BuildMcpConfigJSON(servers map[string]any) (string, error) {
	if len(servers) == 0 {
		return "", nil
	}
	data, err := json.Marshal(servers)
	if err != nil {
		return "", fmt.Errorf("failed to marshal MCP config: %w", err)
	}
	return string(data), nil
}

// AgentDefinition defines a custom agent passed via --agents.
type AgentDefinition struct {
	Description     string   `json:"description"`
	Prompt          string   `json:"prompt"`
	Model           string   `json:"model,omitempty"`
	Tools           []string `json:"tools,omitempty"`
	DisallowedTools []string `json:"disallowedTools,omitempty"`
}

// BuildAgentsJSON marshals a map of agent definitions to JSON for --agents.
func BuildAgentsJSON(agents map[string]AgentDefinition) (string, error) {
	if len(agents) == 0 {
		return "", nil
	}
	data, err := json.Marshal(agents)
	if err != nil {
		return "", fmt.Errorf("failed to marshal agents config: %w", err)
	}
	return string(data), nil
}

// McpStdioServer defines an MCP server using stdio transport.
type McpStdioServer struct {
	Command string            `json:"command"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
}

// McpHTTPServer defines an MCP server using HTTP transport.
type McpHTTPServer struct {
	Type string `json:"type"` // "http"
	URL  string `json:"url"`
}
