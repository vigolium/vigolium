package config

import "fmt"

// AgentConfig holds AI agent integration settings.
type AgentConfig struct {
	DefaultAgent string              `yaml:"default_agent"`
	Backends     map[string]AgentDef `yaml:"backends"`
	TemplatesDir string              `yaml:"templates_dir"`
	SessionsDir  string              `yaml:"sessions_dir"` // directory for agent run session artifacts (default: ~/.vigolium/agent-sessions/)
	Stream       *bool               `yaml:"stream,omitempty"`
	LLM          LLMConfig           `yaml:"llm"`
	WarmSession  WarmSessionConfig   `yaml:"warm_session"`
	McpEnabled    *bool               `yaml:"mcp_enabled,omitempty"`    // enable MCP server passthrough to ACP sessions (default: false)
	McpServers    []McpServerConfig   `yaml:"mcp_servers,omitempty"`    // global MCP servers attached to all ACP sessions when mcp_enabled is true
	SwarmTerminal SwarmTerminalConfig `yaml:"swarm_terminal,omitempty"` // terminal config for swarm agent sessions
	ContextLimits ContextLimits       `yaml:"context_limits,omitempty"` // limits for DB context enrichment
	Guardrails    AutopilotGuardrails `yaml:"guardrails,omitempty"`     // guardrails for SDK autonomous mode
}

// ContextLimits controls how much data is pulled from the DB for agent context enrichment.
type ContextLimits struct {
	MaxFindings  int `yaml:"max_findings,omitempty"`  // default: 50
	MaxEndpoints int `yaml:"max_endpoints,omitempty"` // default: 100
	MaxHighRisk  int `yaml:"max_high_risk,omitempty"` // default: 20
	MinRiskScore int `yaml:"min_risk_score,omitempty"` // default: 50
}

// EffectiveMaxFindings returns MaxFindings or the default (50).
func (c *ContextLimits) EffectiveMaxFindings() int {
	if c.MaxFindings > 0 {
		return c.MaxFindings
	}
	return 50
}

// EffectiveMaxEndpoints returns MaxEndpoints or the default (100).
func (c *ContextLimits) EffectiveMaxEndpoints() int {
	if c.MaxEndpoints > 0 {
		return c.MaxEndpoints
	}
	return 100
}

// EffectiveMaxHighRisk returns MaxHighRisk or the default (20).
func (c *ContextLimits) EffectiveMaxHighRisk() int {
	if c.MaxHighRisk > 0 {
		return c.MaxHighRisk
	}
	return 20
}

// EffectiveMinRiskScore returns MinRiskScore or the default (50).
func (c *ContextLimits) EffectiveMinRiskScore() int {
	if c.MinRiskScore > 0 {
		return c.MinRiskScore
	}
	return 50
}

// AutopilotGuardrails controls safety and observability for SDK autonomous mode.
type AutopilotGuardrails struct {
	LogCommands     bool     `yaml:"log_commands,omitempty"`     // log agent tool use at INFO level (default: false)
	MaxTurns        int      `yaml:"max_turns,omitempty"`        // hard ceiling for max turns (0 = no override, use MaxCommands*3)
	DisallowedTools []string `yaml:"disallowed_tools,omitempty"` // extra tools to block in SDK mode
}

// IsMcpEnabled returns whether MCP server passthrough is enabled. Defaults to false.
func (c *AgentConfig) IsMcpEnabled() bool {
	return c.McpEnabled != nil && *c.McpEnabled
}

// WarmSessionConfig controls ACP subprocess pooling for session reuse.
type WarmSessionConfig struct {
	Enable      *bool `yaml:"enable,omitempty"`      // default: false
	IdleTimeout int   `yaml:"idle_timeout,omitempty"` // seconds, default: 300
	MaxSessions int   `yaml:"max_sessions,omitempty"` // default: 2
}

// IsEnabled returns whether warm sessions are enabled.
func (c *WarmSessionConfig) IsEnabled() bool {
	return c.Enable != nil && *c.Enable
}

// EffectiveIdleTimeout returns the idle timeout in seconds, defaulting to 300.
func (c *WarmSessionConfig) EffectiveIdleTimeout() int {
	if c.IdleTimeout <= 0 {
		return 300
	}
	return c.IdleTimeout
}

// EffectiveMaxSessions returns the max sessions, defaulting to 2.
func (c *WarmSessionConfig) EffectiveMaxSessions() int {
	if c.MaxSessions <= 0 {
		return 2
	}
	return c.MaxSessions
}

// SwarmTerminalConfig configures terminal capability for swarm agent sessions.
// When SlashCommands or CustomAgents are set, the swarm enables CreateTerminal
// in ACP sessions so the agent can invoke slash commands and sub-agents.
type SwarmTerminalConfig struct {
	SlashCommands []string `yaml:"slash_commands,omitempty"`  // custom slash commands available inside the ACP session (e.g. /security-review)
	CustomAgents  []string `yaml:"custom_agents,omitempty"`   // agent backend names the agent can invoke via "vigolium agent query --agent=X"
	MaxCommands   int      `yaml:"max_commands,omitempty"`    // max terminal commands per session (default: 50)
}

// HasTerminal returns true if any terminal capability is configured.
func (c *SwarmTerminalConfig) HasTerminal() bool {
	return len(c.SlashCommands) > 0 || len(c.CustomAgents) > 0
}

// EffectiveMaxCommands returns the max commands, defaulting to 50.
func (c *SwarmTerminalConfig) EffectiveMaxCommands() int {
	if c.MaxCommands <= 0 {
		return 50
	}
	return c.MaxCommands
}

// LLMConfig holds settings for direct LLM API calls (used by JS extension agent API).
type LLMConfig struct {
	Provider    string  `yaml:"provider"`    // "anthropic" (default) or "openai"
	Model       string  `yaml:"model"`       // e.g. "claude-sonnet-4-20250514", "gpt-4o"
	APIKey      string  `yaml:"api_key"`     // inline key (prefer api_key_env)
	APIKeyEnv   string  `yaml:"api_key_env"` // env var name; defaults to ANTHROPIC_API_KEY / OPENAI_API_KEY
	BaseURL     string  `yaml:"base_url"`    // custom endpoint for OpenAI-compatible providers
	MaxTokens   int     `yaml:"max_tokens"`  // default: 4096
	Temperature float64 `yaml:"temperature"` // default: 0.0
	CacheSize   int     `yaml:"cache_size"`  // LRU entries; default: 256, 0 = disabled
	CacheTTL    int     `yaml:"cache_ttl"`   // seconds; default: 300
}

// EffectiveSessionsDir returns the sessions directory, defaulting to ~/.vigolium/agent-sessions/.
func (c *AgentConfig) EffectiveSessionsDir() string {
	if c.SessionsDir != "" {
		return ExpandPath(c.SessionsDir)
	}
	return ExpandPath("~/.vigolium/agent-sessions/")
}

// StreamEnabled returns whether real-time output streaming is enabled.
// Defaults to true when Stream is nil (not set in config).
func (c *AgentConfig) StreamEnabled() bool {
	if c.Stream == nil {
		return true
	}
	return *c.Stream
}

// ACPSessionMeta holds agent-specific session metadata passed via the _meta
// extension point in NewSessionRequest. This allows configuring agent behavior
// (system prompts, thinking mode, disallowed tools, etc.) at session creation.
type ACPSessionMeta struct {
	SystemPrompt *ACPSystemPrompt `yaml:"system_prompt,omitempty" json:"systemPrompt,omitempty"`
	ClaudeCode   *ClaudeCodeMeta  `yaml:"claude_code,omitempty" json:"claudeCode,omitempty"`
}

// ACPSystemPrompt configures system prompt modifications for the session.
type ACPSystemPrompt struct {
	Append string `yaml:"append,omitempty" json:"append,omitempty"`
}

// ClaudeCodeMeta holds Claude Code-specific session options.
type ClaudeCodeMeta struct {
	Options *ClaudeCodeOptions `yaml:"options,omitempty" json:"options,omitempty"`
}

// ClaudeCodeOptions configures Claude Code agent behavior.
type ClaudeCodeOptions struct {
	SettingSources    *[]string         `yaml:"setting_sources,omitempty" json:"settingSources,omitempty"`
	PromptSuggestions *bool             `yaml:"prompt_suggestions,omitempty" json:"promptSuggestions,omitempty"`
	Thinking          *ClaudeThinking   `yaml:"thinking,omitempty" json:"thinking,omitempty"`
	Effort            string            `yaml:"effort,omitempty" json:"effort,omitempty"`
	DisallowedTools   []string          `yaml:"disallowed_tools,omitempty" json:"disallowedTools,omitempty"`
	ExtraArgs         map[string]string `yaml:"extra_args,omitempty" json:"extraArgs,omitempty"`
}

// ClaudeThinking configures the thinking mode for Claude Code.
type ClaudeThinking struct {
	Type string `yaml:"type" json:"type"` // "adaptive" or "disabled"
}

// ProviderConfig holds provider-specific options injected at spawn time
// via CLI args or environment variables (not ACP _meta).
// Currently used by OpenCode; ignored for providers that don't support these options.
type ProviderConfig struct {
	Thinking   *ThinkingConfig   `yaml:"thinking,omitempty"`
	Permission *PermissionConfig `yaml:"permission,omitempty"`
	APIURL     string            `yaml:"api_url,omitempty"` // custom OpenAI-compatible base URL
	APIKey     string            `yaml:"api_key,omitempty"` // API key; use ${ENV_VAR} syntax
}

// ThinkingConfig controls extended thinking for providers that support it.
type ThinkingConfig struct {
	Enabled      bool `yaml:"enabled"`
	BudgetTokens int  `yaml:"budget_tokens,omitempty"` // default: 16000
}

// EffectiveBudgetTokens returns the budget, defaulting to 16000.
func (c *ThinkingConfig) EffectiveBudgetTokens() int {
	if c == nil || c.BudgetTokens <= 0 {
		return 16000
	}
	return c.BudgetTokens
}

// PermissionAllow is the value that auto-approves an agent operation.
const PermissionAllow = "allow"

// PermissionConfig controls auto-approval of agent operations.
// Values: PermissionAllow (auto-approve) or "" (prompt user).
type PermissionConfig struct {
	Read  string `yaml:"read,omitempty"`  // file read permission
	Edit  string `yaml:"edit,omitempty"`  // file edit permission
	Write string `yaml:"write,omitempty"` // file write permission
	Bash  string `yaml:"bash,omitempty"`  // shell command permission
}

// DefaultPermissionConfig returns all-allow permissions for autonomous scanning.
func DefaultPermissionConfig() *PermissionConfig {
	return &PermissionConfig{
		Read: PermissionAllow, Edit: PermissionAllow, Write: PermissionAllow, Bash: PermissionAllow,
	}
}

// DefaultProviderConfig returns default provider config for OpenCode-style backends.
func DefaultProviderConfig() *ProviderConfig {
	return &ProviderConfig{
		Thinking:   &ThinkingConfig{BudgetTokens: 16000},
		Permission: DefaultPermissionConfig(),
	}
}

// McpServerConfig defines an MCP server to attach to ACP sessions.
// Stdio mode: set Command (and optionally Args, Env).
// HTTP mode: set URL instead.
type McpServerConfig struct {
	Name    string            `yaml:"name"`
	Command string            `yaml:"command,omitempty"`
	Args    []string          `yaml:"args,omitempty"`
	Env     map[string]string `yaml:"env,omitempty"`
	URL     string            `yaml:"url,omitempty"`
}

// AgentDef defines a single AI agent backend.
type AgentDef struct {
	Command        string            `yaml:"command"`
	Args           []string          `yaml:"args"`
	Description    string            `yaml:"description"`
	Env            map[string]string `yaml:"env,omitempty"`
	Protocol       string            `yaml:"protocol,omitempty"`
	Enable         *bool             `yaml:"enable,omitempty"`
	Model          string            `yaml:"model,omitempty"`           // universal model override
	SessionMeta    *ACPSessionMeta   `yaml:"session_meta,omitempty"`    // ACP _meta passthrough (Claude)
	ProviderConfig *ProviderConfig   `yaml:"provider_config,omitempty"` // spawn-time injection (OpenCode)
	McpServers     []McpServerConfig `yaml:"mcp_servers,omitempty"`     // MCP servers to attach to ACP sessions
}

// IsEnabled returns whether this agent is enabled. Defaults to true when nil.
func (d *AgentDef) IsEnabled() bool {
	return d.Enable == nil || *d.Enable
}

// EffectiveProtocol returns the protocol to use, defaulting to "pipe".
func (d *AgentDef) EffectiveProtocol() string {
	if d.Protocol == "" {
		return "pipe"
	}
	return d.Protocol
}

// Validate checks that AgentConfig fields are valid.
func (c *AgentConfig) Validate() error {
	if c.DefaultAgent == "" {
		return fmt.Errorf("agent.default_agent must not be empty")
	}
	def, ok := c.Backends[c.DefaultAgent]
	if !ok {
		return fmt.Errorf("agent.default_agent %q not found in agents map", c.DefaultAgent)
	}
	if !def.IsEnabled() {
		return fmt.Errorf("agent.default_agent %q is disabled", c.DefaultAgent)
	}
	for name, d := range c.Backends {
		if d.Command == "" {
			return fmt.Errorf("agent.backends[%q].command must not be empty", name)
		}
		switch d.Protocol {
		case "", "pipe", "acp", "sdk", "codex-sdk", "opencode-sdk":
			// valid
		default:
			return fmt.Errorf("agent.backends[%q].protocol %q is invalid (must be \"pipe\", \"acp\", \"sdk\", \"codex-sdk\", or \"opencode-sdk\")", name, d.Protocol)
		}
	}
	if ws := &c.WarmSession; ws.IsEnabled() {
		if ws.IdleTimeout < 0 {
			return fmt.Errorf("agent.warm_session.idle_timeout must be >= 0")
		}
		if ws.MaxSessions < 0 {
			return fmt.Errorf("agent.warm_session.max_sessions must be >= 0")
		}
	}
	return nil
}

// DefaultLLMConfig returns the default LLM config for JS extensions.
func DefaultLLMConfig() LLMConfig {
	return LLMConfig{
		Provider:  "anthropic",
		Model:     "claude-sonnet-4-20250514",
		CacheSize: 256,
		CacheTTL:  300,
		MaxTokens: 4096,
	}
}

// DefaultClaudeSessionMeta returns the default ACP session metadata for Claude Code.
// This configures the agent for autonomous scanner operation: no interactive prompts,
// adaptive thinking, and restricted tool access.
func DefaultClaudeSessionMeta() *ACPSessionMeta {
	noPromptSuggestions := false
	emptySettings := []string{}
	return &ACPSessionMeta{
		ClaudeCode: &ClaudeCodeMeta{
			Options: &ClaudeCodeOptions{
				SettingSources:    &emptySettings,
				PromptSuggestions: &noPromptSuggestions,
				Thinking:          &ClaudeThinking{Type: "adaptive"},
				Effort:            "medium",
				DisallowedTools: []string{
					"AskUserQuestion",
					"EnterWorktree",
					"EnterPlanMode",
					"ExitPlanMode",
					"Bash(curl:*)",
				},
				ExtraArgs: map[string]string{
					"permission-mode":              "bypassPermissions",
					"dangerously-skip-permissions": "",
				},
			},
		},
	}
}

// DefaultAgentConfig returns sensible defaults for all supported agent backends.
func DefaultAgentConfig() *AgentConfig {
	return &AgentConfig{
		DefaultAgent: "claude-sdk",
		Backends: map[string]AgentDef{
			"claude-sdk": {
				Command:     "claude",
				Description: "Anthropic Claude Code (SDK protocol)",
				Protocol:    "sdk",
			},
			"claude": {
				Command:     "npx",
				Args:        []string{"-y", "@zed-industries/claude-agent-acp@latest"},
				Description: "Anthropic Claude Code (ACP)",
				Protocol:    "acp",
				SessionMeta: DefaultClaudeSessionMeta(),
			},
			"claude-cli": {
				Command:     "claude",
				Args:        []string{"--dangerously-skip-permissions", "-p"},
				Description: "Anthropic Claude Code (pipe mode)",
			},
			"codex": {
				Command:     "codex",
				Description: "OpenAI Codex CLI (native JSON-RPC v2)",
				Protocol:    "codex-sdk",
			},
			"codex-acp": {
				Command:     "codex",
				Args:        []string{"app-server"},
				Description: "OpenAI Codex CLI (ACP, legacy)",
				Protocol:    "acp",
			},
			"opencode": {
				Command:        "opencode",
				Args:           []string{"acp"},
				Description:    "OpenCode agent (ACP)",
				Protocol:       "acp",
				ProviderConfig: DefaultProviderConfig(),
			},
			"opencode-native": {
				Command:        "opencode",
				Description:    "OpenCode agent (native SDK)",
				Protocol:       "opencode-sdk",
				ProviderConfig: DefaultProviderConfig(),
			},
			"opencode-cli": {
				Command:     "opencode",
				Args:        []string{"run"},
				Description: "OpenCode agent (pipe mode)",
			},
			"gemini": {
				Command:     "gemini",
				Args:        []string{"--experimental-acp"},
				Description: "Google Gemini CLI (ACP)",
				Protocol:    "acp",
			},
			"gemini-cli": {
				Command:     "gemini",
				Args:        []string{"-p"},
				Description: "Google Gemini CLI (pipe mode)",
			},
			"cursor": {
				Command:     "cursor",
				Args:        []string{"acp"},
				Description: "Cursor AI editor (ACP)",
				Protocol:    "acp",
			},
		},
		TemplatesDir: "~/.vigolium/prompts/",
		SessionsDir:  "~/.vigolium/agent-sessions/",
		LLM:          DefaultLLMConfig(),
	}
}
