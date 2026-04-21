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
	McpEnabled    *bool               `yaml:"mcp_enabled,omitempty"`    // enable MCP server passthrough to agent sessions (default: false)
	McpServers    []McpServerConfig   `yaml:"mcp_servers,omitempty"`    // global MCP servers attached to all agent sessions when mcp_enabled is true
	ContextLimits ContextLimits       `yaml:"context_limits,omitempty"` // limits for DB context enrichment
	Guardrails    AutopilotGuardrails `yaml:"guardrails,omitempty"`     // guardrails for SDK autonomous mode
	Browser       BrowserConfig       `yaml:"browser,omitempty"`        // optional agent-browser integration for browser-based auth flows
	Archon        AuditAgentConfig    `yaml:"archon,omitempty"`         // optional archon-audit integration for background security audits
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

// WarmSessionConfig controls agent subprocess pooling for session reuse.
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

// BrowserConfig controls optional agent-browser integration for browser-based auth flows.
// When enabled, the agent gains access to agent-browser CLI commands via Bash for
// performing browser-based login, cookie capture, and authenticated exploration.
type BrowserConfig struct {
	Enable     *bool  `yaml:"enable,omitempty"`      // default: false
	BinaryPath string `yaml:"binary_path,omitempty"` // path to agent-browser binary (default: "agent-browser" via $PATH)
}

// IsEnabled returns whether agent-browser integration is enabled. Defaults to false.
func (c *BrowserConfig) IsEnabled() bool {
	return c.Enable != nil && *c.Enable
}

// EffectiveBinaryPath returns the binary path, defaulting to "agent-browser".
func (c *BrowserConfig) EffectiveBinaryPath() string {
	if c.BinaryPath != "" {
		return c.BinaryPath
	}
	return "agent-browser"
}

// AuditAgentConfig controls the optional archon-audit integration.
// When enabled and a source path is provided, agent modes (swarm, autopilot) launch
// archon-audit as a background agent process for parallel security auditing.
// The Platform field selects which agent CLI to use: "claude" (default), "codex", or "opencode".
type AuditAgentConfig struct {
	Enable       *bool  `yaml:"enable,omitempty"`        // default: false
	PluginDir    string `yaml:"plugin_dir,omitempty"`    // path to archon-audit harness dir (default: ~/.vigolium/archon-audit/)
	Mode         string `yaml:"mode,omitempty"`          // "deep" (10-phase), "balanced" (6-phase), or "lite" (3-phase); default: "lite"
	Platform     string `yaml:"platform,omitempty"`      // "claude" (default), "codex", or "opencode"
	SyncInterval int    `yaml:"sync_interval,omitempty"` // seconds between state syncs; default: 30
}

// IsEnabled returns whether archon-audit integration is enabled. Defaults to false.
func (c *AuditAgentConfig) IsEnabled() bool {
	return c.Enable != nil && *c.Enable
}

// EffectivePlatform returns the archon platform, defaulting to "claude".
// Accepts "claude", "codex", "opencode".
func (c *AuditAgentConfig) EffectivePlatform() string {
	switch c.Platform {
	case "codex":
		return "codex"
	case "opencode":
		return "opencode"
	default:
		return "claude"
	}
}

// EffectivePluginDir returns the plugin directory, defaulting to ~/.vigolium/archon-audit/.
func (c *AuditAgentConfig) EffectivePluginDir() string {
	if c.PluginDir != "" {
		return ExpandPath(c.PluginDir)
	}
	return ExpandPath("~/.vigolium/archon-audit/")
}

// EffectiveMode returns the archon audit mode, defaulting to "lite".
// Accepts "deep", "balanced", "lite". Maps legacy "full" to "deep" and
// legacy "scan" to "balanced".
func (c *AuditAgentConfig) EffectiveMode() string {
	switch c.Mode {
	case "deep", "full":
		return "deep"
	case "balanced", "scan":
		return "balanced"
	case "mock":
		return "mock"
	default:
		return "lite"
	}
}

// EffectiveSyncInterval returns the sync interval in seconds, defaulting to 30.
func (c *AuditAgentConfig) EffectiveSyncInterval() int {
	if c.SyncInterval > 0 {
		return c.SyncInterval
	}
	return 30
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

// ProviderConfig holds provider-specific options injected at spawn time
// via CLI args or environment variables.
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

// McpServerConfig defines an MCP server to attach to agent sessions.
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
	ProviderConfig *ProviderConfig   `yaml:"provider_config,omitempty"` // spawn-time injection (OpenCode)
	McpServers     []McpServerConfig `yaml:"mcp_servers,omitempty"`     // MCP servers to attach to agent sessions
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

// BackendMeta resolves (protocol, model) for the named backend. Returns
// zero values when name is empty or the backend is not configured — distinct
// from the "pipe" fallback used by engine.ResolveAgentProtocol, because the
// zero string surfaces "unknown" through to nullzero DB columns.
func (c *AgentConfig) BackendMeta(name string) (protocol, model string) {
	if c == nil || name == "" {
		return "", ""
	}
	def, ok := c.Backends[name]
	if !ok {
		return "", ""
	}
	return def.EffectiveProtocol(), def.Model
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
		case "", "pipe", "sdk", "codex-sdk", "opencode-sdk":
			// valid
		default:
			return fmt.Errorf("agent.backends[%q].protocol %q is invalid (must be \"pipe\", \"sdk\", \"codex-sdk\", or \"opencode-sdk\")", name, d.Protocol)
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

// DefaultAgentConfig returns sensible defaults for all supported agent backends.
func DefaultAgentConfig() *AgentConfig {
	return &AgentConfig{
		DefaultAgent: "claude",
		Backends: map[string]AgentDef{
			"claude": {
				Command:     "claude",
				Description: "Anthropic Claude Code (SDK protocol)",
				Protocol:    "sdk",
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
			"opencode": {
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
		},
		TemplatesDir: "~/.vigolium/prompts/",
		SessionsDir:  "~/.vigolium/agent-sessions/",
		LLM:          DefaultLLMConfig(),
	}
}
