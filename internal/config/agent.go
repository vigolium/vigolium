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
	SystemPrompt   *ACPSystemPrompt   `yaml:"system_prompt,omitempty" json:"systemPrompt,omitempty"`
	ClaudeCode     *ClaudeCodeMeta    `yaml:"claude_code,omitempty" json:"claudeCode,omitempty"`
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
	SettingSources    *[]string          `yaml:"setting_sources,omitempty" json:"settingSources,omitempty"`
	PromptSuggestions *bool              `yaml:"prompt_suggestions,omitempty" json:"promptSuggestions,omitempty"`
	Thinking          *ClaudeThinking    `yaml:"thinking,omitempty" json:"thinking,omitempty"`
	Effort            string             `yaml:"effort,omitempty" json:"effort,omitempty"`
	DisallowedTools   []string           `yaml:"disallowed_tools,omitempty" json:"disallowedTools,omitempty"`
	ExtraArgs         map[string]string  `yaml:"extra_args,omitempty" json:"extraArgs,omitempty"`
}

// ClaudeThinking configures the thinking mode for Claude Code.
type ClaudeThinking struct {
	Type string `yaml:"type" json:"type"` // "adaptive" or "disabled"
}

// AgentDef defines a single AI agent backend.
type AgentDef struct {
	Command     string            `yaml:"command"`
	Args        []string          `yaml:"args"`
	Description string            `yaml:"description"`
	Env         map[string]string `yaml:"env,omitempty"`
	Protocol    string            `yaml:"protocol,omitempty"`
	Enable      *bool             `yaml:"enable,omitempty"`
	Model       string            `yaml:"model,omitempty"` // ACP session model override (e.g. "sonnet", "opus")
	SessionMeta *ACPSessionMeta   `yaml:"session_meta,omitempty"`
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
		case "", "pipe", "acp":
			// valid
		default:
			return fmt.Errorf("agent.backends[%q].protocol %q is invalid (must be \"pipe\" or \"acp\")", name, d.Protocol)
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

// DefaultAgentConfig returns sensible defaults with claude, opencode, and gemini.
func DefaultAgentConfig() *AgentConfig {
	return &AgentConfig{
		DefaultAgent: "claude",
		Backends: map[string]AgentDef{
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
				Args:        []string{"app-server"},
				Description: "OpenAI Codex CLI (ACP)",
				Protocol:    "acp",
			},
			"opencode": {
				Command:     "opencode",
				Args:        []string{"acp"},
				Description: "OpenCode agent (ACP)",
				Protocol:    "acp",
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
		},
		TemplatesDir: "~/.vigolium/prompts/",
		SessionsDir:  "~/.vigolium/agent-sessions/",
		LLM:          DefaultLLMConfig(),
	}
}
