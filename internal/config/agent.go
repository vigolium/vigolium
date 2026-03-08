package config

import "fmt"

// AgentConfig holds AI agent integration settings.
type AgentConfig struct {
	DefaultAgent string              `yaml:"default_agent"`
	Agents       map[string]AgentDef `yaml:"agents"`
	TemplatesDir string              `yaml:"templates_dir"`
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

// StreamEnabled returns whether real-time output streaming is enabled.
// Defaults to true when Stream is nil (not set in config).
func (c *AgentConfig) StreamEnabled() bool {
	if c.Stream == nil {
		return true
	}
	return *c.Stream
}

// AgentDef defines a single AI agent backend.
type AgentDef struct {
	Command     string            `yaml:"command"`
	Args        []string          `yaml:"args"`
	Description string            `yaml:"description"`
	Env         map[string]string `yaml:"env,omitempty"`
	Protocol    string            `yaml:"protocol,omitempty"`
	Enable      *bool             `yaml:"enable,omitempty"`
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
	def, ok := c.Agents[c.DefaultAgent]
	if !ok {
		return fmt.Errorf("agent.default_agent %q not found in agents map", c.DefaultAgent)
	}
	if !def.IsEnabled() {
		return fmt.Errorf("agent.default_agent %q is disabled", c.DefaultAgent)
	}
	for name, d := range c.Agents {
		if d.Command == "" {
			return fmt.Errorf("agent.agents[%q].command must not be empty", name)
		}
		switch d.Protocol {
		case "", "pipe", "acp":
			// valid
		default:
			return fmt.Errorf("agent.agents[%q].protocol %q is invalid (must be \"pipe\" or \"acp\")", name, d.Protocol)
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

// DefaultAgentConfig returns sensible defaults with claude, opencode, and gemini.
func DefaultAgentConfig() *AgentConfig {
	return &AgentConfig{
		DefaultAgent: "claude",
		Agents: map[string]AgentDef{
			"claude": {
				Command:     "npx",
				Args:        []string{"-y", "@zed-industries/claude-code-acp@latest"},
				Description: "Anthropic Claude Code (ACP)",
				Protocol:    "acp",
			},
			"claude-cli": {
				Command:     "claude",
				Args:        []string{"--dangerously-skip-permissions", "-p"},
				Description: "Anthropic Claude Code (pipe mode)",
			},
			"codex": {
				Command:     "npx",
				Args:        []string{"-y", "@zed-industries/codex-acp"},
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
		LLM:          DefaultLLMConfig(),
	}
}
