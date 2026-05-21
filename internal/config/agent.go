package config

import (
	"fmt"
	"time"
)

// AgentConfig holds AI agent integration settings. Dispatch goes through the
// in-process olium runtime; there are no external subprocess backends.
type AgentConfig struct {
	DefaultAgent  string              `yaml:"default_agent"`
	TemplatesDir  string              `yaml:"templates_dir"`
	SessionsDir   string              `yaml:"sessions_dir"` // directory for agent run session artifacts (default: ~/.vigolium/agent-sessions/)
	Stream        *bool               `yaml:"stream,omitempty"`
	LLM           LLMConfig           `yaml:"llm"`
	ContextLimits ContextLimits       `yaml:"context_limits,omitempty"` // limits for DB context enrichment
	Guardrails    AutopilotGuardrails `yaml:"guardrails,omitempty"`     // guardrails for SDK autonomous mode
	Browser       BrowserConfig       `yaml:"browser,omitempty"`        // optional agent-browser integration for browser-based auth flows
	Audit        AuditAgentConfig    `yaml:"audit,omitempty"`         // optional vigolium-audit integration for background security audits
	Olium         OliumConfig         `yaml:"olium"`                    // native in-process olium agent engine settings
}

// OliumConfig holds settings for the native in-process olium agent engine.
// Used by `vigolium agent olium` and the autopilot olium path. All fields are
// optional — CLI flags override these values at runtime.
//
// Provider naming is vendor-first (anthropic-* / openai-* / google-*) so the
// prefix tells you which credentials to provide:
//   - openai-codex-oauth — uses oauth_cred_path (a JSON file produced by `codex login`)
//   - openai-api-key     — uses llm_api_key (or $OPENAI_API_KEY)
//   - anthropic-api-key  — uses llm_api_key (or $ANTHROPIC_API_KEY)
//   - anthropic-oauth    — uses oauth_token (or $ANTHROPIC_API_KEY); for tokens minted with `claude setup-token`
//   - anthropic-cli      — shells out to the `claude` binary; no key needed here
//   - anthropic-vertex   — uses oauth_cred_path (GCP service-account JSON, or $GOOGLE_APPLICATION_CREDENTIALS),
//     plus google_cloud_project + google_cloud_location; routes claude-* models to publishers/anthropic.
//   - google-vertex      — same GCP creds as anthropic-vertex, but routes gemini-* models to publishers/google.
//   - openai-compatible  — any OpenAI Chat-Completions-compatible endpoint
//     (Ollama, OpenRouter, LM Studio, vLLM, Together, Groq, LocalAI, custom
//     proxies); configured under olium.custom_provider.
//
// YAML tags intentionally omit `omitempty` so that every field surfaces in
// `vigolium config ls olium` (including empty strings rendered as "(empty)"),
// making the available knobs discoverable.
type OliumConfig struct {
	Provider            string               `yaml:"provider"`              // openai-codex-oauth | openai-api-key | anthropic-api-key | anthropic-oauth | anthropic-cli | anthropic-vertex | google-vertex | openai-compatible
	Model               string               `yaml:"model"`                 // default "gpt-5.5"; empty = provider default
	OAuthCredPath       string               `yaml:"oauth_cred_path"`       // OAuth/SA file path (openai-codex-oauth, anthropic-vertex, google-vertex); default ~/.codex/auth.json. For Vertex providers, falls back to $GOOGLE_APPLICATION_CREDENTIALS.
	OAuthToken          string               `yaml:"oauth_token"`           // OAuth bearer token (anthropic-oauth); produced by `claude setup-token`. Supports ${ENV_VAR} expansion, falls back to $ANTHROPIC_API_KEY when empty
	LLMAPIKey           string               `yaml:"llm_api_key"`           // API-key providers (anthropic-api-key, openai-api-key); supports ${ENV_VAR} expansion at load time, falls back to provider-specific env (ANTHROPIC_API_KEY / OPENAI_API_KEY)
	GoogleCloudProject  string               `yaml:"google_cloud_project"`  // GCP project for Vertex providers; $GOOGLE_CLOUD_PROJECT wins, then YAML, then SA file's project_id
	GoogleCloudLocation string               `yaml:"google_cloud_location"` // GCP region for Vertex providers; $GOOGLE_CLOUD_LOCATION wins, then YAML, default us-central1
	ReasoningEffort     string               `yaml:"reasoning_effort"`      // minimal|low|medium|high|xhigh (codex today); default medium
	SystemPrompt        string               `yaml:"system_prompt"`         // empty = built-in olium prompt
	CustomProvider      CustomProviderConfig `yaml:"custom_provider"`       // openai-compatible knobs: base_url / model_id / api_key / extra_headers
	MaxTokens           int                  `yaml:"max_tokens"`            // default 1000000
	Temperature         float64              `yaml:"temperature"`           // default 0.0
	MaxTurns            int                  `yaml:"max_turns"`             // default 32. Applies to short non-autopilot engine uses (swarm phases, source analysis, query). Autopilot ignores this and uses its own pkg/olium/autopilot.DefaultAutopilotMaxTurns (200); override autopilot via --max-commands or the API MaxCommands field.
	CacheSize           int                  `yaml:"cache_size"`            // LRU entries; default 1024, 0 disables
	MaxConcurrent       int                  `yaml:"max_concurrent"`        // global cap on simultaneous in-flight provider calls; default 4, 0 disables (unbounded)
	CallTimeoutSec      int                  `yaml:"call_timeout_sec"`      // per-call deadline in seconds (default 600 = 10m). Negative = inherit only the parent ctx (no enforced timeout).
}

// CustomProviderConfig configures the `openai-compatible` provider — any
// backend that speaks the OpenAI Chat Completions wire format. Examples:
// Ollama (http://localhost:11434/v1), OpenRouter, LM Studio, vLLM, Together,
// Groq, LocalAI, or a custom proxy.
//
// BaseURL is the only required field. APIKey is optional (Ollama, LM Studio,
// and local proxies typically don't need one — when empty, no Authorization
// header is sent). ModelID is a fallback for `model` / --model.
//
// ExtraHeaders are applied to every request after the standard headers, so
// they can override Authorization (handy for backends with non-Bearer auth
// schemes like `Api-Key: <value>`).
type CustomProviderConfig struct {
	BaseURL      string            `yaml:"base_url"`      // full chat-completions URL, e.g. http://localhost:11434/v1/chat/completions (the /v1 root also works — /chat/completions is appended)
	ModelID      string            `yaml:"model_id"`      // default model when olium.model and --model are empty
	APIKey       string            `yaml:"api_key"`       // optional; supports ${ENV_VAR} expansion. Empty = no Authorization header sent
	ExtraHeaders map[string]string `yaml:"extra_headers"` // applied to every request; can override standard headers
}

// EffectiveCallTimeout returns the per-call timeout. 0 → 10m default,
// negative → no enforced timeout (parent ctx only).
func (c *OliumConfig) EffectiveCallTimeout() time.Duration {
	if c.CallTimeoutSec < 0 {
		return 0
	}
	if c.CallTimeoutSec > 0 {
		return time.Duration(c.CallTimeoutSec) * time.Second
	}
	return 10 * time.Minute
}

// EffectiveMaxConcurrent returns MaxConcurrent or the default (4). Use 0 in
// config to explicitly disable the cap (unbounded parallelism — only
// sensible if the upstream provider has no rate limit, which is rare).
func (c *OliumConfig) EffectiveMaxConcurrent() int {
	if c.MaxConcurrent < 0 {
		return 0
	}
	if c.MaxConcurrent > 0 {
		return c.MaxConcurrent
	}
	return 4
}

// ContextLimits controls how much data is pulled from the DB for agent context enrichment.
type ContextLimits struct {
	MaxFindings  int `yaml:"max_findings,omitempty"`   // default: 50
	MaxEndpoints int `yaml:"max_endpoints,omitempty"`  // default: 100
	MaxHighRisk  int `yaml:"max_high_risk,omitempty"`  // default: 20
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

// BrowserConfig controls optional agent-browser integration for browser-based auth flows.
// When enabled, the agent gains access to agent-browser CLI commands via Bash for
// performing browser-based login, cookie capture, and authenticated exploration.
type BrowserConfig struct {
	Enable     *bool  `yaml:"enable,omitempty"`      // default: true (set by DefaultAgentConfig); explicit false disables the integration
	BinaryPath string `yaml:"binary_path,omitempty"` // path to agent-browser binary (default: "agent-browser" via $PATH)
}

// IsEnabled returns whether agent-browser integration is enabled. Defaults to
// true via DefaultAgentConfig; an explicit `enable: false` disables it.
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

// AuditAgentConfig controls the optional vigolium-audit integration.
// When enabled and a source path is provided, agent modes (swarm, autopilot)
// launch the embedded vigolium-audit binary as a background process for parallel
// security auditing.
type AuditAgentConfig struct {
	Enable       *bool  `yaml:"enable,omitempty"`        // default: false
	Mode         string `yaml:"mode,omitempty"`          // "deep" (full audit), "balanced" (6-phase), or "lite" (3-phase); default: "lite"
	SyncInterval int    `yaml:"sync_interval,omitempty"` // seconds between state syncs; default: 30
}

// IsEnabled returns whether vigolium-audit integration is enabled. Defaults to false.
func (c *AuditAgentConfig) IsEnabled() bool {
	return c.Enable != nil && *c.Enable
}

// EffectiveMode returns the audit mode, defaulting to "lite".
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

// AgentProtocolLabel is the protocol string written to AgenticScan rows.
// All agent runs are routed through the in-process olium engine, so this
// is a single constant rather than a backend-keyed lookup.
const AgentProtocolLabel = "olium-engine"

// BackendMeta returns the protocol/model metadata stored on AgenticScan
// rows.
func (c *AgentConfig) BackendMeta() (protocol, model string) {
	if c == nil {
		return "", ""
	}
	return AgentProtocolLabel, c.Olium.Model
}

// Validate checks that AgentConfig fields are valid.
func (c *AgentConfig) Validate() error {
	if c.DefaultAgent == "" {
		return fmt.Errorf("agent.default_agent must not be empty")
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

// DefaultAgentConfig returns sensible defaults for the olium-backed agent
// runtime. Every agent invocation is routed through the in-process engine —
// there is no subprocess backend map anymore.
func DefaultAgentConfig() *AgentConfig {
	return &AgentConfig{
		DefaultAgent: "olium",
		TemplatesDir: "~/.vigolium/prompts/",
		SessionsDir:  "~/.vigolium/agent-sessions/",
		LLM:          DefaultLLMConfig(),
		Olium:        DefaultOliumConfig(),
		Browser:      BrowserConfig{Enable: boolPtr(true)},
	}
}

// DefaultOliumConfig returns sensible defaults for the native in-process
// olium agent engine. Values match the documented defaults in
// public/vigolium-configs.example.yaml so `vigolium config ls olium` surfaces
// them without requiring any user-side yaml.
func DefaultOliumConfig() OliumConfig {
	return OliumConfig{
		Provider:        "openai-compatible",
		Model:           "gemma4:latest",
		OAuthCredPath:   "~/.codex/auth.json",
		ReasoningEffort: "medium",
		MaxTokens:       1000000,
		Temperature:     0.0,
		MaxTurns:        32,
		CacheSize:       1024,
		MaxConcurrent:   4,
		CallTimeoutSec:  600, // 10 minutes per provider call
		CustomProvider: CustomProviderConfig{
			BaseURL: "http://localhost:11434/v1",
			ModelID: "gemma4:latest",
		},
	}
}
