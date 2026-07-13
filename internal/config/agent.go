package config

import (
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// AgentConfig holds AI agent integration settings. Dispatch goes through the
// in-process olium runtime; there are no external subprocess backends.
type AgentConfig struct {
	DefaultAgent  string           `yaml:"default_agent"`
	TemplatesDir  string           `yaml:"templates_dir"`
	SessionsDir   string           `yaml:"sessions_dir"` // directory for agent run session artifacts (default: ~/.vigolium/agent-sessions/)
	Stream        *bool            `yaml:"stream,omitempty"`
	LLM           LLMConfig        `yaml:"llm"`
	ContextLimits ContextLimits    `yaml:"context_limits,omitempty"` // limits for DB context enrichment
	Browser       BrowserConfig    `yaml:"browser,omitempty"`        // optional agent-browser integration for browser-based auth flows
	Audit         AuditAgentConfig `yaml:"audit,omitempty"`          // optional vigolium-audit integration for background security audits
	Olium         OliumConfig      `yaml:"olium"`                    // native in-process olium agent engine settings
}

// OliumConfig holds settings for the native in-process olium agent engine.
// Used by `vigolium agent olium` and the autopilot olium path. All fields are
// optional — CLI flags override these values at runtime.
//
// Provider naming is vendor-first (anthropic-* / openai-* / google-*) so the
// prefix tells you which credentials to provide:
//   - openai-codex-oauth — uses oauth_cred_path (a JSON file produced by `codex login`)
//   - openai-api-key     — uses llm_api_key (or $OPENAI_API_KEY); OpenAI Chat Completions API
//   - openai-responses   — uses llm_api_key (or $OPENAI_API_KEY); public OpenAI Responses API (/v1/responses)
//   - anthropic-api-key  — uses llm_api_key (or $ANTHROPIC_API_KEY)
//   - anthropic-oauth    — uses oauth_token (or $ANTHROPIC_API_KEY); for tokens minted with `claude setup-token`
//   - anthropic-cli      — shells out to the `claude` binary; no key needed here
//     (alias: anthropic-claude-cli)
//   - anthropic-claude-sdk-bridge — drives Claude Code through the Agent SDK via
//     the `vigolium-audit bridge` sidecar (bridge_binary; empty = embedded blob,
//     then PATH). No key needed — uses ambient Claude Code subscription auth;
//     an explicit llm_api_key / oauth_token is forwarded when set.
//   - anthropic-vertex   — uses oauth_cred_path (GCP service-account JSON, or $GOOGLE_APPLICATION_CREDENTIALS),
//     plus google_cloud_project + google_cloud_location; routes claude-* models to publishers/anthropic.
//   - google-vertex      — same GCP creds as anthropic-vertex, but routes gemini-* models to publishers/google.
//   - openai-compatible  — any OpenAI Chat-Completions-compatible endpoint
//     (Ollama, OpenRouter, LM Studio, vLLM, Together, Groq, LocalAI, custom
//     proxies); configured under olium.custom_provider.
//   - anthropic-compatible — any Anthropic Messages-compatible endpoint
//     (a self-hosted gateway or Messages-format proxy) at a custom base_url;
//     configured under olium.custom_provider (base_url / model_id / api_key /
//     extra_headers).
//
// YAML tags intentionally omit `omitempty` so that every field surfaces in
// `vigolium config ls olium` (including empty strings rendered as "(empty)"),
// making the available knobs discoverable.
type OliumConfig struct {
	Provider            string               `yaml:"provider"`              // openai-codex-oauth | openai-api-key | openai-responses | anthropic-api-key | anthropic-oauth | anthropic-cli | anthropic-vertex | google-vertex | openai-compatible | anthropic-compatible
	Model               string               `yaml:"model"`                 // empty (default) = provider default; for openai-compatible / anthropic-compatible this falls back to custom_provider.model_id
	OAuthCredPath       string               `yaml:"oauth_cred_path"`       // OAuth/SA file path (openai-codex-oauth, anthropic-vertex, google-vertex); default ~/.codex/auth.json. For Vertex providers, falls back to $GOOGLE_APPLICATION_CREDENTIALS.
	BridgeBinary        string               `yaml:"bridge_binary"`         // path to the `vigolium-audit` binary hosting the SDK bridge (anthropic-claude-sdk-bridge); empty = embedded blob, then PATH
	OAuthToken          string               `yaml:"oauth_token"`           // OAuth bearer token (anthropic-oauth); produced by `claude setup-token`. Supports ${ENV_VAR} expansion, falls back to $ANTHROPIC_API_KEY when empty
	LLMAPIKey           string               `yaml:"llm_api_key"`           // API-key providers (anthropic-api-key, openai-api-key, openai-responses); supports ${ENV_VAR} expansion at load time, falls back to provider-specific env (ANTHROPIC_API_KEY / OPENAI_API_KEY)
	GoogleCloudProject  string               `yaml:"google_cloud_project"`  // GCP project for Vertex providers; $GOOGLE_CLOUD_PROJECT wins, then YAML, then SA file's project_id
	GoogleCloudLocation string               `yaml:"google_cloud_location"` // GCP region for Vertex providers; $GOOGLE_CLOUD_LOCATION wins, then YAML, default us-central1
	ReasoningEffort     string               `yaml:"reasoning_effort"`      // minimal|low|medium|high|xhigh (codex today); default medium
	SystemPrompt        string               `yaml:"system_prompt"`         // empty = built-in olium prompt
	CustomProvider      CustomProviderConfig `yaml:"custom_provider"`       // openai-compatible / anthropic-compatible knobs: base_url / model_id / api_key / extra_headers
	MaxTokens           int                  `yaml:"max_tokens"`            // default 1000000
	Temperature         float64              `yaml:"temperature"`           // default 0.0
	MaxTurns            int                  `yaml:"max_turns"`             // default 32. Applies to short non-autopilot engine uses (swarm phases, source analysis, query). Autopilot ignores this and uses its own pkg/olium/autopilot.DefaultAutopilotMaxTurns (200); override autopilot via --max-commands or the API MaxCommands field.
	CacheSize           int                  `yaml:"cache_size"`            // LRU entries; default 1024, 0 disables
	MaxConcurrent       int                  `yaml:"max_concurrent"`        // global cap on simultaneous in-flight provider calls; default 4, 0 disables (unbounded)
	CallTimeoutSec      int                  `yaml:"call_timeout_sec"`      // per-call deadline in seconds (default 600 = 10m). Negative = inherit only the parent ctx (no enforced timeout).
	AlwaysOnSkills      []string             `yaml:"always_on_skills"`      // skills always loaded regardless of planner selection (autopilot/swarm); empty = built-in default [triage-finding, write-jsext]

	// AutopilotMode selects the durable-autopilot behavior:
	//   - legacy  (default) — current behavior, byte-for-byte unchanged: no
	//     section rotation, report_finding writes findings directly, the new
	//     agent_sections / agent_finding_candidates tables are never touched.
	//   - shadow  — enable bounded operator sections with context rotation AND
	//     mirror every report_finding call to a candidate row, so the fresh-
	//     context verifier can grade them without changing the direct-finding
	//     behavior (findings still land immediately; promoted candidates are
	//     tagged distinctly for FP-rate comparison).
	//   - enforced — enable rotation and route findings through the
	//     candidate → verify → promote pipeline (report_finding is replaced by
	//     propose_candidate; only verified candidates become findings).
	// Empty or any unrecognized value resolves to "legacy" via EffectiveAutopilotMode.
	AutopilotMode string `yaml:"autopilot_mode"`
}

// Autopilot mode constants for OliumConfig.AutopilotMode. Exported so callers
// (CLI/pipeline/autopilot) branch on the same canonical strings.
const (
	AutopilotModeLegacy   = "legacy"
	AutopilotModeShadow   = "shadow"
	AutopilotModeEnforced = "enforced"
)

// NormalizeAutopilotMode resolves an arbitrary autopilot-mode string to one of
// the canonical values, defaulting to "legacy" for empty/unknown input. The
// single source of truth consulted by both EffectiveAutopilotMode and the
// autopilot runtime, so an invalid value can never silently enable rotation /
// verification.
func NormalizeAutopilotMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case AutopilotModeShadow:
		return AutopilotModeShadow
	case AutopilotModeEnforced:
		return AutopilotModeEnforced
	default:
		return AutopilotModeLegacy
	}
}

// EffectiveAutopilotMode returns the resolved durable-autopilot mode, defaulting
// to "legacy" when unset or set to an unrecognized value.
func (c *OliumConfig) EffectiveAutopilotMode() string {
	if c == nil {
		return AutopilotModeLegacy
	}
	return NormalizeAutopilotMode(c.AutopilotMode)
}

// DefaultAlwaysOnSkills are the general-purpose skills kept available in
// every planner-filtered agentic run, even when the planner doesn't pick
// them. They aren't tied to a single vulnerability class, so filtering them
// out would only ever hurt.
var DefaultAlwaysOnSkills = []string{"triage-finding", "write-jsext"}

// EffectiveAlwaysOnSkills returns the configured always-on skill names, or the
// built-in default when unset. A configured empty list (explicit `[]`) is
// indistinguishable from unset in YAML, so the default applies — to truly opt
// out of always-on skills, use --no-skill-filter or rely on planner picks.
func (c *OliumConfig) EffectiveAlwaysOnSkills() []string {
	if c == nil || len(c.AlwaysOnSkills) == 0 {
		return DefaultAlwaysOnSkills
	}
	return c.AlwaysOnSkills
}

// CustomProviderConfig configures the custom-base-url providers. For
// `openai-compatible` it fronts any OpenAI Chat Completions endpoint — Ollama
// (http://localhost:11434/v1), OpenRouter, LM Studio, vLLM, Together, Groq,
// LocalAI, or a custom proxy. For `anthropic-compatible` it fronts any
// Anthropic Messages (/v1/messages) endpoint — a self-hosted gateway or
// Messages-format proxy. (ExtraBody / provider_routing apply to
// openai-compatible only.)
//
// BaseURL is the only required field. APIKey is optional (Ollama, LM Studio,
// and local proxies typically don't need one — when empty, no Authorization
// header is sent). ModelID is a fallback for `model` / --model.
//
// ExtraHeaders are applied to every request after the standard headers, so
// they can override Authorization (handy for backends with non-Bearer auth
// schemes like `Api-Key: <value>`). Each entry is a curl-style "Key: Value"
// string. Use the CLI `.add` / `.clear` operations to mutate the list, e.g.
// `vigolium config set agent.olium.custom_provider.extra_headers.add "X-Foo: bar"`.
type CustomProviderConfig struct {
	BaseURL      string          `yaml:"base_url"`      // full chat-completions URL, e.g. http://localhost:11434/v1/chat/completions (the /v1 root also works — /chat/completions is appended)
	ModelID      string          `yaml:"model_id"`      // default model when olium.model and --model are empty
	APIKey       string          `yaml:"api_key"`       // optional; supports ${ENV_VAR} expansion. Empty = no Authorization header sent
	ExtraHeaders ExtraHeaderList `yaml:"extra_headers"` // curl-style "Key: Value" entries applied to every request; can override standard headers

	// ProviderRouting is the typed convenience knob for OpenRouter's provider
	// routing object. Plays cleanly with `vigolium config set
	// ...provider_routing.<field>` because every field exists as a leaf in
	// the marshaled YAML. Merged into the request body as the "provider"
	// key. See ProviderRoutingConfig for the field list. Use ExtraBody for
	// non-OpenRouter backends or for OpenRouter fields not covered here
	// (max_price, preferred_min_throughput, preferred_max_latency).
	ProviderRouting ProviderRoutingConfig `yaml:"provider_routing"`

	// ExtraBody is a generic JSON-body passthrough merged into every
	// openai-compatible request. The canonical use case is OpenRouter
	// extensions the typed knob doesn't cover, and other backends'
	// body-level options (vLLM, Together's "transforms", etc.). Reserved
	// top-level keys (model, messages, tools, stream, stream_options) are
	// rejected at request time. Setting both this and ProviderRouting with
	// a `provider` key here raises a conflict error — use one or the other.
	ExtraBody map[string]any `yaml:"extra_body,omitempty"`
}

// ProviderRoutingConfig is the typed knob for OpenRouter's provider routing
// object — the JSON `provider` field documented at
// https://openrouter.ai/docs/features/provider-routing.
//
// YAML tags deliberately omit `omitempty` so every field exists as a leaf in
// the marshaled config, which is what `vigolium config set
// ...provider_routing.<field>` needs to navigate to. The trade-off is that
// saved configs show unset fields as YAML nulls; the runtime emit path
// (ProviderRoutingMap) drops those, so the wire body stays clean.
//
// Pointer types are used for bools where false != unset (OpenRouter's
// default for `allow_fallbacks` is true; a user setting `false` alone has
// a real semantic intent).
//
// Fields not covered here (max_price, preferred_min_throughput,
// preferred_max_latency) are intentionally deferred; use
// custom_provider.extra_body as the escape hatch.
type ProviderRoutingConfig struct {
	Order             []string `yaml:"order"`              // upstream provider slugs in preference order
	Only              []string `yaml:"only"`               // restrict to these provider slugs
	Ignore            []string `yaml:"ignore"`             // exclude these provider slugs
	AllowFallbacks    *bool    `yaml:"allow_fallbacks"`    // default unset (OpenRouter defaults to true); false = strict
	Sort              string   `yaml:"sort"`               // "price" | "throughput" | "latency"
	Quantizations     []string `yaml:"quantizations"`      // e.g. ["fp8", "int8"]
	DataCollection    string   `yaml:"data_collection"`    // "allow" | "deny"
	RequireParameters *bool    `yaml:"require_parameters"` // only providers that honour every request parameter
	ZDR               *bool    `yaml:"zdr"`                // Zero Data Retention only
}

// ProviderRoutingMap returns the routing config as a map[string]any with
// only the fields the user actually set. Returns nil if every field is at
// its zero value, signalling "no routing preferences — let OpenRouter
// decide". Slices are emitted only when non-empty.
func (c *ProviderRoutingConfig) ProviderRoutingMap() map[string]any {
	out := map[string]any{}
	if len(c.Order) > 0 {
		out["order"] = c.Order
	}
	if len(c.Only) > 0 {
		out["only"] = c.Only
	}
	if len(c.Ignore) > 0 {
		out["ignore"] = c.Ignore
	}
	if c.AllowFallbacks != nil {
		out["allow_fallbacks"] = *c.AllowFallbacks
	}
	if c.Sort != "" {
		out["sort"] = c.Sort
	}
	if len(c.Quantizations) > 0 {
		out["quantizations"] = c.Quantizations
	}
	if c.DataCollection != "" {
		out["data_collection"] = c.DataCollection
	}
	if c.RequireParameters != nil {
		out["require_parameters"] = *c.RequireParameters
	}
	if c.ZDR != nil {
		out["zdr"] = *c.ZDR
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ExtraHeaderList is a list of curl-style "Key: Value" header strings. It
// implements UnmarshalYAML to tolerate a small set of legacy/empty shapes
// (`null`, `{}`) so existing configs that shipped with the empty-map default
// keep loading. A non-empty YAML map is rejected with a clear error to push
// users toward the list form.
type ExtraHeaderList []string

// UnmarshalYAML accepts a list of strings, null, or an empty mapping. A
// non-empty mapping is rejected.
func (l *ExtraHeaderList) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case 0, yaml.ScalarNode:
		// null / empty scalar → leave as nil
		if node.Tag == "!!null" || node.Value == "" {
			*l = nil
			return nil
		}
		return fmt.Errorf("extra_headers: expected list of \"Key: Value\" strings, got scalar %q", node.Value)
	case yaml.SequenceNode:
		out := make([]string, 0, len(node.Content))
		for _, item := range node.Content {
			var s string
			if err := item.Decode(&s); err != nil {
				return fmt.Errorf("extra_headers: list entries must be strings: %w", err)
			}
			out = append(out, s)
		}
		*l = out
		return nil
	case yaml.MappingNode:
		if len(node.Content) == 0 {
			*l = nil
			return nil
		}
		return fmt.Errorf("extra_headers: map form is no longer supported — use a list of \"Key: Value\" strings (see vigolium config set ... extra_headers.add)")
	default:
		return fmt.Errorf("extra_headers: unsupported YAML node kind %d", node.Kind)
	}
}

// ExtraHeadersMap parses the curl-style entries into a header map suitable
// for http.Header.Set. Malformed entries (missing ":") are logged at warn
// level and skipped. On duplicate keys, the last entry wins — mirroring
// http.Header.Set semantics.
func (c *CustomProviderConfig) ExtraHeadersMap() map[string]string {
	if len(c.ExtraHeaders) == 0 {
		return nil
	}
	out := make(map[string]string, len(c.ExtraHeaders))
	for _, raw := range c.ExtraHeaders {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		name, value, ok := strings.Cut(entry, ":")
		if !ok {
			zap.L().Warn("olium/custom_provider: skipping malformed extra_headers entry (expected \"Key: Value\")", zap.String("entry", raw))
			continue
		}
		name = strings.TrimSpace(name)
		if name == "" {
			zap.L().Warn("olium/custom_provider: skipping extra_headers entry with empty header name", zap.String("entry", raw))
			continue
		}
		out[name] = strings.TrimSpace(value)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ExtraBodyMap returns the extra_body map, or nil if unset. Provided so
// callers stay symmetric with ExtraHeadersMap and so future validation
// (e.g. ${ENV_VAR} expansion) has a single hook point.
func (c *CustomProviderConfig) ExtraBodyMap() map[string]any {
	if len(c.ExtraBody) == 0 {
		return nil
	}
	return c.ExtraBody
}

// EffectiveExtraBody combines the typed ProviderRouting knob with the
// generic ExtraBody passthrough into a single body-extension map. The
// typed knob becomes the "provider" key. Returns nil if neither field is
// set. Returns an error if both set a "provider" key (the operator must
// pick one path — typed is recommended).
func (c *CustomProviderConfig) EffectiveExtraBody() (map[string]any, error) {
	routing := c.ProviderRouting.ProviderRoutingMap()
	extra := c.ExtraBodyMap()
	if routing == nil && extra == nil {
		return nil, nil
	}
	if routing != nil {
		if extra != nil {
			if _, conflict := extra["provider"]; conflict {
				return nil, fmt.Errorf("custom_provider: both provider_routing and extra_body.provider are set; remove one (provider_routing is the recommended typed form)")
			}
		}
	}
	out := make(map[string]any, len(extra)+1)
	for k, v := range extra {
		out[k] = v
	}
	if routing != nil {
		out["provider"] = routing
	}
	return out, nil
}

// DisplayProvider returns the olium provider name for operator-facing output
// (startup banner, hot-reload log), substituting the implicit default when
// unset. Display-only: actual per-provider runtime resolution lives in the
// olium runner, so don't use this to drive provider selection.
func (c *OliumConfig) DisplayProvider() string {
	if c == nil || c.Provider == "" {
		return "openai-codex-oauth"
	}
	return c.Provider
}

// DisplayModel returns the olium model for operator-facing output, or a
// "(provider default)" placeholder when unset (the concrete model is chosen
// per-provider at runtime). Pairs with DisplayProvider.
func (c *OliumConfig) DisplayModel() string {
	if c == nil || c.Model == "" {
		return "(provider default)"
	}
	return c.Model
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
	Mode         string `yaml:"mode,omitempty"`          // "deep" (full audit), "balanced" (6-phase), or "lite" (3-phase); default: "balanced"
	SyncInterval int    `yaml:"sync_interval,omitempty"` // seconds between state syncs; default: 30

	// DefaultAgent pins the coding agent vigolium-audit drives — "claude"
	// or "codex" — without changing agent.olium.provider (which still
	// supplies the BYOK auth). It is a pure agent selector with the same
	// semantics as the `--agent` flag, layered on top of the
	// provider-derived agent. Empty (the default) inherits the agent
	// implied by agent.olium.provider (anthropic-* → claude, openai-* →
	// codex), preserving pre-existing behavior. Per-run --agent / --provider
	// (CLI) and the request `agent` field (REST) both outrank this.
	//
	// Note: because auth still follows the provider, setting this to an
	// agent that doesn't match the provider's credential shape (e.g.
	// default_agent=codex with an anthropic-* provider) forwards
	// mismatched creds — pair it with a provider whose auth matches, or
	// pass per-run --oauth-cred-file / --api-key.
	DefaultAgent string `yaml:"default_agent,omitempty"` // "" (inherit provider) | claude | codex
}

// IsEnabled returns whether vigolium-audit integration is enabled. Defaults to false.
func (c *AuditAgentConfig) IsEnabled() bool {
	return c.Enable != nil && *c.Enable
}

// EffectiveMode returns the audit mode, defaulting to "balanced".
// Accepts "deep", "balanced", "lite". Maps legacy "full" to "deep" and
// legacy "scan" to "balanced". An empty or unrecognized value resolves to
// "balanced" — the recommended default, matching `vigolium agent audit`'s
// own --intensity default.
func (c *AuditAgentConfig) EffectiveMode() string {
	switch c.Mode {
	case "deep", "full":
		return "deep"
	case "lite":
		return "lite"
	case "mock":
		return "mock"
	default:
		// "balanced", "scan" (legacy alias), "" (unset), and any
		// unrecognized value all resolve to the balanced default.
		return "balanced"
	}
}

// EffectiveSyncInterval returns the sync interval in seconds, defaulting to 30.
func (c *AuditAgentConfig) EffectiveSyncInterval() int {
	if c.SyncInterval > 0 {
		return c.SyncInterval
	}
	return 30
}

// LLMConfig is the legacy direct-LLM config block (agent.llm). It is retained
// for backward compatibility only and is no longer consulted: the JS extension
// agent API (vigolium.agent.*) now dispatches through the in-process olium
// engine configured under agent.olium. Configure the provider there instead.
//
// Deprecated: configure agent.olium; this block is ignored.
type LLMConfig struct {
	Provider    string  `yaml:"provider"`    // "anthropic" (default) or "openai"
	Model       string  `yaml:"model"`       // e.g. "claude-sonnet-4-6", "gpt-4o"
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
		Model:     "claude-sonnet-4-6",
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
		Provider: "openai-compatible",
		// Model intentionally left empty: "" means "provider default", which
		// for openai-compatible falls back to custom_provider.model_id (see
		// resolveProvider in pkg/olium/runner.go). Shipping a non-empty default
		// here would shadow custom_provider.model_id and silently override it.
		Model:           "",
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
