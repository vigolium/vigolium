// Package olium is the root of the olium agent runtime. It wires providers,
// tools, and the engine into TUI / headless entrypoints.
package olium

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	oliumresources "github.com/vigolium/vigolium/internal/resources/olium"
	"github.com/vigolium/vigolium/pkg/olium/engine"
	"github.com/vigolium/vigolium/pkg/olium/provider"
	"github.com/vigolium/vigolium/pkg/olium/sessionlog"
	"github.com/vigolium/vigolium/pkg/olium/skill"
	"github.com/vigolium/vigolium/pkg/olium/tool"
	"github.com/vigolium/vigolium/pkg/olium/tui"
)

// LoadSkillsFor loads skills for a given mode. This is the single entry
// point every olium caller should use (TUI, headless, autopilot, swarm).
//
//   - includeUser=false for generic `vigolium agent olium` (chat/dev): only
//     .agents/skills, .claude/skills, and embedded built-ins.
//   - includeUser=true  for autopilot/swarm: adds ~/.vigolium/skills/ so
//     security-scan-specific skills are available without polluting chat.
//
// Warnings are returned but non-fatal — bad skills are skipped.
func LoadSkillsFor(includeUser bool) (*skill.Registry, []string) {
	reg, warnings, err := skill.LoadFromEmbed(oliumresources.SkillsFS, oliumresources.SkillsPrefix, includeUser)
	if err != nil {
		// LoadFromEmbed doesn't currently return errors on its own, but
		// defend against future changes — skills are non-essential.
		return nil, append(warnings, fmt.Sprintf("skill load: %v", err))
	}
	return reg, warnings
}

// DefaultModel is used when the user doesn't pass --model. Provider-specific
// defaults override this in resolveProvider.
const DefaultModel = "gpt-5.5"

// SetDebug toggles provider-level tracing (full request payload + raw SSE
// events to stderr, credentials scrubbed) for every olium backend. The CLI
// wires the global --debug flag to this so the documented flag actually traces
// the in-process agent — the engine itself emits no zap logs, so plain --debug
// would otherwise show nothing for `vigolium ol`. Also honored via the
// VIGOLIUM_OLIUM_DEBUG env var at startup.
func SetDebug(on bool) { provider.SetDebug(on) }

// DefaultSystemPrompt is the baseline prompt when the user doesn't supply one.
const DefaultSystemPrompt = `You are olium, a security-focused coding agent running inside the vigolium scanner.
You have access to tools: bash, read_file, write_file, edit_file, ls, grep, glob, web_fetch.
Use them freely to explore code, run commands, and make changes. Be concise.`

// Options configures a `vigolium agent olium` run.
//
// Field naming spells the auth mechanism so it's obvious which fields apply
// to which provider:
//   - Provider="openai-codex-oauth" → OAuthCredPath
//   - Provider="anthropic-api-key"  → LLMAPIKey (or $ANTHROPIC_API_KEY)
//   - Provider="anthropic-oauth"    → OAuthToken  (or $ANTHROPIC_API_KEY); produced by `claude setup-token`
//   - Provider="openai-api-key"     → LLMAPIKey (or $OPENAI_API_KEY)
//   - Provider="anthropic-cli"      → ClaudeBinary
//   - Provider="anthropic-vertex"   → OAuthCredPath (SA JSON, or $GOOGLE_APPLICATION_CREDENTIALS),
//     plus GoogleCloudProject and GoogleCloudLocation; routes claude-* models.
//   - Provider="google-vertex"      → OAuthCredPath (SA JSON, or $GOOGLE_APPLICATION_CREDENTIALS),
//     plus GoogleCloudProject and GoogleCloudLocation; routes gemini-* models.
//   - Provider="openai-compatible"  → CustomBaseURL (required), CustomAPIKey
//     (optional), CustomModelID (fallback for Model), CustomExtraHeaders,
//     CustomExtraBody.
//     Covers Ollama / OpenRouter / LM Studio / vLLM / Together / Groq /
//     LocalAI / custom proxies.
type Options struct {
	// Provider selection. Empty = auto-detect (defaults to openai-codex-oauth).
	Provider string

	OAuthCredPath string // OAuth/SA credential file path (openai-codex-oauth, anthropic-vertex, google-vertex)
	OAuthToken    string // Anthropic OAuth bearer token (anthropic-oauth); explicit override, else falls back to $ANTHROPIC_API_KEY
	LLMAPIKey     string // API key for key-based providers; explicit override, else falls back to provider-specific env var
	Model         string
	SystemPrompt  string
	ClaudeBinary  string // path to `claude` executable for anthropic-cli provider

	// Vertex tuning (anthropic-vertex, google-vertex). ENV (GOOGLE_CLOUD_PROJECT
	// / GOOGLE_CLOUD_LOCATION) takes precedence at provider-construction time;
	// YAML/CLI values fill in when the env var is unset.
	GoogleCloudProject  string
	GoogleCloudLocation string

	// openai-compatible knobs (Ollama / OpenRouter / LM Studio / vLLM / etc.).
	// Mirrors agent.olium.custom_provider in YAML. CustomBaseURL is required
	// when Provider=="openai-compatible"; the rest are optional.
	CustomBaseURL      string
	CustomModelID      string
	CustomAPIKey       string
	CustomExtraHeaders map[string]string
	// CustomExtraBody is a generic JSON-body extension merged into every
	// outgoing request. Vigolium populates it from
	// custom_provider.EffectiveExtraBody() which combines the typed
	// provider_routing knob with the raw extra_body passthrough. Reserved
	// top-level keys (model, messages, tools, stream, stream_options) trigger
	// a request-time error.
	CustomExtraBody map[string]any

	// ReasoningEffort is shown in the TUI banner alongside the model id.
	// Plumbed from agent.olium.reasoning_effort. Display-only today; the
	// codex provider already defaults to "medium" when unset on the request.
	ReasoningEffort string

	// Version is the vigolium build version, displayed in the TUI banner
	// header (e.g. "Olium agent (v0.1.0-alpha)"). Optional — empty hides the
	// suffix.
	Version string

	// InitialPrompt seeds the TUI with a first message, auto-sent on
	// startup. Ignored in RunHeadless (which uses HeadlessOptions.Prompt).
	InitialPrompt string

	// SessionDir, when non-empty, is an existing directory into which the
	// run writes a Pi-style JSONL session transcript (transcript.jsonl) for
	// debugging. The CLI resolves it under agent.sessions_dir; library
	// callers may leave it empty to disable recording entirely. The runner
	// only writes into the directory — it does not create the per-run dir
	// (that's the CLI's job, mirroring the agentic-scan session layout).
	SessionDir string
}

// newSessionRecorder builds a Pi-style transcript recorder for an interactive
// or headless run when opts.SessionDir is set. It returns a true nil
// interface (never a typed nil) when recording is disabled or construction
// fails, so assigning the result to engine.Config.Recorder is always safe — a
// best-effort debug transcript must never block launching the agent.
func newSessionRecorder(opts Options, providerName, model string) engine.EventRecorder {
	if strings.TrimSpace(opts.SessionDir) == "" {
		return nil
	}
	cwd, _ := os.Getwd()
	rec, err := sessionlog.New(filepath.Join(opts.SessionDir, sessionlog.Filename), sessionlog.Meta{
		// Align the session id with the run dir name (matching autopilot) so
		// the transcript's id ties back to its on-disk location.
		SessionID:     filepath.Base(opts.SessionDir),
		Provider:      providerName,
		Model:         model,
		ThinkingLevel: opts.ReasoningEffort,
		Cwd:           cwd,
	})
	if err != nil {
		return nil
	}
	return rec
}

// RunTUI launches the interactive TUI.
func RunTUI(opts Options) error {
	prov, providerName, resolvedModel, err := resolveProvider(opts)
	if err != nil {
		return err
	}
	if opts.SystemPrompt == "" {
		opts.SystemPrompt = DefaultSystemPrompt
	}

	// yolo by default — nothing prompts; catastrophic patterns hard-reject
	// inside the bash tool itself.
	reg := tool.NewRegistry()
	tool.RegisterBuiltins(reg, nil)

	// Skills for interactive mode: project-local + embedded + user-scope
	// (~/.vigolium/skills, where the materialized + operator-authored skills
	// live). Surfaced so the operator can /skill:<name> them interactively.
	skills, _ := LoadSkillsFor(true)
	if skills != nil && skills.Len() > 0 {
		reg.Register(skill.NewLoadTool(skills))
		fmt.Fprintf(os.Stderr, "Loaded %d skills (invoke with /skill:<name>)\n", skills.Len())
	}

	eng := engine.New(engine.Config{
		Provider: prov,
		Tools:    reg,
		Skills:   skills,
		Model:    resolvedModel,
		System:   opts.SystemPrompt,
		Recorder: newSessionRecorder(opts, providerName, resolvedModel),
	})
	// Flush + close the transcript when the interactive session ends. No-op
	// when no recorder was attached.
	defer func() { _ = eng.CloseRecorder() }()

	return tui.Run(tui.Config{
		Engine:        eng,
		ProviderName:  providerName,
		Model:         resolvedModel,
		Effort:        opts.ReasoningEffort,
		Version:       opts.Version,
		Skills:        skills,
		InitialPrompt: opts.InitialPrompt,
	})
}

// buildHeadlessEngine is used by headless.go; shared so we only have one
// place that constructs the provider + registry + engine triple.
func buildHeadlessEngine(opts Options) (*engine.Engine, string, string, error) {
	prov, name, model, err := resolveProvider(opts)
	if err != nil {
		return nil, "", "", err
	}
	if opts.SystemPrompt == "" {
		opts.SystemPrompt = DefaultSystemPrompt
	}

	reg := tool.NewRegistry()
	tool.RegisterBuiltins(reg, nil)

	// Headless mode is used for smoke tests and scripted invocations —
	// same skill scope as the interactive TUI (no ~/.vigolium/skills).
	skills, _ := LoadSkillsFor(false)
	if skills != nil && skills.Len() > 0 {
		reg.Register(skill.NewLoadTool(skills))
	}

	return engine.New(engine.Config{
		Provider: prov,
		Tools:    reg,
		Skills:   skills,
		Model:    model,
		System:   opts.SystemPrompt,
		Recorder: newSessionRecorder(opts, name, model),
	}), name, model, nil
}

// ResolveProvider picks the provider per options (or auto-detects) and
// resolves the model name (provider-default if the user didn't pass one).
// Exported so autopilot/swarm CLI paths can build a Provider from shared
// Options without duplicating selection logic.
func ResolveProvider(opts Options) (provider.Provider, string, string, error) {
	return resolveProvider(opts)
}

// resolveProvider is the internal implementation. Kept lowercase so
// existing callers (RunTUI, buildHeadlessEngine) continue to work.
func resolveProvider(opts Options) (provider.Provider, string, string, error) {
	name := opts.Provider
	if name == "" {
		name = autoDetectProvider(opts)
	}

	model := opts.Model
	switch name {
	case "openai-codex-oauth":
		if model == "" || model == DefaultModel {
			model = "gpt-5.5"
		}
		return newOpenAICodexOAuthProvider(opts, model)
	case "anthropic-api-key":
		if model == "" || model == DefaultModel {
			model = "claude-opus-4-7"
		}
		return newAnthropicAPIKeyProvider(opts, model)
	case "anthropic-oauth":
		if model == "" || model == DefaultModel {
			model = "claude-opus-4-7"
		}
		return newAnthropicOAuthProvider(opts, model)
	case "openai-api-key":
		if model == "" || model == DefaultModel {
			model = "gpt-5.5"
		}
		return newOpenAIAPIKeyProvider(opts, model)
	case "anthropic-cli":
		if model == "" || model == DefaultModel {
			model = "claude-opus-4-7"
		}
		return newAnthropicCLIProvider(opts, model)
	case "anthropic-vertex":
		if model == "" || model == DefaultModel {
			model = "claude-opus-4-6"
		}
		return newAnthropicVertexProvider(opts, model)
	case "google-vertex":
		if model == "" || model == DefaultModel {
			model = "gemini-2.5-pro"
		}
		return newGoogleVertexProvider(opts, model)
	case "openai-compatible":
		// No universal default — local models vary wildly. Fall back to
		// custom_provider.model_id when --model / agent.olium.model is empty.
		if model == "" || model == DefaultModel {
			model = opts.CustomModelID
		}
		return newOpenAICompatibleProvider(opts, model)
	default:
		return nil, "", "", fmt.Errorf("unknown provider %q (valid: openai-codex-oauth, openai-api-key, anthropic-api-key, anthropic-oauth, anthropic-cli, anthropic-vertex, google-vertex, openai-compatible)", name)
	}
}
