package olium

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	auditbin "github.com/vigolium/vigolium/pkg/audit/bin"
	"github.com/vigolium/vigolium/pkg/olium/auth"
	"github.com/vigolium/vigolium/pkg/olium/provider"
)

// validateKeyShape rejects the obvious cross-wires:
//
//	openai-api-key:    keys starting with sk-ant-* (an Anthropic shape)
//	anthropic-api-key: keys starting with sk-ant-oat* (an OAuth token, not an API key)
//	anthropic-oauth:   tokens starting with sk-ant-api* (an API key, not an OAuth token)
//
// It does NOT enforce a positive shape on openai-api-key — the same field
// is used for proxy / OpenRouter / Together / etc. keys whose prefixes
// vary by vendor, and a false reject there would break legitimate setups.
//
// Also rejects an unexpanded ${VAR} pattern, which usually means the
// operator wrote a YAML reference to an env var that wasn't set at load
// time. The provider call would 401 with an opaque upstream message — a
// friendlier error up-front saves a debugging round-trip.
//
// Returns nil for an empty key (callers handle "missing" separately, with
// a more actionable "set agent.olium.llm_api_key or $..." hint).
func validateKeyShape(provider, key string) error {
	k := strings.TrimSpace(key)
	if k == "" {
		return nil
	}
	if strings.HasPrefix(k, "${") && strings.HasSuffix(k, "}") {
		return fmt.Errorf("%s: key looks like an unexpanded %s — is the env var set in your shell at YAML load time?", provider, k)
	}
	switch provider {
	case "openai-api-key", "openai-responses":
		if strings.HasPrefix(k, "sk-ant-") {
			return fmt.Errorf("%s: key starts with sk-ant- (Anthropic shape); switch agent.olium.provider to anthropic-api-key or anthropic-oauth", provider)
		}
	case "anthropic-api-key":
		if strings.HasPrefix(k, "sk-ant-oat") {
			return fmt.Errorf("anthropic-api-key: key starts with sk-ant-oat (Claude Code OAuth shape); switch agent.olium.provider to anthropic-oauth")
		}
	case "anthropic-oauth":
		if strings.HasPrefix(k, "sk-ant-api") {
			return fmt.Errorf("anthropic-oauth: key starts with sk-ant-api (Anthropic API-key shape); switch agent.olium.provider to anthropic-api-key")
		}
	}
	return nil
}

// Provider constructors — one per backend. Keeping them in this file keeps
// runner.go focused on flow rather than wiring. The function names mirror
// the user-facing provider strings so grepping for either lands you here.

func newOpenAICodexOAuthProvider(opts Options, model string) (provider.Provider, string, string, error) {
	codexAuth, err := auth.LoadCodex(opts.OAuthCredPath)
	if err != nil {
		return nil, "", "", fmt.Errorf("openai-codex-oauth: %w", err)
	}
	return provider.NewCodex(codexAuth), "openai-codex-oauth", model, nil
}

func newAnthropicAPIKeyProvider(opts Options, model string) (provider.Provider, string, string, error) {
	key := opts.LLMAPIKey
	if key == "" {
		key = os.Getenv("ANTHROPIC_API_KEY")
	}
	if key == "" {
		return nil, "", "", fmt.Errorf("anthropic-api-key: no key (set agent.olium.llm_api_key, $ANTHROPIC_API_KEY, --llm-api-key, or pick a different provider)")
	}
	if err := validateKeyShape("anthropic-api-key", key); err != nil {
		return nil, "", "", err
	}
	return provider.NewAnthropic(key), "anthropic-api-key", model, nil
}

// newAnthropicOAuthProvider builds the Anthropic OAuth provider. The token is
// what `claude setup-token` produces — typically `sk-ant-oat01-…` — and is
// sent as a Bearer credential against the Anthropic Messages API. The same
// `ANTHROPIC_API_KEY` env var that holds API keys also doubles as the OAuth
// token store, since `claude setup-token` instructs users to export it there.
func newAnthropicOAuthProvider(opts Options, model string) (provider.Provider, string, string, error) {
	token := opts.OAuthToken
	if token == "" {
		token = os.Getenv("ANTHROPIC_API_KEY")
	}
	if token == "" {
		return nil, "", "", fmt.Errorf("anthropic-oauth: no token (set agent.olium.oauth_token, $ANTHROPIC_API_KEY, --oauth-token, or run `claude setup-token`)")
	}
	if err := validateKeyShape("anthropic-oauth", token); err != nil {
		return nil, "", "", err
	}
	return provider.NewAnthropicOAuth(token), "anthropic-oauth", model, nil
}

func newOpenAIAPIKeyProvider(opts Options, model string) (provider.Provider, string, string, error) {
	key := opts.LLMAPIKey
	if key == "" {
		key = os.Getenv("OPENAI_API_KEY")
	}
	if key == "" {
		return nil, "", "", fmt.Errorf("openai-api-key: no key (set agent.olium.llm_api_key, $OPENAI_API_KEY, --llm-api-key, or pick a different provider)")
	}
	if err := validateKeyShape("openai-api-key", key); err != nil {
		return nil, "", "", err
	}
	return provider.NewOpenAI(key), "openai-api-key", model, nil
}

// newOpenAIResponsesProvider wires the public OpenAI Responses API
// (POST https://api.openai.com/v1/responses) with API-key auth. Same key
// resolution as openai-api-key (agent.olium.llm_api_key → $OPENAI_API_KEY);
// the difference is the wire format — Responses instead of Chat Completions.
func newOpenAIResponsesProvider(opts Options, model string) (provider.Provider, string, string, error) {
	key := opts.LLMAPIKey
	if key == "" {
		key = os.Getenv("OPENAI_API_KEY")
	}
	if key == "" {
		return nil, "", "", fmt.Errorf("openai-responses: no key (set agent.olium.llm_api_key, $OPENAI_API_KEY, --llm-api-key, or pick a different provider)")
	}
	if err := validateKeyShape("openai-responses", key); err != nil {
		return nil, "", "", err
	}
	return provider.NewOpenAIResponses(key), "openai-responses", model, nil
}

func newAnthropicCLIProvider(opts Options, model string) (provider.Provider, string, string, error) {
	bin := opts.ClaudeBinary
	if bin == "" {
		bin = "claude"
	}
	resolved, err := exec.LookPath(bin)
	if err != nil {
		return nil, "", "", fmt.Errorf("anthropic-cli: %q not found on PATH (install Claude Code CLI or pass --claude-bin)", bin)
	}
	return provider.NewClaudeCode(resolved, model), "anthropic-cli", model, nil
}

// newClaudeSDKBridgeProvider wires the anthropic-claude-sdk-bridge provider:
// it drives Claude Code through the Agent SDK by shelling out to the
// `vigolium-audit bridge` sidecar (see platform/vigolium-audit/docs/bridge.md).
// The binary auto-resolves from an explicit override, then the embedded
// vigolium-audit blob, then PATH. Auth defaults to the ambient Claude Code
// subscription; an explicit olium API key / OAuth token is forwarded so a
// keyed setup keeps working.
func newClaudeSDKBridgeProvider(opts Options, model string) (provider.Provider, string, string, error) {
	bin, err := resolveBridgeBinary(opts.BridgeBinary)
	if err != nil {
		return nil, "", "", err
	}
	// Forward only EXPLICIT olium credentials. When both are empty the bridge
	// uses subscription / ambient-env auth on its own — the zero-config "use my
	// logged-in Claude Code" path. OAuthCredPath is intentionally not forwarded:
	// its default (~/.codex/auth.json) is a Codex artifact, not a claude cred.
	auth := provider.BridgeAuth{
		APIKey:     opts.LLMAPIKey,
		OAuthToken: opts.OAuthToken,
	}
	return provider.NewClaudeSDKBridge(bin, model, "claude", auth), "anthropic-claude-sdk-bridge", model, nil
}

// resolveBridgeBinary locates the vigolium-audit executable that hosts the
// `bridge` subcommand. Resolution order: explicit override (a PATH name or an
// absolute path) → the embedded vigolium-audit blob extracted to the user
// cache → a `vigolium-audit` on PATH.
func resolveBridgeBinary(override string) (string, error) {
	if o := strings.TrimSpace(override); o != "" {
		resolved, err := exec.LookPath(o)
		if err != nil {
			return "", fmt.Errorf("anthropic-claude-sdk-bridge: %q not found (%w); set agent.olium.bridge_binary or --bridge-bin to a valid vigolium-audit path", o, err)
		}
		return resolved, nil
	}
	if auditbin.Available() {
		if p, err := auditbin.Path(); err == nil {
			return p, nil
		}
	}
	if p, err := exec.LookPath("vigolium-audit"); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("anthropic-claude-sdk-bridge: no vigolium-audit binary found (embedded blob missing and none on PATH); install vigolium-audit or set --bridge-bin")
}

// newOpenAICompatibleProvider wires any backend that speaks the OpenAI Chat
// Completions wire format — Ollama, OpenRouter, LM Studio, vLLM, Together,
// Groq, LocalAI, custom proxies. base_url is required; api_key is optional
// (unauthenticated local servers skip the Authorization header entirely).
// Keyshape validation is deliberately skipped: the key format is unknowable
// for arbitrary backends, and Ollama-style empty keys would trip the check.
func newOpenAICompatibleProvider(opts Options, model string) (provider.Provider, string, string, error) {
	baseURL := strings.TrimSpace(opts.CustomBaseURL)
	if baseURL == "" {
		return nil, "", "", fmt.Errorf("openai-compatible: agent.olium.custom_provider.base_url is required (e.g. http://localhost:11434/v1 for Ollama)")
	}
	if model == "" {
		return nil, "", "", fmt.Errorf("openai-compatible: model is required (set agent.olium.model, agent.olium.custom_provider.model_id, or pass --model)")
	}
	return provider.NewOpenAICompatible(baseURL, opts.CustomAPIKey, opts.CustomExtraHeaders, opts.CustomExtraBody), "openai-compatible", model, nil
}

// newAnthropicCompatibleProvider wires any backend that speaks the Anthropic
// Messages wire format (POST /v1/messages) — a self-hosted gateway, a
// LiteLLM-style proxy, or any Messages-compatible endpoint. base_url is
// required; api_key is optional (unauthenticated local proxies skip the
// x-api-key header). extra_headers are applied last so a gateway that expects
// Bearer auth can override the scheme. Keyshape validation is skipped: the key
// format is unknowable for arbitrary backends.
func newAnthropicCompatibleProvider(opts Options, model string) (provider.Provider, string, string, error) {
	baseURL := strings.TrimSpace(opts.CustomBaseURL)
	if baseURL == "" {
		return nil, "", "", fmt.Errorf("anthropic-compatible: agent.olium.custom_provider.base_url is required (e.g. https://my-gateway.example.com/v1 for a Messages-compatible proxy)")
	}
	if model == "" {
		return nil, "", "", fmt.Errorf("anthropic-compatible: model is required (set agent.olium.model, agent.olium.custom_provider.model_id, or pass --model)")
	}
	return provider.NewAnthropicCompatible(baseURL, opts.CustomAPIKey, opts.CustomExtraHeaders), "anthropic-compatible", model, nil
}

// resolveVertexCredPath applies the project's documented credential
// resolution order for the two Vertex providers:
//
//	$GOOGLE_APPLICATION_CREDENTIALS wins when the YAML still holds the shared
//	codex default ("~/.codex/auth.json"), since that path obviously can't be
//	a GCP service account. An explicit non-codex YAML/CLI value still wins
//	over the env var so operators can pin a specific SA file.
func resolveVertexCredPath(opts Options) string {
	credPath := opts.OAuthCredPath
	if credPath == "" || credPath == "~/.codex/auth.json" {
		if envPath := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); envPath != "" {
			return envPath
		}
		if credPath == "~/.codex/auth.json" {
			return "" // surface a friendlier "no credential path" error
		}
	}
	return credPath
}

// resolveVertexProjectAndLocation resolves the GCP project and region using
// the documented precedence:
//
//	$GOOGLE_CLOUD_PROJECT  > opts.GoogleCloudProject  > SA file's project_id
//	$GOOGLE_CLOUD_LOCATION > opts.GoogleCloudLocation > "us-central1"
func resolveVertexProjectAndLocation(opts Options, vauth *auth.VertexAuth) (string, string) {
	project := os.Getenv("GOOGLE_CLOUD_PROJECT")
	if project == "" {
		project = opts.GoogleCloudProject
	}
	if project == "" {
		project = vauth.ProjectID()
	}

	location := os.Getenv("GOOGLE_CLOUD_LOCATION")
	if location == "" {
		location = opts.GoogleCloudLocation
	}
	if location == "" {
		location = "us-central1"
	}
	return project, location
}

// newAnthropicVertexProvider wires Claude-on-Vertex from olium options.
// Routes claude-* model ids to publishers/anthropic on Vertex AI.
func newAnthropicVertexProvider(opts Options, model string) (provider.Provider, string, string, error) {
	credPath := resolveVertexCredPath(opts)
	vauth, err := auth.LoadVertex(credPath)
	if err != nil {
		return nil, "", "", fmt.Errorf("anthropic-vertex: %w", err)
	}
	project, location := resolveVertexProjectAndLocation(opts, vauth)
	return provider.NewAnthropicVertex(vauth, project, location), "anthropic-vertex", model, nil
}

// newGoogleVertexProvider wires Gemini-on-Vertex from olium options.
// Routes gemini-* model ids to publishers/google on Vertex AI.
func newGoogleVertexProvider(opts Options, model string) (provider.Provider, string, string, error) {
	credPath := resolveVertexCredPath(opts)
	vauth, err := auth.LoadVertex(credPath)
	if err != nil {
		return nil, "", "", fmt.Errorf("google-vertex: %w", err)
	}
	project, location := resolveVertexProjectAndLocation(opts, vauth)
	return provider.NewGoogleVertex(vauth, project, location), "google-vertex", model, nil
}

// autoDetectProvider picks a provider when the user didn't specify one.
// openai-codex-oauth is the default because the OAuth flow is the cheapest
// path for users on a ChatGPT subscription.
func autoDetectProvider(opts Options) string {
	return "openai-codex-oauth"
}

// providerAliases maps user-facing provider synonyms to their canonical
// name. Aliases exist purely for readability at the config surface — e.g.
// "anthropic-claude-cli" reads more clearly than the terse "anthropic-cli"
// while resolving to the exact same driver. Keep both keys and values
// lowercase; canonicalProviderName trims and lowercases before lookup.
var providerAliases = map[string]string{
	"anthropic-claude-cli": "anthropic-cli",
}

// CanonicalProviderName normalizes a provider string: it trims surrounding
// whitespace, lowercases it, and resolves any registered alias to its
// canonical name. An empty input is returned unchanged so callers can still
// fall through to autoDetectProvider. Unknown names pass through verbatim so
// resolveProvider surfaces the "unknown provider" error with the exact string
// the user typed. Exported so display surfaces (e.g. `vigolium agent
// --list-agents`) can mark the active provider row even when the config uses
// an alias.
func CanonicalProviderName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return ""
	}
	if canonical, ok := providerAliases[n]; ok {
		return canonical
	}
	return n
}
