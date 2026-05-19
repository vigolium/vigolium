package agent

import (
	"strings"

	"github.com/vigolium/vigolium/internal/config"
)

// ResolveArchonInvocation derives the archon-ts agent + auth tuple
// from the configured olium provider and an optional override.
//
// Precedence:
//  1. providerOverride (CLI flag like --archon-provider) — wins outright.
//  2. olium.Provider — anthropic-* → claude, openai-* → codex.
//  3. Default — claude (matches archon-ts's own default).
//
// Auth selection follows the resolved provider:
//   - anthropic-api-key  → APIKey from olium.LLMAPIKey
//   - anthropic-oauth    → OAuthToken from olium.OAuthToken
//   - anthropic-cli      → no override (subscription auth)
//   - openai-api-key     → APIKey from olium.LLMAPIKey
//   - openai-codex-oauth → OAuthCredFile from olium.OAuthCredPath
//   - vertex providers   → no override (archon doesn't authenticate
//     against Vertex itself; the user routes through Anthropic/OpenAI
//     via archon's own provider-detection path)
//
// authOverride (variadic for backwards compatibility) supplies a per-run
// BYOK bundle from the audit CLI/REST surface. When non-empty, it REPLACES
// the olium-derived auth wholesale (see ApplyAuthOverrideToArchon) — the
// resolved agent (claude/codex) still comes from providerOverride/olium.
// Only the first element is consulted; extras are ignored.
func ResolveArchonInvocation(olium config.OliumConfig, providerOverride string, authOverride ...AuthOverride) ArchonInvocation {
	provider := strings.TrimSpace(providerOverride)
	if provider == "" {
		provider = strings.TrimSpace(olium.Provider)
	}

	inv := ArchonInvocation{Agent: archonAgentFromProvider(provider)}

	switch provider {
	case "anthropic-api-key", "openai-api-key":
		inv.Auth.APIKey = olium.LLMAPIKey
	case "anthropic-oauth":
		inv.Auth.OAuthToken = olium.OAuthToken
	case "openai-codex-oauth":
		inv.Auth.OAuthCredFile = olium.OAuthCredPath
	}

	if len(authOverride) > 0 {
		ApplyAuthOverrideToArchon(&inv, authOverride[0])
	}

	return inv
}

// archonAgentFromProvider picks the archon `--agent` value for either
// an olium provider name or a direct archon agent name.
//
// Inputs come from two distinct call sites with different conventions:
//   - CLI's --archon-provider flag → provider names (anthropic-*, openai-*,
//     google-*) which map by prefix to claude/codex.
//   - REST's req.Agent field      → direct agent names ("claude" | "codex")
//     validated upstream by IsValidArchonPlatform.
//
// Direct agent names short-circuit the prefix mapping so REST's
// `agent:"codex"` resolves to codex instead of falling through to the
// default. Without this, REST callers were silently downgraded to claude,
// archon was launched with --agent claude using whatever cred file was in
// the auth override, and the bundle came back with claude artifacts even
// though the request asked for codex.
//
// anthropic-cli + anthropic-vertex still resolve to claude; openai-*
// resolve to codex. Unknown inputs fall back to claude (archon's own
// default) so a misspelled config doesn't error the launcher path —
// archon's own probe will surface the real error.
func archonAgentFromProvider(provider string) ArchonAgent {
	p := strings.ToLower(strings.TrimSpace(provider))
	switch p {
	case string(ArchonAgentClaude):
		return ArchonAgentClaude
	case string(ArchonAgentCodex):
		return ArchonAgentCodex
	}
	switch {
	case strings.HasPrefix(p, "openai-"):
		return ArchonAgentCodex
	case strings.HasPrefix(p, "anthropic-"), strings.HasPrefix(p, "google-"):
		return ArchonAgentClaude
	default:
		return ArchonAgentClaude
	}
}

// IsValidArchonAgent reports whether s is a recognized archon `--agent`
// value (claude|codex). Used by CLI / REST validation of the
// --archon-provider override.
func IsValidArchonAgent(s string) bool {
	switch ArchonAgent(s) {
	case ArchonAgentClaude, ArchonAgentCodex:
		return true
	}
	return false
}

// ForceArchonAgent layers the CLI --agent flag on top of an already
// resolved invocation. It is a *pure agent selector*: when agentOverride
// is a valid archon agent (claude|codex) it replaces inv.Agent only,
// leaving the provider-derived auth on inv untouched. This is what makes
// `--archon-provider <p> --agent <a>` keep <p>'s BYOK auth while running
// agent <a>. An empty or invalid override is a no-op, so the resolver's
// provider-derived agent stands (callers validate up front and surface a
// clear error for genuinely bad input).
func ForceArchonAgent(inv *ArchonInvocation, agentOverride string) {
	if inv == nil {
		return
	}
	a := strings.ToLower(strings.TrimSpace(agentOverride))
	switch ArchonAgent(a) {
	case ArchonAgentClaude, ArchonAgentCodex:
		inv.Agent = ArchonAgent(a)
	}
}
