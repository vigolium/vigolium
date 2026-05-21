package agent

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
)

// Env-var names BYOK injects on the pi subprocess. Shared with the
// log-redactor (audit_redact.go) so the names PiAuthEnv produces and
// the names the redactor masks stay in lockstep — adding a new
// injection here without updating the redactor would silently leak
// the secret into runtime.log.
const (
	envAnthropicAPIKey      = "ANTHROPIC_API_KEY"
	envClaudeCodeOAuthToken = "CLAUDE_CODE_OAUTH_TOKEN"
	envOpenAIAPIKey         = "OPENAI_API_KEY"
	envOpenAIOAuthCredPath  = "OPENAI_OAUTH_CRED_PATH"
	envGoogleAppCredentials = "GOOGLE_APPLICATION_CREDENTIALS"
)

// ValidateAuthOverride enforces the BYOK rules shared by CLI and REST:
//
//  1. At most one of APIKey / OAuthToken / OAuthCredFile is set. Mixing
//     them is almost always an operator mistake and the harness can only
//     honor one at a time anyway.
//  2. OAuthToken requires the claude side. OpenAI/codex has no equivalent
//     bearer token form (codex uses cred files), so this catches the
//     cross-wire of pasting an Anthropic OAuth token into a codex run.
//
// The Agent field on the override drives rule 2. Empty defaults to claude
// (matches audit's own default + the audit resolver's behavior).
//
// Returns nil for an entirely-empty override, since "inherit ambient
// agent.olium.* config" is the documented no-op behavior.
func ValidateAuthOverride(o agenttypes.AuthOverride) error {
	if o.IsZero() {
		return nil
	}

	set := 0
	for _, v := range []string{o.APIKey, o.OAuthToken, o.OAuthCredFile} {
		if v != "" {
			set++
		}
	}
	if set > 1 {
		return fmt.Errorf("auth override: at most one of api-key / oauth-token / oauth-cred-file may be set")
	}

	if o.OAuthToken != "" {
		agent := normalizedAgent(o.Agent)
		if agent != string(agenttypes.AuditDriverAgentClaude) {
			return fmt.Errorf("auth override: --oauth-token is only valid for the claude agent (got %q); codex uses --oauth-cred-file", agent)
		}
	}

	return nil
}

// PiAuthEnv maps the BYOK override into the env vars `pi`'s provider
// drivers honor.
//
// For api_key / oauth_token: returns one or two KEY=VALUE entries the
// caller should append to the pi subprocess env. The function never sets
// the env in-process — vigolium injects per-subprocess so concurrent runs
// don't trample one another.
//
// For oauth_cred_file: returns nil. Codex doesn't read the file from an
// env var; vigolium stages it under <pi-agent-dir>/auth.json (handled by
// the launcher in pkg/agent/audit_agent.go) so the codex provider picks
// it up via its standard read path.
//
// Returns nil for an empty override (no env injection needed).
func PiAuthEnv(o agenttypes.AuthOverride) []string {
	if o.IsZero() {
		return nil
	}
	agent := normalizedAgent(o.Agent)

	switch {
	case o.APIKey != "":
		switch agent {
		case string(agenttypes.AuditDriverAgentCodex):
			return []string{envOpenAIAPIKey + "=" + o.APIKey}
		default:
			// CLAUDE_CODE_OAUTH_TOKEN is intentionally NOT mirrored —
			// that var signals OAuth-flow auth, not API-key auth.
			return []string{envAnthropicAPIKey + "=" + o.APIKey}
		}
	case o.OAuthToken != "":
		// claude-only (validator enforces). Pi's anthropic-oauth provider
		// reads CLAUDE_CODE_OAUTH_TOKEN; setting ANTHROPIC_API_KEY too would
		// cross-wire api-key auth on top of oauth auth, so we don't.
		return []string{envClaudeCodeOAuthToken + "=" + o.OAuthToken}
	case o.OAuthCredFile != "":
		// Staged on disk, not via env — see audit_agent.go.
		return nil
	}
	return nil
}

// ApplyAuthOverrideToAudit folds a BYOK override into an AuditDriverInvocation
// in-place. When the override is empty the invocation is unchanged
// (preserving the agent.olium.* derived auth). When set, the override
// REPLACES whatever the resolver derived from olium config — including
// clearing fields the override doesn't touch, so a half-set audit auth
// from olium (e.g. an OAuthCredFile) doesn't leak into a run where the
// operator passed --oauth-token.
func ApplyAuthOverrideToAudit(inv *agenttypes.AuditDriverInvocation, o agenttypes.AuthOverride) {
	if inv == nil || o.IsZero() {
		return
	}
	inv.Auth = agenttypes.AuditDriverAuthFlags{
		APIKey:        o.APIKey,
		OAuthToken:    o.OAuthToken,
		OAuthCredFile: o.OAuthCredFile,
	}
}

// ResolveAuthAgent picks the audit-style agent identity ("claude" or
// "codex") that BYOK creds should target, given the optional CLI/REST
// override and the configured olium provider. Centralized so the CLI,
// REST, and any future entry point all answer "is this a claude or
// codex key?" the same way.
//
// CLI and REST feed semantically different inputs here:
//   - CLI passes --provider, a provider name like
//     "openai-codex-oauth" → mapped via auditAgentSelFromProvider.
//   - REST passes req.Agent, a direct agent name ("claude" | "codex")
//     validated upstream by IsValidAuditDriverPlatform.
//
// We accept both forms: a direct agent name short-circuits the
// provider-prefix mapping, so REST's `agent:"codex"` correctly resolves
// to "codex" instead of falling through to the default ("claude") and
// silently bypassing the validator's oauth_token-needs-claude rule.
//
// Precedence:
//  1. providerOrAgentOverride (--provider or req.Agent)
//  2. oliumProvider                                            → auditAgentSelFromProvider
//  3. Default                                                   → "claude"
func ResolveAuthAgent(providerOrAgentOverride, oliumProvider string) string {
	s := strings.TrimSpace(providerOrAgentOverride)
	if s == "" {
		s = strings.TrimSpace(oliumProvider)
	}
	if IsValidAuditDriverAgent(strings.ToLower(s)) {
		return strings.ToLower(s)
	}
	return string(auditAgentSelFromProvider(s))
}

// normalizedAgent lower-cases and trims agent strings, defaulting to
// claude on empty.
func normalizedAgent(s string) string {
	a := strings.ToLower(strings.TrimSpace(s))
	if a == "" {
		return string(agenttypes.AuditDriverAgentClaude)
	}
	return a
}
