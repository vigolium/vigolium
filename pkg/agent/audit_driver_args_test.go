package agent

import (
	"reflect"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
)

func TestResolveAuditDriverInvocation_ProviderRouting(t *testing.T) {
	tests := []struct {
		name     string
		olium    config.OliumConfig
		override string
		want     AuditDriverInvocation
	}{
		{
			name:  "anthropic-api-key forwards LLMAPIKey",
			olium: config.OliumConfig{Provider: "anthropic-api-key", LLMAPIKey: "sk-ant-test"},
			want: AuditDriverInvocation{
				Agent: AuditDriverAgentClaude,
				Auth:  AuditDriverAuthFlags{APIKey: "sk-ant-test"},
			},
		},
		{
			name:  "anthropic-oauth forwards OAuthToken",
			olium: config.OliumConfig{Provider: "anthropic-oauth", OAuthToken: "oauth-token-xyz"},
			want: AuditDriverInvocation{
				Agent: AuditDriverAgentClaude,
				Auth:  AuditDriverAuthFlags{OAuthToken: "oauth-token-xyz"},
			},
		},
		{
			name:  "anthropic-cli inherits ambient auth (no flags)",
			olium: config.OliumConfig{Provider: "anthropic-cli"},
			want:  AuditDriverInvocation{Agent: AuditDriverAgentClaude},
		},
		{
			name:  "openai-codex-oauth forwards OAuthCredPath",
			olium: config.OliumConfig{Provider: "openai-codex-oauth", OAuthCredPath: "~/.codex/auth.json"},
			want: AuditDriverInvocation{
				Agent: AuditDriverAgentCodex,
				Auth:  AuditDriverAuthFlags{OAuthCredFile: "~/.codex/auth.json"},
			},
		},
		{
			name:  "openai-api-key forwards LLMAPIKey, agent=codex",
			olium: config.OliumConfig{Provider: "openai-api-key", LLMAPIKey: "sk-openai-test"},
			want: AuditDriverInvocation{
				Agent: AuditDriverAgentCodex,
				Auth:  AuditDriverAuthFlags{APIKey: "sk-openai-test"},
			},
		},
		{
			name:  "google-vertex routes to claude with no auth override",
			olium: config.OliumConfig{Provider: "google-vertex"},
			want:  AuditDriverInvocation{Agent: AuditDriverAgentClaude},
		},
		{
			name:     "providerOverride wins over olium provider",
			olium:    config.OliumConfig{Provider: "anthropic-cli"},
			override: "openai-codex-oauth",
			want:     AuditDriverInvocation{Agent: AuditDriverAgentCodex},
		},
		{
			name:  "empty provider defaults to claude",
			olium: config.OliumConfig{},
			want:  AuditDriverInvocation{Agent: AuditDriverAgentClaude},
		},
		{
			name:  "unknown provider defaults to claude (audit will error itself)",
			olium: config.OliumConfig{Provider: "futurelab-x9"},
			want:  AuditDriverInvocation{Agent: AuditDriverAgentClaude},
		},
		// REST callers pass req.Agent (a direct agent name) here as the
		// override. Without agent-name short-circuiting in
		// auditAgentSelFromProvider, "codex" would fall through to the
		// default and the audit CLI would launch with --agent claude
		// despite the request asking for codex — silently downgrading
		// the run. These cases pin the fix.
		{
			name:     "REST agent='codex' override resolves to codex",
			olium:    config.OliumConfig{Provider: "anthropic-cli"},
			override: "codex",
			want:     AuditDriverInvocation{Agent: AuditDriverAgentCodex},
		},
		{
			name:     "REST agent='claude' override resolves to claude",
			olium:    config.OliumConfig{Provider: "openai-codex-oauth", OAuthCredPath: "/x.json"},
			override: "claude",
			// override wins agent identity; auth-shape switch sees
			// "claude" (not a known provider name) → no olium auth
			// pulled in. BYOK override (variadic) would supply the
			// actual auth on a real run.
			want: AuditDriverInvocation{Agent: AuditDriverAgentClaude},
		},
		{
			name:     "REST agent='CODEX' (case-insensitive) resolves to codex",
			olium:    config.OliumConfig{},
			override: "CODEX",
			want:     AuditDriverInvocation{Agent: AuditDriverAgentCodex},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolveAuditDriverInvocation(tc.olium, tc.override)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ResolveAuditDriverInvocation = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestAuditDriverInvocation_Args(t *testing.T) {
	tests := []struct {
		name string
		inv  AuditDriverInvocation
		want []string
	}{
		{
			name: "claude with no auth → just --agent",
			inv:  AuditDriverInvocation{Agent: AuditDriverAgentClaude},
			want: []string{"--agent", "claude"},
		},
		{
			name: "claude with API key",
			inv: AuditDriverInvocation{
				Agent: AuditDriverAgentClaude,
				Auth:  AuditDriverAuthFlags{APIKey: "sk-ant-x"},
			},
			want: []string{"--agent", "claude", "--api-key", "sk-ant-x"},
		},
		{
			name: "codex with cred file",
			inv: AuditDriverInvocation{
				Agent: AuditDriverAgentCodex,
				Auth:  AuditDriverAuthFlags{OAuthCredFile: "/tmp/codex.json"},
			},
			want: []string{"--agent", "codex", "--oauth-cred-file", "/tmp/codex.json"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.inv.Args()
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Args = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestResolveAuditDriverInvocation_AuthOverrideWins(t *testing.T) {
	// olium-derived APIKey is replaced when an oauth-token override is
	// passed; it does NOT survive alongside the override (replacement is
	// wholesale so a stale config value can't cross-wire onto an
	// override-driven run).
	got := ResolveAuditDriverInvocation(
		config.OliumConfig{Provider: "anthropic-api-key", LLMAPIKey: "sk-from-config"},
		"",
		AuthOverride{OAuthToken: "oat-from-flag"},
	)
	want := AuditDriverInvocation{
		Agent: AuditDriverAgentClaude,
		Auth:  AuditDriverAuthFlags{OAuthToken: "oat-from-flag"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestResolveAuditDriverInvocation_EmptyOverrideKeepsOliumAuth(t *testing.T) {
	got := ResolveAuditDriverInvocation(
		config.OliumConfig{Provider: "anthropic-api-key", LLMAPIKey: "sk-from-config"},
		"",
		AuthOverride{},
	)
	want := AuditDriverInvocation{
		Agent: AuditDriverAgentClaude,
		Auth:  AuditDriverAuthFlags{APIKey: "sk-from-config"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestIsValidAuditDriverAgent(t *testing.T) {
	cases := map[string]bool{
		"claude": true,
		"codex":  true,
		"":       false,
		"opus":   false,
		"gpt":    false,
	}
	for s, want := range cases {
		if got := IsValidAuditDriverAgent(s); got != want {
			t.Errorf("IsValidAuditDriverAgent(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestForceAuditDriverAgent(t *testing.T) {
	// The defining property: --agent is a *pure agent selector*. It
	// flips inv.Agent but leaves the provider-derived auth alone, so
	// `--provider openai-codex-oauth --agent claude` runs claude
	// while still carrying codex's resolved cred file untouched.
	base := ResolveAuditDriverInvocation(
		config.OliumConfig{Provider: "openai-codex-oauth", OAuthCredPath: "/x/auth.json"},
		"", AuthOverride{},
	)
	if base.Agent != AuditDriverAgentCodex {
		t.Fatalf("precondition: expected codex from openai-codex-oauth, got %q", base.Agent)
	}

	cases := []struct {
		name     string
		override string
		want     AuditDriverAgent
	}{
		{"flip to claude", "claude", AuditDriverAgentClaude},
		{"keep codex", "codex", AuditDriverAgentCodex},
		{"case-insensitive + spaces", "  Claude ", AuditDriverAgentClaude},
		{"empty is a no-op", "", AuditDriverAgentCodex},
		{"invalid is a no-op", "opus", AuditDriverAgentCodex},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			inv := base // copy
			ForceAuditDriverAgent(&inv, c.override)
			if inv.Agent != c.want {
				t.Errorf("ForceAuditDriverAgent(%q): agent = %q, want %q", c.override, inv.Agent, c.want)
			}
			// Auth must survive the agent flip in every case.
			if !reflect.DeepEqual(inv.Auth, base.Auth) {
				t.Errorf("ForceAuditDriverAgent(%q): auth mutated: got %+v, want %+v", c.override, inv.Auth, base.Auth)
			}
		})
	}

	// nil receiver must not panic.
	ForceAuditDriverAgent(nil, "codex")
}
