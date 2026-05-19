package agent

import (
	"reflect"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
)

func TestResolveArchonInvocation_ProviderRouting(t *testing.T) {
	tests := []struct {
		name     string
		olium    config.OliumConfig
		override string
		want     ArchonInvocation
	}{
		{
			name:  "anthropic-api-key forwards LLMAPIKey",
			olium: config.OliumConfig{Provider: "anthropic-api-key", LLMAPIKey: "sk-ant-test"},
			want: ArchonInvocation{
				Agent: ArchonAgentClaude,
				Auth:  ArchonAuthFlags{APIKey: "sk-ant-test"},
			},
		},
		{
			name:  "anthropic-oauth forwards OAuthToken",
			olium: config.OliumConfig{Provider: "anthropic-oauth", OAuthToken: "oauth-token-xyz"},
			want: ArchonInvocation{
				Agent: ArchonAgentClaude,
				Auth:  ArchonAuthFlags{OAuthToken: "oauth-token-xyz"},
			},
		},
		{
			name:  "anthropic-cli inherits ambient auth (no flags)",
			olium: config.OliumConfig{Provider: "anthropic-cli"},
			want:  ArchonInvocation{Agent: ArchonAgentClaude},
		},
		{
			name:  "openai-codex-oauth forwards OAuthCredPath",
			olium: config.OliumConfig{Provider: "openai-codex-oauth", OAuthCredPath: "~/.codex/auth.json"},
			want: ArchonInvocation{
				Agent: ArchonAgentCodex,
				Auth:  ArchonAuthFlags{OAuthCredFile: "~/.codex/auth.json"},
			},
		},
		{
			name:  "openai-api-key forwards LLMAPIKey, agent=codex",
			olium: config.OliumConfig{Provider: "openai-api-key", LLMAPIKey: "sk-openai-test"},
			want: ArchonInvocation{
				Agent: ArchonAgentCodex,
				Auth:  ArchonAuthFlags{APIKey: "sk-openai-test"},
			},
		},
		{
			name:  "google-vertex routes to claude with no auth override",
			olium: config.OliumConfig{Provider: "google-vertex"},
			want:  ArchonInvocation{Agent: ArchonAgentClaude},
		},
		{
			name:     "providerOverride wins over olium provider",
			olium:    config.OliumConfig{Provider: "anthropic-cli"},
			override: "openai-codex-oauth",
			want:     ArchonInvocation{Agent: ArchonAgentCodex},
		},
		{
			name:  "empty provider defaults to claude",
			olium: config.OliumConfig{},
			want:  ArchonInvocation{Agent: ArchonAgentClaude},
		},
		{
			name:  "unknown provider defaults to claude (archon will error itself)",
			olium: config.OliumConfig{Provider: "futurelab-x9"},
			want:  ArchonInvocation{Agent: ArchonAgentClaude},
		},
		// REST callers pass req.Agent (a direct agent name) here as the
		// override. Without agent-name short-circuiting in
		// archonAgentFromProvider, "codex" would fall through to the
		// default and the archon CLI would launch with --agent claude
		// despite the request asking for codex — silently downgrading
		// the run. These cases pin the fix.
		{
			name:     "REST agent='codex' override resolves to codex",
			olium:    config.OliumConfig{Provider: "anthropic-cli"},
			override: "codex",
			want:     ArchonInvocation{Agent: ArchonAgentCodex},
		},
		{
			name:     "REST agent='claude' override resolves to claude",
			olium:    config.OliumConfig{Provider: "openai-codex-oauth", OAuthCredPath: "/x.json"},
			override: "claude",
			// override wins agent identity; auth-shape switch sees
			// "claude" (not a known provider name) → no olium auth
			// pulled in. BYOK override (variadic) would supply the
			// actual auth on a real run.
			want: ArchonInvocation{Agent: ArchonAgentClaude},
		},
		{
			name:     "REST agent='CODEX' (case-insensitive) resolves to codex",
			olium:    config.OliumConfig{},
			override: "CODEX",
			want:     ArchonInvocation{Agent: ArchonAgentCodex},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolveArchonInvocation(tc.olium, tc.override)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ResolveArchonInvocation = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestArchonInvocation_Args(t *testing.T) {
	tests := []struct {
		name string
		inv  ArchonInvocation
		want []string
	}{
		{
			name: "claude with no auth → just --agent",
			inv:  ArchonInvocation{Agent: ArchonAgentClaude},
			want: []string{"--agent", "claude"},
		},
		{
			name: "claude with API key",
			inv: ArchonInvocation{
				Agent: ArchonAgentClaude,
				Auth:  ArchonAuthFlags{APIKey: "sk-ant-x"},
			},
			want: []string{"--agent", "claude", "--api-key", "sk-ant-x"},
		},
		{
			name: "codex with cred file",
			inv: ArchonInvocation{
				Agent: ArchonAgentCodex,
				Auth:  ArchonAuthFlags{OAuthCredFile: "/tmp/codex.json"},
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

func TestResolveArchonInvocation_AuthOverrideWins(t *testing.T) {
	// olium-derived APIKey is replaced when an oauth-token override is
	// passed; it does NOT survive alongside the override (replacement is
	// wholesale so a stale config value can't cross-wire onto an
	// override-driven run).
	got := ResolveArchonInvocation(
		config.OliumConfig{Provider: "anthropic-api-key", LLMAPIKey: "sk-from-config"},
		"",
		AuthOverride{OAuthToken: "oat-from-flag"},
	)
	want := ArchonInvocation{
		Agent: ArchonAgentClaude,
		Auth:  ArchonAuthFlags{OAuthToken: "oat-from-flag"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestResolveArchonInvocation_EmptyOverrideKeepsOliumAuth(t *testing.T) {
	got := ResolveArchonInvocation(
		config.OliumConfig{Provider: "anthropic-api-key", LLMAPIKey: "sk-from-config"},
		"",
		AuthOverride{},
	)
	want := ArchonInvocation{
		Agent: ArchonAgentClaude,
		Auth:  ArchonAuthFlags{APIKey: "sk-from-config"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestIsValidArchonAgent(t *testing.T) {
	cases := map[string]bool{
		"claude": true,
		"codex":  true,
		"":       false,
		"opus":   false,
		"gpt":    false,
	}
	for s, want := range cases {
		if got := IsValidArchonAgent(s); got != want {
			t.Errorf("IsValidArchonAgent(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestForceArchonAgent(t *testing.T) {
	// The defining property: --agent is a *pure agent selector*. It
	// flips inv.Agent but leaves the provider-derived auth alone, so
	// `--archon-provider openai-codex-oauth --agent claude` runs claude
	// while still carrying codex's resolved cred file untouched.
	base := ResolveArchonInvocation(
		config.OliumConfig{Provider: "openai-codex-oauth", OAuthCredPath: "/x/auth.json"},
		"", AuthOverride{},
	)
	if base.Agent != ArchonAgentCodex {
		t.Fatalf("precondition: expected codex from openai-codex-oauth, got %q", base.Agent)
	}

	cases := []struct {
		name     string
		override string
		want     ArchonAgent
	}{
		{"flip to claude", "claude", ArchonAgentClaude},
		{"keep codex", "codex", ArchonAgentCodex},
		{"case-insensitive + spaces", "  Claude ", ArchonAgentClaude},
		{"empty is a no-op", "", ArchonAgentCodex},
		{"invalid is a no-op", "opus", ArchonAgentCodex},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			inv := base // copy
			ForceArchonAgent(&inv, c.override)
			if inv.Agent != c.want {
				t.Errorf("ForceArchonAgent(%q): agent = %q, want %q", c.override, inv.Agent, c.want)
			}
			// Auth must survive the agent flip in every case.
			if !reflect.DeepEqual(inv.Auth, base.Auth) {
				t.Errorf("ForceArchonAgent(%q): auth mutated: got %+v, want %+v", c.override, inv.Auth, base.Auth)
			}
		})
	}

	// nil receiver must not panic.
	ForceArchonAgent(nil, "codex")
}
