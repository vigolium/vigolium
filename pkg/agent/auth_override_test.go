package agent

import (
	"reflect"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
)

func TestValidateAuthOverride(t *testing.T) {
	tests := []struct {
		name    string
		o       agenttypes.AuthOverride
		wantErr string // substring; "" = expect no error
	}{
		{
			name:    "empty override is fine",
			o:       agenttypes.AuthOverride{},
			wantErr: "",
		},
		{
			name:    "api key alone",
			o:       agenttypes.AuthOverride{APIKey: "sk-ant", Agent: string(agenttypes.AuditDriverAgentClaude)},
			wantErr: "",
		},
		{
			name:    "oauth token claude default agent",
			o:       agenttypes.AuthOverride{OAuthToken: "oat"},
			wantErr: "",
		},
		{
			name:    "cred file codex",
			o:       agenttypes.AuthOverride{OAuthCredFile: "/tmp/auth.json", Agent: string(agenttypes.AuditDriverAgentCodex)},
			wantErr: "",
		},
		{
			name:    "two flags set is rejected",
			o:       agenttypes.AuthOverride{APIKey: "x", OAuthToken: "y", Agent: string(agenttypes.AuditDriverAgentClaude)},
			wantErr: "at most one",
		},
		{
			name:    "all three flags set is rejected",
			o:       agenttypes.AuthOverride{APIKey: "x", OAuthToken: "y", OAuthCredFile: "z", Agent: string(agenttypes.AuditDriverAgentClaude)},
			wantErr: "at most one",
		},
		{
			name:    "oauth token on codex is rejected",
			o:       agenttypes.AuthOverride{OAuthToken: "oat", Agent: string(agenttypes.AuditDriverAgentCodex)},
			wantErr: "only valid for the claude agent",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateAuthOverride(tc.o)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestPiAuthEnv(t *testing.T) {
	tests := []struct {
		name string
		o    agenttypes.AuthOverride
		want []string
	}{
		{
			name: "empty",
			o:    agenttypes.AuthOverride{},
			want: nil,
		},
		{
			name: "claude api key",
			o:    agenttypes.AuthOverride{APIKey: "sk-ant", Agent: string(agenttypes.AuditDriverAgentClaude)},
			want: []string{"ANTHROPIC_API_KEY=sk-ant"},
		},
		{
			name: "default agent api key → claude",
			o:    agenttypes.AuthOverride{APIKey: "sk-ant"},
			want: []string{"ANTHROPIC_API_KEY=sk-ant"},
		},
		{
			name: "codex api key",
			o:    agenttypes.AuthOverride{APIKey: "sk-openai", Agent: string(agenttypes.AuditDriverAgentCodex)},
			want: []string{"OPENAI_API_KEY=sk-openai"},
		},
		{
			name: "claude oauth token",
			o:    agenttypes.AuthOverride{OAuthToken: "oat", Agent: string(agenttypes.AuditDriverAgentClaude)},
			want: []string{"CLAUDE_CODE_OAUTH_TOKEN=oat"},
		},
		{
			name: "cred file is staged separately, not via env",
			o:    agenttypes.AuthOverride{OAuthCredFile: "/tmp/auth.json", Agent: string(agenttypes.AuditDriverAgentCodex)},
			want: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := PiAuthEnv(tc.o)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestApplyAuthOverrideToAudit(t *testing.T) {
	t.Run("empty override leaves invocation alone", func(t *testing.T) {
		inv := agenttypes.AuditDriverInvocation{
			Agent: agenttypes.AuditDriverAgentClaude,
			Auth:  agenttypes.AuditDriverAuthFlags{APIKey: "from-config"},
		}
		ApplyAuthOverrideToAudit(&inv, agenttypes.AuthOverride{})
		if inv.Auth.APIKey != "from-config" {
			t.Fatalf("override was empty but APIKey changed to %q", inv.Auth.APIKey)
		}
	})

	t.Run("override replaces existing auth wholesale", func(t *testing.T) {
		inv := agenttypes.AuditDriverInvocation{
			Agent: agenttypes.AuditDriverAgentCodex,
			Auth:  agenttypes.AuditDriverAuthFlags{OAuthCredFile: "/old/path"},
		}
		ApplyAuthOverrideToAudit(&inv, agenttypes.AuthOverride{APIKey: "new-key", Agent: string(agenttypes.AuditDriverAgentCodex)})
		want := agenttypes.AuditDriverAuthFlags{APIKey: "new-key"}
		if !reflect.DeepEqual(inv.Auth, want) {
			t.Fatalf("got %+v, want %+v", inv.Auth, want)
		}
	})

	t.Run("nil invocation is a no-op", func(t *testing.T) {
		ApplyAuthOverrideToAudit(nil, agenttypes.AuthOverride{APIKey: "x"})
	})
}

func TestResolveAuthAgent(t *testing.T) {
	cases := []struct {
		name           string
		override, conf string
		want           string
	}{
		{"empty defaults to claude", "", "", "claude"},
		{"override wins", "openai-api-key", "anthropic-api-key", "codex"},
		{"olium provider used when override empty", "", "openai-codex-oauth", "codex"},
		{"unknown provider defaults to claude", "", "futurelab-x9", "claude"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ResolveAuthAgent(tc.override, tc.conf); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
