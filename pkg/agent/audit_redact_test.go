package agent

import (
	"reflect"
	"strings"
	"testing"
)

func TestRedactEnvSlice(t *testing.T) {
	in := []string{
		"PI_CODING_AGENT_DIR=/opt/piolium/agent",
		"ANTHROPIC_API_KEY=sk-ant-real-secret",
		"PIOLIUM_REPOSITORY=acme/widgets",
		"OPENAI_API_KEY=sk-openai",
		"CLAUDE_CODE_OAUTH_TOKEN=oat",
		"GOOGLE_APPLICATION_CREDENTIALS=/etc/sa.json",
		"NOT_A_SECRET=hello world",
		"weird-no-equals",
	}
	want := []string{
		"PI_CODING_AGENT_DIR=/opt/piolium/agent",
		"ANTHROPIC_API_KEY=<redacted>",
		"PIOLIUM_REPOSITORY=acme/widgets",
		"OPENAI_API_KEY=<redacted>",
		"CLAUDE_CODE_OAUTH_TOKEN=<redacted>",
		"GOOGLE_APPLICATION_CREDENTIALS=<redacted>",
		"NOT_A_SECRET=hello world",
		"weird-no-equals",
	}
	got := redactEnvSlice(in)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestRedactEnvSlice_LeavesInputAlone(t *testing.T) {
	in := []string{"ANTHROPIC_API_KEY=sk-ant-real"}
	_ = redactEnvSlice(in)
	// We must not mutate the input slice — callers reuse it for cmd.Env.
	if !strings.HasSuffix(in[0], "sk-ant-real") {
		t.Fatalf("redactor mutated input: %q", in[0])
	}
}

func TestRedactAuditDriverCmdLine(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "api key value redacted",
			in:   "/usr/bin/audit run --target /tmp --mode deep --agent claude --api-key sk-ant-real --json",
			want: "/usr/bin/audit run --target /tmp --mode deep --agent claude --api-key <redacted> --json",
		},
		{
			name: "oauth token value redacted",
			in:   "/usr/bin/audit run --agent claude --oauth-token oat-abc",
			want: "/usr/bin/audit run --agent claude --oauth-token <redacted>",
		},
		{
			name: "cred file path redacted (filesystem layout is also sensitive)",
			in:   "/usr/bin/audit run --agent codex --oauth-cred-file /home/op/codex.json",
			want: "/usr/bin/audit run --agent codex --oauth-cred-file <redacted>",
		},
		{
			name: "no auth flag → unchanged",
			in:   "/usr/bin/audit run --target /tmp --mode deep --agent claude --json",
			want: "/usr/bin/audit run --target /tmp --mode deep --agent claude --json",
		},
		{
			name: "trailing flag with no value is left alone",
			in:   "/usr/bin/audit run --api-key",
			want: "/usr/bin/audit run --api-key",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := redactAuditDriverCmdLine(tc.in)
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
