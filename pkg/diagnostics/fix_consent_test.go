package diagnostics

import (
	"context"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
)

func claudeMissingReport() *Report {
	ok := &ToolCheck{Status: StatusOK, Path: "/bin/x"}
	return &Report{
		NucleiTemplates: &CheckResult{Status: StatusOK},
		Piolium:         &CheckResult{Status: StatusOK},
		Tools: map[string]*ToolCheck{
			"chromium": ok, "bun": ok, "npm": ok, "agent-browser": ok, "pi": ok,
			"claude": {Status: StatusError},
		},
	}
}

// TestRunFixes_VendorScriptNeedsConsent is RUN-6: a bare `doctor --fix` no
// longer pipes the Claude Code installer into a shell; --only claude, --yes
// or a confirmation does.
func TestRunFixes_VendorScriptNeedsConsent(t *testing.T) {
	prevOut := fixOut
	fixOut = discard{}
	t.Cleanup(func() { fixOut = prevOut })
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // any install that does start fails at once

	res := RunFixes(ctx, claudeMissingReport(), config.DefaultSettings(), nil)
	if len(res) != 1 || res[0].Key != "claude" || !res[0].Skipped {
		t.Fatalf("bare --fix = %+v, want claude skipped", res)
	}

	asked := 0
	res = RunFixesWith(ctx, claudeMissingReport(), config.DefaultSettings(), nil, FixOptions{
		Confirm: func(string, string) bool { asked++; return false },
	})
	if asked != 1 || !res[0].Skipped {
		t.Fatalf("declined prompt = %+v (asked %d), want skipped after one prompt", res, asked)
	}

	for name, opts := range map[string]FixOptions{"--yes": {AssumeYes: true}} {
		res = RunFixesWith(ctx, claudeMissingReport(), config.DefaultSettings(), nil, opts)
		if len(res) != 1 || res[0].Skipped {
			t.Fatalf("%s = %+v, want the install attempted", name, res)
		}
	}
	res = RunFixes(ctx, claudeMissingReport(), config.DefaultSettings(), []string{"claude"})
	if len(res) != 1 || res[0].Skipped {
		t.Fatalf("--only claude = %+v, want the install attempted", res)
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
