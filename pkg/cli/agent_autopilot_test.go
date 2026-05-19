package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigolium/vigolium/internal/runner"
)

// TestAutopilotOliumOverrideFlagsRegistered guards M3a parity between the
// `vigolium agent olium` CLI and the autopilot's olium backend. Operators
// expect the same per-run knobs in both places — when this fails, the four
// flags below have been silently dropped from autopilot and users must edit
// vigolium-configs.yaml to switch model/auth.
func TestAutopilotOliumOverrideFlagsRegistered(t *testing.T) {
	flags := agentAutopilotCmd.Flags()
	for _, name := range []string{"model", "system-prompt", "system-prompt-file", "oauth-cred", "llm-api-key"} {
		assert.NotNilf(t, flags.Lookup(name),
			"--%s must be registered on `vigolium agent autopilot` to mirror `vigolium agent olium`",
			name)
	}
}

// TestFirstNonEmptyString_CLIWinsOverConfig documents the override semantics
// for the four olium flags: a non-empty CLI flag must take precedence over
// the agent.olium.* config field. firstNonEmptyString is the single point of
// truth for this — if this test fails, autopilot will silently ignore CLI
// flags whenever the corresponding config field is set.
func TestFirstNonEmptyString_CLIWinsOverConfig(t *testing.T) {
	assert.Equal(t, "from-cli", firstNonEmptyString("from-cli", "from-config"),
		"non-empty CLI flag must beat config")
	assert.Equal(t, "from-config", firstNonEmptyString("", "from-config"),
		"empty CLI flag must fall through to config")
	assert.Equal(t, "", firstNonEmptyString("", ""),
		"both empty must return empty (lets ResolveProvider auto-detect)")
	assert.Equal(t, "from-cli", firstNonEmptyString("   ", "from-cli", "from-config"),
		"whitespace-only is treated as empty")
}

// TestAutopilotPrescanFlagsRegistered guards the operator-facing surface for
// the target-only pre-scan: the --no-prescan flag must exist and the
// --intensity long help must mention the pre-scan so users discover it.
func TestAutopilotPrescanFlagsRegistered(t *testing.T) {
	flags := agentAutopilotCmd.Flags()
	assert.NotNil(t, flags.Lookup("no-prescan"),
		"--no-prescan must be registered so operators can opt out of the pre-scan")
	assert.Contains(t, agentAutopilotCmd.Long, "Pre-scan",
		"the --intensity long help must document the pre-scan behavior")
}

// TestBuildPrescanInstruction_Gating locks each suppression path. Real scans
// would land here only when every gate passes; the test uses target=""/repo=nil
// so runner.LaunchScan is never reached. (We intentionally don't test the
// success path: it requires a live HTTP target and SQLite repo, which belongs
// in test/e2e under -tags=e2e, not a fast unit test.)
func TestBuildPrescanInstruction_Gating(t *testing.T) {
	saveTarget := autopilotTarget
	saveNo := autopilotNoPrescan
	saveIntensity := autopilotIntensity
	t.Cleanup(func() {
		autopilotTarget = saveTarget
		autopilotNoPrescan = saveNo
		autopilotIntensity = saveIntensity
	})
	autopilotIntensity = "balanced"

	// --no-prescan suppresses regardless of other state.
	autopilotNoPrescan = true
	autopilotTarget = "https://example.com"
	assert.Empty(t, buildPrescanInstruction(context.Background(), nil, ""),
		"--no-prescan must suppress the pre-scan")

	// Empty target suppresses (source-only autopilot path takes over via
	// resolveAutopilotAuditCfg before this helper is called, but defense-
	// in-depth: a stray invocation with empty target stays a no-op).
	autopilotNoPrescan = false
	autopilotTarget = "   "
	assert.Empty(t, buildPrescanInstruction(context.Background(), nil, ""),
		"empty/whitespace target must suppress the pre-scan")

	// nil repo suppresses (results would have nowhere to land).
	autopilotTarget = "https://example.com"
	assert.Empty(t, buildPrescanInstruction(context.Background(), nil, ""),
		"missing repo must suppress the pre-scan")
}

// TestFormatPrescanContext_ShapeContract ensures the agent-facing summary
// keeps its three load-bearing properties: the scan UUID is present (so the
// agent can pull structured data via list_findings), counts are surfaced,
// and the agent is steered toward correlation-style follow-up via
// run_extension. If any of these drift, the agent loses the affordance.
func TestFormatPrescanContext_ShapeContract(t *testing.T) {
	out := formatPrescanContext(&runner.LaunchResult{
		ScanUUID:      "scan-uuid-abc",
		TotalRequests: 42,
		FindingCount:  7,
		Critical:      1, High: 2, Medium: 1, Low: 1, Info: 1, Suspect: 1,
	})
	assert.Contains(t, out, "scan-uuid-abc", "scan UUID must be cited so list_findings works")
	assert.Contains(t, out, "42", "request count must be surfaced")
	assert.Contains(t, out, "list_findings", "agent must be steered toward structured queries")
	assert.Contains(t, out, "run_extension", "agent must be steered toward correlation extensions")
	assert.True(t, strings.HasPrefix(out, "**Pre-scan context:"),
		"summary must lead with the Pre-scan label so the agent recognizes it")
}
