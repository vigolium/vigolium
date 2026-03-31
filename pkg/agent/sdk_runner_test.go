package agent

import (
	"strings"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	agentprompt "github.com/vigolium/vigolium/pkg/agent/prompt"
)

// TestEngineSDKCase_AutopilotConfig stays in the root agent package because it
// calls LoadSDKAutopilotSystemPrompt which lives here (not in backend).
func TestEngineSDKCase_AutopilotConfig(t *testing.T) {
	// Verify that autopilot SDK config sets high MaxTurns, effort, and system prompt
	agentDef := config.AgentDef{Command: "claude", Protocol: "sdk"}

	cfg := sdkRunConfig{}

	// Simulate what engine.go does for autopilot
	maxCommands := 100
	cfg.MaxTurns = maxCommands * 3
	if cfg.MaxTurns <= 0 {
		cfg.MaxTurns = 300
	}
	cfg.Effort = "high"
	sysPrompt, source := agentprompt.LoadSDKAutopilotSystemPrompt()
	cfg.AppendSystemPrompt = sysPrompt
	cfg.SystemPromptSource = source

	opts := buildSDKOptions(agentDef, cfg)

	if opts.MaxTurns != 300 {
		t.Errorf("MaxTurns: got %d, want 300", opts.MaxTurns)
	}
	if opts.Effort != "high" {
		t.Errorf("Effort: got %q, want high", opts.Effort)
	}
	// System prompt should be passed either inline or via CLAUDE.md (depending on SystemPromptDir)
	if !strings.Contains(sysPrompt, "vigolium") {
		t.Error("system prompt should contain vigolium context")
	}
}
