package autopilot

import (
	"strings"
	"testing"
)

// namedProvider satisfies the structural interface isClaudeCodeProvider
// accepts. It deliberately doesn't pull in the full provider.Provider
// surface so the test doesn't need to mock Stream.
type namedProvider struct{ name string }

func (n namedProvider) Name() string { return n.name }

func TestIsClaudeCodeProvider(t *testing.T) {
	if !isClaudeCodeProvider(namedProvider{name: "claude-code"}) {
		t.Error("expected claude-code provider to be detected")
	}
	if isClaudeCodeProvider(namedProvider{name: "anthropic-api-key"}) {
		t.Error("anthropic-api-key should not be claude-code")
	}
	if isClaudeCodeProvider(nil) {
		t.Error("nil provider should not be claude-code")
	}
}

func TestClaudeCodeSystemPromptDocumentsProtocol(t *testing.T) {
	body, src := loadClaudeCodeSystemPromptBase()
	if !strings.Contains(body, "<<<VIG:FINDING>>>") {
		t.Errorf("claude-code prompt (%s) missing FINDING sentinel doc", src)
	}
	if !strings.Contains(body, "<<<VIG:HALT>>>") {
		t.Errorf("claude-code prompt (%s) missing HALT sentinel doc", src)
	}
	if strings.Contains(body, "report_finding tool") {
		t.Errorf("claude-code prompt (%s) still references engine-level report_finding tool", src)
	}
	if strings.Contains(body, "halt_scan tool") {
		t.Errorf("claude-code prompt (%s) still references engine-level halt_scan tool", src)
	}
	// Mention of vigolium scan-url confirms the prompt teaches the model
	// to use Bash + vigolium CLI for systematic scans.
	if !strings.Contains(body, "vigolium scan-url") {
		t.Errorf("claude-code prompt (%s) missing `vigolium scan-url` guidance", src)
	}
}

func TestDefaultSystemPromptStillReferencesEngineTools(t *testing.T) {
	body, src := loadSystemPromptBase()
	if !strings.Contains(body, "report_finding") {
		t.Errorf("default prompt (%s) lost report_finding reference", src)
	}
	if strings.Contains(body, "<<<VIG:FINDING>>>") {
		t.Errorf("default prompt (%s) accidentally adopted claude-code sentinel doc", src)
	}
}
