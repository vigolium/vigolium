package archon

import (
	"strings"
	"testing"
)

func TestParseCanonicalAgent(t *testing.T) {
	content := []byte("---\ndescription: Test agent\n---\nBody content here.\n")
	agent, err := ParseCanonicalAgent("test-agent.md", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if agent.Basename != "test-agent" {
		t.Errorf("expected basename 'test-agent', got %q", agent.Basename)
	}
	if agent.Description != "Test agent" {
		t.Errorf("expected description 'Test agent', got %q", agent.Description)
	}
	if !strings.Contains(agent.Body, "Body content") {
		t.Errorf("expected body to contain 'Body content', got %q", agent.Body)
	}
}

func TestBuildPlatformAgent_Claude(t *testing.T) {
	agent := &CanonicalAgent{
		Basename:    "advisory-hunter",
		Description: "Hunt advisories",
		Body:        "Do the thing.\n",
	}
	cfg := &HarnessConfig{
		Format: "md",
		Defaults: map[string]any{
			"tools": "Glob, Grep, Read",
			"model": "sonnet",
		},
		Overrides: map[string]map[string]any{
			"advisory-hunter": {
				"tools": "Glob, Grep, Read, WebSearch",
				"color": "cyan",
			},
		},
	}

	output, err := BuildPlatformAgent(agent, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	s := string(output)
	if !strings.HasPrefix(s, "---\n") {
		t.Error("expected YAML frontmatter prefix")
	}
	if !strings.Contains(s, "name: advisory-hunter") {
		t.Error("expected name in frontmatter")
	}
	if !strings.Contains(s, "WebSearch") {
		t.Error("expected overridden tools")
	}
	if !strings.Contains(s, "cyan") {
		t.Error("expected color override")
	}
	if !strings.Contains(s, "Do the thing.") {
		t.Error("expected body content")
	}
}

func TestBuildCodexAgent(t *testing.T) {
	agent := &CanonicalAgent{
		Basename:    "probe-strategist",
		Description: "Plan the probe",
		Body:        "Execute the probe plan.\n",
	}
	cfg := &HarnessConfig{
		Format:          "toml",
		AgentNamePrefix: "archon:",
		Defaults: map[string]any{
			"model":        "gpt5.2",
			"sandbox_mode": "workspace-write",
		},
		Overrides: map[string]map[string]any{},
	}

	output, err := BuildCodexAgent(agent, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	s := string(output)
	if !strings.Contains(s, `name = "archon:probe-strategist"`) {
		t.Errorf("expected TOML name field, got:\n%s", s)
	}
	if !strings.Contains(s, `description = "Plan the probe"`) {
		t.Error("expected description")
	}
	if !strings.Contains(s, `model = "gpt5.2"`) {
		t.Error("expected model field")
	}
	if !strings.Contains(s, `sandbox_mode = "workspace-write"`) {
		t.Error("expected sandbox_mode field")
	}
	if !strings.Contains(s, "system_prompt") {
		t.Error("expected system_prompt block")
	}
	if !strings.Contains(s, "Execute the probe plan.") {
		t.Error("expected body in system_prompt")
	}
}

func TestBuildCodexAgent_WithOverride(t *testing.T) {
	agent := &CanonicalAgent{
		Basename:    "static-analyzer",
		Description: "Run SAST",
		Body:        "Analyze code.\n",
	}
	cfg := &HarnessConfig{
		Format:          "toml",
		AgentNamePrefix: "archon:",
		Defaults: map[string]any{
			"model":        "gpt5.2",
			"sandbox_mode": "workspace-write",
		},
		Overrides: map[string]map[string]any{
			"static-analyzer": {
				"sandbox_mode": "danger-full-access",
			},
		},
	}

	output, err := BuildCodexAgent(agent, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	s := string(output)
	if !strings.Contains(s, `sandbox_mode = "danger-full-access"`) {
		t.Error("expected overridden sandbox_mode")
	}
}

func TestIsExcluded(t *testing.T) {
	cfg := &HarnessConfig{
		Exclude: []string{"code-anatomist", "cold-verifier"},
		Overrides: map[string]map[string]any{
			"deep-auditor": {"exclude": true},
		},
	}

	if !IsExcluded("code-anatomist", cfg) {
		t.Error("expected code-anatomist to be excluded via list")
	}
	if !IsExcluded("deep-auditor", cfg) {
		t.Error("expected deep-auditor to be excluded via override")
	}
	if IsExcluded("advisory-hunter", cfg) {
		t.Error("expected advisory-hunter to NOT be excluded")
	}
}

func TestAgentExtension(t *testing.T) {
	toml := &HarnessConfig{Format: "toml"}
	if got := toml.AgentExtension(); got != ".toml" {
		t.Errorf("expected .toml, got %q", got)
	}

	md := &HarnessConfig{Format: "md"}
	if got := md.AgentExtension(); got != ".md" {
		t.Errorf("expected .md, got %q", got)
	}

	empty := &HarnessConfig{}
	if got := empty.AgentExtension(); got != ".md" {
		t.Errorf("expected .md for empty format, got %q", got)
	}
}

func TestRenameStrings(t *testing.T) {
	input := "vig-run:deep is run from ~/.vig-audit-agent/"
	got := RenameStrings(input)
	if strings.Contains(got, "vig-run") {
		t.Errorf("expected vig-run to be replaced, got %q", got)
	}
	if !strings.Contains(got, "archon:deep") {
		t.Errorf("expected archon:deep, got %q", got)
	}
}

func TestLoadHarnessConfig(t *testing.T) {
	data := []byte(`format: toml
agent_name_prefix: "archon:"
defaults:
  model: "gpt5.2"
exclude:
  - code-anatomist
overrides:
  static-analyzer:
    sandbox_mode: "danger-full-access"
`)

	cfg, err := LoadHarnessConfig(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Format != "toml" {
		t.Errorf("expected format 'toml', got %q", cfg.Format)
	}
	if cfg.AgentNamePrefix != "archon:" {
		t.Errorf("expected prefix 'archon:', got %q", cfg.AgentNamePrefix)
	}
	if len(cfg.Exclude) != 1 || cfg.Exclude[0] != "code-anatomist" {
		t.Errorf("expected exclude [code-anatomist], got %v", cfg.Exclude)
	}
}
