package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vigolium/vigolium/pkg/archon"
)

func TestCopySkillsToSessionDir_EmptyDir(t *testing.T) {
	// Should not panic with empty session dir
	CopySkillsToSessionDir("", false)
	CopySkillsToSessionDir("", true)
}

func TestCopySkillsToSessionDir_VigoliumScannerAlwaysCopied(t *testing.T) {
	sessionDir := t.TempDir()

	CopySkillsToSessionDir(sessionDir, false)

	// vigolium-scanner should always be copied
	skillPath := filepath.Join(sessionDir, "skills", "vigolium-scanner", "SKILL.md")
	if _, err := os.Stat(skillPath); err != nil {
		t.Errorf("vigolium-scanner SKILL.md should exist, got error: %v", err)
	}

	// agent-browser should NOT be copied when browserEnabled is false
	browserSkillPath := filepath.Join(sessionDir, "skills", "agent-browser", "SKILL.md")
	if _, err := os.Stat(browserSkillPath); err == nil {
		t.Error("agent-browser SKILL.md should NOT exist when browserEnabled is false")
	}
}

func TestCopySkillsToSessionDir_BrowserEnabled(t *testing.T) {
	sessionDir := t.TempDir()

	CopySkillsToSessionDir(sessionDir, true)

	// vigolium-scanner should be copied
	scannerSkill := filepath.Join(sessionDir, "skills", "vigolium-scanner", "SKILL.md")
	if _, err := os.Stat(scannerSkill); err != nil {
		t.Errorf("vigolium-scanner SKILL.md should exist: %v", err)
	}

	// agent-browser should be copied when browserEnabled is true
	browserSkill := filepath.Join(sessionDir, "skills", "agent-browser", "SKILL.md")
	if _, err := os.Stat(browserSkill); err != nil {
		t.Errorf("agent-browser SKILL.md should exist when browserEnabled is true: %v", err)
	}

	// Verify references subdirectory is also copied
	refsDir := filepath.Join(sessionDir, "skills", "agent-browser", "references")
	entries, err := os.ReadDir(refsDir)
	if err != nil {
		t.Fatalf("agent-browser references dir should exist: %v", err)
	}
	if len(entries) == 0 {
		t.Error("agent-browser references dir should contain files")
	}
}

func TestCopySkillsToSessionDir_Idempotent(t *testing.T) {
	sessionDir := t.TempDir()

	CopySkillsToSessionDir(sessionDir, true)
	CopySkillsToSessionDir(sessionDir, true)

	skillPath := filepath.Join(sessionDir, "skills", "vigolium-scanner", "SKILL.md")
	if _, err := os.Stat(skillPath); err != nil {
		t.Errorf("SKILL.md should exist after double copy: %v", err)
	}
}

func TestExtractArchonHarness(t *testing.T) {
	baseDir := filepath.Join(t.TempDir(), "archon-audit")

	pluginDir, err := archon.ExtractArchonHarness(baseDir)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if pluginDir == "" {
		t.Fatal("expected non-empty plugin dir")
	}

	// Verify archon commands exist
	deepCmd := filepath.Join(pluginDir, "commands", "archon", "deep.md")
	if _, err := os.Stat(deepCmd); err != nil {
		t.Errorf("expected deep.md command to be extracted: %v", err)
	}

	liteCmd := filepath.Join(pluginDir, "commands", "archon", "lite.md")
	if _, err := os.Stat(liteCmd); err != nil {
		t.Errorf("expected lite.md command to be extracted: %v", err)
	}

	// Verify agents exist
	agentsDir := filepath.Join(pluginDir, "agents")
	entries, err := os.ReadDir(agentsDir)
	if err != nil {
		t.Fatalf("expected agents dir to exist: %v", err)
	}
	if len(entries) < 20 {
		t.Errorf("expected 20+ agents, got %d", len(entries))
	}

	// Verify plugin.json was extracted
	pluginJSON := filepath.Join(pluginDir, ".claude-plugin", "plugin.json")
	if _, err := os.Stat(pluginJSON); err != nil {
		t.Errorf("expected plugin.json to be extracted: %v", err)
	}

	// Verify marker file (per-platform: .extracted-claude)
	marker := filepath.Join(baseDir, ".extracted-claude")
	markerData, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("expected marker file: %v", err)
	}
	if len(markerData) == 0 {
		t.Error("marker file should contain a version hash")
	}
}

func TestExtractArchonHarness_Idempotent(t *testing.T) {
	baseDir := filepath.Join(t.TempDir(), "archon-audit")

	dir1, err1 := archon.ExtractArchonHarness(baseDir)
	if err1 != nil {
		t.Fatal(err1)
	}

	dir2, err2 := archon.ExtractArchonHarness(baseDir)
	if err2 != nil {
		t.Fatal(err2)
	}

	if dir1 != dir2 {
		t.Errorf("expected same dir on second call, got %q vs %q", dir1, dir2)
	}
}

func TestExtractArchonHarness_Codex(t *testing.T) {
	baseDir := filepath.Join(t.TempDir(), "archon-audit")

	pluginDir, err := archon.ExtractArchonHarnessForPlatform(baseDir, archon.PlatformCodex)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if pluginDir == "" {
		t.Fatal("expected non-empty plugin dir")
	}

	// Verify agents are .toml files (codex format)
	agentsDir := filepath.Join(pluginDir, "agents")
	entries, err := os.ReadDir(agentsDir)
	if err != nil {
		t.Fatalf("expected agents dir to exist: %v", err)
	}
	if len(entries) < 15 {
		t.Errorf("expected 15+ codex agents, got %d", len(entries))
	}
	// Check that at least one is .toml
	foundToml := false
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".toml" {
			foundToml = true
			break
		}
	}
	if !foundToml {
		t.Error("expected .toml agent files for codex platform")
	}

	// Verify AGENTS.md dispatch block was written
	agentsMD := filepath.Join(pluginDir, "AGENTS.md")
	if _, err := os.Stat(agentsMD); err != nil {
		t.Errorf("expected AGENTS.md dispatch block for codex: %v", err)
	}

	// Verify per-platform marker
	marker := filepath.Join(baseDir, ".extracted-codex")
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("expected codex marker file: %v", err)
	}

	// Excluded agents should NOT be present
	excluded := filepath.Join(agentsDir, "cold-verifier.toml")
	if _, err := os.Stat(excluded); err == nil {
		t.Error("cold-verifier should be excluded from codex")
	}
}

func TestExtractArchonHarness_OpenCode(t *testing.T) {
	baseDir := filepath.Join(t.TempDir(), "archon-audit")

	pluginDir, err := archon.ExtractArchonHarnessForPlatform(baseDir, archon.PlatformOpenCode)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if pluginDir == "" {
		t.Fatal("expected non-empty plugin dir")
	}

	// Verify agents are .md files (opencode uses same format as claude)
	agentsDir := filepath.Join(pluginDir, "agents")
	entries, err := os.ReadDir(agentsDir)
	if err != nil {
		t.Fatalf("expected agents dir to exist: %v", err)
	}
	if len(entries) < 20 {
		t.Errorf("expected 20+ opencode agents, got %d", len(entries))
	}

	// Verify per-platform marker
	marker := filepath.Join(baseDir, ".extracted-opencode")
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("expected opencode marker file: %v", err)
	}

	// OpenCode has no plugin.json or AGENTS.md
	pluginJSON := filepath.Join(pluginDir, ".claude-plugin", "plugin.json")
	if _, err := os.Stat(pluginJSON); err == nil {
		t.Error("opencode should not have .claude-plugin/plugin.json")
	}
}

func TestExtractArchonHarness_MultiPlatformCoexist(t *testing.T) {
	baseDir := filepath.Join(t.TempDir(), "archon-audit")

	// Extract claude first, then codex — markers should coexist
	_, err1 := archon.ExtractArchonHarnessForPlatform(baseDir, archon.PlatformClaude)
	if err1 != nil {
		t.Fatal(err1)
	}
	_, err2 := archon.ExtractArchonHarnessForPlatform(baseDir, archon.PlatformCodex)
	if err2 != nil {
		t.Fatal(err2)
	}

	// Both markers should exist
	if _, err := os.Stat(filepath.Join(baseDir, ".extracted-claude")); err != nil {
		t.Error("expected claude marker")
	}
	if _, err := os.Stat(filepath.Join(baseDir, ".extracted-codex")); err != nil {
		t.Error("expected codex marker")
	}
}

func TestExtractArchonHarness_EmptyBaseDir(t *testing.T) {
	_, err := archon.ExtractArchonHarness("")
	if err == nil {
		t.Error("expected error for empty baseDir")
	}
}
