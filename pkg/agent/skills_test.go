package agent

import (
	"os"
	"path/filepath"
	"testing"
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

	// Copy twice — should not error
	CopySkillsToSessionDir(sessionDir, true)
	CopySkillsToSessionDir(sessionDir, true)

	// Files should still exist
	skillPath := filepath.Join(sessionDir, "skills", "vigolium-scanner", "SKILL.md")
	if _, err := os.Stat(skillPath); err != nil {
		t.Errorf("SKILL.md should exist after double copy: %v", err)
	}
}

func TestExtractAuditAgentPlugin(t *testing.T) {
	baseDir := filepath.Join(t.TempDir(), "vig-audit-agent")

	pluginDir, err := extractAuditAgentTo(baseDir)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if pluginDir == "" {
		t.Fatal("expected non-empty plugin dir")
	}

	// Verify the plugin commands exist
	runCmd := filepath.Join(pluginDir, "commands", "vig-run", "run.md")
	if _, err := os.Stat(runCmd); err != nil {
		t.Errorf("expected run.md command to be extracted: %v", err)
	}

	liteCmd := filepath.Join(pluginDir, "commands", "vig-run", "lite.md")
	if _, err := os.Stat(liteCmd); err != nil {
		t.Errorf("expected lite.md command to be extracted: %v", err)
	}

	// Verify agents exist
	agentsDir := filepath.Join(pluginDir, "agents")
	entries, err := os.ReadDir(agentsDir)
	if err != nil {
		t.Fatalf("expected agents dir to exist: %v", err)
	}
	if len(entries) == 0 {
		t.Error("expected agents to be extracted")
	}

	// Verify audit skill was extracted
	auditSkill := filepath.Join(baseDir, "skills", "audit", "SKILL.md")
	if _, err := os.Stat(auditSkill); err != nil {
		t.Errorf("expected audit SKILL.md to be extracted: %v", err)
	}

	// Verify marker file contains a hash (not empty)
	marker := filepath.Join(baseDir, ".extracted")
	markerData, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("expected marker file: %v", err)
	}
	if len(markerData) == 0 {
		t.Error("marker file should contain a version hash")
	}
}

func TestExtractAuditAgentPlugin_Idempotent(t *testing.T) {
	baseDir := filepath.Join(t.TempDir(), "vig-audit-agent")

	dir1, err1 := extractAuditAgentTo(baseDir)
	if err1 != nil {
		t.Fatal(err1)
	}

	dir2, err2 := extractAuditAgentTo(baseDir)
	if err2 != nil {
		t.Fatal(err2)
	}

	if dir1 != dir2 {
		t.Errorf("expected same dir on second call, got %q vs %q", dir1, dir2)
	}
}

func TestExtractAuditAgentPlugin_EmptyBaseDir(t *testing.T) {
	dir, err := extractAuditAgentTo("")
	if err != nil {
		t.Fatalf("expected no error for empty baseDir, got: %v", err)
	}
	if dir != "" {
		t.Errorf("expected empty dir for empty baseDir, got %q", dir)
	}
}
