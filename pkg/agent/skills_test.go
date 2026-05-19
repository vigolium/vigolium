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

	CopySkillsToSessionDir(sessionDir, true)
	CopySkillsToSessionDir(sessionDir, true)

	skillPath := filepath.Join(sessionDir, "skills", "vigolium-scanner", "SKILL.md")
	if _, err := os.Stat(skillPath); err != nil {
		t.Errorf("SKILL.md should exist after double copy: %v", err)
	}
}
