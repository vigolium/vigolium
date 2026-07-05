package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadBundledSkills(t *testing.T) {
	skills, err := loadBundledSkills()
	if err != nil {
		t.Fatalf("loadBundledSkills: %v", err)
	}
	if len(skills) == 0 {
		t.Fatal("expected at least one bundled skill")
	}

	byName := map[string]bundledSkill{}
	for _, s := range skills {
		byName[s.Name] = s
	}

	// The flagship scanner skill must always be present with metadata.
	vs, ok := byName[defaultInstallSkill]
	if !ok {
		t.Fatalf("bundled skills missing %q: got %v", defaultInstallSkill, byName)
	}
	if vs.Description == "" {
		t.Error("vigolium-scanner description should be non-empty")
	}
	if len(vs.References) == 0 {
		t.Error("vigolium-scanner should expose reference files")
	}

	if vs.ThirdParty {
		t.Error("vigolium-scanner must be first-party")
	}

	// agent-browser uses the comma-string allowed-tools form that skill.Parse
	// rejects; the lenient fallback must still recover its description.
	if ab, ok := byName["agent-browser"]; ok {
		if ab.Description == "" {
			t.Error("agent-browser description should be recovered via lenient parse")
		}
		if !ab.ThirdParty {
			t.Error("agent-browser must be classified third-party")
		}
	}
}

func TestVisibleBundles(t *testing.T) {
	skills := []bundledSkill{
		{Name: "vigolium-scanner"},
		{Name: "agent-browser", ThirdParty: true},
	}

	defer func(prev bool) { skillsOpts.ThirdParty = prev }(skillsOpts.ThirdParty)

	// Default: third-party hidden.
	skillsOpts.ThirdParty = false
	visible, hidden := visibleBundles(skills)
	if len(visible) != 1 || visible[0].Name != "vigolium-scanner" {
		t.Errorf("default visible = %+v, want only vigolium-scanner", visible)
	}
	if hidden != 1 {
		t.Errorf("hidden = %d, want 1", hidden)
	}

	// Opted in: all shown, none hidden.
	skillsOpts.ThirdParty = true
	visible, hidden = visibleBundles(skills)
	if len(visible) != 2 {
		t.Errorf("with flag, visible = %d, want 2", len(visible))
	}
	if hidden != 0 {
		t.Errorf("with flag, hidden = %d, want 0", hidden)
	}
}

func TestSkillsInstallBaseDir(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("home: %v", err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("cwd: %v", err)
	}

	tests := []struct {
		agent, scope string
		want         string
	}{
		{"claude", "project", filepath.Join(cwd, ".claude", "skills")},
		{"claude", "global", filepath.Join(home, ".claude", "skills")},
		{"codex", "project", filepath.Join(cwd, ".agents", "skills")},
		{"codex", "global", filepath.Join(home, ".agents", "skills")},
		{"agents", "project", filepath.Join(cwd, ".agents", "skills")},
		{"AGENTS", "GLOBAL", filepath.Join(home, ".agents", "skills")}, // case-insensitive
	}
	for _, tt := range tests {
		got, err := skillsInstallBaseDir(tt.agent, tt.scope)
		if err != nil {
			t.Errorf("skillsInstallBaseDir(%q,%q): %v", tt.agent, tt.scope, err)
			continue
		}
		if got != tt.want {
			t.Errorf("skillsInstallBaseDir(%q,%q) = %q, want %q", tt.agent, tt.scope, got, tt.want)
		}
	}

	if _, err := skillsInstallBaseDir("nope", "project"); err == nil {
		t.Error("expected error for unknown agent")
	}
	if _, err := skillsInstallBaseDir("claude", "nope"); err == nil {
		t.Error("expected error for unknown scope")
	}
}

func TestCopyEmbeddedSkillBundle(t *testing.T) {
	skills, err := loadBundledSkills()
	if err != nil {
		t.Fatalf("loadBundledSkills: %v", err)
	}
	vs, ok := findBundle(skills, defaultInstallSkill)
	if !ok {
		t.Fatalf("missing %q", defaultInstallSkill)
	}

	dest := filepath.Join(t.TempDir(), vs.Name)
	if err := copyEmbeddedSkillBundle(vs.EmbedDir, dest); err != nil {
		t.Fatalf("copyEmbeddedSkillBundle: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dest, "SKILL.md")); err != nil {
		t.Errorf("SKILL.md not copied: %v", err)
	}
	for _, ref := range vs.References {
		if _, err := os.Stat(filepath.Join(dest, ref)); err != nil {
			t.Errorf("reference %s not copied: %v", ref, err)
		}
	}
}

func TestLenientFrontmatter(t *testing.T) {
	raw := []byte("---\nname: demo\ndescription: A demo skill\nallowed-tools: Bash(x:*), Bash(y:*)\n---\n\n# body\n")
	name, desc := lenientFrontmatter(raw)
	if name != "demo" {
		t.Errorf("name = %q, want demo", name)
	}
	if desc != "A demo skill" {
		t.Errorf("description = %q, want 'A demo skill'", desc)
	}

	if n, d := lenientFrontmatter([]byte("no frontmatter here")); n != "" || d != "" {
		t.Errorf("expected empty for no frontmatter, got (%q,%q)", n, d)
	}
}

func TestFindBundleCaseInsensitive(t *testing.T) {
	skills := []bundledSkill{{Name: "vigolium-scanner"}, {Name: "agent-browser"}}
	if _, ok := findBundle(skills, "VIGOLIUM-SCANNER"); !ok {
		t.Error("findBundle should be case-insensitive")
	}
	if _, ok := findBundle(skills, "missing"); ok {
		t.Error("findBundle should not match a missing name")
	}
	if got := bundleNames(skills); !strings.Contains(got, "vigolium-scanner") || !strings.Contains(got, "agent-browser") {
		t.Errorf("bundleNames = %q", got)
	}
}
