package autopilot

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/olium/skill"
)

func TestLogSkillsLoaded(t *testing.T) {
	tmp := t.TempDir()
	mk := func(scope, name string) {
		dir := filepath.Join(tmp, scope, "skills", name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		body := "---\nname: " + name + "\ndescription: " + name + "\n---\nbody"
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk(".agents", "agents-skill")
	mk(".claude", "claude-skill")

	reg, err := skill.Load(skill.LoadOptions{WorkingDir: tmp})
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	var buf bytes.Buffer
	logSkillsLoaded(&buf, reg)
	out := buf.String()

	for _, want := range []string{
		"loaded 2 skills",
		"project-agents: 1",
		"project-claude: 1",
		"agents-skill (project-agents)",
		"claude-skill (project-claude)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- got ---\n%s", want, out)
		}
	}
}

func TestLogSkillsLoadedEmpty(t *testing.T) {
	var buf bytes.Buffer
	logSkillsLoaded(&buf, nil)
	if got := strings.TrimSpace(buf.String()); got != "[autopilot] loaded 0 skills" {
		t.Fatalf("got %q", got)
	}
}
