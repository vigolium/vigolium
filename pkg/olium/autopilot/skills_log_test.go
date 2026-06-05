package autopilot

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/olium/skill"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// loadTmpSkills writes one SKILL.md per (scope, name) pair under a temp dir and
// loads them into a registry. scope is ".agents" or ".claude".
func loadTmpSkills(t *testing.T, pairs ...[2]string) *skill.Registry {
	t.Helper()
	tmp := t.TempDir()
	for _, p := range pairs {
		scope, name := p[0], p[1]
		dir := filepath.Join(tmp, scope, "skills", name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		body := "---\nname: " + name + "\ndescription: " + name + "\n---\nbody"
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	reg, err := skill.Load(skill.LoadOptions{WorkingDir: tmp})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return reg
}

func TestLogSkillsLoaded(t *testing.T) {
	reg := loadTmpSkills(t, [2]string{".agents", "agents-skill"}, [2]string{".claude", "claude-skill"})

	var buf bytes.Buffer
	logSkillsLoaded(&buf, reg)
	out := terminal.StripANSI(buf.String())

	// Shows the total and a per-source COUNT breakdown.
	for _, want := range []string{
		"loaded 2 skills",
		"project-agents: 1",
		"project-claude: 1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- got ---\n%s", want, out)
		}
	}
	// Skill NAMES must not be enumerated here — they belong on the selected
	// line only. The old "project/user skills:" line is gone.
	for _, absent := range []string{"agents-skill", "claude-skill", "project/user skills"} {
		if strings.Contains(out, absent) {
			t.Errorf("output should not list skill names, but contains %q\n--- got ---\n%s", absent, out)
		}
	}
}

func TestLogSkillsLoadedEmpty(t *testing.T) {
	var buf bytes.Buffer
	logSkillsLoaded(&buf, nil)
	if got := strings.TrimSpace(terminal.StripANSI(buf.String())); got != "❯ autopilot │ loaded 0 skills" {
		t.Fatalf("got %q", got)
	}
}

func TestLogSkillsSelected(t *testing.T) {
	all := loadTmpSkills(t,
		[2]string{".agents", "alpha"},
		[2]string{".agents", "bravo"},
		[2]string{".claude", "charlie"},
	)
	selected, _ := all.Select(skill.SelectOptions{Picks: []string{"alpha", "charlie"}})

	var buf bytes.Buffer
	logSkillsSelected(&buf, all, selected)
	out := terminal.StripANSI(buf.String())

	if !strings.Contains(out, "selected 2 of 3 skills for this target:") {
		t.Errorf("missing selection header\n--- got ---\n%s", out)
	}
	// Names appear only here.
	for _, name := range []string{"alpha", "charlie"} {
		if !strings.Contains(out, name) {
			t.Errorf("selected line missing %q\n--- got ---\n%s", name, out)
		}
	}
	if strings.Contains(out, "bravo") {
		t.Errorf("unselected skill 'bravo' should not appear\n--- got ---\n%s", out)
	}
}

// TestLogSkillsSelectedWraps verifies the name list wraps at skillsPerLine per
// continuation line, each line re-stamped with the phase prefix.
func TestLogSkillsSelectedWraps(t *testing.T) {
	all := loadTmpSkills(t,
		[2]string{".agents", "s1"}, [2]string{".agents", "s2"}, [2]string{".agents", "s3"},
		[2]string{".agents", "s4"}, [2]string{".agents", "s5"}, [2]string{".agents", "s6"},
		[2]string{".agents", "s7"}, [2]string{".claude", "extra1"}, [2]string{".claude", "extra2"},
	)
	selected, _ := all.Select(skill.SelectOptions{Picks: []string{"s1", "s2", "s3", "s4", "s5", "s6", "s7"}})

	var buf bytes.Buffer
	logSkillsSelected(&buf, all, selected)
	lines := strings.Split(strings.TrimRight(terminal.StripANSI(buf.String()), "\n"), "\n")

	// Header + ceil(7/4) = 2 wrapped lines.
	if len(lines) != 3 {
		t.Fatalf("expected header + 2 wrapped lines, got %d:\n%s", len(lines), buf.String())
	}
	if !strings.Contains(lines[0], "selected 7 of 9 skills for this target:") {
		t.Errorf("bad header line: %q", lines[0])
	}
	for _, l := range lines[1:] {
		if !strings.Contains(l, "❯ autopilot │") {
			t.Errorf("continuation line missing phase prefix: %q", l)
		}
		body := strings.TrimSpace(strings.SplitN(l, "│", 2)[1])
		n := len(strings.Split(strings.TrimRight(body, ","), ", "))
		if n > skillsPerLine {
			t.Errorf("line has %d skills (> %d per line): %q", n, skillsPerLine, l)
		}
	}
}

// TestLogSkillsSelectedNoFilter: when nothing was filtered out (selected ==
// all), the line is suppressed so unfiltered runs stay quiet.
func TestLogSkillsSelectedNoFilter(t *testing.T) {
	all := loadTmpSkills(t, [2]string{".agents", "alpha"}, [2]string{".agents", "bravo"})

	var buf bytes.Buffer
	logSkillsSelected(&buf, all, all)
	if got := buf.String(); got != "" {
		t.Errorf("expected no output when selected == all, got %q", got)
	}
}

func TestLogSkillsTip(t *testing.T) {
	reg := loadTmpSkills(t, [2]string{".agents", "alpha"})

	t.Run("shows flags by default", func(t *testing.T) {
		var buf bytes.Buffer
		logSkillsTip(&buf, Options{}, reg)
		out := terminal.StripANSI(buf.String())
		for _, want := range []string{"ϟ Tip:", "--skill <name>", "--skill-tag <tag>", "--no-skill-filter"} {
			if !strings.Contains(out, want) {
				t.Errorf("tip missing %q\n--- got ---\n%s", want, out)
			}
		}
	})

	// An explicit override means the operator already knows the knobs — no hint.
	overrides := map[string]Options{
		"--no-skill-filter": {NoSkillFilter: true},
		"--skill":           {SkillNames: []string{"alpha"}},
		"--skill-tag":       {SkillTags: []string{"xss"}},
	}
	for name, opts := range overrides {
		t.Run("suppressed with "+name, func(t *testing.T) {
			var buf bytes.Buffer
			logSkillsTip(&buf, opts, reg)
			if got := buf.String(); got != "" {
				t.Errorf("expected no tip with %s override, got %q", name, got)
			}
		})
	}

	t.Run("suppressed when no skills loaded", func(t *testing.T) {
		var buf bytes.Buffer
		logSkillsTip(&buf, Options{}, nil)
		if got := buf.String(); got != "" {
			t.Errorf("expected no tip when no skills loaded, got %q", got)
		}
	})
}
