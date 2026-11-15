package cli

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/public"
)

// skillBundleDir is the vigolium-scanner bundle inside public.StaticFS.
const skillBundleDir = embedSkillsRoot + "/vigolium-scanner"

// The committed flags.generated.md is what an agent greps to find out what
// exists; a stale copy makes a flag invisible. Rendering in-process replaces
// the `go run … skills gen-flags -o /tmp/…` diff (a full link of the binary and
// a shared /tmp path): `make skill-flags-check` now runs this test.
func TestFlagsGeneratedIsCurrent(t *testing.T) {
	prepareCommandTree(rootCmd)

	committed, err := public.StaticFS.ReadFile(skillBundleDir + "/references/flags.generated.md")
	if err != nil {
		t.Fatalf("read embedded flags.generated.md: %v", err)
	}
	rendered := renderFlagsReference(rootCmd)
	if string(committed) == rendered {
		return
	}

	want := strings.Split(rendered, "\n")
	got := strings.Split(string(committed), "\n")
	var diffs []string
	for i := 0; i < max(len(want), len(got)) && len(diffs) < 10; i++ {
		var w, g string
		if i < len(want) {
			w = want[i]
		}
		if i < len(got) {
			g = got[i]
		}
		if w != g {
			diffs = append(diffs, fmt.Sprintf("line %d:\n    committed: %s\n    generated: %s", i+1, g, w))
		}
	}
	t.Errorf("flags.generated.md is stale; run `make skill-flags` and commit the result. First differences:\n  %s",
		strings.Join(diffs, "\n  "))
}

// skillLineBudget caps SKILL.md, which every agent loads in full.
const skillLineBudget = 300

var skillReferenceLink = regexp.MustCompile(`references/([A-Za-z0-9_.-]+\.md)`)

// SKILL.md is the router: every reference file it names must ship, and every
// reference that ships must be reachable from it.
func TestSkillReferenceRouter(t *testing.T) {
	skill, err := public.StaticFS.ReadFile(skillBundleDir + "/SKILL.md")
	if err != nil {
		t.Fatalf("read SKILL.md: %v", err)
	}
	named := map[string]bool{}
	for _, m := range skillReferenceLink.FindAllStringSubmatch(string(skill), -1) {
		named[m[1]] = true
	}

	entries, err := fs.ReadDir(public.StaticFS, skillBundleDir+"/references")
	if err != nil {
		t.Fatalf("read references: %v", err)
	}
	shipped := map[string]bool{}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".md") {
			shipped[e.Name()] = true
		}
	}

	for name := range named {
		if !shipped[name] {
			t.Errorf("SKILL.md routes to references/%s, which is not in the embedded bundle", name)
		}
	}
	for name := range shipped {
		if !named[name] {
			t.Errorf("references/%s ships but SKILL.md never routes to it (orphan)", name)
		}
	}

	t.Run("line budget", func(t *testing.T) {
		// SKILL.md is always in context: it routes, it does not restate what
		// -h, `vigolium strategy -j` or `vigolium schema` can print.
		lines := strings.Count(string(skill), "\n")
		if lines > skillLineBudget {
			t.Errorf("SKILL.md is %d lines; budget is %d. Move detail into a reference (invariants.md, recipes.md, a loop-*.md step file)", lines, skillLineBudget)
		}
	})

	t.Run("no version-skew narration", func(t *testing.T) {
		// The installed skill is version-stamped (skills install manifest,
		// doctor's skill check), so "on older builds …" / "pre-v0.5.2 …" is
		// noise everywhere except invariants.md's History section.
		stale := regexp.MustCompile(`(?i)older build|pre-v\d`)
		_ = fs.WalkDir(public.StaticFS, skillBundleDir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".md") {
				return nil
			}
			data, _ := public.StaticFS.ReadFile(p)
			inHistory := false
			for i, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "## ") {
					inHistory = path.Base(p) == "invariants.md" && strings.TrimSpace(line) == "## History"
				}
				if stale.MatchString(line) && !inHistory {
					t.Errorf("%s:%d: version-skew narration belongs in references/invariants.md#history: %s", p, i+1, strings.TrimSpace(line))
				}
			}
			return nil
		})
	})
}

// referenceLineBudget caps a reference an agent loads in full. A reference
// is fetched one at a time (`skills get --ref`), so its size is what one hop
// costs. agent-loop.md is the one SKILL.md says to read first, so it gets
// less. The larger budgets are today's sizes of the per-command manuals: lower
// them when a file shrinks or splits, never raise them.
const referenceLineBudget = 500

var referenceLineBudgets = map[string]int{
	"agent-loop.md":  300,
	"invariants.md":  600,
	"auth.md":        600,
	"agent-modes.md": 1160,
	"extensions.md":  1080,
	"scanning.md":    1090,
	"data.md":        1980,
	// flags.generated.md is generated from the command tree and grepped, not read.
	"flags.generated.md": -1,
}

func TestSkillReferenceLineBudgets(t *testing.T) {
	entries, err := fs.ReadDir(public.StaticFS, skillBundleDir+"/references")
	if err != nil {
		t.Fatalf("read references: %v", err)
	}
	seen := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		seen[e.Name()] = true
		budget, ok := referenceLineBudgets[e.Name()]
		if !ok {
			budget = referenceLineBudget
		}
		if budget < 0 {
			continue
		}
		data, err := public.StaticFS.ReadFile(skillBundleDir + "/references/" + e.Name())
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		if lines := strings.Count(string(data), "\n"); lines > budget {
			t.Errorf("references/%s is %d lines; its budget is %d. Split it by topic and route to the parts from SKILL.md", e.Name(), lines, budget)
		}
	}
	for name := range referenceLineBudgets {
		if !seen[name] {
			t.Errorf("referenceLineBudgets names references/%s, which does not ship", name)
		}
	}
}

// presetConsumers says who reads each directory under public/presets/. A
// directory nothing reads is shipped weight that drifts unnoticed (the deleted
// agents-md preset documented commands that no longer existed). A "code"
// consumer must appear as a literal "presets/<dir>" in Go source; a "docs"
// consumer is example material that README.md or docs/ must point at.
var presetConsumers = map[string]string{
	"extensions": "code",
	"overlays":   "code", // --safe overlay (internal/runner/safe_preset.go)
	"profiles":   "code",
	"prompts":    "code",
	"sessions":   "docs", // auth-file examples, linked from README and the auth guide
}

func TestNoOrphanPresets(t *testing.T) {
	entries, err := fs.ReadDir(public.StaticFS, "presets")
	if err != nil {
		t.Fatalf("read presets: %v", err)
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e.Name())
		}
	}
	for _, d := range dirs {
		if _, ok := presetConsumers[d]; !ok {
			t.Errorf("public/presets/%s has no consumer in presetConsumers; wire a loader to it or delete it", d)
		}
	}
	for d := range presetConsumers {
		if !slices.Contains(dirs, d) {
			t.Errorf("presetConsumers names presets/%s, which does not exist", d)
		}
	}

	goSource := readRepoText(t, []string{"../../pkg", "../../internal", "../../cmd"}, ".go")
	docs := readRepoText(t, []string{"../../README.md", "../../docs"}, ".md")
	if goSource == "" {
		t.Skip("repository source not available")
	}
	for d, kind := range presetConsumers {
		needle := "presets/" + d
		switch kind {
		case "code":
			if !strings.Contains(goSource, `"`+needle) {
				t.Errorf("presets/%s is marked code-consumed but no Go source reads %q", d, needle)
			}
		case "docs":
			if docs != "" && !strings.Contains(docs, needle) {
				t.Errorf("presets/%s is marked doc-consumed but README.md/docs never mention %q", d, needle)
			}
		}
	}
}

// readRepoText concatenates every file with the suffix under roots (files or
// directories), skipping test files. Missing roots are ignored.
func readRepoText(t *testing.T, roots []string, suffix string) string {
	t.Helper()
	var b strings.Builder
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, suffix) || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			data, readErr := os.ReadFile(p)
			if readErr == nil {
				b.Write(data)
				b.WriteByte('\n')
			}
			return nil
		})
	}
	return b.String()
}
