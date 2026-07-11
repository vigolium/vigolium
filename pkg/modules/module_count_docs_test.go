package modules

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"testing"
)

// docsWithModuleCounts lists the repo-root-relative docs that state the total
// active/passive module counts in prose. The counts drift whenever modules are
// added or removed, so this contract test reads the documented numbers back and
// asserts they equal the live registry — forcing docs to be updated alongside a
// module change instead of silently going stale. Example CLI output (e.g.
// docs/api-references/scan.md) is deliberately excluded: it reports a single
// scan's module selection, not the registry total.
var docsWithModuleCounts = []string{
	"README.md",
	"HACKING.md",
	"CLAUDE.md",
	"docs/native-scan/modules-reference.md",
	"docs/architecture/overview.md",
}

// moduleCountSentence matches an "<N> active ... <M> passive" pair within a
// single sentence/line (no period or newline between the two numbers), covering
// the phrasings the docs use: "201 active and 116 passive", "201 active + 116
// passive", "201 active, 116 passive", and "201 Active / 116 Passive".
var moduleCountSentence = regexp.MustCompile(`(?i)(\d+)\s+active\b[^.\n|]*?\b(\d+)\s+passive`)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("cannot resolve caller path")
	}
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not locate repo root (go.mod) from %s", file)
		}
		dir = parent
	}
}

// TestDocumentedModuleCountsMatchRegistry keeps the docs' stated active/passive
// module counts in lockstep with the live registry.
func TestDocumentedModuleCountsMatchRegistry(t *testing.T) {
	wantActive := DefaultRegistry.ActiveModuleCount()
	wantPassive := DefaultRegistry.PassiveModuleCount()
	root := repoRoot(t)

	matched := 0
	for _, rel := range docsWithModuleCounts {
		path := filepath.Join(root, rel)
		content, err := os.ReadFile(path)
		if err != nil {
			t.Logf("skipping %s: %v", rel, err)
			continue
		}
		found := moduleCountSentence.FindAllStringSubmatch(string(content), -1)
		if len(found) == 0 {
			t.Errorf("%s: no '<N> active ... <M> passive' module-count sentence found; "+
				"either it drifted out of the expected phrasing or the count line was removed", rel)
			continue
		}
		for _, m := range found {
			matched++
			gotActive, _ := strconv.Atoi(m[1])
			gotPassive, _ := strconv.Atoi(m[2])
			if gotActive != wantActive || gotPassive != wantPassive {
				t.Errorf("%s: documented counts %d active / %d passive != live registry %d active / %d passive "+
					"(update the doc, or the registry changed) — matched text: %q",
					rel, gotActive, gotPassive, wantActive, wantPassive, m[0])
			}
		}
	}
	if matched == 0 {
		t.Fatalf("no module-count sentences were checked in any doc; the contract test is a no-op")
	}
}
