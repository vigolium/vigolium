package harness

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// softCaseBudget is the number of soft benchmark cases allowed. Soft cases
// never fail, so the count is a ratchet: converting a soft case to strict or
// negative must lower this constant (TestDefinitionsLint fails when the count
// drops below it, so the budget cannot silently stay loose).
const softCaseBudget = 155

// allBenchmarkDefinitions loads every YAML benchmark definition (top level and
// one directory down: blackbox/, xbow/). Files without test cases (whitebox
// agent/extraction/handoff specs use their own formats) are skipped.
func allBenchmarkDefinitions(t *testing.T) map[string]*BenchmarkDefinition {
	t.Helper()

	dir := testDefinitionsDir()
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	require.NoError(t, err)
	nested, err := filepath.Glob(filepath.Join(dir, "*", "*.yaml"))
	require.NoError(t, err)
	files = append(files, nested...)
	sort.Strings(files)

	out := make(map[string]*BenchmarkDefinition)
	for _, f := range files {
		def, err := LoadDefinition(f)
		if err != nil || len(def.TestCases) == 0 {
			continue
		}
		rel, _ := filepath.Rel(dir, f)
		out[rel] = def
	}
	require.NotEmpty(t, out, "no benchmark definitions found under %s", dir)
	return out
}

// TestDefinitionsLint is the static gate on benchmark definitions. It needs no
// Docker: every case must name modules that exist, use a known assertion, and
// soft cases must say why they are soft.
func TestDefinitionsLint(t *testing.T) {
	soft := 0
	seen := make(map[string]string)

	for file, def := range allBenchmarkDefinitions(t) {
		for _, tc := range def.TestCases {
			where := file + ":" + tc.ID

			if prev, dup := seen[tc.ID]; dup {
				t.Errorf("%s: duplicate case id (also in %s)", where, prev)
			}
			seen[tc.ID] = file

			if len(tc.Modules) == 0 {
				t.Errorf("%s: no modules", where)
			}
			var err error
			switch tc.ScanMode {
			case "active":
				_, err = ResolveActiveModules(tc.Modules)
			case "passive":
				_, err = ResolvePassiveModules(tc.Modules)
			default:
				t.Errorf("%s: unknown scan_mode %q", where, tc.ScanMode)
			}
			if err != nil {
				t.Errorf("%s: %v", where, err)
			}

			switch tc.Assertion {
			case "strict":
			case "negative":
				if tc.ExpectedFindings != nil {
					t.Errorf("%s: expected_findings on a negative case", where)
				}
			case "soft":
				soft++
				if strings.TrimSpace(tc.SoftReason) == "" {
					t.Errorf("%s: soft case without soft_reason", where)
				}
				if tc.ExpectedFindings != nil {
					t.Errorf("%s: expected_findings on a soft case (make it strict)", where)
				}
			default:
				t.Errorf("%s: unknown assertion %q (want strict, negative or soft)", where, tc.Assertion)
			}
			if tc.Assertion != "soft" && tc.SoftReason != "" {
				t.Errorf("%s: soft_reason on a %s case", where, tc.Assertion)
			}
		}
	}

	if soft > softCaseBudget {
		t.Errorf("%d soft cases exceed the budget of %d: add strict or negative cases instead", soft, softCaseBudget)
	}
	if soft < softCaseBudget {
		t.Errorf("%d soft cases, budget is %d: lower softCaseBudget to %d", soft, softCaseBudget, soft)
	}
}

func TestDefinitionsLint_HasNegativeCases(t *testing.T) {
	negatives := 0
	for _, def := range allBenchmarkDefinitions(t) {
		for _, tc := range def.TestCases {
			if tc.Assertion == "negative" {
				negatives++
			}
		}
	}
	assert.Positive(t, negatives, "benchmark definitions need negative (must-not-fire) cases")
}
