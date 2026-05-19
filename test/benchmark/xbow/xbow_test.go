//go:build xbow

package xbow

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/test/benchmark/harness"
)

// TestXbow_All runs all xbow benchmark definitions.
func TestXbow_All(t *testing.T) {
	defs := loadXbowDefinitions(t)
	for _, def := range defs {
		t.Run(def.App.Name, func(t *testing.T) {
			runXbowDefinition(t, def)
		})
	}
}

// TestXbow_XSS runs only xbow-xss-*.yaml definitions.
func TestXbow_XSS(t *testing.T) {
	runXbowByPrefix(t, "xbow-xss-")
}

// TestXbow_SSTI runs only xbow-ssti-*.yaml definitions.
func TestXbow_SSTI(t *testing.T) {
	runXbowByPrefix(t, "xbow-ssti-")
}

// TestXbow_SQLi runs only xbow-sqli-*.yaml definitions.
func TestXbow_SQLi(t *testing.T) {
	runXbowByPrefix(t, "xbow-sqli-")
}

// TestXbow_CmdI runs only xbow-cmdi-*.yaml definitions.
func TestXbow_CmdI(t *testing.T) {
	runXbowByPrefix(t, "xbow-cmdi-")
}

// TestXbow_LFI runs only xbow-lfi-*.yaml definitions.
func TestXbow_LFI(t *testing.T) {
	runXbowByPrefix(t, "xbow-lfi-")
}

// TestXbow_SSRF runs only xbow-ssrf-*.yaml definitions.
func TestXbow_SSRF(t *testing.T) {
	runXbowByPrefix(t, "xbow-ssrf-")
}

// TestXbow_XXE runs only xbow-xxe-*.yaml definitions.
func TestXbow_XXE(t *testing.T) {
	runXbowByPrefix(t, "xbow-xxe-")
}

// runXbowByPrefix runs all xbow definitions whose filename matches the given prefix.
func runXbowByPrefix(t *testing.T, prefix string) {
	t.Helper()
	defs := loadXbowDefinitions(t)

	var matched int
	for _, def := range defs {
		if !strings.HasPrefix(def.App.Name, prefix) {
			continue
		}
		matched++
		t.Run(def.App.Name, func(t *testing.T) {
			runXbowDefinition(t, def)
		})
	}

	if matched == 0 {
		t.Skipf("No xbow definitions found matching prefix %q", prefix)
	}
}

// loadXbowDefinitions loads all YAML definitions from the xbow subdirectory.
func loadXbowDefinitions(t *testing.T) []*harness.BenchmarkDefinition {
	t.Helper()

	// Verify XBOW_SOURCE_DIR is set
	sourceDir := os.Getenv("XBOW_SOURCE_DIR")
	if sourceDir == "" {
		t.Skip("XBOW_SOURCE_DIR not set; skipping xbow benchmarks")
	}
	if _, err := os.Stat(sourceDir); err != nil {
		t.Skipf("XBOW_SOURCE_DIR %s not accessible: %v", sourceDir, err)
	}

	xbowDefDir := filepath.Join(harness.DefinitionsDir(), "xbow")
	defs, err := harness.LoadDefinitionsFromDir(xbowDefDir)
	require.NoError(t, err, "Failed to load xbow definitions from %s", xbowDefDir)
	require.NotEmpty(t, defs, "No xbow definitions found in %s", xbowDefDir)

	return defs
}

// runXbowDefinition starts a compose stack and runs all test cases for one benchmark.
func runXbowDefinition(t *testing.T, def *harness.BenchmarkDefinition) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// Start the compose stack
	app, err := harness.StartAppFromDefinition(ctx, def.App)
	if err != nil {
		t.Fatalf("Failed to start %s: %v", def.App.Name, err)
	}
	defer func() {
		if stopErr := app.Stop(); stopErr != nil {
			t.Logf("Warning: failed to stop %s: %v", def.App.Name, stopErr)
		}
	}()

	t.Logf("%s running at %s", def.App.Name, app.BaseURL)

	// Setup test infrastructure
	infra, err := harness.SetupTestInfra()
	require.NoError(t, err, "Failed to setup test infrastructure")
	defer infra.Cleanup()

	// Run all active test cases
	var totalResults []harness.TestResult
	for _, tc := range def.TestCases {
		if tc.ScanMode != "active" {
			continue
		}

		t.Run(tc.ID, func(t *testing.T) {
			results := harness.RunActiveTestCase(t, tc, app.BaseURL, infra)
			totalResults = append(totalResults, results...)
		})
	}

	// Summary
	passed := 0
	totalFindings := 0
	for _, r := range totalResults {
		if r.Passed {
			passed++
		}
		totalFindings += r.FindingCount
	}
	t.Logf("=== %s XBOW Benchmark: %d/%d passed, %d findings ===",
		def.App.Name, passed, len(totalResults), totalFindings)
}
