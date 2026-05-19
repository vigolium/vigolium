//go:build canary

package coverage

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/test/benchmark/harness"
)

// TestBenchmark_CoverageReport generates a module coverage matrix report.
// This test does not require Docker — it only analyzes YAML definitions.
func TestBenchmark_CoverageReport(t *testing.T) {
	defDir := harness.DefinitionsDir()

	report, err := harness.GenerateCoverageReport(defDir)
	require.NoError(t, err, "Failed to generate coverage report")

	// Output coverage report
	markdown := harness.FormatCoverageMarkdown(report)
	t.Log(markdown)

	// Write report to file if output directory is writable
	reportPath := filepath.Join(defDir, "..", "coverage-report.md")
	if err := os.WriteFile(reportPath, []byte(markdown), 0644); err != nil {
		t.Logf("Could not write coverage report to %s: %v", reportPath, err)
	} else {
		t.Logf("Coverage report written to %s", reportPath)
	}

	// Assert minimum coverage thresholds
	t.Logf("Active modules: %d/%d (%.0f%%)",
		report.CoveredActive, report.TotalActive,
		float64(report.CoveredActive)/float64(report.TotalActive)*100)
	t.Logf("Passive modules: %d/%d (%.0f%%)",
		report.CoveredPassive, report.TotalPassive,
		float64(report.CoveredPassive)/float64(report.TotalPassive)*100)
	t.Logf("Total test cases: %d", report.TotalTestCases)

	// After all phases, we should have meaningful coverage
	assert.Greater(t, report.CoveredActive, 0, "Should have at least some active module coverage")
	assert.Greater(t, report.CoveredPassive, 0, "Should have at least some passive module coverage")
	assert.Greater(t, report.TotalTestCases, 0, "Should have at least some test cases")
}
