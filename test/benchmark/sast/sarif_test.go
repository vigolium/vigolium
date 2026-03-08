//go:build sast

package sast

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/toolexec/sourcetools"
	"github.com/vigolium/vigolium/test/benchmark/harness"
)

// TestSARIF_All loads all SARIF definitions and runs each.
func TestSARIF_All(t *testing.T) {
	dir := filepath.Join(definitionsDir(), "sarif")
	defs, err := harness.LoadSASTSARIFDefinitionsFromDir(dir)
	require.NoError(t, err, "failed to load SARIF definitions")
	require.NotEmpty(t, defs, "no SARIF definitions found in %s", dir)

	for _, def := range defs {
		t.Run(def.Fixture, func(t *testing.T) {
			runSARIFDefinition(t, def)
		})
	}
}

func TestSARIF_Semgrep_Normal(t *testing.T) {
	runSARIFForFixture(t, "semgrep-normal.yaml")
}

func TestSARIF_Semgrep_Multirule(t *testing.T) {
	runSARIFForFixture(t, "semgrep-multirule.yaml")
}

func TestSARIF_Trivy_Normal(t *testing.T) {
	runSARIFForFixture(t, "trivy-normal.yaml")
}

func TestSARIF_Trivy_Multirule(t *testing.T) {
	runSARIFForFixture(t, "trivy-multirule.yaml")
}

func TestSARIF_EdgeCases(t *testing.T) {
	runSARIFForFixture(t, "sarif-edge-cases.yaml")
}

// TestSARIF_Empty validates zero-finding handling.
func TestSARIF_Empty(t *testing.T) {
	fixtures := []struct {
		name     string
		toolName string
	}{
		{"semgrep-empty.sarif", "semgrep"},
		{"trivy-empty.sarif", "trivy"},
	}

	for _, tc := range fixtures {
		t.Run(tc.name, func(t *testing.T) {
			data, err := os.ReadFile(sarifFixturePath(tc.name))
			require.NoError(t, err)

			findings, err := sourcetools.ParseSARIF(data, tc.toolName)
			require.NoError(t, err)
			assert.Empty(t, findings, "expected 0 findings for empty fixture %s", tc.name)
		})
	}
}

// TestSARIF_Malformed validates error returns for bad input.
func TestSARIF_Malformed(t *testing.T) {
	t.Run("missing_runs_key", func(t *testing.T) {
		data, err := os.ReadFile(sarifFixturePath("sarif-malformed-1.json"))
		require.NoError(t, err)

		findings, err := sourcetools.ParseSARIF(data, "test")
		// ParseSARIF should succeed but return 0 findings (no runs)
		require.NoError(t, err)
		assert.Empty(t, findings, "expected 0 findings from malformed SARIF with no runs")
	})

	t.Run("invalid_json", func(t *testing.T) {
		data, err := os.ReadFile(sarifFixturePath("sarif-malformed-2.json"))
		require.NoError(t, err)

		_, err = sourcetools.ParseSARIF(data, "test")
		assert.Error(t, err, "expected error from invalid JSON")
	})
}

// TestSARIF_SeverityMapping validates SARIF level to severity mapping.
func TestSARIF_SeverityMapping(t *testing.T) {
	data, err := os.ReadFile(sarifFixturePath("sarif-severity-mapping.sarif"))
	require.NoError(t, err)

	findings, err := sourcetools.ParseSARIF(data, "test-tool")
	require.NoError(t, err)
	require.Len(t, findings, 4, "expected 4 findings for severity mapping fixture")

	expectedMapping := map[string]string{
		"sev-error":   "high",
		"sev-warning": "medium",
		"sev-note":    "low",
		"sev-none":    "info",
	}

	for ruleID, expectedSev := range expectedMapping {
		f := findFinding(findings, ruleID)
		require.NotNil(t, f, "finding %q not found", ruleID)
		assert.Equal(t, expectedSev, f.Severity, "SARIF level mapping for %q: expected %q, got %q",
			ruleID, expectedSev, f.Severity)
	}
}

// TestSARIF_ToFinding validates sourcetools.ToFinding produces correct fields.
func TestSARIF_ToFinding(t *testing.T) {
	raw := sourcetools.RawFinding{
		RuleID:    "test-rule-001",
		Message:   "Test finding message",
		Severity:  "high",
		FilePath:  "src/app.py",
		StartLine: 42,
		EndLine:   44,
		ToolName:  "semgrep",
	}

	finding := sourcetools.ToFinding(raw, nil)

	assert.Equal(t, "sourcetools/semgrep", finding.ModuleID)
	assert.Contains(t, finding.Tags, "source-aware")
	assert.Contains(t, finding.Tags, "semgrep")
	assert.Equal(t, "firm", finding.Confidence)
	assert.Equal(t, "high", finding.Severity)
	assert.Contains(t, finding.MatchedAt, "src/app.py:42-44")
	assert.NotEmpty(t, finding.FindingHash, "FindingHash should not be empty")
	assert.Empty(t, finding.HTTPRecordUUIDs, "source findings should have no HTTP record UUIDs")
}

func runSARIFForFixture(t *testing.T, filename string) {
	t.Helper()
	defPath := filepath.Join(definitionsDir(), "sarif", filename)
	def, err := harness.LoadSASTSARIFDefinition(defPath)
	require.NoError(t, err, "failed to load SARIF definition %s", filename)
	runSARIFDefinition(t, def)
}

func runSARIFDefinition(t *testing.T, def *harness.SASTSARIFDefinition) {
	t.Helper()

	fixturePath := sarifFixturePath(def.Fixture)
	data, err := os.ReadFile(fixturePath)
	require.NoError(t, err, "failed to read fixture %s", fixturePath)

	var findings []sourcetools.RawFinding
	var parseErr error

	switch def.Format {
	case "sarif":
		findings, parseErr = sourcetools.ParseSARIF(data, def.ToolName)
	case "semgrep-json":
		findings, parseErr = sourcetools.ParseSemgrepOutput(data)
	case "trivy-json":
		findings, parseErr = sourcetools.ParseTrivyOutput(data)
	default:
		findings, parseErr = sourcetools.ParseSARIF(data, def.ToolName)
	}

	if def.Expected.Error {
		assert.Error(t, parseErr, "[%s] expected parse error", def.Fixture)
		return
	}
	require.NoError(t, parseErr, "[%s] unexpected parse error", def.Fixture)

	t.Logf("[%s] Parsed %d findings", def.Fixture, len(findings))
	for _, f := range findings {
		t.Logf("  Finding: rule=%s severity=%s file=%s line=%d", f.RuleID, f.Severity, f.FilePath, f.StartLine)
	}

	// Validate finding count
	assert.Equal(t, def.Expected.FindingCount, len(findings),
		"[%s] expected %d findings, got %d", def.Fixture, def.Expected.FindingCount, len(findings))

	// Validate specific findings
	for _, ef := range def.Expected.Findings {
		f := findFinding(findings, ef.RuleID)
		if !assert.NotNil(t, f, "[%s] expected finding %q not found", def.Fixture, ef.RuleID) {
			continue
		}
		if ef.Severity != "" {
			assert.Equal(t, ef.Severity, f.Severity,
				"[%s] finding %q severity mismatch", def.Fixture, ef.RuleID)
		}
		if ef.FilePath != "" {
			assert.Equal(t, ef.FilePath, f.FilePath,
				"[%s] finding %q file path mismatch", def.Fixture, ef.RuleID)
		}
		if ef.StartLine > 0 {
			assert.Equal(t, ef.StartLine, f.StartLine,
				"[%s] finding %q start line mismatch", def.Fixture, ef.RuleID)
		}
	}

	// Validate severity distribution
	if len(def.Expected.SeverityDistribution) > 0 {
		actual := buildSeverityDistribution(findings)
		for sev, expectedCount := range def.Expected.SeverityDistribution {
			assert.Equal(t, expectedCount, actual[sev],
				"[%s] severity %q: expected %d, got %d", def.Fixture, sev, expectedCount, actual[sev])
		}
	}
}
