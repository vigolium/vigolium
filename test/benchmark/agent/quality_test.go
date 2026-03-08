//go:build agent_benchmark

package agent

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/test/benchmark/harness"
)

// TestQuality_All loads all quality definitions and runs each.
func TestQuality_All(t *testing.T) {
	dir := filepath.Join(definitionsDir(), "quality")
	defs, err := harness.LoadAgentQualityDefinitionsFromDir(dir)
	require.NoError(t, err, "failed to load quality definitions")
	require.NotEmpty(t, defs, "no quality definitions found in %s", dir)

	for _, def := range defs {
		t.Run(def.Fixture, func(t *testing.T) {
			runQualityDefinition(t, def)
		})
	}
}

func TestQuality_GinSecurityReview(t *testing.T) {
	runQualityForFixture(t, "gin-security-review-quality.yaml")
}

func TestQuality_FlaskSecurityReview(t *testing.T) {
	runQualityForFixture(t, "flask-security-review-quality.yaml")
}

func TestQuality_ExpressSecurityReview(t *testing.T) {
	runQualityForFixture(t, "express-security-review-quality.yaml")
}

func TestQuality_DjangoSecurityReview(t *testing.T) {
	runQualityForFixture(t, "django-security-review-quality.yaml")
}

func TestQuality_FastAPISecurityReview(t *testing.T) {
	runQualityForFixture(t, "fastapi-security-review-quality.yaml")
}

func runQualityForFixture(t *testing.T, filename string) {
	t.Helper()
	defPath := filepath.Join(definitionsDir(), "quality", filename)
	def, err := harness.LoadAgentQualityDefinition(defPath)
	require.NoError(t, err, "failed to load quality definition %s", filename)
	runQualityDefinition(t, def)
}

func runQualityDefinition(t *testing.T, def *harness.AgentQualityDefinition) {
	t.Helper()

	fPath := fixturePath(def.Fixture)
	fixture, err := harness.LoadAgentFixture(fPath)
	require.NoError(t, err, "failed to load fixture %s", fPath)

	findings, parseErr := agent.ParseFindings(fixture.RawOutput)
	require.NoError(t, parseErr, "[%s] failed to parse findings", def.Fixture)

	soft := def.Assertion == "soft"
	assertFn := assertStrict
	if soft {
		assertFn = assertSoft
	}

	t.Logf("[%s] %d findings (assertion=%s)", def.Fixture, len(findings), def.Assertion)

	// Validate finding count range
	if def.Expected.MinFindings > 0 {
		assertFn(t, len(findings) >= def.Expected.MinFindings,
			"[%s] expected at least %d findings, got %d", def.Fixture, def.Expected.MinFindings, len(findings))
	}
	if def.Expected.MaxFindings > 0 {
		assertFn(t, len(findings) <= def.Expected.MaxFindings,
			"[%s] expected at most %d findings, got %d", def.Fixture, def.Expected.MaxFindings, len(findings))
	}

	// Validate expected CWEs
	for _, cwe := range def.Expected.ExpectedCWEs {
		found := findFindingByCWE(findings, cwe)
		assertFn(t, found != nil,
			"[%s] expected CWE %s not found in findings", def.Fixture, cwe)
		if found != nil {
			t.Logf("[%s] Found CWE %s: %q", def.Fixture, cwe, found.Title)
		}
	}

	// Validate expected vuln types
	for _, vt := range def.Expected.ExpectedVulnTypes {
		found := findFindingByVulnType(findings, vt)
		assertFn(t, found != nil,
			"[%s] expected vuln type %q not found in findings", def.Fixture, vt)
		if found != nil {
			t.Logf("[%s] Found vuln type %q: %q", def.Fixture, vt, found.Title)
		}
	}

	// Validate severity distribution
	if len(def.Expected.SeverityDistribution) > 0 {
		actual := buildSeverityDistribution(findings)
		t.Logf("[%s] Severity distribution: %v", def.Fixture, actual)
		for sev, expectedMin := range def.Expected.SeverityDistribution {
			assertFn(t, actual[sev] >= expectedMin,
				"[%s] severity %q: expected at least %d, got %d", def.Fixture, sev, expectedMin, actual[sev])
		}
	}
}

// assertStrict fails the test on false condition.
func assertStrict(t *testing.T, condition bool, msgAndArgs ...interface{}) {
	t.Helper()
	assert.True(t, condition, msgAndArgs...)
}

// assertSoft logs a warning on false condition but does not fail the test.
func assertSoft(t *testing.T, condition bool, msgAndArgs ...interface{}) {
	t.Helper()
	if !condition {
		t.Logf("SOFT ASSERTION FAILED: "+msgAndArgs[0].(string), msgAndArgs[1:]...)
	}
}
