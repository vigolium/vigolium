//go:build canary

package whitebox

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/test/benchmark/harness"
)

// TestWhitebox_Passive runs all passive module benchmark tests from YAML definitions
// against Docker-based vulnerable applications.
func TestWhitebox_Passive(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping benchmark test in short mode")
	}

	defDir := filepath.Join(harness.DefinitionsDir())
	defs, err := harness.LoadDefinitionsFromDir(defDir)
	require.NoError(t, err, "Failed to load benchmark definitions")
	require.NotEmpty(t, defs, "No benchmark definitions found in %s", defDir)

	for _, def := range defs {
		if def.App.Type != "docker" {
			continue
		}

		t.Run(def.App.Name, func(t *testing.T) {
			runPassiveDefinition(t, def)
		})
	}
}

// TestWhitebox_DVWA_Passive runs DVWA passive module benchmarks.
func TestWhitebox_DVWA_Passive(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping benchmark test in short mode")
	}

	defPath := filepath.Join(harness.DefinitionsDir(), "dvwa.yaml")
	def, err := harness.LoadDefinition(defPath)
	require.NoError(t, err, "Failed to load DVWA definition")

	runPassiveDefinition(t, def)
}

// TestWhitebox_VAmPI_Passive runs VAmPI passive module benchmarks.
func TestWhitebox_VAmPI_Passive(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping benchmark test in short mode")
	}

	defPath := filepath.Join(harness.DefinitionsDir(), "vampi.yaml")
	def, err := harness.LoadDefinition(defPath)
	require.NoError(t, err, "Failed to load VAmPI definition")

	runPassiveDefinition(t, def)
}

// TestWhitebox_JuiceShop_Passive runs Juice Shop passive module benchmarks.
func TestWhitebox_JuiceShop_Passive(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping benchmark test in short mode")
	}

	defPath := filepath.Join(harness.DefinitionsDir(), "juiceshop.yaml")
	def, err := harness.LoadDefinition(defPath)
	require.NoError(t, err, "Failed to load Juice Shop definition")

	runPassiveDefinition(t, def)
}

// TestWhitebox_VulnerableJava_Passive runs DataDog vulnerable-java passive module benchmarks.
func TestWhitebox_VulnerableJava_Passive(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping benchmark test in short mode")
	}

	defPath := filepath.Join(harness.DefinitionsDir(), "vulnerable-java.yaml")
	def, err := harness.LoadDefinition(defPath)
	require.NoError(t, err, "Failed to load vulnerable-java definition")

	runPassiveDefinition(t, def)
}

// TestWhitebox_VulnerableNginx_Passive runs detectify vulnerable-nginx passive module benchmarks.
func TestWhitebox_VulnerableNginx_Passive(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping benchmark test in short mode")
	}

	defPath := filepath.Join(harness.DefinitionsDir(), "vulnerable-nginx.yaml")
	def, err := harness.LoadDefinition(defPath)
	require.NoError(t, err, "Failed to load vulnerable-nginx definition")

	runPassiveDefinition(t, def)
}

// TestWhitebox_OopssecStore_Passive runs oss-oopssec-store (Next.js) passive module benchmarks.
func TestWhitebox_OopssecStore_Passive(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping benchmark test in short mode")
	}

	defPath := filepath.Join(harness.DefinitionsDir(), "oopssec-store.yaml")
	def, err := harness.LoadDefinition(defPath)
	require.NoError(t, err, "Failed to load oopssec-store definition")

	runPassiveDefinition(t, def)
}

// TestWhitebox_NextJSVulnExamples_Passive runs upleveled/security-vulnerability-examples (Next.js) passive module benchmarks.
func TestWhitebox_NextJSVulnExamples_Passive(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping benchmark test in short mode")
	}

	defPath := filepath.Join(harness.DefinitionsDir(), "nextjs-vulnexamples.yaml")
	def, err := harness.LoadDefinition(defPath)
	require.NoError(t, err, "Failed to load nextjs-vulnexamples definition")

	runPassiveDefinition(t, def)
}

// runPassiveDefinition starts a container and runs all passive test cases.
func runPassiveDefinition(t *testing.T, def *harness.BenchmarkDefinition) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Start container
	app, err := harness.StartAppFromDefinition(ctx, def.App)
	require.NoError(t, err, "Failed to start %s", def.App.Name)
	defer func() { _ = app.Stop() }()

	t.Logf("%s running at %s", def.App.Name, app.BaseURL)

	// Perform app-specific auth/setup (e.g., DVWA DB init + login)
	authHeaders, err := harness.SetupAppAuth(t, def.App.Name, app.BaseURL)
	if err != nil {
		t.Logf("Warning: auth setup for %s failed: %v", def.App.Name, err)
	}

	// Setup test infrastructure
	infra, err := harness.SetupTestInfra()
	require.NoError(t, err, "Failed to setup test infrastructure")
	defer infra.Cleanup()

	// Filter and run passive test cases
	var totalResults []harness.TestResult
	for _, tc := range def.TestCases {
		if tc.ScanMode != "passive" {
			continue
		}

		// Inject auth headers into test case
		tc.Headers = harness.MergeHeaders(authHeaders, tc.Headers)

		t.Run(tc.ID, func(t *testing.T) {
			results := harness.RunPassiveTestCase(t, tc, app.BaseURL, infra)
			totalResults = append(totalResults, results...)
		})
	}

	// Summary
	passed := 0
	for _, r := range totalResults {
		if r.Passed {
			passed++
		}
	}
	t.Logf("=== %s Passive Benchmark Summary: %d/%d passed ===",
		def.App.Name, passed, len(totalResults))
}
