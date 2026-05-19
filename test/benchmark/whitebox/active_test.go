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

// TestWhitebox_Active runs all active module benchmark tests from YAML definitions
// against Docker-based vulnerable applications.
func TestWhitebox_Active(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping benchmark test in short mode")
	}

	defDir := filepath.Join(harness.DefinitionsDir())
	defs, err := harness.LoadDefinitionsFromDir(defDir)
	require.NoError(t, err, "Failed to load benchmark definitions")
	require.NotEmpty(t, defs, "No benchmark definitions found in %s", defDir)

	for _, def := range defs {
		// Only run Docker-based apps in whitebox tests
		if def.App.Type != "docker" {
			continue
		}

		t.Run(def.App.Name, func(t *testing.T) {
			runActiveDefinition(t, def)
		})
	}
}

// TestWhitebox_DVWA_Active runs DVWA active module benchmarks.
func TestWhitebox_DVWA_Active(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping benchmark test in short mode")
	}

	defPath := filepath.Join(harness.DefinitionsDir(), "dvwa.yaml")
	def, err := harness.LoadDefinition(defPath)
	require.NoError(t, err, "Failed to load DVWA definition")

	runActiveDefinition(t, def)
}

// TestWhitebox_VAmPI_Active runs VAmPI active module benchmarks.
func TestWhitebox_VAmPI_Active(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping benchmark test in short mode")
	}

	defPath := filepath.Join(harness.DefinitionsDir(), "vampi.yaml")
	def, err := harness.LoadDefinition(defPath)
	require.NoError(t, err, "Failed to load VAmPI definition")

	runActiveDefinition(t, def)
}

// TestWhitebox_JuiceShop_Active runs Juice Shop active module benchmarks.
func TestWhitebox_JuiceShop_Active(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping benchmark test in short mode")
	}

	defPath := filepath.Join(harness.DefinitionsDir(), "juiceshop.yaml")
	def, err := harness.LoadDefinition(defPath)
	require.NoError(t, err, "Failed to load Juice Shop definition")

	runActiveDefinition(t, def)
}

// TestWhitebox_VulnerableJava_Active runs DataDog vulnerable-java active module benchmarks.
func TestWhitebox_VulnerableJava_Active(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping benchmark test in short mode")
	}

	defPath := filepath.Join(harness.DefinitionsDir(), "vulnerable-java.yaml")
	def, err := harness.LoadDefinition(defPath)
	require.NoError(t, err, "Failed to load vulnerable-java definition")

	runActiveDefinition(t, def)
}

// TestWhitebox_VulnerableNginx_Active runs detectify vulnerable-nginx active module benchmarks.
func TestWhitebox_VulnerableNginx_Active(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping benchmark test in short mode")
	}

	defPath := filepath.Join(harness.DefinitionsDir(), "vulnerable-nginx.yaml")
	def, err := harness.LoadDefinition(defPath)
	require.NoError(t, err, "Failed to load vulnerable-nginx definition")

	runActiveDefinition(t, def)
}

// TestWhitebox_OopssecStore_Active runs oss-oopssec-store (Next.js) active module benchmarks.
func TestWhitebox_OopssecStore_Active(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping benchmark test in short mode")
	}

	defPath := filepath.Join(harness.DefinitionsDir(), "oopssec-store.yaml")
	def, err := harness.LoadDefinition(defPath)
	require.NoError(t, err, "Failed to load oopssec-store definition")

	runActiveDefinition(t, def)
}

// TestWhitebox_NextJSVulnExamples_Active runs upleveled/security-vulnerability-examples (Next.js) active module benchmarks.
func TestWhitebox_NextJSVulnExamples_Active(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping benchmark test in short mode")
	}

	defPath := filepath.Join(harness.DefinitionsDir(), "nextjs-vulnexamples.yaml")
	def, err := harness.LoadDefinition(defPath)
	require.NoError(t, err, "Failed to load nextjs-vulnexamples definition")

	runActiveDefinition(t, def)
}

// runActiveDefinition starts a container and runs all active test cases.
func runActiveDefinition(t *testing.T, def *harness.BenchmarkDefinition) {
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

	// Check if any test cases require OAST
	hasOAST := false
	for _, tc := range def.TestCases {
		if tc.RequiresOAST {
			hasOAST = true
			break
		}
	}

	// Setup test infrastructure (with or without OAST)
	var infra *harness.TestInfra
	var oastMock *harness.MockOASTProvider
	if hasOAST {
		infra, oastMock, err = harness.SetupTestInfraWithOAST()
	} else {
		infra, err = harness.SetupTestInfra()
	}
	require.NoError(t, err, "Failed to setup test infrastructure")
	defer infra.Cleanup()

	// Filter and run active test cases
	var totalResults []harness.TestResult
	for _, tc := range def.TestCases {
		if tc.ScanMode != "active" {
			continue
		}

		// Inject auth headers into test case
		tc.Headers = harness.MergeHeaders(authHeaders, tc.Headers)

		t.Run(tc.ID, func(t *testing.T) {
			results := harness.RunActiveTestCase(t, tc, app.BaseURL, infra)
			totalResults = append(totalResults, results...)

			// Log OAST probe count for OAST test cases
			if tc.RequiresOAST && oastMock != nil {
				t.Logf("[%s] OAST probes generated: %d", tc.ID, oastMock.ProbeCount())
			}
		})
	}

	// Summary
	passed := 0
	for _, r := range totalResults {
		if r.Passed {
			passed++
		}
	}
	t.Logf("=== %s Active Benchmark Summary: %d/%d passed ===",
		def.App.Name, passed, len(totalResults))

	// Log total findings for visibility
	totalFindings := 0
	for _, r := range totalResults {
		totalFindings += r.FindingCount
	}
	t.Logf("Total findings from %s: %d", def.App.Name, totalFindings)
}
