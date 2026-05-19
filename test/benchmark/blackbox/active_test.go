//go:build blackbox

package blackbox

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/test/benchmark/harness"
)

// TestBlackbox_Active runs all active module benchmark tests against external sites.
// All assertions are soft — blackbox tests never block CI.
func TestBlackbox_Active(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping blackbox test in short mode")
	}

	defDir := filepath.Join(harness.DefinitionsDir(), "blackbox")
	defs, err := harness.LoadDefinitionsFromDir(defDir)
	require.NoError(t, err, "Failed to load blackbox definitions")

	if len(defs) == 0 {
		t.Skip("No blackbox definitions found")
	}

	for _, def := range defs {
		if def.App.Type != "external" {
			continue
		}

		t.Run(def.App.Name, func(t *testing.T) {
			runBlackboxActive(t, def)
		})
	}
}

// TestBlackbox_Acunetix_Active runs active benchmarks against testphp.vulnweb.com.
func TestBlackbox_Acunetix_Active(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping blackbox test in short mode")
	}

	defPath := filepath.Join(harness.DefinitionsDir(), "blackbox", "acunetix.yaml")
	def, err := harness.LoadDefinition(defPath)
	require.NoError(t, err, "Failed to load Acunetix definition")

	runBlackboxActive(t, def)
}

// TestBlackbox_GinAndJuice_Active runs active benchmarks against ginandjuice.shop.
func TestBlackbox_GinAndJuice_Active(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping blackbox test in short mode")
	}

	defPath := filepath.Join(harness.DefinitionsDir(), "blackbox", "ginandjuice.yaml")
	def, err := harness.LoadDefinition(defPath)
	require.NoError(t, err, "Failed to load Gin and Juice definition")

	runBlackboxActive(t, def)
}

// TestBlackbox_Testfire_Active runs active benchmarks against demo.testfire.net.
func TestBlackbox_Testfire_Active(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping blackbox test in short mode")
	}

	defPath := filepath.Join(harness.DefinitionsDir(), "blackbox", "testfire.yaml")
	def, err := harness.LoadDefinition(defPath)
	require.NoError(t, err, "Failed to load Testfire definition")

	runBlackboxActive(t, def)
}

func runBlackboxActive(t *testing.T, def *harness.BenchmarkDefinition) {
	t.Helper()

	// Check external site availability
	harness.CheckExternalAvailability(t, def.App.BaseURL)

	// Setup test infrastructure
	infra, err := harness.SetupTestInfra()
	require.NoError(t, err, "Failed to setup test infrastructure")
	defer infra.Cleanup()

	// Run active test cases with per-test timeout
	for _, tc := range def.TestCases {
		if tc.ScanMode != "active" {
			continue
		}

		t.Run(tc.ID, func(t *testing.T) {
			// Per-test timeout for blackbox
			timeout := tc.Timeout
			if timeout == 0 {
				timeout = 30 * time.Second
			}

			done := make(chan struct{})
			go func() {
				defer close(done)
				results := harness.RunActiveTestCase(t, tc, def.App.BaseURL, infra)
				for _, r := range results {
					t.Logf("[%s] %s: %d findings (duration=%v)",
						tc.ID, r.ModuleID, r.FindingCount, r.Duration)
				}
			}()

			select {
			case <-done:
			case <-time.After(timeout):
				t.Logf("[%s] Test timed out after %v", tc.ID, timeout)
			}
		})

		// Rate limiting between test cases for external sites
		rateLimit := def.App.RateLimit
		if rateLimit > 0 {
			time.Sleep(time.Duration(1000/rateLimit) * time.Millisecond)
		}
	}
}
