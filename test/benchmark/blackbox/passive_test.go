//go:build blackbox

package blackbox

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/test/benchmark/harness"
)

// TestBlackbox_Passive runs all passive module benchmark tests against external sites.
func TestBlackbox_Passive(t *testing.T) {
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
			runBlackboxPassive(t, def)
		})
	}
}

// TestBlackbox_Acunetix_Passive runs passive benchmarks against testphp.vulnweb.com.
func TestBlackbox_Acunetix_Passive(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping blackbox test in short mode")
	}

	defPath := filepath.Join(harness.DefinitionsDir(), "blackbox", "acunetix.yaml")
	def, err := harness.LoadDefinition(defPath)
	require.NoError(t, err, "Failed to load Acunetix definition")

	runBlackboxPassive(t, def)
}

func runBlackboxPassive(t *testing.T, def *harness.BenchmarkDefinition) {
	t.Helper()

	harness.CheckExternalAvailability(t, def.App.BaseURL)

	infra, err := harness.SetupTestInfra()
	require.NoError(t, err, "Failed to setup test infrastructure")
	defer infra.Cleanup()

	for _, tc := range def.TestCases {
		if tc.ScanMode != "passive" {
			continue
		}

		t.Run(tc.ID, func(t *testing.T) {
			timeout := tc.Timeout
			if timeout == 0 {
				timeout = 30 * time.Second
			}

			done := make(chan struct{})
			go func() {
				defer close(done)
				results := harness.RunPassiveTestCase(t, tc, def.App.BaseURL, infra)
				for _, r := range results {
					t.Logf("[%s] %s: %d findings",
						tc.ID, r.ModuleID, r.FindingCount)
				}
			}()

			select {
			case <-done:
			case <-time.After(timeout):
				t.Logf("[%s] Test timed out after %v", tc.ID, timeout)
			}
		})

		rateLimit := def.App.RateLimit
		if rateLimit > 0 {
			time.Sleep(time.Duration(1000/rateLimit) * time.Millisecond)
		}
	}
}
