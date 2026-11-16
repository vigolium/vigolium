package cli

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
)

// Every sender's rate and count flags are clamped by VIGOLIUM_RATE_CEILING:
// unset leaves them alone, a value above the ceiling is lowered, one below it
// is untouched, and an unlimited rate becomes the ceiling.
func TestApplyRateCeilingToFlags(t *testing.T) {
	swapGlobal(t, &fuzzRateLimit, 500.0)
	swapGlobal(t, &fuzzConcurrency, 40)
	swapGlobal(t, &kitParamMineRateLimit, defaultParamMineRateLimit)
	swapGlobal(t, &findingVerifyRateLimit, float64(unlimitedRate))
	swapGlobal(t, &globalRateLimit, defaultRateLimit)
	swapGlobal(t, &globalConcurrency, 5)
	swapGlobal(t, &globalMaxPerHost, defaultMaxPerHost)
	swapGlobal(t, &rateLimitKnob.perPhase, map[string]int{"known-issue-scan": 0})
	swapGlobal(t, &rateLimitKnob.globalSet, false)

	t.Run("unset leaves every flag alone", func(t *testing.T) {
		t.Setenv(config.RateCeilingEnv, "")
		for _, cmd := range []*cobra.Command{fuzzCmd, kitParamMineCmd, findingVerifyCmd, scanCmd} {
			require.NoError(t, applyRateCeilingToFlags(cmd))
		}
		assert.InDelta(t, 500.0, fuzzRateLimit, 0)
		assert.Equal(t, 40, fuzzConcurrency)
		assert.Equal(t, defaultParamMineRateLimit, kitParamMineRateLimit)
		assert.InDelta(t, 0.0, findingVerifyRateLimit, 0, "verify stays unlimited")
		assert.Equal(t, defaultRateLimit, globalRateLimit)
	})

	t.Run("set: above is lowered, below untouched, unlimited is the ceiling", func(t *testing.T) {
		t.Setenv(config.RateCeilingEnv, "10")
		for _, cmd := range []*cobra.Command{fuzzCmd, kitParamMineCmd, findingVerifyCmd, scanCmd} {
			require.NoError(t, applyRateCeilingToFlags(cmd))
		}
		assert.InDelta(t, 10.0, fuzzRateLimit, 0, "fuzz -r 500 → 10")
		assert.Equal(t, 10, fuzzConcurrency, "fuzz -c 40 → 10")
		assert.Equal(t, 10, kitParamMineRateLimit, "param-mine default 20 → 10")
		assert.InDelta(t, 10.0, findingVerifyRateLimit, 0, "verify unlimited → 10")
		assert.Equal(t, 10, globalRateLimit, "the unset scan default of 100 → 10")
		assert.Equal(t, 5, globalConcurrency, "-c 5 is under the ceiling")
		assert.Equal(t, 10, globalMaxPerHost)
		assert.Equal(t, 10, rateLimitKnob.perPhase["known-issue-scan"], "an unlimited phase rate → 10")
		assert.False(t, rateLimitKnob.globalChanged(), "clamping is not typing the flag")
		assert.False(t, fuzzCmd.Flags().Lookup("rate-limit").Changed, "Changed keeps its meaning")
	})

	t.Run("a ceiling above every value changes nothing", func(t *testing.T) {
		swapGlobal(t, &fuzzRateLimit, 50.0)
		swapGlobal(t, &kitParamMineRateLimit, 20)
		t.Setenv(config.RateCeilingEnv, "1000")
		require.NoError(t, applyRateCeilingToFlags(fuzzCmd))
		require.NoError(t, applyRateCeilingToFlags(kitParamMineCmd))
		assert.InDelta(t, 50.0, fuzzRateLimit, 0)
		assert.Equal(t, 20, kitParamMineRateLimit)
	})

	t.Run("a negative value is left for the command to refuse", func(t *testing.T) {
		swapGlobal(t, &fuzzRateLimit, -1.0)
		t.Setenv(config.RateCeilingEnv, "10")
		require.NoError(t, applyRateCeilingToFlags(fuzzCmd))
		assert.InDelta(t, -1.0, fuzzRateLimit, 0)
	})
}

// The multiplexed fuzz default (50 workers) replaces -c after the flag pass,
// so the pace resolution clamps it too.
func TestFuzzPaceClampsTheMultiplexedDefault(t *testing.T) {
	t.Setenv(config.RateCeilingEnv, "6")
	assert.Equal(t, 6, currentFuzzPace(fuzzWire{concurrency: fuzzMultiplexedConcurrency}).Concurrency)
}

// A bad ceiling is a usage error (exit 2) before anything runs.
func TestRateCeilingEnvRejectedAtStartup(t *testing.T) {
	t.Setenv(config.RateCeilingEnv, "fast")
	err := rootCmd.PersistentPreRunE(versionCmd, nil)
	var ue usageError
	require.ErrorAs(t, err, &ue)
	assert.Contains(t, err.Error(), config.RateCeilingEnv)
}
