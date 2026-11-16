package runner

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/types"
)

// A dial VIGOLIUM_RATE_CEILING lowered becomes one rate_ceiling note on the
// next phase to finish, and only that one: the coverage caveat on
// scan.finished says the ceiling applied without repeating it per phase.
func TestRateCeilingClampBecomesAPhaseNote(t *testing.T) {
	t.Setenv(config.RateCeilingEnv, "3")
	r := &Runner{rateClampsNoted: len(config.RateClamps())}

	quiet := &phaseTracker{phase: "discovery"}
	r.noteRateCeiling(quiet)
	assert.NotContains(t, quiet.notes, database.LimitRateCeiling, "no clamp, no note")

	config.CeilIntRate("runner-note-test --rate-limit", 100)
	first := &phaseTracker{phase: "discovery"}
	r.noteRateCeiling(first)
	assert.Contains(t, first.notes, database.LimitRateCeiling)

	second := &phaseTracker{phase: "dynamic-assessment"}
	r.noteRateCeiling(second)
	assert.NotContains(t, second.notes, database.LimitRateCeiling, "already noted on an earlier phase")

	caveats := database.CoverageCaveats(database.ScanCompletion{Phases: []database.PhaseOutcome{
		{Phase: "discovery", State: database.PhaseCompleted, Notes: []string{database.LimitRateCeiling}},
	}}, nil)
	if assert.Len(t, caveats, 1) {
		assert.Equal(t, database.LimitRateCeiling, caveats[0].Code)
		assert.Contains(t, caveats[0].Message, "VIGOLIUM_RATE_CEILING")
	}
}

// The scan-wide options and the settings a runner receives are clamped at the
// runner's own entry points, whatever resolution the caller ran.
func TestRunnerEntryPointsApplyTheCeiling(t *testing.T) {
	t.Setenv(config.RateCeilingEnv, "4")
	settings := &config.Settings{ScanningPace: *config.DefaultScanningPaceConfig()}
	r := &Runner{}
	r.SetSettings(settings)
	assert.Equal(t, 4, settings.ScanningPace.RateLimit)
	assert.Equal(t, 4, settings.ScanningPace.Concurrency)
	assert.Equal(t, 4, settings.ScanningPace.MaxPerHost)
	assert.Equal(t, 4, r.discoveryRateLimit(), "discovery is unpaced by default; under a ceiling it is not")

	// The shared resolution (CLI, REST, agent launcher): a typed -r 500 and
	// the config's concurrency both end at the ceiling.
	resolved := &config.Settings{ScanningPace: *config.DefaultScanningPaceConfig()}
	opts := &types.Options{RateLimit: 500, Concurrency: 2, MaxPerHost: 40}
	assert.NoError(t, ApplyScanPace(resolved, opts, ExplicitPace{RateLimit: true}))
	assert.Equal(t, 4, opts.RateLimit)
	assert.Equal(t, 4, opts.Concurrency, "the config's 25 folded in, then clamped")
	assert.Equal(t, 4, opts.MaxPerHost)
}
