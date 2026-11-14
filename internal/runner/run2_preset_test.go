package runner

import (
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/types"
)

// TestScanTierCeilingFromResolvedProfile: the tier ceiling follows the
// resolved profile, not only a typed --intensity, and --safe caps it.
func TestScanTierCeilingFromResolvedProfile(t *testing.T) {
	cases := []struct {
		name string
		opts types.Options
		want int
	}{
		{"default", types.Options{}, modules.TierRankIntrusive},
		{"typed quick", types.Options{Intensity: "quick"}, modules.TierRankModerate},
		{"profile quick (config default_profile)", types.Options{ScanningProfile: "quick"}, modules.TierRankModerate},
		{"typed intensity wins over profile", types.Options{Intensity: "deep", ScanningProfile: "quick"}, modules.TierRankIntrusive},
		{"safe", types.Options{Safe: true, Intensity: "deep"}, modules.TierRankModerate},
	}
	for _, c := range cases {
		opts := c.opts
		if got := scanTierCeiling(&opts); got != c.want {
			t.Errorf("%s: ceiling = %d, want %d", c.name, got, c.want)
		}
	}
}

// TestPhaseConcurrencyHonoursCeiling: a strategy ceiling or --safe narrows a
// phase's own scanning_pace section, which used to win over the narrowed
// global value (quick's dynamic-assessment concurrency: 100 under --safe).
func TestPhaseConcurrencyHonoursCeiling(t *testing.T) {
	settings := config.DefaultSettings()
	settings.ScanningPace.DynamicAssessment.Concurrency = 100
	r := &Runner{options: &types.Options{Concurrency: 10, ConcurrencyCeiling: 10}, settings: settings}
	if got := r.phaseConcurrency("dynamic-assessment"); got != 10 {
		t.Fatalf("phase concurrency = %d, want the ceiling 10", got)
	}
	r.options.ConcurrencyExplicitlySet = true
	r.options.Concurrency = 50
	if got := r.phaseConcurrency("dynamic-assessment"); got != 50 {
		t.Fatalf("typed -c = %d, want 50", got)
	}
}
