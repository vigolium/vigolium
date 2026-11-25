package runner

import (
	"slices"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/types"
)

// The hard tier ceiling binds a broad selection, an explicit -m and a config
// allowlist alike, and the lower of the flag and the config key applies.
func TestFilterModulesForRunHardTierCeiling(t *testing.T) {
	settings := config.DefaultSettings()
	opts := types.DefaultOptions()
	opts.Modules = []string{"all"}
	opts.Intensity = "deep"
	opts.MaxModuleTier = "heavy"

	sel := FilterModulesForRun(opts, settings)
	for _, m := range sel.Active {
		if modules.ModuleTierRank(m.Tags()) > modules.TierRankHeavy {
			t.Fatalf("%s is above heavy but selected", m.ID())
		}
	}
	if !slices.Contains(sel.TierCapped, "php2shell") || !slices.Contains(sel.TierCapped, "node2shell") {
		t.Fatalf("TierCapped = %v, want the intrusive modules", sel.TierCapped)
	}

	// An explicit -m naming an intrusive module is capped too.
	opts.Modules = []string{"php2shell"}
	if sel = FilterModulesForRun(opts, settings); len(sel.Active) != 0 {
		t.Fatalf("explicit -m php2shell ran above the hard ceiling")
	}

	// The config key binds when the flag is absent, and the flag cannot raise it.
	opts.Modules = []string{"all"}
	opts.MaxModuleTier = "intrusive"
	settings.DynamicAssessment.MaxModuleTier = "moderate"
	sel = FilterModulesForRun(opts, settings)
	if sel.MaxTier != modules.TierRankModerate {
		t.Fatalf("MaxTier = %d, want moderate", sel.MaxTier)
	}
	for _, m := range sel.Active {
		if modules.ModuleTierRank(m.Tags()) > modules.TierRankModerate {
			t.Fatalf("%s is above moderate but selected", m.ID())
		}
	}
}

func TestValidateMaxModuleTier(t *testing.T) {
	for _, ok := range []string{"", "light", "Moderate", "heavy", "intrusive"} {
		if err := ValidateMaxModuleTier(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	if err := ValidateMaxModuleTier("lite"); err == nil {
		t.Errorf("lite accepted")
	}
}

// php2shell kills PHP-FPM workers, so a broad selection withholds it below deep.
func TestPhp2shellIsRiskHigh(t *testing.T) {
	settings := config.DefaultSettings()
	opts := types.DefaultOptions()
	opts.Modules = []string{"all"}
	opts.Intensity = "balanced"
	sel := FilterModulesForRun(opts, settings)
	if !slices.Contains(sel.RiskWithheld, "php2shell") {
		t.Fatalf("RiskWithheld = %v, want php2shell", sel.RiskWithheld)
	}
}
