package runner

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/modules"
	"go.uber.org/zap"
)

// intensityTierCeiling maps a resolved scan intensity to the maximum module
// tier rank that runs. A module runs when its tier rank is <= the ceiling;
// untagged modules (modules.TierAlwaysOn == 0) always run.
//
//	quick    -> moderate  drops the heavy blind/timing probes and the rare
//	                       intrusive checks for a fast pass
//	balanced -> heavy      keeps the full active battery, drops only intrusive
//	                       (this is the default and mirrors legacy coverage)
//	deep     -> intrusive  runs everything
//
// Profile-name aliases ("lite"/"standard"/"full") and the empty string (which
// defaults to balanced) are accepted so the ceiling is robust to either the
// raw --intensity value or a resolved profile name.
func intensityTierCeiling(intensity string) int {
	switch strings.ToLower(strings.TrimSpace(intensity)) {
	case "quick", "lite":
		return modules.TierRankModerate
	case "deep", "full":
		return modules.TierRankIntrusive
	default: // "", "balanced", "standard"
		return modules.TierRankHeavy
	}
}

// intensityLabel returns the resolved intensity for logging, tolerating a nil
// options (e.g. in unit tests that exercise the filters directly).
func (r *Runner) intensityLabel() string {
	if r == nil || r.options == nil {
		return ""
	}
	return r.options.Intensity
}

// filterModulesByTier drops modules whose tier rank exceeds the ceiling and logs
// what was deferred. It is shared by the active and passive filters (both element
// types embed modules.Module); kind labels the log line ("Active"/"Passive").
func filterModulesByTier[T modules.Module](r *Runner, mods []T, ceiling int, kind string) []T {
	if len(mods) == 0 {
		return mods
	}
	kept := make([]T, 0, len(mods))
	dropped := make([]string, 0)
	for _, m := range mods {
		if modules.ModuleTierRank(m.Tags()) <= ceiling {
			kept = append(kept, m)
		} else {
			dropped = append(dropped, m.ID())
		}
	}
	if len(dropped) > 0 {
		zap.L().Info(kind+" modules deferred by intensity tier",
			zap.String("intensity", r.intensityLabel()),
			zap.Int("ceiling", ceiling),
			zap.Int("deferred", len(dropped)),
			zap.Strings("ids", dropped))
	}
	return kept
}

// filterActiveModulesByTier drops active modules whose tier rank exceeds the ceiling.
func (r *Runner) filterActiveModulesByTier(mods []modules.ActiveModule, ceiling int) []modules.ActiveModule {
	return filterModulesByTier(r, mods, ceiling, "Active")
}

// filterPassiveModulesByTier drops passive modules whose tier rank exceeds the
// ceiling. Passive modules are almost all light/untagged, so this rarely fires,
// but the gate is applied symmetrically for consistency.
func (r *Runner) filterPassiveModulesByTier(mods []modules.PassiveModule, ceiling int) []modules.PassiveModule {
	return filterModulesByTier(r, mods, ceiling, "Passive")
}
