package modules

import "testing"

func TestModuleTierRank(t *testing.T) {
	cases := []struct {
		name string
		tags []string
		want int
	}{
		{"untagged is always-on", []string{"injection", "xss", "stored"}, TierAlwaysOn},
		{"nil tags", nil, TierAlwaysOn},
		{"light", []string{"spring", "light"}, 1},
		{"moderate", []string{"csrf", "moderate"}, 2},
		{"heavy", []string{"ssrf", "injection", "heavy"}, 3},
		{"intrusive", []string{"cors", "intrusive"}, 4},
		{"case insensitive", []string{"HEAVY"}, 3},
		{"whitespace tolerant", []string{" moderate "}, 2},
		{"highest tier wins on multiple", []string{"light", "heavy"}, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ModuleTierRank(tc.tags); got != tc.want {
				t.Fatalf("ModuleTierRank(%v) = %d, want %d", tc.tags, got, tc.want)
			}
		})
	}
}

// TestModuleTierRank_RegistryCoverage documents how the built-in modules
// distribute across tiers and guards against a tier tag being misspelled (which
// would silently demote a module to always-on). It is informational: it only
// fails if the registry somehow loses all tiered modules.
func TestModuleTierRank_RegistryCoverage(t *testing.T) {
	counts := map[int]int{}
	for _, m := range DefaultRegistry.GetActiveModules() {
		counts[ModuleTierRank(m.Tags())]++
	}
	for _, m := range DefaultRegistry.GetPassiveModules() {
		counts[ModuleTierRank(m.Tags())]++
	}
	t.Logf("tier distribution (rank->count): always-on=%d light=%d moderate=%d heavy=%d intrusive=%d",
		counts[TierAlwaysOn], counts[1], counts[2], counts[3], counts[4])
	if counts[3] == 0 {
		t.Fatal("expected at least one heavy-tier module in the registry")
	}
}
