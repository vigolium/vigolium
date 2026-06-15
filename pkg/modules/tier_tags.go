package modules

import "strings"

// Module intensity-tier tags. A module declares at most one of these in its
// Tags() slice to advertise how expensive/aggressive it is. The native scan
// runner uses the tier together with the resolved --intensity to decide which
// modules run (see internal/runner intensity tier ceiling):
//
//   - light     reconnaissance, fingerprinting, cheap exposure probes
//   - moderate  standard active testing (csrf, xxe, debug-exposure, …)
//   - heavy     expensive blind/timing probes (sqli-blind, ssti-blind, ssrf-blind,
//     command-injection-timing, file-upload, request-smuggling, …)
//   - intrusive rare, high-side-effect checks reserved for the deepest scans
//
// Keep this vocabulary aligned with the tier tags declared in module metadata
// and with the ModuleTier* contract test in default_registry_contract_test.go.
const (
	TagTierLight     = "light"
	TagTierModerate  = "moderate"
	TagTierHeavy     = "heavy"
	TagTierIntrusive = "intrusive"
)

// TierAlwaysOn is the rank assigned to a module that declares no tier tag. It is
// strictly below every real tier so an untagged module is never excluded by an
// intensity ceiling — a missing tag must never silently drop a module (e.g. the
// core xss_stored / xss_dom_confirm modules carry no tier tag and must run at
// every intensity).
const TierAlwaysOn = 0

// Tier ranks order the tier tags from cheapest (light) to most aggressive
// (intrusive). ModuleTierRank returns one of these for a tagged module, or
// TierAlwaysOn (0) for an untagged one. The native scan runner compares a
// module's rank against an intensity-derived ceiling — this is the single source
// of the ordering both sides share.
const (
	TierRankLight     = 1
	TierRankModerate  = 2
	TierRankHeavy     = 3
	TierRankIntrusive = 4
)

// tierRank orders the tier tags from cheapest to most aggressive.
var tierRank = map[string]int{
	TagTierLight:     TierRankLight,
	TagTierModerate:  TierRankModerate,
	TagTierHeavy:     TierRankHeavy,
	TagTierIntrusive: TierRankIntrusive,
}

// ModuleTierRank returns the intensity rank implied by a module's tags. It
// returns TierAlwaysOn (0) when no tier tag is present. If more than one tier
// tag is declared (not expected), the highest rank wins so the module is gated
// by its most aggressive classification.
func ModuleTierRank(tags []string) int {
	rank := TierAlwaysOn
	for _, t := range tags {
		if r, ok := tierRank[strings.ToLower(strings.TrimSpace(t))]; ok && r > rank {
			rank = r
		}
	}
	return rank
}
