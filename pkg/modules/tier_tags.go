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

// TagRiskHigh marks a whole module whose probes can change server state or
// degrade the target (send real emails, overrun limits, lock rows, DoS a
// regex). It is orthogonal to the tier tags: the native scan runner drops a
// risk:high module from a broad selection unless the scan runs at --intensity
// deep or the operator opted in with --allow-risky-payloads (config
// dynamic-assessment.allow_risky_payloads). Naming the module explicitly
// (-m/--module-id/--module-tag) still runs it, like the tier ceiling.
//
// Modules whose risk lives in a subset of payloads (sqli-time-blind's per-row
// OR and stacked forms) gate those payloads themselves via
// modkit.ScanContext.RiskyPayloadsAllowed instead of carrying this tag.
const TagRiskHigh = "risk:high"

// IsRiskHighModule reports whether a module's tags include TagRiskHigh.
func IsRiskHighModule(tags []string) bool {
	for _, t := range tags {
		if strings.EqualFold(strings.TrimSpace(t), TagRiskHigh) {
			return true
		}
	}
	return false
}

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

// Tier names ModuleTierName returns besides the tier tags.
const TierNameNone = "none"

// ModuleTierName returns the tier tag ModuleTierRank ranks a module by
// (light, moderate, heavy, intrusive), or TierNameNone for a module with no
// tier tag, which runs at every intensity.
func ModuleTierName(tags []string) string {
	rank := ModuleTierRank(tags)
	for name, r := range tierRank {
		if r == rank {
			return name
		}
	}
	return TierNameNone
}
