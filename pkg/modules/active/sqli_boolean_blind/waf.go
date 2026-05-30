package sqli_boolean_blind

import "github.com/vigolium/vigolium/pkg/modules/infra"

// wafVariants produces WAF-evasion copies of the curated/bypass payloads when a
// WAF is detected fronting the host. The randomized boundary-matrix pairs are
// skipped to keep the extra request budget bounded — the curated pairs are the
// highest-signal seeds to mutate.
//
// Variants are marked non-boundaried so they confirm via the repeat path, which
// re-sends the exact mutated strings. That keeps the whole TRUE/FALSE lifecycle
// (detection and confirmation) in the evaded form, rather than confirming with
// plain conditions the WAF would block.
func wafVariants(pairs []payloadPair, wafType string) []payloadPair {
	mutators := infra.SQLWAFMutators(wafType)
	var out []payloadPair
	for _, p := range pairs {
		if p.context == "matrix" {
			continue
		}
		for _, mut := range mutators {
			tv, fv := mut(p.trueVal), mut(p.falseVal)
			// Skip mutators that don't actually change the payload.
			if tv == p.trueVal && fv == p.falseVal {
				continue
			}
			out = append(out, payloadPair{context: "waf", trueVal: tv, falseVal: fv})
		}
	}
	return out
}
