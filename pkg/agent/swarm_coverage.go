package agent

import (
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// planPathRE captures path-like substrings from free-text focus areas
// or notes. Excludes colon/space/comma/quotes to avoid matching prose
// fragments like "/login fails on:".
var planPathRE = regexp.MustCompile(`/[a-zA-Z0-9_/.\-]+`)

// PlanCoverage describes how well a SwarmPlan's focus areas + notes
// blanket the record set. MissingPrefixes is ordered by first appearance
// in records.
type PlanCoverage struct {
	MissingPrefixes []string
	TotalPrefixes   int
	CoveredPrefixes int
}

// AnalyzePlanCoverage returns the URL-prefix clusters in records that
// no FocusArea or Notes substring references (directly or via a
// parent/child path match).
func AnalyzePlanCoverage(plan *SwarmPlan, records []*httpmsg.HttpRequestResponse) PlanCoverage {
	if plan == nil || len(records) == 0 {
		return PlanCoverage{}
	}

	covered := planMentionedPrefixes(plan)

	seen := make(map[string]bool, len(records))
	ordered := make([]string, 0, len(records))
	for _, rr := range records {
		prefix := recordPathPrefix(rr)
		if prefix == "" || seen[prefix] {
			continue
		}
		seen[prefix] = true
		ordered = append(ordered, prefix)
	}

	cov := PlanCoverage{TotalPrefixes: len(ordered)}
	for _, prefix := range ordered {
		if prefixIsCovered(prefix, covered) {
			cov.CoveredPrefixes++
			continue
		}
		cov.MissingPrefixes = append(cov.MissingPrefixes, prefix)
	}
	return cov
}

func planMentionedPrefixes(plan *SwarmPlan) map[string]bool {
	out := map[string]bool{}
	add := func(text string) {
		for _, match := range planPathRE.FindAllString(text, -1) {
			prefix := pathToPrefix(match)
			if prefix == "" {
				continue
			}
			out[prefix] = true
		}
	}
	for _, fa := range plan.FocusAreas {
		add(fa)
	}
	if plan.Notes != "" {
		add(plan.Notes)
	}
	return out
}

// prefixIsCovered returns true when prefix matches any covered entry
// exactly, or is a parent/child of one. "/" is excluded — too broad to
// count as coverage on either side.
func prefixIsCovered(prefix string, covered map[string]bool) bool {
	if covered[prefix] {
		return true
	}
	for c := range covered {
		if c == "/" || prefix == "/" {
			continue
		}
		if strings.HasPrefix(prefix, c+"/") || strings.HasPrefix(c, prefix+"/") {
			return true
		}
	}
	return false
}

func RecordsForPrefixes(records []*httpmsg.HttpRequestResponse, prefixes []string) []*httpmsg.HttpRequestResponse {
	if len(records) == 0 || len(prefixes) == 0 {
		return nil
	}
	want := make(map[string]bool, len(prefixes))
	for _, p := range prefixes {
		want[p] = true
	}
	out := make([]*httpmsg.HttpRequestResponse, 0, len(records))
	for _, rr := range records {
		if want[recordPathPrefix(rr)] {
			out = append(out, rr)
		}
	}
	return out
}
