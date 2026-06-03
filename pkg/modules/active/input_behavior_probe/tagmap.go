package input_behavior_probe

import (
	"regexp"
	"strings"
)

var tagPattern = regexp.MustCompile(`(?i)<[a-z]+`)

// ExtractTags extracts all opening HTML tags from response body.
// Returns concatenated string of tags: "<div<script<a..."
func ExtractTags(body string) string {
	matches := tagPattern.FindAllString(body, -1)
	if len(matches) == 0 {
		return ""
	}
	var result strings.Builder
	for _, m := range matches {
		result.WriteString(strings.ToLower(m))
	}
	return result.String()
}

// scanTags extracts, in a SINGLE pass over body, both the readable concatenated
// opening-tag string (as ExtractTags) and the order-independent multiset (as
// extractTagCounts). Callers that need both — the baseline and each probe
// comparison — use this to avoid scanning the body with tagPattern twice.
func scanTags(body string) (string, map[string]int) {
	matches := tagPattern.FindAllString(body, -1)
	if len(matches) == 0 {
		return "", nil
	}
	var sb strings.Builder
	counts := make(map[string]int, len(matches))
	for _, m := range matches {
		lm := strings.ToLower(m)
		sb.WriteString(lm)
		counts[lm]++
	}
	return sb.String(), counts
}

// extractTagCounts returns an order-independent multiset of opening tag names,
// e.g. {"<div": 3, "<script": 1}. Unlike ExtractTags it ignores tag ORDER, so a
// page that merely reorders or shuffles its markup between requests yields an
// identical signature — only added/removed tags register.
func extractTagCounts(body string) map[string]int {
	matches := tagPattern.FindAllString(body, -1)
	if len(matches) == 0 {
		return nil
	}
	counts := make(map[string]int, len(matches))
	for _, m := range matches {
		counts[strings.ToLower(m)]++
	}
	return counts
}

// tagDistance is the L1 distance between two tag multisets: the count of opening
// tags added or removed between them. Reordering contributes zero, and a handful
// of incidental tags (a rotating ad block, a CDN-injected challenge script)
// produces a small, bounded distance rather than the all-or-nothing flip of exact
// string comparison.
func tagDistance(a, b map[string]int) int {
	dist := 0
	for tag, ca := range a {
		if d := ca - b[tag]; d > 0 {
			dist += d
		} else {
			dist -= d
		}
	}
	for tag, cb := range b {
		if _, ok := a[tag]; !ok {
			dist += cb
		}
	}
	return dist
}
