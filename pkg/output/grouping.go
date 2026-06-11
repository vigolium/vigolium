package output

import (
	"fmt"
	"sort"
	"strings"

	"github.com/vigolium/vigolium/pkg/terminal"
)

// valueKeySeparator joins normalized extracted values into a single grouping key.
// It must not appear inside an individual value (record separator, 0x1e).
const valueKeySeparator = "\x1e"

// NormalizedValueKey builds a stable grouping key from a finding's extracted
// results: each entry trimmed, empties dropped, the remainder sorted (so order
// doesn't matter), joined with a separator that can't appear inside a single
// value. Returns "" when nothing usable remains (callers treat that as
// "ungroupable"). This is the single source of truth for the value-identity
// contract shared by the live console grouper and the DB grouping pass.
func NormalizedValueKey(values []string) string {
	if len(values) == 1 {
		return strings.TrimSpace(values[0]) // common single-value fast path
	}
	cleaned := make([]string, 0, len(values))
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			cleaned = append(cleaned, v)
		}
	}
	if len(cleaned) == 0 {
		return ""
	}
	sort.Strings(cleaned)
	return strings.Join(cleaned, valueKeySeparator)
}

// NormalizeTagSet lowercases and trims a tag filter into a set, returning nil when
// the filter is empty (meaning "match regardless of tags").
func NormalizeTagSet(tags []string) map[string]struct{} {
	if len(tags) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(tags))
	for _, t := range tags {
		if t = strings.ToLower(strings.TrimSpace(t)); t != "" {
			set[t] = struct{}{}
		}
	}
	return set
}

// TagsIntersect reports whether any of tags is present in set (built by
// NormalizeTagSet). An empty/nil set never matches — callers gate on len(set) first.
func TagsIntersect(tags []string, set map[string]struct{}) bool {
	for _, t := range tags {
		if _, ok := set[strings.ToLower(strings.TrimSpace(t))]; ok {
			return true
		}
	}
	return false
}

// MatchedURL returns the location a finding points at, preferring the precise
// matched-at over the request URL and finally the host. Single source of truth
// for the Matched→URL→Host fallback used by screen formatting and grouping.
func MatchedURL(r *ResultEvent) string {
	if r.Matched != "" {
		return r.Matched
	}
	if r.URL != "" {
		return r.URL
	}
	return r.Host
}

// liveFindingValueMax bounds the extracted-value snippet in a live finding line.
const liveFindingValueMax = 48

// FormatPhaseFindingLine renders a compact, phase-prefixed one-line summary of a
// finding for live display on stderr during a scan, e.g.:
//
//	❯ dynamic-assessment │ ⚠ high reflected-xss — https://h/p?q=… [<svg/onload=…]
//
// It mirrors the chevron/pipe prefix of the phase status line so streamed
// findings read as part of the same phase output. Used when the stdout result
// stream is deferred to files (jsonl/html) and findings would otherwise stay
// invisible until the scan finishes. The trailing newline is included.
func FormatPhaseFindingLine(phaseTag string, r *ResultEvent) string {
	prefix := terminal.Muted(terminal.SymbolChevron + " " + phaseTag + " " + terminal.SymbolPipe)
	line := fmt.Sprintf("%s %s %s",
		prefix,
		severityColor(r.Info.Severity),
		terminal.BoldCyan(r.ModuleID))
	if loc := MatchedURL(r); loc != "" {
		line += " " + terminal.Muted("—") + " " + terminal.Gray(loc)
	}
	if v := NormalizedValueKey(r.ExtractedResults); v != "" {
		line += " " + terminal.Yellow("["+terminal.Truncate(v, liveFindingValueMax)+"]")
	}
	return line + "\n"
}
