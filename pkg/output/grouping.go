package output

import (
	"sort"
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// valueKeySeparator joins normalized extracted values into a single grouping key.
// It must not appear inside an individual value (record separator, 0x1e).
const valueKeySeparator = "\x1e"

// groupKeySeparator joins the (module, severity, value[, host]) components of a
// finding grouping key. A different control char (unit separator, 0x1f) than
// valueKeySeparator so the two layers never collide.
const groupKeySeparator = "\x1f"

// GroupingKey assembles the finding grouping key from its components, prefixing
// the host when perHost is set. The single source of truth for the key layout
// (and its separator) shared by the live console grouper and the DB grouping
// pass — callers compute value via NormalizedValueKey (or "" to collapse a whole
// module) and pass it in.
func GroupingKey(moduleID, severity, value, host string, perHost bool) string {
	key := moduleID + groupKeySeparator + severity + groupKeySeparator + value
	if perHost {
		key = host + groupKeySeparator + key
	}
	return key
}

// RuleGroupKey folds a module's per-finding rule identity (e.g. secret-detect's
// secret-scan rule name, carried in Info.Name / module_name) into the module
// component of a grouping key. ByRule grouping then collapses repeats of the
// SAME rule on a host while keeping DISTINCT rules — a "Looker Client ID" vs an
// "AWS Access Key", both emitted by secret-detect — as separate findings. Uses
// groupKeySeparator so the composite slots cleanly into GroupingKey's module
// position (every component there is control-char delimited, so the extra slot
// is unambiguous).
func RuleGroupKey(moduleID, rule string) string {
	return moduleID + groupKeySeparator + rule
}

// SuspectBundleTag marks a finding as eligible for its module's Suspect-tier
// bundle (see IsSuspectBundle): a low-signal, family-less secret-shaped match —
// a generic API-key / password / token pattern that names no specific provider —
// which folds into the per-host "Low-confidence secret-shaped matches" rollup
// instead of standing on its own. A NAMED provider family (a Google / Slack /
// Storyblok rule) is deliberately left untagged, so it stays a per-rule finding
// even at Suspect severity and is never collapsed into the generic rollup with
// unrelated families. secret-detect sets it on its generic-namespace rules.
const SuspectBundleTag = "secret-generic"

// suspectBundleTagSet is the singleton set form of SuspectBundleTag, built once so
// IsSuspectBundle can reuse TagsIntersect (the shared trim/case-fold tag matcher)
// rather than a parallel one-off scan.
var suspectBundleTagSet = NormalizeTagSet([]string{SuspectBundleTag})

// GroupingBranch decides how one finding folds into a group, shared by the DB
// grouping pass and the live console grouper so the by-module / suspect-bundle /
// by-rule / value branches can't drift between the two. value is the finding's
// already-normalized extracted-value key (see NormalizedValueKey); severity is
// its severity name; tags is its tag list; byModule, byRule, bundleSuspect and
// tagSet are the resolved option sets.
//
// It returns the module component of the grouping key (moduleID, or the
// rule-folded key for a by-rule module), the value component (emptied for
// by-module, suspect-bundle, and by-rule so every value collapses into one
// group), and ok=false when the finding is ungroupable — no stable extracted
// value, or the tag gate rejects it. A returned empty valueKey with ok=true
// therefore marks a collapse-all group, where distinct values get unioned onto
// the survivor.
//
// The suspect-bundle branch (see IsSuspectBundle) sits between by-module and
// by-rule: a module can be BOTH by-rule and bundle-suspect (secret-detect is),
// so its Suspect-severity findings collapse by module (every low-confidence rule
// on a host folds into one bundle) while its higher-severity findings stay
// per-rule. Severity is also a component of the outer GroupingKey, so the two
// tiers never share a group regardless.
func GroupingBranch(moduleID, rule, value, severity string, tags []string, byModule, byRule, bundleSuspect, tagSet map[string]struct{}) (moduleKey, valueKey string, ok bool) {
	if _, isByModule := byModule[moduleID]; isByModule {
		return moduleID, "", true
	}
	if IsSuspectBundle(moduleID, severity, tags, bundleSuspect) {
		return moduleID, "", true
	}
	if _, isByRule := byRule[moduleID]; isByRule {
		return RuleGroupKey(moduleID, rule), "", true
	}
	if value == "" {
		return "", "", false // no stable extracted value to group on
	}
	if len(tagSet) > 0 && !TagsIntersect(tags, tagSet) {
		return "", "", false
	}
	return moduleID, value, true
}

// IsSuspectBundle reports whether a finding folds into a module's Suspect-tier
// bundle: the module is listed in bundleSuspect, the finding's severity is
// "suspect", AND the finding carries SuspectBundleTag — the marker a module sets
// only on its generic, family-less matches. Such findings group by module (the
// rule/value is dropped from the key), collapsing the low-signal noise on a host
// into a single bundle, while a NAMED provider family (which the module leaves
// untagged) stays per-rule so distinct families are never merged into one
// rollup. The same module's higher-severity findings group by rule regardless.
//
// Currently only secret-detect uses this — its generic-namespace rules (the
// "Generic Password" / "Generic API Key" matchers) are the noisy, family-less
// tier that warrants one per-host rollup; a recognisable provider key (Google,
// Storyblok, …) keeps its own triage row even when severity-downgraded to Suspect.
func IsSuspectBundle(moduleID, severity string, tags []string, bundleSuspect map[string]struct{}) bool {
	if len(bundleSuspect) == 0 {
		return false
	}
	if _, ok := bundleSuspect[moduleID]; !ok {
		return false
	}
	if !strings.EqualFold(severity, "suspect") {
		return false
	}
	return TagsIntersect(tags, suspectBundleTagSet)
}

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
// nothing usable remains (meaning "match regardless of tags").
func NormalizeTagSet(tags []string) map[string]struct{} {
	return normalizeToSet(tags, true)
}

// NormalizeStringSet trims each entry and drops empties and duplicates, returning
// a lookup set (nil when nothing usable remains). Unlike NormalizeTagSet it does
// NOT lowercase — it is for exact-match identifiers such as module IDs, which are
// matched case-sensitively against module_id in the DB.
func NormalizeStringSet(items []string) map[string]struct{} {
	return normalizeToSet(items, false)
}

// normalizeToSet trims each entry, drops empties and duplicates (lowercasing when
// lower is set), and returns nil when nothing usable remains.
func normalizeToSet(items []string, lower bool) map[string]struct{} {
	if len(items) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(items))
	for _, it := range items {
		it = strings.TrimSpace(it)
		if it == "" {
			continue
		}
		if lower {
			it = strings.ToLower(it)
		}
		set[it] = struct{}{}
	}
	if len(set) == 0 {
		return nil
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

// FormatPhaseFindingLine renders a phase-prefixed one-line summary of a finding
// for live display on stderr during a scan, e.g.:
//
//	❯ dynamic-assessment │ [passive] [crypto-weakness-detect] [• low] GET https://h/p
//
// It mirrors the chevron/pipe prefix of the phase status line plus the bracketed
// [type] [module] [severity] METHOD URL layout of the console result writer
// (formatScreen), so streamed findings read identically whether they reach the
// terminal via stdout (console format) or this stderr echo (jsonl/html format,
// where the stdout result stream is deferred to files). The trailing newline is
// included.
func FormatPhaseFindingLine(phaseTag string, r *ResultEvent) string {
	var b strings.Builder
	b.WriteString(terminal.Muted(terminal.SymbolChevron + " " + phaseTag + " " + terminal.SymbolPipe))

	// [type] — active/passive, colored. Suppressed when it duplicates the phase
	// tag (e.g. a known-issue-scan finding whose type mirrors the phase wrapper),
	// matching formatScreen's de-duplication.
	if r.ModuleType != "" && !strings.EqualFold(r.ModuleType, phaseTag) {
		b.WriteString(" [" + moduleTypeColor(r.ModuleType) + "]")
	}
	// [module-name]
	if r.ModuleID != "" {
		b.WriteString(" [" + r.ModuleID + "]")
	}
	// [• severity]
	b.WriteString(" [" + severityColor(r.Info.Severity) + "]")

	// METHOD URL — prefix the HTTP method when the finding carries a request,
	// exactly as formatScreen does.
	if loc := MatchedURL(r); loc != "" {
		b.WriteString(" ")
		if r.Request != "" {
			if method, err := httpmsg.GetMethod([]byte(r.Request)); err == nil && method != "" {
				b.WriteString(method + " ")
			}
		}
		b.WriteString(loc)
	}
	// [value] — the grouped extracted value, when present. Escape embedded
	// newlines/tabs to their literal form (\n, \t) before truncating so the
	// snippet stays on one line and the width budget counts visible characters.
	if v := NormalizedValueKey(r.ExtractedResults); v != "" {
		v = EscapeOneLine(v)
		b.WriteString(" " + terminal.Yellow("["+terminal.Truncate(v, liveFindingValueMax)+"]"))
	}
	b.WriteString("\n")
	return b.String()
}
