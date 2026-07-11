package client_prototype_pollution

import "regexp"

// ppSourcePattern defines a known vulnerable URL parameter parsing pattern.
type ppSourcePattern struct {
	Name    string
	Desc    string
	Pattern *regexp.Regexp
	// RequiresURLSource marks "sink-only" patterns — generic deep-merge / recursive
	// bracket-assignment shapes that are only exploitable for prototype pollution when
	// attacker-controlled URL input actually flows into them. A safe object clone
	// (e.g. a script loader's `for (k in cfg) out[k]=cfg[k]`) and a vulnerable URL
	// param parser share the *same* structural shape, so the regex alone cannot tell
	// them apart; the scanner additionally requires a URL source (urlSourceRe) within
	// urlSourceWindow chars of the match before reporting these. Patterns that already
	// embed a URL source in their own regex (Object.assign-from-params, URLSearchParams,
	// location.search/hash parsers) leave this false and fire on the regex alone.
	RequiresURLSource bool
}

// ppSourcePatterns contains known vulnerable URL parameter parsing patterns.
var ppSourcePatterns = []ppSourcePattern{
	{
		Name:              "jQuery.extend (deep)",
		Pattern:           regexp.MustCompile(`\$\.extend\s*\(\s*true`),
		Desc:              "jQuery deep extend with URL-sourced input",
		RequiresURLSource: true,
	},
	{
		Name:              "lodash.merge",
		Pattern:           regexp.MustCompile(`_\.merge\s*\(`),
		Desc:              "lodash/underscore merge (recursive assignment)",
		RequiresURLSource: true,
	},
	{
		Name:              "lodash.defaultsDeep",
		Pattern:           regexp.MustCompile(`_\.defaultsDeep\s*\(`),
		Desc:              "lodash defaultsDeep (recursive assignment)",
		RequiresURLSource: true,
	},
	{
		Name:              "lodash.set",
		Pattern:           regexp.MustCompile(`_\.set\s*\(`),
		Desc:              "lodash set (path-based assignment)",
		RequiresURLSource: true,
	},
	{
		Name:              "Object.assign from params",
		Pattern:           regexp.MustCompile(`Object\.assign\s*\([^)]*(?:location|search|hash|params)`),
		Desc:              "Object.assign with potentially URL-sourced input",
		RequiresURLSource: true,
	},
	{
		Name:              "Custom recursive assign",
		Pattern:           regexp.MustCompile(`(?:for|forEach)\s*\([^)]*\)\s*\{[^}]*\[[^\]]*\]\s*=`),
		Desc:              "Custom recursive property assignment loop",
		RequiresURLSource: true,
	},
	{
		Name:              "decodeURIComponent with bracket notation",
		Pattern:           regexp.MustCompile(`decodeURIComponent[^;]*\[[^\]]*\]\s*=`),
		Desc:              "URL-decoded value assigned via bracket notation",
		RequiresURLSource: true,
	},
	{
		Name:    "URLSearchParams to object",
		Pattern: regexp.MustCompile(`URLSearchParams[^;]*forEach[^}]*\[[^\]]*\]\s*=`),
		Desc:    "URLSearchParams iterated into object via bracket notation",
	},
	{
		Name:    "location.search split parser",
		Pattern: regexp.MustCompile(`location\.search[^;]*split[^;]*\[[^\]]*\]\s*=`),
		Desc:    "Manual URL parameter parser using split + bracket assignment",
	},
	{
		Name:    "location.hash parser",
		Pattern: regexp.MustCompile(`location\.hash[^;]*(?:split|match|replace)[^;]*\[[^\]]*\]\s*=`),
		Desc:    "Hash fragment parser with bracket assignment",
	},
}

// urlSourceRe matches references to attacker-controllable URL input. Client-side
// prototype pollution requires such a source flowing into a merge/assign sink. The
// well-known false positives are minified third-party libraries (analytics hit
// serializers, script loaders, framework helpers) that trip the generic sink patterns
// purely on shape while reading internal config, never URL data — so sink-only patterns
// are gated on a nearby match of this expression.
var urlSourceRe = regexp.MustCompile(
	`location\.(?:search|hash|href|pathname|toString)` +
		`|\blocation\s*\[` + // location["search"], location['hash']
		`|document\.(?:URL|documentURI|location|referrer)` +
		`|window\.name\b` +
		`|URLSearchParams` +
		`|\.searchParams\b`)

// urlSourceWindow bounds how far (in characters, each direction) a URL source may sit
// from a sink-only match and still count as feeding it. Sized to span a typical
// same-function "parse location.search → recursively assign" flow while excluding an
// unrelated URL reference elsewhere in a minified bundle (e.g. a script loader's
// BasePath calc ~700 chars from its config-clone loop).
const urlSourceWindow = 500

// urlSourceNearby reports whether an attacker-controllable URL source appears within
// urlSourceWindow chars of pos in content.
func urlSourceNearby(content string, pos int) bool {
	start := pos - urlSourceWindow
	if start < 0 {
		start = 0
	}
	end := pos + urlSourceWindow
	if end > len(content) {
		end = len(content)
	}
	return urlSourceRe.MatchString(content[start:end])
}

// ppSourceHit is a source pattern that fired on a JS block, with the match position so
// callers can extract an evidence line.
type ppSourceHit struct {
	Pattern ppSourcePattern
	Pos     int
}

// firingSourcePatterns returns the source patterns that fire on content, applying the
// URL-source proximity gate to sink-only patterns. Centralizing the decision here keeps
// the scanner and tests on one code path.
func firingSourcePatterns(content string) []ppSourceHit {
	var hits []ppSourceHit
	for _, sp := range ppSourcePatterns {
		loc := sp.Pattern.FindStringIndex(content)
		if loc == nil {
			continue
		}
		if sp.RequiresURLSource && !urlSourceNearby(content, loc[0]) {
			continue
		}
		hits = append(hits, ppSourceHit{Pattern: sp, Pos: loc[0]})
	}
	return hits
}
