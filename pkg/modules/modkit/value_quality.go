package modkit

import "strings"

// valuePlaceholders are values a client emits in place of a real secret, token,
// id, or URL when none exists — chiefly a JS client serializing an absent
// variable into a request (`token=${t}` with t undefined yields "token=null").
// They are not real values, so a presence-based detector that flags a sensitive
// parameter/header/value MUST treat them as "no value": reporting "token=null"
// or "redirect=undefined" is noise, not a finding.
//
// The set is deliberately limited to unambiguous null-ish sentinels. Values like
// "0", "true", or "false" are intentionally excluded: they are legitimate values
// in many contexts (a numeric id of 0, a boolean flag), and a caller that wants
// to reject them should do so explicitly.
var valuePlaceholders = map[string]bool{
	"":                true,
	"null":            true,
	"undefined":       true,
	"nil":             true,
	"none":            true,
	"nan":             true,
	"(null)":          true,
	"[object object]": true,
	"{}":              true,
	"[]":              true,
}

// IsPlaceholderValue reports whether v is empty, whitespace-only, or a
// well-known null-ish placeholder/sentinel (null, undefined, nil, none, nan,
// [object Object], {}, []) rather than a real value. Comparison is trimmed and
// case-insensitive.
func IsPlaceholderValue(v string) bool {
	return valuePlaceholders[strings.ToLower(strings.TrimSpace(v))]
}
