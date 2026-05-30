package infra

import "strings"

// sqlKeywordCase maps an uppercase SQL keyword to a mixed-case variant. SQL is
// case-insensitive to keywords, so this preserves semantics while breaking
// naive WAF signatures that match exact keyword casing.
var sqlKeywordCase = map[string]string{
	"AND":     "AnD",
	"OR":      "oR",
	"UNION":   "UnIoN",
	"SELECT":  "sElEcT",
	"ORDER":   "OrDeR",
	"BY":      "bY",
	"NULL":    "nUlL",
	"SLEEP":   "SlEeP",
	"WAITFOR": "WaItFoR",
	"DELAY":   "DeLaY",
}

// sqlSpaceToComment replaces spaces with empty inline comments — a classic
// signature-evasion that most SQL engines treat as whitespace.
func sqlSpaceToComment(s string) string {
	return strings.ReplaceAll(s, " ", "/**/")
}

// sqlCaseFlip rewrites known SQL keywords (assumed uppercase in our generated
// payloads) to a mixed-case form.
func sqlCaseFlip(s string) string {
	for kw, mixed := range sqlKeywordCase {
		s = strings.ReplaceAll(s, kw, mixed)
	}
	return s
}

// SQLWAFMutators returns payload transforms to try when a WAF is detected
// fronting the target. Each mutator preserves SQL semantics while altering the
// surface a signature-based WAF inspects. The wafType is accepted for future
// per-vendor specialization; today all vendors get the same generic set.
func SQLWAFMutators(wafType string) []func(string) string {
	_ = wafType
	return []func(string) string{
		sqlSpaceToComment,
		sqlCaseFlip,
		func(s string) string { return sqlCaseFlip(sqlSpaceToComment(s)) },
	}
}
