package llm

import "regexp"

// secretRule pairs a rule name with a compiled matcher. High-value, structurally
// distinctive vendor patterns are matched first; the loose generic keyword=value
// pattern is last so a structured key never gets mislabeled as generic.
type secretRule struct {
	name string
	re   *regexp.Regexp
}

// secretRules is the ordered matcher set. The first rule to match wins. The
// vendor patterns match the whole token; the generic rule captures the value in
// group 1 so the returned secret is the credential, not the keyword prefix.
var secretRules = []secretRule{
	{"aws-access-key-id", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"google-api-key", regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`)},
	{"github-personal-access-token", regexp.MustCompile(`ghp_[0-9A-Za-z]{36}`)},
	{"stripe-secret-key", regexp.MustCompile(`sk_live_[0-9A-Za-z]{24,}`)},
	{"slack-token", regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,}`)},
	{"generic-credential", regexp.MustCompile(`(?i)(?:api[_-]?key|secret|token|password|connection ?string)["'\s:=]{1,4}([A-Za-z0-9/+_\-]{20,})`)},
}

// FindValidatedSecret scans text for the first high-value credential pattern and
// returns the matched secret, the rule name that matched, and ok=true. It is a
// compact, deterministic stand-in for live credential validation: the same input
// always yields the same result, which is what the boundary-probe module relies
// on to require cross-prompt agreement on the identical secret string.
//
// For the vendor rules the returned secret is the whole matched token; for the
// generic keyword=value rule it is the captured value (group 1) so callers get
// the credential itself rather than the "api_key=" prefix.
func FindValidatedSecret(text string) (secret string, rule string, ok bool) {
	if text == "" {
		return "", "", false
	}
	for _, r := range secretRules {
		m := r.re.FindStringSubmatch(text)
		if m == nil {
			continue
		}
		if len(m) > 1 && m[1] != "" {
			return m[1], r.name, true
		}
		return m[0], r.name, true
	}
	return "", "", false
}
