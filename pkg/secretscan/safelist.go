package secretscan

import "regexp"

// safeListPatterns are benign placeholder / example / redaction shapes ported
// from kingfisher's src/safe_list.rs (Apache-2.0). A match here means the
// candidate is almost certainly not a live secret (EXAMPLE keys, ${ENV} refs,
// hunter2, 123456789, mongodb://user:pass@…, etc.). All patterns are already
// RE2-compatible. Like kingfisher's is_safe_match, these run against the secret
// capture only — never the surrounding line — so ordinary `name = <token>`
// assignments are not mistaken for placeholders.
var safeListPatterns = compileSafeList([]string{
	`(?i)[:=][^:=]{0,64}EXAMPLEKEY`,
	`(?i)\b(AKIA(?:.*?EXAMPLE|.*?FAKE|TEST|.*?SAMPLE))\b`,
	`(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,8}[=:?][^=:?]{0,8}\s(&&|\|\||\*{5,50})`,
	`(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,8}[=:?][^=:?]{0,8}\b\w{4,12}\s{0,6}=\s{0,6}\D{0,3}\w{1,12}`,
	`(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,8}[=:?][^=:?]{0,8}\$\w{4,30}`,
	`(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,16}[=:?][^=:?]{0,8}\bopenssl\s{0,4}rand\b`,
	`(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,8}[=:?][^=:?]{0,8}encrypted`,
	`(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,8}[=:?][^=:?]{0,8}\b(?:false|true)\b`,
	`(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,8}[=:?][^=:?]{0,8}\b(null|nil|none|password|pass|pwd|passwd|secret|cred|key|auth|authorization).{1,6}$`,
	`(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,8}[=:?][^=:?]{0,8}hunter2`,
	`(?i)123456789|abcdefghij`,
	`(?i)<secretmanager>`,
	`(?i)[=:?][^=:?]{0,8}#/components/schemas/`,
	`(?i)\b(mongodb(?:\+srv)?://(?:user|foo)[^:@]+:(?:pass|bar)[^@]+@[-\w.%+/:]{3,64}(?:/\w+)?)`,
	`(?i)\b(classpath://)`,
	`(?i)(\b[^\s\t]{0,16}[=:][^$]*\$\{[a-z_-]{5,30}\})`,
	`(?i)\b((?:https?:)?//[^:@]{3,50}:[^:@]{3,50}@[\w.]{0,16}(?:example|test))`,
	`(?i)[:=][^:=]{0,32}\bSECRETMANAGER`,
})

func compileSafeList(pats []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(pats))
	for _, p := range pats {
		// Compiled at init; a bad pattern here is a build-time bug.
		out = append(out, regexp.MustCompile(p))
	}
	return out
}

// isBenign reports whether the secret capture matches a known-benign
// placeholder shape. These patterns are cheap and short so running stdlib
// regexp (not go-re2) is fine.
func isBenign(secret []byte) bool {
	for _, re := range safeListPatterns {
		if re.Match(secret) {
			return true
		}
	}
	return false
}
