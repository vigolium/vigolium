package lfi_generic

import (
	"encoding/base64"
	"regexp"
	"strings"
)

// base64RunRe captures contiguous base64-alphabet runs long enough to plausibly
// encode a PHP snippet (>= 20 chars ⇒ >= ~15 decoded bytes, enough to carry an
// open tag plus a little source). The php://filter/convert.base64-encode wrapper
// returns the whole file as one such run; ordinary HTML pages also carry base64
// (data-URI images, fonts), which is exactly why decoding — not a bare
// length/charset match — is what tells them apart. The decode-to-PHP check below
// is the real gate, so this bound only trims obviously-too-short fragments.
var base64RunRe = regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)

// phpOpenTags are the unambiguous opening markers of PHP source. A file read via
// php://filter/convert.base64-encode/resource=<file>.php decodes to source that
// contains one of these; a base64-encoded PNG/woff/jpeg decodes to binary that
// does not.
var phpOpenTags = []string{"<?php", "<?=", "<?\n", "<?\r", "<?\t", "<? "}

// confirmPHPFilterBase64 corroborates a php://filter base64 read by actually
// decoding the base64 blob(s) in the response and requiring the decoded bytes to
// contain real PHP source. It returns true only when:
//
//   - a base64 run decodes to content carrying a PHP open tag, and
//   - that same run is not already present in the baseline (so the evidence is
//     attacker-induced, not part of the page in its unfuzzed state), and
//   - the run is not simply our own data:// payload being reflected back, and
//   - the decoded bytes do not carry our injection marker.
//
// This replaces the former `^[A-Za-z0-9+/=]{50,}` regex, which flagged any
// response whose body merely contained a base64 blob — e.g. CDN/static 404
// pages (GitHub Pages) that embed base64 data-URI logos. The reflection guards
// additionally kill the Salesforce-Aura class of false positive: endpoints that
// echo the request body (aura.context) bounce our data:// payload — which
// base64-encodes PHP carrying injectionMarker — straight back, where a naive
// decode looks identical to a successful source read.
func confirmPHPFilterBase64(data, baseline, payload string) bool {
	for _, run := range base64RunRe.FindAllString(data, -1) {
		// A run already present verbatim in the baseline is page furniture
		// (an embedded image/font), not something the payload surfaced.
		if baseline != "" && strings.Contains(baseline, run) {
			continue
		}
		// A run contained in the payload we just sent is the target reflecting
		// our request body, not reading a file. The data:// wrapper payload is
		// itself base64, so its reflection trivially decodes back to PHP.
		if payload != "" && strings.Contains(payload, run) {
			continue
		}
		decoded, ok := tryBase64Decode(run)
		if !ok {
			continue
		}
		// Our own marker can only be present because the data:// payload was
		// reflected and decoded back; a genuine server-side PHP file never
		// contains it.
		if strings.Contains(decoded, injectionMarker) {
			continue
		}
		if containsPHPSource(decoded) {
			return true
		}
	}
	return false
}

// winIniSectionRe matches a bracketed win.ini section header at the start of a
// line (case-insensitive). A genuine Windows win.ini always carries several of
// these; reflected `../../windows/win.ini` payloads and ordinary pages do not.
var winIniSectionRe = regexp.MustCompile(`(?im)^\[(fonts|extensions|mci extensions|files|mail|ports|devices)\]`)

// confirmWinIni corroborates a leaked win.ini by requiring at least two distinct
// bracketed section headers that are not already present in the baseline.
func confirmWinIni(data, baseline, _ string) bool {
	return countNewDistinctMatches(winIniSectionRe, data, baseline) >= 2
}

// dotenvAssignRe matches a single .env assignment line carrying a sensitive key
// in KEY=VALUE form with a non-empty value. Requiring the assignment shape —
// not a bare "DB_PASSWORD" token — keeps the rule from firing on prose or JSON
// that merely mentions the word.
var dotenvAssignRe = regexp.MustCompile(`(?im)^[ \t]*(DB_PASSWORD|DB_USERNAME|DB_DATABASE|DB_HOST|APP_KEY|APP_SECRET|APP_ENV|MAIL_PASSWORD|REDIS_PASSWORD|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|SECRET_KEY|JWT_SECRET|STRIPE_SECRET)[ \t]*=[ \t]*\S`)

// htaccessDirectiveRe matches common Apache .htaccess directives at the start of
// a line. Two distinct directives are required so a stray mention can't confirm.
var htaccessDirectiveRe = regexp.MustCompile(`(?im)^[ \t]*(RewriteEngine|RewriteRule|RewriteCond|RewriteBase|AuthType|AuthUserFile|AuthName|Require\s+all|Order\s+(allow|deny)|Deny\s+from|Allow\s+from|<(Files|Directory|FilesMatch|Location)\b)`)

// confirmAppConfig corroborates a leaked .env / .htaccess file by requiring at
// least two distinct, file-shaped lines (sensitive KEY=VALUE assignments for
// .env, recognised Apache directives for .htaccess) that are not already present
// in the baseline. This both strengthens the evidence (the file's actual content
// must appear, not just a referenced word) and broadens detection beyond the
// former rigid DB_PASSWORD+APP_KEY+APP_SECRET triple.
func confirmAppConfig(data, baseline, _ string) bool {
	if countNewDistinctMatches(dotenvAssignRe, data, baseline) >= 2 {
		return true
	}
	return countNewDistinctMatches(htaccessDirectiveRe, data, baseline) >= 2
}

// countNewDistinctMatches counts the distinct (case-insensitive) substrings re
// matches in data that are not already present verbatim in baseline. It is the
// shared corroboration primitive behind confirmWinIni and confirmAppConfig:
// "the file's own lines appeared, and they weren't there before we fuzzed".
func countNewDistinctMatches(re *regexp.Regexp, data, baseline string) int {
	seen := make(map[string]struct{})
	for _, m := range re.FindAllString(data, -1) {
		if baseline != "" && strings.Contains(baseline, m) {
			continue
		}
		seen[strings.ToLower(strings.TrimSpace(m))] = struct{}{}
	}
	return len(seen)
}

// tryBase64Decode attempts to decode a base64 run using the standard and
// raw (unpadded) alphabets, returning the decoded bytes on the first success.
func tryBase64Decode(s string) (string, bool) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) > 0 {
			return string(b), true
		}
	}
	return "", false
}

// containsPHPSource reports whether decoded carries an unambiguous PHP open tag.
func containsPHPSource(decoded string) bool {
	for _, tag := range phpOpenTags {
		if strings.Contains(decoded, tag) {
			return true
		}
	}
	return false
}
