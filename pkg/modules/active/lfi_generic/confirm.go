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
//     attacker-induced, not part of the page in its unfuzzed state).
//
// This replaces the former `^[A-Za-z0-9+/=]{50,}` regex, which flagged any
// response whose body merely contained a base64 blob — e.g. CDN/static 404
// pages (GitHub Pages) that embed base64 data-URI logos.
func confirmPHPFilterBase64(data, baseline string) bool {
	for _, run := range base64RunRe.FindAllString(data, -1) {
		// A run already present verbatim in the baseline is page furniture
		// (an embedded image/font), not something the payload surfaced.
		if baseline != "" && strings.Contains(baseline, run) {
			continue
		}
		decoded, ok := tryBase64Decode(run)
		if !ok {
			continue
		}
		if containsPHPSource(decoded) {
			return true
		}
	}
	return false
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
