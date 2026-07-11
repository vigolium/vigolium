package secret_detect

import "bytes"

// IsNonSecretMatch reports whether a secret-scan match on snippet is a structural
// false positive rather than a real credential: an encoded-binary blob
// (IsBinaryBlobMatch), a JavaScript unicode-escape source artifact
// (IsJSEscapeArtifactMatch), or a build-tool content-hash manifest entry
// (IsChunkHashManifestMatch). Each guard is pinned to the detector's exact match
// offsets (start/end; see resolveMatchSpan), so it inspects the occurrence that
// fired instead of re-searching the body — faster, and it can no longer classify
// the wrong occurrence when the same value appears in both a blob and a genuine
// assignment. Passing start<0 locates by substring instead (the guards' tests).
func IsNonSecretMatch(body []byte, snippet string, start, end int) bool {
	return IsBinaryBlobMatch(body, snippet, start, end) ||
		IsJSEscapeArtifactMatch(body, snippet, start, end) ||
		IsChunkHashManifestMatch(body, snippet, start, end)
}

// minChunkHashSiblings is how many distinct quoted, same-length lowercase-hex
// values (the match itself included) must appear in a body for it to be treated
// as a content-hash manifest rather than a credential carrier.
//
// A webpack/Vite/rspack chunk-hash map (`{name:"<hash>", ...}`, or the
// `__webpack_require__.u` jsonp src map) lists every code-split chunk's content
// hash, so one minified bundle ships dozens to hundreds of identical-shape
// hashes. A response that genuinely leaks one short hex credential carries at
// most a small handful of unrelated hashes (an ETag, a CSRF nonce), never a map
// of them. Eight cleanly separates the two: a manifest clears it by orders of
// magnitude while a credential payload never reaches it.
const minChunkHashSiblings = 8

// chunkHashMinLen and chunkHashMaxLen bound the snippet widths this guard
// considers. Webpack/Vite/rspack content hashes are short fixed-width hex
// (default `[hash:20]`, also 8 and 16); 32 covers the md5-width variant.
// Anything outside this band is not a content hash, so the guard never fires.
const (
	chunkHashMinLen = 8
	chunkHashMaxLen = 32
)

// IsChunkHashManifestMatch reports whether the matched snippet is one entry in a
// JavaScript content-hash manifest — a webpack/Vite/rspack chunk-name→content-
// hash map — rather than a leaked credential.
//
// This is the dominant false-positive class for short fixed-length hex secret
// rules whose pattern keys off a nearby English word. the ruleset's "Looker
// Client ID" rule, for instance, fires on any 20-char [a-z0-9] token within 64
// characters of the word "looker"; a Looker SPA bundle ships a chunk map like
// `{"looker.dataflux.stores.folder_model":"8b2d330eb01e5f1c4263", ...}`, so every
// chunk hash sitting beside a "looker."-prefixed module name is reported as a
// leaked client ID. The same shape sinks any generic md5/sha-width rule against
// a minified bundle's chunk map.
//
// The signal is structural and self-contained: the snippet is a lowercase-hex
// run of content-hash width, it appears in the body as a quoted string value
// (`"<snippet>"`), and the body holds at least minChunkHashSiblings distinct
// quoted hex values of the EXACT same length — i.e. it is a map of content
// hashes. A real credential is a lone value, not one of dozens of identical-
// width siblings, so it never trips the count.
//
// Conservative like the sibling body guards (IsBinaryBlobMatch,
// IsJSEscapeArtifactMatch): a snippet that is not lowercase hex, is outside the
// width band, is not quoted in the body, or lacks enough siblings keeps the
// finding — so a genuine secret served alongside a chunk map is still reported.
// It is pinned to the detector's exact match offsets (see resolveMatchSpan): with
// valid offsets the "sits in a quoted value" test checks the bytes bracketing the
// occurrence that fired; with start<0 it falls back to an any-occurrence
// quoted-substring search. The same-width sibling count is a property of the whole
// body, so it is unaffected by the offsets.
func IsChunkHashManifestMatch(body []byte, snippet string, start, end int) bool {
	if len(body) == 0 {
		return false
	}
	n := len(snippet)
	if n < chunkHashMinLen || n > chunkHashMaxLen {
		return false
	}
	if !isLowerHexRun(snippet) {
		return false
	}
	// The match must itself sit in a quoted-string value position — a bare hex
	// token in prose or a path is not a manifest entry.
	if !quotedValuePosition(body, snippet, start, end) {
		return false
	}
	// A chunk map carries dozens of same-width hashes; a credential payload a
	// handful at most. Stop scanning as soon as the threshold is reached — the
	// body can be a 10MB minified bundle, and the first handful of manifest
	// entries already settle the question.
	return countQuotedHexOfLen(body, n, minChunkHashSiblings) >= minChunkHashSiblings
}

// quotedValuePosition reports whether the matched snippet occupies a double-quoted
// value position (`"<snippet>"`). With valid detector offsets it checks the single
// byte on each side of the exact occurrence — pinning the test to the value that
// fired. Without offsets it falls back to the whole-body "any quoted occurrence"
// search the two-arg guard has always used.
func quotedValuePosition(body []byte, snippet string, start, end int) bool {
	if offsetsAreMatch(body, snippet, start, end) {
		return start > 0 && end < len(body) && body[start-1] == '"' && body[end] == '"'
	}
	return bytes.Contains(body, []byte(`"`+snippet+`"`))
}

// isLowerHexByte reports whether b is a lowercase hex digit (0-9, a-f) — the
// alphabet of a webpack/Vite content hash. Uppercase and the letters g-z are
// intentionally excluded: a genuine Looker client ID such as "1a2b…7g8h9i0j"
// carries letters past f, so it is never mistaken for a content hash.
func isLowerHexByte(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')
}

// isLowerHexRun reports whether s is a non-empty run of lowercase hex digits.
func isLowerHexRun(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isLowerHexByte(s[i]) {
			return false
		}
	}
	return true
}

// countQuotedHexOfLen counts the distinct double-quoted lowercase-hex strings of
// exactly n characters (`"` + n hex + `"`) in body, stopping early once the
// distinct count reaches stopAt (pass stopAt <= 0 to count them all). Matching
// the length exactly means a wider quoted hex string is not counted (the byte
// after n hex digits is another hex digit, not the closing quote), so each
// manifest width is tallied independently. Counting distinct values stops a
// single hash repeated many times from masquerading as a map.
func countQuotedHexOfLen(body []byte, n, stopAt int) int {
	seen := make(map[string]struct{})
	end := len(body)
	for i := 0; i < end; {
		if body[i] != '"' {
			i++
			continue
		}
		// Need an opening quote at i, n hex digits, then a closing quote — so the
		// closing quote sits at i+n+1 and must be within bounds.
		if i+n+1 >= end {
			break
		}
		ok := true
		for j := 1; j <= n; j++ {
			if !isLowerHexByte(body[i+j]) {
				ok = false
				break
			}
		}
		if ok && body[i+n+1] == '"' {
			seen[string(body[i+1:i+1+n])] = struct{}{}
			if stopAt > 0 && len(seen) >= stopAt {
				return len(seen)
			}
			i += n + 2 // jump past the closing quote
			continue
		}
		i++
	}
	return len(seen)
}
