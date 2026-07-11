package secret_detect

// binaryBlobSurroundThreshold is how many contiguous base64-family characters
// must surround a match (before + after, with no delimiter between them and the
// match) for it to be treated as a chunk of encoded binary — an inline data:
// URI image, embedded font, or asset blob rendered into the page — rather than a
// standalone secret literal.
//
// A genuine credential is a bounded token: it sits between delimiters (quotes,
// =, :, &, ?, whitespace, line breaks), so it has ~0 base64 characters glued
// onto it as a prefix or suffix. A generic fixed-length / high-entropy token
// rule (e.g. ZeroTier's [A-Za-z0-9]{32}) matching mid-stream inside a large
// base64 image instead has hundreds of thousands. 160 leaves a wide margin: no
// real delimited secret carries 160 unbroken base64 characters as padding, while
// every encoded blob clears it by orders of magnitude (and an RS256 JWT
// signature substring — also a false positive — is caught too).
const binaryBlobSurroundThreshold = 160

// isBase64FamilyByte reports whether b belongs to the base64 / base64url
// alphabet (including padding). These are exactly the bytes that make up an
// unbroken encoded-binary stream; anything else — whitespace, line breaks,
// quotes, ., :, &, ?, , — delimits a real token.
func isBase64FamilyByte(b byte) bool {
	return (b >= 'A' && b <= 'Z') ||
		(b >= 'a' && b <= 'z') ||
		(b >= '0' && b <= '9') ||
		b == '+' || b == '/' || b == '=' || b == '-' || b == '_'
}

// IsBinaryBlobMatch reports whether the matched secret snippet is embedded
// inside a long contiguous run of base64-family characters in body — i.e. it is
// a substring of encoded binary (an inline data: URI image, embedded font, or
// gzip/asset blob rendered into the page) rather than a delimited credential.
//
// This is a dominant false-positive class for generic fixed-length / high-
// entropy token rules: a 32-character [A-Za-z0-9] pattern will match somewhere
// inside almost any large base64 image, so a benign 4xx error page that ships a
// branded inline graphic gets reported as a leaked API token. Dropping the match
// by its surrounding bytes — rather than by status code or content type — means a
// genuine secret served in the same response is still reported.
//
// The guard is pinned to the detector's exact match offsets (see resolveMatchSpan)
// so it inspects the base64-family run surrounding the occurrence that fired,
// not the first textual occurrence of snippet — the same value seen both in an
// encoded blob and in a delimited assignment is judged by the position that
// actually matched. Passing start<0 (no offsets) locates by substring instead.
//
// The check is conservative: if the snippet cannot be located verbatim in body
// it returns false (keep the finding), so it never drops a match it cannot
// positively explain.
func IsBinaryBlobMatch(body []byte, snippet string, start, end int) bool {
	idx, matchEnd, ok := resolveMatchSpan(body, snippet, start, end)
	if !ok {
		return false
	}

	// Count contiguous base64-family bytes immediately before the match. A
	// delimiter (quote, whitespace, line break, . : & ? …) stops the run, so a
	// normally-delimited token scores 0 here.
	before := 0
	for i := idx - 1; i >= 0 && isBase64FamilyByte(body[i]); i-- {
		before++
	}
	// …and immediately after.
	after := 0
	for i := matchEnd; i < len(body) && isBase64FamilyByte(body[i]); i++ {
		after++
	}

	return before+after >= binaryBlobSurroundThreshold
}
