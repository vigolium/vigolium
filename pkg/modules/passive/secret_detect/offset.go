package secret_detect

import "bytes"

// resolveMatchSpan returns the [start, end) byte span of the matched secret
// within body. When the detector's own offsets are supplied and valid (start>=0,
// the span is in range, and its bytes equal snippet) they are used verbatim —
// pinning every structural guard to the exact occurrence the detector matched, so
// a value that appears both inside an encoded blob and in a genuine assignment is
// classified by the occurrence that actually fired rather than the first textual
// one. When no offsets are given (start<0) or they don't line up with body (a
// caller grading against a different body copy), it falls back to the first
// verbatim occurrence, returning ok=false when the snippet is absent — preserving
// the long-standing "can't locate it → keep the finding" conservatism the guards
// rely on.
func resolveMatchSpan(body []byte, snippet string, start, end int) (int, int, bool) {
	if snippet == "" || len(body) == 0 {
		return 0, 0, false
	}
	if offsetsAreMatch(body, snippet, start, end) {
		return start, end, true
	}
	idx := bytes.Index(body, []byte(snippet))
	if idx < 0 {
		return 0, 0, false
	}
	return idx, idx + len(snippet), true
}

// offsetsAreMatch reports whether [start, end) are valid detector offsets whose
// bytes equal snippet — i.e. the caller passed real match offsets (start>=0) that
// line up with body. It is the shared "are these the real match offsets?"
// predicate for resolveMatchSpan and the guards' offset-precise branches.
func offsetsAreMatch(body []byte, snippet string, start, end int) bool {
	return start >= 0 && end > start && end <= len(body) && bytes.Equal(body[start:end], []byte(snippet))
}
