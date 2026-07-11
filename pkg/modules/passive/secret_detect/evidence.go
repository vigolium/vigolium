package secret_detect

import "github.com/vigolium/vigolium/pkg/modules/modkit"

// Evidence-rendering tunables. A small response body is shown in full; a large
// one (typically a minified JS bundle) is reduced to a window around the matched
// secret so the finding carries useful context without storing a multi-megabyte
// asset. These mirror the long-standing secret_detect behavior; the windowing
// itself is the shared modkit.WindowBody helper.
const (
	// evidenceFullThreshold is the body size (bytes) at or below which the whole
	// body is shown verbatim. Above it, only a window around the match is kept.
	evidenceFullThreshold = 8 * 1024

	// evidenceContextLines is how many lines of context to show on each side of
	// the matched line in a windowed body.
	evidenceContextLines = 5

	// evidenceContextChars caps the window to this many bytes on each side of the
	// match. This bounds the minified single-line case, where evidenceContextLines
	// would otherwise span the entire bundle.
	evidenceContextChars = 512
)

// BuildEvidenceResponse renders the raw HTTP response head (status line plus
// headers, no body) followed by a body view. Small bodies are shown in full;
// large bodies are reduced to a window anchored on the detector's [start, end)
// byte offsets, so the window centers on the exact occurrence that fired rather
// than the first textual occurrence of snippet. The snippet (as a locator) and
// matchLine are fallback anchors for when the offsets are unavailable (start<0)
// or out of range.
func BuildEvidenceResponse(head string, body []byte, snippet string, start, end, matchLine int) string {
	return head + modkit.WindowBodyAt(body, start, end, []string{snippet}, matchLine, modkit.ResponseWindowOpts{
		FullThreshold: evidenceFullThreshold,
		ContextLines:  evidenceContextLines,
		ContextChars:  evidenceContextChars,
		FallbackLines: evidenceContextLines,
	})
}
