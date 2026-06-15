package modkit

import (
	"bytes"
	"fmt"
	"strings"
)

// ResponseWindowOpts tunes WindowBody. It lets a caller trade off how much
// context to keep around a match against how large the stored evidence may grow.
type ResponseWindowOpts struct {
	// FullThreshold is the body size (bytes) at or below which the whole body is
	// returned verbatim. Above it, only a window is kept.
	FullThreshold int
	// ContextLines is how many lines of context to keep on each side of a located
	// match.
	ContextLines int
	// ContextChars caps the window to this many bytes on each side of the match so
	// a single very long line (a minified bundle) can't defeat the line window.
	ContextChars int
	// FallbackLines is how many lines from the start of the body to keep when no
	// locator matches and no usable line anchor is given.
	FallbackLines int
}

// DefaultResponseWindowOpts is the tuning used when storing a static-asset
// response body on a finding: keep bodies up to 8 KB whole; otherwise window 10
// lines / 1 KB on each side of the match, or the first 5 lines when the match
// can't be located.
func DefaultResponseWindowOpts() ResponseWindowOpts {
	return ResponseWindowOpts{
		FullThreshold: 8 * 1024,
		ContextLines:  10,
		ContextChars:  1024,
		FallbackLines: 5,
	}
}

// WindowBody returns a view of body suitable for storing as finding evidence.
// Bodies at or below opts.FullThreshold are returned unchanged. Larger bodies are
// reduced to a window centered on the first entry of locators found in the body
// (each tried verbatim, then on the tail after its last ": " so a wrapped label
// like "Matched: <x>" or "MD5 hash near 'k': <x>" still resolves); failing that,
// on the 1-indexed matchLine when > 1; failing that, on the first
// opts.FallbackLines lines. The kept window spans opts.ContextLines lines on each
// side, clamped to opts.ContextChars bytes, and dropped edges are marked with a
// "... [N bytes truncated] ..." note.
func WindowBody(body []byte, locators []string, matchLine int, opts ResponseWindowOpts) string {
	if len(body) <= opts.FullThreshold {
		return string(body)
	}

	start, end, found := locateAny(body, locators)
	if !found && matchLine > 1 {
		// Zero-width anchor at the start of the reported line.
		start = lineStartOffset(body, matchLine)
		end = start
		found = true
	}
	if !found {
		// Head-of-body fallback: the first FallbackLines lines, byte-capped so a
		// minified single-line body (no newlines) can't dump the whole asset.
		e := firstNLinesEnd(body, opts.FallbackLines)
		if opts.FullThreshold > 0 && e > opts.FullThreshold {
			e = opts.FullThreshold
		}
		return renderWindow(body, 0, e)
	}

	// Line window: ContextLines full lines on each side of the match.
	lineStart := lineWindowStart(body, start, opts.ContextLines)
	lineEnd := lineWindowEnd(body, end, opts.ContextLines)

	// Char window: a hard byte cap on each side of the match.
	charStart := start - opts.ContextChars
	if charStart < 0 {
		charStart = 0
	}
	charEnd := end + opts.ContextChars
	if charEnd > len(body) {
		charEnd = len(body)
	}

	// Take the tighter of the two windows on each side: show ContextLines of
	// context, but never more than ContextChars worth.
	return renderWindow(body, max(lineStart, charStart), min(lineEnd, charEnd))
}

// renderWindow returns body[start:end] with a "... [N bytes truncated] ..." note
// on any edge that was cut.
func renderWindow(body []byte, start, end int) string {
	if start < 0 {
		start = 0
	}
	if end > len(body) {
		end = len(body)
	}
	if start > end {
		start = end
	}
	var b strings.Builder
	if start > 0 {
		fmt.Fprintf(&b, "... [%d bytes truncated] ...\n", start)
	}
	b.Write(body[start:end])
	if end < len(body) {
		fmt.Fprintf(&b, "\n... [%d bytes truncated] ...", len(body)-end)
	}
	return b.String()
}

// locateAny returns the [start, end) byte range of the first locator found in
// body, or found=false when none match.
func locateAny(body []byte, locators []string) (start, end int, found bool) {
	for _, loc := range locators {
		if s, e, ok := locateOne(body, loc); ok {
			return s, e, true
		}
	}
	return 0, 0, false
}

// locateOne tries the locator verbatim, then — to resolve descriptive labels such
// as "Matched: <token>" or "MD5 hash near 'k': <token>" — the substring after its
// last ": ".
func locateOne(body []byte, locator string) (start, end int, found bool) {
	s := strings.TrimSpace(locator)
	if s == "" {
		return 0, 0, false
	}
	if idx := bytes.Index(body, []byte(s)); idx >= 0 {
		return idx, idx + len(s), true
	}
	if i := strings.LastIndex(s, ": "); i >= 0 {
		if tail := strings.TrimSpace(s[i+2:]); tail != "" && tail != s {
			if idx := bytes.Index(body, []byte(tail)); idx >= 0 {
				return idx, idx + len(tail), true
			}
		}
	}
	return 0, 0, false
}

// lineStartOffset returns the byte offset of the start of the 1-indexed line.
func lineStartOffset(body []byte, line int) int {
	off := 0
	for n := 1; n < line && off < len(body); n++ {
		nl := bytes.IndexByte(body[off:], '\n')
		if nl < 0 {
			break
		}
		off += nl + 1
	}
	return off
}

// firstNLinesEnd returns the byte offset just past the nth newline (the end of the
// first n lines), or len(body) if the body has fewer than n lines.
func firstNLinesEnd(body []byte, n int) int {
	off := 0
	for i := 0; i < n; i++ {
		nl := bytes.IndexByte(body[off:], '\n')
		if nl < 0 {
			return len(body)
		}
		off += nl + 1
	}
	return off
}

// lineWindowStart returns the byte offset of the start of the line that is ctx
// lines before the line containing pos.
func lineWindowStart(body []byte, pos, ctx int) int {
	if pos > len(body) {
		pos = len(body)
	}
	home := bytes.LastIndexByte(body[:pos], '\n') + 1 // start of pos's line (0 if none)
	for i := 0; i < ctx && home > 0; i++ {
		home = bytes.LastIndexByte(body[:home-1], '\n') + 1
	}
	return home
}

// lineWindowEnd returns the byte offset of the end of the line that is ctx lines
// after the line containing pos (the offset of the terminating newline, or
// len(body) if the window runs to the end).
func lineWindowEnd(body []byte, pos, ctx int) int {
	if pos >= len(body) {
		return len(body)
	}
	nl := bytes.IndexByte(body[pos:], '\n')
	if nl < 0 {
		return len(body)
	}
	end := pos + nl // newline ending pos's line
	for i := 0; i < ctx; i++ {
		next := bytes.IndexByte(body[end+1:], '\n')
		if next < 0 {
			return len(body)
		}
		end += 1 + next
	}
	return end
}
