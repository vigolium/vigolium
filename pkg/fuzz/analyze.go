package fuzz

import (
	"bytes"

	"github.com/vigolium/vigolium/pkg/replay"
)

// signals extracts the response metrics (status/size/words/lines) from a send.
func signals(sum *replay.Summary) (status, length, words, lines int) {
	if sum == nil {
		return 0, 0, 0, 0
	}
	return sum.Status, sum.ResponseLen, countWords(sum.RawBody), countLines(sum.RawBody)
}

// countWords counts whitespace-separated tokens in the response body.
func countWords(body []byte) int {
	return len(bytes.Fields(body))
}

// countLines counts newlines in the response body.
func countLines(body []byte) int {
	if len(body) == 0 {
		return 0
	}
	return bytes.Count(body, []byte("\n"))
}

// reflected reports whether the payload appears verbatim in the response body.
// Guarded to non-trivial payloads so short tokens (e.g. "1", "'") don't produce
// meaningless reflection noise.
func reflected(body []byte, payload string) bool {
	if len(payload) < 3 {
		return false
	}
	return bytes.Contains(body, []byte(payload))
}

// keep applies the matcher/filter gate. A result is kept when it matches the
// matcher set (OR across configured categories; empty = match all) AND does not
// match any configured filter category (OR).
func keep(r Result, body []byte, m Matchers, f Filters) bool {
	if m.configured() && !matchesMatchers(r, body, m) {
		return false
	}
	if f.configured() && matchesFilters(r, body, f) {
		return false
	}
	return true
}

func matchesMatchers(r Result, body []byte, m Matchers) bool {
	if m.AllStatus {
		return true
	}
	if intIn(r.Status, m.Status) {
		return true
	}
	if intIn(r.Length, m.Sizes) {
		return true
	}
	if intIn(r.Words, m.Words) {
		return true
	}
	if intIn(r.Lines, m.Lines) {
		return true
	}
	if m.TimeMs > 0 && r.TimeMs >= m.TimeMs {
		return true
	}
	if m.Regex != nil && m.Regex.Match(body) {
		return true
	}
	return false
}

func matchesFilters(r Result, body []byte, f Filters) bool {
	if intIn(r.Status, f.Status) {
		return true
	}
	if intIn(r.Length, f.Sizes) {
		return true
	}
	if intIn(r.Words, f.Words) {
		return true
	}
	if intIn(r.Lines, f.Lines) {
		return true
	}
	if f.TimeMs > 0 && r.TimeMs >= f.TimeMs {
		return true
	}
	if f.Regex != nil && f.Regex.Match(body) {
		return true
	}
	return false
}

func intIn(v int, set []int) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

// calibration captures the target's wildcard/catch-all response fingerprint,
// learned by sending improbable probe values. A result whose (status,length)
// matches a learned signature is suppressed as noise.
type calibration struct {
	sigs map[calibSig]struct{}
}

type calibSig struct {
	status int
	length int
}

func (c *calibration) matches(status, length int) bool {
	if c == nil || len(c.sigs) == 0 {
		return false
	}
	_, ok := c.sigs[calibSig{status: status, length: length}]
	return ok
}
