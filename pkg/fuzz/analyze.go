package fuzz

import (
	"bytes"
	"html"
	"net/http"
	"net/textproto"
	"net/url"
	"sort"
	"strings"

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
// A single pass rather than len(bytes.Fields(body)): Fields allocates a slice
// header per word purely to be measured, which on a 100KB page is ~300KB of
// garbage per send.
func countWords(body []byte) int {
	count, inWord := 0, false
	for _, c := range body {
		switch c {
		case ' ', '\t', '\n', '\r', '\v', '\f':
			inWord = false
		default:
			if !inWord {
				count++
				inWord = true
			}
		}
	}
	return count
}

// countLines counts newlines in the response body.
func countLines(body []byte) int {
	if len(body) == 0 {
		return 0
	}
	return bytes.Count(body, []byte("\n"))
}

// reflectionOf reports where and how a payload came back. Guarded to
// non-trivial payloads so short tokens (e.g. "1", "'") don't produce
// meaningless reflection noise.
//
// Both the location and the encoding matter. Body-only checking misses
// Location and Set-Cookie echoes, which are the entire signal for open
// redirect and response splitting; and conflating a verbatim echo with an
// HTML-escaped one hides the difference between "this might execute" and "the
// app escaped it correctly".
func reflectionOf(body []byte, headers http.Header, payload string) (any_, raw bool, where []string) {
	if len(payload) < 3 {
		return false, false, nil
	}
	p := []byte(payload)
	// Built once: the escapings are a function of the payload alone, and this
	// is otherwise recomputed for the body plus every header value.
	forms := encodedForms(payload)

	if bytes.Contains(body, p) {
		raw = true
		where = append(where, "body")
	} else if anyForm(forms, func(f string) bool { return bytes.Contains(body, []byte(f)) }) {
		where = append(where, "body")
	}

	for name, values := range headers {
		for _, v := range values {
			if strings.Contains(v, payload) {
				raw = true
				where = append(where, "header:"+name)
				break
			}
			if anyForm(forms, func(f string) bool { return strings.Contains(v, f) }) {
				where = append(where, "header:"+name)
				break
			}
		}
	}
	if len(where) > 1 {
		sort.Strings(where)
	}
	return len(where) > 0, raw, where
}

// encodedForms returns the escapings an application might apply when echoing a
// payload back, minus any that are identical to the payload itself.
func encodedForms(payload string) []string {
	var forms []string
	for _, f := range []string{
		html.EscapeString(payload),
		url.QueryEscape(payload),
		url.PathEscape(payload),
		strings.ReplaceAll(payload, `"`, `\"`), // JSON/JS string escaping
	} {
		if f != payload {
			forms = append(forms, f)
		}
	}
	return forms
}

// anyForm reports whether match accepts any of the escaped forms.
func anyForm(forms []string, match func(string) bool) bool {
	for _, f := range forms {
		if match(f) {
			return true
		}
	}
	return false
}

// dedupeStrings removes duplicates while preserving order.
func dedupeStrings(in []string) []string {
	if len(in) < 2 {
		return in
	}
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// keep applies the matcher/filter gate. A result is kept when it satisfies the
// matcher set (empty = match all) AND does not satisfy any configured filter.
func keep(r Result, body []byte, headers http.Header, m Matchers, f Filters) bool {
	if m.configured() && !m.match(r, body, headers) {
		return false
	}
	if f.configured() && f.match(r, body, headers) {
		return false
	}
	return true
}

// match evaluates the configured categories under the criteria's mode.
func (c Criteria) match(r Result, body []byte, headers http.Header) bool {
	if c.AllStatus {
		return true
	}

	var evaluated, passed int
	check := func(ok bool) {
		evaluated++
		if ok {
			passed++
		}
	}

	if !c.Status.Empty() {
		check(c.Status.Match(int64(r.Status)))
	}
	if !c.Sizes.Empty() {
		check(c.Sizes.Match(int64(r.Length)))
	}
	if !c.Words.Empty() {
		check(c.Words.Match(int64(r.Words)))
	}
	if !c.Lines.Empty() {
		check(c.Lines.Match(int64(r.Lines)))
	}
	if !c.TimeMs.Empty() {
		check(c.TimeMs.Match(r.TimeMs))
	}
	if !c.TimeZ.Empty() {
		check(c.TimeZ.Match(int64(r.TimeZ)))
	}
	if c.Regex != nil {
		check(c.Regex.Match(body))
	}
	for _, h := range c.Headers {
		check(matchHeader(headers, h))
	}

	if evaluated == 0 {
		return false
	}
	if c.Mode == MatchAll {
		return passed == evaluated
	}
	return passed > 0
}

// matchHeader tests one header criterion. A nil Value means the header just
// has to be present.
func matchHeader(headers http.Header, h HeaderMatcher) bool {
	if headers == nil {
		return false
	}
	values, ok := headers[textproto.CanonicalMIMEHeaderKey(h.Name)]
	if !ok || len(values) == 0 {
		return false
	}
	if h.Value == nil {
		return true
	}
	for _, v := range values {
		if h.Value.MatchString(v) {
			return true
		}
	}
	return false
}

// calibration captures the target's wildcard/catch-all response fingerprint
// at one position, learned by sending improbable probe values there. A result
// whose signature matches a learned one is suppressed as noise.
//
// The match is deliberately approximate: a catch-all page that reflects the
// probe (or carries a timestamp or a CSRF token) differs by a few bytes per
// send, and an exact (status, length) key never matched it again — so the
// noise it was meant to remove came straight through.
type calibration struct {
	sigs []calibSig
}

// calibSig is one learned catch-all shape: status and word count exactly,
// length within a tolerance band (see lengthClose).
type calibSig struct {
	status int
	length int
	words  int
}

// lengthClose reports whether two body lengths fall in the same bucket:
// within max(16 bytes, 2% of the reference).
func lengthClose(ref, got int) bool {
	tol := ref / 50
	if tol < 16 {
		tol = 16
	}
	d := got - ref
	if d < 0 {
		d = -d
	}
	return d <= tol
}

func (s calibSig) matches(status, length, words int) bool {
	return s.status == status && s.words == words && lengthClose(s.length, length)
}

func (c *calibration) matches(status, length, words int) bool {
	if c == nil {
		return false
	}
	for _, s := range c.sigs {
		if s.matches(status, length, words) {
			return true
		}
	}
	return false
}
