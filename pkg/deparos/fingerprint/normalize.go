package fingerprint

import (
	"bytes"
	"net/url"
	"sort"
	"strings"
)

// pathSentinel replaces stripped URL fragments in normalized bodies. The
// constant width keeps response lengths roughly stable across probes so
// length-derived attributes (Content-Length, line/word counts) don't drift.
const pathSentinel = "__VIG_PATH__"

// minSegmentLen is the minimum path-segment length we'll strip individually.
// Bumped to 6 to avoid scrubbing common short words (api, rest, user) that
// frequently appear in legitimate body text.
const minSegmentLen = 6

// NormalizeBody returns body with substrings derived from reqURL replaced by
// a fixed sentinel. This makes fingerprint hashes stable across probes whose
// response bodies echo the requested URL (e.g. "Forbidden: /ftp/api/x" error
// pages where each probe gets a slightly different body).
//
// The function is conservative: it strips the full path + URL-encoded path,
// long path segments (>= 6 chars), and query values (>= 3 chars). It never
// strips short tokens that could collide with normal English words.
//
// reqURL=nil or empty body → returns body unchanged.
func NormalizeBody(body []byte, reqURL *url.URL) []byte {
	if reqURL == nil || len(body) == 0 {
		return body
	}

	needles := collectNeedles(reqURL)
	if len(needles) == 0 {
		return body
	}

	out := body
	sentinel := []byte(pathSentinel)
	for _, n := range needles {
		nb := []byte(n)
		if bytes.Contains(out, nb) {
			out = bytes.ReplaceAll(out, nb, sentinel)
		}
	}
	return out
}

// collectNeedles returns the substrings derived from reqURL that should be
// stripped from response bodies. The slice is ordered longest-first so that
// wider matches (full path) consume their substrings before per-segment
// matches get a chance to fragment them.
func collectNeedles(u *url.URL) []string {
	seen := make(map[string]struct{})
	add := func(s string) {
		if len(s) < 3 || s == "/" {
			return
		}
		seen[s] = struct{}{}
	}

	// Full path and trimmed variant.
	add(u.Path)
	add(strings.TrimPrefix(u.Path, "/"))

	// URL-encoded full path (some error pages re-emit the encoded form).
	if encoded := url.PathEscape(u.Path); encoded != u.Path {
		add(encoded)
	}

	// Long path segments (skip short common tokens to avoid false positives).
	for _, seg := range strings.Split(u.Path, "/") {
		if len(seg) >= minSegmentLen {
			add(seg)
		}
	}

	// Query values — these are usually concrete parameters, not English text.
	for _, vs := range u.Query() {
		for _, v := range vs {
			if len(v) >= 3 {
				add(v)
			}
		}
	}

	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}
