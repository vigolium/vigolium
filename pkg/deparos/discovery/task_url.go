package discovery

import "strings"

// collapseDoubleSlashes collapses runs of consecutive '/' in a built discovery
// URL's path down to a single '/', leaving the scheme separator "://" intact.
//
// A stray double slash inherited from a discovered path (e.g.
// /jboss-net//happyaxis.jsp) makes a Jetty/nginx origin answer
// "400 Ambiguous URI empty segment" for every probe, and the error page echoes
// the requested URI — so each fuzzed variant otherwise lands as a distinct junk
// record. The fuzzing builders (extension/module/wordlist/numeric) route their
// output through here so such paths are never sent on the wire.
//
// The deliberate MalformedPathProbeTask does NOT use this — it preserves
// malformed paths verbatim by design.
func collapseDoubleSlashes(u string) string {
	// Skip the scheme separator so "https://" is preserved; collapse only the
	// path that follows, using the same idiom as redirect.go's NormalizePath.
	prefix, rest := "", u
	if i := strings.Index(u, "://"); i >= 0 {
		prefix, rest = u[:i+3], u[i+3:]
	}
	if !strings.Contains(rest, "//") {
		return u
	}
	for strings.Contains(rest, "//") {
		rest = strings.ReplaceAll(rest, "//", "/")
	}
	return prefix + rest
}
