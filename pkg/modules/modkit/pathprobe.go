package modkit

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// MatchAllGroups reports whether body satisfies every group in requireAll — it
// must contain at least one substring from EACH group (an AND across groups, OR
// within each group). This is the structural-confirmation primitive shared by
// the path-probing exposure modules: instead of firing on any single weak
// substring (which catch-all / SPA / i18n handlers trivially contain — e.g. a
// bare "status", "name", or "filter"), a probe lists one group of strong anchor
// synonyms plus one or more corroborating groups, so a finding requires the
// co-occurrence that only the real endpoint emits.
//
// matched returns the specific substring hit from each group (suitable for
// ExtractedResults / finding evidence). ok is false — and matched nil — if any
// group has no hit, or requireAll is empty (a probe with no confirmation tokens
// never fires).
func MatchAllGroups(body string, requireAll [][]string) (matched []string, ok bool) {
	if len(requireAll) == 0 {
		return nil, false
	}
	matched = make([]string, 0, len(requireAll))
	for _, group := range requireAll {
		hit := ""
		for _, sub := range group {
			if sub != "" && strings.Contains(body, sub) {
				hit = sub
				break
			}
		}
		if hit == "" {
			return nil, false
		}
		matched = append(matched, hit)
	}
	return matched, true
}

// SiblingPathCatchAll probes a guaranteed-nonexistent sibling under the SAME
// parent directory as probePath and reports whether its 200 response satisfies
// match. It is the catch-all guard for path-probing modules: a genuinely exposed
// endpoint serves its content only at its own path, whereas a catch-all handler
// (SPA fallback, i18n/static blob server, reverse-proxy wildcard) returns the
// same body for an arbitrary sibling too. The root-scoped soft-404 fingerprint
// these modules already take cannot see a catch-all scoped to a sub-directory
// prefix (e.g. /admin/*, /actuator/gateway/*, /jolokia/*); this sibling probe can.
//
// Root-level probe paths (a single path segment, e.g. /admin or /jolokia) are a
// no-op here and return false: their sibling IS a random root path, which the
// caller's existing root 404 fingerprint already covers. Returns false on any
// build/transport error or a non-200 sibling so a flaky probe never suppresses a
// real finding.
func SiblingPathCatchAll(
	ctx *httpmsg.HttpRequestResponse,
	client *http.Requester,
	probePath string,
	match func(body string) bool,
) bool {
	if ctx == nil || ctx.Request() == nil || client == nil || match == nil {
		return false
	}

	parent := ""
	if trimmed := strings.TrimRight(probePath, "/"); trimmed != "" {
		// Drop any query string so the parent is a real directory.
		if q := strings.IndexByte(trimmed, '?'); q >= 0 {
			trimmed = trimmed[:q]
		}
		if i := strings.LastIndex(trimmed, "/"); i > 0 {
			parent = trimmed[:i]
		}
	}
	if parent == "" {
		return false // root-level path: covered by the caller's root soft-404 fingerprint
	}
	siblingPath := parent + "/" + FreshCanary()

	raw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return false
	}
	raw, err = httpmsg.SetPath(raw, siblingPath)
	if err != nil {
		return false
	}
	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return false
	}
	req = req.WithService(ctx.Service())

	resp, _, err := client.Execute(req, http.Options{NoRedirects: true})
	if err != nil {
		return false
	}
	defer resp.Close()
	if resp.Response() == nil || resp.Response().StatusCode != 200 {
		return false
	}
	return match(resp.Body().String())
}

// MatchAndConfirmSibling is the combined marker-match + catch-all guard used by
// the marker-based path-probing exposure modules. It confirms body satisfies the
// marker groups (MatchAllGroups), then drops the finding if a guaranteed-
// nonexistent sibling under the same parent directory returns the same markers
// (SiblingPathCatchAll) — a catch-all handler that 200s every child path. Root-
// level probe paths are already covered by the caller's root soft-404
// fingerprint, so the sibling probe is a no-op for them.
//
// matched carries the evidence substrings for ExtractedResults; ok is false (and
// matched nil) when the body doesn't satisfy the groups or the sibling reveals a
// catch-all.
func MatchAndConfirmSibling(
	ctx *httpmsg.HttpRequestResponse,
	client *http.Requester,
	probePath, body string,
	markers [][]string,
) (matched []string, ok bool) {
	matched, ok = MatchAllGroups(body, markers)
	if !ok {
		return nil, false
	}
	if SiblingPathCatchAll(ctx, client, probePath, func(b string) bool {
		_, sibOK := MatchAllGroups(b, markers)
		return sibOK
	}) {
		return nil, false
	}
	return matched, true
}
