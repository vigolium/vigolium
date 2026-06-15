package modkit

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/utils"
)

// MaxBasePathDepth caps how many base paths CandidateBasePaths returns (the web
// root plus ancestor directories of the observed path). It bounds the request
// fan-out a context-path-aware probe generates on deep URLs: real framework
// context paths (server.servlet.context-path, an API gateway prefix, a
// reverse-proxy mount) are almost always one or two segments, so the shallowest
// few prefixes capture nearly every genuine deployment.
const MaxBasePathDepth = 5

// CandidateBasePaths returns the base path prefixes under which a context-path-
// mounted application may expose a known endpoint. The result is the web root
// ("") first, then ancestor directories of the observed path shallowest-first,
// then the observed path itself when it looks like a directory (no file
// extension), e.g.:
//
//	"/api/v1/users" -> ["", "/api", "/api/v1", "/api/v1/users"]
//	"/myapp"        -> ["", "/myapp"]          (single-segment context root)
//	"/index.html"   -> [""]                     (a file, not a mount point)
//	"/assets/app.js"-> [""]                     (static-asset dirs are skipped)
//
// Callers append their endpoint suffix (e.g. "/actuator/env") to each base; the
// "" root yields the original root-anchored probe unchanged, so adopting this
// helper never loses the root coverage a module already had. Static-asset
// directories (/assets, /static, /css, ...) are skipped because known endpoints
// are never mounted under them, and the list is capped at MaxBasePathDepth to
// bound fan-out. Results are de-duplicated and order-stable (shallowest first).
func CandidateBasePaths(p string) []string {
	return candidateBasePaths(p, false)
}

// CandidateBasePathsIncludingStatic is CandidateBasePaths but keeps static-asset
// directory prefixes (/assets, /static, a CDN/object-storage path, ...). Use it
// for sensitive-file discovery, where a misconfigured static or CDN-fronted
// directory is exactly where an exposed .env / .git / backup is found — the one
// place a known-endpoint probe would never look. Known-endpoint modules should
// use CandidateBasePaths instead, which skips these.
func CandidateBasePathsIncludingStatic(p string) []string {
	return candidateBasePaths(p, true)
}

func candidateBasePaths(p string, includeStatic bool) []string {
	// Drop any query/fragment so a base is a real directory prefix.
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}

	bases := make([]string, 0, MaxBasePathDepth)
	seen := map[string]bool{"": true}
	bases = append(bases, "") // web root — preserves existing root-anchored coverage

	add := func(raw string) bool {
		b := "/" + strings.Trim(raw, "/")
		if b == "/" || seen[b] || (!includeStatic && IsStaticAssetPath(b)) {
			return true // skip, but keep walking
		}
		seen[b] = true
		bases = append(bases, b)
		return len(bases) < MaxBasePathDepth
	}

	for _, anc := range utils.SplitPathRecursive(p) {
		if !add(anc) {
			return bases
		}
	}

	// SplitPathRecursive drops the final segment, so a request straight to a
	// single-segment context root like "/myapp" yields no ancestors. Add the
	// observed path itself as a candidate base when it looks like a directory
	// rather than a file (a dot in the last segment marks a file or dotfile).
	if trimmed := strings.TrimRight(p, "/"); trimmed != "" && !lastSegmentLooksLikeFile(trimmed) {
		add(trimmed)
	}

	return bases
}

// lastSegmentLooksLikeFile reports whether the final path segment contains a dot,
// marking it a file (index.html) or dotfile (.env) rather than a directory that
// could be an application mount point.
func lastSegmentLooksLikeFile(p string) bool {
	seg := p
	if i := strings.LastIndex(p, "/"); i >= 0 {
		seg = p[i+1:]
	}
	return strings.Contains(seg, ".")
}

// BasePathClaimKey builds the per-scan dedup key for a (host, base path) pair so
// a base prefix shared by many observed requests is probed exactly once by a
// given module. The NUL separator cannot appear in a host or path, so distinct
// pairs never collide. Pass the result to a module's dedup DiskSet.IsSeen, which
// atomically claims the pair (returns false and marks it on first sight, true
// thereafter) — this both de-duplicates across requests and prevents two
// concurrent workers from probing the same base.
func BasePathClaimKey(host, base string) string {
	return host + "\x00" + base
}

// UnclaimedBasePaths returns the subset of candidates this scan has not yet
// probed for host, atomically claiming each returned base via diskSet (IsSeen is
// test-and-set: false-and-claim on first sight, true thereafter). It collapses
// the per-(host,base) dedup loop every context-path-walking module runs into one
// call; pass the output of CandidateBasePaths / CandidateBasePathsIncludingStatic.
// Order is preserved (so the web root "" stays first when unclaimed). A nil
// diskSet returns candidates unchanged.
func UnclaimedBasePaths(diskSet *dedup.DiskSet, host string, candidates []string) []string {
	if diskSet == nil {
		return candidates
	}
	bases := make([]string, 0, len(candidates))
	for _, base := range candidates {
		if diskSet.IsSeen(BasePathClaimKey(host, base)) {
			continue
		}
		bases = append(bases, base)
	}
	return bases
}

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

// DecoyFileBaseline fetches a guaranteed-nonexistent file that shares probePath's
// parent directory AND file extension, and returns its response status and body
// for baseline subtraction. It is the file-discovery baseline companion to
// SiblingPathCatchAll: a directory (or extension-specific handler) that answers
// every <dir>/<anything>.<ext> request with the same content — a SPA fallback, a
// logging proxy, a catch-all object store — returns that content for the decoy
// too, so an exposed-file candidate whose body is textually equivalent to the
// decoy (BodiesSimilar) is a false positive. This is exactly the
// "/orders/run.log and /orders/<random>.log return the same body" case.
//
// The decoy keeps the candidate's extension because catch-alls are frequently
// extension-scoped (a *.log handler, a static *.json fallback); a no-extension
// probe would miss them. ok is false on any build/transport error or a missing
// response, so a flaky decoy fetch never suppresses a real finding (fail-open).
// The probe runs with NoClustering so the host's per-request response cache does
// not alias it to the candidate's own cached entry.
func DecoyFileBaseline(
	ctx *httpmsg.HttpRequestResponse,
	client *http.Requester,
	probePath string,
) (status int, body string, ok bool) {
	if ctx == nil || ctx.Request() == nil || client == nil {
		return 0, "", false
	}

	p := probePath
	if q := strings.IndexAny(p, "?#"); q >= 0 {
		p = p[:q]
	}
	dir, name := "/", p
	if i := strings.LastIndex(p, "/"); i >= 0 {
		dir, name = p[:i+1], p[i+1:] // keep the trailing slash on dir
	}
	// A dot at index > 0 marks a real extension; a leading dot (.env, .git) is a
	// dotfile name, not an extension, so it yields no decoy suffix.
	ext := ""
	if d := strings.LastIndex(name, "."); d > 0 {
		ext = name[d:]
	}
	decoyPath := dir + "vigolium-decoy-" + FreshCanary() + ext
	// NoRedirects: a decoy that 30x-redirects is not a served baseline body.
	return fetchGET(ctx, client, decoyPath, http.Options{NoRedirects: true, NoClustering: true})
}

// RandomDirCatchAll GETs a guaranteed-nonexistent directory (a random path with
// a trailing slash, at the web root) and reports whether its 2xx body already
// satisfies match. It is the host-wide catch-all guard for directory-listing
// probes: a real autoindex/serve-index server returns a listing only for
// directories that exist on disk and 404s a random non-existent dir, so if a
// random dir already "lists" (or matches the detector at all), the host renders
// that body for ANY path — an SPA shell, a wildcard rewrite, a templated soft-404
// — and every per-directory finding is spurious. Drop the whole host's findings
// when this returns true.
//
// The trailing slash matters: directory handlers key on it. Runs with
// NoRedirects (a 30x is not a served listing) and NoClustering (so the probe is
// not aliased to a cached entry). Returns false on any build/transport error, a
// missing/non-2xx response, or a nil match (fail-open — a flaky probe never
// suppresses a real finding).
func RandomDirCatchAll(
	ctx *httpmsg.HttpRequestResponse,
	client *http.Requester,
	match func(body string) bool,
) bool {
	if match == nil {
		return false
	}
	status, body, ok := fetchGET(ctx, client, "/vigolium-catchall-dir-"+FreshCanary()+"/", http.Options{NoRedirects: true, NoClustering: true})
	if !ok || status < 200 || status >= 300 {
		return false
	}
	return match(body)
}

// MultiRoundExtDecoyCatchAll probes `rounds` distinct guaranteed-nonexistent
// siblings that share probePath's parent directory AND file extension (e.g.
// /WEB-INF/vigolium-decoy-<rand>.xml for /WEB-INF/web.xml) and reports whether
// the path is served by an extension-scoped catch-all rather than a real file.
//
// It is the multi-round companion to DecoyFileBaseline, built for the
// application-shell host that answers EVERY /<dir>/<anything>.<ext> with the
// same 200 page (a SPA fallback, a reverse-proxy wildcard, a Salesforce-style
// framework shell). The root soft-404 fingerprint these modules take cannot see
// such a catch-all — it probes a no-extension path at the web root, and a shell
// that embeds the request path / a session token differs enough per path to dodge
// the fingerprint's hash and length checks — so a weak content marker that merely
// appears somewhere in the shell forges a finding. Requesting
// /WEB-INF/thisisclearly404.xml and observing the same shell come back is the
// direct disproof.
//
// A round trips the catch-all when its decoy returns the SAME status as the
// candidate AND either the decoy body satisfies markerMatch (the same markers the
// candidate matched) or is textually ~equal (BodiesSimilar) to candidateBody.
// Returns true (catch-all → drop the candidate) as soon as any round trips;
// returns false when every round 404s / errors / serves a clearly different body.
// Each round uses a fresh canary (DecoyFileBaseline) so a per-path response cache
// cannot alias the decoys to one another. rounds < 1 is treated as 1. Fails OPEN
// per round (a transport error or missing decoy response cannot prove a catch-all)
// so a flaky probe never suppresses a real finding.
func MultiRoundExtDecoyCatchAll(
	ctx *httpmsg.HttpRequestResponse,
	client *http.Requester,
	probePath, candidateBody string,
	candidateStatus, rounds int,
	markerMatch func(body string) bool,
) bool {
	if rounds < 1 {
		rounds = 1
	}
	for i := 0; i < rounds; i++ {
		decoyStatus, decoyBody, served := DecoyFileBaseline(ctx, client, probePath)
		if !served || decoyStatus != candidateStatus {
			continue // a 404 / differently-statused / errored decoy is the real-file case
		}
		if markerMatch != nil && markerMatch(decoyBody) {
			return true // decoy carries the same markers → extension-scoped catch-all
		}
		if candidateBody != "" && BodiesSimilar(decoyBody, candidateBody) {
			return true // decoy body ≈ candidate body → catch-all shell
		}
	}
	return false
}

// FetchPath issues a fresh GET to probePath carrying the observed request's
// headers and service, with the response cache bypassed (NoClustering) so a
// reproduce/re-confirmation probe is never aliased to a cached entry. It returns
// the response status and body; ok is false on any build/transport error so a
// flaky fetch never suppresses a finding (fail-open). It is the shared re-fetch
// primitive behind the file-discovery confirmation rounds.
func FetchPath(ctx *httpmsg.HttpRequestResponse, client *http.Requester, probePath string) (status int, body string, ok bool) {
	return fetchGET(ctx, client, probePath, http.Options{NoClustering: true})
}

// fetchGET is the shared GET primitive: it rebuilds the observed request as a GET
// to path (preserving headers and service) and executes it with opts. ok is false
// on any build/transport error or a missing response, so every caller fails open.
func fetchGET(
	ctx *httpmsg.HttpRequestResponse,
	client *http.Requester,
	path string,
	opts http.Options,
) (status int, body string, ok bool) {
	if ctx == nil || ctx.Request() == nil || client == nil {
		return 0, "", false
	}
	raw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return 0, "", false
	}
	raw, err = httpmsg.SetPath(raw, path)
	if err != nil {
		return 0, "", false
	}
	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return 0, "", false
	}
	req = req.WithService(ctx.Service())

	resp, _, err := client.Execute(req, opts)
	if err != nil {
		return 0, "", false
	}
	defer resp.Close()
	if resp.Response() == nil {
		return 0, "", false
	}
	return resp.Response().StatusCode, resp.Body().String(), true
}

// SiblingServesAnyMarker reports whether a guaranteed-nonexistent sibling under
// probePath's parent directory returns a body containing any of markers — i.e. a
// sub-directory catch-all that 200s every child with the same content. It is the
// flat-marker ([]string) convenience over SiblingPathCatchAll, replacing the
// "for marker := range markers { strings.Contains }" closure the path-probing
// modules each hand-rolled. Returns false (no catch-all detected) for empty
// markers, a root-level probe path, or any probe error.
func SiblingServesAnyMarker(
	ctx *httpmsg.HttpRequestResponse,
	client *http.Requester,
	probePath string,
	markers []string,
) bool {
	return SiblingPathCatchAll(ctx, client, probePath, func(b string) bool {
		for _, marker := range markers {
			if marker != "" && strings.Contains(b, marker) {
				return true
			}
		}
		return false
	})
}

// ResemblesObservedPage reports whether probeBody is textually equivalent
// (BodiesSimilar, QuickRatio >= UpperRatioBound) to the page originally observed
// on ctx — the request/response the module was handed before it began probing.
// A catch-all / SPA application serves that same application shell for an
// arbitrary path, so a path-probe whose response matches the observed page is a
// false positive: the body is "the same with or without the probe". It is the
// shared catch-all-shell guard for path-probing exposure modules — place it after
// the soft-404 fingerprint and before marker matching, dropping the candidate
// when it returns true.
//
// Returns false (fail-open) when ctx carries no baseline response or an empty
// observed body, so a module invoked without a captured baseline never has a real
// finding suppressed. A genuinely exposed file (source, config, log, directory
// listing) is never ~95% similar to the homepage shell, so the guard does not
// cost true positives.
func ResemblesObservedPage(ctx *httpmsg.HttpRequestResponse, probeBody string) bool {
	if ctx == nil || ctx.Response() == nil {
		return false
	}
	baseline := ctx.Response().BodyToString()
	if baseline == "" {
		return false
	}
	return BodiesSimilar(probeBody, baseline)
}

// StripReflectedProbePath removes occurrences of the probe path from body so a
// marker that merely echoes the request path cannot satisfy a marker check. A
// path-routing app reflects the requested URL straight into the page — a
// <form action="/.../admin">, an href, a breadcrumb, a JSON "path":"/x" field —
// so a generic-word marker that is also a segment of the probe path (e.g.
// "admin" for /admin, "profiler" for /_profiler/, "restart" for
// /.~~spring-boot!~/restart) matches our OWN request, not the endpoint's content.
// This is the self-reflection FP class. Strip the reflected path before marker
// matching so a marker only counts when it comes from the endpoint's own body.
//
// Both the full path and its query-stripped prefix are removed (a reflected
// <form action> commonly drops the query string). Returns body unchanged for an
// empty probePath or body. Run it ONLY for the marker match — keep the original
// body for the shell/soft-404 guards and for the stored response evidence.
func StripReflectedProbePath(body, probePath string) string {
	if probePath == "" || body == "" {
		return body
	}
	body = strings.ReplaceAll(body, probePath, "")
	if i := strings.IndexAny(probePath, "?#"); i > 0 {
		body = strings.ReplaceAll(body, probePath[:i], "")
	}
	return body
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
