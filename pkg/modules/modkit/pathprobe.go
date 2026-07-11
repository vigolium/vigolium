package modkit

import (
	"strings"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/utils"
)

const (
	// decoyCacheSize bounds the per-scan catch-all decoy cache (LRU).
	decoyCacheSize = 512
	// decoyBodyCap caps how much of a decoy body is retained for comparison; the
	// catch-all shell identity lives in the head and the similarity helpers cap
	// their scan at ratioBodyScanLimit anyway, so retaining more wastes memory.
	decoyBodyCap = ratioBodyScanLimit
)

// decoyResult is a memoized catch-all decoy probe response.
type decoyResult struct {
	status int
	body   string
	ok     bool
}

func (sc *ScanContext) getDecoyCache() *lru.Cache[string, *decoyResult] {
	sc.decoyOnce.Do(func() {
		sc.decoyCache, _ = lru.New[string, *decoyResult](decoyCacheSize)
	})
	return sc.decoyCache
}

// decoyProbe fetches (once per observed-record + kind + dir + ext, memoized) a
// guaranteed-nonexistent GET probe and returns its status/body. A probe to a
// random nonexistent path under a given directory is host-stable, so reusing it
// across a module's probe loop — and across modules processing the same record —
// avoids re-firing the same catch-all detection round-trip. buildPath maps a
// fresh canary to the probe path (invoked only on a cache miss). The cache is
// keyed on the observed request's ID so the auth/header context is captured
// (the native scan hands the same raw request to every module for a record, so
// the key is shared within a record and isolated across records). A nil sc
// disables caching (direct fetch), preserving the original behavior.
func (sc *ScanContext) decoyProbe(
	ctx *httpmsg.HttpRequestResponse,
	client *http.Requester,
	kind, dir, ext string,
	opts http.Options,
	buildPath func(canary string) string,
) decoyResult {
	fetch := func() decoyResult {
		status, body, ok := fetchGET(ctx, client, buildPath(FreshCanary()), opts)
		if len(body) > decoyBodyCap {
			body = body[:decoyBodyCap]
		}
		return decoyResult{status: status, body: body, ok: ok}
	}

	if sc == nil || ctx == nil || ctx.Request() == nil {
		return fetch()
	}

	key := ctx.Request().ID() + "\x00" + kind + "\x00" + dir + "\x00" + ext
	cache := sc.getDecoyCache()
	if v, ok := cache.Get(key); ok {
		return *v
	}
	res, _, _ := sc.decoyFlight.Do(key, func() (interface{}, error) {
		if v, ok := cache.Get(key); ok {
			return v, nil
		}
		r := fetch()
		cache.Add(key, &r)
		return &r, nil
	})
	return *res.(*decoyResult)
}

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
	sc *ScanContext,
	ctx *httpmsg.HttpRequestResponse,
	client *http.Requester,
	probePath string,
	match func(body string) bool,
) bool {
	if ctx == nil || ctx.Request() == nil || client == nil || match == nil {
		return false
	}

	parent, _ := splitProbePath(probePath)
	if parent == "" {
		return false // root-level path: covered by the caller's root soft-404 fingerprint
	}

	res := sc.decoyProbe(ctx, client, "sibling", parent, "", http.Options{NoRedirects: true},
		func(canary string) string { return parent + "/" + canary })
	if !res.ok || res.status != 200 {
		return false
	}
	return match(res.body)
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
	sc *ScanContext,
	ctx *httpmsg.HttpRequestResponse,
	client *http.Requester,
	probePath string,
) (status int, body string, ok bool) {
	if ctx == nil || ctx.Request() == nil || client == nil {
		return 0, "", false
	}
	dir, ext := decoyFileParts(probePath)
	// NoRedirects: a decoy that 30x-redirects is not a served baseline body.
	res := sc.decoyProbe(ctx, client, "decoyfile", dir, ext, http.Options{NoRedirects: true, NoClustering: true},
		func(canary string) string { return dir + "vigolium-decoy-" + canary + ext })
	return res.status, res.body, res.ok
}

// decoyFileParts splits probePath into its parent directory (with trailing slash)
// and file extension for decoy construction. A dot at index > 0 marks a real
// extension; a leading dot (.env, .git) is a dotfile name, not an extension, so
// it yields no decoy suffix.
func decoyFileParts(probePath string) (dir, ext string) {
	p := probePath
	if q := strings.IndexAny(p, "?#"); q >= 0 {
		p = p[:q]
	}
	dir, name := "/", p
	if i := strings.LastIndex(p, "/"); i >= 0 {
		dir, name = p[:i+1], p[i+1:] // keep the trailing slash on dir
	}
	if d := strings.LastIndex(name, "."); d > 0 {
		ext = name[d:]
	}
	return dir, ext
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
	sc *ScanContext,
	ctx *httpmsg.HttpRequestResponse,
	client *http.Requester,
	match func(body string) bool,
) bool {
	if match == nil {
		return false
	}
	res := sc.decoyProbe(ctx, client, "randomdir", "/", "", http.Options{NoRedirects: true, NoClustering: true},
		func(canary string) string { return "/vigolium-catchall-dir-" + canary + "/" })
	if !res.ok || res.status < 200 || res.status >= 300 {
		return false
	}
	return match(res.body)
}

// RootPageCatchAll GETs the site root ("/") — memoized per observed record — and
// reports whether its 2xx body satisfies match. On a single-page application the
// root serves the same client-side shell for every unknown route, so a path
// probe whose body matches the root is that shell rather than a distinct
// resource. It is the site-root companion to RandomDirCatchAll (which probes a
// random nonexistent directory): the two are INDEPENDENT shell samples, so a
// caller that OR-s them tolerates a WAF/CDN that intermittently blocks or
// throttles a single probe — the failure mode that lets a wildcard-shell
// response slip past a lone control. Runs with NoRedirects (a 30x root is not a
// served shell) and NoClustering (so the probe is not aliased to a cached entry).
// Returns false on any build/transport error or a non-2xx root, so a flaky root
// fetch never suppresses a real finding (fail-open toward "not a catch-all").
func RootPageCatchAll(
	sc *ScanContext,
	ctx *httpmsg.HttpRequestResponse,
	client *http.Requester,
	match func(body string) bool,
) bool {
	if match == nil {
		return false
	}
	res := sc.decoyProbe(ctx, client, "rootpage", "/", "", http.Options{NoRedirects: true, NoClustering: true},
		func(string) string { return "/" })
	if !res.ok || res.status < 200 || res.status >= 300 {
		return false
	}
	return match(res.body)
}

// ResemblesCatchAllShell reports whether hitBody is the host's catch-all
// application shell rather than a distinct resource produced by a path probe. It
// is the shared, WAF-flake-robust guard against the wildcard-SPA false positive
// that path-mangling modules (off-by-slash alias traversal, path normalization,
// proxy path confusion) share: a wildcard SPA / reverse proxy serves one
// index.html for EVERY unknown path, so a probe's "successful" 2xx body is just
// that shell. A lone control probe cannot see this reliably on a WAF/CDN-fronted
// host — each control is one request that fails (open or closed) the moment it is
// throttled to a non-2xx — so this confirms the shell POSITIVELY from several
// INDEPENDENT samples and OR-s them, and no single flaky probe can hide the
// catch-all:
//   - the page originally observed on ctx (ResemblesObservedPage — zero traffic),
//   - a random nonexistent directory at the web root (RandomDirCatchAll), and
//   - the site root "/" (RootPageCatchAll).
//
// All three compare with the dynamic-content-robust BodiesSimilar (QuickRatio),
// so per-request tokens/timestamps in the shell do not defeat the match. A
// genuinely distinct resource — an escaped source/config file, a real admin page
// — is never ~equal to the homepage or a random-directory response, so the guard
// costs no true positives. The two directory/root probes are memoized per
// observed record (via decoyProbe), so calling this once per candidate in a probe
// loop issues at most two extra requests for the whole record.
//
// CAUTION: the site-root sample makes this unsuitable for a detector whose
// genuine hit can legitimately equal the home page (e.g. an index.php PATH_INFO
// misconfig where /index.php renders the homepage) — such a module should call
// ResemblesObservedPage + RandomDirCatchAll directly and skip RootPageCatchAll.
func ResemblesCatchAllShell(
	scanCtx *ScanContext,
	ctx *httpmsg.HttpRequestResponse,
	client *http.Requester,
	hitBody string,
) bool {
	// Tokenize the hit body once and reuse the signature for the observed-page
	// compare and both shell probes.
	hitSig := BodySignature(hitBody)
	if ResemblesObservedPageSig(ctx, hitSig) {
		return true
	}
	shellMatch := func(b string) bool { return BodiesSimilarSig(hitSig, b) }
	if RandomDirCatchAll(scanCtx, ctx, client, shellMatch) {
		return true
	}
	return RootPageCatchAll(scanCtx, ctx, client, shellMatch)
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
	// The candidate body is compared against every round's decoy, so tokenize it
	// once up front instead of re-normalizing it on each BodiesSimilar call.
	var candidateSig ResponseSignature
	haveCandidate := candidateBody != ""
	if haveCandidate {
		candidateSig = BodySignature(candidateBody)
	}
	for i := 0; i < rounds; i++ {
		// Pass a nil ScanContext so each round is a genuinely distinct fetch with
		// a fresh canary — the multi-round confirmation deliberately wants several
		// independent decoys, not one memoized result.
		decoyStatus, decoyBody, served := DecoyFileBaseline(nil, ctx, client, probePath)
		if !served || decoyStatus != candidateStatus {
			continue // a 404 / differently-statused / errored decoy is the real-file case
		}
		if markerMatch != nil && markerMatch(decoyBody) {
			return true // decoy carries the same markers → extension-scoped catch-all
		}
		if haveCandidate && BodiesSimilarSig(candidateSig, decoyBody) {
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
	sc *ScanContext,
	ctx *httpmsg.HttpRequestResponse,
	client *http.Requester,
	probePath string,
	markers []string,
) bool {
	return SiblingPathCatchAll(sc, ctx, client, probePath, func(b string) bool {
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
	return ResemblesObservedPageSig(ctx, newRatioSignature(probeBody))
}

// ResemblesObservedPageSig is the precomputed-signature form of
// ResemblesObservedPage: a caller that already holds the probe body's ratio
// signature (e.g. ResemblesCatchAllShell, which reuses it for the shell probes)
// passes it here to avoid tokenizing the probe body a second time.
func ResemblesObservedPageSig(ctx *httpmsg.HttpRequestResponse, probeSig ResponseSignature) bool {
	if ctx == nil || ctx.Response() == nil {
		return false
	}
	// The observed baseline is constant across a module's probe loop, so its
	// ratio signature is memoized on the response and reused per probe.
	baselineSig := observedPageSignature(ctx.Response())
	if baselineSig.BodyLength == 0 {
		return false
	}
	return QuickRatio(probeSig, baselineSig) >= UpperRatioBound
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

// StripReflected removes occurrences of an injected payload from body so a
// signature or marker that is itself part of that payload cannot self-match when a
// validation/error response echoes the rejected input verbatim. It is the
// request-body analogue of StripReflectedProbePath (which strips a reflected URL
// path): an endpoint that merely REJECTS a request and quotes it back — a 400
// "invalid input: <payload>", a gRPC 415 echoing the Content-Type — would otherwise
// trip any detector whose marker the payload contains. Examples this defends: the
// PHP unserialize probe O:8:"stdClass":0:{} matching an O:\d+:"..." error pattern,
// an XXE internal-entity probe carrying its own success marker as the entity value,
// a NoSQL operator payload echoed back into a would-be error string.
//
// A genuine server-side signal (a real deserialization error, an expanded entity,
// an evaluated expression) emits its OWN text that is not part of the literal
// payload, so it survives the strip while a bare reflection does not. Returns body
// unchanged for an empty payload or body. Run it ONLY for the marker/signature
// match — keep the original body for stored response evidence.
func StripReflected(body, payload string) string {
	if payload == "" || body == "" {
		return body
	}
	return strings.ReplaceAll(body, payload, "")
}

// MatchAndConfirmSibling is the combined marker-match + catch-all guard used by
// the marker-based path-probing exposure modules. It confirms body satisfies the
// marker groups (MatchAllGroups), then drops the finding if a guaranteed-
// nonexistent sibling under the same parent directory returns the same markers
// (SiblingPathCatchAll) — a catch-all handler that 200s every child path. Root-
// level probe paths are already covered by the caller's root soft-404
// fingerprint, so the sibling probe is a no-op for them. Finally, when the
// framework anchor is merely the probe's own last path segment echoed back, it
// applies a slug-reflection control (PathSegmentReflected) so a content route
// that renders the requested slug (/topic/<slug> -> "<slug> …") does not
// self-confirm on the reflected word.
//
// matched carries the evidence substrings for ExtractedResults; ok is false (and
// matched nil) when the body doesn't satisfy the groups, the sibling reveals a
// catch-all, or the anchor is only a reflected path slug.
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
	// Uncached sibling probe (nil ScanContext): these marker-confirmation callers
	// span the FP-tuned Spring/CMS family and are left on the direct path. The
	// per-record decoy cache is opt-in via the sc-taking probe entry points.
	if SiblingPathCatchAll(nil, ctx, client, probePath, func(b string) bool {
		_, sibOK := MatchAllGroups(b, markers)
		return sibOK
	}) {
		return nil, false
	}
	// Slug-reflection guard: when the framework anchor (the first group's hit) is
	// merely the probe's own last path segment echoed back — a content route where
	// /topic/<slug> renders "<slug> …" in the title/JSON-LD/breadcrumb/canonical
	// link, OR a path-reflecting SPA/CMS shell embedding a {"view":"<slug>"} router
	// context (root-level too — SlugReflectionFP probes the web root for single-segment
	// paths) — the marker proves nothing about the endpoint. The sibling catch-all
	// check above cannot catch this because a random sibling reflects a DIFFERENT
	// slug (so it never carries the anchor word). Pass only the anchor
	// (matched[:1]): the grouped confirmation already required real corroboration
	// from the later groups, so the anchor is the one hit that must not be a mere
	// slug echo. This is the /topic/filament FP that matched the reflected word
	// "Filament", not a Filament panel.
	if SlugReflectionFP(ctx, client, probePath, matched[:1]) {
		return nil, false
	}
	return matched, true
}

// splitProbePath splits probePath into its parent directory and final path
// segment, dropping any query/fragment and trailing slash. "/topic/filament" ->
// ("/topic", "filament"); "/redoc" -> ("", "redoc"); "/a/b/" -> ("/a", "b").
// parent is "" for a root-level (single-segment) path, so callers can treat ""
// as "no same-parent sibling exists". It is the shared path-decomposition used by
// SiblingPathCatchAll, PathSegmentReflected, and SlugReflectionFP.
func splitProbePath(probePath string) (parent, segment string) {
	p := probePath
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	p = strings.TrimRight(p, "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[:i], p[i+1:]
	}
	return "", p
}

// PathSegmentReflected reports whether the application echoes an arbitrary
// requested path segment back into a 200 response body — a slug-reflecting content
// route (the /topic/<slug> -> "<slug> …" SEO pattern) OR a path-reflecting SPA/CMS
// shell (a Frontify/brand app whose router renders one 200 shell for every route and
// embeds the requested slug as a {"view":"<slug>"} router context, a canonical link,
// a title). It probes a guaranteed-nonexistent canary path under probePath's BASE
// directory — the parent directory for a multi-segment path, the web root "/" for a
// single-segment (root-level) path — and reports whether the app served 200 AND
// reflected that exact canary. Requiring a 200 canary reflection is what separates a
// real endpoint (whose random siblings 404) from a reflecting route/shell (whose
// every path renders): if the canary 404s, redirects, or errors, this is NOT a
// reflecting host and the finding stands.
//
// Root-level paths are probed at the web root rather than skipped: a path-reflecting
// shell defeats the root soft-404 fingerprint (the reflected slug + a per-request
// token vary the body per path), so a root-level slug-equal marker self-matches the
// reflected request path with no endpoint behind it (the branding.roche.com
// /healthchecks-ui, /redoc false positives). Requiring an EXACT 200 canary reflection
// keeps this false-negative-safe: a genuine root-level endpoint (/redoc, /h2-console)
// whose random web-root siblings 404 is never dropped. Runs with NoRedirects (a 30x
// is not a reflected body) and NoClustering (the control must be a distinct fetch,
// never aliased to the candidate's cached entry). Fails open (false) on any
// build/transport error so a flaky control probe never suppresses a real finding.
func PathSegmentReflected(
	ctx *httpmsg.HttpRequestResponse,
	client *http.Requester,
	probePath string,
) bool {
	if ctx == nil || ctx.Request() == nil || client == nil {
		return false
	}

	base := "/"
	if parent, _ := splitProbePath(probePath); parent != "" {
		base = parent + "/"
	}

	canary := FreshCanary()
	status, body, ok := fetchGET(ctx, client, base+canary, http.Options{NoRedirects: true, NoClustering: true})
	if !ok || status != 200 {
		return false
	}
	return strings.Contains(body, canary)
}

// SlugReflectionFP reports whether a flat-marker path-probe match is merely the
// probe's own last path segment reflected into a content route or a path-reflecting
// shell — the false positive PathSegmentReflected guards. It is the flat-[]string
// companion to the grouped slug-reflection guard inside MatchAndConfirmSibling, for
// modules that confirm with a plain "any marker in the list matched" loop (the
// SiblingServesAnyMarker callers): pass the markers that ACTUALLY matched the body.
//
// It fires (returns true → drop the finding) ONLY when EVERY passed marker is a
// case-insensitive substring of probePath's last segment — so no structural marker
// (a hyphenated tag, an asset URL, a quoted JSON key) is holding the finding up —
// AND PathSegmentReflected confirms the host echoes an arbitrary slug. Returning
// early on the first non-segment marker keeps the network control probe off the
// common path and preserves any finding backed by real endpoint content. The
// reflection control covers root-level probe paths too (it probes the web root), so a
// single-segment slug like /redoc reflected by a wildcard shell is caught. Returns
// false for empty markers or a segmentless path.
//
// Flat-marker callers pass every marker that matched (pure-OR: a single reflected
// slug is the whole finding, so all must be segment-explained to drop). The
// grouped MatchAndConfirmSibling passes only the anchor (matched[:1]): its later
// groups already supplied real corroboration, so only the anchor hit needs the
// reflection check.
func SlugReflectionFP(
	ctx *httpmsg.HttpRequestResponse,
	client *http.Requester,
	probePath string,
	matchedMarkers []string,
) bool {
	if len(matchedMarkers) == 0 {
		return false
	}
	_, segment := splitProbePath(probePath)
	seg := strings.ToLower(segment)
	if seg == "" {
		return false
	}
	for _, mk := range matchedMarkers {
		if mk == "" || !strings.Contains(seg, strings.ToLower(mk)) {
			return false // a structural / non-reflected marker supports the finding
		}
	}
	return PathSegmentReflected(ctx, client, probePath)
}
