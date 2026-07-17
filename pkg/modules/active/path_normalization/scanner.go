package path_normalization

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	syncutils "github.com/projectdiscovery/utils/sync"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"go.uber.org/zap"
)

// Note: sync is still needed for the goroutine mutex

// PathPayload defines a structure for path normalization payloads
type PathPayload struct {
	Payload          string // The actual traversal/normalization payload string
	DisableAutoSlash bool   // If true, don't automatically add a trailing slash to the base path before appending the payload
}

var (
	// Common path normalization/traversal payloads with auto-slash control
	pathNormalizationPayloads = []PathPayload{
		{Payload: "..;/", DisableAutoSlash: true}, // /js..;/xxx.jsp
		{Payload: "../", DisableAutoSlash: true},  // /js../
		{Payload: "..%2f", DisableAutoSlash: true},
		{Payload: "..%252f", DisableAutoSlash: true},
		{Payload: "%2e%2e%2f", DisableAutoSlash: true},
		{Payload: "%252e%252e%252f", DisableAutoSlash: true},
		{Payload: "..//", DisableAutoSlash: true},
		{Payload: "...//", DisableAutoSlash: true},
		{Payload: ".../", DisableAutoSlash: true},
		{Payload: "..\\", DisableAutoSlash: true},
		{Payload: "...\\", DisableAutoSlash: true},
		{Payload: "..%5c", DisableAutoSlash: true},
		{Payload: "..%255c", DisableAutoSlash: true},
		{Payload: "..%255c\\", DisableAutoSlash: true},
		{Payload: "%2e%2e%5c", DisableAutoSlash: true},
		{Payload: "%252e%252e%255c", DisableAutoSlash: true},
		{Payload: "..\\/", DisableAutoSlash: true},
		{Payload: "../\\", DisableAutoSlash: true},
		{Payload: "..;a=a/", DisableAutoSlash: true},
		{Payload: "..%01/", DisableAutoSlash: true},
		{Payload: "..%0a/", DisableAutoSlash: true},
		{Payload: "..%0b/;.css", DisableAutoSlash: true},
		{Payload: "./", DisableAutoSlash: true},
	}
	// Number of times to repeat the payload prefix, relative to original path depth
	payloadRepetitionDepth = 5

	// Status codes based on pathbuster description.
	//
	// pubStatus: the over-traversed ("public"/proxy) path is rejected as a
	// malformed request. This is the corroborating boundary signal — it proves a
	// real parser limit exists one step beyond the path we report — but it is NOT
	// the finding on its own (see the oracle in ScanPerRequest).
	pubStatus = map[int]bool{
		400: true,
	}

	// minNormalizationBodyLen drops empty/stub backed-off bodies so a blank 200
	// (an SPA shell stripped to nothing, a 204-like response) is never compared as
	// an "internal resource".
	minNormalizationBodyLen = 24
)

type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
	// ds gates the static-root traversal branch to once per (host, mount-segment).
	ds dedup.Lazy[dedup.DiskSet]
}

func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		rhm: dedup.LazyRHM("path_normalization", dedup.Option{
			Host: true,
			Path: true,
		}),
		ds: dedup.LazyDiskSet("path_normalization_static"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest scans the request for path normalization vulnerabilities.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	// Static-root traversal oracle (matrix-parameter + encoded-slash bypass of
	// static file handlers — express.static / send and similar). It has its own
	// per-(host, mount-segment) dedup and a file-content/listing oracle, distinct
	// from the normalization status oracle below, and deliberately runs on
	// static-asset URLs. A confirmed file read is the higher-signal finding, so
	// return it immediately.
	if staticRes, fatal := m.scanStaticRootTraversal(ctx, httpClient, scanCtx, urlx); len(staticRes) > 0 {
		return staticRes, nil
	} else if fatal {
		return results, nil
	}

	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil && !rhm.ShouldCheck3(urlx, "GET", "", "path", urlx.EscapedPath(), "inURL") {
		return results, nil
	}

	var findingReported atomic.Bool
	findingReported.Store(false)

	wg, err := syncutils.New(syncutils.WithSize(1))
	if err != nil {
		return nil, err
	}
	var mutex sync.Mutex

	rawRequest := ctx.Request().Raw()
	httpService := ctx.Service()

	originalPath := urlx.Path
	if originalPath == "" {
		originalPath = "/"
	}

	// Reference probes: the clean original path (baseline), the site root, and a
	// random non-existent sibling. We compare the backed-off (traversal-bearing)
	// path against all three: it must reach a real resource that is NOT the host's
	// generic shell for root / unknown paths.
	baseline := m.probePath(rawRequest, originalPath, httpService, httpClient, false)

	// The clean path is the reference side of BOTH status oracles below: accessUnlock
	// treats a denied baseline as "protected", and differential treats a 2xx baseline
	// as the normal page. If that baseline is a vendor WAF/CDN edge block (a CloudFront
	// "Request blocked" 403, a Cloudflare challenge served at 200/403, a 429) rather
	// than a genuine app response, a traversal shape that merely evades the edge rule
	// returns real 2xx content and both oracles misreport a normalization bypass.
	// GetBlockDetectionValidator flags only vendor edge blocks, so a genuine app 401/403
	// baseline (a real accessUnlock signal) is preserved.
	if baseline.edgeBlocked {
		return results, nil
	}

	root := baseline
	if originalPath != "/" {
		root = m.probePath(rawRequest, "/", httpService, httpClient, false)
	}

	nonExistentPath := strings.TrimSuffix(originalPath, "/") + "/nonexistentpathcheck12345abcde"
	nonExistent := m.probePath(rawRequest, nonExistentPath, httpService, httpClient, false)

	baselineSig := modkit.NewResponseSignature(baseline.status, baseline.body, "")
	rootSig := modkit.NewResponseSignature(root.status, root.body, "")
	nonExistentSig := modkit.NewResponseSignature(nonExistent.status, nonExistent.body, "")

	pathDepth := strings.Count(strings.Trim(originalPath, "/"), "/")
	repeatCount := pathDepth + payloadRepetitionDepth

	for _, pld := range pathNormalizationPayloads {
		wg.Add()
		go func(payloadInfo PathPayload) {
			defer wg.Done()

			payload := payloadInfo.Payload
			disableAutoSlash := payloadInfo.DisableAutoSlash

			var basePathForPayload string
			if disableAutoSlash {
				basePathForPayload = strings.TrimSuffix(originalPath, "/")
			} else {
				if !strings.HasSuffix(originalPath, "/") {
					basePathForPayload = originalPath + "/"
				} else {
					basePathForPayload = originalPath
				}
			}

			// Start at i = 2 so the backed-off path (i-1 repetitions) always
			// carries at least one traversal segment. At i = 1 the backed-off
			// path collapses to the untouched original URL, so "over-traversal
			// rejected (400) / clean path served (200)" — the normal behaviour of
			// any host that rejects a malformed `..%2f` suffix and serves the
			// canonical path — was reported as a bypass. That degenerate case was
			// the reported false positive and is now excluded entirely.
			for i := 2; i <= repeatCount; i++ {
				if findingReported.Load() {
					return
				}

				fuzzedPath := basePathForPayload + strings.Repeat(payload, i)
				backedOffPath := basePathForPayload + strings.Repeat(payload, i-1)

				// Step 1: the over-traversed path must be REJECTED as malformed
				// (the public/proxy 400). This locates a genuine parser boundary
				// one step past the path we report.
				fuzz := m.probePath(rawRequest, fuzzedPath, httpService, httpClient, false)
				if !fuzz.ok {
					continue
				}
				if _, ok := pubStatus[fuzz.status]; !ok {
					continue
				}

				// Step 2: the backed-off path must REACH A RESOURCE — a 2xx
				// success with a real, text response body. A WAF/CDN block, a
				// generic 4xx/5xx, or a binary/static asset is not a normalization
				// bypass (binary/static reads are the separate static-root
				// oracle's job).
				backed := m.probePath(rawRequest, backedOffPath, httpService, httpClient, false)
				if !backed.ok || !isResourceReached(backed.status) || backed.blocked || backed.binary {
					continue
				}
				if len(strings.TrimSpace(backed.body)) < minNormalizationBodyLen {
					continue
				}

				backedSig := modkit.NewResponseSignature(backed.status, backed.body, "")

				// Catch-all / SPA guard: a host that serves the same shell for the
				// root and for a random non-existent path is not exposing an
				// internal resource through normalization.
				if modkit.RatioSimilar(backedSig, rootSig) || modkit.RatioSimilar(backedSig, nonExistentSig) {
					continue
				}

				// The oracle — the two sound path-normalization signals:
				//
				//   accessUnlock  the clean original path is refused by a STABLE
				//                 access-control / routing decision (401/403/404)
				//                 but the traversal-bearing path reaches a 2xx
				//                 resource. A transient infrastructure response on
				//                 the clean path (429 rate limit, 503, 5xx, or a 3xx
				//                 canonicalization redirect) is NOT a denial — the
				//                 motivating false positive was a rate-limited (429)
				//                 clean path read as "the traversal unlocked access"
				//                 when the payload merely resolved to the public
				//                 site root.
				//
				//   differential  both the clean path and the traversal-bearing
				//                 path reach 2xx, but the traversal response is a
				//                 materially different resource than the clean
				//                 baseline (substantial body delta).
				//
				// accessUnlock requires a successful baseline probe — a failed
				// baseline fetch (status 0) is excluded by isAccessDenialStatus.
				accessUnlock := baseline.ok && isAccessDenialStatus(baseline.status)
				differential := isResourceReached(baseline.status) &&
					modkit.HasSubstantialBodyDifference(backedSig, baselineSig)
				if !accessUnlock && !differential {
					continue
				}

				// Independent catch-all sample. The root/nonExistent references above
				// are captured ONCE at the top of the scan and can be poisoned by a
				// transient throttle at capture time (the WAF/CDN-flake false-positive
				// class): on a host whose deep unknown paths render an app-shell that
				// differs from "/", a poisoned nonExistent reference lets the shell
				// through. RandomDirCatchAll adds a freshly-memoized
				// random-web-root-directory shell sample a single poisoned capture
				// cannot disable; it fails open (a non-2xx control is "not a
				// catch-all"), so a genuine internal resource is never suppressed. It
				// runs only after the local oracle admits the candidate, so the
				// (memoized) probe never fires for a record that has no candidate worth
				// reporting.
				if modkit.RandomDirCatchAll(scanCtx, ctx, httpClient, func(b string) bool {
					return modkit.BodiesSimilarSig(backedSig, b)
				}) {
					continue
				}

				// Traversal-shape catch-all guard: the clean-path references above
				// (root/nonExistent, and the freshRoot guard below) miss a host that
				// serves one generic body ONLY for the traversal SHAPE — the observed
				// false positive where `/<anything>..%2f..%2f` returns a byte-identical
				// "feature not available" page while clean `/` serves the real homepage.
				// Re-issue the identical traversal from a same-depth random base (see
				// collapseControlPath): a matching body proves the leading segments were
				// irrelevant. Fails open — a non-2xx or dissimilar control never
				// suppresses a genuine, base-specific resource.
				if controlPath, okControl := collapseControlPath(basePathForPayload, payload, i-1); okControl {
					control := m.probePath(rawRequest, controlPath, httpService, httpClient, true)
					if control.ok && isResourceReached(control.status) &&
						modkit.RatioSimilar(backedSig, modkit.NewResponseSignature(control.status, control.body, "")) {
						continue
					}
				}

				// Reproducibility: a genuine bypass is deterministic. Re-fetch the
				// backed-off path with the cache bypassed and require the same 2xx
				// resource with a stable body.
				confirm := m.probePath(rawRequest, backedOffPath, httpService, httpClient, true)
				if !confirm.ok || !isResourceReached(confirm.status) ||
					!modkit.RatioSimilar(backedSig, modkit.NewResponseSignature(confirm.status, confirm.body, "")) {
					continue
				}

				// Root-resolution guard — the dominant false positive. An upward
				// `../`-family traversal that does not over-shoot simply normalizes
				// to the site ROOT and returns the public homepage; reaching it is
				// not a bypass. The initial root reference (captured once above) can
				// be poisoned by a transient block — the very rate-limiting that
				// produced the accessUnlock noise — so re-fetch root fresh (cache
				// bypassed) and drop the finding when:
				//   - the backed-off resource matches the fresh root (it IS the
				//     public homepage), or
				//   - root cannot be established because of a transient block, so
				//     "resolved to root" cannot be ruled out and a High finding
				//     must not ride on an unverifiable reference.
				// A stable access-denial root (401/403/404) is left to proceed: the
				// homepage is not public there, so reaching a 2xx via traversal is a
				// genuinely distinct resource.
				if originalPath != "/" {
					freshRoot := m.probePath(rawRequest, "/", httpService, httpClient, true)
					if isTransientBlock(freshRoot) {
						continue
					}
					if freshRoot.ok && isResourceReached(freshRoot.status) &&
						modkit.RatioSimilar(backedSig, modkit.NewResponseSignature(freshRoot.status, freshRoot.body, "")) {
						continue
					}
				}

				ev := m.buildFinding(urlx, payload, fuzzedPath, backedOffPath, baseline, fuzz, backed, confirm, accessUnlock)

				mutex.Lock()
				results = append(results, ev)
				mutex.Unlock()

				findingReported.Store(true)

				zap.L().Info("Path Normalization Vulnerability Found",
					zap.String("moduleID", m.ID()),
					zap.String("url", ev.URL),
					zap.String("payload", payload),
				)

				return
			}
		}(pld)
	}

	wg.Wait()
	return results, nil
}

// buildFinding assembles the ResultEvent for a confirmed normalization bypass,
// attaching the backed-off request/response as the primary evidence and the
// baseline, over-traversal and confirmation rounds as additional evidence so a
// reviewer can see the whole oracle.
func (m *Module) buildFinding(
	urlx *urlutil.URL,
	payload, fuzzedPath, backedOffPath string,
	baseline, fuzz, backed, confirm pathProbe,
	accessUnlock bool,
) *output.ResultEvent {
	// Build the URL string by concatenation (not url.URL.String(), which would
	// re-escape the `%` in the encoded payload and corrupt the path).
	vulnURLString := urlx.Scheme + "://" + urlx.Host + backedOffPath
	fuzzURLString := urlx.Scheme + "://" + urlx.Host + fuzzedPath

	var oracleClause string
	if accessUnlock {
		oracleClause = fmt.Sprintf(
			"the clean path could not reach this resource (status %d) — the traversal unlocked access",
			baseline.status,
		)
	} else {
		oracleClause = "its response differs substantially from the clean baseline response"
	}

	desc := fmt.Sprintf(
		"Path normalization bypass detected with payload '%s'. The over-traversed path '%s' is rejected as malformed (status %d), "+
			"while the traversal-bearing path '%s' reproducibly reaches a resource (status %d) where %s. "+
			"This indicates a reverse-proxy/backend disagreement on path parsing that lets the request normalize through to a resource the clean URL does not serve.",
		payload, fuzzURLString, fuzz.status, vulnURLString, backed.status, oracleClause,
	)

	evidence := make([]string, 0, 3)
	for _, e := range []string{
		probeEvidence("baseline (clean path)", baseline),
		probeEvidence("over-traversed (rejected)", fuzz),
		probeEvidence("confirmation (re-fetch)", confirm),
	} {
		if e != "" {
			evidence = append(evidence, e)
		}
	}

	return &output.ResultEvent{
		ModuleID: m.ID(),
		Info: output.Info{
			Name:        m.Name(),
			Description: desc,
			Severity:    m.Severity(),
			Confidence:  m.Confidence(),
		},
		URL:                vulnURLString,
		Host:               urlx.Host,
		// Matched is the location the console/grouping renders (MatchedURL prefers
		// it over URL); use the full absolute URL so the live finding line shows
		// the target host, matching every other active module. The bare path is
		// still surfaced via ExtractedResults for the trailing [.../] annotation.
		Matched:            vulnURLString,
		Request:            backed.requestRaw,
		Response:           truncateBody(backed.body),
		AdditionalEvidence: evidence,
		ExtractedResults:   []string{backedOffPath},
		Timestamp:          time.Now(),
	}
}

// probeEvidence renders one probe's request + (truncated) response body into an
// AdditionalEvidence entry. Returns "" for an empty probe so a failed reference
// fetch is not recorded.
func probeEvidence(label string, p pathProbe) string {
	return output.BuildEvidence(label, p.requestRaw, truncateBody(p.body))
}

// collapseControlPath builds the traversal-shape catch-all control: the identical
// payload (repeated `repeat` times) appended to a guaranteed-nonexistent base of the
// SAME segment depth as basePath, constructed the same way the backed-off path is
// (payload appended directly to the final segment). See modkit.RandomSameDepthPath
// for why a same-depth random base collapses to the same ancestor/root. Returns
// ("", false) when basePath has no segment to randomize (bare root), so the caller
// skips the guard rather than probe a degenerate control.
func collapseControlPath(basePath, payload string, repeat int) (string, bool) {
	if strings.Trim(basePath, "/") == "" {
		return "", false
	}
	return modkit.RandomSameDepthPath(basePath) + strings.Repeat(payload, repeat), true
}

// isResourceReached reports whether a response represents actually reaching a
// resource — a 2xx success — rather than a default-deny (403), not-found (404)
// or server-error (500) response.
func isResourceReached(status int) bool {
	return status >= 200 && status < 300
}

// isAccessDenialStatus reports whether status is a STABLE access-control or
// routing denial — the only clean-baseline states for which "clean path refused,
// traversal-bearing path served" is a meaningful normalization bypass (the
// accessUnlock oracle). Transient infrastructure responses (429 rate limit, 503
// maintenance, 5xx server errors) and 3xx canonicalization redirects are
// deliberately excluded: the motivating false positive was a rate-limited (429)
// clean path read as "the traversal unlocked access" when the payload merely
// resolved to the public site root.
func isAccessDenialStatus(status int) bool {
	switch status {
	case 401, 403, 404:
		return true
	}
	return false
}

// isTransientBlock reports whether a probe failed for a transient infrastructure
// reason — a rate limit (429), maintenance/unavailable (503), or a WAF/CDN
// challenge interstitial (which infra.IsBlockedResponse flags even on a 200/202)
// — as opposed to a stable access-control decision (401/403). A transient block
// on a REFERENCE probe (root) poisons the oracle's comparisons, so a finding that
// depends on it must be dropped rather than emitted on noise.
func isTransientBlock(p pathProbe) bool {
	switch p.status {
	case 429, 503:
		return true
	}
	return p.blocked && p.status != 401 && p.status != 403
}

// pathProbe is a single probe result: status and body (the oracle inputs) plus
// the raw request, retained so the rare reported finding can render evidence
// without re-fetching. The response body alone (no headers) is kept — matching
// the sibling static-root oracle's evidence — so the common, discarded probe
// does not pay for a full headers+body copy.
type pathProbe struct {
	status      int
	body        string
	blocked     bool // WAF/CDN/auth/rate-limit block page (any 401/403/429/503)
	edgeBlocked bool // vendor-identified WAF/CDN edge block (NOT a plain app 401/403)
	binary      bool // static-asset / binary content type
	requestRaw  string
	ok          bool
}

// probePath issues a GET to path (query string cleared, encoded payload preserved
// on the wire) and captures everything the oracle and the finding evidence need.
// noClustering bypasses the requester's short-lived response cache for
// back-to-back confirmation replays.
func (m *Module) probePath(
	rawRequest []byte,
	path string,
	httpService *httpmsg.Service,
	httpClient *http.Requester,
	noClustering bool,
) pathProbe {
	modifiedRaw, err := httpmsg.SetPath(rawRequest, path)
	if err != nil {
		return pathProbe{}
	}
	modifiedRaw, _ = httpmsg.ClearQueryString(modifiedRaw)

	// BuildRequest/SetMethod/... produce well-formed raw, so wrap directly instead
	// of re-parsing on this hot path.
	req := httpmsg.NewRequestResponseRaw(modifiedRaw, httpService)

	resp, _, err := httpClient.Execute(req, http.Options{NoClustering: noClustering})
	if err != nil {
		return pathProbe{}
	}
	defer resp.Close()
	if resp.Response() == nil {
		return pathProbe{}
	}

	ct := resp.Response().Header.Get("Content-Type")
	return pathProbe{
		status:      resp.Response().StatusCode,
		body:        resp.BodyString(),
		blocked:     infra.IsBlockedResponse(resp),
		edgeBlocked: infra.GetBlockDetectionValidator().Validate(resp) != nil,
		binary:      modkit.IsStaticAssetContentType(ct),
		requestRaw:  string(modifiedRaw),
		ok:          true,
	}
}
