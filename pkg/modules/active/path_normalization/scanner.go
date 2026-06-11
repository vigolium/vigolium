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
				//   accessUnlock  the clean original path does NOT reach a
				//                 resource (4xx/5xx/3xx) but the traversal-bearing
				//                 path reaches a 2xx resource. The payload unlocked
				//                 access to something the clean URL cannot reach.
				//
				//   differential  both the clean path and the traversal-bearing
				//                 path reach 2xx, but the traversal response is a
				//                 materially different resource than the clean
				//                 baseline (substantial body delta).
				//
				// This replaces the old "over-traversal 400 / clean path 200"
				// oracle, which fired on the normal behaviour of any host that
				// rejects malformed suffixes and serves the canonical path.
				// accessUnlock requires a successful baseline probe — a failed
				// baseline fetch (status 0) must not be read as "the clean path
				// cannot reach the resource".
				accessUnlock := baseline.ok && !isResourceReached(baseline.status)
				differential := isResourceReached(baseline.status) &&
					modkit.HasSubstantialBodyDifference(backedSig, baselineSig)
				if !accessUnlock && !differential {
					continue
				}

				// Reproducibility: a genuine bypass is deterministic. Re-fetch the
				// backed-off path with the cache bypassed and require the same 2xx
				// resource with a stable body.
				confirm := m.probePath(rawRequest, backedOffPath, httpService, httpClient, true)
				if !confirm.ok || !isResourceReached(confirm.status) ||
					!modkit.RatioSimilar(backedSig, modkit.NewResponseSignature(confirm.status, confirm.body, "")) {
					continue
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
		Matched:            backedOffPath,
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

// isResourceReached reports whether a response represents actually reaching a
// resource — a 2xx success — rather than a default-deny (403), not-found (404)
// or server-error (500) response.
func isResourceReached(status int) bool {
	return status >= 200 && status < 300
}

// pathProbe is a single probe result: status and body (the oracle inputs) plus
// the raw request, retained so the rare reported finding can render evidence
// without re-fetching. The response body alone (no headers) is kept — matching
// the sibling static-root oracle's evidence — so the common, discarded probe
// does not pay for a full headers+body copy.
type pathProbe struct {
	status     int
	body       string
	blocked    bool // WAF/CDN/auth/rate-limit block page
	binary     bool // static-asset / binary content type
	requestRaw string
	ok         bool
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

	req, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return pathProbe{}
	}
	req.WithService(httpService)

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
		status:     resp.Response().StatusCode,
		body:       resp.BodyString(),
		blocked:    infra.IsBlockedResponse(resp),
		binary:     modkit.IsStaticAssetContentType(ct),
		requestRaw: string(modifiedRaw),
		ok:         true,
	}
}
