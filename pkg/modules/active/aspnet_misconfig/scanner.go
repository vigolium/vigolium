package aspnet_misconfig

import (
	"crypto/sha256"
	"fmt"
	"math"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

// decoyRounds is how many same-directory negative-control probes the catch-all
// disproof issues per candidate. A host that answers every /<dir>/<anything> with
// the same 200 page (a reflecting/echo server, an SPA fallback, a blanket rewrite)
// trips at least one round and the candidate is dropped. Two rounds tolerate a
// single WAF/CDN flake without over-probing.
const decoyRounds = 2

type notFoundFingerprint struct {
	bodyHash string
	bodyLen  int
}

// ysodMarkerGroups is the AND-of-OR confirmation for a Yellow Screen of Death: the
// body must carry the "Server Error in" page anchor AND a stack-trace / .NET
// version corroborator. A single weak marker ("Stack Trace:") surviving in a
// catch-all/echo shell tail cannot forge the finding — YSoD cannot use the decoy
// disproof the path probes use, because a genuinely-misconfigured host renders a
// YSoD for EVERY random error path (the decoy would look like a catch-all), so the
// co-occurrence anchor is the robust guard here.
var ysodMarkerGroups = [][]string{
	{"Server Error in"},
	{"Stack Trace:", "Version Information: Microsoft .NET Framework", "[HttpException", "at System.", "Microsoft .NET Framework"},
}

type Module struct {
	modkit.BaseActiveModule
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
		ds: dedup.LazyDiskSet("aspnet_misconfig"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil {
		return false
	}
	return ctx.Response() != nil
}

func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}

	if !modkit.BeginHostProbeFor(scanCtx, httpClient, &m.ds, ctx) {
		return nil, nil
	}

	fp := m.fingerprint404(ctx, httpClient)

	var results []*output.ResultEvent

	// Probe diagnostic endpoints
	for _, p := range probes {
		if result := m.probeEndpoint(ctx, httpClient, p, fp); result != nil {
			results = append(results, result)
		}
	}

	// Probe for Yellow Screen of Death (verbose errors)
	if result := m.probeYSoD(ctx, httpClient, fp); result != nil {
		results = append(results, result)
	}

	return results, nil
}

func (m *Module) fingerprint404(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) *notFoundFingerprint {
	randomPath := "/vigolium-aspnet-404-" + utils.RandomString(8)

	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, randomPath)
	if err != nil {
		return nil
	}

	// SetMethod/SetPath produce well-formed raw, so wrap directly instead of
	// re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	body := resp.Body().String()
	return &notFoundFingerprint{
		bodyHash: fmt.Sprintf("%x", sha256.Sum256([]byte(body))),
		bodyLen:  len(body),
	}
}

func (m *Module) probeEndpoint(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	p probe,
	fp *notFoundFingerprint,
) *output.ResultEvent {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, p.path)
	if err != nil {
		return nil
	}

	// SetMethod/SetPath produce well-formed raw, so wrap directly instead of
	// re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil
	}

	status := resp.Response().StatusCode
	if status == 404 || status == 500 || status == 502 || status == 503 || status == 403 || status == 401 {
		return nil
	}

	if status == 301 || status == 302 {
		location := resp.Response().Header.Get("Location")
		if strings.Contains(strings.ToLower(location), "login") || strings.Contains(strings.ToLower(location), "user") {
			return nil
		}
	}

	// Content-type discipline (survives the body-truncation FP — the header is
	// intact when a gzip/Content-Length:0 quirk leaves only a partial body tail):
	// the SignalR negotiate/hubs probes target JSON/JS documents never served as an
	// HTML *document*. A reflecting/catch-all host that answers arbitrary paths with
	// its themed text/html shell would otherwise forge a match on a weak marker in
	// that tail; rejecting an HTML document for a JSON/JS probe costs no true
	// positives (a real negotiate reply simply never comes back as text/html).
	if p.jsonBody && modkit.ClassifyContentType(resp.Response().Header.Get("Content-Type")) == modkit.ContentClassHTML {
		return nil
	}

	body := resp.Body().String()

	if fp != nil {
		bodyHash := fmt.Sprintf("%x", sha256.Sum256([]byte(body)))
		if bodyHash == fp.bodyHash {
			return nil
		}
		if fp.bodyLen > 0 {
			ratio := math.Abs(float64(len(body)-fp.bodyLen)) / float64(fp.bodyLen)
			if ratio < 0.05 {
				return nil
			}
		}
	}

	// Catch-all / SPA shell guard: a themed app that returns the same shell for
	// any path is a false positive even when a weak marker appears in that shell.
	if modkit.ResemblesObservedPage(ctx, body) {
		return nil
	}

	for _, anti := range p.antiMarkers {
		if strings.Contains(body, anti) {
			return nil
		}
	}

	if status != 200 {
		return nil
	}

	// Strip the reflected request path before marker matching: a catch-all/echo host
	// that mirrors the requested path into its response would otherwise let a marker
	// that is itself a path segment satisfy the check ("hangfire" from /hangfire,
	// "profiler" from /mini-profiler-resources/results). The original body is kept
	// for anti-markers and stored evidence.
	matchBody := modkit.StripReflectedProbePath(body, p.path)

	matchedMarkers, ok := p.accepts(matchBody)
	if !ok {
		return nil
	}

	// Multi-round catch-all disproof: probe several guaranteed-nonexistent siblings
	// under this probe's parent directory. If a random sibling returns the same
	// status and also satisfies the marker predicate, the host serves this content
	// for any path — a reflecting/echo server or a wildcard rewrite — so a weak
	// dashboard word ("Dashboard", "profiler") in the shell proves nothing. A
	// genuinely exposed diagnostic endpoint has no such sibling (the decoy 404s), so
	// this costs no true positives, and it is robust to the body-truncation quirk
	// because the decoy is run through the same predicate, not a body-similarity
	// compare.
	if modkit.MultiRoundExtDecoyCatchAll(ctx, httpClient, p.path, body, status, decoyRounds, func(b string) bool {
		_, sibOK := p.accepts(b)
		return sibOK
	}) {
		return nil
	}

	urlx, _ := ctx.URL()
	targetURL := urlx.Scheme + "://" + urlx.Host + p.path

	return &output.ResultEvent{
		URL:              targetURL,
		Matched:          targetURL,
		Request:          string(modifiedRaw),
		Response:         resp.FullResponseString(),
		ExtractedResults: matchedMarkers,
		Info: output.Info{
			Name:        fmt.Sprintf("ASP.NET Diagnostic Exposed: %s", p.name),
			Description: p.desc,
			Severity:    p.sev,
			Confidence:  severity.Firm,
			Tags:        []string{"aspnet", "misconfiguration", "diagnostics"},
			Reference:   []string{"https://learn.microsoft.com/en-us/aspnet/core/fundamentals/error-handling"},
		},
	}
}

func (m *Module) probeYSoD(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	fp *notFoundFingerprint,
) *output.ResultEvent {
	errorPath := "/vigolium-ysod-" + utils.RandomString(6) + "?aspxerrorpath=/"

	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, errorPath)
	if err != nil {
		return nil
	}

	// SetMethod/SetPath produce well-formed raw, so wrap directly instead of
	// re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil
	}

	body := resp.Body().String()

	// Strip the reflected request path/query before matching so a catch-all/echo
	// host that mirrors the aspxerrorpath probe back cannot self-satisfy the anchor.
	matchBody := modkit.StripReflectedProbePath(body, errorPath)

	// AND-of-OR co-occurrence: require the "Server Error in" YSoD page anchor AND a
	// stack-trace / .NET version corroborator. A lone weak marker surviving in a
	// truncated catch-all/echo tail cannot forge the finding.
	matchedMarkers, ok := modkit.MatchAllGroups(matchBody, ysodMarkerGroups)
	if !ok {
		return nil
	}

	// Also check for customErrors off indicator
	if strings.Contains(matchBody, "customErrors") {
		matchedMarkers = append(matchedMarkers, "customErrors mode detected")
	}

	urlx, _ := ctx.URL()
	targetURL := urlx.Scheme + "://" + urlx.Host + errorPath

	return &output.ResultEvent{
		URL:              targetURL,
		Matched:          targetURL,
		Request:          string(modifiedRaw),
		Response:         resp.FullResponseString(),
		ExtractedResults: matchedMarkers,
		Info: output.Info{
			Name:        "ASP.NET Verbose Error Page (YSoD)",
			Description: "The application returns detailed error information (Yellow Screen of Death) including stack traces and .NET Framework version, indicating customErrors is set to Off",
			Severity:    severity.Medium,
			Confidence:  severity.Firm,
			Tags:        []string{"aspnet", "misconfiguration", "verbose-error", "information-disclosure"},
			Reference:   []string{"https://learn.microsoft.com/en-us/aspnet/core/fundamentals/error-handling"},
		},
	}
}
