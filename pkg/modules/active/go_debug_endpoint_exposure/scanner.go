package go_debug_endpoint_exposure

import (
	"strings"

	"github.com/pkg/errors"
	httputil "github.com/projectdiscovery/utils/http"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// Module implements the Go Debug Endpoint Exposure active scanner. It probes the
// net/http/pprof family and the expvar /debug/vars endpoint under the web root
// plus every context-path prefix of the observed URL.
type Module struct {
	modkit.BaseActiveModule
	ds       dedup.Lazy[dedup.DiskSet]
	pprof    []debugEndpoint
	expvar   debugEndpoint
	inferred []debugEndpoint
}

// New creates a new Go Debug Endpoint Exposure module.
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
		ds:       dedup.LazyDiskSet("go_debug_endpoint_exposure"),
		pprof:    pprofEndpoints(),
		expvar:   expvarEndpoint(),
		inferred: inferredFromIndex(),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest probes the host for exposed Go pprof / expvar debug endpoints.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	// CandidateBasePaths yields the web root ("") plus each context-path prefix of
	// the observed URL, so a pprof mux at the root (/debug/pprof/) is probed
	// alongside one mounted under a context path (/api/debug/pprof/). Each
	// (host, base) pair is claimed up front so a host is swept exactly once even
	// across many observed requests.
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	host := urlx.Scheme + "|" + urlx.Host
	bases := modkit.UnclaimedBasePaths(diskSet, host, modkit.CandidateBasePaths(urlx.Path))

	var results []*output.ResultEvent
	for _, base := range bases {
		results = append(results, m.probeBase(ctx, httpClient, scanCtx, urlx, base)...)
	}
	return results, nil
}

// probeBase sweeps every debug endpoint under a single base path.
func (m *Module) probeBase(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
	urlx *urlutil.URL,
	base string,
) []*output.ResultEvent {
	deep := scanCtx != nil && scanCtx.DeepScan

	var results []*output.ResultEvent
	var indexResult *output.ResultEvent

	for _, ep := range m.pprof {
		if ep.deepOnly && !deep {
			continue
		}
		if res := m.probeEndpoint(ctx, httpClient, scanCtx, urlx, base, ep); res != nil {
			results = append(results, res)
			if ep.id == "index" {
				indexResult = res
			}
		}
	}

	// expvar is registered independently of the pprof mux, so probe it regardless
	// of whether any pprof handler confirmed at this base.
	if res := m.probeEndpoint(ctx, httpClient, scanCtx, urlx, base, m.expvar); res != nil {
		results = append(results, res)
	}

	// The time-based /profile and /trace handlers are never invoked (a CPU profile
	// is a free DoS). A confirmed index proves they are mounted, so report them
	// from the index evidence.
	if indexResult != nil {
		for _, ep := range m.inferred {
			results = append(results, m.inferredFinding(urlx, base, ep, indexResult))
		}
	}

	return results
}

// probeEndpoint fetches one endpoint and emits a finding only when the body
// satisfies the endpoint's structural confirm predicate, the response is not the
// host's wildcard/soft-404 shell, a guaranteed-nonexistent sibling under the same
// directory does not return the same markers (sub-directory catch-all guard), and
// the markers reproduce on a cache-bypassing second fetch.
func (m *Module) probeEndpoint(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
	urlx *urlutil.URL,
	base string,
	ep debugEndpoint,
) *output.ResultEvent {
	probePath := base + ep.path

	resp, rawReq, ok := m.fetch(ctx, httpClient, probePath, http.Options{})
	if !ok {
		return nil
	}
	defer resp.Close()

	if resp.Response().StatusCode != 200 {
		return nil
	}
	// A WAF/CDN challenge, auth gate, or rate-limit page is not the app serving the
	// endpoint — reject it before any marker match.
	if infra.IsBlockedResponse(resp) {
		return nil
	}
	if ep.ctMatch != "" && !strings.Contains(strings.ToLower(resp.Response().Header.Get("Content-Type")), ep.ctMatch) {
		return nil
	}
	// Materialize the body only once the cheap status/content-type gates pass; a
	// large non-matching 200 (a homepage, a catch-all shell) is never read in full.
	body := resp.Body().String()
	if !ep.confirm(body) {
		return nil
	}

	// Baseline 1 — host-wide soft-404 / SPA shell: drop when this body is just the
	// wildcard page a catch-all host returns for any path. Fails open on a probe
	// error so a flaky wildcard fetch never suppresses a real finding.
	if !modkit.ConfirmNotSoft404(scanCtx, httpClient, ctx, 200, []byte(body), "") {
		return nil
	}

	// Baseline 2 — sub-directory catch-all: a guaranteed-nonexistent sibling under
	// the same parent directory must NOT satisfy the same markers. A real pprof mux
	// answers an unknown profile with a 404 "Unknown profile", so the sibling fails
	// the predicate and the finding survives; a wildcard handler echoes the same
	// body for the sibling and is dropped.
	if modkit.SiblingPathCatchAll(scanCtx, ctx, httpClient, probePath, ep.confirm) {
		return nil
	}

	// Reproduce — re-fetch with the response cache bypassed and require the
	// structural markers to hold again. Profiles change their numeric values
	// between calls, so we re-run the marker predicate rather than compare bodies.
	repStatus, repBody, repOK := modkit.FetchPath(ctx, httpClient, probePath)
	if !repOK || repStatus != 200 || !ep.confirm(repBody) {
		return nil
	}

	target := urlx.Scheme + "://" + urlx.Host + probePath
	return &output.ResultEvent{
		URL:              target,
		Matched:          target,
		Request:          rawReq,
		Response:         resp.FullResponseString(), // materialized only for a confirmed finding
		FuzzingParameter: base,
		ExtractedResults: []string{ep.id + " @ " + probePath},
		Info:             m.info(ep),
	}
}

// inferredFinding builds a finding for a never-invoked handler (/profile, /trace)
// from the confirmed index's request/response evidence.
func (m *Module) inferredFinding(
	urlx *urlutil.URL,
	base string,
	ep debugEndpoint,
	indexResult *output.ResultEvent,
) *output.ResultEvent {
	target := urlx.Scheme + "://" + urlx.Host + base + ep.path
	return &output.ResultEvent{
		URL:              target,
		Matched:          target,
		Request:          indexResult.Request,
		Response:         indexResult.Response,
		FuzzingParameter: base,
		ExtractedResults: []string{"confirmed via " + base + pprofIndexPath + " index (handler not invoked)"},
		Info:             m.info(ep),
	}
}

// info builds the per-endpoint finding metadata so each finding reports its own
// severity/confidence rather than the module-level default.
func (m *Module) info(ep debugEndpoint) output.Info {
	return output.Info{
		Name:        ep.name,
		Description: ep.desc,
		Severity:    ep.sev,
		Confidence:  ep.conf,
		Tags:        append([]string(nil), m.Tags()...),
		Reference: []string{
			"https://pkg.go.dev/net/http/pprof",
			"https://pkg.go.dev/expvar",
		},
	}
}

// fetch issues a GET to path carrying the observed request's headers and service.
// It returns the OPEN response chain — the caller must Close it — together with
// the raw request string for evidence. ok is false on any build/transport error
// or a missing response, in which case there is nothing to close. The body and
// full-response string are left unmaterialized so the caller can apply its cheap
// status/content-type gates before paying to read a potentially large body.
func (m *Module) fetch(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	path string,
	opts http.Options,
) (resp *httputil.ResponseChain, rawReq string, ok bool) {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil, "", false
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, path)
	if err != nil {
		return nil, "", false
	}

	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return nil, "", false
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err = httpClient.Execute(fuzzedReq, opts)
	if err != nil {
		return nil, "", false
	}
	if resp.Response() == nil {
		resp.Close()
		return nil, "", false
	}
	return resp, string(modifiedRaw), true
}
