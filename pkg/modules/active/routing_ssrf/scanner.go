package routing_ssrf

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	urlutil "github.com/projectdiscovery/utils/url"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const (
	// limitPerHost gates the (heavy) request-line sweep to once per host.
	limitPerHost = 1
	// confirmRounds is how many extra times a candidate internal-marker hit must
	// reproduce (2xx + marker, not blocked) before it is reported.
	confirmRounds = 2
	// decoyEffective is an RFC 5737 TEST-NET-1 host that never answers a metadata
	// request; used as the negative control for the in-band oracle.
	decoyEffective = "192.0.2.1/"
)

// Module implements the routing-based (request-line) SSRF active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new routing-ssrf module.
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
		ds: dedup.LazyDiskSet("routing_ssrf"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest runs the OAST oracle (fire-and-forget, async correlation) and
// the in-band internal/metadata oracle (synchronous, strongly confirmed), once
// per host.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}
	if !infra.IsValidForInjectionVulns(urlx, ctx) {
		return nil, nil
	}
	if !m.markAndShouldContinue(urlx, scanCtx) {
		return nil, nil
	}

	baseRaw := ctx.Request().Raw()
	if ctx.Request().Method() != "GET" {
		baseRaw = infra.SwapToGetMethodRequest(baseRaw)
	}
	service := ctx.Service()
	victimHost := urlx.Host

	// Oracle 1 — OAST (out-of-band). Findings arrive asynchronously via polling.
	m.runOASTOracle(ctx, httpClient, scanCtx, urlx, baseRaw, service, victimHost)

	// Oracle 2 — internal / cloud metadata (in-band, confirmed).
	if ev := m.runInternalOracle(httpClient, urlx, baseRaw, service, victimHost); ev != nil {
		return []*output.ResultEvent{ev}, nil
	}
	return nil, nil
}

// runOASTOracle points the request-line ladder at an OAST collaborator host. A
// callback from the proxy's network confirms routing SSRF; correlation and the
// finding are handled asynchronously by the OAST service.
func (m *Module) runOASTOracle(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
	urlx *urlutil.URL,
	baseRaw []byte,
	service *httpmsg.Service,
	victimHost string,
) {
	oast := scanCtx.OASTProv()
	if oast == nil || !oast.Enabled() {
		return
	}
	oastHost := oast.GenerateURL(urlx.String(), "request-line", "routing-ssrf (request-line)", ModuleID, ctx.Request().ID())
	if oastHost == "" {
		return
	}
	for _, t := range infra.RoutingTargets(victimHost, oastHost+"/") {
		// Fire-and-forget: a hit is observed out-of-band, not in this response.
		if _, _, _, _, _, fatal := m.fireTarget(httpClient, service, baseRaw, t.Target, nil); fatal {
			return
		}
	}
}

// runInternalOracle points the request-line ladder at internal/metadata endpoints
// and reports only a marker that reproduces, is absent from a fresh baseline of
// the original request, and is absent for a benign decoy target.
func (m *Module) runInternalOracle(
	httpClient *http.Requester,
	urlx *urlutil.URL,
	baseRaw []byte,
	service *httpmsg.Service,
	victimHost string,
) *output.ResultEvent {
	baselineBody := m.freshBaseline(httpClient, service, baseRaw)

	for _, tgt := range infra.InternalSSRFTargets() {
		for _, f := range infra.RoutingTargets(victimHost, tgt.Effective) {
			status, body, fullResp, blocked, ok, fatal := m.fireTarget(httpClient, service, baseRaw, f.Target, tgt.ExtraHeaders)
			if fatal {
				return nil
			}
			if !ok || blocked || !is2xx(status) {
				continue
			}
			// A real metadata endpoint answers with a plain (non-HTML) body carrying a
			// cluster of distinct self-evidencing tokens; one common word like
			// "hostname" echoed by the app's own HTML page is not evidence.
			markers, ok := infra.ConfirmFreshMetadata(body, baselineBody, tgt.Markers)
			if !ok {
				continue
			}
			if ev := m.confirmInternal(httpClient, service, baseRaw, baselineBody, urlx, victimHost, tgt, f, markers, fullResp); ev != nil {
				return ev
			}
		}
	}
	return nil
}

// confirmInternal runs the strengthened, drop-on-fail gate for an internal-marker
// candidate: reproduce the marker on a 2xx (not a WAF page), prove a benign decoy
// target does NOT yield it (rules out a catch-all/canned page), and rely on the
// already-checked baseline-absence. Fails CLOSED whenever it cannot positively
// prove the marker came from the reached endpoint.
func (m *Module) confirmInternal(
	httpClient *http.Requester,
	service *httpmsg.Service,
	baseRaw []byte,
	baselineBody string,
	urlx *urlutil.URL,
	victimHost string,
	tgt infra.SSRFInternalTarget,
	f infra.RoutingTarget,
	markers []string,
	candidateResp string,
) *output.ResultEvent {
	ev := modkit.NewEvidenceCollector()
	ev.Add("candidate", displayRequest(baseRaw, f.Target), candidateResp)

	// (1) Reproducible: the SAME multi-marker cluster must reappear on a 2xx,
	// non-blocked, non-HTML response. Fails closed on any miss.
	for i := 0; i < confirmRounds; i++ {
		status, body, fullResp, blocked, ok, fatal := m.fireTarget(httpClient, service, baseRaw, f.Target, tgt.ExtraHeaders)
		if fatal || !ok || blocked || !is2xx(status) || !infra.MetadataBodyReproduces(body, markers) {
			return nil // fail closed
		}
		ev.Add(fmt.Sprintf("reproduce-%d", i+1), displayRequest(baseRaw, f.Target), fullResp)
	}

	// (2) Decoy-negative: the SAME request-line quirk around an unrelated TEST-NET
	// host must NOT yield the markers. If it does, the proxy serves this content for
	// any absolute target (a catch-all / canned error page) — not a reached endpoint.
	if decoy := decoyTargetLike(f, victimHost); decoy != "" {
		status, body, fullResp, blocked, ok, _ := m.fireTarget(httpClient, service, baseRaw, decoy, tgt.ExtraHeaders)
		if ok && !blocked && is2xx(status) && infra.BodyContainsAllMarkers(body, markers) {
			return nil // catch-all → false positive
		}
		ev.Add("decoy-negative", displayRequest(baseRaw, decoy), fullResp)
	}

	// (3) Baseline-absence was established before reporting; record it as evidence.
	ev.Add("baseline (original request)", string(baseRaw), baselineBody)

	markerList := strings.Join(markers, ", ")
	desc := fmt.Sprintf(
		"Routing-based SSRF: the proxy reached %s and returned internal-metadata markers (%s) when the request line named it via %s (%q) — while the connection and Host header were the victim. The response is a plain metadata body (not the app's HTML page), reproduces, and is absent for the victim baseline and a benign decoy.",
		tgt.Label, markerList, f.Label, f.Target,
	)
	return &output.ResultEvent{
		URL:                urlx.String(),
		Request:            displayRequest(baseRaw, f.Target),
		Response:           candidateResp,
		FuzzingParameter:   "request-line",
		ExtractedResults:   []string{f.Target, tgt.Label, "markers=" + markerList, f.Label},
		AdditionalEvidence: ev.Entries(),
		Info: output.Info{
			Name:        "Routing-Based SSRF (Internal Metadata Reached)",
			Description: desc,
			Severity:    severity.Info,
			Confidence:  severity.Tentative,
		},
	}
}

// fireTarget sends baseRaw with the literal request-line target written verbatim
// (connection still to service's host). Cache-Control: no-transform discourages
// intermediaries from mangling the payload (the "Cracking the lens" trick).
func (m *Module) fireTarget(
	httpClient *http.Requester,
	service *httpmsg.Service,
	baseRaw []byte,
	target string,
	extraHeaders map[string]string,
) (status int, body, fullResp string, blocked, ok, fatal bool) {
	raw, err := httpmsg.AddOrReplaceHeader(baseRaw, "Cache-Control", "no-transform")
	if err != nil {
		return 0, "", "", false, false, false
	}
	for k, v := range extraHeaders {
		raw, err = httpmsg.AddOrReplaceHeader(raw, k, v)
		if err != nil {
			return 0, "", "", false, false, false
		}
	}

	// AddOrReplaceHeader produces well-formed raw, so wrap directly instead
	// of re-parsing on this hot path.
	req := httpmsg.NewRequestResponseRaw(raw, service)

	resp, _, err := httpClient.Execute(req, http.Options{
		RawRequest:       true,
		RawRequestTarget: target,
		NoRedirects:      true,
		NoClustering:     true,
	})
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return 0, "", "", false, false, true
		}
		return 0, "", "", false, false, false
	}
	defer resp.Close()
	if resp.Response() == nil {
		return 0, "", "", false, false, false
	}
	return resp.Response().StatusCode, resp.Body().String(), resp.FullResponseString(), infra.IsBlockedResponse(resp), true, false
}

// freshBaseline fetches the original origin-form request once, for marker-absence
// comparison and evidence. Returns "" on any error (callers treat that as "no
// baseline content", which only makes the marker-absence check stricter).
func (m *Module) freshBaseline(httpClient *http.Requester, service *httpmsg.Service, baseRaw []byte) string {
	// baseRaw is already well-formed, so wrap directly instead of
	// re-parsing on this hot path.
	req := httpmsg.NewRequestResponseRaw(baseRaw, service)
	resp, _, err := httpClient.Execute(req, http.Options{NoRedirects: true})
	if err != nil {
		return ""
	}
	defer resp.Close()
	if resp.Response() == nil {
		return ""
	}
	return resp.Body().String()
}

// decoyTargetLike returns the request-line target for the same quirk as f but
// pointed at the benign TEST-NET decoy host.
func decoyTargetLike(f infra.RoutingTarget, victimHost string) string {
	for _, d := range infra.RoutingTargets(victimHost, decoyEffective) {
		if d.Label == f.Label {
			return d.Target
		}
	}
	return ""
}

func is2xx(status int) bool { return status >= 200 && status < 300 }

// displayRequest renders an evidence-friendly request showing the literal target
// on the request line (the wire form), preserving the original headers.
func displayRequest(baseRaw []byte, target string) string {
	s := string(baseRaw)
	rest := ""
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		rest = strings.TrimLeft(s[i+1:], "\r")
	}
	return "GET " + target + " HTTP/1.1\r\n" + rest
}

// markAndShouldContinue gates the sweep to effectively once per host.
func (m *Module) markAndShouldContinue(urlx *urlutil.URL, scanCtx *modkit.ScanContext) bool {
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet == nil {
		return true
	}
	_, shouldContinue := diskSet.IncrementAndCheck(urlx.Hostname(), limitPerHost)
	return shouldContinue
}
