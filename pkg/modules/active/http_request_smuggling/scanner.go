package http_request_smuggling

import (
	"fmt"
	"strings"
	"time"

	httputil "github.com/projectdiscovery/utils/http"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// Timing-anomaly thresholds. A probe must be both relatively (vs the host
// baseline) and absolutely slow before it is even considered — and then it
// still has to clear the confirmation gates in confirmTimingDesync.
const (
	timingMultiplier = 5
	timingFloor      = 5 * time.Second
)

// smugglingProbe defines a request smuggling test case.
type smugglingProbe struct {
	name    string
	headers map[string]string
	body    string
	desc    string
}

// CL.TE: backend uses Transfer-Encoding, frontend uses Content-Length
// TE.CL: backend uses Content-Length, frontend uses Transfer-Encoding
var probes = []smugglingProbe{
	{
		name: "CL.TE Basic",
		headers: map[string]string{
			"Content-Length":    "4",
			"Transfer-Encoding": "chunked",
		},
		body: "1\r\nZ\r\nQ\r\n\r\n",
		desc: "CL.TE desync: frontend uses Content-Length, backend uses Transfer-Encoding. The extra data after the chunked body may be treated as a separate request.",
	},
	{
		name: "TE.CL Basic",
		headers: map[string]string{
			"Content-Length":    "6",
			"Transfer-Encoding": "chunked",
		},
		body: "0\r\n\r\nX",
		desc: "TE.CL desync: frontend uses Transfer-Encoding, backend uses Content-Length. Content after the terminating chunk may be treated as a separate request.",
	},
	{
		name: "TE.TE Obfuscation",
		headers: map[string]string{
			"Content-Length":    "4",
			"Transfer-Encoding": "chunked",
			"Transfer-encoding": "x",
		},
		body: "1\r\nZ\r\nQ\r\n\r\n",
		desc: "TE.TE desync via header obfuscation: uses duplicate Transfer-Encoding headers with different casing to confuse parsers.",
	},
	{
		name: "Chunked Extension",
		headers: map[string]string{
			"Content-Length":    "4",
			"Transfer-Encoding": "chunked",
		},
		body: "1;ext=val\r\nZ\r\n0\r\n\r\n",
		desc: "Chunked extension confusion: uses chunk extension syntax that may be parsed differently.",
	},
	{
		name: "TE Tab Obfuscation",
		headers: map[string]string{
			"Content-Length":    "4",
			"Transfer-Encoding": "\tchunked",
		},
		body: "1\r\nZ\r\nQ\r\n\r\n",
		desc: "Transfer-Encoding with leading tab may bypass header parsing.",
	},
}

// Module implements the HTTP Request Smuggling active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new HTTP Request Smuggling module.
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
			modkit.ScanScopeHost,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("http_request_smuggling"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// IncludesBaseCanProcess returns false because this module uses a custom CanProcess
// that does not include the base URL/media/method checks.
func (m *Module) IncludesBaseCanProcess() bool { return false }

// CanProcess checks if the request is suitable for smuggling tests.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil {
		return false
	}
	if ctx.Response() == nil {
		return false
	}
	return true
}

// ScanPerHost runs smuggling probes once per unique host.
func (m *Module) ScanPerHost(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}

	host := service.Host()

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	// First, measure baseline response time.
	baselineStart := time.Now()
	baseResp, _, err := httpClient.Execute(ctx, http.Options{})
	if err != nil {
		return nil, nil
	}
	baselineBlocked := isBlockedResponse(baseResp)
	baseResp.Close()
	baselineDuration := time.Since(baselineStart)

	// If the host's normal response is already an edge/CDN/WAF rejection
	// (e.g. a Cloudflare 403 "Edge IP Restricted" page), requests never reach
	// an origin frontend/backend parser chain. Every probe will be blocked the
	// same way and the timing reading just measures edge processing, not a
	// desync — so timing-based detection cannot produce a trustworthy result
	// here. Skip the host rather than emit a guaranteed false positive.
	if baselineBlocked {
		return nil, nil
	}

	var results []*output.ResultEvent

	for _, probe := range probes {
		modifiedRaw, ok := buildProbeRequest(ctx, probe)
		if !ok {
			continue
		}

		fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
		if err != nil {
			continue
		}
		fuzzedReq = fuzzedReq.WithService(ctx.Service())

		start := time.Now()
		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		elapsed := time.Since(start)
		if err != nil {
			// A timeout itself can be an indicator of a backend hanging on the
			// smuggled bytes — but only after it survives confirmation (the
			// re-probe and a fast well-formed control), otherwise it is just a
			// slow/erroring host.
			if isTimingAnomaly(elapsed, baselineDuration) {
				if ev, ok := m.confirmTimingDesync(ctx, modifiedRaw, httpClient, baselineDuration); ok {
					results = append(results, buildResult(ctx, modifiedRaw, probe, baselineDuration, elapsed, true, ev))
				}
			}
			continue
		}

		anomaly := isTimingAnomaly(elapsed, baselineDuration)
		blocked := isBlockedResponse(resp)
		resp.Close()

		if !anomaly {
			continue
		}
		// Edge/CDN/WAF block: the slow response is the edge rejecting the probe,
		// not a frontend/backend desync. This is the direct fix for the
		// Cloudflare 403 "Edge IP Restricted" false positive.
		if blocked {
			continue
		}

		if ev, ok := m.confirmTimingDesync(ctx, modifiedRaw, httpClient, baselineDuration); ok {
			results = append(results, buildResult(ctx, modifiedRaw, probe, baselineDuration, elapsed, false, ev))
		}
	}

	return results, nil
}

// isTimingAnomaly reports whether elapsed is slow enough — both relative to the
// host baseline and in absolute terms — to be worth confirming as a desync.
func isTimingAnomaly(elapsed, baseline time.Duration) bool {
	return elapsed > baseline*timingMultiplier && elapsed > timingFloor
}

// confirmTimingDesync re-validates a probe that produced an initial timing
// anomaly. A single slow response is not enough on its own: it is most often
// network jitter, a transient backend stall, or general host/path latency. We
// only keep the finding when:
//
//  1. the slowness reproduces on a second send of the same probe (rules out
//     one-off jitter), and the re-send is not an edge/CDN/WAF block, and
//  2. a well-formed control POST of similar shape (no conflicting CL/TE, valid
//     body) returns quickly — if the control is ALSO slow the host/path is
//     simply slow for POST traffic and the anomaly is not a desync.
//
// desyncEvidence carries the confirmation-round measurements confirmTimingDesync
// takes while validating a timing anomaly: the reconfirmed probe (which must
// still be slow) and, when one could be sent, the well-formed control (which
// must be fast). Preserving these lets the finding show the differential that
// distinguishes a real desync from a host that is simply slow for POST traffic,
// instead of asserting it in prose.
type desyncEvidence struct {
	reElapsed   time.Duration
	probeReq    string
	probeResp   string
	hasControl  bool
	ctrlElapsed time.Duration
	ctrlReq     string
	ctrlResp    string
}

func (m *Module) confirmTimingDesync(
	ctx *httpmsg.HttpRequestResponse,
	modifiedRaw []byte,
	httpClient *http.Requester,
	baseline time.Duration,
) (desyncEvidence, bool) {
	ev := desyncEvidence{probeReq: string(modifiedRaw)}

	// 1. Reconfirm the anomaly with a fresh send of the same probe.
	probeReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return ev, false
	}
	probeReq = probeReq.WithService(ctx.Service())

	reStart := time.Now()
	reResp, _, reErr := httpClient.Execute(probeReq, http.Options{})
	reElapsed := time.Since(reStart)
	ev.reElapsed = reElapsed
	if reErr == nil {
		// A reproduced block means the edge is rejecting us, not a desync.
		blocked := isBlockedResponse(reResp)
		ev.probeResp = reResp.FullResponseString()
		reResp.Close()
		if blocked {
			return ev, false
		}
	}
	if !isTimingAnomaly(reElapsed, baseline) {
		return ev, false
	}

	// 2. A well-formed control POST must be fast. If we cannot build one, fall
	// back to the (already reconfirmed) anomaly rather than dropping it.
	controlRaw, ok := buildControlRequest(ctx)
	if !ok {
		return ev, true
	}
	controlReq, err := httpmsg.ParseRawRequest(string(controlRaw))
	if err != nil {
		return ev, true
	}
	controlReq = controlReq.WithService(ctx.Service())

	ctrlStart := time.Now()
	ctrlResp, _, ctrlErr := httpClient.Execute(controlReq, http.Options{})
	ctrlElapsed := time.Since(ctrlStart)
	if ctrlErr != nil {
		// The control errored where the probe returned: inconclusive, and a
		// host that errors on a plain POST is not safe to call desynced.
		return ev, false
	}
	ev.hasControl = true
	ev.ctrlElapsed = ctrlElapsed
	ev.ctrlReq = string(controlRaw)
	ev.ctrlResp = ctrlResp.FullResponseString()
	ctrlResp.Close()

	// If a plain, unambiguous POST is just as slow, the latency is general and
	// not attributable to CL/TE desync.
	return ev, !isTimingAnomaly(ctrlElapsed, baseline)
}

// buildProbeRequest turns the host's request into a smuggling probe: forced to
// POST, with the probe's conflicting CL/TE headers and crafted body.
func buildProbeRequest(ctx *httpmsg.HttpRequestResponse, probe smugglingProbe) ([]byte, bool) {
	raw := ctx.Request().Raw()

	var err error
	raw, err = httpmsg.SetMethod(raw, "POST")
	if err != nil {
		return nil, false
	}
	for k, v := range probe.headers {
		raw, err = httpmsg.AddOrReplaceHeader(raw, k, v)
		if err != nil {
			return nil, false
		}
	}
	raw, err = httpmsg.SetBody(raw, []byte(probe.body))
	if err != nil {
		return nil, false
	}
	return raw, true
}

// buildControlRequest produces a well-formed POST of similar shape to the
// probes but with no conflicting framing: Transfer-Encoding removed and a small
// valid body whose Content-Length SetBody recomputes correctly. Such a request
// can never trigger a CL/TE desync, so it serves as the "should always be fast"
// baseline for the timing differential.
func buildControlRequest(ctx *httpmsg.HttpRequestResponse) ([]byte, bool) {
	raw := ctx.Request().Raw()

	var err error
	raw, err = httpmsg.SetMethod(raw, "POST")
	if err != nil {
		return nil, false
	}
	raw, err = httpmsg.RemoveHeader(raw, "Transfer-Encoding")
	if err != nil {
		return nil, false
	}
	raw, err = httpmsg.SetBody(raw, []byte("1"))
	if err != nil {
		return nil, false
	}
	return raw, true
}

// buildResult constructs the finding for a confirmed timing anomaly. It carries
// the confirmation differential captured by confirmTimingDesync — the
// reconfirmed slow probe and the fast well-formed control — as AdditionalEvidence
// and Metadata, so the proof of "desync, not a generally slow host" travels with
// the finding instead of being collapsed to a one-line claim.
func buildResult(
	ctx *httpmsg.HttpRequestResponse,
	modifiedRaw []byte,
	probe smugglingProbe,
	baseline, elapsed time.Duration,
	timeout bool,
	ev desyncEvidence,
) *output.ResultEvent {
	name := fmt.Sprintf("HTTP Request Smuggling: %s", probe.name)
	timing := fmt.Sprintf("Baseline: %s, Probe: %s", baseline, elapsed)
	if timeout {
		name = fmt.Sprintf("HTTP Request Smuggling: %s (Timeout)", probe.name)
		timing = fmt.Sprintf("Baseline: %s, Probe: %s (timeout)", baseline, elapsed)
	}

	extracted := []string{
		fmt.Sprintf("Probe: %s", probe.name),
		timing,
		fmt.Sprintf("Reconfirm probe: %s (anomaly reproduced)", ev.reElapsed),
	}

	collector := modkit.NewEvidenceCollector()
	collector.Add("reconfirm probe (anomaly reproduced)", ev.probeReq, ev.probeResp)

	meta := map[string]any{
		"baseline_ms":  baseline.Milliseconds(),
		"probe_ms":     elapsed.Milliseconds(),
		"reconfirm_ms": ev.reElapsed.Milliseconds(),
		"timeout":      timeout,
	}

	if ev.hasControl {
		extracted = append(extracted, fmt.Sprintf(
			"Well-formed control: %s (fast → latency is desync-specific, not general)", ev.ctrlElapsed))
		collector.Add("well-formed control (returned fast)", ev.ctrlReq, ev.ctrlResp)
		meta["control_ms"] = ev.ctrlElapsed.Milliseconds()
	}
	extracted = append(extracted,
		"Confirmation: anomaly reproduced and well-formed control returned fast (not an edge/CDN block)")

	return &output.ResultEvent{
		URL:                ctx.Target(),
		Matched:            ctx.Target(),
		Request:            string(modifiedRaw),
		Response:           ev.probeResp,
		AdditionalEvidence: collector.Entries(),
		ExtractedResults:   extracted,
		Metadata:           meta,
		Info: output.Info{
			Name:        name,
			Description: probe.desc,
			// Timing inference is prone to backend-delay false positives, so
			// even a confirmed anomaly is reported as suspect/tentative.
			Severity:   severity.Suspect,
			Confidence: severity.Tentative,
		},
	}
}

// isBlockedResponse reports whether the response is an edge/CDN/WAF rejection
// rather than an origin backend response. A timing anomaly on a blocked request
// is the edge processing (or rate-limiting) the request, not a frontend/backend
// desync, so such responses must never back a smuggling finding. It combines
// the vendor-aware block detector (Cloudflare, Akamai, Incapsula, …) with a
// body-marker check that also catches generic edge error pages the
// header-based detector does not recognize.
func isBlockedResponse(resp *httputil.ResponseChain) bool {
	if resp == nil || resp.Response() == nil {
		return false
	}
	if infra.GetBlockDetectionValidator().Validate(resp) != nil {
		return true
	}
	switch resp.Response().StatusCode {
	case 401, 403, 429, 503:
		if looksLikeEdgeBlockPage(resp.BodyString()) {
			return true
		}
	}
	return false
}

// looksLikeEdgeBlockPage detects common CDN/WAF interstitial block pages (e.g.
// Cloudflare edge errors such as "Edge IP Restricted" / error 1034) by body
// markers. These pages are served by the edge before the origin chain is ever
// reached, so any timing measured against them is meaningless for desync.
func looksLikeEdgeBlockPage(body string) bool {
	if body == "" {
		return false
	}
	lower := strings.ToLower(body)
	markers := []string{
		"cf-error-details",                   // Cloudflare error page container
		"cloudflare ray id",                  // Cloudflare footer
		"/cdn-cgi/",                          // Cloudflare edge asset path
		"edge ip restricted",                 // Cloudflare error 1034
		"attention required",                 // Cloudflare challenge/block
		"error 1020",                         // Cloudflare access denied
		"access denied",                      // Akamai / generic WAF
		"akamaighost",                        // Akamai
		"request unsuccessful. incapsula",    // Imperva Incapsula
		"_incapsula_resource",                // Imperva Incapsula
		"the request could not be satisfied", // CloudFront
	}
	for _, mk := range markers {
		if strings.Contains(lower, mk) {
			return true
		}
	}
	return false
}
