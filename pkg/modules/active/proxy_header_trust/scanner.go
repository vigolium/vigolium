package proxy_header_trust

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const (
	injectedHost = "vigolium-probe.example"
	injectedIP   = "127.0.0.1"
)

// isAccessDenied returns true for status codes that indicate the request was
// rejected by an auth/WAF/rate-limit layer rather than served by the app.
func isAccessDenied(status int) bool {
	return status == 401 || status == 403 || status == 429 || status == 503
}

// Module implements the Proxy Header Trust active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Proxy Header Trust module.
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
		ds: dedup.LazyDiskSet("proxy_header_trust"),
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

// ScanPerRequest tests the host for proxy header trust issues.
func (m *Module) ScanPerRequest(
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

	// Send baseline request.
	baselineRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil, nil
	}
	baselineRaw, err = httpmsg.SetPath(baselineRaw, "/")
	if err != nil {
		return nil, nil
	}

	baselineReq, err := httpmsg.ParseRawRequest(string(baselineRaw))
	if err != nil {
		return nil, nil
	}
	baselineReq = baselineReq.WithService(ctx.Service())

	baselineResp, _, err := httpClient.Execute(baselineReq, http.Options{})
	if err != nil {
		return nil, nil
	}

	baselineStatus := 0
	baselineLocation := ""
	if baselineResp.Response() != nil {
		baselineStatus = baselineResp.Response().StatusCode
		baselineLocation = baselineResp.Response().Header.Get("Location")
	}
	baselineBody := baselineResp.Body().String()
	_ = baselineLocation

	// Build the no-header baseline evidence once and share it across all three
	// findings: each compares its spoofed-header probe (the attack pair) against the
	// same GET / baseline. Capture before Close frees the buffer.
	baselineEv := modkit.NewEvidenceCollector()
	baselineEv.Add("baseline", string(baselineRaw), baselineResp.FullResponseString())
	baselineEvidence := baselineEv.Entries()

	baselineResp.Close()

	urlx, _ := ctx.URL()
	var results []*output.ResultEvent

	// Test 1: X-Forwarded-Host reflection.
	if result := m.testForwardedHost(ctx, httpClient, urlx.String(), baselineEvidence); result != nil {
		results = append(results, result)
	}

	// Test 2: X-Forwarded-Proto behavior change.
	if result := m.testForwardedProto(ctx, httpClient, baselineStatus, urlx.String(), baselineEvidence); result != nil {
		results = append(results, result)
	}

	// Test 3: X-Forwarded-For IP trust bypass.
	if result := m.testForwardedFor(ctx, httpClient, baselineStatus, baselineBody, urlx.String(), baselineEvidence); result != nil {
		results = append(results, result)
	}

	return results, nil
}

func (m *Module) testForwardedHost(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	targetURL string,
	baselineEvidence []string,
) *output.ResultEvent {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, "/")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.AddOrReplaceHeader(modifiedRaw, "X-Forwarded-Host", injectedHost)
	if err != nil {
		return nil
	}

	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return nil
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil
	}

	probeBody := resp.Body().String()
	probeLocation := ""
	if resp.Response() != nil {
		probeLocation = resp.Response().Header.Get("Location")
	}

	var finding string

	if strings.Contains(probeLocation, injectedHost) {
		finding = fmt.Sprintf("Injected host %q reflected in Location header: %s", injectedHost, probeLocation)
	} else if strings.Contains(probeBody, injectedHost) {
		finding = fmt.Sprintf("Injected host %q reflected in response body", injectedHost)
	}

	if finding == "" {
		return nil
	}

	return &output.ResultEvent{
		URL:                targetURL,
		Request:            string(modifiedRaw),
		Response:           resp.FullResponseString(),
		AdditionalEvidence: baselineEvidence,
		ExtractedResults: []string{
			"Header: X-Forwarded-Host: " + injectedHost,
			"Finding: " + finding,
		},
		Info: output.Info{
			Name:        "Proxy Header Trust: X-Forwarded-Host Injection",
			Description: "X-Forwarded-Host header is trusted for URL generation, allowing host-based attacks such as password reset poisoning and cache poisoning",
			Severity:    severity.High,
			Confidence:  ModuleConfidence,
			Tags:        []string{"proxy", "forwarded-headers", "ip-spoofing", "host-injection"},
			Reference:   []string{"https://owasp.org/www-project-web-security-testing-guide/"},
		},
	}
}

func (m *Module) testForwardedProto(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	baselineStatus int,
	targetURL string,
	baselineEvidence []string,
) *output.ResultEvent {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, "/")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.AddOrReplaceHeader(modifiedRaw, "X-Forwarded-Proto", "https")
	if err != nil {
		return nil
	}

	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return nil
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil
	}

	probeStatus := resp.Response().StatusCode
	probeLocation := resp.Response().Header.Get("Location")

	var finding string

	isBaselineRedirect := baselineStatus >= 300 && baselineStatus < 400
	isProbeRedirect := probeStatus >= 300 && probeStatus < 400

	if isBaselineRedirect && !isProbeRedirect {
		finding = fmt.Sprintf("X-Forwarded-Proto: https removed redirect (baseline status %d, probe status %d)", baselineStatus, probeStatus)
	} else if !isBaselineRedirect && isProbeRedirect {
		finding = fmt.Sprintf("X-Forwarded-Proto: https caused new redirect (status %d, Location: %s)", probeStatus, probeLocation)
	} else if baselineStatus != probeStatus && !isAccessDenied(probeStatus) && !isAccessDenied(baselineStatus) {
		// Skip transitions that touch an access-denied status on either side: a
		// 200→429/403 is the WAF reacting to the header (not trust), and a
		// 429/503→200 is a transient rate-limit/maintenance baseline simply
		// clearing — neither is X-Forwarded-Proto confusion.
		finding = fmt.Sprintf("X-Forwarded-Proto: https changed response status from %d to %d", baselineStatus, probeStatus)
	}

	if finding == "" {
		return nil
	}

	return &output.ResultEvent{
		URL:                targetURL,
		Request:            string(modifiedRaw),
		Response:           resp.FullResponseString(),
		AdditionalEvidence: baselineEvidence,
		ExtractedResults: []string{
			"Header: X-Forwarded-Proto: https",
			"Finding: " + finding,
		},
		Info: output.Info{
			Name:        "Proxy Header Trust: X-Forwarded-Proto Confusion",
			Description: "X-Forwarded-Proto header is trusted, causing protocol confusion that may affect redirect behavior, cookie security flags, or HTTPS enforcement",
			Severity:    severity.Medium,
			Confidence:  ModuleConfidence,
			Tags:        []string{"proxy", "forwarded-headers", "ip-spoofing", "host-injection"},
			Reference:   []string{"https://owasp.org/www-project-web-security-testing-guide/"},
		},
	}
}

func (m *Module) testForwardedFor(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	baselineStatus int,
	baselineBody string,
	targetURL string,
	baselineEvidence []string,
) *output.ResultEvent {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, "/")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.AddOrReplaceHeader(modifiedRaw, "X-Forwarded-For", injectedIP)
	if err != nil {
		return nil
	}

	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return nil
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil
	}

	probeStatus := resp.Response().StatusCode
	probeBody := resp.Body().String()

	// A true IP-trust bypass goes from blocked→allowed: the spoofed source IP was
	// trusted and granted access. The reverse (200→429/403) is the WAF detecting
	// the spoofed header and throttling — that's the opposite of trust. A single
	// baseline status is unreliable, though (a transient 429/503 that simply
	// cleared by the probe reads as a bypass), so confirm the split is reproducible
	// and header-attributable before asserting an access-control bypass.
	if isAccessDenied(baselineStatus) && probeStatus >= 200 && probeStatus < 300 &&
		m.confirmForwardedForBypass(ctx, httpClient) {
		return &output.ResultEvent{
			URL:                targetURL,
			Request:            string(modifiedRaw),
			Response:           resp.FullResponseString(),
			AdditionalEvidence: baselineEvidence,
			ExtractedResults: []string{
				"Header: X-Forwarded-For: " + injectedIP,
				"Finding: " + fmt.Sprintf("X-Forwarded-For IP spoofing bypassed access control (status %d → %d)", baselineStatus, probeStatus),
			},
			Info: output.Info{
				Name:        "Proxy Header Trust: X-Forwarded-For IP Bypass",
				Description: "X-Forwarded-For header is trusted for IP-based access controls, allowing attackers to bypass rate limiting or IP restrictions by spoofing their source address",
				Severity:    severity.High,
				Confidence:  ModuleConfidence,
				Tags:        []string{"proxy", "forwarded-headers", "ip-spoofing", "host-injection"},
				Reference:   []string{"https://owasp.org/www-project-web-security-testing-guide/"},
			},
		}
	}

	// A raw body-length delta is a poor signal: most pages jitter in size on every
	// request (rotating CSRF tokens, timestamps, ads, view counts), so a one-shot
	// baseline-vs-probe comparison flags benign variance as a vuln — the reported
	// false positive ("response is not much different, still flagged"). Attribute a
	// size shift to the header only when it is reproducible AND lands clearly
	// outside the page's natural jitter (measured by a fresh no-header control).
	// Skip entirely when either side is a WAF/denied page — that size is noise, and
	// a WAF reacting to the spoofed header is the opposite of trusting it.
	if !isAccessDenied(baselineStatus) && !isAccessDenied(probeStatus) && len(baselineBody) > 0 {
		if shift, ok := m.confirmForwardedForSizeShift(ctx, httpClient, len(baselineBody), len(probeBody)); ok {
			return &output.ResultEvent{
				URL:                targetURL,
				Request:            string(modifiedRaw),
				Response:           resp.FullResponseString(),
				AdditionalEvidence: baselineEvidence,
				ExtractedResults: []string{
					"Header: X-Forwarded-For: " + injectedIP,
					"Finding: " + shift,
				},
				Info: output.Info{
					Name:        "Proxy Header Trust: X-Forwarded-For Content Variation",
					Description: "Response content reproducibly varies with the spoofed X-Forwarded-For source IP, beyond the page's natural per-request variance. The application appears to gate content on the client-supplied source address, which may expose IP-restricted content or behavior to a spoofed caller. Verify what differs before treating it as an access-control bypass.",
					Severity:    severity.Medium,
					Confidence:  severity.Tentative,
					Tags:        []string{"proxy", "forwarded-headers", "ip-spoofing", "host-injection"},
					Reference:   []string{"https://owasp.org/www-project-web-security-testing-guide/"},
				},
			}
		}
	}

	return nil
}

// confirmForwardedForSizeShift decides whether the spoofed X-Forwarded-For header
// is responsible for a response-size change, rather than ordinary per-request
// jitter. It fetches a fresh no-header control (to learn the page's natural
// variance) and re-sends the spoofed-IP probe (to require reproducibility), then
// reports a hit only when BOTH probe responses land on the same side of, and
// clearly outside, the no-header size band by more than a meaningful margin.
// Returns the human description and true on a confirmed shift; false whenever a
// sample can't be taken cleanly, so an unverifiable change is never reported.
func (m *Module) confirmForwardedForSizeShift(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	baselineLen, probeLen int,
) (string, bool) {
	controlLen, ok := m.fetchBodyLen(ctx, httpClient, false)
	if !ok {
		return "", false // can't establish natural variance → don't attribute
	}
	probe2Len, ok := m.fetchBodyLen(ctx, httpClient, true)
	if !ok {
		return "", false // can't confirm reproducibility → don't attribute
	}

	// Attribute the shift to the header only when both spoofed-IP samples land on
	// the same side of, and clear of, the no-header band by more than its variance.
	if _, ok := modkit.SizeShiftGap(baselineLen, controlLen, probeLen, probe2Len); !ok {
		return "", false
	}

	noHdrMin, noHdrMax := min(baselineLen, controlLen), max(baselineLen, controlLen)
	probeMin, probeMax := min(probeLen, probe2Len), max(probeLen, probe2Len)
	return fmt.Sprintf(
		"X-Forwarded-For reproducibly shifted response size outside natural variance (no-header %d–%d bytes, spoofed-IP %d–%d bytes)",
		noHdrMin, noHdrMax, probeMin, probeMax,
	), true
}

// confirmForwardedForBypass verifies an apparent blocked→allowed transition is
// genuinely caused by trusting the spoofed X-Forwarded-For header, not transient
// rate-limit/maintenance flapping. A 429/503 (or even 401/403) captured on the
// single baseline fetch can simply clear by the time the probe is sent — e.g. the
// scan hammered the host into a 429 that recovered a moment later — which then
// reads as "spoofing bypassed access control" though the header did nothing.
//
// It re-runs the pair interleaved, with the spoofed header as the ONLY variable:
// each round the no-header control must STILL be denied and the spoofed-IP probe
// must STILL be allowed. A real IP-trust bypass holds every round; flapping
// breaks it (the no-header control comes back allowed, or the probe comes back
// denied). Drops on any miss or fetch error so an unverifiable transition is
// never reported.
func (m *Module) confirmForwardedForBypass(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester) bool {
	const rounds = 2
	for range rounds {
		if _, controlStatus, ok := m.doFetch(ctx, httpClient, false); !ok || !isAccessDenied(controlStatus) {
			return false // not denied WITHOUT the header → the block isn't header-attributable
		}
		if _, probeStatus, ok := m.doFetch(ctx, httpClient, true); !ok || probeStatus < 200 || probeStatus >= 300 {
			return false // not allowed WITH the header → not a reproducible bypass
		}
	}
	return true
}

// fetchBodyLen issues a GET / (optionally carrying the spoofed X-Forwarded-For
// header) and returns the response body length. ok is false on any build/parse/
// transport error, a nil response, or a WAF/denied status — none of which can
// serve as a clean size sample.
func (m *Module) fetchBodyLen(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, withSpoofedIP bool) (int, bool) {
	bodyLen, status, ok := m.doFetch(ctx, httpClient, withSpoofedIP)
	if !ok || isAccessDenied(status) {
		return 0, false
	}
	return bodyLen, true
}

// doFetch issues a GET / (optionally carrying the spoofed X-Forwarded-For header),
// bypassing the response cache so it truly hits the wire, and returns the body
// length and status code. ok is false only on a build/parse/transport error or a
// nil response — an access-denied status is a valid observation the caller judges.
func (m *Module) doFetch(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, withSpoofedIP bool) (bodyLen, status int, ok bool) {
	raw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return 0, 0, false
	}
	raw, err = httpmsg.SetPath(raw, "/")
	if err != nil {
		return 0, 0, false
	}
	if withSpoofedIP {
		raw, err = httpmsg.AddOrReplaceHeader(raw, "X-Forwarded-For", injectedIP)
		if err != nil {
			return 0, 0, false
		}
	}
	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return 0, 0, false
	}
	req = req.WithService(ctx.Service())
	// NoClustering: the requester replays a cached response for an identical
	// request (500ms TTL). A replayed baseline/probe would collapse the measured
	// natural variance to zero and make a transient block look reproducible —
	// defeating both confirmation gates. These fetches must really hit the wire.
	resp, _, err := httpClient.Execute(req, http.Options{NoClustering: true})
	if err != nil {
		return 0, 0, false
	}
	defer resp.Close()
	if resp.Response() == nil {
		return 0, 0, false
	}
	return len(resp.Body().String()), resp.Response().StatusCode, true
}
