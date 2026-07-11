package proxy_header_trust

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const (
	injectedHost = "vigolium-probe.example"
	injectedIP   = "127.0.0.1"
	controlIP    = "198.51.100.42"
)

type headerCapture struct {
	rawRequest   string
	fullResponse string
	body         string
	status       int
}

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

	if scanCtx != nil {
		diskSet := m.ds.Get(scanCtx.DedupMgr())
		if diskSet != nil && diskSet.IsSeen(host) {
			return nil, nil
		}
	}

	// Send baseline request.
	baselineRaw, ok := rootGetRaw(ctx, "", "")
	if !ok {
		return nil, nil
	}

	// BuildRequest/SetMethod/... produce well-formed raw, so wrap directly instead
	// of re-parsing on this hot path.
	baselineReq := httpmsg.NewRequestResponseRaw(baselineRaw, ctx.Service())

	baselineResp, _, err := httpClient.Execute(baselineReq, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return nil, nil
	}
	defer baselineResp.Close()
	if baselineResp.Response() == nil || infra.GetBlockDetectionValidator().Validate(baselineResp) != nil {
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

	urlx, err := ctx.URL()
	if err != nil || urlx == nil {
		return nil, nil
	}
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
	modifiedRaw, ok := rootGetRaw(ctx, "X-Forwarded-Host", injectedHost)
	if !ok {
		return nil
	}

	// BuildRequest/SetMethod/... produce well-formed raw, so wrap directly instead
	// of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	// NoRedirects: host-injection lives in the Location header the app GENERATES.
	// Following the redirect would replace it with the destination's response
	// (losing the evidence) and, worse, chase an attacker-influenced host — a
	// self-inflicted SSRF. Inspect the immediate hop instead, deterministically and
	// regardless of the requester's follow-redirect configuration.
	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil || infra.GetBlockDetectionValidator().Validate(resp) != nil {
		return nil
	}

	probeBody := resp.Body().String()
	probeLocation := ""
	if resp.Response() != nil {
		probeLocation = resp.Response().Header.Get("Location")
	}

	// Host poisoning requires the injected host to become the AUTHORITY of a
	// generated URL — the host a redirect actually sends the victim to, or the
	// host of a generated link (a password-reset URL) — not merely to appear as a
	// substring somewhere inside another URL. The reported false positive is the
	// latter: behind CloudFront an OAuth login flow reflects X-Forwarded-Host into
	// the URL-encoded redirect_uri= query parameter of a 302 whose authority stays
	// the trusted IdP (wam.acme.com), so the real destination is identical with or
	// without the spoofed header — there is nothing to poison. Match authority
	// position only; an echo inside a query value (or any %2F%2Fhost reflection)
	// does not qualify.
	locAuthority := modkit.HostReflectedAsAuthority(probeLocation, injectedHost)
	bodyAuthority := !locAuthority && modkit.HostReflectedAsAuthority(probeBody, injectedHost)

	var finding string
	confidence := severity.Firm
	switch {
	case locAuthority:
		finding = fmt.Sprintf("Injected host %q set as the redirect authority in the Location header: %s", injectedHost, probeLocation)
	case bodyAuthority:
		// A generated absolute URL in the body (e.g. a password-reset link) is a
		// weaker, harder-to-attribute sink than a redirect whose destination we can
		// see — report it for review rather than as a confirmed redirect poisoning.
		finding = fmt.Sprintf("Injected host %q reflected as a URL authority in the response body", injectedHost)
		confidence = severity.Tentative
	}

	if finding == "" {
		return nil
	}

	// Strict drop-on-fail: confirm the X-Forwarded-Host value genuinely flows into
	// the output in authority position (a real input→output reflection), not a
	// one-shot echo, a coincidental static string, or a query-parameter echo. A
	// fresh random host must reflect as a URL authority every round. An incomplete
	// confirmation cannot establish attacker control, so it is dropped.
	if confirmed, err := m.confirmForwardedHostReflection(ctx, httpClient); err != nil || !confirmed {
		return nil
	}

	return &output.ResultEvent{
		ModuleID:           ModuleID,
		RecordKind:         output.RecordKindCandidate,
		EvidenceGrade:      output.EvidenceGradeDifferential,
		URL:                targetURL,
		Request:            string(modifiedRaw),
		Response:           resp.FullResponseString(),
		AdditionalEvidence: baselineEvidence,
		ExtractedResults: []string{
			"Header: X-Forwarded-Host: " + injectedHost,
			"Finding: " + finding,
		},
		Info: output.Info{
			Name:        "Proxy Header Trust Candidate: X-Forwarded-Host URL Generation",
			Description: "Fresh X-Forwarded-Host values reproducibly control a generated URL authority. This proves exposed header trust, but password-reset poisoning, cache poisoning, or another security-sensitive consumer was not demonstrated.",
			Severity:    severity.High,
			Confidence:  confidence,
			Tags:        []string{"proxy", "forwarded-headers", "ip-spoofing", "host-injection"},
			Reference:   []string{"https://owasp.org/www-project-web-security-testing-guide/"},
		},
		Metadata: map[string]any{
			"header":                   "X-Forwarded-Host",
			"authority_sink":           map[bool]string{true: "location", false: "body"}[locAuthority],
			"confirmation_rounds":      2,
			"sensitive_flow_confirmed": false,
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
	modifiedRaw, ok := rootGetRaw(ctx, "X-Forwarded-Proto", "https")
	if !ok {
		return nil
	}

	// BuildRequest/SetMethod/... produce well-formed raw, so wrap directly instead
	// of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil || infra.GetBlockDetectionValidator().Validate(resp) != nil {
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

	// Strict drop-on-fail: a single baseline-vs-probe status flip is unreliable
	// (transient flap, load-balancer routing). Confirm the split is reproducible
	// AND attributable to the "https" VALUE specifically — a benign X-Forwarded-
	// Proto value must behave like the no-header baseline, not like the probe.
	// The negative-control collector records the benign "http" round so the
	// finding carries the value-attribution side of the comparison, not just the
	// no-header baseline.
	negControlEv := modkit.NewEvidenceCollector()
	if !m.confirmForwardedProtoChange(ctx, httpClient, baselineStatus, probeStatus, negControlEv) {
		return nil
	}

	// Copy baselineEvidence into a fresh slice before appending: it is shared
	// across all three findings, so appending in place could clobber a sibling.
	evidence := append(append([]string{}, baselineEvidence...), negControlEv.Entries()...)

	return &output.ResultEvent{
		ModuleID:           ModuleID,
		RecordKind:         output.RecordKindCandidate,
		EvidenceGrade:      output.EvidenceGradeDifferential,
		URL:                targetURL,
		Request:            string(modifiedRaw),
		Response:           resp.FullResponseString(),
		AdditionalEvidence: evidence,
		ExtractedResults: []string{
			"Header: X-Forwarded-Proto: https",
			"Finding: " + finding,
		},
		Info: output.Info{
			Name:        "Proxy Header Trust Candidate: X-Forwarded-Proto Behavior",
			Description: "X-Forwarded-Proto: https reproducibly causes a value-specific response change. This proves exposed protocol-header trust, but no HTTPS downgrade, insecure cookie issuance, or protected-route bypass was demonstrated.",
			Severity:    severity.Medium,
			Confidence:  ModuleConfidence,
			Tags:        []string{"proxy", "forwarded-headers", "ip-spoofing", "host-injection"},
			Reference:   []string{"https://owasp.org/www-project-web-security-testing-guide/"},
		},
		Metadata: map[string]any{
			"header":                    "X-Forwarded-Proto",
			"confirmation_rounds":       2,
			"security_impact_confirmed": false,
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
	modifiedRaw, ok := rootGetRaw(ctx, "X-Forwarded-For", injectedIP)
	if !ok {
		return nil
	}

	// BuildRequest/SetMethod/... produce well-formed raw, so wrap directly instead
	// of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil || infra.GetBlockDetectionValidator().Validate(resp) != nil {
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
	if isAccessDenied(baselineStatus) && probeStatus >= 200 && probeStatus < 300 {
		confirmationEvidence, semanticAccess, confirmed := m.confirmForwardedForBypass(ctx, httpClient)
		if !confirmed {
			return nil
		}
		kind := output.RecordKindCandidate
		name := "Proxy Header Trust Candidate: X-Forwarded-For Access Change"
		description := "X-Forwarded-For: 127.0.0.1 reproducibly changes a denied response to 2xx while an unrelated IP remains denied. The status bypass is value-specific, but protected content was not independently established."
		if semanticAccess {
			kind = output.RecordKindFinding
			name = "Proxy Header Trust: X-Forwarded-For IP Bypass"
			description = "X-Forwarded-For: 127.0.0.1 reproducibly bypasses an IP-based denial, while an unrelated IP remains denied, and returns stable content semantically distinct from both denial responses."
		}
		evidence := append(append([]string{}, baselineEvidence...), confirmationEvidence...)
		return &output.ResultEvent{
			ModuleID:           ModuleID,
			RecordKind:         kind,
			EvidenceGrade:      output.EvidenceGradeBypass,
			URL:                targetURL,
			Request:            string(modifiedRaw),
			Response:           resp.FullResponseString(),
			AdditionalEvidence: evidence,
			ExtractedResults: []string{
				"Header: X-Forwarded-For: " + injectedIP,
				"Finding: " + fmt.Sprintf("X-Forwarded-For IP spoofing bypassed access control (status %d → %d)", baselineStatus, probeStatus),
			},
			Info: output.Info{
				Name:        name,
				Description: description,
				Severity:    severity.High,
				Confidence:  ModuleConfidence,
				Tags:        []string{"proxy", "forwarded-headers", "ip-spoofing", "host-injection"},
				Reference:   []string{"https://owasp.org/www-project-web-security-testing-guide/"},
			},
			Metadata: map[string]any{
				"header":                    "X-Forwarded-For",
				"trusted_value":             injectedIP,
				"negative_control_value":    controlIP,
				"confirmation_rounds":       2,
				"semantic_access_confirmed": semanticAccess,
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
		if shift, confirmationEvidence, ok := m.confirmForwardedForSizeShift(ctx, httpClient, len(baselineBody), len(probeBody)); ok {
			evidence := append(append([]string{}, baselineEvidence...), confirmationEvidence...)
			return &output.ResultEvent{
				ModuleID:           ModuleID,
				RecordKind:         output.RecordKindCandidate,
				EvidenceGrade:      output.EvidenceGradeDifferential,
				URL:                targetURL,
				Request:            string(modifiedRaw),
				Response:           resp.FullResponseString(),
				AdditionalEvidence: evidence,
				ExtractedResults: []string{
					"Header: X-Forwarded-For: " + injectedIP,
					"Finding: " + shift,
				},
				Info: output.Info{
					Name:        "Proxy Header Trust Candidate: X-Forwarded-For Content Variation",
					Description: "Response content reproducibly varies with the spoofed X-Forwarded-For source IP, beyond the page's natural per-request variance. The application appears to gate content on the client-supplied source address, which may expose IP-restricted content or behavior to a spoofed caller. Verify what differs before treating it as an access-control bypass.",
					Severity:    severity.Medium,
					Confidence:  severity.Tentative,
					Tags:        []string{"proxy", "forwarded-headers", "ip-spoofing", "host-injection"},
					Reference:   []string{"https://owasp.org/www-project-web-security-testing-guide/"},
				},
				Metadata: map[string]any{
					"header":                    "X-Forwarded-For",
					"trusted_value":             injectedIP,
					"semantic_access_confirmed": false,
				},
			}
		}
	}

	return nil
}

// confirmForwardedHostReflection confirms the X-Forwarded-Host value genuinely
// flows into the response AS A URL AUTHORITY (the host component of the Location
// redirect or a generated link), by sending a fresh random host each round and
// requiring it to reflect in authority position every time. A page that merely
// contains a fixed string, echoes the header only once, or echoes it inside
// another URL's query parameter (the OAuth redirect_uri= case) will not satisfy
// the authority check across the changing canary. Returns ConfirmReflection's
// (confirmed, err); callers require a complete confirmation.
func (m *Module) confirmForwardedHostReflection(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester) (bool, error) {
	return modkit.ConfirmReflection(2, func(canary string) (bool, error) {
		host := "vgo" + canary + ".example"
		raw, ok := rootGetRaw(ctx, "X-Forwarded-Host", host)
		if !ok {
			return false, fmt.Errorf("build X-Forwarded-Host confirmation request")
		}
		// BuildRequest/SetMethod/... produce well-formed raw, so wrap directly instead
		// of re-parsing on this hot path.
		req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
		// NoRedirects mirrors the primary probe: confirm the canary reflects into the
		// immediate Location/body, not a followed destination. NoClustering keeps each
		// fresh-canary round on the wire.
		resp, _, err := httpClient.Execute(req, http.Options{NoClustering: true, NoRedirects: true})
		if err != nil {
			return false, err
		}
		defer resp.Close()
		if resp.Response() == nil || infra.GetBlockDetectionValidator().Validate(resp) != nil {
			return false, nil
		}
		loc := resp.Response().Header.Get("Location")
		return modkit.HostReflectedAsAuthority(loc, host) || modkit.HostReflectedAsAuthority(resp.Body().String(), host), nil
	})
}

// confirmForwardedProtoChange confirms an X-Forwarded-Proto status change is
// reproducible AND attributable to the "https" value rather than mere header
// presence or transient flapping. Across two rounds the no-header baseline must
// keep returning baselineStatus and the "https" probe must keep returning
// probeStatus; then a benign value ("http") must NOT reproduce the changed
// status. Incomplete controls fail closed. The benign-value round is
// captured into negControl (nil-safe) so the finding can show that the change is
// specific to "https", not just any X-Forwarded-Proto value.
func (m *Module) confirmForwardedProtoChange(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	baselineStatus, probeStatus int,
	negControl *modkit.EvidenceCollector,
) bool {
	for range 2 {
		_, bs, ok := m.headerFetch(ctx, httpClient, "X-Forwarded-Proto", "")
		if !ok {
			return false
		}
		if bs != baselineStatus {
			return false // baseline not stable → change not attributable
		}
		_, ps, ok := m.headerFetch(ctx, httpClient, "X-Forwarded-Proto", "https")
		if !ok {
			return false
		}
		if ps != probeStatus {
			return false // probe not reproducible
		}
	}
	// Negative control: a benign proto value must behave like the no-header
	// baseline. If "http" differs from the baseline, the effect may be from
	// header presence/instability, not the "https" value. Capture the pair as
	// evidence regardless of the outcome — it documents the attribution check.
	control, ok := m.captureFetch(ctx, httpClient, "X-Forwarded-Proto", "http")
	if !ok {
		return false
	}
	negControl.Add("negative control: X-Forwarded-Proto: http (benign value)", control.rawRequest, control.fullResponse)
	if control.status != baselineStatus {
		return false
	}
	return true
}

// captureFetch issues a GET / optionally carrying one header, bypasses cached
// clustering and redirects, and retains the request/response/body needed by
// confirmation controls. Known edge challenge responses fail closed.
func (m *Module) captureFetch(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, name, value string) (headerCapture, bool) {
	raw, ok := rootGetRaw(ctx, name, value)
	if !ok {
		return headerCapture{}, false
	}
	// BuildRequest/SetMethod/... produce well-formed raw, so wrap directly instead
	// of re-parsing on this hot path.
	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
	resp, _, err := httpClient.Execute(req, http.Options{NoClustering: true, NoRedirects: true})
	if err != nil {
		return headerCapture{}, false
	}
	defer resp.Close()
	if resp.Response() == nil || infra.GetBlockDetectionValidator().Validate(resp) != nil {
		return headerCapture{}, false
	}
	return headerCapture{
		rawRequest:   string(raw),
		fullResponse: resp.FullResponseString(),
		body:         resp.BodyString(),
		status:       resp.Response().StatusCode,
	}, true
}

// rootGetRaw builds a GET / request from ctx, optionally carrying one header
// (name=="" or value=="" sends no extra header). It is the shared request
// construction behind headerFetch and captureFetch; ok is false on any build
// error.
func rootGetRaw(ctx *httpmsg.HttpRequestResponse, name, value string) ([]byte, bool) {
	raw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil, false
	}
	raw, err = httpmsg.SetPath(raw, "/")
	if err != nil {
		return nil, false
	}
	// Captured traffic may already contain forwarding headers added by a proxy.
	// Remove the entire family first so each probe differs from its control by
	// exactly one attacker-supplied value.
	for _, header := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-IP"} {
		raw, err = httpmsg.RemoveHeader(raw, header)
		if err != nil {
			return nil, false
		}
	}
	if name != "" && value != "" {
		raw, err = httpmsg.AddOrReplaceHeader(raw, name, value)
		if err != nil {
			return nil, false
		}
	}
	return raw, true
}

// confirmForwardedForSizeShift decides whether the spoofed X-Forwarded-For header
// is responsible for a response-size change, rather than ordinary per-request
// jitter. It fetches a fresh no-header control (to learn the page's natural
// variance) and re-sends the spoofed-IP probe (to require reproducibility), then
// reports a hit only when BOTH probe responses land on the same side of, and
// clearly outside, the no-header size band by more than a meaningful margin.
// Returns the human description, the fresh control/replay evidence, and true on
// a confirmed shift; an unverifiable change is never reported.
func (m *Module) confirmForwardedForSizeShift(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	baselineLen, probeLen int,
) (string, []string, bool) {
	control, ok := m.captureFetch(ctx, httpClient, "", "")
	if !ok || isAccessDenied(control.status) {
		return "", nil, false
	}
	probe2, ok := m.captureFetch(ctx, httpClient, "X-Forwarded-For", injectedIP)
	if !ok || isAccessDenied(probe2.status) {
		return "", nil, false
	}
	controlLen, probe2Len := len(control.body), len(probe2.body)

	// Attribute the shift to the header only when both spoofed-IP samples land on
	// the same side of, and clear of, the no-header band by more than its variance.
	if _, ok := modkit.SizeShiftGap(baselineLen, controlLen, probeLen, probe2Len); !ok {
		return "", nil, false
	}

	noHdrMin, noHdrMax := min(baselineLen, controlLen), max(baselineLen, controlLen)
	probeMin, probeMax := min(probeLen, probe2Len), max(probeLen, probe2Len)
	shift := fmt.Sprintf(
		"X-Forwarded-For reproducibly shifted response size outside natural variance (no-header %d–%d bytes, spoofed-IP %d–%d bytes)",
		noHdrMin, noHdrMax, probeMin, probeMax,
	)
	evidence := []string{
		output.BuildEvidence("fresh no-header variance control", control.rawRequest, control.fullResponse),
		output.BuildEvidence("spoofed-IP size replay", probe2.rawRequest, probe2.fullResponse),
	}
	return shift, evidence, true
}

// confirmForwardedForBypass verifies an apparent blocked→allowed transition is
// genuinely caused by trusting the spoofed X-Forwarded-For header, not transient
// rate-limit/maintenance flapping. A 429/503 (or even 401/403) captured on the
// single baseline fetch can simply clear by the time the probe is sent — e.g. the
// scan hammered the host into a 429 that recovered a moment later — which then
// reads as "spoofing bypassed access control" though the header did nothing.
//
// It re-runs the pair interleaved, with the spoofed header as the ONLY variable,
// then sends an unrelated documentation-range IP as a value-specific negative
// control. semanticAccess is true only when the allowed responses are stable,
// non-empty, and distinct from both denial bodies; status-only evidence remains
// a candidate instead of a confirmed vulnerability.
func (m *Module) confirmForwardedForBypass(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) (evidence []string, semanticAccess, confirmed bool) {
	const rounds = 2
	var allowedBody string
	hasAllowedBody := false
	var denialBodies []string
	for range rounds {
		control, ok := m.captureFetch(ctx, httpClient, "", "")
		if !ok || !isAccessDenied(control.status) {
			return nil, false, false
		}
		probe, ok := m.captureFetch(ctx, httpClient, "X-Forwarded-For", injectedIP)
		if !ok || probe.status < 200 || probe.status >= 300 {
			return nil, false, false
		}
		evidence = append(evidence,
			output.BuildEvidence("no-header denial control", control.rawRequest, control.fullResponse),
			output.BuildEvidence("trusted-IP replay", probe.rawRequest, probe.fullResponse),
		)
		denialBodies = append(denialBodies, control.body)
		if !hasAllowedBody {
			allowedBody = probe.body
			hasAllowedBody = true
		} else if !modkit.BodiesSimilar(allowedBody, probe.body) {
			return nil, false, false
		}
	}

	negative, ok := m.captureFetch(ctx, httpClient, "X-Forwarded-For", controlIP)
	if !ok || !isAccessDenied(negative.status) {
		return nil, false, false
	}
	evidence = append(evidence, output.BuildEvidence("untrusted-IP negative control", negative.rawRequest, negative.fullResponse))

	semanticAccess = strings.TrimSpace(allowedBody) != "" && !modkit.BodiesSimilar(allowedBody, negative.body)
	for _, deniedBody := range denialBodies {
		if modkit.BodiesSimilar(allowedBody, deniedBody) {
			semanticAccess = false
			break
		}
	}
	return evidence, semanticAccess, true
}

// headerFetch issues a GET / optionally carrying a single request header
// (name=="" or value=="" sends no extra header), bypassing the response cache so
// it truly hits the wire, and returns the response body length and status code.
// ok is false only on a build/transport error or a nil response — an
// access-denied status is a valid observation the caller judges.
//
// NoClustering: the requester replays a cached response for an identical request
// (500ms TTL). A replayed baseline/probe would collapse the measured natural
// variance to zero and make a transient block look reproducible — defeating the
// confirmation gates. These fetches must really hit the wire.
func (m *Module) headerFetch(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, name, value string) (bodyLen, status int, ok bool) {
	capture, ok := m.captureFetch(ctx, httpClient, name, value)
	if !ok {
		return 0, 0, false
	}
	return len(capture.body), capture.status, true
}
