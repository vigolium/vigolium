package express_trust_proxy_misconfig

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

const (
	injectedHost = "vgn-trust-test.example"
	injectedIP   = "127.0.0.1"
	injectedPort = "1337"
)

// isAccessDenied returns true for status codes that indicate the request was
// rejected by an auth/WAF/rate-limit layer rather than served by the app.
func isAccessDenied(status int) bool {
	return status == 401 || status == 403 || status == 429 || status == 503
}

// trustProxyProbe defines a trust proxy misconfiguration test case.
type trustProxyProbe struct {
	headerName string
	value      string
	desc       string
}

var probes = []trustProxyProbe{
	{
		headerName: "X-Forwarded-Proto",
		value:      "http",
		desc:       "X-Forwarded-Proto protocol confusion — may cause redirect to HTTPS or strip cookie Secure flag",
	},
	{
		headerName: "X-Forwarded-Host",
		value:      injectedHost,
		desc:       "X-Forwarded-Host trusted for URL generation — injected host appears in response",
	},
	{
		headerName: "X-Forwarded-For",
		value:      injectedIP,
		desc:       "X-Forwarded-For IP spoofing — may bypass IP-based access controls or rate limiting",
	},
	{
		headerName: "X-Forwarded-Port",
		value:      injectedPort,
		desc:       "X-Forwarded-Port injection — injected port appears in generated URLs or redirects",
	},
}

// Module implements the Express Trust Proxy Misconfiguration active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Express Trust Proxy Misconfiguration module.
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
		ds: dedup.LazyDiskSet("express_trust_proxy_misconfig"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest tests the request for Express trust proxy misconfiguration.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	hash := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(hash) {
		return nil, nil
	}

	// Send baseline request to capture normal behavior.
	baselineReq, err := httpmsg.ParseRawRequest(string(ctx.Request().Raw()))
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
	baselineHeaders := baselineResp.Headers().String()

	// Retain the no-header baseline request/response so each finding can carry the
	// differential it was judged against (the spoofed-header probe is the attack
	// pair; this is what it's compared to). Capture before Close frees the buffer.
	baselineReqStr := string(ctx.Request().Raw())
	baselineRespStr := baselineResp.FullResponseString()

	baselineResp.Close()

	var results []*output.ResultEvent

	for _, probe := range probes {
		modifiedRaw, err := httpmsg.AddOrReplaceHeader(ctx.Request().Raw(), probe.headerName, probe.value)
		if err != nil {
			continue
		}

		fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
		if err != nil {
			continue
		}
		fuzzedReq = fuzzedReq.WithService(ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			continue
		}

		probeBody := resp.Body().String()
		probeHeaders := resp.Headers().String()
		probeStatus := 0
		probeLocation := ""
		if resp.Response() != nil {
			probeStatus = resp.Response().StatusCode
			probeLocation = resp.Response().Header.Get("Location")
		}

		var finding string

		switch probe.headerName {
		case "X-Forwarded-Proto":
			finding = checkProtocolConfusion(
				baselineStatus, probeStatus,
				baselineHeaders, probeHeaders,
				baselineLocation, probeLocation,
			)

		case "X-Forwarded-Host":
			finding = checkHostInjection(probeBody, probeHeaders, probeLocation)

		case "X-Forwarded-For":
			finding = m.checkIPBypass(ctx, httpClient, modifiedRaw, baselineStatus, probeStatus, baselineBody, probeBody)

		case "X-Forwarded-Port":
			finding = checkPortInjection(probeBody, probeLocation)
		}

		if finding != "" {
			// Every positive must be re-confirmed against the original request: a
			// genuine trust-proxy effect tracks the value/behaviour our header
			// introduces and is ABSENT from the no-header baseline, whereas a
			// coincidental static string — or per-request volatile content (an edge
			// affinity cookie issued only on first contact, a rotating redirect) that
			// merely happened to differ in one sample — does not. Host/Port re-prove
			// the reflection; Proto re-proves the behavioural diff reproduces on fresh
			// interleaved samples; For self-confirms (confirmIPBypass/confirmSizeShift).
			confidence := severity.ConfidenceUndefined // → module default (Firm)
			switch probe.headerName {
			case "X-Forwarded-Host":
				if !m.confirmHostReflection(ctx, httpClient) {
					resp.Close()
					continue
				}
			case "X-Forwarded-Port":
				if !m.confirmPortReflection(ctx, httpClient, baselineRespStr) {
					resp.Close()
					continue
				}
			case "X-Forwarded-Proto":
				if !m.confirmProtoEffect(ctx, httpClient) {
					resp.Close()
					continue
				}
				// A proto-downgrade effect is a behavioural baseline diff (cookie-flag
				// or redirect change), the weakest signal class in this module and the
				// most exposed to edge/CDN volatility, so it ships as Tentative even
				// after reproduction.
				confidence = severity.Tentative
			}

			extracted := []string{
				fmt.Sprintf("Header: %s: %s", probe.headerName, probe.value),
				fmt.Sprintf("Finding: %s", finding),
			}

			ev := modkit.NewEvidenceCollector()
			ev.Add("baseline", baselineReqStr, baselineRespStr)

			results = append(results, &output.ResultEvent{
				URL:                urlx.String(),
				Request:            string(modifiedRaw),
				Response:           resp.FullResponseString(),
				AdditionalEvidence: ev.Entries(),
				ExtractedResults:   extracted,
				Info: output.Info{
					Name:        fmt.Sprintf("Express Trust Proxy Misconfiguration: %s", probe.headerName),
					Description: probe.desc,
					Severity:    severity.Medium,
					Confidence:  confidence,
				},
			})
			resp.Close()
			return results, nil
		}
		resp.Close()
	}

	return results, nil
}

// checkProtocolConfusion detects if X-Forwarded-Proto: http causes a
// security-relevant behavioural change versus the no-header baseline: it either
// introduces a NEW plaintext-HTTP redirect the baseline didn't have, or strips
// the Secure attribute off a cookie the app STILL re-issues. Both effects are
// header-attributable changes, not mere differences between two responses.
func checkProtocolConfusion(
	baselineStatus, probeStatus int,
	baselineHeaders, probeHeaders string,
	baselineLocation, probeLocation string,
) string {
	// New redirect the baseline didn't have. Only meaningful when the probe
	// INTRODUCES a redirect (baseline didn't redirect) AND the new target is an
	// explicit plaintext http:// URL — i.e. the app honoured X-Forwarded-Proto:
	// http and downgraded the scheme. A 3xx→3xx pair where both sides already
	// redirect (e.g. an access-proxy/SSO login redirect) is NOT proto-attributable,
	// and an https:// redirect is the app forcing TLS — neither is a vulnerability.
	isBaselineRedirect := baselineStatus >= 300 && baselineStatus < 400
	isProbeRedirect := probeStatus >= 300 && probeStatus < 400
	if !isBaselineRedirect && isProbeRedirect {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(probeLocation)), "http://") {
			return fmt.Sprintf("Proto downgrade introduced plaintext-HTTP redirect (status %d, Location: %s)", probeStatus, probeLocation)
		}
		return ""
	}

	// Genuine Secure-flag strip: the SAME cookie is re-issued WITHOUT Secure. A
	// cookie that simply vanishes from the probe response (a volatile edge/affinity
	// cookie set only on first contact, or any per-request Set-Cookie that wasn't
	// re-emitted) is NOT a downgrade and must not be reported — that disappearance
	// is exactly the X-Forwarded-Proto false positive this guard exists to kill.
	if name := secureCookieStripped(baselineHeaders, probeHeaders); name != "" {
		return fmt.Sprintf("Proto downgrade stripped Secure flag from re-issued Set-Cookie %q", name)
	}

	return ""
}

// secureCookieStripped reports the name of a cookie that carried the Secure
// attribute in the no-header baseline AND is re-issued by the proto-downgrade
// probe WITHOUT it. It returns "" when no such cookie exists — in particular when
// a baseline Secure cookie is absent from the probe entirely (not re-issued), the
// classic volatile-edge-cookie case, since a missing Set-Cookie is no evidence
// the Secure flag was stripped.
func secureCookieStripped(baselineHeaders, probeHeaders string) string {
	baseline := setCookieSecurity(baselineHeaders)
	probe := setCookieSecurity(probeHeaders)
	for name, hadSecure := range baseline {
		if !hadSecure {
			continue
		}
		if reSecure, reissued := probe[name]; reissued && !reSecure {
			return name
		}
	}
	return ""
}

// setCookieSecurity parses the Set-Cookie lines out of a raw response header
// block, returning a map of cookie name → whether that Set-Cookie carries the
// Secure attribute as a distinct directive. Bare substring matching of "Secure"
// is deliberately avoided: it would match a cookie value, a CSP token, or another
// header and falsely read as a Secure flag.
func setCookieSecurity(headers string) map[string]bool {
	const prefix = "set-cookie:"
	out := map[string]bool{}
	for _, line := range strings.Split(headers, "\n") {
		line = strings.TrimRight(line, "\r")
		if len(line) < len(prefix) || !strings.EqualFold(line[:len(prefix)], prefix) {
			continue
		}
		val := strings.TrimSpace(line[len(prefix):])
		// Cookie name = text before the first ';' and the first '='.
		nameAndValue := val
		if i := strings.IndexByte(nameAndValue, ';'); i >= 0 {
			nameAndValue = nameAndValue[:i]
		}
		name := nameAndValue
		if i := strings.IndexByte(name, '='); i >= 0 {
			name = name[:i]
		}
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		out[name] = cookieHasSecure(val)
	}
	return out
}

// cookieHasSecure reports whether a single Set-Cookie value carries the Secure
// attribute as its own ';'-delimited directive (case-insensitive), not as a
// substring of the cookie value or another attribute.
func cookieHasSecure(setCookieValue string) bool {
	for _, part := range strings.Split(setCookieValue, ";") {
		if strings.EqualFold(strings.TrimSpace(part), "Secure") {
			return true
		}
	}
	return false
}

// confirmProtoEffect re-confirms an X-Forwarded-Proto behavioural diff is
// reproducible and header-attributable rather than an artifact of volatile
// per-request content (an edge cookie issued only on first contact, a rotating
// redirect). It re-fetches a FRESH no-header control and a fresh proto-downgrade
// probe, interleaved, and requires checkProtocolConfusion to fire on the same
// effect every round. Drops on any miss or fetch error so an unverifiable diff is
// never reported.
func (m *Module) confirmProtoEffect(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester) bool {
	raw, err := httpmsg.AddOrReplaceHeader(ctx.Request().Raw(), "X-Forwarded-Proto", "http")
	if err != nil {
		return false
	}
	const rounds = 2
	for range rounds {
		ctrlHeaders, ctrlStatus, ctrlLoc, ok := fetchHeadStatusLoc(ctx, httpClient, ctx.Request().Raw())
		if !ok {
			return false
		}
		probeHeaders, probeStatus, probeLoc, ok := fetchHeadStatusLoc(ctx, httpClient, raw)
		if !ok {
			return false
		}
		if checkProtocolConfusion(ctrlStatus, probeStatus, ctrlHeaders, probeHeaders, ctrlLoc, probeLoc) == "" {
			return false
		}
	}
	return true
}

// fetchHeadStatusLoc re-issues raw with the response cache bypassed (NoClustering)
// so each confirmation sample is a genuinely fresh render, returning the raw
// header block, status code, and Location header. ok is false on a build/parse/
// transport error or nil response.
func fetchHeadStatusLoc(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, raw []byte) (headers string, status int, location string, ok bool) {
	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return "", 0, "", false
	}
	req = req.WithService(ctx.Service())
	resp, _, err := httpClient.Execute(req, http.Options{NoClustering: true})
	if err != nil {
		return "", 0, "", false
	}
	defer resp.Close()
	if resp.Response() == nil {
		return "", 0, "", false
	}
	return resp.Headers().String(), resp.Response().StatusCode, resp.Response().Header.Get("Location"), true
}

// confirmHostReflection re-sends X-Forwarded-Host with a FRESH random host each
// round and requires it to reflect (in the status line, headers, or body) every
// time. A real trust-proxy reflection tracks the header value we send; a static
// string that merely matched the fixed probe host, or per-request volatile
// content, does not — and a fresh canary is by construction absent from the
// no-header baseline. Fails OPEN on a fetch error so a transient failure never
// suppresses a real finding.
func (m *Module) confirmHostReflection(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester) bool {
	confirmed, err := modkit.ConfirmReflection(2, func(canary string) (bool, error) {
		host := canary + ".vgn-trust.example"
		raw, herr := httpmsg.AddOrReplaceHeader(ctx.Request().Raw(), "X-Forwarded-Host", host)
		if herr != nil {
			return false, herr
		}
		full, ok := doFetchFull(ctx, httpClient, raw)
		if !ok {
			return false, fmt.Errorf("x-forwarded-host confirmation fetch failed")
		}
		return strings.Contains(full, host), nil
	})
	if err != nil {
		return true // fail open — never suppress on a probe failure
	}
	return confirmed
}

// confirmPortReflection re-confirms an X-Forwarded-Port reflection against the
// original request: the injected port must be ABSENT from the no-header baseline
// (so its appearance is attributable to the header, not pre-existing content)
// AND must reproducibly reflect when the header is re-sent. Fails OPEN on a
// fetch error.
func (m *Module) confirmPortReflection(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, baselineResp string) bool {
	portPattern := ":" + injectedPort
	// If the port already appears in the clean baseline, the reflection is not
	// introduced by our header — it is pre-existing (or volatile) content.
	if strings.Contains(baselineResp, portPattern) {
		return false
	}
	raw, err := httpmsg.AddOrReplaceHeader(ctx.Request().Raw(), "X-Forwarded-Port", injectedPort)
	if err != nil {
		return true // fail open
	}
	full, ok := doFetchFull(ctx, httpClient, raw)
	if !ok {
		return true // fail open
	}
	return strings.Contains(full, portPattern)
}

// doFetchFull re-issues raw with the response cache bypassed (NoClustering) and
// returns the full raw response string (status line + headers + body) so a
// reflected value is visible wherever it lands. ok is false on a build/parse/
// transport error or a nil response.
func doFetchFull(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, raw []byte) (string, bool) {
	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return "", false
	}
	req = req.WithService(ctx.Service())
	resp, _, err := httpClient.Execute(req, http.Options{NoClustering: true})
	if err != nil {
		return "", false
	}
	defer resp.Close()
	if resp.Response() == nil {
		return "", false
	}
	return resp.FullResponseString(), true
}

// checkHostInjection detects if X-Forwarded-Host value appears in response
// body or Location header, indicating trusted host generation.
func checkHostInjection(
	probeBody, probeHeaders string,
	probeLocation string,
) string {
	if strings.Contains(probeBody, injectedHost) {
		return fmt.Sprintf("Injected host %q reflected in response body", injectedHost)
	}

	if strings.Contains(probeLocation, injectedHost) {
		return fmt.Sprintf("Injected host %q reflected in Location header: %s", injectedHost, probeLocation)
	}

	if strings.Contains(probeHeaders, injectedHost) {
		return fmt.Sprintf("Injected host %q reflected in response headers", injectedHost)
	}

	return ""
}

// checkIPBypass detects if X-Forwarded-For: 127.0.0.1 causes a different
// response status or significantly different content, indicating IP-based
// access control bypass. Both signals are confirmed before reporting: a single
// baseline status is unreliable (a transient 429/503 that simply cleared by the
// probe reads as a bypass), and a one-shot body-length delta is dominated by the
// page's natural per-request jitter (rotating tokens, ads, view counts).
func (m *Module) checkIPBypass(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	modifiedRaw []byte,
	baselineStatus, probeStatus int,
	baselineBody, probeBody string,
) string {
	// A real bypass goes blocked→allowed (the spoofed IP was trusted). The reverse
	// (200→429/403/503) is the WAF rejecting the spoofed header — not trust. Confirm
	// the split is reproducible and header-attributable before asserting it.
	if isAccessDenied(baselineStatus) && probeStatus >= 200 && probeStatus < 300 {
		if m.confirmIPBypass(ctx, httpClient, modifiedRaw) {
			return fmt.Sprintf("IP spoofing bypassed access control (status %d → %d)", baselineStatus, probeStatus)
		}
		return ""
	}

	// Significant body length difference suggests different content served — but
	// only when it reproducibly exceeds the page's natural jitter. Skip when either
	// side is a WAF/denied page (that size is noise, not the app's content).
	if !isAccessDenied(baselineStatus) && !isAccessDenied(probeStatus) && len(baselineBody) > 0 {
		if shift, ok := m.confirmSizeShift(ctx, httpClient, modifiedRaw, len(baselineBody), len(probeBody)); ok {
			return shift
		}
	}

	return ""
}

// confirmIPBypass verifies an apparent blocked→allowed transition is genuinely
// caused by trusting the spoofed X-Forwarded-For header, not transient
// rate-limit/maintenance flapping. It re-runs the pair interleaved, with the
// spoofed header as the only variable: each round the unmodified control must
// STILL be denied and the spoofed-IP probe must STILL be allowed. Drops on any
// miss or fetch error so an unverifiable transition is never reported.
func (m *Module) confirmIPBypass(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, modifiedRaw []byte) bool {
	const rounds = 2
	for range rounds {
		if _, status, ok := doFetch(ctx, httpClient, ctx.Request().Raw()); !ok || !isAccessDenied(status) {
			return false // not denied WITHOUT the header → the block isn't header-attributable
		}
		if _, status, ok := doFetch(ctx, httpClient, modifiedRaw); !ok || status < 200 || status >= 300 {
			return false // not allowed WITH the header → not a reproducible bypass
		}
	}
	return true
}

// confirmSizeShift decides whether the spoofed X-Forwarded-For header is
// responsible for a response-size change, rather than ordinary per-request
// jitter. It fetches a fresh unmodified control (natural variance) and re-sends
// the spoofed-IP probe (reproducibility), then reports a hit only when BOTH probe
// responses land on the same side of, and clearly outside, the no-header size
// band by more than a meaningful margin.
func (m *Module) confirmSizeShift(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	modifiedRaw []byte,
	baselineLen, probeLen int,
) (string, bool) {
	controlLen, ok := fetchBodyLen(ctx, httpClient, ctx.Request().Raw())
	if !ok {
		return "", false
	}
	probe2Len, ok := fetchBodyLen(ctx, httpClient, modifiedRaw)
	if !ok {
		return "", false
	}

	// Attribute the shift to the header only when both spoofed-IP samples land on
	// the same side of, and clear of, the no-header band by more than its variance.
	if _, ok := modkit.SizeShiftGap(baselineLen, controlLen, probeLen, probe2Len); !ok {
		return "", false
	}

	noHdrMin, noHdrMax := min(baselineLen, controlLen), max(baselineLen, controlLen)
	probeMin, probeMax := min(probeLen, probe2Len), max(probeLen, probe2Len)
	return fmt.Sprintf(
		"IP spoofing reproducibly shifted response size outside natural variance (no-header %d–%d bytes, spoofed-IP %d–%d bytes)",
		noHdrMin, noHdrMax, probeMin, probeMax,
	), true
}

// fetchBodyLen returns the body length of a clean (non-denied) fresh sample of
// raw; ok is false on transport error, nil response, or a WAF/denied status.
func fetchBodyLen(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, raw []byte) (int, bool) {
	bodyLen, status, ok := doFetch(ctx, httpClient, raw)
	if !ok || isAccessDenied(status) {
		return 0, false
	}
	return bodyLen, true
}

// doFetch re-issues raw with the response cache bypassed (NoClustering) so each
// confirmation sample is a genuinely fresh render, and returns the body length
// and status. ok is false only on a build/parse/transport error or nil response.
func doFetch(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, raw []byte) (bodyLen, status int, ok bool) {
	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return 0, 0, false
	}
	req = req.WithService(ctx.Service())
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

// checkPortInjection detects if X-Forwarded-Port value appears in generated
// URLs within the response body or in redirect Location headers.
func checkPortInjection(
	probeBody string,
	probeLocation string,
) string {
	portPattern := ":" + injectedPort

	if strings.Contains(probeLocation, portPattern) {
		return fmt.Sprintf("Injected port %s reflected in Location header: %s", injectedPort, probeLocation)
	}

	if strings.Contains(probeBody, portPattern) {
		return fmt.Sprintf("Injected port %s reflected in response body URLs", injectedPort)
	}

	return ""
}
