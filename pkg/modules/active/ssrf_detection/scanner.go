package ssrf_detection

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	httputil "github.com/projectdiscovery/utils/http"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// ssrfPayload defines a single SSRF test case.
type ssrfPayload struct {
	payload string
	markers []string // strings to look for in response body
	desc    string
}

var payloads = []ssrfPayload{
	{
		payload: "http://127.0.0.1",
		markers: []string{"<html", "<!DOCTYPE", "root:", "localhost"},
		desc:    "Localhost access via 127.0.0.1",
	},
	{
		payload: "http://[::1]",
		markers: []string{"<html", "<!DOCTYPE", "root:", "localhost"},
		desc:    "Localhost access via IPv6 loopback",
	},
	{
		payload: "http://169.254.169.254/latest/meta-data/",
		markers: []string{"ami-id", "instance-id", "local-hostname", "public-hostname"},
		desc:    "AWS EC2 metadata endpoint access",
	},
	{
		payload: "http://metadata.google.internal/computeMetadata/v1/",
		markers: []string{"attributes/", "project-id", "instance/"},
		desc:    "GCP metadata endpoint access",
	},
	{
		payload: "http://169.254.169.254/metadata/instance",
		markers: []string{"compute", "vmId", "vmSize"},
		desc:    "Azure metadata endpoint access",
	},
	// Encoding bypass payloads for localhost
	{
		payload: "http://0177.0.0.1",
		markers: []string{"<html", "<!DOCTYPE", "root:", "localhost"},
		desc:    "Localhost access via octal IP encoding",
	},
	{
		payload: "http://2130706433",
		markers: []string{"<html", "<!DOCTYPE", "root:", "localhost"},
		desc:    "Localhost access via decimal IP encoding",
	},
	{
		payload: "http://0x7f000001",
		markers: []string{"<html", "<!DOCTYPE", "root:", "localhost"},
		desc:    "Localhost access via hexadecimal IP encoding",
	},
	{
		payload: "http://[::ffff:127.0.0.1]",
		markers: []string{"<html", "<!DOCTYPE", "root:", "localhost"},
		desc:    "Localhost access via IPv6-mapped IPv4 address",
	},
	{
		payload: "http://127.1",
		markers: []string{"<html", "<!DOCTYPE", "root:", "localhost"},
		desc:    "Localhost access via shortened IP notation",
	},
	{
		payload: "file:///etc/passwd",
		markers: []string{"root:", "/bin/bash", "/bin/sh"},
		desc:    "Local file read via file:// protocol",
	},
	{
		payload: "http://169.254.169.254/metadata/v1/",
		markers: []string{"droplet_id", "hostname", "region"},
		desc:    "DigitalOcean metadata endpoint access",
	},
	{
		payload: "http://127.0.0.1:6379",
		markers: []string{"REDIS", "-ERR", "+PONG"},
		desc:    "Redis internal service probing",
	},
	{
		payload: "http://127.0.0.1:27017",
		markers: []string{"MongoDB", "ismaster", "It looks like you are"},
		desc:    "MongoDB internal service probing",
	},
}

// Module implements the SSRF detection active scanner.
type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new SSRF Detection module.
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
			modkit.ScanScopeInsertionPoint,
			modkit.AllParamTypes,
		),
		rhm: dedup.LazyDefaultRHM("ssrf_detection"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerInsertionPoint tests a single insertion point for SSRF.
func (m *Module) ScanPerInsertionPoint(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	// Check if we should scan this insertion point
	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		paramName := ip.Name()
		paramType := fmt.Sprintf("%d", ip.Type())
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), paramName, ip.BaseValue(), paramType) {
			return nil, nil
		}
	}

	// Only test parameters that look like they might accept URLs
	baseVal := ip.BaseValue()
	if !looksLikeURLParam(ip.Name(), baseVal) {
		return nil, nil
	}

	var results []*output.ResultEvent

	// Get original response body for comparison
	var origBody string
	if ctx.Response() != nil {
		origBody = ctx.Response().BodyToString()
	}

	for _, p := range payloads {
		fuzzedRaw := ip.BuildRequest([]byte(p.payload))

		fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
		if err != nil {
			continue
		}
		fuzzedReq = fuzzedReq.WithService(ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		// A WAF/CDN/rate-limit page (e.g. a 429 "Too Many Requests" HTML error) is
		// not the target proxying our injected URL — yet its generic HTML body trips
		// the deliberately-broad localhost markers (`<html`, `<!DOCTYPE`, …). The
		// motivating false positive: a scan hammered a host into a 429 whose HTML
		// error page carried `<html`, absent from the (redirect) baseline, and was
		// reported as IPv6-loopback SSRF. Never read such a response as SSRF signal.
		if isBlockedResponse(resp) {
			resp.Close()
			continue
		}

		body := resp.Body().String()
		all := matchedSSRFMarkers(body, origBody, p.markers)
		if len(all) == 0 {
			resp.Close()
			continue
		}
		// The strongest matched marker drives gating and reporting: a self-evidencing
		// token (`root:`, `droplet_id`, …) outranks a generic field-word or page shape.
		primary := strongestMarker(all)

		// The generic page-shape markers (`<html`, `<!DOCTYPE`, `localhost`) only
		// assert "this is an HTML page" — the app's OWN error, redirect, or login
		// pages trip them just as readily as a fetched localhost resource does. They
		// are credible SSRF evidence ONLY on a 2xx response: the single state in which
		// the server returning HTML for a localhost payload means it actually fetched
		// and proxied that content. A 3xx redirect, 4xx rejection, or 5xx error
		// returning HTML is the app answering us, not SSRF (the original Cloudflare
		// Access "Invalid redirect URL" false positive).
		if isGenericMarker(primary) && !isSuccessStatus(resp) {
			resp.Close()
			continue
		}

		// Grade the evidence for the structured payloads (cloud metadata, file://,
		// internal services). A genuinely proxied internal endpoint answers with
		// plain text or JSON on a 2xx, so a field token appearing inside an HTML
		// document, on a non-2xx response, or a common field-WORD (hostname, region,
		// compute) with no distinctive marker beside it, is at most a Suspect lead —
		// not a firm High finding. The motivating false positive: the DigitalOcean
		// payload's "hostname" marker matched `window.location.hostname` inside a Ping
		// SSO error page's <script> on a 400 "Invalid redirect_uri" response. The
		// localhost family (whose genuine response IS html) keeps the High default.
		//
		// Confidence ceiling: this module confirms entirely IN-BAND (it never has an
		// out-of-band oracle), and an in-band marker — however well controlled — can
		// only ever be Tentative. A firm SSRF requires an OAST callback proving the
		// server actually reached the attacker-named host; that proof lives in the
		// OAST-driven modules (ssrf-blind, routing-ssrf, …), which report Certain.
		// So the strongest this module emits is High/Tentative; gradeStructuredEvidence
		// likewise tops out at Tentative.
		sev, conf := severity.High, severity.Tentative
		suspectReason := ""
		if !htmlPagePayload(p) {
			sev, conf, suspectReason = gradeStructuredEvidence(primary, all, resp)
		}

		fullResp := resp.FullResponseString()
		resp.Close()

		// The markers are deliberately broad, so even a graded hit is confirmed
		// reproducible and absent from a fresh control fetch of the original value
		// before reporting.
		ev := modkit.NewEvidenceCollector()
		if !m.confirmSSRFMarker(ctx, ip, httpClient, fuzzedRaw, primary, ev) {
			continue
		}

		desc := fmt.Sprintf("SSRF: %s — marker %q found in response", p.desc, primary)
		if sev == severity.Suspect {
			desc = fmt.Sprintf("Possible SSRF (unconfirmed): %s — marker %q in response, but %s; manual verification required", p.desc, primary, suspectReason)
		}
		results = append(results, &output.ResultEvent{
			URL:                urlx.String(),
			Request:            string(fuzzedRaw),
			Response:           fullResp,
			FuzzingParameter:   ip.Name(),
			ExtractedResults:   append([]string{p.payload}, all...),
			AdditionalEvidence: ev.Entries(),
			Info: output.Info{
				Severity:    sev,
				Confidence:  conf,
				Description: desc,
			},
		})
		return results, nil
	}

	return results, nil
}

// confirmSSRFMarker verifies a matched marker is genuinely introduced by the
// payload rather than ambient or random. It requires the marker to (1) reappear
// when the payload request is re-sent (reproducible — not per-request noise) and
// (2) be ABSENT from a fresh fetch of the ORIGINAL value (the control — so a
// marker the live page always carries, regardless of the payload, is rejected
// even when the captured baseline happened to miss it). It drops the finding when
// any re-fetch returns a WAF/rate-limit page: such a page is noise, not a
// reproduced SSRF response, and can't serve as a clean control.
//
// For a GENERIC page-shape marker it adds two further checks beyond mere token
// presence (the substring match a bare `<!DOCTYPE` would rely on): a benign
// dead-host (TEST-NET 192.0.2.1) probe must NOT carry the same token, AND the
// payload body must differ SUBSTANTIALLY from that dead-host body. The latter
// (the differential) is the load-bearing one: it proves the server's response
// genuinely changed with the target instead of returning a fixed page for every
// absolute URL — which is what a generic substring match alone can never show.
//
// Fail-open vs fail-closed turns on marker strength. A self-evidencing marker
// (`root:`, `ami-id`, `+PONG`, …) is itself strong evidence, so a transient
// transport error on a control must not suppress that true positive — it fails
// OPEN. A GENERIC page-shape marker (`<html`, `<!DOCTYPE`, `localhost`) carries no
// specificity of its own: the entire case for SSRF rests on the negative controls
// proving the page differs for an internal vs. a benign URL. If those controls
// cannot be established (transport error, or a WAF/block page), there is no
// evidence left, so a generic marker fails CLOSED. This is the fix for the
// /Error.aspx false positive: a flaky host errored on both control fetches, they
// failed open under the old logic, and a static `<!DOCTYPE` error page that merely
// reproduced once was reported as IPv6-loopback SSRF.
func (m *Module) confirmSSRFMarker(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	payloadRaw []byte,
	marker string,
	ev *modkit.EvidenceCollector,
) bool {
	markerLower := strings.ToLower(marker)
	generic := isGenericMarker(marker)

	// (1) Reproducible under the payload, on a genuine (non-blocked) response.
	body, blocked, ok := m.fetchBody(ctx, httpClient, payloadRaw, ev, "confirm round 1")
	if !ok {
		// A generic marker has nothing going for it but the controls below; if we
		// can't even reproduce the payload, drop it. A specific marker fails open.
		return !generic
	}
	if blocked {
		return false
	}
	if !strings.Contains(strings.ToLower(body), markerLower) {
		return false
	}

	// (1b) For generic HTML markers only: discriminate "the server fetched
	// localhost" from "the app handles every absolute URL identically". Re-probe
	// with a benign, non-internal absolute URL (RFC 5737 TEST-NET — not localhost,
	// metadata, or any internal target). If the SAME generic marker appears for
	// that too, the app emits this HTML for ANY absolute URL it is handed (a
	// validation/error/redirect page), not because it reached localhost — so it is
	// not SSRF. This is what separates a real loopback proxy from the Cloudflare
	// "Invalid redirect URL" class of page, which rejects 127.0.0.1 and 192.0.2.1
	// the same way. Specific markers (`root:`, `ami-id`, …) are self-evidencing and
	// skip this control. This control is MANDATORY for a generic marker: if it
	// cannot be run (transport error) or returns a block page, the generic hit is
	// unconfirmed and must be dropped — failing open here is what let the flaky
	// /Error.aspx host through.
	if generic {
		siblingRaw := ip.BuildRequest([]byte(benignSiblingURL))
		siblingBody, siblingBlocked, ok := m.fetchBody(ctx, httpClient, siblingRaw, ev, "non-internal control")
		if !ok || siblingBlocked {
			return false
		}
		if strings.Contains(strings.ToLower(siblingBody), markerLower) {
			return false
		}
		// Differential gate — the validation that goes beyond "is the token present".
		// A genuine loopback fetch returns DIFFERENT content for an internal target
		// than for a dead external host: 127.0.0.1 serves a real page, 192.0.2.1
		// times out. So the payload body must differ SUBSTANTIALLY from the dead-host
		// body. If the two are the same page (BodiesSimilar — token-similarity ≥0.95,
		// tolerant of per-request noise), the server returns a fixed response for any
		// absolute URL — its own status/error/SPA template that merely echoes the
		// host word — and the generic marker is that template, not a fetched resource.
		// This catches the FP the token-absence check above cannot: the dead-host page
		// lacks the one matched token (e.g. it says "192.0.2.1" where the probe says
		// "localhost") yet is otherwise byte-for-byte the same canned page.
		if modkit.BodiesSimilar(body, siblingBody) {
			return false
		}
	}

	// (2) Absent from a fresh, non-blocked control fetch of the original value.
	controlRaw := ip.BuildRequest([]byte(ip.BaseValue()))
	controlBody, controlBlocked, ok := m.fetchBody(ctx, httpClient, controlRaw, ev, "control")
	if !ok {
		// Fail open for a self-evidencing marker (a transient error must not bury a
		// true positive); fail closed for a generic marker, which depends on this
		// control to prove the marker is not part of the app's own baseline page.
		return !generic
	}
	if controlBlocked {
		return false
	}
	return !strings.Contains(strings.ToLower(controlBody), markerLower)
}

// fetchBody re-issues a raw request and returns its response body and whether the
// response was a WAF/CDN/rate-limit page. ok is false on any parse/HTTP error.
// When ev is non-nil, the full request/response pair is captured under label
// before the response is closed.
func (m *Module) fetchBody(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, raw []byte, ev *modkit.EvidenceCollector, label string) (body string, blocked, ok bool) {
	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return "", false, false
	}
	req = req.WithService(ctx.Service())
	resp, _, err := httpClient.Execute(req, http.Options{})
	if err != nil {
		return "", false, false
	}
	defer resp.Close()
	// Capture before Close: FullResponseString() reads pooled buffers Close() returns.
	ev.Add(label, string(raw), resp.FullResponseString())
	return resp.Body().String(), isBlockedResponse(resp), true
}

// isBlockedResponse reports whether resp is a WAF/CDN challenge, auth gate, rate
// limiter, or maintenance page rather than genuine application traffic. Such
// pages carry generic HTML that trips the deliberately-broad SSRF markers
// (`<html`, `<!DOCTYPE`, `localhost`), so they must never be read as evidence of
// SSRF. It combines the vendor-aware block detector (Cloudflare, Akamai,
// Incapsula, …) with a plain status gate that also catches generic WAFs the
// detector does not recognize.
func isBlockedResponse(resp *httputil.ResponseChain) bool {
	return infra.IsBlockedResponse(resp)
}

// looksLikeURLParam checks if a parameter name or value suggests URL input.
func looksLikeURLParam(name, value string) bool {
	nameLower := strings.ToLower(name)
	urlParamNames := []string{"url", "uri", "link", "src", "href", "dest", "redirect", "path", "file", "page", "target", "callback", "endpoint", "resource", "fetch", "load", "proxy", "request"}
	for _, n := range urlParamNames {
		if strings.Contains(nameLower, n) {
			return true
		}
	}
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") || strings.HasPrefix(value, "//") {
		return true
	}
	return false
}

// benignSiblingURL is a structurally-identical absolute URL (RFC 5737 TEST-NET-1
// documentation address) used as a negative control for the generic HTML
// markers. It is NOT localhost, a metadata endpoint, or any internal target, so
// a server that genuinely proxies localhost would not return localhost content
// for it — yet an app that simply rejects every absolute URL (an open-redirect
// validator, a login gate) answers it with the same generic error page it gives
// 127.0.0.1. A generic marker that reproduces here is therefore the app's own
// page, not SSRF.
const benignSiblingURL = "http://192.0.2.1"

// genericMarkers are the deliberately-broad "this is an HTML page" tokens. They
// match any HTML body — the application's own error, redirect, login, or
// maintenance pages included — so on their own they cannot tell a fetched
// localhost page apart from the app rejecting our payload. They demand extra
// corroboration (a 2xx status and a localhost-specific differential) before they
// count as SSRF; the specific markers (`root:`, `ami-id`, `REDIS`, …) are
// self-evidencing and need neither.
var genericMarkers = map[string]bool{
	"<html":     true,
	"<!doctype": true,
	"localhost": true,
}

// isGenericMarker reports whether marker is one of the weak, page-shape markers
// that require the extra status/differential confirmation above.
func isGenericMarker(marker string) bool {
	return genericMarkers[strings.ToLower(marker)]
}

// isSuccessStatus reports whether resp carries a 2xx status — the only class in
// which a server returning HTML for a localhost payload means it fetched and
// proxied that content. A 3xx redirect, 4xx rejection (e.g. 400 "Invalid
// redirect URL"), or 5xx error returning HTML is the app's own page, not SSRF.
func isSuccessStatus(resp *httputil.ResponseChain) bool {
	if resp == nil || resp.Response() == nil {
		return false
	}
	sc := resp.Response().StatusCode
	return sc >= 200 && sc < 300
}

// matchedSSRFMarkers returns every marker present in the probe body but absent
// from the original baseline body (case-insensitive), preserving the declared
// marker order so the most distinctive token can be selected afterwards.
func matchedSSRFMarkers(body, origBody string, markers []string) []string {
	bodyLower := strings.ToLower(body)
	origLower := strings.ToLower(origBody)
	var out []string
	for _, marker := range markers {
		m := strings.ToLower(marker)
		if strings.Contains(bodyLower, m) && !strings.Contains(origLower, m) {
			out = append(out, marker)
		}
	}
	return out
}

// checkSSRFMarkers returns the first marker present in the probe body but absent
// from the baseline, or "" when none match.
func checkSSRFMarkers(body, origBody string, markers []string) string {
	if m := matchedSSRFMarkers(body, origBody, markers); len(m) > 0 {
		return m[0]
	}
	return ""
}

// weakMarkers are metadata FIELD-NAME tokens that are also ordinary English words
// (or appear in routine JavaScript), so they trip on HTML and script content that
// has nothing to do with a proxied internal fetch. The motivating false positive:
// the DigitalOcean payload's "hostname" marker matched `window.location.hostname`
// in a Ping SSO error page. On their own they are weak — a Suspect lead at best —
// and only count toward a firm finding when a self-evidencing marker (droplet_id,
// vmId, …) corroborates them.
var weakMarkers = map[string]bool{
	"hostname": true,
	"region":   true,
	"compute":  true,
}

// isWeakMarker reports whether marker is a common-word metadata field token.
func isWeakMarker(marker string) bool {
	return weakMarkers[strings.ToLower(marker)]
}

// isStrongMarker reports whether marker is self-evidencing: neither a generic
// page-shape token nor a common-word field name, so its mere presence is strong
// evidence the target returned internal content (`root:`, `ami-id`, `droplet_id`,
// `+PONG`, …).
func isStrongMarker(marker string) bool {
	return !isGenericMarker(marker) && !isWeakMarker(marker)
}

// hasStrongMarker reports whether any matched marker is self-evidencing.
func hasStrongMarker(matched []string) bool {
	for _, m := range matched {
		if isStrongMarker(m) {
			return true
		}
	}
	return false
}

// strongestMarker returns the most distinctive matched marker — a self-evidencing
// one if present, else a common-word field token, else the first match — so gating
// and reporting key off the strongest available signal rather than declaration order.
func strongestMarker(matched []string) string {
	for _, m := range matched {
		if isStrongMarker(m) {
			return m
		}
	}
	for _, m := range matched {
		if isWeakMarker(m) {
			return m
		}
	}
	if len(matched) > 0 {
		return matched[0]
	}
	return ""
}

// htmlPagePayload reports whether p probes an internal WEB PAGE (the loopback /
// localhost family, whose markers include `<html`) rather than a structured
// endpoint. For those the genuine proxied response is itself HTML, so the
// content-type discipline in gradeStructuredEvidence does not apply.
func htmlPagePayload(p ssrfPayload) bool {
	for _, m := range p.markers {
		if strings.EqualFold(m, "<html") {
			return true
		}
	}
	return false
}

// isHTMLResponse reports whether resp carries an HTML content-type. Genuine cloud
// metadata, file://, and internal-service responses are plain text or JSON, so a
// metadata marker found in an HTML body is page markup or script, not proxied
// content.
func isHTMLResponse(resp *httputil.ResponseChain) bool {
	if resp == nil || resp.Response() == nil {
		return false
	}
	ct := strings.ToLower(resp.Response().Header.Get("Content-Type"))
	return strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml")
}

// gradeStructuredEvidence weighs how firmly a matched marker proves a structured
// internal endpoint (metadata/file/service) was actually proxied, returning the
// severity/confidence to report plus a human-readable reason when the evidence is
// only Suspect-grade. A genuinely proxied fetch returns internal data (plain text
// or JSON) on a 2xx; anything short of that — a rejection/redirect/error status,
// a marker buried in an HTML document, or a lone common-word field token with no
// distinctive marker beside it — is downgraded to a Suspect lead for manual review
// rather than reported as a likely vulnerability. The strongest grade it returns
// is High/Tentative: this is an in-band oracle and never reaches Firm — only an
// OAST callback warrants that (see the OAST-driven SSRF modules).
func gradeStructuredEvidence(primary string, matched []string, resp *httputil.ResponseChain) (severity.Severity, severity.Confidence, string) {
	if !isSuccessStatus(resp) {
		status := 0
		if resp != nil && resp.Response() != nil {
			status = resp.Response().StatusCode
		}
		return severity.Suspect, severity.Tentative, fmt.Sprintf("the target answered %d rather than a 2xx — it rejected the URL instead of fetching it", status)
	}
	if isHTMLResponse(resp) {
		return severity.Suspect, severity.Tentative, "the marker appears inside an HTML document, whereas a genuine metadata/internal response is plain text or JSON"
	}
	if isWeakMarker(primary) && !hasStrongMarker(matched) {
		return severity.Suspect, severity.Tentative, "only a generic field-name token matched, with no distinctive marker to corroborate it"
	}
	return severity.High, severity.Tentative, ""
}
