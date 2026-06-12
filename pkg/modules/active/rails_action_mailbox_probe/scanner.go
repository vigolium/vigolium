package rails_action_mailbox_probe

import (
	"crypto/sha256"
	"fmt"
	"math"
	"strings"

	httputil "github.com/projectdiscovery/utils/http"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

type notFoundFingerprint struct {
	bodyHash string
	bodyLen  int
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
		ds: dedup.LazyDiskSet("rails_action_mailbox_probe"),
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

	host := service.Host()
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	// Detect blanket OPTIONS handlers before probing.
	// If a completely unrelated path returns 200 + Allow with POST,
	// the server responds to OPTIONS uniformly on all paths —
	// OPTIONS-based evidence is meaningless on this host.
	if m.detectBlanketOptions(ctx, httpClient) {
		return nil, nil
	}

	fp := m.fingerprint404(ctx, httpClient)

	var results []*output.ResultEvent
	for _, p := range probes {
		if result := m.probeEndpoint(ctx, httpClient, p, fp); result != nil {
			results = append(results, result)
		}
	}

	return results, nil
}

// detectBlanketOptions sends OPTIONS to a random non-Rails path.
// If the server returns 200/204 with an Allow header containing POST — or a
// generic CORS preflight (Access-Control-Allow-* with no Allow header) — it has
// a catch-all OPTIONS responder (e.g. Apache mod_headers, a reverse proxy, an
// API gateway like AWS API Gateway, or middleware) and OPTIONS probing will
// produce false positives on every path.
func (m *Module) detectBlanketOptions(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) bool {
	randomPath := "/vigolium-not-rails-" + utils.RandomString(12)

	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "OPTIONS")
	if err != nil {
		return false
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, randomPath)
	if err != nil {
		return false
	}

	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return false
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return false
	}
	defer resp.Close()

	if resp.Response() == nil {
		return false
	}

	if resp.Response().StatusCode == 200 || resp.Response().StatusCode == 204 {
		allow := resp.Response().Header.Get("Allow")
		if allow != "" && strings.Contains(strings.ToUpper(allow), "POST") {
			return true
		}
		// CORS-preflight blanket responder: API gateways (AWS API Gateway,
		// nginx, Cloudflare) answer OPTIONS on every path with 204/200 +
		// Access-Control-Allow-* and no Allow header. A guaranteed-nonexistent
		// path getting this proves the host has a catch-all OPTIONS responder,
		// so OPTIONS evidence is meaningless on every path.
		if isCORSPreflightResponse(resp) {
			return true
		}
	}

	return false
}

func (m *Module) fingerprint404(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester) *notFoundFingerprint {
	randomPath := "/rails/action_mailbox/vigolium-404-" + utils.RandomString(8)

	modifiedRaw, _ := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	modifiedRaw, _ = httpmsg.SetPath(modifiedRaw, randomPath)

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
	method := p.method
	if method == "" {
		method = "OPTIONS"
	}

	modifiedRaw, _ := httpmsg.SetMethod(ctx.Request().Raw(), method)
	modifiedRaw, _ = httpmsg.SetPath(modifiedRaw, p.path)

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

	status := resp.Response().StatusCode

	// Reject responses that never reached the Rails route: 404s, server
	// errors, and — critically — throttled or WAF/CDN-blocked replies (429,
	// vendor challenge pages). Their bodies are rate-limit/error pages that
	// frequently echo the requested path; since every probe path embeds
	// "action_mailbox"/"inbound_emails", a reflected path would otherwise
	// trip the body markers below and forge a finding (e.g. a 429 from the
	// edge reflecting "/rails/conductor/action_mailbox/inbound_emails").
	if status == 404 || status >= 500 || isBlockedOrThrottled(resp) {
		return nil
	}

	body := resp.Body().String()

	// Check 404 fingerprint
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

	urlx, _ := ctx.URL()
	targetURL := urlx.Scheme + "://" + urlx.Host + p.path

	// Strip any echo of the request target before scanning for page content.
	// Throttle/error/404 pages routinely reflect the requested URL, and every
	// probe path contains "action_mailbox"/"inbound_emails" — so a reflected
	// path must not be mistaken for a rendered Action Mailbox page.
	scanBody := stripEcho(body, p.path, targetURL)

	var evidence []string

	switch method {
	case "GET":
		// Conductor UI: confirm on the actual rendered page content, never on
		// status or headers alone. The page must be a real 200 and the body
		// must contain a genuine Action Mailbox conductor marker — a bare 2xx,
		// a redirect-to-login, or a generic 200 page yields no finding.
		if status != 200 {
			return nil
		}
		for _, marker := range p.bodyMarkers {
			if strings.Contains(scanBody, marker) {
				evidence = append(evidence, "Body: "+marker)
			}
		}
		if len(evidence) == 0 {
			return nil
		}
	default:
		// A genuine Rails route answering OPTIONS returns a 2xx: the Journey
		// router emits a 200/204 carrying the Allow header for a path it has
		// mounted (the module's positive case is a 200). A 405 Method Not
		// Allowed is the *opposite* signal — a front-end server (commonly nginx)
		// rejecting the OPTIONS method, whose `Allow` header advertises the
		// methods *it* permits for a static/proxied location, not a mounted Rails
		// route. nginx's stock "405 Not Allowed" page carries exactly
		// `Allow: GET, POST`, which satisfies the Allow+POST check below — this
		// is the recurring production false positive this guard kills.
		if status < 200 || status >= 300 {
			return nil
		}
		// Reject stock front-end server status/error pages (nginx, Apache,
		// Tomcat). A real ingress OPTIONS reply carries no rendered HTML; an HTML
		// page whose title/heading is an HTTP status line ("405 Not Allowed",
		// "502 Bad Gateway", …) was produced by the web server or proxy in front
		// of the app, so the request never reached a Rails route.
		if looksLikeServerStatusPage(scanBody) {
			return nil
		}
		// Ingress endpoints are POST-only API routes with no rendered body.
		// A generic CORS preflight (Access-Control-Allow-* with no Allow header)
		// is the API-gateway/proxy reply to OPTIONS on *any* path — it proves a
		// CORS responder exists, not that the Rails route is mounted. This is
		// the production false positive this guard targets.
		if isCORSPreflightResponse(resp) {
			return nil
		}
		// A genuine Rails route answering OPTIONS advertises POST via the
		// standard Allow header. That route signal — not a bare status — is the
		// confirmation for these body-less endpoints.
		allowHeader := resp.Response().Header.Get("Allow")
		if allowHeader == "" || !strings.Contains(strings.ToUpper(allowHeader), "POST") {
			return nil
		}
		// Action Mailbox ingress routes are strictly POST-only; Rails advertises
		// exactly that on OPTIONS and never lists GET. An Allow header that also
		// lists GET is a front-end web-server signal for a static/proxied
		// location (e.g. nginx's `GET, POST`), not a mounted Rails ingress route.
		if strings.Contains(strings.ToUpper(allowHeader), "GET") {
			return nil
		}
		evidence = append(evidence, "Allow: "+allowHeader)
		// Surface any Action Mailbox reference that genuinely appears in the
		// body as corroborating evidence (does not gate the finding).
		for _, marker := range []string{"ActionMailbox", "Action Mailbox"} {
			if strings.Contains(scanBody, marker) {
				evidence = append(evidence, "Body: "+marker+" reference")
				break
			}
		}
	}

	return &output.ResultEvent{
		URL:              targetURL,
		Matched:          targetURL,
		Request:          string(modifiedRaw),
		Response:         resp.FullResponseString(),
		ExtractedResults: evidence,
		Info: output.Info{
			Name:        fmt.Sprintf("Rails %s", p.name),
			Description: p.desc,
			Severity:    p.sev,
			Confidence:  severity.Firm,
			Tags:        []string{"rails", "ruby", "action-mailbox", "email-ingress"},
			Reference:   []string{"https://guides.rubyonrails.org/action_mailbox_basics.html"},
		},
	}
}

// isBlockedOrThrottled reports whether a probe response came from a rate
// limiter, WAF/CDN edge, or server error rather than the Rails application.
// Such responses never exercised the Action Mailbox route, so their bodies —
// often error pages that reflect the requested path — cannot confirm exposure.
func isBlockedOrThrottled(resp *httputil.ResponseChain) bool {
	if resp == nil || resp.Response() == nil {
		return false
	}
	// Vendor-aware detector (Cloudflare, Akamai, CloudFront, Incapsula, AWS
	// ELB) plus the generic 429 rate-limit case.
	if infra.GetBlockDetectionValidator().Validate(resp) != nil {
		return true
	}
	switch resp.Response().StatusCode {
	case 408, // request timeout
		425, // too early
		429, // too many requests
		451: // unavailable for legal reasons (edge block)
		return true
	}
	return false
}

// isCORSPreflightResponse reports whether resp is a generic CORS preflight
// reply rather than a real Rails route. API gateways and reverse proxies (AWS
// API Gateway, Cloudflare, nginx) answer OPTIONS for every path with an empty
// 204/200 carrying Access-Control-Allow-* headers and no standard Allow header.
// A real Rails route answering OPTIONS sets the Allow header (which the caller
// treats as positive evidence), so the presence of Allow rules out a preflight.
func isCORSPreflightResponse(resp *httputil.ResponseChain) bool {
	if resp == nil || resp.Response() == nil {
		return false
	}
	h := resp.Response().Header
	if h.Get("Access-Control-Allow-Origin") == "" && h.Get("Access-Control-Allow-Methods") == "" {
		return false
	}
	return h.Get("Allow") == ""
}

// looksLikeServerStatusPage reports whether body is a stock front-end server
// status/error page (nginx, Apache, Tomcat) rather than a Rails response. A
// genuine Action Mailbox ingress OPTIONS reply carries no rendered HTML; an HTML
// page whose title/heading is an HTTP status line ("405 Not Allowed",
// "404 Not Found", "502 Bad Gateway", …) was emitted by the web server or proxy
// in front of the app, so the request never reached a Rails route. This catches
// the recurring production false positive: nginx answering OPTIONS with its
// stock "405 Not Allowed" page plus an `Allow: GET, POST` header.
func looksLikeServerStatusPage(body string) bool {
	b := strings.ToLower(body)
	for _, marker := range []string{
		"<title>403", "<title>404", "<title>405", "<title>406",
		"<title>500", "<title>502", "<title>503", "<title>504",
		"not allowed",         // nginx 405 title/heading
		"bad gateway",         // nginx/proxy 502
		"gateway time-out",    // nginx 504
		"service unavailable", // nginx/proxy 503
		"<center>nginx",       // nginx error-page footer (server token present)
		"<hr><center>",        // nginx error-page footer structure (token stripped)
		"<address>apache",     // apache error-page footer
	} {
		if strings.Contains(b, marker) {
			return true
		}
	}
	return false
}

// stripEcho removes occurrences of the requested path and full URL from the
// body. Reflected request targets are common on WAF, rate-limit, and 404
// pages; because every probe path contains "action_mailbox" and
// "inbound_emails", an echoed target would masquerade as genuine page content.
func stripEcho(body, path, fullURL string) string {
	out := body
	for _, echo := range []string{fullURL, path} {
		if echo != "" {
			out = strings.ReplaceAll(out, echo, "")
		}
	}
	return out
}
