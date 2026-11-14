package rails_active_storage_probe

import (
	"crypto/sha256"
	"fmt"
	"math"
	"sort"
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

// Module implements the Rails Active Storage Probe active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Rails Active Storage Probe module.
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
		ds: dedup.LazyDiskSet("rails_active_storage_probe"),
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

// ScanPerRequest probes the host for exposed Active Storage and Action Mailbox endpoints.
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

	if !modkit.BeginHostProbeFor(scanCtx, httpClient, &m.ds, ctx) {
		return nil, nil
	}

	// Detect blanket OPTIONS handlers before probing. If a guaranteed-nonexistent
	// path answers OPTIONS with 200/204 + Allow:POST (or a generic CORS preflight),
	// the host responds to OPTIONS uniformly on every path and OPTIONS-based
	// evidence is meaningless here.
	if m.detectBlanketOptions(ctx, httpClient) {
		return nil, nil
	}

	fp := m.fingerprint404(ctx, httpClient)

	var results []*output.ResultEvent
	for _, p := range probes {
		if result := m.probeEndpoint(ctx, httpClient, p, fp, scanCtx, host); result != nil {
			results = append(results, result)
		}
	}

	return results, nil
}

// detectBlanketOptions sends OPTIONS to a random non-Rails path. A host whose
// reverse proxy / API gateway / CORS middleware answers OPTIONS uniformly (Allow
// with POST, or an Access-Control-Allow-* preflight) would yield a finding on
// every probe path, so OPTIONS evidence is discarded for the whole host.
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

	// BuildRequest/SetMethod/... produce well-formed raw, so wrap directly instead
	// of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

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
		if isCORSPreflightResponse(resp) {
			return true
		}
	}

	return false
}

func (m *Module) fingerprint404(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) *notFoundFingerprint {
	randomPath := "/vigolium-rails-storage-404-" + utils.RandomString(8)

	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, randomPath)
	if err != nil {
		return nil
	}

	// BuildRequest/SetMethod/... produce well-formed raw, so wrap directly instead
	// of re-parsing on this hot path.
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
	scanCtx *modkit.ScanContext,
	host string,
) *output.ResultEvent {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), p.method)
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, p.path)
	if err != nil {
		return nil
	}

	// BuildRequest/SetMethod/... produce well-formed raw, so wrap directly instead
	// of re-parsing on this hot path.
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
	// Reject responses that never reached — or were rejected by — the Rails route:
	//   404            route absent
	//   405            method not allowed; OPTIONS isn't handled here. This is the
	//                  production false-positive status: an nginx "405 Not Allowed"
	//                  page literally contains "Allow" inside "Not Allowed".
	//   401/403        generic auth / WAF gates
	//   5xx            upstream / CDN errors (incl. Cloudflare 520-526)
	//   blocked        rate-limit / vendor challenge pages (429/408/425/451, …)
	// None of these confirm the endpoint exists.
	if status == 404 || status == 405 || status == 401 || status == 403 ||
		status >= 500 || infra.IsBlockedOrThrottled(resp) {
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

	urlx, _ := ctx.URL()
	targetURL := urlx.Scheme + "://" + urlx.Host + p.path

	// Strip any echo of the request target before scanning the body for markers.
	// Error / 404 / throttle pages routinely reflect the requested URL, and every
	// probe path contains "active_storage"/"action_mailbox" — a reflected target
	// must not be mistaken for genuine framework content.
	scanBody := stripEcho(body, p.path, targetURL)

	for _, anti := range p.antiMarkers {
		if strings.Contains(scanBody, anti) {
			return nil
		}
	}

	var evidence []string

	switch p.method {
	case "OPTIONS":
		// Direct-upload and mail-ingress endpoints are POST-only API routes with
		// no rendered body. A generic CORS preflight (Access-Control-Allow-* with
		// no Allow header) is the API-gateway / proxy reply to OPTIONS on *any*
		// path — it proves a CORS responder exists, not that the Rails route is
		// mounted.
		if isCORSPreflightResponse(resp) {
			return nil
		}
		// Only a 2xx OPTIONS advertising POST via the standard Allow *header*
		// confirms a live Rails route. We never match "POST"/"Allow" as body
		// substrings: that is the exact bug that flagged nginx "405 Not Allowed"
		// pages (which contain "Allow" inside "Not Allowed").
		if status != 200 && status != 204 {
			return nil
		}
		allowHeader := resp.Response().Header.Get("Allow")
		// A genuine Active Storage / Action Mailbox route is POST-only: its Allow
		// set is a subset of {POST, OPTIONS}. A generic web-server / front-controller
		// catch-all answers OPTIONS on *every* path with a broad
		// "OPTIONS, TRACE, GET, HEAD, POST" Allow and a blank body — the production
		// false positive on vn.einvoice.initech.com. Reject any Allow set that also
		// advertises read/other methods (GET/HEAD/TRACE/PUT/...): that is a server
		// default, not a mounted Rails route.
		if !allowAdvertisesIngress(allowHeader) {
			return nil
		}
		// Baseline against a random, guaranteed-nonexistent sibling under the same
		// parent path. A real route answers only at its own path; if a random
		// sibling returns the same status *and* the same Allow set, this prefix has
		// a catch-all OPTIONS handler and the probe path is not a live Rails route
		// — i.e. the same response with or without the real path.
		if m.siblingOptionsMatches(ctx, httpClient, p.path, status, allowHeader) {
			return nil
		}
		// An OPTIONS Allow header is not, by itself, proof of a mounted Rails
		// route — any proxy / middleware can answer OPTIONS with `Allow: POST` on
		// a blank body. Require positive evidence the host actually runs Rails (a
		// Ruby app-server Server header, a Rails session cookie, X-Runtime, or
		// rendered framework markers) before reporting. Generic gateways carry
		// none of these — that is the production false-positive class.
		railsSignals := railsHostSignals(ctx, resp, scanCtx, host, scanBody)
		if len(railsSignals) == 0 {
			return nil
		}
		evidence = append(evidence, "Allow: "+allowHeader)
		evidence = append(evidence, railsSignals...)
	case "GET":
		// Blob routes: confirm on a real redirect to a stored object (the genuine
		// Active Storage behavior) or on actual framework body content — never on a
		// bare 200, which SPA/landing pages return for every path.
		if status == 301 || status == 302 {
			loc := resp.Response().Header.Get("Location")
			if loc != "" && !strings.Contains(loc, p.path) {
				evidence = append(evidence, "Redirect: "+loc)
			}
		}
		for _, marker := range p.markers {
			if strings.Contains(scanBody, marker) {
				evidence = append(evidence, "Body: "+marker)
			}
		}
		if len(evidence) == 0 {
			return nil
		}
	default:
		return nil
	}

	return &output.ResultEvent{
		URL:              targetURL,
		Matched:          targetURL,
		Request:          string(modifiedRaw),
		Response:         resp.FullResponseString(),
		ExtractedResults: evidence,
		Info: output.Info{
			Name:        fmt.Sprintf("Rails Endpoint Exposed: %s", p.name),
			Description: p.desc,
			Severity:    p.sev,
			Confidence:  severity.Tentative,
			Tags:        []string{"rails", "ruby", "active-storage", "action-mailbox"},
			Reference:   []string{"https://guides.rubyonrails.org/active_storage_overview.html", "https://guides.rubyonrails.org/action_mailbox_basics.html"},
		},
	}
}

// isCORSPreflightResponse reports whether resp is a generic CORS preflight reply
// rather than a real Rails route. API gateways and reverse proxies (AWS API
// Gateway, Cloudflare, nginx) answer OPTIONS for every path with an empty 204/200
// carrying Access-Control-Allow-* headers and no standard Allow header. A real
// Rails route answering OPTIONS sets the Allow header, so its presence rules out
// a preflight.
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

// railsHostSignals returns the Rails/Ruby fingerprints observed for this host,
// or nil when none are present. It checks (in order) the probe response, the
// original response that triggered the scan, and the shared tech registry (which
// the passive rails_fingerprint module populates). A non-empty result is the
// gate that turns a weak OPTIONS `Allow` header into a reportable finding: a
// generic proxy / API gateway answering OPTIONS uniformly carries none of these.
// scanBody is the echo-stripped probe body so a reflected probe path cannot
// masquerade as a framework marker.
func railsHostSignals(
	ctx *httpmsg.HttpRequestResponse,
	resp *httputil.ResponseChain,
	scanCtx *modkit.ScanContext,
	host string,
	scanBody string,
) []string {
	if resp != nil && resp.Response() != nil {
		if sig := infra.RailsSignals(
			resp.Response().Header.Get,
			resp.Response().Header.Values("Set-Cookie"),
			scanBody,
		); len(sig) > 0 {
			return sig
		}
	}
	if orig := ctx.Response(); orig != nil {
		if sig := infra.RailsSignals(orig.Header, rawSetCookies(orig), orig.BodyToString()); len(sig) > 0 {
			return sig
		}
	}
	if scanCtx != nil && scanCtx.TechStack != nil &&
		(scanCtx.TechStack.Has(host, "rails") || scanCtx.TechStack.Has(host, "ruby")) {
		return []string{"Tech: rails (observed elsewhere on host)"}
	}
	return nil
}

// rawSetCookies returns the raw Set-Cookie header values from the original
// response.
func rawSetCookies(resp *httpmsg.HttpResponse) []string {
	var cookies []string
	for _, h := range resp.Headers() {
		if strings.EqualFold(h.Name, "Set-Cookie") {
			cookies = append(cookies, h.Value)
		}
	}
	return cookies
}

// allowAdvertisesIngress reports whether an Allow header describes a POST-only
// Rails ingress/upload route. Such routes advertise POST (optionally with
// OPTIONS) and nothing else. Any read/other method in the set (GET, HEAD, TRACE,
// PUT, DELETE, PATCH, …) marks a generic server / front-controller catch-all
// Allow header — the false-positive class where every path answers OPTIONS with
// the same broad "OPTIONS, TRACE, GET, HEAD, POST" list and a blank body.
func allowAdvertisesIngress(allow string) bool {
	methods := parseAllowMethods(allow)
	if !methods["POST"] {
		return false
	}
	for method := range methods {
		switch method {
		case "POST", "OPTIONS":
			// expected for a POST-only ingress / direct-upload route
		default:
			return false
		}
	}
	return true
}

// parseAllowMethods splits an Allow header into an upper-cased set of methods.
func parseAllowMethods(allow string) map[string]bool {
	methods := make(map[string]bool)
	for _, part := range strings.Split(allow, ",") {
		if m := strings.ToUpper(strings.TrimSpace(part)); m != "" {
			methods[m] = true
		}
	}
	return methods
}

// normalizeAllow returns a canonical, order-independent representation of an
// Allow header so two responses can be compared regardless of method ordering
// or spacing.
func normalizeAllow(allow string) string {
	methods := parseAllowMethods(allow)
	keys := make([]string, 0, len(methods))
	for k := range methods {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

// siblingRandomPath replaces the final segment of path with a random,
// guaranteed-nonexistent token while preserving the parent directory, so the
// probe lands on the same routing prefix as the real path.
func siblingRandomPath(path string) string {
	idx := strings.LastIndex(path, "/")
	if idx < 0 {
		return ""
	}
	return path[:idx+1] + "vigolium-not-rails-" + utils.RandomString(10)
}

// siblingOptionsMatches sends OPTIONS to a random sibling of probePath and
// reports whether it answers with the same status and Allow set as the probe.
// A live Rails route responds only at its own path, so a matching random sibling
// proves the OPTIONS reply is a catch-all on the prefix, not route-specific —
// the "same response with or without the payload" false positive.
func (m *Module) siblingOptionsMatches(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	probePath string,
	status int,
	allow string,
) bool {
	sibling := siblingRandomPath(probePath)
	if sibling == "" {
		return false
	}

	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "OPTIONS")
	if err != nil {
		return false
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, sibling)
	if err != nil {
		return false
	}

	// BuildRequest/SetMethod/... produce well-formed raw, so wrap directly instead
	// of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return false
	}
	defer resp.Close()

	if resp.Response() == nil || resp.Response().StatusCode != status {
		return false
	}
	return normalizeAllow(resp.Response().Header.Get("Allow")) == normalizeAllow(allow)
}

// stripEcho removes occurrences of the requested path and full URL from the body.
// Reflected request targets are common on WAF, rate-limit, and 404 pages; because
// every probe path contains "active_storage"/"action_mailbox", an echoed target
// would masquerade as genuine framework content.
func stripEcho(body, path, fullURL string) string {
	out := body
	for _, echo := range []string{fullURL, path} {
		if echo != "" {
			out = strings.ReplaceAll(out, echo, "")
		}
	}
	return out
}
