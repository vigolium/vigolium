package csrf_verify

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

// csrfParamPattern matches common CSRF token parameter names. The bare token
// alternative is anchored with word boundaries (\btoken\b) so it matches a field
// literally named "token" but NOT camelCase application fields whose name merely
// ends in "Token" (siteToken, accessToken, deviceToken, pageToken, …). Genuine
// anti-CSRF fields that use camelCase are still caught via the csrf/xsrf prefix
// (csrfToken, xsrfToken) or the explicit _token / authenticity.token alternatives.
var csrfParamPattern = regexp.MustCompile(`(?i)(csrf|xsrf|\btoken\b|authenticity.token|__RequestVerificationToken|antiforgery|_token|nonce|csrfmiddlewaretoken)`)

// stateChangingMethods are HTTP methods that modify server state.
var stateChangingMethods = map[string]bool{
	"POST":   true,
	"PUT":    true,
	"DELETE": true,
	"PATCH":  true,
}

// csrfForgeableContentType reports whether a request body content type is one a
// cross-site HTML form (or a "simple" CORS request) can produce without a
// preflight. A CSRF token is only a meaningful defense for these.
//
// Any other body type — application/json, application/xml, application/*+json,
// etc. — is a CORS "non-simple" request: a cross-origin HTML form cannot set its
// Content-Type, and a fetch/XHR carrying it triggers a preflight the target must
// explicitly allow. Such a request is not auto-submittable cross-origin, so a
// field whose name merely contains "token" (e.g. a Cloudflare RUM beacon's
// siteToken) is application data, not an anti-CSRF token, and removing it proves
// nothing about CSRF. An empty/absent content type is treated as forgeable to
// stay false-negative safe — the name pattern and param-location guard still apply.
func csrfForgeableContentType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if i := strings.IndexByte(ct, ';'); i >= 0 { // drop ";charset=" / ";boundary="
		ct = strings.TrimSpace(ct[:i])
	}
	switch ct {
	case "",
		"application/x-www-form-urlencoded",
		"multipart/form-data",
		"text/plain":
		return true
	default:
		return false
	}
}

// isForgeableTokenLocation reports whether a parameter location can hold a real
// anti-CSRF token. JSON and XML body values are CORS non-simple and not
// cross-origin-forgeable, so a "*token*"-named value parsed from them is
// application data rather than an anti-CSRF defense. This backstops
// csrfForgeableContentType for requests whose body parses as JSON/XML without a
// matching Content-Type header.
func isForgeableTokenLocation(pt httpmsg.ParamType) bool {
	switch pt {
	case httpmsg.ParamJSON, httpmsg.ParamXML, httpmsg.ParamXMLAttr:
		return false
	default:
		return true
	}
}

// csrfProbe defines a CSRF verification strategy.
type csrfProbe struct {
	name string
	desc string
	// mutate returns modified raw request bytes; receives param name, type, and original raw
	mutate func(raw []byte, paramName string, paramType httpmsg.ParamType) ([]byte, error)
}

var probes = []csrfProbe{
	{
		name: "Token Removed",
		desc: "CSRF token was completely removed from the request, but the server still accepted it",
		mutate: func(raw []byte, paramName string, paramType httpmsg.ParamType) ([]byte, error) {
			return httpmsg.RemoveParametersByName(raw, []string{paramName}, paramType)
		},
	},
	{
		name: "Token Empty",
		desc: "CSRF token was set to an empty string, but the server still accepted it",
		mutate: func(raw []byte, paramName string, paramType httpmsg.ParamType) ([]byte, error) {
			param := httpmsg.BuildParameter(paramName, "", paramType)
			return httpmsg.UpdateParameter(raw, param)
		},
	},
	{
		name: "Token Randomized",
		desc: "CSRF token was replaced with a random value, but the server still accepted it",
		mutate: func(raw []byte, paramName string, paramType httpmsg.ParamType) ([]byte, error) {
			param := httpmsg.BuildParameter(paramName, utils.RandomString(32), paramType)
			return httpmsg.UpdateParameter(raw, param)
		},
	},
}

// Module implements the CSRF Token Verification active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new CSRF Token Verification module.
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
		ds: dedup.LazyDiskSet("csrf_verify"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest verifies CSRF token enforcement by mutating the token.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	// Only check state-changing methods
	method := strings.ToUpper(ctx.Request().Method())
	if !stateChangingMethods[method] {
		return nil, nil
	}

	// CSRF preconditions — mirror the passive csrf_detect module. The attack only
	// works against a request a browser will replay cross-site using AMBIENT
	// credentials, so "token not enforced" is moot (and a false positive) unless
	// all of these hold:
	//
	//  1. A simple/form content type. A non-simple body (application/json,
	//     application/xml, …) cannot be produced by a cross-site HTML form and
	//     forces a CORS preflight — so a "*token*"-named field there is app data,
	//     not an anti-CSRF token (the reported FP: a Cloudflare RUM beacon's
	//     JSON siteToken).
	//  2. No header-based auth. Authorization: Bearer/Basic is never attached
	//     automatically cross-site, so the endpoint is not CSRF-able.
	//  3. A Cookie is present. No Cookie means no ambient session for an attacker
	//     to ride, so token enforcement is irrelevant.
	if !csrfForgeableContentType(ctx.Request().Header("Content-Type")) {
		return nil, nil
	}
	if ctx.Request().Header("Authorization") != "" {
		return nil, nil
	}
	if ctx.Request().Header("Cookie") == "" {
		return nil, nil
	}
	hasSessionCookie := false
	for _, name := range modkit.RequestCookieNames(ctx.Request().Header("Cookie")) {
		if modkit.LikelySessionCookie(name) {
			hasSessionCookie = true
			break
		}
	}
	if !hasSessionCookie {
		return nil, nil
	}
	if scanCtx != nil {
		scanCtx.ObserveResponseCookies(ctx)
		for _, policy := range scanCtx.RequestCookiePolicies(ctx) {
			if modkit.LikelySessionCookie(policy.Name) && (policy.SameSite == "strict" || policy.SameSite == "lax") {
				return nil, nil
			}
		}
	}

	// Find CSRF token parameter
	params, err := ctx.Request().Parameters()
	if err != nil {
		return nil, nil
	}

	var csrfParamName string
	var csrfParamType httpmsg.ParamType
	for _, param := range params {
		if !isForgeableTokenLocation(param.Type()) {
			continue
		}
		if csrfParamPattern.MatchString(param.Name()) {
			csrfParamName = param.Name()
			csrfParamType = param.Type()
			break
		}
	}

	// No CSRF token found — passive module handles this case
	if csrfParamName == "" {
		return nil, nil
	}

	// Dedup after applicability checks so an irrelevant request shape cannot
	// claim the route before a forgeable session-backed token is observed.
	dedupKey := utils.Sha1(fmt.Sprintf("%s:%s:%s:%s", method, urlx.Host, urlx.Path, ctx.Request().IdentityFingerprint()))
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	// Get baseline status code + body (the original request carried a VALID token
	// and succeeded). The body is used to confirm a mutated-token request was
	// processed the SAME way, not merely returned some 2xx.
	baselineStatus := 0
	baselineBody := ""
	if ctx.Response() != nil {
		baselineStatus = ctx.Response().StatusCode()
		baselineBody = ctx.Response().BodyToString()
	}

	var results []*output.ResultEvent

	for _, probe := range probes {
		mutatedRaw, err := probe.mutate(ctx.Request().Raw(), csrfParamName, csrfParamType)
		if err != nil {
			continue
		}
		// Model a real cross-site submission. Origin/Referer enforcement will make
		// this response diverge from the successful same-site baseline.
		mutatedRaw, err = httpmsg.AddOrReplaceHeader(mutatedRaw, "Origin", "https://csrf-probe.invalid")
		if err != nil {
			continue
		}
		mutatedRaw, err = httpmsg.AddOrReplaceHeader(mutatedRaw, "Referer", "https://csrf-probe.invalid/probe")
		if err != nil {
			continue
		}

		// probe.mutate produces well-formed raw, so wrap directly instead of
		// re-parsing on this hot path.
		fuzzedReq := httpmsg.NewRequestResponseRaw(mutatedRaw, ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		respStatus := 0
		respBody := ""
		respFull := ""
		if resp.Response() != nil {
			respStatus = resp.Response().StatusCode
			respBody = resp.Body().String()
			// Only a 2xx response can become a finding below (a reject is 4xx/5xx),
			// so capture the full raw proof response — the forged cross-site request
			// processed like the valid-token baseline — just for that path, before
			// Close. Reject responses skip the headers+body copy they'd never use.
			if respStatus >= 200 && respStatus < 300 {
				respFull = resp.FullResponseString()
			}
		}
		resp.Close()

		// If server rejects with 4xx/5xx, token is validated — stop probing
		if respStatus >= 400 {
			return results, nil
		}

		// If response is 2xx and same class as baseline, token was not validated
		if respStatus >= 200 && respStatus < 300 && sameStatusClass(respStatus, baselineStatus) {
			// Strict drop-on-fail: a same-class 2xx is not enough. The mutated
			// request must have been processed the SAME way as the valid-token
			// baseline (textually equivalent response body), proving the token was
			// ignored rather than the request being soft-rejected with a 200
			// error/re-render page. Without a baseline body, fall back to status.
			if !sameAsBaseline(respBody, baselineBody) {
				continue
			}
			results = append(results, &output.ResultEvent{
				URL:              urlx.String(),
				Matched:          urlx.String(),
				Request:          string(mutatedRaw),
				Response:         respFull,
				FuzzingParameter: csrfParamName,
				ExtractedResults: []string{probe.name},
				RecordKind:       output.RecordKindCandidate,
				EvidenceGrade:    output.EvidenceGradeDifferential,
				DedupKey:         fmt.Sprintf("csrf-token-bypass|%s|%s|%s|%s", urlx.Host, method, urlx.Path, ctx.Request().IdentityFingerprint()),
				Info: output.Info{
					Name:        fmt.Sprintf("Potential CSRF Token Bypass: %s", probe.name),
					Description: probe.desc + ". The cross-site response matched the valid-token baseline, but a durable unauthorized state change was not measured.",
					Severity:    severity.Medium,
					Confidence:  severity.Tentative,
					Tags:        []string{"csrf", "token-bypass", "session"},
					Reference:   []string{"https://portswigger.net/web-security/csrf/bypassing-token-validation"},
				},
				Metadata: map[string]any{
					"csrf_param":      csrfParamName,
					"probe":           probe.name,
					"baseline_status": baselineStatus,
					"probe_status":    respStatus,
				},
			})
			return results, nil
		}
	}

	return results, nil
}

// sameStatusClass checks if two status codes are in the same HTTP status class (2xx, 3xx, etc.)
func sameStatusClass(a, b int) bool {
	return a/100 == b/100
}

// sameAsBaseline reports whether a mutated-token response is the same processed
// outcome as the valid-token baseline: textually equivalent bodies (QuickRatio
// >= UpperRatioBound). When no baseline body is available it falls back to the
// status-class match the caller already established.
func sameAsBaseline(body, baselineBody string) bool {
	if strings.TrimSpace(baselineBody) == "" {
		return true
	}
	return modkit.BodiesSimilar(body, baselineBody)
}
