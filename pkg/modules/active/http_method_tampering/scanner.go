package http_method_tampering

import (
	"strings"
	"sync"

	"github.com/pkg/errors"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// wildcardShellFinding rejects findings whose response is indistinguishable
// from the host's wildcard / SPA shell. Compares status + body length + head
// against both a same-host random-path probe and the original baseline (so a
// PUT returning the same SPA index.html as GET / is not reported).
func looksLikeWildcardShell(
	statusCode int,
	body []byte,
	wildcard *modkit.WildcardEntry,
	baseline *modkit.BaselineEntry,
) bool {
	if wildcard != nil && wildcard.MatchesBody(statusCode, body) {
		return true
	}
	if baseline == nil || baseline.Response == nil {
		return false
	}
	if statusCode != baseline.StatusCode {
		return false
	}
	if baseline.BodyLen == 0 || len(body) == 0 {
		return false
	}
	diff := baseline.BodyLen - len(body)
	if diff < 0 {
		diff = -diff
	}
	if float64(diff)/float64(baseline.BodyLen) > 0.10 {
		return false
	}
	baseHead := baseline.Response.Body()
	if len(baseHead) > 256 {
		baseHead = baseHead[:256]
	}
	probeHead := body
	if len(probeHead) > 256 {
		probeHead = probeHead[:256]
	}
	return string(baseHead) == string(probeHead)
}

// dangerousMethods are write methods that should not be blindly enabled.
var dangerousMethods = []string{"PUT", "DELETE", "PATCH", "MKCOL", "MOVE", "COPY"}

// methodOverrideHeaders are headers that can override the HTTP method at the server level.
var methodOverrideHeaders = []string{
	"X-HTTP-Method-Override",
	"X-HTTP-Method",
	"X-Method-Override",
}

// Module implements the HTTP Method Tampering active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds                dedup.Lazy[dedup.DiskSet]
	limitCheckPerHost int
}

// New creates a new HTTP Method Tampering module.
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
		ds:                dedup.LazyDiskSet("http_method_tampering"),
		limitCheckPerHost: 15,
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest tests HTTP method tampering on the given request.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if !infra.IsValidForInjectionVulns(urlx, ctx) {
		return nil, nil
	}
	// Generic method discovery must not mutate a real resource. PUT, PATCH,
	// DELETE, MOVE, COPY, and POST-with-DELETE-override can all have irreversible
	// effects, and a 2xx response still would not prove what state changed. Limit
	// this module to an idempotent GET seed plus safe OPTIONS semantics.
	if ctx.Request() == nil || !strings.EqualFold(ctx.Request().Method(), "GET") ||
		ctx.Response() == nil || ctx.Response().StatusCode() < 200 || ctx.Response().StatusCode() >= 300 {
		return nil, nil
	}

	if !m.markAndShouldContinue(urlx, scanCtx) {
		return nil, nil
	}

	options, ok := m.fetchSafeMethodResponse(ctx, httpClient, "OPTIONS", "", "")
	if !ok {
		return nil, nil
	}
	var results []*output.ResultEvent
	if declared := declaredDangerousMethods(options.allow, options.corsAllow); len(declared) > 0 {
		results = append(results, safeMethodObservation(
			urlx,
			"Server Declares Write-Oriented HTTP Methods",
			"The OPTIONS response advertises write-oriented methods. This is capability metadata only; it does not show that an unauthenticated write succeeds or that any state changes.",
			"OPTIONS",
			options,
			[]string{"declared_methods=" + strings.Join(declared, ",")},
		))
	}

	getResponse, getOK := m.fetchSafeMethodResponse(ctx, httpClient, "GET", "", "")
	getReplay, replayOK := m.fetchSafeMethodResponse(ctx, httpClient, "GET", "", "")
	if !getOK || !replayOK || !safeResponsesSimilar(getResponse, getReplay) {
		return results, nil
	}
	for _, header := range methodOverrideHeaders {
		first, firstOK := m.fetchSafeMethodResponse(ctx, httpClient, "GET", header, "OPTIONS")
		second, secondOK := m.fetchSafeMethodResponse(ctx, httpClient, "GET", header, "OPTIONS")
		if !firstOK || !secondOK ||
			!safeResponsesSimilar(first, second) ||
			!safeResponsesSimilar(first, options) ||
			safeResponsesSimilar(first, getResponse) {
			continue
		}
		results = append(results, safeMethodObservation(
			urlx,
			"HTTP Method Override Mechanism Observed",
			"A GET carrying "+header+": OPTIONS reproduced the direct OPTIONS response twice and differed from the normal GET. This proves override capability only; no privileged or state-changing method was invoked.",
			header,
			first,
			[]string{"visible_method=GET", "override_header=" + header, "override_value=OPTIONS", "replay_count=2"},
		))
		break
	}
	return results, nil
}

type safeMethodResponse struct {
	status      int
	body        string
	contentType string
	allow       string
	corsAllow   string
	request     string
	response    string
}

func (m *Module) fetchSafeMethodResponse(ctx *httpmsg.HttpRequestResponse, client *http.Requester, method, header, value string) (safeMethodResponse, bool) {
	raw, err := httpmsg.SetMethod(ctx.Request().Raw(), method)
	if err != nil {
		return safeMethodResponse{}, false
	}
	if header != "" {
		raw, err = httpmsg.AddOrReplaceHeader(raw, header, value)
		if err != nil {
			return safeMethodResponse{}, false
		}
	}
	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
	resp, _, err := client.Execute(req, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil || resp == nil || resp.Response() == nil {
		if resp != nil {
			resp.Close()
		}
		return safeMethodResponse{}, false
	}
	defer resp.Close()
	if infra.IsBlockedResponse(resp) || resp.Response().StatusCode >= 500 {
		return safeMethodResponse{}, false
	}
	return safeMethodResponse{
		status:      resp.Response().StatusCode,
		body:        resp.BodyString(),
		contentType: resp.Response().Header.Get("Content-Type"),
		allow:       resp.Response().Header.Get("Allow"),
		corsAllow:   resp.Response().Header.Get("Access-Control-Allow-Methods"),
		request:     string(raw),
		response:    resp.FullResponseString(),
	}, true
}

func declaredDangerousMethods(values ...string) []string {
	wanted := make(map[string]bool, len(dangerousMethods))
	for _, method := range dangerousMethods {
		wanted[method] = true
	}
	seen := make(map[string]bool)
	var declared []string
	for _, value := range values {
		for _, token := range strings.FieldsFunc(strings.ToUpper(value), func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
			if wanted[token] && !seen[token] {
				seen[token] = true
				declared = append(declared, token)
			}
		}
	}
	return declared
}

func safeResponsesSimilar(left, right safeMethodResponse) bool {
	if left.status != right.status || !strings.EqualFold(strings.TrimSpace(strings.Split(left.contentType, ";")[0]), strings.TrimSpace(strings.Split(right.contentType, ";")[0])) {
		return false
	}
	if left.body == "" || right.body == "" {
		return left.body == right.body
	}
	leftSig := modkit.NewResponseSignature(left.status, left.body, "OPTIONS")
	rightSig := modkit.NewResponseSignature(right.status, right.body, "OPTIONS")
	return modkit.RatioSimilar(leftSig, rightSig)
}

func safeMethodObservation(urlx *urlutil.URL, name, description, fuzzingParameter string, response safeMethodResponse, extracted []string) *output.ResultEvent {
	return &output.ResultEvent{
		ModuleID:         ModuleID,
		RecordKind:       output.RecordKindObservation,
		EvidenceGrade:    output.EvidenceGradeObservation,
		Host:             urlx.Host,
		URL:              urlx.String(),
		Matched:          urlx.String(),
		Request:          response.request,
		Response:         response.response,
		FuzzingParameter: fuzzingParameter,
		ExtractedResults: extracted,
		Info: output.Info{
			Name:        name,
			Description: description,
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        ModuleTags,
		},
		Metadata: map[string]any{"state_change_observed": false, "authorization_bypass_observed": false, "safe_probe_only": true},
	}
}

// endpointAcceptsAnyMethod sends a syntactically valid but unsupported sentinel
// method and reports whether the endpoint still returns a "successful",
// non-shell response. Such catch-all endpoints respond 2xx to anything, so a
// dangerous method or honored override returning 2xx is meaningless. Uses the
// SAME success+shell criteria as the real checks, so a bogus method getting the
// same treatment as a dangerous one is exactly what flags a catch-all. Returns
// false on a transport error so it never suppresses on a transient failure.
func (m *Module) endpointAcceptsAnyMethod(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	wildcard *modkit.WildcardEntry,
	baseline *modkit.BaselineEntry,
) bool {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "VIGOLIUMX")
	if err != nil {
		return false
	}
	// modifiedRaw is well-formed raw, so wrap directly instead of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
	if err != nil {
		return false
	}
	defer resp.Close()
	if resp.Response() == nil {
		return false
	}
	return isSuccessfulMethod(resp.Response().StatusCode, resp.BodyString()) &&
		!looksLikeWildcardShell(resp.Response().StatusCode, resp.Body().Bytes(), wildcard, baseline)
}

// testDangerousMethods sends PUT/DELETE/PATCH to see if they are unexpectedly enabled.
func (m *Module) testDangerousMethods(
	urlx *urlutil.URL,
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	wildcard *modkit.WildcardEntry,
	baseline *modkit.BaselineEntry,
	isCatchAll func() bool,
) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent

	// Lazily fetch (once) a benign GET control so a dangerous method that merely
	// gets routed to the same read handler is not mistaken for an enabled write.
	// Memoized so we issue at most one control request per endpoint, and only when
	// a candidate is actually found.
	getGetControl := sync.OnceValues(func() (methodControl, bool) {
		return m.fetchMethodControl(ctx, httpClient, "GET")
	})

	for _, method := range dangerousMethods {
		// Skip if the original request already uses this method
		if strings.EqualFold(ctx.Request().Method(), method) {
			continue
		}

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

		if resp.Response() != nil && isSuccessfulMethod(resp.Response().StatusCode, resp.BodyString()) &&
			!looksLikeWildcardShell(resp.Response().StatusCode, resp.Body().Bytes(), wildcard, baseline) {
			if isCatchAll() {
				resp.Close()
				return results, nil // endpoint 2xx-es any method — not a real finding
			}

			// Confirm the write verb was honored, not merely routed to the same
			// read handler. A benign GET control tells the two apart:
			//   • response ~ GET  → the endpoint ignores the verb entirely (geo /
			//     beacon / RPC handler that answers any method) — nothing written.
			//   • HTML while GET is non-HTML → the server rendered its SPA / error
			//     page for the unhandled verb (content-type flip), not a write.
			// Both are endpoint-level properties, so a hit ends the leg. Skipped
			// only when the control is unavailable/blocked (stay false-negative safe).
			dangerSig := modkit.NewResponseSignature(resp.Response().StatusCode, resp.BodyString(), "")
			if gc, ok := getGetControl(); ok {
				if modkit.RatioSimilar(gc.sig, dangerSig) {
					resp.Close()
					return results, nil // verb-agnostic endpoint — verb ignored
				}
				if isHTMLContentType(resp.Response().Header.Get("Content-Type")) &&
					!isHTMLContentType(gc.contentType) {
					resp.Close()
					return results, nil // catch-all SPA / error render, not a write
				}
			}

			ev := modkit.NewEvidenceCollector()
			ev.Add("baseline", string(ctx.Request().Raw()), baselineFullResponse(baseline))
			results = append(results, &output.ResultEvent{
				URL:                urlx.String(),
				Request:            string(modifiedRaw),
				Response:           resp.FullResponseString(),
				AdditionalEvidence: ev.Entries(),
				FuzzingParameter:   "method",
				ExtractedResults:   []string{method + " method returned 2xx"},
				Info: output.Info{
					Description: "Dangerous HTTP method " + method + " is enabled on this endpoint",
				},
			})
			resp.Close()
			return results, nil
		}
		resp.Close()
	}

	return results, nil
}

// testMethodOverrideHeaders tests if method override headers change server behavior.
func (m *Module) testMethodOverrideHeaders(
	urlx *urlutil.URL,
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	wildcard *modkit.WildcardEntry,
	baseline *modkit.BaselineEntry,
	isCatchAll func() bool,
) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent

	// Lazily fetch (once) a plain-POST control: the SAME request as the override
	// probe but WITHOUT the override header. The override is only "respected" if
	// it materially changes the response relative to this control — so an ignored
	// override that returns the same page (e.g. a body-less 200 from an SSO/auth
	// endpoint that answers POST identically with or without the header) is not a
	// finding. Memoized so we issue at most one control request per endpoint, and
	// only when a candidate is actually found.
	getControl := sync.OnceValues(func() (postControl, bool) {
		return m.fetchPostControl(ctx, httpClient)
	})

	for _, header := range methodOverrideHeaders {
		for _, overrideMethod := range []string{"DELETE", "PUT"} {
			modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "POST")
			if err != nil {
				continue
			}
			modifiedRaw, err = httpmsg.AddOrReplaceHeader(modifiedRaw, header, overrideMethod)
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

			if resp.Response() != nil && isSuccessfulMethod(resp.Response().StatusCode, resp.BodyString()) &&
				!looksLikeWildcardShell(resp.Response().StatusCode, resp.Body().Bytes(), wildcard, baseline) {
				if isCatchAll() {
					resp.Close()
					return results, nil // endpoint 2xx-es any method — override proves nothing
				}

				// Differential confirmation: the override must change the response
				// versus a plain POST. If it returns effectively the same page, the
				// header was ignored — drop the candidate and try the next variant.
				overrideSig := modkit.NewResponseSignature(resp.Response().StatusCode, resp.BodyString(), "")
				ctrl, ctrlOK := getControl()
				if ctrlOK && modkit.RatioSimilar(ctrl.sig, overrideSig) {
					resp.Close()
					continue
				}

				// Determinism gate: the override "changed" the response only if the
				// endpoint answers a plain POST deterministically. Endpoints that mint
				// a fresh token/nonce (analytics init, attestation/session bootstrap)
				// or stream a variable SSR shell return a different body for ANY two
				// requests, so the override delta would be pure per-request noise. A
				// SECOND no-override control must match the first before we trust it;
				// two dissimilar controls mean the endpoint is non-deterministic and
				// no override can be confirmed here.
				if ctrlOK {
					if ctrl2, ok := m.fetchPostControl(ctx, httpClient); !ok ||
						!modkit.RatioSimilar(ctrl.sig, ctrl2.sig) {
						resp.Close()
						return results, nil
					}
				}

				ev := modkit.NewEvidenceCollector()
				ev.Add("baseline", string(ctx.Request().Raw()), baselineFullResponse(baseline))
				if ctrlOK {
					ev.Add("control: plain POST without "+header, ctrl.reqRaw, ctrl.respRaw)
				}
				results = append(results, &output.ResultEvent{
					URL:                urlx.String(),
					Request:            string(modifiedRaw),
					Response:           resp.FullResponseString(),
					AdditionalEvidence: ev.Entries(),
					FuzzingParameter:   header,
					ExtractedResults:   []string{"POST with " + header + ": " + overrideMethod + " changes the response vs a plain POST"},
					Info: output.Info{
						Description: "Method override header " + header + " is respected (overrides to " + overrideMethod + ")",
					},
				})
				resp.Close()
				return results, nil
			}
			resp.Close()
		}
	}

	return results, nil
}

// postControl is a memoized plain-POST control response (no method-override
// header) used as the differential baseline for the override check.
type postControl struct {
	sig     modkit.ResponseSignature
	reqRaw  string
	respRaw string
}

// fetchPostControl issues the request as a plain POST WITHOUT any method-override
// header and returns its response signature plus the raw request/response for
// evidence. ok is false on any transport/parse error so the caller falls back to
// the success+shell gates rather than dropping a finding on a transient failure.
// NoClustering bypasses the response cache so the control is a genuinely fresh
// observation rather than a replay of a previously-cached probe.
func (m *Module) fetchPostControl(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) (postControl, bool) {
	controlRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "POST")
	if err != nil {
		return postControl{}, false
	}
	// controlRaw is well-formed raw, so wrap directly instead of re-parsing on this hot path.
	req := httpmsg.NewRequestResponseRaw(controlRaw, ctx.Service())

	resp, _, err := httpClient.Execute(req, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return postControl{}, false
	}
	defer resp.Close()
	if resp.Response() == nil {
		return postControl{}, false
	}
	return postControl{
		sig:     modkit.NewResponseSignature(resp.Response().StatusCode, resp.BodyString(), ""),
		reqRaw:  string(controlRaw),
		respRaw: resp.FullResponseString(),
	}, true
}

// isSuccessfulMethod checks if a response indicates the method was accepted.
func isSuccessfulMethod(statusCode int, body string) bool {
	if statusCode < 200 || statusCode >= 300 {
		return false
	}

	// Filter out common false positives
	bodyLower := strings.ToLower(body)
	if strings.Contains(bodyLower, "method not allowed") ||
		strings.Contains(bodyLower, "not supported") ||
		strings.Contains(bodyLower, "/login") ||
		strings.Contains(bodyLower, "/signin") ||
		// Framework soft-errors: a 200 that is actually a session/CSRF/validation
		// rejection, not a performed action. Salesforce Aura answers ANY verb
		// (including DELETE) with an aura:invalidSession / exceptionEvent event at
		// HTTP 200 — the action never ran, so this is not a "successful" method.
		strings.Contains(bodyLower, "aura:invalidsession") ||
		strings.Contains(bodyLower, "\"exceptionevent\"") {
		return false
	}

	// Require meaningful body (not just empty 200)
	if len(body) < 50 {
		return false
	}

	return true
}

// isHTMLContentType reports whether a Content-Type header names a full HTML
// document. A genuinely honored method-override or an actually-enabled write verb
// answers with JSON, an empty body, or a status — essentially never a rendered
// HTML page — so an HTML response to a write/override probe on an endpoint that
// normally serves non-HTML is the host's SPA shell / error page swallowing the
// request, not a resource write.
func isHTMLContentType(contentType string) bool {
	return strings.Contains(strings.ToLower(contentType), "text/html")
}

// methodControl is a memoized control response fetched with a benign method. It
// lets the dangerous-method leg tell a genuinely method-tampered response apart
// from a verb-agnostic read endpoint (geo/beacon/RPC handler that answers the
// same content to any verb) and from a catch-all SPA/error renderer.
type methodControl struct {
	sig         modkit.ResponseSignature
	contentType string
}

// fetchMethodControl issues the request with the given benign method and no
// tampering, returning its response signature and content type. ok is false on a
// transport error OR when the control is a WAF/edge/rate-limit block (401/403/429/
// 503/challenge): a blocked response is the edge talking, not the endpoint, so it
// cannot serve as a comparison control — callers then fall back to reporting
// rather than dropping a finding on a transient block. NoClustering bypasses the
// response cache so the control is a genuinely fresh observation.
func (m *Module) fetchMethodControl(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	method string,
) (methodControl, bool) {
	controlRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), method)
	if err != nil {
		return methodControl{}, false
	}
	// controlRaw is well-formed raw, so wrap directly instead of re-parsing on this hot path.
	req := httpmsg.NewRequestResponseRaw(controlRaw, ctx.Service())

	resp, _, err := httpClient.Execute(req, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return methodControl{}, false
	}
	defer resp.Close()
	if resp.Response() == nil || infra.IsBlockedResponse(resp) {
		return methodControl{}, false
	}
	return methodControl{
		sig:         modkit.NewResponseSignature(resp.Response().StatusCode, resp.BodyString(), ""),
		contentType: resp.Response().Header.Get("Content-Type"),
	}, true
}

// baselineFullResponse renders the cached same-method baseline as a full raw
// response string for evidence capture, returning "" when no baseline is present.
func baselineFullResponse(baseline *modkit.BaselineEntry) string {
	if baseline == nil || baseline.Response == nil {
		return ""
	}
	return string(baseline.Response.Raw())
}

// markAndShouldContinue limits checks per host.
func (m *Module) markAndShouldContinue(urlx *urlutil.URL, scanCtx *modkit.ScanContext) bool {
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet == nil {
		return true
	}
	host := urlx.Hostname()
	_, shouldContinue := diskSet.IncrementAndCheck(host, m.limitCheckPerHost)
	return shouldContinue
}
