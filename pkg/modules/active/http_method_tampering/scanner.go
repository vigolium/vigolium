package http_method_tampering

import (
	"strings"

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

	if !m.markAndShouldContinue(urlx, scanCtx) {
		return nil, nil
	}

	// Only test on endpoints that originally return 2xx (GET endpoints)
	origStatus := 0
	if ctx.Response() != nil {
		origStatus = ctx.Response().StatusCode()
	}

	// Fetch a wildcard probe and a same-method baseline so we can reject
	// findings whose response is just the host's SPA / wildcard shell. If
	// the probe itself errors out we fall back to running without it.
	wildcard, _ := scanCtx.WildcardProbe(ctx, httpClient)
	baseline, _ := scanCtx.GetOrFetchBaseline(ctx, httpClient)

	// Catch-all guard, evaluated lazily and memoized: only when a phase finds a
	// candidate do we probe with an unsupported sentinel method. If THAT also
	// looks "successful" and non-shell, the endpoint accepts ANY method
	// (analytics beacon / permissive edge handler) and a 2xx for a dangerous
	// method or honored override proves nothing — so the candidate is dropped.
	catchAll := -1 // -1 unknown, 0 no, 1 yes
	isCatchAll := func() bool {
		if catchAll == -1 {
			if m.endpointAcceptsAnyMethod(ctx, httpClient, wildcard, baseline) {
				catchAll = 1
			} else {
				catchAll = 0
			}
		}
		return catchAll == 1
	}

	var results []*output.ResultEvent

	// Phase 1: Test dangerous methods on 2xx endpoints
	if origStatus >= 200 && origStatus < 300 {
		r, err := m.testDangerousMethods(urlx, ctx, httpClient, wildcard, baseline, isCatchAll)
		if err != nil {
			return nil, err
		}
		results = append(results, r...)
	}

	// Phase 2: Test method override headers
	r, err := m.testMethodOverrideHeaders(urlx, ctx, httpClient, wildcard, baseline, isCatchAll)
	if err != nil {
		return nil, err
	}
	results = append(results, r...)

	return results, nil
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
	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return false
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
	if err != nil {
		return false
	}
	defer resp.Close()
	if resp.Response() == nil {
		return false
	}
	return isSuccessfulMethod(resp.Response().StatusCode, resp.FullResponseString()) &&
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

	for _, method := range dangerousMethods {
		// Skip if the original request already uses this method
		if strings.EqualFold(ctx.Request().Method(), method) {
			continue
		}

		modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), method)
		if err != nil {
			continue
		}

		fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
		if err != nil {
			continue
		}
		fuzzedReq = fuzzedReq.WithService(ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		if resp.Response() != nil && isSuccessfulMethod(resp.Response().StatusCode, resp.FullResponseString()) &&
			!looksLikeWildcardShell(resp.Response().StatusCode, resp.Body().Bytes(), wildcard, baseline) {
			if isCatchAll() {
				resp.Close()
				return results, nil // endpoint 2xx-es any method — not a real finding
			}
			results = append(results, &output.ResultEvent{
				URL:              urlx.String(),
				Request:          string(modifiedRaw),
				Response:         resp.FullResponseString(),
				FuzzingParameter: "method",
				ExtractedResults: []string{method + " method returned 2xx"},
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

			fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
			if err != nil {
				continue
			}
			fuzzedReq = fuzzedReq.WithService(ctx.Service())

			resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
			if err != nil {
				if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
					return results, nil
				}
				continue
			}

			if resp.Response() != nil && isSuccessfulMethod(resp.Response().StatusCode, resp.FullResponseString()) &&
				!looksLikeWildcardShell(resp.Response().StatusCode, resp.Body().Bytes(), wildcard, baseline) {
				if isCatchAll() {
					resp.Close()
					return results, nil // endpoint 2xx-es any method — override proves nothing
				}
				results = append(results, &output.ResultEvent{
					URL:              urlx.String(),
					Request:          string(modifiedRaw),
					Response:         resp.FullResponseString(),
					FuzzingParameter: header,
					ExtractedResults: []string{"POST with " + header + ": " + overrideMethod},
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
		strings.Contains(bodyLower, "/signin") {
		return false
	}

	// Require meaningful body (not just empty 200)
	if len(body) < 50 {
		return false
	}

	return true
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
