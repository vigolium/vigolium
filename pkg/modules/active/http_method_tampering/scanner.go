package http_method_tampering

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/pkg/errors"
	urlutil "github.com/projectdiscovery/utils/url"
)

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

	var results []*output.ResultEvent

	// Phase 1: Test dangerous methods on 2xx endpoints
	if origStatus >= 200 && origStatus < 300 {
		r, err := m.testDangerousMethods(urlx, ctx, httpClient)
		if err != nil {
			return nil, err
		}
		results = append(results, r...)
	}

	// Phase 2: Test method override headers
	r, err := m.testMethodOverrideHeaders(urlx, ctx, httpClient)
	if err != nil {
		return nil, err
	}
	results = append(results, r...)

	return results, nil
}

// testDangerousMethods sends PUT/DELETE/PATCH to see if they are unexpectedly enabled.
func (m *Module) testDangerousMethods(
	urlx *urlutil.URL,
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
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

		if resp.Response() != nil && isSuccessfulMethod(resp.Response().StatusCode, resp.FullResponse().String()) {
			results = append(results, &output.ResultEvent{
				URL:              urlx.String(),
				Request:          string(modifiedRaw),
				Response:         resp.FullResponse().String(),
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

			if resp.Response() != nil && isSuccessfulMethod(resp.Response().StatusCode, resp.FullResponse().String()) {
				results = append(results, &output.ResultEvent{
					URL:              urlx.String(),
					Request:          string(modifiedRaw),
					Response:         resp.FullResponse().String(),
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
