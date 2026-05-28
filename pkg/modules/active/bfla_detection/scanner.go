package bfla_detection

import (
	"fmt"
	"math"
	"strings"

	"github.com/pkg/errors"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// adminPathPatterns contains path segments that indicate admin/privileged endpoints.
var adminPathPatterns = []string{
	"/admin",
	"/management",
	"/manager",
	"/dashboard",
	"/console",
	"/api/admin",
	"/api/v1/admin",
	"/users/delete",
	"/users/create",
	"/settings",
	"/config",
	"/system",
	"/internal",
	"/debug",
	"/actuator",
	"/ops",
	"/backoffice",
	"/moderate",
	"/staff",
}

// Module implements the BFLA detection active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new BFLA Detection module.
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
		ds: dedup.LazyDiskSet("bfla_detection"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest tests privileged endpoints for broken function-level authorization.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	// Skip media and JS URLs
	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	// Dedup by host+path
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	hash := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(hash) {
		return nil, nil
	}

	// Check if this looks like an admin/privileged endpoint
	if !isAdminPath(urlx.Path) {
		return nil, nil
	}

	// Original response must be 2xx (we can only test what currently succeeds)
	if ctx.Response() == nil {
		return nil, nil
	}
	origStatus := ctx.Response().StatusCode()
	if origStatus < 200 || origStatus >= 300 {
		return nil, nil
	}
	origBody := ctx.Response().Body()
	origBodyLen := len(origBody)

	// Probe the host with a random nonexistent path. If the original "admin"
	// response is just the host's wildcard / SPA shell, every BFLA test will
	// fire because removing auth still returns the same shell. Bail out.
	wildcard, _ := scanCtx.WildcardProbe(ctx, httpClient)
	if wildcard.MatchesBody(origStatus, origBody) {
		return nil, nil
	}

	var results []*output.ResultEvent

	// Test a) Remove Authorization and Cookie headers
	result, err := m.testNoAuth(ctx, httpClient, urlx, origStatus, origBodyLen, wildcard)
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return nil, nil
		}
		// Non-fatal, continue to next test
	}
	if result != nil {
		results = append(results, result)
	}

	// Test b) Downgrade role with empty/generic token
	result, err = m.testDowngradedAuth(ctx, httpClient, urlx, origStatus, origBodyLen, wildcard)
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return nil, nil
		}
	}
	if result != nil {
		results = append(results, result)
	}

	// Test c) Method switching on admin paths without auth
	methodResults, err := m.testMethodSwitching(ctx, httpClient, urlx, origStatus, wildcard)
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return nil, nil
		}
	}
	if len(methodResults) > 0 {
		results = append(results, methodResults...)
	}

	return results, nil
}

// testNoAuth removes Authorization and Cookie headers and checks if the endpoint still responds with 2xx.
func (m *Module) testNoAuth(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	urlx *urlutil.URL,
	origStatus int,
	origBodyLen int,
	wildcard *modkit.WildcardEntry,
) (*output.ResultEvent, error) {
	modifiedRaw, err := httpmsg.RemoveHeader(ctx.Request().Raw(), "Authorization")
	if err != nil {
		return nil, err
	}
	modifiedRaw, err = httpmsg.RemoveHeader(modifiedRaw, "Cookie")
	if err != nil {
		return nil, err
	}

	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return nil, err
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
	if err != nil {
		return nil, err
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil, nil
	}

	respStatus := resp.Response().StatusCode
	respBodyBytes := resp.Body().Bytes()
	respBody := resp.FullResponseString()
	respBodyLen := len(respBody)

	// Reject responses that match the wildcard shell — those are the same
	// page the host returns for every URL, not a real bypass.
	if wildcard.MatchesBody(respStatus, respBodyBytes) {
		return nil, nil
	}

	// Report if original was 200 AND unauthenticated request is also 200
	// AND body length is within 50% of original
	if origStatus == 200 && respStatus == 200 && isBodyLengthSimilar(origBodyLen, respBodyLen) {
		return &output.ResultEvent{
			URL:              urlx.String(),
			Matched:          urlx.String(),
			Request:          string(modifiedRaw),
			Response:         respBody,
			FuzzingParameter: "Authorization",
			ExtractedResults: []string{
				fmt.Sprintf("Original status: %d, Unauthenticated status: %d", origStatus, respStatus),
				fmt.Sprintf("Original body length: %d, Unauthenticated body length: %d", origBodyLen, respBodyLen),
			},
			Info: output.Info{
				Name:        "BFLA: Unauthenticated Access to Privileged Endpoint",
				Description: "The privileged endpoint returns a successful response after removing Authorization and Cookie headers, indicating broken function-level authorization.",
			},
		}, nil
	}

	return nil, nil
}

// testDowngradedAuth attempts to send a generic/empty Bearer token.
func (m *Module) testDowngradedAuth(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	urlx *urlutil.URL,
	origStatus int,
	origBodyLen int,
	wildcard *modkit.WildcardEntry,
) (*output.ResultEvent, error) {
	// Check if there is an Authorization header with a Bearer token
	authHeader, err := httpmsg.GetHeaderValue(ctx.Request().Raw(), "Authorization")
	if err != nil || authHeader == "" {
		return nil, nil
	}

	if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		return nil, nil
	}

	// Replace with an empty Bearer token
	modifiedRaw, err := httpmsg.AddOrReplaceHeader(ctx.Request().Raw(), "Authorization", "Bearer invalid_downgraded_token")
	if err != nil {
		return nil, err
	}

	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return nil, err
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
	if err != nil {
		return nil, err
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil, nil
	}

	respStatus := resp.Response().StatusCode
	respBodyBytes := resp.Body().Bytes()
	respBody := resp.FullResponseString()
	respBodyLen := len(respBody)

	if wildcard.MatchesBody(respStatus, respBodyBytes) {
		return nil, nil
	}

	if origStatus == 200 && respStatus == 200 && isBodyLengthSimilar(origBodyLen, respBodyLen) {
		return &output.ResultEvent{
			URL:              urlx.String(),
			Matched:          urlx.String(),
			Request:          string(modifiedRaw),
			Response:         respBody,
			FuzzingParameter: "Authorization",
			ExtractedResults: []string{
				fmt.Sprintf("Original status: %d, Downgraded token status: %d", origStatus, respStatus),
				"Token replaced with invalid_downgraded_token",
			},
			Info: output.Info{
				Name:        "BFLA: Downgraded Token Accepted on Privileged Endpoint",
				Description: "The privileged endpoint returns a successful response with an invalid/downgraded Bearer token, indicating broken function-level authorization.",
			},
		}, nil
	}

	return nil, nil
}

// testMethodSwitching tries different HTTP methods on admin paths without auth.
func (m *Module) testMethodSwitching(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	urlx *urlutil.URL,
	origStatus int,
	wildcard *modkit.WildcardEntry,
) ([]*output.ResultEvent, error) {
	// Only test method switching if original request is GET
	method, err := httpmsg.GetMethod(ctx.Request().Raw())
	if err != nil || strings.ToUpper(method) != "GET" {
		return nil, nil
	}

	var results []*output.ResultEvent
	methodsToTry := []string{"POST", "PUT", "DELETE"}

	for _, tryMethod := range methodsToTry {
		// Switch method and remove auth
		modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), tryMethod)
		if err != nil {
			continue
		}
		modifiedRaw, err = httpmsg.RemoveHeader(modifiedRaw, "Authorization")
		if err != nil {
			continue
		}
		modifiedRaw, err = httpmsg.RemoveHeader(modifiedRaw, "Cookie")
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
				return results, err
			}
			continue
		}

		if resp.Response() != nil && resp.Response().StatusCode >= 200 && resp.Response().StatusCode < 300 &&
			!wildcard.MatchesBody(resp.Response().StatusCode, resp.Body().Bytes()) {
			respBody := resp.FullResponseString()
			results = append(results, &output.ResultEvent{
				URL:              urlx.String(),
				Matched:          urlx.String(),
				Request:          string(modifiedRaw),
				Response:         respBody,
				FuzzingParameter: "method",
				ExtractedResults: []string{
					fmt.Sprintf("Method %s accepted without authentication on admin path", tryMethod),
				},
				Info: output.Info{
					Name:        fmt.Sprintf("BFLA: Unauthenticated %s on Privileged Endpoint", tryMethod),
					Description: fmt.Sprintf("The privileged endpoint accepts %s requests without authentication, indicating broken function-level authorization.", tryMethod),
				},
			})
			resp.Close()
			return results, nil
		}
		resp.Close()
	}

	return results, nil
}

// isAdminPath checks if the path matches known admin/privileged patterns (case-insensitive).
func isAdminPath(path string) bool {
	pathLower := strings.ToLower(path)
	for _, pattern := range adminPathPatterns {
		if strings.Contains(pathLower, pattern) {
			return true
		}
	}
	return false
}

// isBodyLengthSimilar returns true if the two body lengths are within 50% of each other.
func isBodyLengthSimilar(origLen, newLen int) bool {
	if origLen == 0 && newLen == 0 {
		return true
	}
	if origLen == 0 || newLen == 0 {
		return false
	}
	ratio := math.Abs(float64(origLen-newLen)) / float64(origLen)
	return ratio <= 0.5
}
