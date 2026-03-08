package firebase_functions_exposure

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

var (
	// Extract Cloud Functions URLs
	cloudFuncURLRe = regexp.MustCompile(`https://([a-z0-9-]+)-([a-z0-9-]+)\.cloudfunctions\.net/([a-zA-Z0-9_-]+)`)

	// Stack trace / error leakage patterns
	stackTraceMarkers = []string{
		"Error:",
		"at Object.",
		"at Module.",
		"/workspace/",
		"node_modules/",
		"Traceback (most recent call last)",
		"File \"/workspace/",
		"TypeError:",
		"ReferenceError:",
		"SyntaxError:",
		"UnhandledPromiseRejection",
	}
)

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
		ds: dedup.LazyDiskSet("firebase_functions_exposure"),
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
	if !ctx.HasResponse() {
		return nil, nil
	}

	body := ctx.Response().BodyToString()
	if body == "" {
		return nil, nil
	}

	// Extract Cloud Functions URLs
	urlMatches := cloudFuncURLRe.FindAllStringSubmatch(body, 20)
	if len(urlMatches) == 0 {
		return nil, nil
	}

	// Deduplicate function URLs
	type funcInfo struct {
		funcName string
		fullURL  string
	}
	seen := make(map[string]struct{})
	var functions []funcInfo
	for _, match := range urlMatches {
		if len(match) > 3 {
			url := match[0]
			if _, ok := seen[url]; !ok {
				seen[url] = struct{}{}
				functions = append(functions, funcInfo{
					funcName: match[3],
					fullURL:  url,
				})
			}
		}
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())

	urlx, _ := ctx.URL()
	sourceURL := ""
	if urlx != nil {
		sourceURL = urlx.String()
	}

	var results []*output.ResultEvent
	for _, fn := range functions {
		if diskSet != nil && diskSet.IsSeen(fn.fullURL) {
			continue
		}

		// Probe function with GET (unauthenticated)
		if result := m.probeFunction(httpClient, fn.fullURL, fn.funcName, sourceURL); result != nil {
			results = append(results, result)
		}

		// Probe for error leakage with malformed POST
		if result := m.probeErrorLeakage(httpClient, fn.fullURL, fn.funcName, sourceURL); result != nil {
			results = append(results, result)
		}
	}

	return results, nil
}

func (m *Module) probeFunction(
	httpClient *http.Requester,
	funcURL string,
	funcName string,
	sourceURL string,
) *output.ResultEvent {
	host := extractHost(funcURL)
	rawReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nAccept: application/json\r\n\r\n",
		funcURL, host)

	fuzzedReq, err := httpmsg.ParseRawRequest(rawReq)
	if err != nil {
		return nil
	}

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil
	}

	status := resp.Response().StatusCode

	// 200 without auth = unauthenticated access
	if status != 200 {
		return nil
	}

	respBody := resp.Body().String()
	trimmed := strings.TrimSpace(respBody)

	// Skip empty/trivial responses
	if trimmed == "" || trimmed == "ok" || trimmed == "OK" || trimmed == "{}" || trimmed == "null" {
		return nil
	}

	// Check content-type for meaningful response
	ct := resp.Response().Header.Get("Content-Type")
	isJSON := strings.Contains(ct, "json")
	isHTML := strings.Contains(ct, "html")

	// Only flag if response contains actual data
	if !isJSON && !isHTML && len(trimmed) < 20 {
		return nil
	}

	responseStr := resp.FullResponse().String()
	if len(responseStr) > 4096 {
		responseStr = responseStr[:4096] + "\n... (truncated)"
	}

	return &output.ResultEvent{
		URL:      funcURL,
		Matched:  funcURL,
		Request:  rawReq,
		Response: responseStr,
		Info: output.Info{
			Name:        fmt.Sprintf("Firebase Cloud Function Unauthenticated (%s)", funcName),
			Description: fmt.Sprintf("Cloud Function '%s' at %s responds with data without authentication — may expose business logic or sensitive data", funcName, funcURL),
			Severity:    severity.Medium,
			Confidence:  severity.Firm,
			Tags:        []string{"firebase", "cloud-functions", "unauthenticated"},
		},
		Metadata: map[string]any{
			"function": funcName,
			"source":   sourceURL,
		},
	}
}

func (m *Module) probeErrorLeakage(
	httpClient *http.Requester,
	funcURL string,
	funcName string,
	sourceURL string,
) *output.ResultEvent {
	host := extractHost(funcURL)
	malformedBody := `{invalid json`
	rawReq := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		funcURL, host, len(malformedBody), malformedBody)

	fuzzedReq, err := httpmsg.ParseRawRequest(rawReq)
	if err != nil {
		return nil
	}

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil
	}

	respBody := resp.Body().String()

	// Check for stack trace / error detail leakage
	var matchedMarkers []string
	for _, marker := range stackTraceMarkers {
		if strings.Contains(respBody, marker) {
			matchedMarkers = append(matchedMarkers, marker)
		}
	}
	if len(matchedMarkers) == 0 {
		return nil
	}

	responseStr := resp.FullResponse().String()
	if len(responseStr) > 4096 {
		responseStr = responseStr[:4096] + "\n... (truncated)"
	}

	return &output.ResultEvent{
		URL:              funcURL,
		Matched:          funcURL,
		Request:          rawReq,
		Response:         responseStr,
		ExtractedResults: matchedMarkers,
		Info: output.Info{
			Name:        fmt.Sprintf("Firebase Cloud Function Error Leakage (%s)", funcName),
			Description: fmt.Sprintf("Cloud Function '%s' returns verbose error details including stack traces or internal paths when given malformed input", funcName),
			Severity:    severity.Low,
			Confidence:  severity.Certain,
			Tags:        []string{"firebase", "cloud-functions", "info-disclosure"},
		},
		Metadata: map[string]any{
			"function": funcName,
			"source":   sourceURL,
		},
	}
}

func extractHost(rawURL string) string {
	url := strings.TrimPrefix(rawURL, "https://")
	url = strings.TrimPrefix(url, "http://")
	if idx := strings.Index(url, "/"); idx != -1 {
		return url[:idx]
	}
	return url
}
