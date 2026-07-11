package firebase_functions_exposure

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
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

type functionResponse struct {
	status       int
	body         string
	contentType  string
	rawRequest   string
	fullResponse string
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

	var diskSet *dedup.DiskSet
	if scanCtx != nil {
		diskSet = m.ds.Get(scanCtx.DedupMgr())
	}
	probeClient, err := httpClient.CloneWithoutCredentials()
	if err != nil {
		return nil, nil
	}

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
		if result := m.probeFunction(probeClient, fn.fullURL, fn.funcName, sourceURL); result != nil {
			results = append(results, result)
		}

		// Probe for error leakage with malformed POST
		if result := m.probeErrorLeakage(probeClient, fn.fullURL, fn.funcName, sourceURL); result != nil {
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
	first, ok := getFuncResponse(httpClient, "GET", funcURL, "")
	if !ok {
		return nil
	}

	// 200 without auth = unauthenticated access
	if first.status != 200 {
		return nil
	}
	if !meaningfulFunctionResponse(first.body, first.contentType) {
		return nil
	}

	// Strict drop-on-fail: confirm the 200 is a stable, function-SPECIFIC
	// response, not a transient blip or a catch-all the host returns for any path
	// (including a nonexistent sibling function).
	confirmationEvidence, confirmed := m.confirmFunctionExposure(httpClient, funcURL, first.body)
	if !confirmed {
		return nil
	}

	responseStr := first.fullResponse
	if len(responseStr) > 4096 {
		responseStr = responseStr[:4096] + "\n... (truncated)"
	}

	return &output.ResultEvent{
		ModuleID:           ModuleID,
		RecordKind:         output.RecordKindCandidate,
		EvidenceGrade:      output.EvidenceGradeDifferential,
		URL:                funcURL,
		Matched:            funcURL,
		Request:            first.rawRequest,
		Response:           responseStr,
		AdditionalEvidence: confirmationEvidence,
		Info: output.Info{
			Name:        fmt.Sprintf("Public Firebase Cloud Function Candidate (%s)", funcName),
			Description: fmt.Sprintf("Cloud Function %q at %s returns a stable, function-specific nontrivial response without credentials. Public HTTP functions are supported; sensitive data or unauthorized state access was not established.", funcName, funcURL),
			Severity:    severity.Medium,
			Confidence:  severity.Firm,
			Tags:        []string{"firebase", "cloud-functions", "unauthenticated"},
		},
		Metadata: map[string]any{
			"function":                 funcName,
			"source":                   sourceURL,
			"credential_free":          true,
			"sensitive_data_confirmed": false,
		},
	}
}

func (m *Module) probeErrorLeakage(
	httpClient *http.Requester,
	funcURL string,
	funcName string,
	sourceURL string,
) *output.ResultEvent {
	malformedBody := `{invalid json`
	first, ok := getFuncResponse(httpClient, "POST", funcURL, malformedBody)
	if !ok || first.status < 400 || first.status >= 600 {
		return nil
	}
	matchedMarkers, categories := stackLeakEvidence(first.body)
	if len(matchedMarkers) < 2 || categories < 2 {
		return nil
	}

	// Strict drop-on-fail: the error markers must be INTRODUCED by the malformed
	// input — markers that also appear in a clean response are static boilerplate
	// (a CDN/proxy error template), not payload-driven leakage.
	clean, ok := getFuncResponse(httpClient, "GET", funcURL, "")
	if !ok {
		return nil
	}
	var introduced []string
	for _, marker := range matchedMarkers {
		if !strings.Contains(clean.body, marker) {
			introduced = append(introduced, marker)
		}
	}
	if len(introduced) < 2 || stackMarkerCategoryCount(introduced) < 2 {
		return nil
	}
	matchedMarkers = introduced

	// Replay the malformed request and require every introduced anchor again.
	replay, ok := getFuncResponse(httpClient, "POST", funcURL, malformedBody)
	if !ok || replay.status != first.status {
		return nil
	}
	for _, marker := range matchedMarkers {
		if !strings.Contains(replay.body, marker) {
			return nil
		}
	}

	responseStr := first.fullResponse
	if len(responseStr) > 4096 {
		responseStr = responseStr[:4096] + "\n... (truncated)"
	}

	return &output.ResultEvent{
		ModuleID:         ModuleID,
		RecordKind:       output.RecordKindFinding,
		EvidenceGrade:    output.EvidenceGradeImpact,
		URL:              funcURL,
		Matched:          funcURL,
		Request:          first.rawRequest,
		Response:         responseStr,
		ExtractedResults: matchedMarkers,
		AdditionalEvidence: []string{
			output.BuildEvidence("clean function control", clean.rawRequest, clean.fullResponse),
			output.BuildEvidence("malformed request replay", replay.rawRequest, replay.fullResponse),
		},
		Info: output.Info{
			Name:        fmt.Sprintf("Firebase Cloud Function Error Leakage (%s)", funcName),
			Description: fmt.Sprintf("Cloud Function %q reproducibly returns multiple payload-introduced stack-trace/internal-path anchors for malformed JSON; the clean control lacks them.", funcName),
			Severity:    severity.Low,
			Confidence:  severity.Certain,
			Tags:        []string{"firebase", "cloud-functions", "info-disclosure"},
		},
		Metadata: map[string]any{
			"function":           funcName,
			"source":             sourceURL,
			"introduced_markers": len(matchedMarkers),
			"replayed":           true,
		},
	}
}

// getFuncResponse issues a credential-free absolute Cloud Functions request and
// captures the full exchange. Known edge challenges and incomplete responses
// fail closed.
func getFuncResponse(httpClient *http.Requester, method, funcURL, body string) (functionResponse, bool) {
	host := extractHost(funcURL)
	var rawReq string
	if body == "" {
		rawReq = fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\nAccept: application/json\r\n\r\n", method, funcURL, host)
	} else {
		rawReq = fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
			method, funcURL, host, len(body), body)
	}
	fuzzedReq, err := httpmsg.ParseRawRequest(rawReq)
	if err != nil {
		return functionResponse{}, false
	}
	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoClustering: true, NoRedirects: true})
	if err != nil {
		return functionResponse{}, false
	}
	defer resp.Close()
	if resp.Response() == nil || infra.IsBlockedResponse(resp) {
		return functionResponse{}, false
	}
	return functionResponse{
		status:       resp.Response().StatusCode,
		body:         resp.BodyString(),
		contentType:  strings.ToLower(resp.Response().Header.Get("Content-Type")),
		rawRequest:   rawReq,
		fullResponse: resp.FullResponseString(),
	}, true
}

// confirmFunctionExposure confirms an unauthenticated 200 is a stable,
// function-specific response: it must reproduce (stable 200, body textually
// equivalent to the first hit), and a nonexistent sibling function must NOT
// return the same 200 (which would mean the host serves a catch-all). Incomplete
// controls fail closed and the replay/decoy exchanges are retained as evidence.
func (m *Module) confirmFunctionExposure(httpClient *http.Requester, funcURL, firstBody string) ([]string, bool) {
	replay, ok := getFuncResponse(httpClient, "GET", funcURL, "")
	if !ok {
		return nil, false
	}
	if replay.status != 200 || !modkit.BodiesSimilar(firstBody, replay.body) {
		return nil, false
	}

	nonexistentURL := funcURL + "-" + modkit.FreshCanary()
	decoy, ok := getFuncResponse(httpClient, "GET", nonexistentURL, "")
	if !ok {
		return nil, false
	}
	if decoy.status == 200 && modkit.BodiesSimilar(firstBody, decoy.body) {
		return nil, false
	}
	return []string{
		output.BuildEvidence("function replay", replay.rawRequest, replay.fullResponse),
		output.BuildEvidence("nonexistent-function control", decoy.rawRequest, decoy.fullResponse),
	}, true
}

func meaningfulFunctionResponse(body, contentType string) bool {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" || strings.EqualFold(trimmed, "ok") || trimmed == "{}" || trimmed == "[]" || trimmed == "null" {
		return false
	}
	if strings.Contains(contentType, "json") {
		var value any
		if json.Unmarshal([]byte(trimmed), &value) != nil {
			return false
		}
		switch typed := value.(type) {
		case map[string]any:
			return len(typed) > 0
		case []any:
			return len(typed) > 0
		default:
			return false
		}
	}
	return strings.Contains(contentType, "html") && len(trimmed) >= 100
}

func stackLeakEvidence(body string) ([]string, int) {
	var markers []string
	categories := map[string]bool{}
	for _, marker := range stackTraceMarkers {
		if !strings.Contains(body, marker) {
			continue
		}
		markers = append(markers, marker)
		categories[stackMarkerCategory(marker)] = true
	}
	return markers, len(categories)
}

func stackMarkerCategoryCount(markers []string) int {
	categories := map[string]bool{}
	for _, marker := range markers {
		categories[stackMarkerCategory(marker)] = true
	}
	return len(categories)
}

func stackMarkerCategory(marker string) string {
	switch marker {
	case "at Object.", "at Module.", "Traceback (most recent call last)", `File "/workspace/`:
		return "frame"
	case "/workspace/", "node_modules/":
		return "path"
	default:
		return "exception"
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
