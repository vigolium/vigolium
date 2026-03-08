package express_debug_probe

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// stackTraceMarkers indicates stack trace leakage in error responses.
var stackTraceMarkers = []string{
	"at ",
	"/usr/src/app/",
	"node_modules/",
	".ts:",
	".js:",
}

// expressMarkers indicates Express.js debug information.
var expressMarkers = []string{
	"NODE_ENV",
	"express",
	"Error:",
}

// nestjsMarkers indicates NestJS debug information.
var nestjsMarkers = []string{
	"\"statusCode\"",
	"\"error\"",
}

// filePathRegex matches Unix and Windows file paths in error responses.
var filePathRegex = regexp.MustCompile(`(?:/[a-zA-Z0-9._-]+){3,}|[A-Z]:\\(?:[a-zA-Z0-9._-]+\\){2,}`)

// numericSegmentRegex matches numeric path segments for type-mismatch probing.
var numericSegmentRegex = regexp.MustCompile(`/(\d+)(?:/|$)`)

// Module implements the Express debug probe active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Express Debug Probe module.
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
		ds: dedup.LazyDiskSet("express_debug_probe"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// IncludesBaseCanProcess returns false because this module uses a custom CanProcess.
func (m *Module) IncludesBaseCanProcess() bool { return false }

// CanProcess returns true if the request has a response.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	return ctx != nil && ctx.Request() != nil && ctx.Response() != nil
}

// ScanPerRequest probes for Express/NestJS debug information leakage.
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

	// Dedup by host
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	// Fingerprint 404 response body hash
	notFoundHash := get404Hash(ctx, httpClient)

	var results []*output.ResultEvent
	target := ctx.Target()

	// Probe 1: Random 404 endpoint to trigger default error handler
	if r := probeRandomEndpoint(ctx, httpClient, target, host, notFoundHash); r != nil {
		results = append(results, r)
	}

	// Probe 2: Malformed JSON body
	if r := probeMalformedJSON(ctx, httpClient, target, host, notFoundHash); r != nil {
		results = append(results, r)
	}

	// Probe 3: Type mismatch on numeric path segments
	if rs := probeTypeMismatch(ctx, httpClient, target, host, notFoundHash); len(rs) > 0 {
		results = append(results, rs...)
	}

	return results, nil
}

// probeRandomEndpoint sends a GET to a non-existent path to trigger the default error handler.
func probeRandomEndpoint(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	target, host, notFoundHash string,
) *output.ResultEvent {
	probePath := "/vgn-express-debug-test"

	probeRaw, err := httpmsg.SetPath(ctx.Request().Raw(), probePath)
	if err != nil {
		return nil
	}
	probeRaw, _ = httpmsg.SetMethod(probeRaw, "GET")

	probeReq, err := httpmsg.ParseRawRequest(string(probeRaw))
	if err != nil {
		return nil
	}
	probeReq = probeReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(probeReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil
	}

	body := resp.Body().String()
	evidence := analyzeErrorResponse(body)
	if len(evidence) == 0 {
		return nil
	}

	// Skip if body hash matches known 404 page without debug info
	if notFoundHash != "" && utils.Sha1(body) == notFoundHash && len(evidence) == 0 {
		return nil
	}

	return buildResult(target, host, "Random 404 Endpoint", probePath,
		"Default error handler leaks debug information",
		evidence, string(probeRaw), resp.FullResponse().String())
}

// probeMalformedJSON sends a POST with malformed JSON to trigger parsing errors.
func probeMalformedJSON(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	target, host, notFoundHash string,
) *output.ResultEvent {
	// Use the current path as the target for malformed JSON
	probeRaw := ctx.Request().Raw()

	probeRaw, _ = httpmsg.SetMethod(probeRaw, "POST")
	probeRaw, _ = httpmsg.SetBody(probeRaw, []byte("{"))
	probeRaw, _ = httpmsg.AddOrReplaceHeader(probeRaw, "Content-Type", "application/json")

	probeReq, err := httpmsg.ParseRawRequest(string(probeRaw))
	if err != nil {
		return nil
	}
	probeReq = probeReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(probeReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil
	}

	body := resp.Body().String()
	if notFoundHash != "" && utils.Sha1(body) == notFoundHash {
		return nil
	}

	evidence := analyzeErrorResponse(body)
	if len(evidence) == 0 {
		return nil
	}

	path := ctx.Request().Path()
	return buildResult(target, host, "Malformed JSON", path,
		"Malformed JSON body triggers verbose error response",
		evidence, string(probeRaw), resp.FullResponse().String())
}

// probeTypeMismatch replaces numeric path segments with non-numeric values.
func probeTypeMismatch(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	target, host, notFoundHash string,
) []*output.ResultEvent {
	path := ctx.Request().Path()
	matches := numericSegmentRegex.FindAllStringIndex(path, -1)
	if len(matches) == 0 {
		return nil
	}

	var results []*output.ResultEvent

	// Replace numeric segments with "not-a-number"
	mutatedPath := numericSegmentRegex.ReplaceAllStringFunc(path, func(match string) string {
		// Preserve leading slash and trailing slash if present
		prefix := "/"
		suffix := ""
		if strings.HasSuffix(match, "/") {
			suffix = "/"
		}
		return prefix + "not-a-number" + suffix
	})

	probeRaw, err := httpmsg.SetPath(ctx.Request().Raw(), mutatedPath)
	if err != nil {
		return nil
	}
	probeRaw, _ = httpmsg.SetMethod(probeRaw, "GET")

	probeReq, err := httpmsg.ParseRawRequest(string(probeRaw))
	if err != nil {
		return nil
	}
	probeReq = probeReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(probeReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil
	}

	body := resp.Body().String()
	if notFoundHash != "" && utils.Sha1(body) == notFoundHash {
		return nil
	}

	evidence := analyzeErrorResponse(body)
	if len(evidence) == 0 {
		return nil
	}

	results = append(results, buildResult(target, host, "Type Mismatch", mutatedPath,
		"Type-mismatch parameter triggers verbose error response",
		evidence, string(probeRaw), resp.FullResponse().String()))

	return results
}

// analyzeErrorResponse checks an error response body for debug information leakage.
func analyzeErrorResponse(body string) []string {
	if body == "" {
		return nil
	}

	var evidence []string

	// Check stack trace markers
	for _, marker := range stackTraceMarkers {
		if strings.Contains(body, marker) {
			evidence = append(evidence, fmt.Sprintf("Stack trace marker: %s", marker))
		}
	}

	// Check Express markers
	for _, marker := range expressMarkers {
		if strings.Contains(body, marker) {
			evidence = append(evidence, fmt.Sprintf("Express marker: %s", marker))
		}
	}

	// Check NestJS markers
	nestjsCount := 0
	for _, marker := range nestjsMarkers {
		if strings.Contains(body, marker) {
			nestjsCount++
		}
	}
	// Require both statusCode and error for NestJS detection
	if nestjsCount >= 2 {
		evidence = append(evidence, "NestJS error response detected")
	}

	// Check for validation error arrays (NestJS class-validator)
	if strings.Contains(body, "\"message\"") && strings.Contains(body, "[") && strings.Contains(body, "\"statusCode\"") {
		evidence = append(evidence, "NestJS validation error array detected")
	}

	// Check for file paths
	if filePathRegex.MatchString(body) {
		matches := filePathRegex.FindStringSubmatch(body)
		if len(matches) > 0 {
			evidence = append(evidence, fmt.Sprintf("File path disclosed: %s", matches[0]))
		}
	}

	return evidence
}

// get404Hash fetches a known-missing path to fingerprint the 404 page.
func get404Hash(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester) string {
	notFoundPath := "/vigolium-nonexistent-path-404-check"
	raw, err := httpmsg.SetPath(ctx.Request().Raw(), notFoundPath)
	if err != nil {
		return ""
	}
	raw, _ = httpmsg.SetMethod(raw, "GET")

	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return ""
	}
	req = req.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(req, http.Options{})
	if err != nil {
		return ""
	}
	defer resp.Close()

	return utils.Sha1(resp.Body().String())
}

func buildResult(target, host, probeName, probePath, desc string, evidence []string, request, response string) *output.ResultEvent {
	extracted := []string{
		fmt.Sprintf("Probe: %s", probeName),
		fmt.Sprintf("Endpoint: %s", probePath),
	}
	extracted = append(extracted, evidence...)

	return &output.ResultEvent{
		ModuleID: ModuleID,
		Host:     host,
		URL:      target,
		Matched:  fmt.Sprintf("%s%s", target, probePath),
		Request:  request,
		Response: response,
		ExtractedResults: extracted,
		Info: output.Info{
			Name:        fmt.Sprintf("Express Debug Info: %s", probeName),
			Description: desc,
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        []string{"express", "nestjs", "debug", "information-disclosure", "stack-trace"},
			Reference: []string{
				"https://expressjs.com/en/guide/error-handling.html",
				"https://docs.nestjs.com/exception-filters",
			},
		},
	}
}
