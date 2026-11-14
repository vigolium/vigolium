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

// stackTraceSubstrings are literal substrings that only appear in real Node.js
// stack traces or debug dumps. Generic tokens like "at " or ".js:" are excluded
// because they match ordinary prose and URLs. A bare "node_modules/" was removed
// too: it appears in benign asset URLs, webpack sourcemap comments, and bundle
// paths, so it is matched only as a real file path (nodeModulesPathRegex below).
var stackTraceSubstrings = []string{
	"/usr/src/app/",
}

// nodeModulesPathRegex matches a node_modules source file with a stack-frame
// line:column suffix ("node_modules/express/lib/router/layer.js:95:5") — the form
// that appears in a genuine Node.js stack frame, including the relative-path frame
// that nodeStackTraceRegex (which requires a leading slash after "at (") misses. A
// bare "node_modules/" mention or a static asset URL (no :line:col) is excluded,
// since those appear in benign bundles, sourcemaps, and asset references.
var nodeModulesPathRegex = regexp.MustCompile(`node_modules/[A-Za-z0-9_.@/-]+\.(?:js|ts|mjs|cjs):\d+:\d+`)

// nodeStackTraceRegex matches a real Node.js stack frame:
//
//	"at functionName (/abs/path/file.js:10:5)" or "at /abs/path/file.js:10:5".
//
// The line:column suffix is the strong signal — prose rarely produces it.
var nodeStackTraceRegex = regexp.MustCompile(`at\s+(?:[^\s()]+\s+)?\(?[/\\][^\s()]+\.(?:js|ts|mjs|cjs):\d+:\d+\)?`)

// nodeEnvRegex matches NODE_ENV in a config-dump context (NODE_ENV=... or "NODE_ENV": ...),
// not a bare mention in documentation prose.
var nodeEnvRegex = regexp.MustCompile(`NODE_ENV\s*[=:]`)

// filesystemPathRegex matches absolute filesystem paths that look like real
// server file locations, not URL routes. Requires a known top-level directory
// and a file extension.
var filesystemPathRegex = regexp.MustCompile(`(?:/(?:home|usr|var|opt|root|app|srv|tmp|Users|mnt|etc|private)/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*\.[A-Za-z0-9]+)|(?:[A-Z]:\\(?:[A-Za-z0-9._-]+\\)+[A-Za-z0-9._-]+\.[A-Za-z0-9]+)`)

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
	if !modkit.BeginHostProbeFor(scanCtx, httpClient, &m.ds, ctx) {
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

	// All three probes prove the SAME signal — this host leaks debug info — so
	// collapse them into one finding (one http_record per host); the other probes
	// ride along as inline evidence instead of each writing their own record.
	return modkit.CollapseFindings(results, modkit.CollapseSpec{
		Key: func(*output.ResultEvent) string { return host },
	}), nil
}

// probeRandomEndpoint sends a GET to a non-existent path to trigger the default error handler.
func probeRandomEndpoint(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	target, host, notFoundHash string,
) *output.ResultEvent {
	probePath := "/vigolium-express-debug-test"

	probeRaw, err := httpmsg.SetPath(ctx.Request().Raw(), probePath)
	if err != nil {
		return nil
	}
	probeRaw, _ = httpmsg.SetMethod(probeRaw, "GET")

	// probeRaw is well-formed raw, so wrap directly instead of re-parsing on this hot path.
	probeReq := httpmsg.NewRequestResponseRaw(probeRaw, ctx.Service())

	resp, _, err := httpClient.Execute(probeReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil
	}

	body := resp.Body().String()

	// Skip if the probe returned the host's generic 404 page (a catch-all shell):
	// a debug marker inside the standard 404 is page noise, not a probe-specific
	// leak. Checked BEFORE evidence analysis, mirroring the other two probes — the
	// previous `&& len(evidence) == 0` made this guard dead code (evidence is
	// already non-empty here), so a catch-all shell carrying a marker still emitted.
	if notFoundHash != "" && utils.Sha1(body) == notFoundHash {
		return nil
	}

	evidence := analyzeErrorResponse(body)
	if len(evidence) == 0 {
		return nil
	}

	return buildResult(target, host, "Random 404 Endpoint", probePath,
		"Default error handler leaks debug information",
		evidence, string(probeRaw), resp.FullResponseString())
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

	// probeRaw is well-formed raw, so wrap directly instead of re-parsing on this hot path.
	probeReq := httpmsg.NewRequestResponseRaw(probeRaw, ctx.Service())

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
		evidence, string(probeRaw), resp.FullResponseString())
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

	// probeRaw is well-formed raw, so wrap directly instead of re-parsing on this hot path.
	probeReq := httpmsg.NewRequestResponseRaw(probeRaw, ctx.Service())

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
		evidence, string(probeRaw), resp.FullResponseString()))

	return results
}

// analyzeErrorResponse checks an error response body for debug information leakage.
// Only substantive evidence of a leak (real stack frames, internal filesystem
// paths, NODE_ENV dumps) is returned. Standard framework error shapes such as
// NestJS's `{"statusCode":…,"error":…}` are intentionally NOT treated as
// evidence because they are the documented error format, not a debug leak.
func analyzeErrorResponse(body string) []string {
	if body == "" {
		return nil
	}

	var evidence []string

	// Literal substrings that only show up in real stack traces / debug dumps.
	for _, marker := range stackTraceSubstrings {
		if strings.Contains(body, marker) {
			evidence = append(evidence, fmt.Sprintf("Stack trace marker: %s", marker))
		}
	}

	// A node_modules path naming a real source file (stack frame / module-resolution error).
	if m := nodeModulesPathRegex.FindString(body); m != "" {
		evidence = append(evidence, fmt.Sprintf("node_modules path disclosed: %s", m))
	}

	// Real Node.js stack frame with line:column suffix.
	if m := nodeStackTraceRegex.FindString(body); m != "" {
		evidence = append(evidence, fmt.Sprintf("Node.js stack frame: %s", m))
	}

	// NODE_ENV appearing as a config/env entry (NODE_ENV=... or "NODE_ENV": ...).
	if nodeEnvRegex.MatchString(body) {
		evidence = append(evidence, "NODE_ENV disclosed")
	}

	// Absolute filesystem path with a known top-level directory and file extension.
	if m := filesystemPathRegex.FindString(body); m != "" {
		evidence = append(evidence, fmt.Sprintf("File path disclosed: %s", m))
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

	// raw is well-formed raw, so wrap directly instead of re-parsing on this hot path.
	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())

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
		ModuleID:         ModuleID,
		Host:             host,
		URL:              target,
		Matched:          fmt.Sprintf("%s%s", target, probePath),
		Request:          request,
		Response:         response,
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
