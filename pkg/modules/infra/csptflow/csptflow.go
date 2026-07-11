// Package csptflow holds the Client-Side Path Traversal (CSPT) flow-recognition
// primitives shared by the passive client_path_taint detector and the active
// client_path_traversal_confirm module. Keeping the recognition heuristic — which
// taint flows count as CSPT, how a request-path prefix and method are parsed — in
// one place stops the detector and its confirmer from silently diverging: the
// confirmer must recognize exactly what the detector publishes. Neither module
// imports the other; both import this package.
package csptflow

import (
	"regexp"
	"strings"
	"sync"
	"time"

	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/vigolium/vigolium/pkg/deparos/jstangle"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// TechTagCSPTCandidate is the per-host tech tag the passive detector publishes
// and the active confirmer is fail-closed on.
const TechTagCSPTCandidate = "cspt-candidate"

// ScanTimeout bounds a single jstangle subprocess invocation. Far shorter than
// jstangle's own MaxScanTimeout, which is meant for large-bundle deobfuscation
// rather than per-response CSPT analysis.
const ScanTimeout = 20 * time.Second

// NetworkPathFlowType is jstangle's CSPT flow class: a URL-controlled source
// reaching a client-side request-path sink (fetch/XHR/axios). Confirmed
// empirically against the embedded helper.
const NetworkPathFlowType = "clientRequestInjection"

var (
	scriptBlockRe = regexp.MustCompile(`(?is)<script[^>]*>(.*?)</script>`)

	// flowSourceRe/flowSinkRe match the short Source/Sink descriptors jstangle
	// reports (e.g. "location.hash", "network.fetch") — looser than a raw-JS gate
	// because the field carries no surrounding syntax.
	flowSourceRe = regexp.MustCompile(`(?i)(location\.(search|hash|pathname|href)|URLSearchParams|document\.(URL|documentURI))`)
	flowSinkRe   = regexp.MustCompile(`(?i)(fetch|XMLHttpRequest|\.open\b|axios|\.ajax\b)`)

	// pathLiteralRe extracts the first quoted path/absolute-URL literal (the
	// constant prefix a source value is appended to).
	pathLiteralRe = regexp.MustCompile("[\"'`]((?:https?://[^\"'`]+)|/[^\"'`]*)")

	xhrMethodRe   = regexp.MustCompile(`(?i)\.open\s*\(\s*["']([A-Za-z]+)["']`)
	fetchMethodRe = regexp.MustCompile(`(?i)method\s*:\s*["']([A-Za-z]+)["']`)
)

// domXSSOwnedFlowTypes are consumed by dom_xss_taint / navigation modules and
// must never be treated as CSPT here.
var domXSSOwnedFlowTypes = map[string]struct{}{
	"domXss":             {},
	"dynamicExecution":   {},
	"scriptUrlInjection": {},
	"openRedirect":       {},
}

// Flow is a normalized CSPT request-path taint flow, annotated with its parsed
// request-path prefix and inferred HTTP method.
type Flow struct {
	Source   string
	Sink     string
	Snippet  string
	FlowType string
	Line     int
	Prefix   string
	Method   string
}

var (
	scannerOnce sync.Once
	scanner     *jstangle.Service
)

// Scanner lazily resolves the process-wide jstangle service. It returns nil when
// the embedded binary is unavailable (unsupported platform / LFS pointer), so
// callers cleanly no-op.
func Scanner() *jstangle.Service {
	scannerOnce.Do(func() {
		if s, err := jstangle.DefaultService(); err == nil {
			scanner = s
		}
	})
	return scanner
}

// NetworkPathFlows normalizes both jstangle record families, keeps the CSPT
// request-path flows, dedups by source|sink|snippet, and annotates each with its
// parsed prefix and inferred method. Pure, so it is unit-testable over synthetic
// records without a binary.
func NetworkPathFlows(domFlows []jstangle.DomFlow, browserFlows []jstangle.BrowserSecurityFlowFact) []Flow {
	type nf struct {
		source, sink, snippet, flowType string
		line                            int
	}
	norm := make([]nf, 0, len(domFlows)+len(browserFlows))
	for _, f := range domFlows {
		norm = append(norm, nf{f.Source, f.Sink, f.Snippet, f.FlowType, f.Line})
	}
	for _, f := range browserFlows {
		line := 0
		if f.Provenance.Start != nil {
			line = f.Provenance.Start.Line
		}
		norm = append(norm, nf{f.Source, f.Sink, f.Evidence, f.FlowType, line})
	}

	var out []Flow
	seen := make(map[string]struct{}, len(norm))
	for _, f := range norm {
		if !IsNetworkPathFlow(f.source, f.sink, f.snippet, f.flowType) {
			continue
		}
		key := f.source + "|" + f.sink + "|" + f.snippet
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, Flow{
			Source: f.source, Sink: f.sink, Snippet: f.snippet,
			FlowType: f.flowType, Line: f.line,
			Prefix: ParsePrefix(f.snippet), Method: InferMethod(f.snippet),
		})
	}
	return out
}

// IsNetworkPathFlow reports whether a flow is a URL source reaching a client-side
// request-path sink (CSPT) and not a DOM-XSS/redirect/execution flow owned
// elsewhere. It requires a URL source; it accepts the dedicated
// clientRequestInjection class directly, otherwise it additionally requires a
// network-request-shaped sink (the belt-and-suspenders fallback).
func IsNetworkPathFlow(source, sink, snippet, flowType string) bool {
	if _, owned := domXSSOwnedFlowTypes[flowType]; owned {
		return false
	}
	if !flowSourceRe.MatchString(source) && !flowSourceRe.MatchString(snippet) {
		return false
	}
	if flowType == NetworkPathFlowType {
		return true
	}
	return flowSinkRe.MatchString(sink) || flowSinkRe.MatchString(snippet)
}

// ParsePrefix extracts the first path/URL string literal from snippet — the
// constant prefix a source value is appended to (e.g. "/api/items/" from
// fetch('/api/items/' + location.hash)). Returns "" when none is present.
func ParsePrefix(snippet string) string {
	if m := pathLiteralRe.FindStringSubmatch(snippet); len(m) > 1 {
		return m[1]
	}
	return ""
}

// InferMethod best-effort infers the request-path sink's HTTP method, defaulting
// to GET.
func InferMethod(snippet string) string {
	if m := xhrMethodRe.FindStringSubmatch(snippet); len(m) > 1 {
		return strings.ToUpper(m[1])
	}
	if m := fetchMethodRe.FindStringSubmatch(snippet); len(m) > 1 {
		return strings.ToUpper(m[1])
	}
	low := strings.ToLower(snippet)
	for _, verb := range []string{"delete", "patch", "put", "post"} {
		if strings.Contains(low, "."+verb+"(") {
			return strings.ToUpper(verb)
		}
	}
	return "GET"
}

// ExtractJS returns the JavaScript worth analyzing from a response: the body for
// a JS response, or the concatenated inline <script> contents for an HTML page.
// Returns "" for anything else (images, CSS, JSON).
func ExtractJS(ctx *httpmsg.HttpRequestResponse, urlx *urlutil.URL) string {
	if ctx == nil {
		return ""
	}
	resp := ctx.Response()
	if resp == nil {
		return ""
	}
	body := resp.BodyToString()
	if body == "" {
		return ""
	}

	ct := strings.ToLower(resp.Header("Content-Type"))
	if strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript") {
		return body
	}

	if urlx != nil {
		path := strings.ToLower(urlx.Path)
		if strings.HasSuffix(path, ".js") || strings.HasSuffix(path, ".mjs") {
			return body
		}
	}

	if strings.Contains(ct, "html") || ct == "" {
		var sb strings.Builder
		for _, m := range scriptBlockRe.FindAllStringSubmatch(body, -1) {
			if len(m) > 1 && strings.TrimSpace(m[1]) != "" {
				sb.WriteString(m[1])
				sb.WriteString("\n;\n")
			}
		}
		return sb.String()
	}

	return ""
}
