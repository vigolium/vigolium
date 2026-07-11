package postmessage_handler_detect

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

const (
	// originWindow is how far past a listener match we look for an origin /
	// source validation token (catches the common top-of-handler guard clause,
	// e.g. `if (e.origin !== ...) return;`).
	originWindow = 500
	// snippetContext is the number of bytes of surrounding code captured as
	// evidence on each side of a match.
	snippetContext = 40
	// maxMatchesPerKind caps the number of evidence snippets per finding bucket
	// so a framework bundle with many handlers does not produce huge findings.
	maxMatchesPerKind = 25
)

var (
	// addEventListenerRe matches a window-scoped `addEventListener("message", ...)`.
	// The prefix alternation accepts an explicit window/self/globalThis receiver
	// OR a bare global call (boundary char / start of input), but NOT
	// `someObj.addEventListener` — the leading `.` is excluded so WebSocket,
	// Worker, EventSource and BroadcastChannel message listeners do not match.
	// Group 1 captures the start of the handler argument for inline-vs-named
	// classification.
	addEventListenerRe = regexp.MustCompile(
		`(?:(?:window|self|globalThis)\.|[^.\w$]|^)addEventListener\s*\(\s*['"]message['"]\s*,\s*(.{0,80})`,
	)

	// onMessageRe matches a window-scoped `window.onmessage = ...` assignment.
	// Bare `.onmessage =` is intentionally excluded — it is dominated by
	// WebSocket / EventSource / Worker handlers, not postMessage. Group 1
	// captures the start of the handler for classification.
	onMessageRe = regexp.MustCompile(
		`(?:window|self|globalThis)\.onmessage\s*=\s*(.{0,80})`,
	)

	// wildcardSendRe matches a `postMessage(<message>, "*")` call: the wildcard
	// target origin. Worker/MessagePort `postMessage` takes no origin argument,
	// so this pattern is inherently scoped to window-style postMessage and does
	// not false-positive on them. `[^;]` keeps the match inside one statement;
	// the wildcard string must be immediately followed by `)` or `,` so an
	// object literal such as `postMessage({k:"*"})` does not match.
	//
	// Group 1 captures the receiver chain before `.postMessage` (e.g.
	// `window.parent`, `iframe.contentWindow`, or a minified alias `P`; empty for
	// a bare `postMessage(`), and group 2 captures the message-payload expression.
	// Both drive false-positive suppression: a same-window/self receiver posting a
	// trivial scheduler token is the setImmediate/setTimeout(0) polyfill emitted by
	// bundlers, not a cross-document data leak.
	wildcardSendRe = regexp.MustCompile(
		`(?:([\w$][\w$.\[\]]*)\s*\.\s*)?postMessage\s*\(\s*([^;]{0,500}?)\s*,\s*['"]\*['"]\s*[,)]`,
	)

	// payloadCoercionRe matches a scalar string-coercion (`x + ""`, `"" + x`, and
	// the '' / `` variants): the setImmediate/setTimeout(0) polyfill posts a
	// numeric/opaque token coerced to a string, which carries no exfiltratable
	// data, so the wildcard "*" target is harmless.
	payloadCoercionRe = regexp.MustCompile("(?:\\+\\s*(?:''|\"\"|``))|(?:(?:''|\"\"|``)\\s*\\+)")

	// inlineHandlerRe reports that a captured handler argument is an inline
	// function (function expression, arrow function, or async variant) whose
	// body we can therefore inspect for an origin check.
	inlineHandlerRe = regexp.MustCompile(
		`^(?:async\s+)?(?:function\b|\(|[A-Za-z_$][\w$]*\s*=>)`,
	)
)

// Module implements the passive postMessage handler / wildcard-send detector.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new JavaScript postMessage Handler Detected module.
func New() *Module {
	m := &Module{
		BasePassiveModule: modkit.NewBasePassiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.PassiveScanScopeResponse,
		),
		ds: dedup.LazyDiskSet("postmessage_handler_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// CanProcess accepts responses with JS/TS content types, JS/TS/Vue/Svelte URL
// paths, or HTML responses (for inline scripts).
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Response() == nil {
		return false
	}
	if len(ctx.Response().Body()) == 0 {
		return false
	}

	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if modkit.IsJSOrTSContentType(ct) || strings.Contains(ct, "text/html") {
		return true
	}

	if u, err := ctx.URL(); err == nil {
		pathLower := strings.ToLower(u.Path)
		for _, ext := range modkit.JSExtensionsExtended {
			if strings.HasSuffix(pathLower, ext) {
				return true
			}
		}
	}

	return false
}

// ScanPerRequest scans the response body for window message handlers and
// wildcard-origin postMessage sends.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	// Dedup by host+path — scan each endpoint once.
	var diskSet *dedup.DiskSet
	if scanCtx != nil {
		diskSet = m.ds.Get(scanCtx.DedupMgr())
	}
	dedupKey := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	pathLower := strings.ToLower(urlx.Path)
	if strings.Contains(pathLower, "test") ||
		strings.Contains(pathLower, "spec") ||
		strings.Contains(pathLower, "mock") {
		return nil, nil
	}

	body := ctx.Response().BodyToString()

	var (
		crossDocSends     []string // Medium — cross-document postMessage(data, "*")
		selfSends         []string // Low    — same-window/self postMessage(x, "*")
		uncheckedHandlers []string // Medium — inline handler, no origin/source check
		detectedHandlers  []string // Info   — handler that validates, or named ref
	)

	// A service worker's `message` events can only be delivered by same-origin
	// clients/workers it controls — a cross-origin page cannot postMessage to
	// another origin's service worker — so an "unchecked" SW handler is not the
	// cross-origin DOM-XSS class and stays Info. This suppresses the workbox
	// service-worker false positive (self.addEventListener("message", …) in
	// service-worker.js / sw.js).
	swScript := isServiceWorkerScript(urlx.Path)

	// Receivers: addEventListener("message", ...) and window.onmessage = ...
	// Both forms classify identically: an inline handler whose body lacks an
	// origin/source check is Medium; anything else (validates origin, or a named
	// reference we can't inspect) is Info.
	classifyReceivers := func(re *regexp.Regexp) {
		for _, loc := range re.FindAllStringSubmatchIndex(body, -1) {
			snippet := snippetAt(body, loc[0], loc[1])
			if !swScript && isVulnerableHandler(body, loc[0], captureGroup(body, loc, 1)) {
				uncheckedHandlers = appendCapped(uncheckedHandlers, snippet)
			} else {
				detectedHandlers = appendCapped(detectedHandlers, snippet)
			}
		}
	}
	classifyReceivers(addEventListenerRe)
	classifyReceivers(onMessageRe)

	// Sender: postMessage(..., "*"). Split by cross-document vs same-window/self.
	for _, loc := range wildcardSendRe.FindAllStringSubmatchIndex(body, -1) {
		receiver := submatch(body, loc, 1)
		payload := strings.TrimSpace(submatch(body, loc, 2))
		// Drop scheduler self-pings: a wildcard send whose payload is empty or a
		// scalar string-coercion is the setImmediate/setTimeout(0) polyfill
		// (postMessage("","*"), postMessage(id+"","*")) emitted by bundlers. It
		// carries no data, so "*" is harmless — this is the dominant
		// postMessage(...,"*") false positive in minified vendor bundles.
		if isSchedulerPing(payload) {
			continue
		}
		snippet := snippetAt(body, loc[0], loc[1])
		if isCrossDocumentReceiver(receiver) {
			crossDocSends = appendCapped(crossDocSends, snippet)
		} else {
			selfSends = appendCapped(selfSends, snippet)
		}
	}

	var results []*output.ResultEvent

	if len(crossDocSends) > 0 {
		results = append(results, m.finding(
			urlx.Host, urlx.String(),
			"postMessage Sent to Wildcard Origin (*)",
			fmt.Sprintf("Found %d cross-document postMessage call(s) using a wildcard \"*\" target origin in %s. Data is delivered to whatever origin currently occupies the target window (parent, opener, or a framed/opened window), so a malicious page that controls that location can read it.", len(crossDocSends), urlx.Path),
			severity.Medium,
			crossDocSends,
			"wildcard-send",
		))
	}
	if len(selfSends) > 0 {
		results = append(results, m.finding(
			urlx.Host, urlx.String(),
			"postMessage to Wildcard Origin (same-window)",
			fmt.Sprintf("Found %d same-window/self postMessage call(s) using a wildcard \"*\" target origin in %s. These target the current window (commonly a scheduler or worker channel), so the wildcard rarely exposes data; verify none carries a sensitive payload.", len(selfSends), urlx.Path),
			severity.Low,
			selfSends,
			"wildcard-send-self",
		))
	}
	if len(uncheckedHandlers) > 0 {
		results = append(results, m.finding(
			urlx.Host, urlx.String(),
			"postMessage Handler Without Origin Validation",
			fmt.Sprintf("Found %d window message handler(s) in %s whose inline body does not reference event.origin or event.source. Such a handler trusts messages from any window, including attacker-controlled frames or popups.", len(uncheckedHandlers), urlx.Path),
			severity.Medium,
			uncheckedHandlers,
			"unchecked-handler",
		))
	}
	if len(detectedHandlers) > 0 {
		results = append(results, m.finding(
			urlx.Host, urlx.String(),
			"postMessage Handler Detected",
			fmt.Sprintf("Found %d window message handler(s) in %s. Verify each one validates event.origin against an allowlist (and event.source where applicable) before trusting the message data.", len(detectedHandlers), urlx.Path),
			severity.Info,
			detectedHandlers,
			"handler-detected",
		))
	}

	return results, nil
}

// isVulnerableHandler reports whether a receiver should be treated as missing
// origin validation (→ Medium). It returns true only when the handler is an
// inline function whose body window contains no origin/source token: that is
// the only case where we can positively see the whole handler and confirm the
// check is absent. Named-function references (body not visible) and handlers
// that reference origin/source stay Info — this keeps the Medium verdict
// conservative and avoids false positives.
func isVulnerableHandler(body string, matchStart int, handler string) bool {
	if hasOriginCheck(body, matchStart) {
		return false
	}
	return inlineHandlerRe.MatchString(strings.TrimSpace(handler))
}

// hasOriginCheck reports whether an origin/source validation token appears in
// the window of code immediately following the listener match.
func hasOriginCheck(body string, matchStart int) bool {
	end := matchStart + originWindow
	if end > len(body) {
		end = len(body)
	}
	window := strings.ToLower(body[matchStart:end])
	return strings.Contains(window, ".origin") || strings.Contains(window, ".source")
}

// captureGroup returns submatch group n (1-based) from a FindAllSubmatchIndex
// location, or "" if it was not captured.
func captureGroup(body string, loc []int, n int) string {
	start, end := loc[2*n], loc[2*n+1]
	if start < 0 || end < 0 || end > len(body) {
		return ""
	}
	return body[start:end]
}

// submatch returns capture group n (1-based) from a FindAllStringSubmatchIndex
// location, or "" if the group did not participate in the match.
func submatch(body string, loc []int, n int) string {
	if 2*n+1 >= len(loc) {
		return ""
	}
	start, end := loc[2*n], loc[2*n+1]
	if start < 0 || end < 0 || end > len(body) {
		return ""
	}
	return body[start:end]
}

// isSchedulerPing reports whether a wildcard-send message payload carries no
// exfiltratable data: an empty-string/template literal, or a scalar coerced to a
// string (`x+""`). This is the setImmediate/setTimeout(0) polyfill pattern that
// bundlers emit (postMessage("","*"), postMessage(id+"","*")), where "*" is
// harmless because nothing meaningful is transmitted.
func isSchedulerPing(payload string) bool {
	switch payload {
	case "", `""`, `''`, "``":
		return true
	}
	return payloadCoercionRe.MatchString(payload)
}

// crossDocAccessors are the explicit cross-document window accessors: reaching
// one of them means the wildcard send targets a *different* document, where "*"
// can leak data to an attacker-controlled window.
var crossDocAccessors = []string{
	".parent", ".opener", ".top", ".frames", ".contentwindow", ".contentdocument",
}

// crossDocNameHints are substrings in a receiver's trailing identifier that name
// it for another window/frame/popup (e.g. targetWindow, childFrame, popupWin).
var crossDocNameHints = []string{
	"window", "frame", "iframe", "popup", "child", "target",
	"remote", "embed", "peer", "opener",
}

// isCrossDocumentReceiver reports whether a postMessage receiver expression
// targets a different document. A bare self target (window/self/globalThis/
// global/this or a minified alias such as `P`/`t`) is NOT cross-document — those
// are the same-window scheduler/library sends — and returns false so they stay
// Low rather than Medium.
func isCrossDocumentReceiver(receiver string) bool {
	r := strings.ToLower(strings.TrimSpace(receiver))
	if r == "" {
		return false
	}
	for _, acc := range crossDocAccessors {
		if strings.Contains(r, acc) {
			return true
		}
	}
	// Inspect the trailing identifier segment.
	seg := r
	if i := strings.LastIndex(seg, "."); i >= 0 {
		seg = seg[i+1:]
	}
	seg = strings.TrimRight(seg, "[]0123456789")
	switch seg {
	case "window", "self", "globalthis", "global", "this":
		return false
	case "top", "parent":
		// A bare `top`/`parent` receiver still targets an ancestor document.
		return true
	}
	for _, hint := range crossDocNameHints {
		if strings.Contains(seg, hint) {
			return true
		}
	}
	return false
}

// isServiceWorkerScript reports whether a path serves a service worker, whose
// `message` events are same-origin by construction (only clients the worker
// controls can post to it), so its handlers are not the cross-origin DOM-XSS
// class the Medium unchecked-handler verdict targets.
func isServiceWorkerScript(path string) bool {
	p := strings.ToLower(path)
	if strings.Contains(p, "service-worker") || strings.Contains(p, "serviceworker") || strings.Contains(p, "workbox") {
		return true
	}
	return strings.HasSuffix(p, "/sw.js") || strings.HasSuffix(p, "-sw.js")
}

// snippetAt returns a trimmed, truncated slice of body around [start,end) for
// use as finding evidence.
func snippetAt(body string, start, end int) string {
	ctxStart := start - snippetContext
	if ctxStart < 0 {
		ctxStart = 0
	}
	ctxEnd := end + snippetContext
	if ctxEnd > len(body) {
		ctxEnd = len(body)
	}
	return modkit.Truncate(strings.TrimSpace(body[ctxStart:ctxEnd]), 150)
}

// appendCapped appends s unless the slice has reached maxMatchesPerKind.
func appendCapped(dst []string, s string) []string {
	if len(dst) >= maxMatchesPerKind {
		return dst
	}
	return append(dst, s)
}

// finding builds a ResultEvent for a detection bucket.
func (m *Module) finding(host, url, name, desc string, sev severity.Severity, extracted []string, kind string) *output.ResultEvent {
	recordKind := output.RecordKindObservation
	grade := output.EvidenceGradeObservation
	if kind == "wildcard-send" || kind == "unchecked-handler" {
		recordKind = output.RecordKindCandidate
		grade = output.EvidenceGradeCandidate
		desc += " This is a static candidate: sensitive payload flow, attacker-controlled window reachability, and a dangerous message-data sink were not proven."
	}
	return &output.ResultEvent{
		ModuleID:         ModuleID,
		RecordKind:       recordKind,
		EvidenceGrade:    grade,
		Host:             host,
		URL:              url,
		Matched:          url,
		ExtractedResults: extracted,
		Info: output.Info{
			Name:        name,
			Description: desc,
			Severity:    sev,
			Confidence:  ModuleConfidence,
			Tags:        ModuleTags,
			Reference: []string{
				"https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage",
				"https://labs.detectify.com/2016/12/08/the-pitfalls-of-postmessage/",
			},
		},
		Metadata: map[string]any{
			"kind":                     kind,
			"matchCount":               len(extracted),
			"connected_flow_proven":    false,
			"sensitive_payload_proven": false,
			"dangerous_sink_proven":    false,
		},
	}
}
