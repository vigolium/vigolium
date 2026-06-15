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
	wildcardSendRe = regexp.MustCompile(
		`postMessage\s*\([^;]{0,500}?,\s*['"]\*['"]\s*[,)]`,
	)

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
	diskSet := m.ds.Get(scanCtx.DedupMgr())
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
		wildcardSends     []string // Medium — postMessage(..., "*")
		uncheckedHandlers []string // Medium — inline handler, no origin/source check
		detectedHandlers  []string // Info   — handler that validates, or named ref
	)

	// Receivers: addEventListener("message", ...) and window.onmessage = ...
	// Both forms classify identically: an inline handler whose body lacks an
	// origin/source check is Medium; anything else (validates origin, or a named
	// reference we can't inspect) is Info.
	classifyReceivers := func(re *regexp.Regexp) {
		for _, loc := range re.FindAllStringSubmatchIndex(body, -1) {
			snippet := snippetAt(body, loc[0], loc[1])
			if isVulnerableHandler(body, loc[0], captureGroup(body, loc, 1)) {
				uncheckedHandlers = appendCapped(uncheckedHandlers, snippet)
			} else {
				detectedHandlers = appendCapped(detectedHandlers, snippet)
			}
		}
	}
	classifyReceivers(addEventListenerRe)
	classifyReceivers(onMessageRe)

	// Sender: postMessage(..., "*")
	for _, loc := range wildcardSendRe.FindAllStringIndex(body, -1) {
		wildcardSends = appendCapped(wildcardSends, snippetAt(body, loc[0], loc[1]))
	}

	var results []*output.ResultEvent

	if len(wildcardSends) > 0 {
		results = append(results, m.finding(
			urlx.Host, urlx.String(),
			"postMessage Sent to Wildcard Origin (*)",
			fmt.Sprintf("Found %d postMessage call(s) using a wildcard \"*\" target origin in %s. Data is delivered to whatever origin currently occupies the receiver window, so a malicious page that controls that location can read it.", len(wildcardSends), urlx.Path),
			severity.Medium,
			wildcardSends,
			"wildcard-send",
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
	return &output.ResultEvent{
		ModuleID:         ModuleID,
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
			"kind":       kind,
			"matchCount": len(extracted),
		},
	}
}
