package xss_light_scanner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/shared/xssbreakout"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/spitolas"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// Reflected XSS confirmation pipeline.
//
// The character-transform analysis only tells us a breakout *character* survived
// — it cannot tell whether the surrounding bytes form an executable context.
// Salesforce Aura, JSON echo endpoints and CSP-locked pages all reflect quotes
// and angle brackets verbatim without ever executing script, which is exactly
// the JSStringDQBreakout-style false positive this module used to report at
// High/Firm. Confirmation re-sends a real, context-shaped XSS payload and grades
// the candidate in two tiers:
//
//	tier 1 (drop)  the executable payload's breakout signature never reappears
//	               unescaped in the body — the per-char heuristic was wrong.
//	tier 2 (Low)   the signature survived but no JavaScript dialog fired (no
//	               browser, or execution blocked by CSP / a non-executing
//	               context) — reflection-only, tentative.
//	tier 3 (High)  a headless browser navigation popped alert(marker) — the
//	               canonical confirmed-XSS signal.
const (
	confirmNavTimeout    = 25 * time.Second
	confirmWaitExtra     = 700 * time.Millisecond
	maxConfirmContexts   = 3
	maxConfirmProbes     = 2 // concurrent headless browsers across the package
	maxConfirmNavs       = 4 // bounded headless navs across every candidate/context
	confirmSigPreviewLen = 48
)

// ProbeFunc navigates a URL in a headless browser and returns any JavaScript
// dialogs that fired. Injectable so tests never spawn a real browser.
type ProbeFunc func(ctx context.Context, cfg spitolas.ProbeConfig) (*spitolas.ProbeResult, error)

// probeSem bounds concurrent browser probes — each spawns a real browser
// process, far pricier than an HTTP request. Findings here are rare, so a small
// global cap is plenty.
var probeSem = make(chan struct{}, maxConfirmProbes)

func acquireProbe(ctx context.Context) (release func(), ok bool) {
	select {
	case probeSem <- struct{}{}:
		return func() { <-probeSem }, true
	case <-ctx.Done():
		return nil, false
	}
}

// confirmOutcome records how strongly a reflected-XSS candidate was confirmed.
type confirmOutcome struct {
	httpBreakout     bool   // executable payload's breakout signature survived unescaped
	browserConfirmed bool   // a JS dialog carrying our marker actually fired
	browserRan       bool   // a browser navigation was attempted
	marker           string // unique alert marker
	dialogMessage    string // captured dialog text on a confirm
	request          string // raw fuzzed request that carried the executable payload
	signature        string // the breakout signature matched in the body
	bodySnippet      string // window of the response body around the surviving signature

	fuzzedReq *httpmsg.HttpRequestResponse // parsed request, reused for browser confirm
}

// snippetAround returns a bounded window of body centred on the first occurrence
// of sig, so the finding can show the exact bytes that landed in the response.
func snippetAround(body, sig string) string {
	idx := strings.Index(body, sig)
	if idx < 0 {
		return ""
	}
	const pad = 80
	start := idx - pad
	if start < 0 {
		start = 0
	}
	end := idx + len(sig) + pad
	if end > len(body) {
		end = len(body)
	}
	return body[start:end]
}

// newConfirmMarker returns a unique, JS-safe token placed inside alert() so a
// fired dialog can be attributed to this scan and not a pre-existing page alert.
func newConfirmMarker() string {
	buf := make([]byte, 5)
	if _, err := rand.Read(buf); err != nil {
		return "vigxss0confirm"
	}
	return "vigx" + hex.EncodeToString(buf)
}

// execCandidate is one executable payload attempt: the bytes to inject plus the
// literal breakout signatures that must appear UNESCAPED in the response body for
// the breakout to count (strongest first).
type execCandidate struct {
	payload    string
	signatures []string
}

// execContextCandidates returns the executable XSS payloads to try for a
// reflection context, ordered most-confident first. The marker rides inside
// alert() via a template literal so it never collides with the breakout quote.
//
// For JS-string / template / code contexts it returns several candidates: the
// statement-terminator break AND operator-chaining breaks ('^alert()^',
// '-alert()-'). Operator chaining is what confirms a string reflected inside an
// *expression* (a function argument, array, or object literal) where injecting a
// statement terminator would SyntaxError and stop the whole script — the case
// the terminator-only payload silently missed (e.g. the Salesforce Apex
// 'source' parameter that a sibling scanner popped with '^alert(1)^').
func execContextCandidates(rc ReflectionContext, marker string) []execCandidate {
	alert := "alert(`" + marker + "`)"
	svg := "<svg onload=" + alert + ">"

	one := func(payload string, sigs ...string) []execCandidate {
		return []execCandidate{{payload: payload, signatures: sigs}}
	}
	// jsString builds the operator-chaining + terminator candidate set for a value
	// reflected inside a quote-delimited JS string.
	jsString := func(quote byte) []execCandidate {
		var out []execCandidate
		for _, p := range xssbreakout.JSStringPayloads(quote, alert) {
			out = append(out, execCandidate{payload: p, signatures: []string{p, alert}})
		}
		return out
	}

	switch rc {
	// Raw HTML / text node — inject a fresh element directly.
	case HTMLGeneric, HTMLTagCloseAndInject, XMLGeneric:
		return one(svg, svg)
	case HTMLAfterTitleClose:
		return one("</title>"+svg, "</title>"+svg, svg)
	case HTMLAfterXMPClose:
		return one("</xmp>"+svg, "</xmp>"+svg, svg)
	case HTMLAfterNoscriptClose:
		return one("</noscript>"+svg, "</noscript>"+svg, svg)

	// Attribute values & event/URL handlers — break the quote, close the tag,
	// inject. The quoted signature is strongest; the bare element is the
	// fallback (covers apps that strip the quote but keep the markup).
	case HTMLAttributeValueDQBreakout, JSInURLAttributeDQ, JSInEventHandlerDQ:
		return one(`">`+svg, `">`+svg, svg)
	case HTMLAttributeValueSQBreakout, JSInURLAttributeSQ, JSInEventHandlerSQ:
		return one(`'>`+svg, `'>`+svg, svg)
	case HTMLAttributeValueBTBreakout, JSInURLAttributeBT, JSInEventHandlerBT:
		return one("`>"+svg, "`>"+svg, svg)
	case HTMLAttributeValueUnquotedBreakout, JSInUnquotedURLAttribute, JSInEventHandlerUnquoted:
		return one(" "+svg, " "+svg, svg)
	case HTMLAttributeName:
		return one(">"+svg, ">"+svg, svg)

	// JS string contexts — operator chaining first, statement terminator last.
	case JSStringDQBreakout:
		return jsString('"')
	case JSStringSQBreakout:
		return jsString('\'')
	case JSTemplateLiteral:
		// ${...} template injection is the natural break; back it with backtick
		// operator-chaining for templates embedded in an expression.
		out := one("${"+alert+"}", "${"+alert+"}", alert)
		return append(out, jsString('`')...)
	case JSCodeStatement:
		return one(";"+alert+"//", ";"+alert, alert)

	// Comment contexts — close the comment, then inject.
	case HTMLCommentBreakout:
		return one("--><svg onload="+alert+">", "-->"+svg, svg)
	case JSLineComment:
		return one("\n"+alert+"//", alert)
	case JSBlockComment:
		return one("*/"+alert+"//", "*/"+alert, alert)

	default:
		return one(svg, svg)
	}
}

// prefixByName resolves the winning bypass prefix so the confirmation payload is
// shaped the same way the canary that triggered detection was.
func prefixByName(name string) BypassPrefix {
	for _, p := range BypassPrefixes {
		if p.Name == name {
			return p
		}
	}
	return BypassPrefixes[0] // "none"
}

// distinctContexts returns up to maxConfirmContexts unique reflection contexts in
// discovery order, so confirmation tries the most-confident one first.
func distinctContexts(analyses []*EscapeAnalysis, limit int) []ReflectionContext {
	seen := make(map[ReflectionContext]bool)
	var out []ReflectionContext
	for _, ea := range analyses {
		if ea == nil || seen[ea.Context] {
			continue
		}
		seen[ea.Context] = true
		out = append(out, ea.Context)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// confirmXSS builds the reflection finding, tags it with descPrefix (a strategy
// label like "[path:cut] ", or "" for none), then grades it by re-sending real
// executable payloads and, on a surviving breakout, confirming execution in a
// headless browser. It returns the graded event, or nil when the executable
// breakout never survived (drop the reflection-only false positive). encode (nil
// for most callers) pre-encodes the payload for the Encoded scanner. Shared by
// every xss-light sub-scanner so they confirm the same classes of flaw
// identically.
func confirmXSS(
	probe ProbeFunc,
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	result *XSSScanResult,
	httpClient *http.Requester,
	descPrefix string,
	encode func(string) string,
) *output.ResultEvent {
	base := buildResultEvent(ctx, ip, result)
	base.Info.Description = descPrefix + base.Info.Description
	outcome := confirmCandidate(probe, ctx, ip, result, httpClient, encode)
	return gradeConfirmedEvent(base, outcome)
}

// confirmCandidate re-sends real XSS payloads for each exploitable context and
// returns the strongest outcome. For each context it tries every executable
// candidate (operator-chaining and statement-terminator forms for JS-string
// contexts), checking the body for a surviving breakout signature and, on a hit
// for a navigable GET, confirming execution in a headless browser. It returns as
// soon as any candidate pops a dialog; otherwise it returns the richest
// surviving-breakout outcome (Low tier) or an empty outcome (caller drops it).
//
// encode, when non-nil, wraps each payload before it is sent — the Encoded
// scanner uses it to apply the same pre-encoding that detected the reflection so
// the executable payload survives the app's extra decode; the body signature is
// still matched against the decoded form. A nil probe caps the outcome at the
// HTTP-breakout (Low) tier.
//
// HTTP sends are cheap and run for every candidate; the far pricier browser navs
// are bounded by maxConfirmNavs across the whole call.
func confirmCandidate(
	probe ProbeFunc,
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	result *XSSScanResult,
	httpClient *http.Requester,
	encode func(string) string,
) confirmOutcome {
	prefix := prefixByName(result.UsedPrefix)
	marker := newConfirmMarker()
	var best confirmOutcome
	navs := 0

	for _, rc := range distinctContexts(result.ExploitableAnalyses, maxConfirmContexts) {
		for _, cand := range execContextCandidates(rc, marker) {
			out := sendExec(ctx, ip, cand, prefix, marker, httpClient, encode)
			if !out.httpBreakout {
				continue
			}
			// Remember the first surviving breakout so a Low-tier finding still
			// fires even if no browser is available or no payload pops.
			if !best.httpBreakout {
				best = out
			}
			if navs >= maxConfirmNavs {
				continue
			}
			navs++
			browserConfirm(probe, &out, out.fuzzedReq)
			if out.browserConfirmed {
				return out
			}
			best = out // keep the richest outcome that actually ran a browser
		}
	}
	return best
}

// sendExec sends one executable candidate and checks the response body for a
// surviving breakout signature. It does not touch the browser — confirmCandidate
// drives that so it can bound the number of navs across all candidates.
func sendExec(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	cand execCandidate,
	prefix BypassPrefix,
	marker string,
	httpClient *http.Requester,
	encode func(string) string,
) confirmOutcome {
	out := confirmOutcome{marker: marker}
	payload := string(prefix.Bytes) + cand.payload
	if encode != nil {
		payload = encode(payload)
	}

	fuzzedRaw := ip.BuildRequest([]byte(payload))
	out.request = string(fuzzedRaw)
	fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
	if err != nil {
		return out
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())
	out.fuzzedReq = fuzzedReq

	// NoClustering: the executable payload differs from the canary, but a fresh
	// send guarantees we never read back a cluster-cached response.
	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoClustering: true})
	if err != nil || resp == nil {
		return out
	}
	status := 0
	if r := resp.Response(); r != nil {
		status = r.StatusCode
	}
	body := resp.Body().String()
	resp.Close()

	// Redirects and error pages don't carry an exploitable reflection.
	if status >= 300 {
		return out
	}

	for _, sig := range cand.signatures {
		if sig != "" && strings.Contains(body, sig) {
			out.httpBreakout = true
			out.signature = sig
			out.bodySnippet = snippetAround(body, sig)
			break
		}
	}
	return out
}

// browserConfirm navigates the fuzzed GET request in a headless browser and
// flips browserConfirmed when a dialog carrying our marker fires. A nil probe, a
// non-GET request, or an unavailable browser simply leaves the outcome at the
// httpBreakout (Low) tier.
func browserConfirm(probe ProbeFunc, out *confirmOutcome, fuzzedReq *httpmsg.HttpRequestResponse) {
	if probe == nil {
		return
	}
	method := strings.ToUpper(fuzzedReq.Request().Method())
	if method != "GET" && method != "" {
		return
	}
	urlx, err := fuzzedReq.Request().URL()
	if err != nil {
		return
	}

	bgCtx, cancel := context.WithTimeout(context.Background(), confirmNavTimeout+5*time.Second)
	defer cancel()

	release, ok := acquireProbe(bgCtx)
	if !ok {
		return
	}
	defer release()

	out.browserRan = true
	// The error is intentionally ignored: a nav error can still carry dialogs
	// (a javascript: URL errors out *after* firing alert), so inspect dialogs
	// regardless. A truly failed probe simply yields res == nil below.
	res, _ := probe(bgCtx, spitolas.ProbeConfig{
		URL:        urlx.String(),
		WaitExtra:  confirmWaitExtra,
		NavTimeout: confirmNavTimeout,
	})
	if res == nil {
		return
	}
	for i := range res.Dialogs {
		if strings.Contains(res.Dialogs[i].Message, out.marker) {
			out.browserConfirmed = true
			out.dialogMessage = res.Dialogs[i].Message
			return
		}
	}
}

// gradeConfirmedEvent applies the confirmation tier to a heuristic reflection
// finding. It returns nil (caller drops it) when the executable payload's
// breakout signature never survived in the body — the reflection-only false
// positive this step exists to suppress. Otherwise it upgrades to High/Certain
// on a browser popup, or downgrades to Low/Tentative when the breakout survived
// the wire but no dialog fired (CSP-locked, JSON echo, non-executing context).
func gradeConfirmedEvent(base *output.ResultEvent, outcome confirmOutcome) *output.ResultEvent {
	if base == nil || !outcome.httpBreakout {
		return nil
	}

	base.Request = outcome.request

	evidenceLabel := "reflection-only payload"
	if outcome.browserConfirmed {
		evidenceLabel = "browser-confirm payload"
		base.Info.Severity = severity.High
		base.Info.Confidence = severity.Certain
		base.Info.Description += fmt.Sprintf(
			" — browser-confirmed: alert(%q) fired in a headless browser", outcome.dialogMessage,
		)
		base.ExtractedResults = append(base.ExtractedResults, "alert: "+outcome.dialogMessage)
	} else {
		base.Info.Severity = severity.Low
		base.Info.Confidence = severity.Tentative
		note := " — reflection-only: executable payload survived unescaped in the response" +
			" (signature: " + sigPreview(outcome.signature) + "), but no JavaScript dialog fired"
		if outcome.browserRan {
			note += " in a headless browser (execution likely blocked by CSP or a non-executing context)"
		} else {
			note += " (no browser confirmation was performed)"
		}
		note += "; manual verification recommended"
		base.Info.Description += note
	}

	if ev := output.BuildEvidence(evidenceLabel, outcome.request, outcome.bodySnippet); ev != "" {
		base.AdditionalEvidence = append(base.AdditionalEvidence, ev)
	}
	return base
}

func sigPreview(sig string) string {
	if len(sig) > confirmSigPreviewLen {
		return sig[:confirmSigPreviewLen] + "…"
	}
	return sig
}
