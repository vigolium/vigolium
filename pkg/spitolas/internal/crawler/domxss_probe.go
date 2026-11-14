package crawler

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"go.uber.org/zap"
)

const (
	// maxDOMXssProbes caps browser confirmations per crawl so a param-heavy app
	// cannot turn the probe into an unbounded navigation loop.
	maxDOMXssProbes = 16
	// domXssBudget is the hard wall-clock ceiling for the whole probe pass, so it
	// can never overrun the spider watchdog grace regardless of candidate count.
	domXssBudget = 45 * time.Second
	// domXssNavTimeout bounds a single confirm navigation.
	domXssNavTimeout = 6 * time.Second
	// domXssSettle is the post-navigation idle wait for the SPA to render the
	// reflected value into its sink (and fire the canary).
	domXssSettle = 600 * time.Millisecond
	// domXssMinValueLen ignores trivially short parameter values that would match
	// ambient DOM text and manufacture reflection candidates.
	domXssMinValueLen = 4
)

// DOMXssFinding is a browser-confirmed DOM-based XSS on a client route: an
// execution canary placed in a reflected query parameter ran in the page.
type DOMXssFinding struct {
	URL      string // exact route + injected param that executed the canary
	Param    string // the injected query parameter name
	Payload  string // the canary payload (decoded)
	Evidence string // the sink element as rendered
}

// reflectedCandidate is a (route, param) surface worth confirming. valueReflected
// is set when the crawled value already appeared verbatim in the captured DOM (a
// free, no-navigation reflection signal); otherwise the param is a known slot on a
// discovered route and confirmDOMXSS first does a cheap marker-reflection probe
// before ever sending the execution canary — so the browser is never driven blindly.
type reflectedCandidate struct {
	rawURL         string // full navigable URL to base the probe on
	param          string
	inFrag         bool   // param lives in the SPA fragment ("#/route?p=v") vs the query string
	valueReflected bool   // crawled value already reflected into the captured DOM
	dedupeKey      string // value-independent identity so each surface is confirmed once
}

// domXssProbeBudget computes the probe's wall-clock budget from the parent
// context and reports whether the probe should run at all. It returns ok=false
// when the parent is already cancelled/expired or has no remaining time, so the
// probe never starts fresh navigations after the scan has been stopped; otherwise
// it caps the budget at domXssBudget and at whatever time the parent has left.
func domXssProbeBudget(parent context.Context) (time.Duration, bool) {
	if parent.Err() != nil {
		return 0, false
	}
	budget := domXssBudget
	if dl, ok := parent.Deadline(); ok {
		if remaining := time.Until(dl); remaining < budget {
			budget = remaining
		}
	}
	if budget <= 0 {
		return 0, false
	}
	return budget, true
}

// probeDOMXSS confirms DOM-based XSS on client routes the crawl already visited.
// It never navigates the browser blindly: a cheap prefilter over each captured
// state's DOM selects only (route, param) pairs whose value actually reflected, and
// only those are re-navigated with an execution canary. Best-effort and budget-
// capped; runs while the crawl browser is still alive (from buildResult).
func (c *Crawler) probeDOMXSS(parent context.Context) []DOMXssFinding {
	if c.browser == nil || c.graph == nil {
		return nil
	}
	// A walled start means the only state in the graph is the login wall itself,
	// whose URL carries an OAuth `state` parameter that the prefilter below reads
	// as a perfectly good reflected-parameter candidate. Without this the probe
	// fires marker-bearing requests at the identity provider — plus an origin
	// navigation that re-enters the OAuth bounce — which is exactly the traffic
	// the wall denial exists to stop.
	if c.startWalled.Load() {
		zap.L().Debug("DOM-XSS probe: skipped, start URL is behind a denied login wall")
		return nil
	}
	// Honor cancellation and budget from the remaining parent deadline. If the
	// crawl/phase/operator context is already done (Ctrl-C, the per-target
	// max-duration, or the enclosing phase deadline), don't spin up a fresh
	// navigation pass — that is exactly the traffic the operator asked to stop.
	// Previously this rooted its own 45s window at context.Background(), so it kept
	// hitting the target for the full budget after the scan was cancelled and hid
	// inside the runner's teardown grace.
	budget, ok := domXssProbeBudget(parent)
	if !ok {
		zap.L().Debug("DOM-XSS probe: skipped, crawl context cancelled or out of budget", zap.Error(parent.Err()))
		return nil
	}

	// Cheap no-navigation prefilter first: reflected params on routes the crawl
	// already visited, read from captured DOM. Collected before opening any page so a
	// crawl with nothing reflected and no mineable route table costs no navigation.
	freeCandidates := c.collectReflectedCandidates()

	origin := ""
	if c.config != nil && c.config.URL != nil {
		origin = c.config.URL.Scheme + "://" + c.config.URL.Host
	}

	// Keep the probe a child of the parent so it can never exceed the scan's own
	// bound and a Ctrl-C mid-probe cancels it promptly.
	ctx, cancel := context.WithTimeout(parent, budget)
	defer cancel()

	// The crawl's pages are bound to the (now-expired) crawl deadline, so every op on
	// them would fail. Rebind the browser to our own budget and open a fresh page,
	// then load the app so its route bundle is available and client routes render.
	c.browser.SetCrawlContext(ctx)
	page, err := c.browser.NewPage()
	if err != nil || page == nil {
		zap.L().Debug("DOM-XSS probe: could not open a probe page", zap.Error(err))
		return nil
	}
	defer func() { _ = page.Close() }()
	if origin != "" {
		if err := page.NavigateCtx(ctx, origin+"/#/"); err != nil {
			return nil
		}
		page.WaitNetworkIdle(domXssSettle, domXssNavTimeout)
	}

	// Candidates come from two sources: (1) reflected params on routes the crawl
	// actually visited (free, from captured DOM, collected above), and (2) the app's
	// own client route table mined from its JS bundle, paired with common reflected-
	// param names — this reaches user-driven routes (e.g. a search view) the crawl
	// never hit with a parameter. Both only reach the execution canary through a
	// marker-reflection gate.
	candidates := append(freeCandidates, c.jsRouteCandidates(page)...)
	zap.L().Debug("DOM-XSS probe: candidates collected", zap.Int("count", len(candidates)))
	if len(candidates) == 0 {
		return nil
	}

	var findings []DOMXssFinding
	for i, cand := range candidates {
		if i >= maxDOMXssProbes || ctx.Err() != nil {
			break
		}
		if f := c.confirmDOMXSS(ctx, page, cand, i); f != nil {
			zap.L().Info("Spidering: confirmed DOM-based XSS on a client route",
				zap.String("url", f.URL), zap.String("param", f.Param))
			findings = append(findings, *f)
		}
	}
	return findings
}

// collectReflectedCandidates scans captured states for query parameters (in the
// query string or the SPA fragment). A param whose crawled value already reflected
// into that state's DOM is a confirmed-reflection candidate; any other param slot on
// a discovered route is kept for a marker-reflection probe. Deduped by value-
// independent route+param, confirmed-reflection first so the budget favors them.
func (c *Crawler) collectReflectedCandidates() []reflectedCandidate {
	seen := make(map[string]bool)
	var reflected, slots []reflectedCandidate
	for _, st := range c.graph.AllStates() {
		if st == nil || st.URL == "" {
			continue
		}
		for _, cand := range paramsFromURL(st.URL, st.StrippedDOM) {
			if seen[cand.dedupeKey] {
				continue
			}
			seen[cand.dedupeKey] = true
			if cand.valueReflected {
				reflected = append(reflected, cand)
			} else {
				slots = append(slots, cand)
			}
		}
	}
	return append(reflected, slots...)
}

// paramsFromURL returns the (route, param) surfaces of rawURL — the query string
// and, for hash-routed SPAs, the fragment's "?..." query — flagging each with
// whether its crawled value already reflected verbatim into dom.
func paramsFromURL(rawURL, dom string) []reflectedCandidate {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	base := u.Scheme + "://" + u.Host + u.EscapedPath()
	var out []reflectedCandidate

	for p, vals := range u.Query() {
		out = append(out, reflectedCandidate{rawURL: rawURL, param: p, inFrag: false, valueReflected: anyReflects(vals, dom), dedupeKey: base + "?" + p})
	}
	if frag := u.Fragment; strings.Contains(frag, "?") {
		qi := strings.IndexByte(frag, '?')
		route := frag[:qi]
		fq, _ := url.ParseQuery(frag[qi+1:])
		for p, vals := range fq {
			out = append(out, reflectedCandidate{rawURL: rawURL, param: p, inFrag: true, valueReflected: anyReflects(vals, dom), dedupeKey: base + "#" + route + "?" + p})
		}
	}
	return out
}

// commonReflectedParams are the query-parameter names most commonly consumed by a
// client route and rendered back into the page (search / listing views), tried
// against JS-mined routes the crawl never navigated with a parameter.
var commonReflectedParams = []string{"q", "query", "search", "s"}

// maxJSRouteCandidates bounds how many (route, param) slots the JS-route source
// contributes, so a large route table cannot flood the budget.
const maxJSRouteCandidates = 24

// jsRouteCandidates mines the SPA's own client route table from its main JS bundle
// (Angular/webpack `path:"..."`) and pairs each route with common reflected-param
// names, prioritizing search-like routes so the budget reaches them first. These are
// slot candidates: confirmDOMXSS still marker-gates each before any execution canary.
func (c *Crawler) jsRouteCandidates(page *browser.Page) []reflectedCandidate {
	if c.config == nil || c.config.URL == nil {
		return nil
	}
	origin := c.config.URL.Scheme + "://" + c.config.URL.Host
	raw, err := page.EvalAwait(spaRouteExtractScript, domXssNavTimeout)
	if err != nil {
		return nil
	}
	joined, _ := raw.(string)
	routes := prioritizeRoutes(strings.Fields(joined))
	zap.L().Debug("DOM-XSS probe: mined SPA routes", zap.Int("routes", len(routes)))
	seen := make(map[string]bool)
	var out []reflectedCandidate
	for _, route := range routes {
		for _, p := range commonReflectedParams {
			key := route + "?" + p
			if seen[key] {
				continue
			}
			seen[key] = true
			// dedupeKey is unset: JS-route candidates dedupe via the local `seen`
			// map above and never flow through collectReflectedCandidates (the only
			// reader of dedupeKey), so setting it here would be dead state.
			out = append(out, reflectedCandidate{
				rawURL: origin + "/#/" + route + "?" + p + "=x",
				param:  p,
				inFrag: true,
			})
			if len(out) >= maxJSRouteCandidates {
				return out
			}
		}
	}
	return out
}

// prioritizeRoutes puts search/listing-style route names first so the bounded probe
// budget covers the routes most likely to reflect a URL parameter into a DOM sink.
func prioritizeRoutes(routes []string) []string {
	var hot, cold []string
	for _, r := range routes {
		r = strings.Trim(r, "/")
		if r == "" || !isPlainRouteName(r) {
			continue
		}
		if routeLooksReflective(r) {
			hot = append(hot, r)
		} else {
			cold = append(cold, r)
		}
	}
	return append(hot, cold...)
}

func routeLooksReflective(route string) bool {
	for _, kw := range []string{"search", "find", "query", "result", "list", "filter", "product"} {
		if strings.Contains(route, kw) {
			return true
		}
	}
	return false
}

// isPlainRouteName guards against route strings carrying regex/param syntax so only
// a directly navigable static route is probed.
func isPlainRouteName(route string) bool {
	if len(route) < 2 || len(route) > 40 {
		return false
	}
	for i := 0; i < len(route); i++ {
		ch := route[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' {
			continue
		}
		return false
	}
	return true
}

// spaRouteExtractScript fetches the app's main JS bundle and returns its client
// route names (space-joined) from the framework route table. Best-effort: returns
// "" on any failure.
const spaRouteExtractScript = `(async function(){
  try {
    var srcs = Array.from(document.scripts).map(function(s){return s.src}).filter(Boolean);
    var main = srcs.find(function(s){return /\/main[.-][^\/]*\.js(\?|$)/i.test(s)}) ||
               srcs.find(function(s){return /main\.js(\?|$)/i.test(s)});
    if(!main) return "";
    var js = await fetch(main).then(function(r){return r.text()});
    var m = js.match(/path:"[a-zA-Z0-9\-_]{2,40}"/g) || [];
    var set = {};
    m.forEach(function(x){ set[x.replace(/path:"|"/g,'')] = 1; });
    return Object.keys(set).slice(0,60).join(" ");
  } catch(e){ return ""; }
})()`

func anyReflects(vals []string, dom string) bool {
	for _, v := range vals {
		v = strings.TrimSpace(v)
		if len(v) >= domXssMinValueLen && strings.Contains(dom, v) {
			return true
		}
	}
	return false
}

// confirmDOMXSS navigates the reflected route with an execution canary and reports
// a finding only when the canary's onerror handler actually ran — so a value that
// reflects as encoded text (not an HTML sink) yields nothing.
func (c *Crawler) confirmDOMXSS(ctx context.Context, page *browser.Page, cand reflectedCandidate, seq int) *DOMXssFinding {
	// Probe-first: for a param slot whose crawled value did not already reflect,
	// navigate once with a benign marker and bail unless it reflects into the DOM.
	// Only a reflecting param earns the execution-canary navigation below.
	if !cand.valueReflected && !c.paramReflectsMarker(ctx, page, cand, seq) {
		return nil
	}

	prop := fmt.Sprintf("__vigoliumxss%d", seq)
	payload := fmt.Sprintf("<img src=x onerror=window.%s=1>", prop)
	probeURL, ok := buildDOMXssProbeURL(cand, payload)
	if !ok {
		return nil
	}
	// Clear any stale flag, then navigate. A javascript-triggered nav error still
	// lets the handler run, so proceed to the flag check regardless of nav error.
	_, _ = page.Eval(fmt.Sprintf("try{delete window.%s}catch(e){}", prop))
	_ = page.NavigateCtx(ctx, probeURL)
	page.WaitNetworkIdle(domXssSettle, domXssNavTimeout)

	res, err := page.Eval(fmt.Sprintf("(function(){try{return window.%s===1}catch(e){return false}})()", prop))
	if err != nil {
		return nil
	}
	if fired, _ := res.(bool); !fired {
		return nil
	}
	ev, _ := page.Eval(`(function(){var e=document.querySelector('img[onerror]');return e?e.outerHTML.slice(0,200):''})()`)
	evidence, _ := ev.(string)
	return &DOMXssFinding{URL: probeURL, Param: cand.param, Payload: payload, Evidence: evidence}
}

// paramReflectsMarker navigates the candidate route with a benign, HTML-inert
// marker and reports whether it appears in the rendered DOM. This is the cheap
// reflection gate for a param slot whose crawled value did not already reflect — a
// non-reflecting slot never reaches the execution-canary navigation.
func (c *Crawler) paramReflectsMarker(ctx context.Context, page *browser.Page, cand reflectedCandidate, seq int) bool {
	marker := fmt.Sprintf("vigoliumrefl%d7k", seq)
	probeURL, ok := buildDOMXssProbeURL(cand, marker)
	if !ok {
		return false
	}
	if err := page.NavigateCtx(ctx, probeURL); err != nil {
		return false
	}
	page.WaitNetworkIdle(domXssSettle, domXssNavTimeout)
	res, err := page.Eval(fmt.Sprintf("document.documentElement.innerHTML.indexOf(%q)>=0", marker))
	if err != nil {
		return false
	}
	reflected, _ := res.(bool)
	return reflected
}

// buildDOMXssProbeURL rebuilds cand's URL with the target parameter's value replaced
// by the (fully percent-encoded) payload, preserving the route and other params.
// Fragment params are encoded with %20 for spaces (never "+") so the SPA router
// decodes the payload intact.
func buildDOMXssProbeURL(cand reflectedCandidate, payload string) (string, bool) {
	u, err := url.Parse(cand.rawURL)
	if err != nil {
		return "", false
	}
	enc := pctEncodeComponent(payload)
	if !cand.inFrag {
		q := u.Query()
		q.Set(cand.param, "VIGOLIUMPLACEHOLDER")
		u.RawQuery = q.Encode()
		return strings.Replace(u.String(), "VIGOLIUMPLACEHOLDER", enc, 1), true
	}
	frag := u.Fragment
	qi := strings.IndexByte(frag, '?')
	route := frag[:qi]
	fq, _ := url.ParseQuery(frag[qi+1:])
	parts := make([]string, 0, len(fq))
	for p, vals := range fq {
		val := enc
		if p != cand.param {
			val = pctEncodeComponent(firstOrEmpty(vals))
		}
		parts = append(parts, pctEncodeComponent(p)+"="+val)
	}
	u.Fragment = "" // rebuild the fragment manually below so String() can't re-escape it
	return u.String() + "#" + route + "?" + strings.Join(parts, "&"), true
}

func firstOrEmpty(vals []string) string {
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

// pctEncodeComponent percent-encodes every byte outside the unreserved set, so a
// payload's HTML metacharacters, spaces, and '=' survive transport in either a query
// string or a fragment without the "+"-means-space ambiguity url.Values.Encode has.
func pctEncodeComponent(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '_' || ch == '.' || ch == '~' {
			b.WriteByte(ch)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", ch)
	}
	return b.String()
}

// domXssLead is how much of the crawl's end the DOM-XSS probe is given when
// it has work: min(domXssBudget, MaxDuration/10).
func (c *Crawler) domXssLead() time.Duration {
	if c.config == nil {
		return 0
	}
	if c.config.MaxDuration <= 0 {
		return domXssBudget
	}
	return min(domXssBudget, c.config.MaxDuration/10)
}

// domXssPrefilterEvery bounds how often the drain check re-runs the prefilter.
const domXssPrefilterEvery = 2 * time.Second

// domXssCandidatesPending runs the no-navigation prefilter (memoized: once
// true it stays true; a negative answer is re-checked at most every 2s as
// the crawl adds states).
func (c *Crawler) domXssCandidatesPending() bool {
	if c.domXssHasCandidates.Load() {
		return true
	}
	now := time.Now().UnixNano()
	last := c.domXssCheckedAt.Load()
	if last != 0 && now-last < int64(domXssPrefilterEvery) {
		return false
	}
	if !c.domXssCheckedAt.CompareAndSwap(last, now) {
		return false
	}
	if len(c.collectReflectedCandidates()) > 0 {
		c.domXssHasCandidates.Store(true)
		return true
	}
	return false
}
