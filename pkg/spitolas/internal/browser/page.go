package browser

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"github.com/ysmood/gson"
)

// maxRecordedDialogs caps per-page dialog history so a malicious page can't
// drive memory growth by spamming alert() calls.
const maxRecordedDialogs = 64

// DialogEvent describes a JavaScript dialog (alert/confirm/prompt/beforeunload)
// that opened on the page. Captured by setupAutoDialogHandler before the
// dialog is answered, so consumers can confirm XSS by observing fired alerts
// without blocking the page — and regardless of how the policy answers it.
type DialogEvent struct {
	Type    string    // "alert", "confirm", "prompt", "beforeunload"
	Message string    // The dialog message text
	URL     string    // Frame URL where the dialog originated
	At      time.Time // When the dialog opened
	// Answered is how the dialog policy told the browser to answer it:
	// DialogAccepted or DialogDismissed.
	Answered string
}

// DialogEvent.Answered values.
const (
	DialogAccepted  = "accepted"
	DialogDismissed = "dismissed"
)

// Page wraps rod.Page with additional functionality.
type Page struct {
	rodPage *rod.Page
	config  *config.Config
	browser *Browser
	// release ends the context of the browser handle that created this tab
	// (see Browser.createRodPage); nil for pages not created by NewPage.
	release context.CancelFunc

	dialogMu sync.Mutex
	dialogs  []DialogEvent

	// credRouter is the Fetch-interception credential policy
	// (InstallCredentialRouter, SAFE-3); credRouterOnce starts its event loop.
	credRouter     atomic.Pointer[credentialRouter]
	credRouterOnce sync.Once
	routerMu       sync.Mutex
}

// crawlCtxDone reports whether the crawl context bound to this page (via
// Browser.SetCrawlContext) has been cancelled or has expired. Used to skip the
// non-ctx fallback sleeps below once the crawl deadline has fired, so a
// cancelled crawl winds down promptly instead of sleeping per operation.
func (p *Page) crawlCtxDone() bool {
	return p.rodPage.GetContext().Err() != nil
}

// adopt wraps a rod element returned by a BOUNDED lookup and rebinds it to the
// page's own (crawl-bound) context.
//
// This rebinding is load-bearing, not tidiness. Every lookup below runs through
// p.rodPage.Timeout(ElementTimeout), and rod copies that timed context into each
// element it returns (ElementFromObject: `ctx: p.ctx`). A later
// Element.Timeout(d) does context.WithTimeout(e.ctx, d) — it DERIVES from the
// expired lookup deadline rather than replacing it, so the earlier deadline
// always wins and no per-operation timeout can revive the handle. The whole
// returned slice therefore shares ONE 5s budget covering its entire life.
//
// The visible symptom is silent coverage loss, not an error: candidate
// extraction pays several CDP round-trips per element (ancestor exclusion walk,
// GetXPath, Attribute, metadata), and its loops `continue` on error — so on a
// dense or slow page every element after the deadline is quietly dropped and the
// crawl reports fewer actions rather than a failure.
//
// Binding to p.rodPage.GetContext() keeps cancellation intact (that context is
// the crawl context installed by Browser.SetCrawlContext) while letting the
// per-operation Timeout wrappers in element.go actually bound each call.
func (p *Page) adopt(re *rod.Element) *Element {
	return &Element{rodElem: re.Context(p.rodPage.GetContext()), page: p}
}

// Navigate navigates to a URL with timeout.
func (p *Page) Navigate(url string) error {
	if err := p.rodPage.Timeout(p.config.PageLoadTimeout).Navigate(url); err != nil {
		return fmt.Errorf("failed to navigate to %s: %w", url, err)
	}

	// Wait for page to load
	if err := p.WaitStable(p.config.DOMStableTime); err != nil && !p.crawlCtxDone() {
		// Non-fatal, log and continue
		time.Sleep(p.config.DOMStableTime)
	}

	return nil
}

// Reload reloads the current page with timeout.
func (p *Page) Reload() error {
	if err := p.rodPage.Timeout(p.config.PageLoadTimeout).Reload(); err != nil {
		return fmt.Errorf("failed to reload: %w", err)
	}

	if err := p.WaitStable(p.config.WaitAfterReload); err != nil && !p.crawlCtxDone() {
		time.Sleep(p.config.WaitAfterReload)
	}

	return nil
}

// sleepWithContext sleeps for duration d but returns early if ctx is cancelled.
func sleepWithContext(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

// NavigateCtx navigates to a URL with timeout, capping rod timeout to remaining context deadline.
func (p *Page) NavigateCtx(ctx context.Context, url string) error {
	timeout := p.config.PageLoadTimeout
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return ctx.Err()
		}
		if remaining < timeout {
			timeout = remaining
		}
	}
	if err := p.rodPage.Timeout(timeout).Navigate(url); err != nil {
		return fmt.Errorf("failed to navigate to %s: %w", url, err)
	}
	if err := p.WaitStable(p.config.DOMStableTime); err != nil {
		if ctxErr := sleepWithContext(ctx, p.config.DOMStableTime); ctxErr != nil {
			return ctxErr
		}
	}
	return nil
}

// ReloadCtx reloads the current page with timeout, capping rod timeout to remaining context deadline.
func (p *Page) ReloadCtx(ctx context.Context) error {
	timeout := p.config.PageLoadTimeout
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return ctx.Err()
		}
		if remaining < timeout {
			timeout = remaining
		}
	}
	if err := p.rodPage.Timeout(timeout).Reload(); err != nil {
		return fmt.Errorf("failed to reload: %w", err)
	}
	if err := p.WaitStable(p.config.WaitAfterReload); err != nil {
		if ctxErr := sleepWithContext(ctx, p.config.WaitAfterReload); ctxErr != nil {
			return ctxErr
		}
	}
	return nil
}

// URL returns the current page URL.
func (p *Page) URL() (string, error) {
	info, err := p.rodPage.Timeout(p.config.PageLoadTimeout).Info()
	if err != nil {
		return "", err
	}
	return info.URL, nil
}

// HTML returns the page HTML.
func (p *Page) HTML() (string, error) {
	var html string
	if err := safeRod("HTML", func() (err error) {
		html, err = p.rodPage.Timeout(p.config.PageLoadTimeout).HTML()
		return err
	}); err != nil {
		return "", err
	}
	return html, nil
}

// settleCap bounds how long WaitStable waits for a DOM that never stops
// changing (ECON-9).
const settleCap = 3 * time.Second

// stableCapHits counts WaitStable calls that hit settleCap (process-wide).
var stableCapHits atomic.Int64

// StableCapHits is how many WaitStable calls ended at the settle cap.
func StableCapHits() int64 { return stableCapHits.Load() }

// WaitStable waits for the page to be stable, at most min(PageLoadTimeout,
// 3s) (ECON-9). A page whose DOM changes every window (a ticker, a carousel)
// used to cost the whole 30s page timeout per action; reaching the cap is
// treated as settled — the DOM is as stable as it will get — and counted.
func (p *Page) WaitStable(d time.Duration) error {
	if d == 0 {
		d = 500 * time.Millisecond
	}
	limit := settleCap
	if p.config != nil && p.config.PageLoadTimeout > 0 && p.config.PageLoadTimeout < limit {
		limit = p.config.PageLoadTimeout
	}
	start := time.Now()
	err := p.rodPage.Timeout(limit).WaitStable(d)
	// rod reports reaching the bound either as a deadline error or as a nil
	// return at the bound, depending on which internal wait it was in.
	if (err == nil || errors.Is(err, context.DeadlineExceeded)) && time.Since(start) >= limit-50*time.Millisecond && !p.crawlCtxDone() {
		stableCapHits.Add(1)
		return nil
	}
	return err
}

// WaitLoad waits for the page to finish loading with timeout.
func (p *Page) WaitLoad() error {
	return p.rodPage.Timeout(p.config.PageLoadTimeout).WaitLoad()
}

// WaitNetworkIdle blocks until no in-flight document/XHR/fetch request has been
// seen for idle duration, bounded by max (returns at max even if the network
// never quiesces, e.g. a long-poll/SSE app). Unlike WaitStable's fixed window
// this is a targeted second settle used right before reading the DOM to harvest
// dynamically-injected iframes: frameworks such as Aura/Lightning or Angular
// mount subframes from an after-paint component fetch, and this gives that fetch
// (and the subframe load it triggers) time to land in the network capture.
// Best-effort: a go-rod panic on a detached/navigating page is contained.
func (p *Page) WaitNetworkIdle(idle, max time.Duration) {
	if max <= 0 {
		return
	}
	if idle <= 0 {
		idle = 500 * time.Millisecond
	}
	_ = safeRod("WaitNetworkIdle", func() error {
		// Timeout caps the whole wait: when it fires the cloned page's context is
		// cancelled and WaitRequestIdle's wait returns promptly.
		p.rodPage.Timeout(max).WaitRequestIdle(idle, nil, nil, nil)()
		return nil
	})
}

// WaitElement waits for an element to exist.
func (p *Page) WaitElement(selector string, timeout time.Duration) error {
	rodPage := p.rodPage.Timeout(timeout)
	_, err := rodPage.Element(selector)
	return err
}

// WaitVisible waits for an element to be visible.
func (p *Page) WaitVisible(selector string, timeout time.Duration) error {
	rodPage := p.rodPage.Timeout(timeout)
	elem, err := rodPage.Element(selector)
	if err != nil {
		return err
	}
	return elem.WaitVisible()
}

// SetCookies sets cookies on the page from http.Cookie slice.
// Converts net/http cookies to rod's NetworkCookieParam format (cookieParams).
func (p *Page) SetCookies(cookies []*http.Cookie) error {
	if len(cookies) == 0 {
		return nil
	}

	// Get target URL from config for setting cookies before navigation
	var targetURL string
	if p.config != nil && p.config.URL != nil {
		targetURL = p.config.URL.String()
	}

	return p.boundedPage(0).SetCookies(cookieParams(cookies, targetURL))
}

// cookieParams converts net/http cookies to CDP cookie parameters, keeping the
// attributes that decide where a cookie is sent. A cookie with a Domain is
// installed for that domain (a leading dot or not, exactly as given) and its
// Path ("/" when unset) — never also with URL, which CDP reconciles with
// Domain inconsistently. A host-only cookie (no Domain) is bound to targetURL,
// the pre-navigation case: CDP derives the host from it, and a Path, when the
// cookie has one, narrows it.
func cookieParams(cookies []*http.Cookie, targetURL string) []*proto.NetworkCookieParam {
	params := make([]*proto.NetworkCookieParam, 0, len(cookies))
	for _, c := range cookies {
		if c == nil {
			continue
		}
		// Map SameSite from http to proto
		sameSite := proto.NetworkCookieSameSiteLax // Default
		switch c.SameSite {
		case http.SameSiteStrictMode:
			sameSite = proto.NetworkCookieSameSiteStrict
		case http.SameSiteNoneMode:
			sameSite = proto.NetworkCookieSameSiteNone
		}

		param := &proto.NetworkCookieParam{
			Name:     c.Name,
			Value:    c.Value,
			Path:     c.Path,
			Secure:   c.Secure,
			HTTPOnly: c.HttpOnly,
			SameSite: sameSite,
		}
		if c.Domain != "" {
			param.Domain = c.Domain
			if param.Path == "" {
				param.Path = "/"
			}
		} else {
			param.URL = targetURL
		}

		// Set expiry if present
		if !c.Expires.IsZero() {
			param.Expires = proto.TimeSinceEpoch(c.Expires.Unix())
		}

		params = append(params, param)
	}
	return params
}

// SetExtraHeaders replaces the page's extra request headers (CDP
// Network.setExtraHTTPHeaders) — they ride on every request the page makes.
// An empty map clears them. Unlike rod's Page.SetExtraHeaders this returns no
// cleanup: rod's handle restores the Network domain's enabled state, not the
// headers, so calling it would stop the page's network events instead.
func (p *Page) SetExtraHeaders(headers map[string]string) error {
	h := proto.NetworkHeaders{}
	for k, v := range headers {
		h[k] = gson.New(v)
	}
	return proto.NetworkSetExtraHTTPHeaders{Headers: h}.Call(p.boundedPage(0))
}

// ShadowUIDAttr is the attribute the shadow-piercing queries stamp on each element
// they surface so it can be re-resolved later by an attribute selector — an XPath
// cannot cross a shadow boundary. It is the single source of truth for the tag,
// shared by the tagging JS, the resolver, and the callers that build/match it.
const ShadowUIDAttr = "data-vgo-uid"

// ShadowUIDSelector builds the attribute selector that re-resolves a tagged shadow
// element (resolved via Page.Element's shadow-piercing fallback).
func ShadowUIDSelector(uid string) string {
	return "[" + ShadowUIDAttr + `="` + uid + `"]`
}

// IsShadowUIDSelector reports whether a selector targets a shadow-tagged element.
func IsShadowUIDSelector(selector string) bool {
	return strings.Contains(selector, ShadowUIDAttr)
}

// shadowQueryAllJS collects elements matching a selector across the light DOM and
// every (open) shadow root, recursively. Web-component apps (a web-component design system,
// Stencil, Lit, Angular ShadowDom encapsulation) render their interactive UI
// inside shadow roots, where a plain document.querySelectorAll can't see it — so
// the crawler would find no clickables/inputs and drive nothing. Each match is
// tagged with ShadowUIDAttr (injected via fmt) so it can be re-resolved later.
var shadowQueryAllJS = fmt.Sprintf(`(selector, shadowOnly) => {
  if (!window.__vgoUid) window.__vgoUid = 0;
  const out = [];
  const visit = (root, inShadow) => {
    if (!shadowOnly || inShadow) {
      let m; try { m = root.querySelectorAll(selector); } catch (e) { m = []; }
      for (const el of m) {
        if (el.getAttribute && el.setAttribute && !el.getAttribute('%[1]s')) {
          el.setAttribute('%[1]s', String(++window.__vgoUid));
        }
        out.push(el);
      }
    }
    let all; try { all = root.querySelectorAll('*'); } catch (e) { all = []; }
    for (const el of all) { if (el.shadowRoot) visit(el.shadowRoot, true); }
  };
  visit(document, false);
  return out;
}`, ShadowUIDAttr)

// shadowQueryOneJS returns the first element matching selector, piercing shadow
// roots — used to re-resolve a shadow element by its data-vgo-uid tag.
const shadowQueryOneJS = `(selector) => {
  const visit = (root) => {
    let el; try { el = root.querySelector(selector); } catch (e) { el = null; }
    if (el) return el;
    let all; try { all = root.querySelectorAll('*'); } catch (e) { all = []; }
    for (const e of all) { if (e.shadowRoot) { const r = visit(e.shadowRoot); if (r) return r; } }
    return null;
  };
  return visit(document);
}`

// Element finds an element by CSS selector with safe timeout.
// Uses config.ElementTimeout to prevent infinite waits. When the selector targets
// a shadow-tagged element ([data-vgo-uid=...]) and the light-DOM lookup misses, it
// falls back to a shadow-piercing query, and an encoded Locator is resolved with
// ElementByLocator, so candidates/inputs discovered inside web components can be
// re-resolved and acted on. Both are gated on the selector's shape so every other
// lookup keeps its fast light-only path.
func (p *Page) Element(selector string) (*Element, error) {
	// An encoded Locator (a candidate behind a shadow or frame boundary) is
	// resolved hop by hop; a CSS lookup could never match it.
	if loc, ok := ParseLocator(selector); ok {
		return p.ElementByLocator(loc)
	}
	// A shadow-tagged selector targets an element we tagged inside a shadow root.
	// Resolve it directly with the shadow-piercing query (which also matches the
	// light DOM), skipping the light-only lookup that would otherwise burn the
	// full ElementTimeout retrying a selector it can never match.
	if IsShadowUIDSelector(selector) {
		if deep, derr := p.shadowElement(selector); derr == nil && deep != nil {
			return deep, nil
		}
	}
	var rodElem *rod.Element
	if err := safeRod("Element", func() (e error) {
		rodElem, e = p.rodPage.Timeout(p.config.ElementTimeout).Element(selector)
		return e
	}); err != nil {
		return nil, err
	}
	return p.adopt(rodElem), nil
}

// shadowElement re-resolves a single element by a shadow-piercing query.
func (p *Page) shadowElement(selector string) (*Element, error) {
	var rodElem *rod.Element
	if err := safeRod("shadowElement", func() (e error) {
		rodElem, e = p.rodPage.Timeout(p.config.ElementTimeout).ElementByJS(rod.Eval(shadowQueryOneJS, selector))
		return e
	}); err != nil {
		return nil, err
	}
	if rodElem == nil {
		return nil, fmt.Errorf("shadow element not found: %s", selector)
	}
	return p.adopt(rodElem), nil
}

// ElementPiercing resolves the first element matching selector across both the
// light DOM and every open shadow root (unlike Element, which is light-DOM-first
// and only pierces for data-vgo-uid selectors). Use it to act — e.g. a real CDP
// click — on an element tagged inside a web component's shadow tree by a custom
// attribute. Returns an error if nothing matches.
func (p *Page) ElementPiercing(selector string) (*Element, error) {
	return p.shadowElement(selector)
}

// ShadowElements returns interactive elements matching selector that live INSIDE
// shadow roots (light-DOM matches are returned by Elements). Each is tagged with a
// stable data-vgo-uid so it can be re-resolved later via Element([data-vgo-uid=…]).
func (p *Page) ShadowElements(selector string) ([]*Element, error) {
	var rodElems rod.Elements
	if err := safeRod("ShadowElements", func() (err error) {
		rodElems, err = p.rodPage.Timeout(p.config.ElementTimeout).ElementsByJS(rod.Eval(shadowQueryAllJS, selector, true))
		return err
	}); err != nil {
		return nil, err
	}
	elements := make([]*Element, len(rodElems))
	for i, re := range rodElems {
		elements[i] = p.adopt(re)
	}
	return elements, nil
}

// Elements finds all elements matching a CSS selector with safe timeout.
// Uses config.ElementTimeout to prevent infinite waits.
func (p *Page) Elements(selector string) ([]*Element, error) {
	var rodElems rod.Elements
	if err := safeRod("Elements", func() (err error) {
		rodElems, err = p.rodPage.Timeout(p.config.ElementTimeout).Elements(selector)
		return err
	}); err != nil {
		return nil, err
	}

	elements := make([]*Element, len(rodElems))
	for i, re := range rodElems {
		elements[i] = p.adopt(re)
	}
	return elements, nil
}

// ElementX finds an element by XPath with safe timeout.
// Uses config.ElementTimeout to prevent infinite waits.
func (p *Page) ElementX(xpath string) (*Element, error) {
	var rodElem *rod.Element
	if err := safeRod("ElementX", func() (err error) {
		rodElem, err = p.rodPage.Timeout(p.config.ElementTimeout).ElementX(xpath)
		return err
	}); err != nil {
		return nil, err
	}
	return p.adopt(rodElem), nil
}

// ElementsX finds all elements matching an XPath with safe timeout.
// Uses config.ElementTimeout to prevent infinite waits.
func (p *Page) ElementsX(xpath string) ([]*Element, error) {
	var rodElems rod.Elements
	if err := safeRod("ElementsX", func() (err error) {
		rodElems, err = p.rodPage.Timeout(p.config.ElementTimeout).ElementsX(xpath)
		return err
	}); err != nil {
		return nil, err
	}

	elements := make([]*Element, len(rodElems))
	for i, re := range rodElems {
		elements[i] = p.adopt(re)
	}
	return elements, nil
}

// Click clicks an element by selector.
func (p *Page) Click(selector string) error {
	elem, err := p.Element(selector)
	if err != nil {
		return err
	}
	return elem.Click()
}

// Hover hovers over an element by selector.
func (p *Page) Hover(selector string) error {
	elem, err := p.Element(selector)
	if err != nil {
		return err
	}
	return elem.Hover()
}

// firstPositiveDuration returns the first argument greater than zero, or 0 if
// none — used to resolve a timeout from a preferred value, a config default, and
// a hardcoded floor in order.
func firstPositiveDuration(ds ...time.Duration) time.Duration {
	for _, d := range ds {
		if d > 0 {
			return d
		}
	}
	return 0
}

// boundedPage returns the rod page capped (at the caller's timeout, else
// PageLoadTimeout) for a one-shot CDP call. It is the single chokepoint that
// keeps every direct rod/CDP call on a page bounded: the CDP call blocks on the
// page context waiting for the renderer, so a wedged/unresponsive one would hang
// forever on a deadline-less context (a RuntimeEvaluate's own Timeout only bounds
// JS execution once it starts). Do NOT use it for long-lived loops (EachEvent),
// which must run for the whole crawl. See Browser.crawlCtx for the binding that
// makes the effective bound min(cap, remaining-crawl-deadline).
func (p *Page) boundedPage(timeout time.Duration) *rod.Page {
	return p.rodPage.Timeout(firstPositiveDuration(timeout, p.config.PageLoadTimeout, 30*time.Second))
}

// evalContextID is the execution context a raw Runtime.evaluate on this page
// must name. A frame page shares its tab's CDP session, and a Runtime.evaluate
// without a contextId runs in the session's default context, the TOP document:
// every expression "evaluated in a frame" would silently read the parent page
// instead (and the CDP clickable pass would then resolve the parent's XPaths
// inside the frame, burning an element timeout per miss). For a frame page this
// resolves the frame document's main-world context, where the Command Line API
// (getEventListeners) and the page's own globals (jQuery) live. A top-level page
// returns 0, which the request omits.
func (p *Page) evalContextID() (proto.RuntimeExecutionContextID, error) {
	if !p.rodPage.IsIframe() {
		return 0, nil
	}
	var objID proto.RuntimeRemoteObjectID
	if err := safeRod("evalContextID", func() error {
		// rod's Evaluate is frame-aware: it calls the function on the frame's
		// own window.
		bp := p.boundedPage(0)
		obj, err := bp.Evaluate(rod.Eval(`() => window`).ByObject())
		if err != nil {
			return err
		}
		objID = obj.ObjectID
		_ = proto.RuntimeReleaseObject{ObjectID: objID}.Call(bp)
		return nil
	}); err != nil {
		return 0, err
	}
	return contextIDFromObjectID(objID)
}

// contextIDFromObjectID reads the execution context out of a V8 remote object
// id, which V8 serialises as "<isolateId>.<contextId>.<objectId>".
func contextIDFromObjectID(id proto.RuntimeRemoteObjectID) (proto.RuntimeExecutionContextID, error) {
	parts := strings.Split(string(id), ".")
	if len(parts) == 3 {
		if n, err := strconv.Atoi(parts[1]); err == nil && n > 0 {
			return proto.RuntimeExecutionContextID(n), nil
		}
	}
	return 0, fmt.Errorf("frame execution context: unrecognised remote object id %q", id)
}

// Eval evaluates JavaScript expression on the page.
// Uses CDP RuntimeEvaluate directly to support arbitrary expressions (not just functions).
func (p *Page) Eval(script string) (interface{}, error) {
	ctxID, err := p.evalContextID()
	if err != nil {
		return nil, err
	}
	result, err := proto.RuntimeEvaluate{
		Expression:            script,
		ContextID:             ctxID,
		IncludeCommandLineAPI: true,
		ReturnByValue:         true,
	}.Call(p.boundedPage(0))

	if err != nil {
		return nil, err
	}

	if result.ExceptionDetails != nil {
		return nil, fmt.Errorf("eval error: %s", result.ExceptionDetails.Text)
	}

	return result.Result.Value.Val(), nil
}

// EvalWithArgs evaluates JavaScript with arguments.
func (p *Page) EvalWithArgs(script string, args ...interface{}) (interface{}, error) {
	var val interface{}
	if err := safeRod("EvalWithArgs", func() error {
		result, err := p.boundedPage(0).Evaluate(rod.Eval(script, args...))
		if err != nil {
			return err
		}
		val = result.Value.Val()
		return nil
	}); err != nil {
		return nil, err
	}
	return val, nil
}

// EvalAwait evaluates a JavaScript expression that returns a Promise and waits
// for it to resolve, returning the resolved value. timeout bounds the whole
// evaluation (0 = no explicit timeout). Used for in-page async work such as
// priming service-worker assets with fetch().
func (p *Page) EvalAwait(script string, timeout time.Duration) (interface{}, error) {
	ctxID, err := p.evalContextID()
	if err != nil {
		return nil, err
	}
	eval := proto.RuntimeEvaluate{
		Expression:            script,
		ContextID:             ctxID,
		IncludeCommandLineAPI: true,
		ReturnByValue:         true,
		AwaitPromise:          true,
	}
	if timeout > 0 {
		eval.Timeout = proto.RuntimeTimeDelta(timeout.Milliseconds())
	}

	// Cap the CDP call itself (not just JS execution) so a wedged renderer can't
	// hang the await forever; eval.Timeout above only applies once the script runs.
	result, err := eval.Call(p.boundedPage(timeout))
	if err != nil {
		return nil, err
	}

	if result.ExceptionDetails != nil {
		return nil, fmt.Errorf("eval error: %s", result.ExceptionDetails.Text)
	}

	return result.Result.Value.Val(), nil
}

// EvalCDP executes a CDP command via Runtime.evaluate.
func (p *Page) EvalCDP(expression string) (interface{}, error) {
	ctxID, err := p.evalContextID()
	if err != nil {
		return nil, err
	}
	result, err := proto.RuntimeEvaluate{
		Expression:            expression,
		ContextID:             ctxID,
		IncludeCommandLineAPI: true,
		ReturnByValue:         true,
	}.Call(p.boundedPage(0))

	if err != nil {
		return nil, err
	}

	if result.ExceptionDetails != nil {
		return nil, fmt.Errorf("CDP eval exception: %s", result.ExceptionDetails.Text)
	}

	return result.Result.Value.Val(), nil
}

// ExecuteCDP runs a CDP command directly.
func (p *Page) ExecuteCDP(method string, params map[string]interface{}) (interface{}, error) {
	// This would require direct CDP access through rod
	// For now, use Eval as workaround
	return nil, fmt.Errorf("ExecuteCDP not implemented - use EvalCDP instead")
}

// Screenshot takes a viewport screenshot as PNG.
func (p *Page) Screenshot() ([]byte, error) {
	return p.boundedPage(0).Screenshot(false, nil)
}

// FullScreenshot takes a full page screenshot as PNG.
func (p *Page) FullScreenshot() ([]byte, error) {
	return p.boundedPage(0).Screenshot(true, nil)
}

// ScreenshotCompact captures a viewport screenshot as JPEG at reduced quality.
// Optimized for AI agent consumption: small file size, sufficient visual fidelity.
func (p *Page) ScreenshotCompact(quality int) ([]byte, error) {
	return p.boundedPage(0).Screenshot(false, &proto.PageCaptureScreenshot{
		Format:           proto.PageCaptureScreenshotFormatJpeg,
		Quality:          &quality,
		OptimizeForSpeed: true,
	})
}

// Close closes the page. Two hazards to navigate at teardown:
//   - The crawl context is usually cancelled by now (the deadline fired), so
//     closing on the page's own context would fail and leak the tab — detach to
//     a background context so the close still runs.
//   - A wedged/unresponsive browser (busy renderer, anti-bot challenge) makes the
//     close CDP call block forever on that deadline-less background context.
//
// closePageWithTimeout runs the close in a goroutine and abandons it after a
// bound, so teardown can never hang the scan forever even against a stuck browser.
func (p *Page) Close() error {
	err := closePageWithTimeout(p.rodPage.Context(context.Background()), browserOpTimeout, 1)
	if p.release != nil {
		p.release()
	}
	return err
}

// CloseWithin closes the tab, giving up after timeout, and stops tracking it
// on its browser. Used to tear down a crawl's extra tabs, where a wedged tab
// must not hold up the end of a cancelled crawl.
func (p *Page) CloseWithin(timeout time.Duration) error {
	err := closePageWithTimeout(p.rodPage.Context(context.Background()), timeout, 1)
	if p.release != nil {
		p.release()
	}
	if p.browser != nil {
		p.browser.forget(p)
	}
	return err
}

// Browser returns the parent browser.
func (p *Page) Browser() *Browser {
	return p.browser
}

// RodPage returns the underlying rod.Page (for advanced usage).
func (p *Page) RodPage() *rod.Page {
	return p.rodPage
}

// Title returns the page title.
func (p *Page) Title() (string, error) {
	info, err := p.rodPage.Timeout(p.config.PageLoadTimeout).Info()
	if err != nil {
		return "", err
	}
	return info.Title, nil
}

// NavigateBack navigates back in history and waits for navigation to complete.
func (p *Page) NavigateBack() error {
	// Setup wait BEFORE triggering navigation with timeout
	// Use PageLoadTimeout to prevent infinite waiting
	wait := p.rodPage.Timeout(p.config.PageLoadTimeout).WaitNavigation(proto.PageLifecycleEventNameNetworkAlmostIdle)

	// Trigger back navigation
	if err := p.boundedPage(0).NavigateBack(); err != nil {
		return err
	}

	// Wait for navigation to complete (with timeout)
	wait()

	return nil
}

// NavigateForward navigates forward in history with timeout.
func (p *Page) NavigateForward() error {
	return p.rodPage.Timeout(p.config.PageLoadTimeout).NavigateForward()
}

// SetViewport sets the page viewport size.
func (p *Page) SetViewport(width, height int) error {
	return p.boundedPage(0).SetViewport(&proto.EmulationSetDeviceMetricsOverride{
		Width:  width,
		Height: height,
	})
}

// WaitDOMStable waits for DOM to be stable.
func (p *Page) WaitDOMStable(d time.Duration, diff float64) error {
	return p.rodPage.Timeout(p.config.PageLoadTimeout).WaitDOMStable(d, diff)
}

// WaitDOMStableBounded waits until the DOM stops mutating — successive snapshots
// taken window apart differ by at most diff (0..1 fraction of changed nodes) —
// but bounded by max so a page whose DOM never fully settles (carousels, live
// clocks, spinners) returns at max instead of blocking for the full page-load
// timeout. Used to let a client-render commit (a framework mounting real
// content/anchors after its bundle loads) land before the DOM is snapshotted.
// Best-effort: a rod timeout/error/panic is swallowed and the caller proceeds
// with whatever is currently rendered.
func (p *Page) WaitDOMStableBounded(window time.Duration, diff float64, max time.Duration) {
	if max <= 0 {
		return
	}
	if window <= 0 {
		window = 300 * time.Millisecond
	}
	_ = safeRod("WaitDOMStableBounded", func() error {
		_ = p.rodPage.Timeout(max).WaitDOMStable(window, diff)
		return nil
	})
}

// HasElement checks if an element exists.
func (p *Page) HasElement(selector string) bool {
	found := false
	_ = safeRod("HasElement", func() error {
		_, err := p.rodPage.Timeout(100 * time.Millisecond).Element(selector)
		found = err == nil
		return nil
	})
	return found
}

// HasElementX checks if an element exists by XPath.
func (p *Page) HasElementX(xpath string) bool {
	found := false
	_ = safeRod("HasElementX", func() error {
		_, err := p.rodPage.Timeout(100 * time.Millisecond).ElementX(xpath)
		found = err == nil
		return nil
	})
	return found
}

// Frames returns all iframe elements in the page with safe timeout.
// Uses config.ElementTimeout to prevent infinite waits. Frames are adopted for
// the same reason elements are — see Page.adopt.
func (p *Page) Frames() ([]*Page, error) {
	iframes, err := p.rodPage.Timeout(p.config.ElementTimeout).Elements("iframe")
	if err != nil {
		return nil, err
	}

	frames := make([]*Page, 0, len(iframes))
	for _, iframe := range iframes {
		if !frameAccessible(iframe) {
			continue
		}
		framePage, err := iframe.Frame()
		if err != nil {
			continue // Skip iframes that can't be accessed
		}
		frames = append(frames, p.adoptFrame(framePage))
	}
	return frames, nil
}

// adoptFrame wraps a rod frame page and rebinds it to the parent page's
// (crawl-bound) context, so recursive frame work is bounded by the crawl rather
// than by whatever lookup deadline happened to produce the iframe element.
func (p *Page) adoptFrame(fp *rod.Page) *Page {
	return &Page{rodPage: fp.Context(p.rodPage.GetContext()), config: p.config, browser: p.browser}
}

// safeRod runs fn and converts a panic raised inside the go-rod library into an
// error. rod's lazy getJSCtxID() (page_eval.go) dereferences a nil
// ContentDocument for cross-origin or detached frames. frameAccessible()
// pre-filters such frames at enumeration time, but a same-origin frame can
// navigate cross-origin or detach between enumeration and the actual element
// query (TOCTOU) — common on SPAs — and the nil dereference then crashes the
// whole scan instead of just skipping the frame. Recovering here turns that into
// a normal error so callers skip the frame/element and the crawl continues.
func safeRod(op string, fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("go-rod panic during %s (cross-origin/detached frame?): %v", op, r)
		}
	}()
	return fn()
}

// frameAccessible returns true if the iframe has a usable content document.
// Cross-origin or detached iframes return ContentDocument == nil from CDP, and
// rod's lazy getJSCtxID() panics when it dereferences that nil pointer the first
// time we touch the resulting frame Page. We pre-filter here with a cheap
// Describe(pierce=true) call so cross-origin frames are skipped up front
// rather than crashing later. This is best-effort: see safeRod for the runtime
// backstop that covers the frame going cross-origin after this check.
func frameAccessible(iframe *rod.Element) bool {
	node, err := iframe.Describe(1, true)
	if err != nil {
		return false
	}
	return node.ContentDocument != nil
}

// FrameInfo contains information about an iframe.
type FrameInfo struct {
	Page  *Page  // The frame's page object
	ID    string // Frame id or name (empty if neither exists)
	Index int    // Index in parent's iframe list
}

// FramesWithInfo returns all iframe elements with their identification info.
func (p *Page) FramesWithInfo() ([]FrameInfo, error) {
	iframes, err := p.rodPage.Timeout(p.config.ElementTimeout).Elements("iframe")
	if err != nil {
		return nil, err
	}

	frames := make([]FrameInfo, 0, len(iframes))
	for i, iframe := range iframes {
		if !frameAccessible(iframe) {
			continue
		}
		framePage, err := iframe.Frame()
		if err != nil {
			continue // Skip iframes that can't be accessed
		}

		idPtr, _ := iframe.Attribute("id")
		namePtr, _ := iframe.Attribute("name")

		frameID := ""
		if idPtr != nil && *idPtr != "" && *idPtr != "<nil>" {
			frameID = *idPtr
		} else if namePtr != nil && *namePtr != "" && *namePtr != "<nil>" {
			frameID = *namePtr
		}

		frames = append(frames, FrameInfo{
			Page:  p.adoptFrame(framePage),
			ID:    frameID,
			Index: i,
		})
	}
	return frames, nil
}

// HTMLWithFrames returns the page HTML with all iframe content embedded.
// builds a combined DOM by importing frame content into iframe elements.
// This is critical for proper state comparison when content changes in iframes.
func (p *Page) HTMLWithFrames() (string, error) {
	return p.htmlWithFramesRecursive("", make(map[string]bool))
}

// htmlWithFramesRecursive recursively builds HTML with frame content.
// This approach is simpler than DOM manipulation and works for state comparison.
func (p *Page) htmlWithFramesRecursive(parentFramePath string, visited map[string]bool) (string, error) {
	// Use the guarded HTML() — p may be a (possibly cross-origin/detached) frame
	// page here, and rod's HTML() goes through getJSCtxID, which can panic.
	mainHTML, err := p.HTML()
	if err != nil {
		return "", err
	}

	// Get all iframes with their info
	frameInfos, err := p.FramesWithInfo()
	if err != nil {
		return mainHTML, nil // Return main HTML if can't get frames
	}

	// Collect frame HTML parts
	var frameParts []string
	for _, fi := range frameInfos {
		// Build frame identification
		frameIdent := fi.ID
		if frameIdent == "" {
			frameIdent = fmt.Sprintf("frame%d", fi.Index)
		}

		// Build full frame path
		fullPath := frameIdent
		if parentFramePath != "" {
			fullPath = parentFramePath + "." + frameIdent
		}

		// Avoid infinite recursion
		if visited[fullPath] {
			continue
		}
		visited[fullPath] = true

		// Get frame content recursively
		frameHTML, err := fi.Page.htmlWithFramesRecursive(fullPath, visited)
		if err != nil {
			continue
		}

		// Simply append frame HTML (no markers that could cause spurious state differences)
		frameParts = append(frameParts, frameHTML)
	}

	// Combine main HTML with frame HTML
	if len(frameParts) > 0 {
		return mainHTML + strings.Join(frameParts, ""), nil
	}
	return mainHTML, nil
}

// HTMLWithFramesFiltered returns HTML with frame content, respecting ignore patterns.
func (p *Page) HTMLWithFramesFiltered(crawlFrames bool, ignorePatterns []string) (string, error) {
	if !crawlFrames {
		// If frame crawling is disabled, return just the main page HTML
		return p.HTML()
	}
	return p.htmlWithFramesFilteredRecursive("", make(map[string]bool), ignorePatterns)
}

// htmlWithFramesFilteredRecursive recursively builds HTML with filtered frame content.
func (p *Page) htmlWithFramesFilteredRecursive(parentFramePath string, visited map[string]bool, ignorePatterns []string) (string, error) {
	// Use the guarded HTML() — p may be a (possibly cross-origin/detached) frame
	// page here, and rod's HTML() goes through getJSCtxID, which can panic.
	mainHTML, err := p.HTML()
	if err != nil {
		return "", err
	}

	// Get all iframes with their info
	frameInfos, err := p.FramesWithInfo()
	if err != nil {
		return mainHTML, nil
	}

	var frameParts []string
	for _, fi := range frameInfos {
		// Build frame identification
		frameIdent := fi.ID
		if frameIdent == "" {
			frameIdent = fmt.Sprintf("frame%d", fi.Index)
		}

		// Build full frame path
		fullPath := frameIdent
		if parentFramePath != "" {
			fullPath = parentFramePath + "." + frameIdent
		}

		// Check if frame should be ignored
		if isFrameIgnored(fullPath, ignorePatterns) {
			continue
		}

		// Avoid infinite recursion
		if visited[fullPath] {
			continue
		}
		visited[fullPath] = true

		// Get frame content recursively
		frameHTML, err := fi.Page.htmlWithFramesFilteredRecursive(fullPath, visited, ignorePatterns)
		if err != nil {
			continue
		}

		// Simply append frame HTML
		frameParts = append(frameParts, frameHTML)
	}

	// Combine main HTML with frame HTML
	if len(frameParts) > 0 {
		return mainHTML + strings.Join(frameParts, ""), nil
	}
	return mainHTML, nil
}

// isFrameIgnored checks if a frame should be ignored based on patterns.
// Pattern matching: "%" is treated as wildcard (replaced with ".*" for regex)
// Go version uses "*" as wildcard for consistency with glob patterns.
func isFrameIgnored(frameIdent string, patterns []string) bool {
	for _, pattern := range patterns {
		if matchesFramePattern(pattern, frameIdent) {
			return true
		}
	}
	return false
}

// matchesFramePattern checks if frameIdent matches the pattern.
// Supports wildcard: "*" matches any characters, "%" also supported.
func matchesFramePattern(pattern, frameIdent string) bool {
	// Handle both "*" (Go style) and "%" wildcards
	if strings.Contains(pattern, "%") || strings.Contains(pattern, "*") {
		// Convert to regex pattern
		regexPattern := "^" + regexp.QuoteMeta(pattern) + "$"
		regexPattern = strings.ReplaceAll(regexPattern, "\\%", ".*")
		regexPattern = strings.ReplaceAll(regexPattern, "\\*", ".*")
		matched, _ := regexp.MatchString(regexPattern, frameIdent)
		return matched
	}
	// Exact match
	return pattern == frameIdent
}

// setupAutoDialogHandler sets up automatic dialog handling for alert/confirm/prompt.
// Must be called when page is created to ensure dialogs don't block crawl.
// The handler runs in a background goroutine: it records the event so XSS
// confirmation can observe it, then answers the dialog per the configured
// dialog policy (see dialogResponse).
func (p *Page) setupAutoDialogHandler() {
	// Enable Page domain for dialog events
	_ = proto.PageEnable{}.Call(p.boundedPage(0))

	// Start background goroutine to handle all dialogs.
	// Callback returns bool: false = keep listening, true = stop.
	go p.rodPage.EachEvent(func(e *proto.PageJavascriptDialogOpening) bool {
		p.handleDialog(e, func(accept bool, promptText string) error {
			return proto.PageHandleJavaScriptDialog{
				Accept:     accept,
				PromptText: promptText,
			}.Call(p.boundedPage(0))
		})
		return false
	})()
}

// handleDialog records a dialog and only then answers it through respond.
// Recording first is load-bearing: dialog-based XSS confirmation depends on the
// event alone, so it must never wait on — or be lost to — the answer.
func (p *Page) handleDialog(e *proto.PageJavascriptDialogOpening, respond func(accept bool, promptText string) error) {
	policy := config.DialogRecordDismiss
	if p.config != nil {
		policy = p.config.Policy.DialogResponse
	}
	kind := string(e.Type)
	accept, promptText := dialogResponse(policy, kind)
	answered := DialogDismissed
	if accept {
		answered = DialogAccepted
	}
	p.recordDialog(DialogEvent{
		Type:     kind,
		Message:  e.Message,
		URL:      e.URL,
		At:       time.Now(),
		Answered: answered,
	})
	_ = respond(accept, promptText)
}

// dialogResponse decides how a dialog of kind is answered under policy.
//
// record-dismiss (the default, and what an empty or unknown policy means):
//   - alert accepts — it has only one button, so there is nothing to cancel;
//   - confirm and prompt dismiss — the only answer that cannot authorize an
//     application change ("Delete this account?");
//   - beforeunload accepts — dismissing it cancels the crawler's own
//     navigation and wedges the loop on the page.
//
// accept-all accepts everything, the pre-policy behavior.
func dialogResponse(policy config.DialogPolicy, kind string) (accept bool, promptText string) {
	if policy == config.DialogAcceptAll {
		return true, ""
	}
	switch kind {
	case string(proto.PageDialogTypeAlert), string(proto.PageDialogTypeBeforeunload):
		return true, ""
	default:
		return false, ""
	}
}

// recordDialog appends a dialog event to the page log, dropping the oldest
// entry once the cap is hit so memory stays bounded.
func (p *Page) recordDialog(ev DialogEvent) {
	p.dialogMu.Lock()
	defer p.dialogMu.Unlock()
	if len(p.dialogs) >= maxRecordedDialogs {
		copy(p.dialogs, p.dialogs[1:])
		p.dialogs = p.dialogs[:len(p.dialogs)-1]
	}
	p.dialogs = append(p.dialogs, ev)
}

// DialogEvents returns a copy of all dialog events recorded on this page.
// Safe for concurrent use.
func (p *Page) DialogEvents() []DialogEvent {
	p.dialogMu.Lock()
	defer p.dialogMu.Unlock()
	if len(p.dialogs) == 0 {
		return nil
	}
	out := make([]DialogEvent, len(p.dialogs))
	copy(out, p.dialogs)
	return out
}

// DrainDialogs returns all recorded dialog events and clears the log.
// Use when you want "events since last drain" semantics.
func (p *Page) DrainDialogs() []DialogEvent {
	p.dialogMu.Lock()
	defer p.dialogMu.Unlock()
	if len(p.dialogs) == 0 {
		return nil
	}
	out := p.dialogs
	p.dialogs = nil
	return out
}

// HandlePopups handles any alert/confirm/prompt dialogs on the page.
// Note: Auto-dialog handler is already set up in setupAutoDialogHandler().
// This method is kept for manual dialog handling if needed.
func (p *Page) HandlePopups() error {
	// Dialog handler is already running in background from setupAutoDialogHandler()
	// This method can be used to trigger immediate check if needed
	return nil
}

// DismissDialog dismisses any currently open dialog.
func (p *Page) DismissDialog() error {
	return proto.PageHandleJavaScriptDialog{
		Accept: false, // Dismiss/cancel
	}.Call(p.boundedPage(0))
}

// AcceptDialog accepts any currently open dialog.
func (p *Page) AcceptDialog(promptText string) error {
	return proto.PageHandleJavaScriptDialog{
		Accept:     true,
		PromptText: promptText,
	}.Call(p.boundedPage(0))
}

// HandleFileDialog enables file chooser interception and returns a handler function.
// Call the returned function with file paths after triggering the file dialog.
// GO EXTENSION: Intercepts OS file chooser dialog for any file upload trigger.
//
// Usage:
//
//	handler, err := page.HandleFileDialog()
//	// Click button/element that opens file dialog
//	button.Click()
//	// Provide files to the intercepted dialog
//	err = handler([]string{"/path/to/file.png"})
func (p *Page) HandleFileDialog() (func([]string) error, error) {
	return p.rodPage.HandleFileDialog()
}
