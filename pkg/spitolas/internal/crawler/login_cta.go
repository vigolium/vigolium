package crawler

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"go.uber.org/zap"
)

// settleSPA waits for the index/seed page's bootstrap network to go idle before
// the crawler snapshots its state and extracts clickables. A heavy enterprise SPA
// (Angular, Salesforce Lightning, …) renders its real UI — including the login
// CTA — only after a chain of sequential bootstrap XHRs lands; the short
// DOMStableTime wait fires while the page is still a half-rendered shell, so the
// CTA and most data calls are otherwise missed. Best-effort and bounded by
// SPASettleTimeout (WaitNetworkIdle returns at that bound even on a long-poll/SSE
// app), so it can never stall the crawl.
func (c *Crawler) settleSPA(ctx context.Context, page *browser.Page) {
	if page == nil || c.config == nil || c.config.SPASettleTimeout <= 0 {
		return
	}
	if ctx.Err() != nil {
		return
	}
	page.WaitNetworkIdle(c.config.DOMStableTime, c.config.SPASettleTimeout)
}

// consentDismissScript clicks cookie-consent "accept" controls in the live DOM,
// piercing shadow roots (web-component consent widgets render inside them). It
// targets well-known consent button ids/classes (OneTrust, TrustArc, HubSpot, …)
// and, as a fallback, any button/link whose visible label is exactly an
// accept-style phrase. Clicking an accept control is harmless and lets the app
// render the content the overlay was gating. Returns the number of controls
// clicked. No backticks: this is embedded as a Go raw string.
const consentDismissScript = `(() => {
  const SELS = [
    '#onetrust-accept-btn-handler',
    '#accept-recommended-btn-handler',
    '.onetrust-accept-btn-handler',
    '#truste-consent-button',
    '#hs-eu-confirmation-button',
    '.cc-allow', '.cc-dismiss',
    '.cookie-accept', '.accept-cookies', '#cookie-accept',
    'button[aria-label="Accept all"]',
    'button[aria-label="Accept All"]',
    'button[aria-label="Accept all cookies"]'
  ];
  const RX = /^(accept all|accept all cookies|accept cookies|accept|agree|i agree|allow all|allow cookies|allow|got it|ok)$/i;
  let clicked = 0;
  const tryClick = (el) => {
    if (!el) return;
    try { el.click(); clicked++; } catch (e) {}
  };
  const walk = (root) => {
    for (const s of SELS) {
      let el; try { el = root.querySelector(s); } catch (e) { el = null; }
      if (el) tryClick(el);
    }
    let btns; try { btns = root.querySelectorAll('button, [role=button], a'); } catch (e) { btns = []; }
    for (const b of btns) {
      const t = (b.innerText || b.textContent || '').trim();
      if (t && t.length <= 24 && RX.test(t)) tryClick(b);
    }
    let all; try { all = root.querySelectorAll('*'); } catch (e) { all = []; }
    for (const el of all) { if (el.shadowRoot) { try { walk(el.shadowRoot); } catch (e) {} } }
  };
  walk(document);
  return clicked;
})()`

// dismissConsentOverlays clicks any cookie-consent accept controls on the page so
// they neither block the app from rendering its real content nor mask the
// elements the crawler extracts/clicks. Best-effort: any failure is logged at
// debug and the crawl continues. When something was dismissed, a short stabilize
// lets the post-consent render settle.
func (c *Crawler) dismissConsentOverlays(ctx context.Context, page *browser.Page) {
	if page == nil || c.config == nil || !c.config.DismissConsent {
		return
	}
	if ctx.Err() != nil {
		return
	}
	raw, err := page.Eval(consentDismissScript)
	if err != nil {
		zap.L().Debug("Consent dismissal failed", zap.Error(err))
		return
	}
	// page.Eval returns JS numbers as float64 (CDP ReturnByValue).
	n, _ := raw.(float64)
	if n > 0 {
		zap.L().Debug("Dismissed cookie-consent overlay", zap.Int("controls_clicked", int(n)))
		_ = page.WaitStable(c.config.DOMStableTime)
	}
}

// loginCTADetectScript scans the live DOM (piercing shadow roots) for the element
// that most looks like a login call-to-action and tags the winner with
// data-vgo-login-cta="1" so Go can click it next. It scores by visible label
// (Log on / Log in / Sign in / Login), by href/onclick pointing at an auth
// endpoint (/oauth2/authorize, response_type=, /idp, /saml, /sso, /login), and by
// login-ish element attributes; anything that reads as a logout control is
// excluded. It returns a JSON object {found,text,href,reason}. No backticks: this
// is embedded as a Go raw string.
const loginCTADetectScript = `(() => {
  const RX_TEXT = /(log\s?on|log\s?in|sign\s?in|signin|logon|login)/i;
  const RX_OUT  = /(log\s?out|sign\s?out|logout|signout)/i;
  const RX_HREF = /(\/oauth2?\/authorize|\/connect\/authorize|response_type=|identity_provider=|\/saml|\/sso(\/|$|\?)|\/idp(\/|$|\?)|\/signin|\/login|\/logon)/i;
  const RX_ATTR = /(login|signin|sign-in|logon|log-on|sso|oauth|openid|saml|idp)/i;
  // Collect candidates piercing shadow roots. Two sources: explicit interactive
  // elements (a/button/role=button/onclick/inputs) AND any element whose own short
  // text reads like a login label — a web-component app (a web-component design system,
  // Stencil, Lit) renders its "Log on" button as a <div>/custom element with a
  // JS-attached click handler, matching none of the standard interactive
  // selectors. Multi-line / long-text containers are excluded so we target the
  // button, not its enclosing card.
  const set = new Set();
  const walk = (root) => {
    let sel; try { sel = root.querySelectorAll('a,button,[role=button],[onclick],input[type=submit],input[type=button]'); } catch (e) { sel = []; }
    for (const el of sel) set.add(el);
    let all; try { all = root.querySelectorAll('*'); } catch (e) { all = []; }
    for (const el of all) {
      let t = ''; try { t = (el.innerText || el.textContent || el.value || '').trim(); } catch (e) {}
      if (t && t.length <= 24 && t.indexOf('\n') === -1 && RX_TEXT.test(t)) set.add(el);
      if (el.shadowRoot) { try { walk(el.shadowRoot); } catch (e) {} }
    }
  };
  walk(document);
  const visible = (el) => {
    try {
      const r = el.getBoundingClientRect();
      if (r.width < 1 || r.height < 1) return false;
      const s = getComputedStyle(el);
      if (s.visibility === 'hidden' || s.display === 'none') return false;
      return true;
    } catch (e) { return true; }
  };
  // Non-interactive: hidden from accessibility, disabled, or a still-loading
  // skeleton placeholder — clicking it does nothing and a real CDP click just
  // times out. SPAs render such a placeholder for the login button before the
  // framework hydrates the real one, so picking it strands the whole flow.
  const interactive = (el) => {
    try {
      if (el.getAttribute('aria-hidden') === 'true') return false;
      if (el.getAttribute('aria-disabled') === 'true') return false;
      if (el.disabled) return false;
      if (el.closest && el.closest('[aria-hidden="true"],[disabled]')) return false;
    } catch (e) {}
    return true;
  };
  // clickableLike reports whether an element can carry a click handler: a real
  // a/button/input, a custom element (web component), a role=button, or an onclick.
  // withCursor also accepts a cursor:pointer element — used when picking a clickable
  // candidate, but NOT when deciding a hidden skeleton is "a login button still
  // hydrating" (a skeleton's cursor style is unreliable).
  const clickableLike = (el, withCursor) => {
    const tag = el.tagName.toLowerCase();
    if (tag === 'a' || tag === 'button' || tag === 'input') return true;
    if (tag.indexOf('-') >= 0) return true; // custom element (web component)
    try {
      if (el.getAttribute('role') === 'button') return true;
      if (el.hasAttribute('onclick')) return true;
      if (withCursor && getComputedStyle(el).cursor === 'pointer') return true;
    } catch (e) {}
    return false;
  };
  // pending = a button-like login control exists but is currently NON-interactive
  // (aria-hidden/disabled, or inside such a subtree — a loading skeleton). It
  // signals "a real CTA is hydrating, worth waiting for" so the Go caller retries
  // longer, while a page with no login affordance at all returns immediately.
  let pending = false;
  const scored = [];
  for (const el of set) {
    const text = (el.innerText || el.textContent || el.value || '').trim();
    const aria = (el.getAttribute && (el.getAttribute('aria-label') || '')) || '';
    const title = (el.getAttribute && (el.getAttribute('title') || '')) || '';
    const labelShort = text.length <= 24 && text.indexOf('\n') === -1;
    const isLoginText = (labelShort && RX_TEXT.test(text)) || RX_TEXT.test(aria) || RX_TEXT.test(title);
    if (!interactive(el)) {
      if (isLoginText && clickableLike(el, false)) pending = true; // a login button still hydrating
      continue;
    }
    // Only genuinely clickable elements — this drops plain containers (body, a
    // wrapping div/section) whose aggregate text happens to be just the login
    // label on an otherwise-empty page, which would never carry the handler.
    if (!clickableLike(el, true)) continue;
    const label = (text + ' ' + aria + ' ' + title);
    if (RX_OUT.test(label)) continue;
    let href = ''; try { href = el.href || el.getAttribute('href') || ''; } catch (e) {}
    let onclick = ''; try { onclick = el.getAttribute('onclick') || ''; } catch (e) {}
    let attrs = '';
    try { for (const a of el.attributes) attrs += ' ' + a.name + '=' + a.value; } catch (e) {}
    let score = 0; const reasons = [];
    if (isLoginText) { score += 5; reasons.push('text'); }
    if ((href && RX_HREF.test(href)) || (onclick && RX_HREF.test(onclick))) { score += 4; reasons.push('href'); }
    if (RX_ATTR.test(attrs)) { score += 1; reasons.push('attr'); }
    if (!reasons.includes('text') && !reasons.includes('href')) continue;
    if (!visible(el)) score -= 3;
    scored.push({el: el, score: score, reason: reasons.join('+'), text: text.slice(0, 80), href: href, tag: el.tagName.toLowerCase()});
  }
  scored.sort((a, b) => b.score - a.score);
  const out = [];
  for (let i = 0; i < scored.length && out.length < 5; i++) {
    const s = scored[i];
    if (s.score < 4) break;
    try { s.el.setAttribute('data-vgo-login-cta', String(out.length)); } catch (e) { continue; }
    out.push({idx: out.length, text: s.text, href: s.href, reason: s.reason, tag: s.tag, score: s.score});
  }
  return JSON.stringify({found: out.length > 0, candidates: out, pending: pending});
})()`

// loginCTASelector re-resolves the i-th candidate tagged by loginCTADetectScript.
func loginCTASelector(idx int) string {
	return fmt.Sprintf(`[data-vgo-login-cta="%d"]`, idx)
}

// loginCTAJSClickScriptFmt is the fallback click path: it finds the tagged
// element (piercing shadow roots) and fires a synthetic click. Used only when the
// real CDP click can't resolve/interact with the element. %s is the selector. No
// backticks: embedded as a Go raw string.
const loginCTAJSClickScriptFmt = `(() => {
  const sel = '%s';
  const find = (root) => {
    let el; try { el = root.querySelector(sel); } catch (e) { el = null; }
    if (el) return el;
    let all; try { all = root.querySelectorAll('*'); } catch (e) { all = []; }
    for (const e of all) { if (e.shadowRoot) { const r = find(e.shadowRoot); if (r) return r; } }
    return null;
  };
  const el = find(document);
  if (!el) return 'notfound';
  try { el.scrollIntoView({block: 'center'}); } catch (e) {}
  el.click();
  return 'clicked';
})()`

// loginCTACandidate is one scored login-CTA candidate from loginCTADetectScript,
// tagged in the DOM as data-vgo-login-cta="<idx>".
type loginCTACandidate struct {
	Idx    int    `json:"idx"`
	Text   string `json:"text"`
	Href   string `json:"href"`
	Reason string `json:"reason"`
	Tag    string `json:"tag"`
	Score  int    `json:"score"`
}

// loginCTAResult is the JSON shape returned by loginCTADetectScript: the
// highest-scoring login CTAs (most likely first), each tagged for re-resolution.
// Pending is true when a login control is present but still hydrating (a
// non-interactive skeleton), so the caller should keep waiting for it.
type loginCTAResult struct {
	Found      bool                `json:"found"`
	Candidates []loginCTACandidate `json:"candidates"`
	Pending    bool                `json:"pending"`
}

// primeLoginCTA finds and clicks a login call-to-action on the landing page (once
// per crawl) to drive the OAuth/SAML/SSO navigation chain it kicks off, then lets
// that chain and the destination login page's own XHRs settle so the network
// capture records every URL they touch, harvests any iframe the login page mounts
// (e.g. an Aura/Lightning captcha), and returns the browser to the landing so the
// crawl loop resumes from a known state. Best-effort: any failure is logged at
// debug and the crawl continues. landingURL is the post-redirect index URL.
func (c *Crawler) primeLoginCTA(ctx context.Context, page *browser.Page, landingURL string) {
	if page == nil || c.config == nil || !c.config.LoginCTAPriming {
		return
	}
	if c.loginCTAPrimed || ctx.Err() != nil {
		return
	}
	c.loginCTAPrimed = true

	// Poll for an interactive login CTA. A heavy SPA renders a non-interactive
	// loading-skeleton placeholder for the login button first and only hydrates the
	// real, clickable one a beat later (after its config/auth XHRs land) — and on a
	// slow landing (an SSO bounce that then client-routes + loads content) that can
	// take many seconds. Keep retrying ONLY while the page still shows a hydrating
	// login control (res.Pending); a page with no login affordance at all returns
	// immediately so ordinary pages aren't slowed.
	var res loginCTAResult
	for attempt := 0; attempt < loginCTADetectAttempts; attempt++ {
		if attempt > 0 {
			if serr := sleepWithContext(ctx, loginCTADetectInterval); serr != nil {
				return
			}
		}
		res = loginCTAResult{}
		raw, err := page.Eval(loginCTADetectScript)
		if err != nil {
			zap.L().Debug("Login-CTA detection failed", zap.Error(err))
			continue
		}
		jsonStr, ok := raw.(string)
		if !ok || jsonStr == "" || jsonStr == "<nil>" {
			continue
		}
		if jerr := json.Unmarshal([]byte(jsonStr), &res); jerr != nil {
			continue
		}
		if res.Found {
			break
		}
		// Probe a minimum window unconditionally — a slow landing (SSO bounce →
		// client-route → content load) renders the login control a few seconds in,
		// after this step starts, so the first probe(s) legitimately see nothing.
		// Past that window, keep going ONLY while a login control is actively
		// hydrating (res.Pending), so ordinary pages with no login affordance stop
		// instead of burning the full budget.
		if attempt+1 >= loginCTAMinAttempts && !res.Pending {
			break
		}
	}
	if !res.Found {
		return
	}

	urlBefore, _ := page.URL()

	// Try the top candidates in score order until one actually drives a navigation.
	// A web-component login button often has several text matches (the host element,
	// its content wrapper, its label) and the real handler may sit on any of them;
	// clicking each in turn — a click bubbles to the handler regardless — until the
	// URL changes is more robust than betting on a single best guess. Bounded so a
	// landing that never navigates can't drain the crawl budget.
	driven := false
	for i, cand := range res.Candidates {
		if i >= loginCTAMaxClicks || ctx.Err() != nil {
			break
		}
		zap.L().Debug("Trying login-CTA candidate",
			zap.String("text", cand.Text),
			zap.String("href", cand.Href),
			zap.String("matched", cand.Reason),
			zap.String("tag", cand.Tag),
			zap.Int("score", cand.Score))

		c.clickLoginCTA(page, cand.Idx, cand.Tag)

		// The click's effect (an async PKCE handler, a router hop, then a full-page
		// OAuth redirect) is not instantaneous, so wait for the top-level URL to
		// actually change before deciding the click drove a flow. Only a real
		// navigation counts as "driven" — a click that does nothing must not be
		// reported as having entered the auth flow.
		if c.waitForNavigation(ctx, page, urlBefore, loginCTANavTimeout) {
			c.stats.LoginCTADriven = true
			c.stats.LoginCTAText = cand.Text
			driven = true
			zap.L().Info("Spidering: drove login CTA into the auth flow",
				zap.String("text", cand.Text), zap.String("matched", cand.Reason))
			break
		}
		zap.L().Debug("Login-CTA candidate did not navigate", zap.Int("idx", cand.Idx), zap.String("text", cand.Text))
	}
	if !driven {
		// Nothing navigated — don't burn the crawl budget on settles and an
		// iframe-prime that have nothing new to capture.
		return
	}

	// Let the OAuth/SAML/SSO chain land and the destination login page run its own
	// bootstrap XHRs (Aura/Lightning data calls, captcha, …) so the capture records
	// them. Bounded by SPASettleTimeout.
	_ = page.WaitStable(c.config.DOMStableTime)
	page.WaitNetworkIdle(c.config.DOMStableTime, c.config.SPASettleTimeout)

	if landedURL, uerr := page.URL(); uerr == nil {
		zap.L().Debug("Login-CTA flow landed", zap.String("url", landedURL))
	}

	// Harvest any iframe the login page mounts (e.g. an Aura/Lightning captcha host
	// whose URL carries a reflected query parameter). The destination login app
	// (Salesforce Lightning/Aura) mounts that iframe a beat AFTER its own bootstrap
	// (/aura, /c/*.app) lands, so harvest twice with a settle between to catch the
	// late mount, not just the iframes present on first paint.
	for pass := 0; pass < loginCTAIframePasses; pass++ {
		if pass > 0 {
			page.WaitNetworkIdle(c.config.DOMStableTime, c.config.SPASettleTimeout)
		}
		if ctx.Err() != nil {
			break
		}
		c.primeIframeAssets(ctx, page)
	}

	// Return to the landing so the crawl loop resumes from the captured index
	// state rather than stranded deep in the login flow.
	if landingURL != "" {
		if nerr := page.Navigate(landingURL); nerr != nil {
			zap.L().Debug("Failed to return to landing after login-CTA flow", zap.Error(nerr))
		}
	}
}

// clickLoginCTA clicks the idx-th tagged candidate. For a real <button>/<a>/input
// it prefers a real CDP mouse click (a trusted event with the full pointer
// sequence) — SPA login buttons sometimes build the OAuth/PKCE URL in a handler a
// synthetic click does not reliably trigger — resolving the element piercing
// shadow roots. For other tags (a web-component <div> label/host) the CDP click
// just waits out the element timeout because the node isn't "interactable", so go
// straight to a synthetic click, which bubbles to the real handler on an ancestor.
func (c *Crawler) clickLoginCTA(page *browser.Page, idx int, tag string) {
	selector := loginCTASelector(idx)
	if tag == "button" || tag == "a" || tag == "input" {
		if elem, eerr := page.ElementPiercing(selector); eerr == nil && elem != nil {
			if cerr := elem.Click(); cerr == nil {
				return
			}
			zap.L().Debug("Login-CTA real click failed, falling back to JS click", zap.String("selector", selector))
		}
	}
	if _, cerr := page.Eval(fmt.Sprintf(loginCTAJSClickScriptFmt, selector)); cerr != nil {
		zap.L().Debug("Login-CTA JS click eval returned (navigation likely in flight)", zap.Error(cerr))
	}
}

// loginCTADetectAttempts / loginCTADetectInterval bound the poll for an
// interactive login CTA to appear (a SPA hydrates the real button shortly after
// rendering a loading skeleton). The full budget (~25s) is only ever spent while
// the page still shows a hydrating login control; a page with no login affordance
// returns after the first probe, so ordinary pages pay almost nothing.
const (
	loginCTADetectAttempts = 25
	loginCTAMinAttempts    = 10
	loginCTADetectInterval = 1 * time.Second
)

// loginCTAMaxClicks caps how many candidate CTAs primeLoginCTA clicks while
// looking for one that drives a navigation, so a landing whose login button never
// becomes interactive (e.g. an auth-gated app that stalls unauthenticated) can't
// drain the crawl budget.
const loginCTAMaxClicks = 3

// loginCTANavTimeout bounds how long primeLoginCTA waits for the login-CTA click
// to produce a top-level navigation before concluding the click drove nothing.
const loginCTANavTimeout = 6 * time.Second

// loginCTAIframePasses is how many settle+harvest passes run on the destination
// login page, to catch iframes (e.g. an Aura captcha) that mount after the page's
// own bootstrap rather than on first paint.
const loginCTAIframePasses = 2

// waitForNavigation polls the page URL until it differs from before (a redirect,
// router hop, or full navigation started), returning true on change. Bounded by
// timeout and by ctx; returns false if the URL never changes.
func (c *Crawler) waitForNavigation(ctx context.Context, page *browser.Page, before string, timeout time.Duration) bool {
	attempts := int(timeout / loginCTANavPollInterval)
	for i := 0; i < attempts; i++ {
		if ctx.Err() != nil {
			return false
		}
		if cur, err := page.URL(); err == nil && cur != before {
			return true
		}
		if serr := sleepWithContext(ctx, loginCTANavPollInterval); serr != nil {
			return false
		}
	}
	return false
}

// loginCTANavPollInterval is the poll cadence for waitForNavigation.
const loginCTANavPollInterval = 250 * time.Millisecond
