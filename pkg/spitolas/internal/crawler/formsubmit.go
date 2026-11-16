package crawler

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/safety"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
	"go.uber.org/zap"
)

// getFormSubmitURLsScript enumerates the GET forms in the live DOM and, for each,
// builds the exact URL the browser would navigate to on submit from the form's
// resolved action plus its currently-filled successful controls — i.e. the same
// serialization a real GET submit performs. It returns a JSON array of absolute,
// same-origin URLs (deduped, only forms that produce at least one query value).
//
// This is what makes a search/filter box discoverable: the interaction crawl only
// submits a form when its submit control happens to be clicked as an ordinary
// clickable, which the bounded action budget frequently never selects. Fetching
// the synthesized URLs makes GET-form submission deterministic. No backticks: this
// is embedded as a Go raw string.
const getFormSubmitURLsScript = `(() => {
  const out = [];
  const seen = new Set();
  let forms;
  try { forms = document.querySelectorAll('form'); } catch (e) { forms = []; }
  for (const form of forms) {
    const method = (form.getAttribute('method') || form.method || 'get').toLowerCase();
    if (method !== 'get') continue;
    let action;
    try { action = new URL(form.action || location.href, location.href); } catch (e) { continue; }
    if (action.origin !== location.origin) continue;
    const params = new URLSearchParams();
    let named = 0;
    let els; try { els = form.elements; } catch (e) { els = []; }
    for (const el of els) {
      const name = el.name;
      if (!name || el.disabled) continue;
      const type = (el.type || '').toLowerCase();
      // Skip non-successful / non-serialized controls and never leak a password
      // or upload into a URL.
      if (type === 'submit' || type === 'button' || type === 'reset' ||
          type === 'image' || type === 'file' || type === 'password') continue;
      if ((type === 'checkbox' || type === 'radio') && !el.checked) continue;
      if (el.tagName === 'SELECT' && el.multiple) {
        for (const opt of el.selectedOptions) { params.append(name, opt.value); named++; }
        continue;
      }
      params.append(name, el.value != null ? el.value : '');
      named++;
    }
    if (named === 0) continue;
    const qs = params.toString();
    if (!qs) continue;
    action.search = qs;
    const href = action.href;
    if (seen.has(href)) continue;
    seen.add(href);
    out.push(href);
  }
  return JSON.stringify(out);
})()`

// submitGetForms synthesizes the submit URL of each GET form on the page from its
// resolved action + filled values and fetches the new ones in-page so the
// browser's network capture records them. It is the deterministic counterpart to
// hoping the interaction crawl clicks each search/filter form's submit button.
// Best-effort: any failure is logged at debug and the crawl continues. Deduped
// and capped across the whole crawl so a form present on every page is fetched
// once. alreadyFilled says the caller has just filled the page's forms (the index
// path does), so the fill isn't repeated; new states pass false.
func (c *Crawler) submitGetForms(ctx context.Context, page *browser.Page, alreadyFilled bool) {
	// The mechanism switch (derived from the policy by ApplyPolicy) and the
	// permission itself must both allow it.
	if page == nil || c.config == nil || !c.config.SubmitGetForms || !c.config.Policy.SubmitForms {
		return
	}
	if ctx.Err() != nil {
		return
	}

	// Fill the page's forms first so a search/filter box carries a real value
	// (getSmartValue seeds e.g. searchTerm=a); an unfilled GET form would either
	// produce no query or an empty one and get skipped by the synthesizer.
	if !alreadyFilled && c.config.FormFillEnabled {
		c.fillFormsIfPresent(page, "")
	}

	raw, err := page.Eval(getFormSubmitURLsScript)
	if err != nil {
		zap.L().Debug("GET-form submit URL synthesis failed", zap.Error(err))
		return
	}
	jsonStr, ok := raw.(string)
	if !ok || jsonStr == "" || jsonStr == "<nil>" {
		return
	}
	var discovered []string
	if err := parseJSONLinks(jsonStr, &discovered); err != nil || len(discovered) == 0 {
		return
	}

	toFetch := c.selectUnsubmittedForms(discovered, c.config.SubmitFormMaxVariants)
	c.countSubmitDispatched(submitMechGetSynthesis, c.fetchURLsInPage(ctx, page, toFetch, "GET-form"))
}

// selectUnsubmittedForms returns the URLs from in that have not been submitted yet
// this crawl (marking them submitted), capped so the running crawl-wide total
// stays at or below max (<=0 disables the cap). Safe for concurrent use.
func (c *Crawler) selectUnsubmittedForms(in []string, max int) []string {
	c.submittedFormsMu.Lock()
	defer c.submittedFormsMu.Unlock()
	if c.submittedForms == nil {
		c.submittedForms = make(map[string]bool)
	}
	out := make([]string, 0, len(in))
	for _, u := range in {
		// GET and POST form submissions share one crawl-wide budget, so the cap
		// counts both maps' running totals (submitPostForms uses submittedPostForms).
		if max > 0 && len(c.submittedForms)+len(c.submittedPostForms) >= max {
			break
		}
		if c.submittedForms[u] {
			continue
		}
		c.submittedForms[u] = true
		out = append(out, u)
	}
	return out
}

// enumeratePostFormsScript lists the same-origin POST forms in the live DOM that are
// safe to exercise, tags each with a data-vig-pf index attribute (so the submit pass
// can target the exact element), and returns a JSON array of {i, sig, action}. It
// skips forms that carry a password field (authentication — left to the login pass)
// and forms whose action/id/class/name reads as destructive (logout, delete,
// unsubscribe, close-account) so a crawl never fires an irreversible action. The sig
// is the resolved action plus the sorted names of the form's serialized controls, so
// the same structural form recurring across pages dedups to one submission. No
// backticks: this is embedded as a Go raw string.
var enumeratePostFormsScript = strings.Replace(enumeratePostFormsScriptSrc,
	"__DESTRUCTIVE_RE__", safety.JSRegexLiteral(safety.DestructivePattern), 1)

// postFormsScript is enumeratePostFormsScript, its destructive pattern
// widened by spidering.deny_click_extra when set; built once per crawl. An
// extra JavaScript cannot parse makes the enumeration fail, so no POST form is
// submitted: the failure is on the safe side.
func (c *Crawler) postFormsScript() string {
	c.postFormsJSOnce.Do(func() {
		c.postFormsJS = enumeratePostFormsScript
		if extra := strings.TrimSpace(c.config.DenyClickExtra); extra != "" {
			c.postFormsJS = strings.Replace(enumeratePostFormsScriptSrc,
				"__DESTRUCTIVE_RE__", safety.JSRegexLiteral(safety.DestructivePattern+"|"+extra), 1)
		}
	})
	return c.postFormsJS
}

const enumeratePostFormsScriptSrc = `(() => {
  const out = [];
  let forms;
  try { forms = document.querySelectorAll('form'); } catch (e) { forms = []; }
  const DESTRUCTIVE = __DESTRUCTIVE_RE__;
  const METHOD_OVERRIDE = /^(_method|_HttpMethod|X-HTTP-Method-Override)$/i;
  const DESTRUCTIVE_VERB = /^(delete|put|patch)$/i;
  let i = 0;
  for (const form of forms) {
    try { form.removeAttribute('data-vig-pf'); } catch (e) {}
    const method = (form.getAttribute('method') || form.method || 'get').toLowerCase();
    if (method !== 'post') continue;
    let action;
    try { action = new URL(form.getAttribute('action') || form.action || location.href, location.href); } catch (e) { continue; }
    if (action.origin !== location.origin) continue;
    let els; try { els = form.elements; } catch (e) { els = []; }
    let hasPassword = false;
    let destructiveControl = false;
    const names = [];
    for (const el of els) {
      const type = (el.type || '').toLowerCase();
      if (type === 'password') { hasPassword = true; break; }
      // A framework method-override control (Rails/Laravel _method=DELETE, …)
      // encodes the real verb in a hidden field the form's method attribute hides,
      // so submitting the form would fire a destructive DELETE/PUT/PATCH the crawl
      // never saw. Skip such forms.
      if (el.name && METHOD_OVERRIDE.test(el.name) && DESTRUCTIVE_VERB.test((el.value || '').trim())) {
        destructiveControl = true; break;
      }
      // A submit control whose label/value reads destructive (a "Delete" button)
      // even when the form's action/id/class do not.
      if ((type === 'submit' || type === 'image' || type === 'button') &&
          DESTRUCTIVE.test((el.value || '') + ' ' + (el.textContent || ''))) {
        destructiveControl = true; break;
      }
      if (el.name && el.name.length && !el.disabled &&
          type !== 'submit' && type !== 'button' && type !== 'reset' && type !== 'image') {
        names.push(el.name);
      }
    }
    if (hasPassword || destructiveControl) continue;
    const hay = (form.getAttribute('action') || '') + ' ' + (form.id || '') + ' ' +
                (form.className || '') + ' ' + (form.getAttribute('name') || '');
    if (DESTRUCTIVE.test(hay)) continue;
    names.sort();
    const sig = action.href + ' post ' + names.join(',');
    form.setAttribute('data-vig-pf', String(i));
    out.push({ i: i, sig: sig });
    i++;
  }
  return JSON.stringify(out);
})()`

// submitPostFormsScript triggers the forms whose data-vig-pf index is in the
// Go-supplied approved set (the %s, a JSON array of indices); the two %d
// are the per-form handler grace and the whole script's time budget, in ms.
//
// Forms are triggered one at a time. For each it installs a capture-phase submit
// guard that preventDefaults native navigation — so a POST submit never unloads
// the crawl page — and dispatches a SINGLE trigger (the submit button's click,
// or a synthetic submit event when the form has no button) so a JS-driven form
// fires its real, correctly-typed request (e.g. a stock check posting
// application/xml). fetch and XMLHttpRequest are instrumented with per-form
// attribution: while a form is current, a request whose URL resolves under the
// form's action origin+path is that form's submission; any other request is
// activity that cannot be attributed to it. The form then settles — polled every
// 25 ms for up to the grace window — and gets exactly one outcome:
//
//   - handler_submitted: an attributed request was seen (the page's handler did it)
//   - uncertain:         only unattributable requests were seen — a handler posting
//     elsewhere, or a background poll. NO fallback is sent: guessing wrong would
//     fire the same state-changing request twice
//   - fallback_sent:     nothing fired in the whole window (a handler-less form), so
//     a plain urlencoded (or multipart) POST is synthesized — fallback_failed when
//     that request could not be sent
//   - not_triggered:     the time budget ran out before the form was reached
//
// The browser's network capture records whichever requests result. Returns the
// JSON array of {i, action, outcome}. No backticks: embedded as a Go raw string.
const submitPostFormsScript = `(async () => {
  const approved = new Set(%s);
  const graceMs = %d;
  const deadline = Date.now() + %d;
  let forms;
  try { forms = document.querySelectorAll('form[data-vig-pf]'); } catch (e) { forms = []; }
  const results = [];
  const jobs = [];

  // Per-form attribution: current is the form being triggered and settled.
  let current = null;
  const underPath = (p, base) => p === base ||
    p.startsWith(base.endsWith('/') ? base : base + '/');
  const note = (u) => {
    if (!current) return;
    let url;
    try { url = new URL(String(u), location.href); } catch (e) { current.other++; return; }
    if (url.origin === current.action.origin && underPath(url.pathname, current.action.pathname)) {
      current.attributed++;
    } else {
      current.other++;
    }
  };
  const realFetch = window.fetch;
  const realOpen = XMLHttpRequest.prototype.open;
  const realSend = XMLHttpRequest.prototype.send;
  try {
    window.fetch = function (input) {
      try { note(input && typeof input === 'object' && 'url' in input ? input.url : input); } catch (e) {}
      return realFetch.apply(this, arguments);
    };
    XMLHttpRequest.prototype.open = function (method, url) { this.__vigURL = url; return realOpen.apply(this, arguments); };
    XMLHttpRequest.prototype.send = function () { if (this.__vigURL !== undefined) note(this.__vigURL); return realSend.apply(this, arguments); };
  } catch (e) {}

  // Bounded settle: return as soon as the form's own request is seen, else after
  // the whole grace window, so a delayed handler is still attributed.
  const settle = async (rec) => {
    const until = Math.min(Date.now() + graceMs, deadline);
    while (rec.attributed === 0 && Date.now() < until) {
      await new Promise((r) => setTimeout(r, 25));
    }
  };

  try {
    for (const form of forms) {
      const idx = parseInt(form.getAttribute('data-vig-pf') || '-1', 10);
      try { form.removeAttribute('data-vig-pf'); } catch (e) {}
      if (!approved.has(idx)) continue;
      let action;
      try { action = new URL(form.getAttribute('action') || form.action || location.href, location.href); } catch (e) {
        results.push({ i: idx, outcome: 'not_triggered' });
        continue;
      }
      if (Date.now() >= deadline) {
        results.push({ i: idx, action: action.href, outcome: 'not_triggered' });
        continue;
      }
      const btn = form.querySelector('button[type=submit],input[type=submit],button:not([type]):not([type=button]):not([type=reset])');
      const guard = (e) => { try { e.preventDefault(); } catch (x) {} };
      const rec = { action: action, attributed: 0, other: 0 };
      // The guard stays on through the settle window, so a handler that calls
      // requestSubmit() late still cannot navigate the crawl page away.
      form.addEventListener('submit', guard, true);
      current = rec;
      // Dispatch EITHER the button click OR a synthetic submit — not both. A button
      // click natively produces a submit event, so doing both would double-fire the
      // page's handler on its own.
      try {
        if (btn) {
          btn.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
        } else {
          const SE = window.SubmitEvent || Event;
          form.dispatchEvent(new SE('submit', { bubbles: true, cancelable: true }));
        }
      } catch (e) {}
      await settle(rec);
      current = null;
      try { form.removeEventListener('submit', guard, true); } catch (e) {}
      if (rec.attributed > 0) {
        results.push({ i: idx, action: action.href, outcome: 'handler_submitted' });
        continue;
      }
      if (rec.other > 0) {
        results.push({ i: idx, action: action.href, outcome: 'uncertain' });
        continue;
      }
      // Nothing fired in the whole window: a handler-less form. realFetch keeps the
      // fallback out of the attribution of the forms that follow.
      const res = { i: idx, action: action.href, outcome: 'fallback_sent' };
      results.push(res);
      jobs.push((async () => {
        try {
          const fd = new FormData(form, btn || undefined);
          const enctype = (form.getAttribute('enctype') || '').toLowerCase();
          let body, headers = {};
          if (enctype.indexOf('multipart') >= 0) {
            body = fd;
          } else {
            body = new URLSearchParams(fd).toString();
            headers['Content-Type'] = 'application/x-www-form-urlencoded';
          }
          const r = await realFetch.call(window, action.href, { method: 'POST', body, headers, credentials: 'include', redirect: 'follow' });
          try { await r.arrayBuffer(); } catch (e) {}
        } catch (e) {
          res.outcome = 'fallback_failed';
        }
      })());
    }
    await Promise.all(jobs);
  } finally {
    // Restore originals so the instrumentation never leaks into later page use.
    current = null;
    try {
      window.fetch = realFetch;
      XMLHttpRequest.prototype.open = realOpen;
      XMLHttpRequest.prototype.send = realSend;
    } catch (e) {}
  }
  return JSON.stringify(results);
})()`

// POST-form outcomes returned by submitPostFormsScript.
const (
	postOutcomeHandler        = "handler_submitted"
	postOutcomeFallback       = "fallback_sent"
	postOutcomeFallbackFailed = "fallback_failed"
	postOutcomeUncertain      = "uncertain"
	postOutcomeNotTriggered   = "not_triggered"
)

// postFormScriptBudget bounds the triggering loop inside submitPostFormsScript,
// leaving the rest of iframePrimeTimeout for the fallback requests to finish, so
// the eval returns its outcomes instead of being abandoned mid-run.
const postFormScriptBudget = iframePrimeTimeout - 15*time.Second

// postFormOutcome is one approved form's result from submitPostFormsScript.
type postFormOutcome struct {
	Index   int    `json:"i"`
	Action  string `json:"action"`
	Outcome string `json:"outcome"`
}

// postFormDescriptor is one candidate POST form returned by enumeratePostFormsScript:
// its data-vig-pf index and its dedup signature (which already begins with the
// resolved action).
type postFormDescriptor struct {
	Index int    `json:"i"`
	Sig   string `json:"sig"`
}

// submitPostForms triggers each same-origin POST form on the page so its endpoint is
// exercised and captured. Unlike GET forms — whose submit URL can be synthesized and
// fetched (submitGetForms) — POST forms are frequently JS-driven: the page intercepts
// the submit and fires the real request through its own handler with a specific
// content type (a stock check posting an XML body, a newsletter posting JSON on button
// click). So for each approved form this dispatches the page's submit and
// submit-button-click handlers under a navigation guard — letting the site build the
// correctly-typed request — and, for forms with no JS handler, synthesizes a plain
// POST. This is what makes a JS-driven endpoint like /catalog/product/stock (a common
// home for XXE and body/cookie SQLi) reachable; the interaction crawl only submits a
// POST form if its bounded budget happens to click the button. Deduped by
// (action + field-name) signature and capped across the whole crawl. Best-effort: any
// failure is logged at debug and the crawl continues. alreadyFilled says the caller
// has just filled the page's forms, so the fill isn't repeated.
func (c *Crawler) submitPostForms(ctx context.Context, page *browser.Page, alreadyFilled bool) {
	if page == nil || c.config == nil || !c.config.SubmitPostForms || !c.config.Policy.SubmitForms {
		return
	}
	if ctx.Err() != nil {
		return
	}

	// Fill the page's forms first so a stock/quote form carries real values (a
	// selected store, a quantity) rather than submitting empty fields.
	if !alreadyFilled && c.config.FormFillEnabled {
		c.fillFormsIfPresent(page, "")
	}

	raw, err := page.Eval(c.postFormsScript())
	if err != nil {
		zap.L().Debug("POST-form enumeration failed", zap.Error(err))
		return
	}
	jsonStr, ok := raw.(string)
	if !ok || jsonStr == "" || jsonStr == "<nil>" {
		return
	}
	var descs []postFormDescriptor
	if err := json.Unmarshal([]byte(jsonStr), &descs); err != nil || len(descs) == 0 {
		return
	}

	approved := c.selectUnsubmittedPostForms(descs, c.config.SubmitFormMaxVariants)
	if len(approved) == 0 {
		return
	}
	payload, err := json.Marshal(approved)
	if err != nil {
		return
	}
	grace := c.config.FormHandlerGrace
	if grace <= 0 {
		grace = config.DefaultFormHandlerGrace
	}
	script := fmt.Sprintf(submitPostFormsScript, string(payload), grace.Milliseconds(), postFormScriptBudget.Milliseconds())

	result, evalOK := evalAwaitCtx(ctx, page, script, iframePrimeTimeout, "post-form-submit")
	outcomes, parsed := parsePostFormOutcomes(result)
	if !evalOK || !parsed {
		// The forms may already have been triggered; with no outcome to read,
		// every approved form is uncertain. Their signatures stay consumed.
		outcomes = make([]postFormOutcome, 0, len(approved))
		for _, idx := range approved {
			outcomes = append(outcomes, postFormOutcome{Index: idx, Outcome: postOutcomeUncertain})
		}
	}
	c.applyPostFormOutcomes(descs, approved, outcomes)
}

// parsePostFormOutcomes decodes submitPostFormsScript's JSON result.
func parsePostFormOutcomes(result interface{}) ([]postFormOutcome, bool) {
	s, ok := result.(string)
	if !ok || s == "" || s == "<nil>" {
		return nil, false
	}
	var outcomes []postFormOutcome
	if err := json.Unmarshal([]byte(s), &outcomes); err != nil {
		return nil, false
	}
	return outcomes, true
}

// applyPostFormOutcomes records what submitPostFormsScript reported for the
// approved forms. handler_submitted and fallback_sent are dispatched
// submissions. uncertain is counted in Stats.FormSubmitsUncertain with a warn
// naming the action; its signature stays consumed (selectUnsubmittedPostForms
// marked it), so no later page retries it — a retry is exactly the duplicate
// write the outcome exists to avoid. not_triggered never reached the page, so
// its signature is released for a later page. An approved form the script did
// not report on is treated as uncertain.
func (c *Crawler) applyPostFormOutcomes(descs []postFormDescriptor, approved []int, outcomes []postFormOutcome) {
	sigByIndex := make(map[int]string, len(descs))
	for _, d := range descs {
		sigByIndex[d.Index] = d.Sig
	}
	reported := make(map[int]bool, len(outcomes))
	dispatched, uncertain, fallbacks := 0, 0, 0
	for _, o := range outcomes {
		reported[o.Index] = true
		switch o.Outcome {
		case postOutcomeHandler:
			dispatched++
		case postOutcomeFallback:
			dispatched++
			fallbacks++
		case postOutcomeNotTriggered:
			c.releasePostFormSignature(sigByIndex[o.Index])
		case postOutcomeFallbackFailed:
			zap.L().Debug("POST-form fallback request could not be sent", zap.String("action", o.Action))
		default: // postOutcomeUncertain, or anything unrecognized
			uncertain++
			action := o.Action
			if action == "" {
				action, _, _ = strings.Cut(sigByIndex[o.Index], " post ")
			}
			zap.L().Warn("POST form submission uncertain: requests fired that cannot be attributed to the form; no fallback sent and the form will not be retried",
				zap.String("action", action))
		}
	}
	for _, idx := range approved {
		if !reported[idx] {
			uncertain++
			action, _, _ := strings.Cut(sigByIndex[idx], " post ")
			zap.L().Warn("POST form submission uncertain: no outcome reported; the form will not be retried",
				zap.String("action", action))
		}
	}

	c.countSubmitDispatched(submitMechPostTrigger, dispatched)
	if uncertain > 0 {
		c.mu.Lock()
		c.stats.FormSubmitsUncertain += uncertain
		c.mu.Unlock()
	}
	zap.L().Debug("POST forms triggered",
		zap.Int("approved", len(approved)),
		zap.Int("dispatched", dispatched),
		zap.Int("fallback_fetches", fallbacks),
		zap.Int("uncertain", uncertain))
}

// releasePostFormSignature un-consumes a POST-form signature that was approved
// but never triggered, so a later page may submit it.
func (c *Crawler) releasePostFormSignature(sig string) {
	if sig == "" {
		return
	}
	c.submittedFormsMu.Lock()
	delete(c.submittedPostForms, sig)
	c.submittedFormsMu.Unlock()
}

// selectUnsubmittedPostForms returns the data-vig-pf indices of the descriptors whose
// (action + field-name) signature has not been submitted yet this crawl (marking them
// submitted), capped so the running crawl-wide form-submission total stays at or below
// max (<=0 disables the cap). Mirrors selectUnsubmittedForms for the GET path but keys
// on the structural signature (POST bodies differ per page) and shares the same cap
// budget via a distinct dedup set. Safe for concurrent use.
func (c *Crawler) selectUnsubmittedPostForms(descs []postFormDescriptor, max int) []int {
	c.submittedFormsMu.Lock()
	defer c.submittedFormsMu.Unlock()
	if c.submittedPostForms == nil {
		c.submittedPostForms = make(map[string]bool)
	}
	out := make([]int, 0, len(descs))
	for _, d := range descs {
		// GET and POST form submissions share one crawl-wide budget, so the cap
		// counts both maps' running totals (submitGetForms uses submittedForms).
		if max > 0 && len(c.submittedForms)+len(c.submittedPostForms) >= max {
			break
		}
		if d.Sig == "" || c.submittedPostForms[d.Sig] {
			continue
		}
		c.submittedPostForms[d.Sig] = true
		out = append(out, d.Index)
	}
	return out
}
