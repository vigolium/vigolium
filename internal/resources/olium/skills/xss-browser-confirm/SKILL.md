---
name: xss-browser-confirm
description: Turn a suspected Cross-Site Scripting reflection or DOM sink into proof of JavaScript execution by firing a uniquely-tagged dialog in a real headless browser via the browser_probe tool — not by string-matching the response. Covers reflected, stored, and DOM-based XSS, context-aware payload crafting (HTML body, attribute, JS string, URL/href, DOM sink), light WAF/encoding evasion when a payload reflects but doesn't execute, and persisting a finding sized by real impact. Use when a parameter's value appears in the response, when a DOM sink (innerHTML, document.write, eval, location) consumes input, when CWE-79 was flagged, or when a scanner saw reflection but couldn't confirm execution.
license: MIT
tags:
  - xss
  - dom
  - browser-confirm
allowed-tools:
  - query_records
  - inspect_record
  - replay_request
  - browser_probe
  - report_finding
  - update_finding
  - remember
  - update_plan
---

# XSS → Browser-Confirmed Execution

You suspect XSS somewhere. Reflection is a hint, not proof. Your job is to
make JavaScript actually *run* in a real browser and capture the proof —
then persist a finding with the exact URL that executed. `browser_probe`
loads a URL in headless Chrome and reports any `alert`/`confirm`/`prompt`
dialog that fires, even when nothing reflects visibly in the HTML. That
dialog is your oracle.

## When this skill applies

- A URL/body/header param value appears in the response body or a header.
- A scanner/audit flagged CWE-79, "reflected XSS", "DOM XSS", or "reflection
  observed, execution unconfirmed".
- The page's JS feeds input into a sink: `innerHTML`, `outerHTML`,
  `document.write`, `eval`, `setTimeout(string)`, `location`/`href`,
  `$(...).html()`, `dangerouslySetInnerHTML`.

If you only have "fuzz everything", anchor on a record first
(`query_records` for reflected params / search endpoints, then
`inspect_record`). Don't probe blind.

## The canary discipline

Use one **unique** canary per probe so a dialog can't be a coincidence or a
leftover from another page. Make it specific and greppable, e.g.
`alert('xss-9f3a2c')`. After `browser_probe`, the proof is
`dialog_fired == true` **and** the dialog message equals your canary. A
dialog with a different message is the app's own JS — not your finding.

`remember` the canary + target as `xss-target` so it survives context churn.

## Workflow

### 1. Anchor and find the reflection / sink

`inspect_record` the candidate. Find **where** the input lands:

- In the **response body** → reflected; note the surrounding bytes.
- Consumed by **client JS** with no server reflection → DOM-based; read the
  JS to find the sink and the source (`location.hash`, `location.search`,
  `document.referrer`, `postMessage`).
- Persisted then rendered on **another page** (profile, comment, admin
  panel) → stored; note the injection request and the rendering URL.

### 2. Classify the injection context

The payload must break out of *its* context. Identify which one:

- **HTML element body** (`<div>HERE</div>`): `<script>alert('c')</script>`
  or, if `<script>` is stripped, `<img src=x onerror=alert('c')>`.
- **HTML attribute** (`value="HERE"`): close the attribute/tag first —
  `"><img src=x onerror=alert('c')>` or, inside an event-capable tag,
  `" onmouseover=alert('c') autofocus tabindex=1 x="`.
- **JS string literal** (`var q='HERE'`): close the string —
  `';alert('c')//` or `</script><script>alert('c')</script>`.
- **URL / href sink** (`<a href="HERE">`, `location='HERE'`):
  `javascript:alert('c')`.
- **DOM sink** (`el.innerHTML = location.hash.slice(1)`): put the payload in
  the **fragment** — `#<img src=x onerror=alert('c')>` — see step 4.

### 3. Confirm reflected XSS

Build the full URL with the payload in the query string and call
`browser_probe`:

- `url`: the endpoint with `?param=<url-encoded payload>`.
- `wait_ms`: bump to `1500` if the app defers work (SPA hydration,
  `setTimeout`-wrapped sinks); the default `700` misses late dialogs.
- `wait_selector`: optional CSS selector to wait for before sampling.

Read the result: `dialog_fired:true` + message == canary → **confirmed**.
If the value reflects in the HTML but no dialog fires, it's reflected-only
(likely encoded or CSP-blocked) — go to step 6, don't report yet.

### 4. Confirm DOM-based XSS

DOM XSS often lives in the **fragment**, which the server never sees (so
server-side reflection and WAFs are blind to it). Put the payload after `#`:

- `url`: `https://target/page#<img src=x onerror=alert('c')>` (or
  `#javascript:alert('c')` for a location sink).
- `browser_probe` executes the page's real JS, so a vulnerable
  `innerHTML = location.hash` fires the dialog. No dialog → the sink sanitizes
  or the source isn't what you think; re-read the JS.

### 5. Confirm stored XSS

Two steps:

1. `replay_request` the write that persists your payload (post a comment,
   update a profile field) with the canary payload in the stored field.
2. `browser_probe` the **rendering** page (where the stored value is shown,
   often an admin/other-user view). Dialog fires there → stored XSS, which is
   higher impact than reflected (no user interaction / victim is whoever
   views the page).

Note the rendering context in the finding — "fires in the admin moderation
queue" is materially worse than "fires on the author's own page".

### 6. Reflected-but-not-executing: light evasion

If the payload reflects but no dialog fires, the value is encoded, filtered,
or CSP-blocked. Iterate a *few* targeted variants — don't brute force:

- **Case / tag mutation**: `<sCRipt>`, `<svg/onload=alert('c')>`,
  `<img src=x onerror=alert('c')>` when `script` is filtered.
- **Encoding**: HTML entities, URL double-encoding, or splitting filtered
  keywords; match the encoding to where reflection lands.
- **Attribute breakout** variants if `>` or `"` is stripped but the other
  isn't.
- **CSP check**: if `final_url`/headers show a strict `Content-Security-Policy`
  with no `unsafe-inline`, inline handlers won't run. Note the CSP — it can
  downgrade or block the finding; an injection that can't execute under the
  deployed CSP is at most informational. Look for a CSP bypass (allowed CDN,
  `nonce` reuse, JSONP endpoint) before claiming execution.

Re-`browser_probe` after each variant. Stop after a handful; if nothing
fires, report it as reflection-only (low/informational) with the encoding
you observed, not as confirmed XSS.

### 7. Persist the finding

`report_finding` once per distinct sink:

- `severity`: stored → high/critical; reflected with execution → high; DOM
  with execution → high; reflection-only / CSP-blocked → low or
  informational.
- `title`: type + endpoint + param/sink, e.g. `"Reflected XSS in
  /search?q executes arbitrary JS"` or `"DOM XSS via location.hash →
  innerHTML on /dashboard"`.
- `cwe_id`: CWE-79.
- `description`: 2–3 sentences — context, the payload, that a real browser
  fired `alert(<canary>)`, and the rendering context for stored XSS.
- Include the **exact URL** (or the write request + rendering URL for stored)
  that fired the dialog — this is the reproducible proof.

If the audit harness already filed a theoretical XSS for the same sink,
`update_finding` with `status: triaged` and the browser-confirmed evidence
instead of double-reporting.

## Pitfalls — read before claiming

- **Reflection ≠ execution.** Never report XSS off a string match alone.
  The dialog from `browser_probe` is the bar.
- **Match the canary.** A fired dialog whose message isn't your canary is the
  app's own code; keep the canary unique per probe.
- **Deferred alerts** need a larger `wait_ms` — a sink wrapped in
  `setTimeout`/`requestAnimationFrame` won't fire within the default window.
- **Fragments aren't sent to the server.** For DOM/hash XSS, the WAF and
  server logs won't show it — that's expected; the browser still executes it.
- **CSP can make a "working" payload inert** in production. Always check
  whether inline execution is actually allowed before sizing the finding.
- One `report_finding` per sink, not per payload variant tried.

## Output expectations

- One finding per confirmed sink, each with a browser-fired-dialog proof URL.
- A `remember` note with the canonical confirming URL + canary.
- The plan item that triggered this skill marked `done` via `update_plan`.
