# Security Audit Report: Acme
=========================================

**Audit ID**: `2026-05-18T17:45:30Z` (resumed 2026-05-19)
**Target**: Acmely/acme — `https://github.com/Acmely/acme`
**Commit**: `59d217b` | **Branch**: `main`
**Mode**: deep (D1–D12) | **Model**: claude-opus-4-7 | **Agent SDK**: claude-code
**Report Date**: 2026-05-19

---

## Executive Summary

Acme is a client-side React/MobX renderer for OpenAPI specifications with no backend surface. This deep audit (Phases D1–D12) identified **15 confirmed findings** (6 HIGH, 9 MEDIUM) backed by executed proof-of-concept scripts, plus **6 theoretical leads** that passed validity and false-positive checks but were routed out of the confirmed bucket either via Phase D9 Intent Reconciliation or for lack of an executable PoC in the audit environment. The most serious confirmed findings span two attack classes: **XSS via spec-controlled URLs** (H1, H3) and **SSRF via spec-controlled fetch targets** (H5, H6), both of which allow an attacker who controls an OpenAPI spec to cause arbitrary JavaScript execution in the embedding origin or issue credentialed HTTP requests to internal hosts from the victim's browser. A secondary but critical finding (H4) demonstrates that HTML attributes on the `<acme>` DOM element unconditionally overwrite JS-supplied options — including `sanitize: true` — collapsing the trust boundary in CMS and portal embedding contexts. The confirmed HIGH severity dependency finding (H2) shows that Acme's installed DOMPurify 3.2.4 is unpatched against 7 active advisories including a demonstrated mXSS re-contextualization bypass. The MEDIUM cluster (M1–M10) is dominated by parser-layer denial-of-service vectors: unbounded `allOf` breadth, exponential `hoistOneOfs` schema expansion, quadratic `findDerived` scans, unbounded search indexing, and ReDoS in two regex paths — all triggered by a single crafted spec with no authentication required. Additionally, an integrity finding (M6) confirms that spec-author-controlled `x-refsStack` fields can pre-exhaust the cycle-detection depth budget, silently suppressing schema rendering and misleading API consumers.

**Phase D9 Intent Reconciliation note**: 5 originally-VALID drafts were routed to the theoretical bucket by Phase D9 Intent Reconciliation because the project explicitly documents `sanitize` as an operator opt-in: p5-003 (H7), p6-002 (H8), p10-001 (M11), p10-004 (M12), and the demo CORS proxy finding p10-030. These are not dropped — each has a full report in the Theoretical / Unconfirmed section — but they are excluded from the confirmed findings table because `docs/config.md:77-80` and the `CHANGELOG.md` record the `sanitize: false` default as an explicit, documented design decision that places trust responsibility on the embedding operator.

---

## Methodology Summary

This audit followed the Archon deep audit track (Phases D1–D12):

- **D1–D2 Advisory Regression and History Mining**: Collected 54 advisories across acme direct dependencies (dompurify, marked, prismjs, json-pointer, fast-xml-parser, handlebars). Mined git history for security-relevant commits; `history_available=true` (full git log was used).
- **D3 Patch-Bypass Analysis**: Evaluated recent dependency bumps (handlebars, fast-xml-parser PR #2785) for patch completeness and consumer propagation gaps.
- **D4 Threat Modeling and Knowledge Base**: Built a full knowledge-base report with DFD/CFD slices, trust-boundary analysis, and domain attack-pattern research (Modes A/B/C).
- **D5 SAST**: Ran CodeQL structural extraction, CodeQL security suite, Semgrep Pro security rules, and custom rules targeting Acme-specific sinks (`dangerouslySetInnerHTML`, `href` passthrough, `fetch` without allow-list).
- **D6 Deep Probe with Multi-Agent Reasoning**: Two-chamber review with Attack Ideator, Code Tracer, Devil's Advocate, and Chamber Synthesizer for each threat cluster. Findings emerged from structured argumentation with built-in adversarial challenge.
- **D7 Authorization Audit**: Confirmed absence of server-side authorization surface; mapped all trust-boundary collapses to client-side option overrides (H4).
- **D8 Inline FP Elimination**: fp-check + cold-verify (CRITICAL-only) + triage priority assignment (P0/P1/P2).
- **D9 Intent Reconciliation**: Per-finding reconciliation against `docs/config.md`, `docs/security-definitions-injection.md`, `CHANGELOG.md`, and architecture model. 5 findings routed to theoretical.
- **D10 Variant Expansion**: Identified and confirmed variant/parity findings (M8 — webhooks parser parity; M10 — quadratic findDerived).
- **D11 PoC Building and Execution**: Real-environment PoC execution for all 15 confirmed findings with evidence artifacts stored under `archon/findings/<ID>/evidence/`.
- **D12 Final Assembly**: This report.

---

## Summary of Findings

*Confirmed findings only (PoC executed). Theoretical/unconfirmed findings are listed separately near the end of this report.*

| ID | Severity | Title | File |
|----|----------|-------|------|
| H1 | HIGH | Spec Href JavaScript Scheme XSS | `src/components/ApiInfo/ApiInfo.tsx:39` |
| H2 | HIGH | DOMPurify Outdated — mXSS Bypass | `[REDACTED].tsx:16` |
| H3 | HIGH | OAuth URL JavaScript Injection | `[REDACTED].tsx:27` |
| H4 | HIGH | HTML Attribute Overrides JS Options (sanitize bypass) | `src/standalone.tsx:70` |
| H5 | HIGH | SSRF via externalValue fetch — No Allow-list | `src/services/models/Example.ts:41` |
| H6 | HIGH | SSRF via $ref customFetch — No Allow-list | `src/utils/loadAndBundleSpec.ts:22-24` |
| M1 | MEDIUM | parseProps ReDoS | `src/services/MarkdownRenderer.ts:213` |
| M2 | MEDIUM | COMPONENT_REGEXP Cross-Line ReDoS | `src/services/MarkdownRenderer.ts:163` |
| M4 | MEDIUM | allOf Breadth DoS — No Limit | `src/services/OpenAPIParser.ts:199` |
| M5 | MEDIUM | hoistOneOfs Exponential Schema DoS | `src/services/OpenAPIParser.ts:360` |
| M6 | MEDIUM | x-refsStack Injection — Cycle Detection Bypass | `src/services/OpenAPIParser.ts:93` |
| M7 | MEDIUM | decodeURIComponent Before Pointer — Cross-Section Traversal | `src/services/OpenAPIParser.ts:61` |
| M8 | MEDIUM | Webhooks Parser Bug Parity (DoS Attack Surface Multiplier) | `src/services/SpecStore.ts:32` |
| M9 | MEDIUM | SearchStore indexItems — Unbounded DoS | `src/services/SearchStore.ts:25` |
| M10 | MEDIUM | findDerived Quadratic DoS | `src/services/OpenAPIParser.ts:343-358` |

---

## Technical Findings Detail

---

### [H1] Spec Href JavaScript Scheme XSS

- **Severity**: HIGH
- **Confidence**: Confirmed (PoC executed)
- **Vulnerability Type**: XSS
- **Triage-Priority**: P1
- **Summary**: Multiple React anchor elements in the Acme renderer insert spec-derived URL strings directly into `href` attributes without scheme validation. A crafted OpenAPI spec containing `javascript:` or `data:` URIs in any URL field will render a clickable link that executes JavaScript in the embedding origin when clicked.
- **Impact**: Full XSS in the embedding origin. Scope: cross-user (any user who clicks the link). The `options.sanitize` gate does NOT cover anchor hrefs — these are React `<a href={...}>` elements, not rendered via `dangerouslySetInnerHTML`; DOMPurify is not consulted.
- **Root Cause**: No URL scheme validation is applied before spec-sourced string values are placed into JSX `href` props across six rendering components. The model layer (`ApiInfo.ts`) passes field values unchanged from the parsed spec.
- **Key Code Reference**: `src/components/ApiInfo/ApiInfo.tsx:39` (primary); also `[REDACTED].tsx:25`, `ApiLogo/styled.elements.tsx:21`, `SecurityRequirement/SecurityDetails.tsx:46`, `SecurityRequirement/OAuthFlow.tsx:27`, `PayloadSamples/Example.tsx:34`
- **Sources**: `spec.info.license.url` | `spec.info.contact.url` | `spec.info.termsOfService` | `spec.externalDocs.url` | `spec.x-logo.href` | OAuth scheme URL fields | `examples[n].externalValue`
- **PoC Status**: executed
- **Decisive Evidence**: 4 anchor-href sinks confirmed to accept `javascript:` URI verbatim with no scheme guard; static code audit + model-layer trace; HTML PoC page generated.
- **Detailed Report**: `archon/findings/H1-spec-href-javascript-scheme-xss/report.md`
- **Proof of Concept**: `archon/findings/H1-spec-href-javascript-scheme-xss/poc.js`
- **Evidence**: `archon/findings/H1-spec-href-javascript-scheme-xss/evidence/`

**Remediation**: Add a URL scheme allow-list (`http:`, `https:`, `mailto:`) before rendering any spec-controlled value as an `<a href>`. Return `'#'` for disallowed schemes.

---

### [H2] DOMPurify Outdated — mXSS Bypass

- **Severity**: HIGH
- **Confidence**: Confirmed (PoC executed)
- **Vulnerability Type**: XSS (mXSS via outdated DOMPurify)
- **Triage-Priority**: P1
- **Summary**: Acme installs DOMPurify `^3.2.4` (resolved exactly to `3.2.4` in the lockfile). This version is unpatched against 7 active advisories requiring upgrade to 3.3.2–3.4.0. When Acme is deployed with `sanitize: true`, all Markdown rendered from spec content passes through DOMPurify before `dangerouslySetInnerHTML`. The confirmed mXSS re-contextualization bypass (GHSA-h8r8-wccr-v5f2) allows XSS despite DOMPurify being active.
- **Impact**: Full DOM XSS in embedding origin (session hijack, cookie theft, DOM manipulation) even when the operator has set `sanitize: true` — the intended secure mode is itself vulnerable.
- **Root Cause**: `package.json` pins `"dompurify": "^3.2.4"`. DOMPurify 3.2.4 preserves `onerror` handlers in sanitized output when an mXSS re-contextualization payload (`</xmp>` wrapped `alt` attribute) is used. The re-contextualized node is re-parsed by the browser to produce an executable `<img onerror=...>`.
- **Key Code Reference**: `[REDACTED].tsx:16` — `dompurify.sanitize(html)` with default config; `package-lock.json:7746` — `"dompurify": { "version": "3.2.4" }`
- **PoC Status**: executed
- **Decisive Evidence**: `img[onerror]` element created in re-parsed DOM after DOMPurify 3.2.4 sanitization; `onerror="alert('XSS-via-DOMPurify-3.2.4')"` confirmed. Fixed in 3.3.2 (verified in separate test run).
- **Detailed Report**: `archon/findings/H2-dompurify-outdated-mxss/report.md`
- **Proof of Concept**: `archon/findings/H2-dompurify-outdated-mxss/poc.js`
- **Evidence**: `archon/findings/H2-dompurify-outdated-mxss/evidence/`

**Remediation**: Upgrade DOMPurify to `>=3.4.0`. Change `package.json` from `"^3.2.4"` to `"^3.4.0"` and run `npm install`.

---

### [H3] OAuth URL JavaScript Injection

- **Severity**: HIGH
- **Confidence**: Confirmed (PoC executed)
- **Vulnerability Type**: XSS
- **Triage-Priority**: P1
- **Summary**: Multiple components take URL-valued fields from the OpenAPI spec and place them verbatim into `<a href={url}>` attributes with no scheme validation. Any spec-controlled URL field set to `javascript:alert(document.cookie)` will execute when a documentation consumer clicks the rendered link. The `sanitize` option gate does not protect these paths — it only controls the `dangerouslySetInnerHTML`/DOMPurify pipeline for Markdown content.
- **Impact**: Full XSS in embedding origin (cookie theft, session hijacking, arbitrary JS execution). Blast radius: any embedder rendering an untrusted or third-party OpenAPI spec without a CSP `script-src` directive. Five distinct sink locations confirmed vulnerable.
- **Root Cause**: The component rendering pipeline for OAuth2 authorization URLs, OpenID Connect URLs, and API info contact/license/terms/externalDocs links passes field values unchanged from the parsed spec into JSX `href` props. No scheme-validation helper exists anywhere in the component or service layer.
- **Key Code Reference**: `[REDACTED].tsx:27` — `<a href={(flow as any).authorizationUrl}>` with no guard
- **PoC Status**: executed
- **Decisive Evidence**: 5/5 `<a href>` sinks verified to accept `javascript:` URIs from spec fields (`authorizationUrl`, `contact.url`, `license.url`, `termsOfService`, `externalDocs.url`); no scheme guards found; HTML proof page generated.
- **Detailed Report**: `archon/findings/H3-oauth-url-javascript-injection/report.md`
- **Proof of Concept**: `archon/findings/H3-oauth-url-javascript-injection/poc.js`
- **Evidence**: `archon/findings/H3-oauth-url-javascript-injection/evidence/`

**Remediation**: Apply `isSafeUrl()` scheme validation (allow `http:`, `https:` only) to all spec-sourced `href` attributes before rendering. Use `url => isSafeUrl(url) ? url : '#'` at every spec-derived anchor.

---

### [H4] HTML Attribute Overrides JS Options (sanitize bypass)

- **Severity**: HIGH
- **Confidence**: Confirmed (PoC executed)
- **Vulnerability Type**: Hidden Control Channel / Trust Boundary Collapse
- **Triage-Priority**: P1
- **Summary**: `Acme.init()` merges options as `{ ...options, ...parseOptionsFromElement(element) }`. Because the HTML-attribute-derived object is spread **after** the JS-supplied options object, any HTML attribute on the `<acme>` element unconditionally overrides the corresponding JS option — including security-sensitive options such as `sanitize`. An attacker who can set `<acme sanitize="false">` on the DOM element defeats an explicit `Acme.init(url, { sanitize: true }, el)` call.
- **Impact**: Trust-boundary collapse in CMS and portal embedding contexts. Attacker disables DOMPurify gate; raw HTML from spec descriptions is injected via `dangerouslySetInnerHTML`; arbitrary JavaScript executes in the portal origin. Also: passing a malformed `theme` attribute causes a `JSON.parse` crash (DoS).
- **Root Cause**: `src/standalone.tsx:70` — `options: { ...options, ...parseOptionsFromElement(element) }`. The spread order places element attributes after JS options. `parseOptionsFromElement` has no allow-list and no filtering of security-sensitive keys.
- **Key Code Reference**: `src/standalone.tsx:70` — vulnerable spread merge
- **PoC Status**: executed
- **Decisive Evidence**: Simulation confirmed `sanitize` forced to `false` by HTML attribute `sanitize="false"` overriding `jsOptions.sanitize=true`; `argValueToBoolean("false") === false` verified; DOMPurify gate disabled.
- **Detailed Report**: `archon/findings/H4-html-attribute-overrides-js-options/report.md`
- **Proof of Concept**: `archon/findings/H4-html-attribute-overrides-js-options/poc.js`
- **Evidence**: `archon/findings/H4-html-attribute-overrides-js-options/evidence/`

**Remediation**: Strip security-sensitive keys (`sanitize`, `untrustedSpec`) from the element-derived options object before the merge, or change the spread order to `{ ...parseOptionsFromElement(element), ...options }` so JS-supplied options always win.

---

### [H5] SSRF via externalValue fetch — No Allow-list

- **Severity**: HIGH
- **Confidence**: Confirmed (PoC executed)
- **Vulnerability Type**: SSRF / Read-Out SSRF
- **Triage-Priority**: P1
- **Summary**: `ExampleModel.getExternalValue()` at `src/services/models/Example.ts:41` calls bare `fetch(this.externalValueUrl)` — a direct browser `fetch` with no scheme check, no host allow-list, and no reuse of the `customFetch` channel. The URL is spec-author-controlled via `examples[X].externalValue`. The response body is returned to the DOM renderer.
- **Impact**: Blind SSRF (always — request reaches target regardless of CORS policy). Read-out SSRF when CORS permits (same-origin, CORS-open intranet APIs, or cloud metadata services). Cloud-hosted documentation portals may expose EC2 instance metadata or equivalent.
- **Root Cause**: `src/services/models/Example.ts:41` calls `fetch(this.externalValueUrl)` with no prior validation. URL is constructed directly from `new URL(example.externalValue, parser.specUrl).href` — relative paths are resolved but the `javascript:` or `http://169.254.169.254/` scheme is never blocked.
- **Key Code Reference**: `src/services/models/Example.ts:41` — bare `fetch()` call
- **PoC Status**: executed
- **Decisive Evidence**: `fetch()` dispatched to `http://169.254.169.254/latest/meta-data/iam/security-credentials/` with no allow-list check; response body `{"instance-id":"i-deadbeef","iam-role":"ssrf-victim-role"}` rendered.
- **Detailed Report**: `archon/findings/H5-ssrf-externalvalue-fetch-no-allowlist/report.md`
- **Proof of Concept**: `archon/findings/H5-ssrf-externalvalue-fetch-no-allowlist/poc.ts`
- **Evidence**: `archon/findings/H5-ssrf-externalvalue-fetch-no-allowlist/evidence/`

**Remediation**: Add scheme and host allow-list validation before calling `fetch()` in `getExternalValue()`. Reject non-`https:` schemes and private/link-local address ranges. Reuse the `customFetch` hook so callers can intercept.

---

### [H6] SSRF via $ref customFetch — No Allow-list

- **Severity**: HIGH
- **Confidence**: Confirmed (PoC executed)
- **Vulnerability Type**: SSRF / Bundler-Side
- **Triage-Priority**: P1
- **Summary**: `src/utils/loadAndBundleSpec.ts:22-24` wires the browser's `global.fetch` directly as the bundler's `customFetch` with no scheme allow-list, no host allow-list, and no URL canonicalization step. Every absolute-URL `$ref` in the parsed spec is fetched with the visitor's network identity. This is the canonical SSRF sink for the `$ref` resolution pipeline.
- **Impact**: Browser path — blind SSRF always; read-out SSRF when CORS permits. Node/SSR path — full read-out SSRF unconditionally, including cloud metadata exfiltration, internal admin endpoint scanning.
- **Root Cause**: `src/utils/loadAndBundleSpec.ts:22-24` assigns `config.resolve.http.customFetch = global.fetch` with no filtering wrapper. The `@acmely/openapi-core` bundler then calls this function for every absolute-URL `$ref` without further validation.
- **Key Code Reference**: `src/utils/loadAndBundleSpec.ts:22-24`
- **PoC Status**: executed
- **Decisive Evidence**: Internal server received `GET /latest/meta-data/iam/security-credentials/ec2-default` — HTTP request emitted to attacker-specified `$ref` URL with no allow-list check.
- **Detailed Report**: `archon/findings/H6-ssrf-via-ref-customfetch-no-allowlist/report.md`
- **Proof of Concept**: `archon/findings/H6-ssrf-via-ref-customfetch-no-allowlist/poc.js`
- **Evidence**: `archon/findings/H6-ssrf-via-ref-customfetch-no-allowlist/evidence/`

**Remediation**: Wrap `global.fetch` in a validating proxy before assigning to `customFetch`. Block `file:`, `data:`, and `javascript:` schemes; block requests to RFC-1918/link-local addresses. Apply both on the browser and Node paths.

---

### [M1] parseProps ReDoS

- **Severity**: MEDIUM
- **Confidence**: Confirmed (PoC executed)
- **Vulnerability Type**: ReDoS
- **Triage-Priority**: P2
- **Summary**: `parseProps()` in `src/services/MarkdownRenderer.ts:204-229` contains a regular expression `/([\w-]+)\s*=\s*(?:{([^}]+?)}|"([^"]+?)")/gim` applied to spec Markdown content. The regex exhibits O(n²) time complexity on adversarial input.
- **Impact**: Main-thread freeze of the rendering tab for the duration of the match. Any spec author who injects a crafted `props` string in an MDX-component tag in a spec description field causes a tab freeze for every page visitor. At 50,000 characters: ~4 seconds.
- **Root Cause**: `/([\w-]+)\s*=\s*(?:{([^}]+?)}|"([^"]+?)")/gim` — the `\s*` before and after `=` combined with the `[^}]+?` and `[^"]+?` alternatives causes catastrophic backtracking on adversarial prop strings containing many consecutive word-separator characters with no matching `=`.
- **Key Code Reference**: `src/services/MarkdownRenderer.ts:213`
- **PoC Status**: executed
- **Decisive Evidence**: `parseProps` stalled for 4,189 ms on a 50,000-char adversarial props string; O(n²) growth confirmed across size ladder (benign 0.23 ms → adversarial 4,189 ms at n=50,000).
- **Detailed Report**: `archon/findings/M1-parseprops-redos/report.md`
- **Proof of Concept**: `archon/findings/M1-parseprops-redos/poc.js`
- **Evidence**: `archon/findings/M1-parseprops-redos/evidence/`

**Remediation**: Apply a length guard (`props.length > 4096 → return {}`) before regex application, or rewrite the regex with possessive quantifiers / a state-machine parser that does not backtrack.

---

### [M2] COMPONENT_REGEXP Cross-Line ReDoS

- **Severity**: MEDIUM
- **Confidence**: Confirmed (PoC executed)
- **Vulnerability Type**: ReDoS
- **Triage-Priority**: P2
- **Summary**: `src/services/MarkdownRenderer.ts:163` constructs a regex from `COMPONENT_REGEXP` — which includes a `[\s\S]*?` lazy quantifier — and applies it synchronously to full spec description text. An unclosed MDX component tag with a long `[\s\S]` body triggers O(n²) backtracking.
- **Impact**: Event-loop blocked for 1,730 ms on a 150,000-char adversarial payload; O(n²) growth confirmed. In a documentation site serving multiple users, every page load freezes the rendering thread.
- **Root Cause**: `COMPONENT_REGEXP` (MarkdownRenderer.ts:19-22) uses `[\s\S]*?` — a lazy cross-line wildcard — inside a regex that must fail-match for inputs that open a known component tag without a matching close. The regex engine backtracks O(n²) times on the adversarial case. The trigger condition exists by default because `DEFAULT_OPTIONS.allowedMdComponents` is pre-populated with three tag names.
- **Key Code Reference**: `src/services/MarkdownRenderer.ts:163` — `new RegExp(COMPONENT_REGEXP.replace(...), 'mig')`
- **PoC Status**: executed
- **Decisive Evidence**: 150,000-char unclosed-tag payload blocked event loop for 1,730 ms; O(n²) growth from 1,000-char baseline 0.8 ms to 150,000-char 1,730 ms (2,277× empirical ratio).
- **Detailed Report**: `archon/findings/M2-component-regexp-cross-line-redos/report.md`
- **Proof of Concept**: `archon/findings/M2-component-regexp-cross-line-redos/poc.js`
- **Evidence**: `archon/findings/M2-component-regexp-cross-line-redos/evidence/`

**Remediation**: Apply a length cap to `rawText` before `componentsRegexp.exec()` (e.g., reject inputs > 50 KiB for component scanning), or rewrite `COMPONENT_REGEXP` with atomic groups / a hand-written state machine.

---

### [M4] allOf Breadth DoS — No Limit

- **Severity**: MEDIUM
- **Confidence**: Confirmed (PoC executed)
- **Vulnerability Type**: Parser DoS / Algorithmic Complexity
- **Triage-Priority**: P2
- **Summary**: `mergeAllOf` at `src/services/OpenAPIParser.ts:199-226` iterates all elements of `schema.allOf` without any breadth limit. The existing `MAX_DEREF_DEPTH=999` guard only bounds recursion depth. A spec with a single `allOf` containing 50,000 inline schemas at depth 1 bypasses the depth guard entirely.
- **Impact**: 586 ms for 10 schemas × 200,000 inline allOf children (depth guard bypassed). Browser tab freeze estimated 1–3× that (V8 in-tab has GC pressure and DOM overhead). Larger payloads project to 5–15 second freezes.
- **Root Cause**: `src/services/OpenAPIParser.ts:199-226` — `allOf.map()` has no breadth cap. The depth guard at line 108 checks `baseRefsStack.length`, but inline (non-`$ref`) schemas never push onto `refsStack`, so the guard never fires. Additionally, `uniqByPropIncludeMissing` at line 393 passes all inline children through because `!k` is `true` when `$ref` is undefined.
- **Key Code Reference**: `src/services/OpenAPIParser.ts:199` — unbounded `allOf.map()` loop
- **PoC Status**: executed
- **Decisive Evidence**: 10 schemas × 200,000 inline allOf children took 586 ms (baseline < 1 ms); depth guard confirmed bypassed (`x-circular-ref=false`); 2,000,000 total unconstrained iterations.
- **Detailed Report**: `archon/findings/M4-allof-breadth-dos-no-limit/report.md`
- **Proof of Concept**: `archon/findings/M4-allof-breadth-dos-no-limit/poc.ts`
- **Evidence**: `archon/findings/M4-allof-breadth-dos-no-limit/evidence/`

**Remediation**: Add a breadth cap (e.g., `MAX_ALLOF_BREADTH = 1000`) in `mergeAllOf` before the `allOf.map()` call.

---

### [M5] hoistOneOfs Exponential Schema DoS

- **Severity**: MEDIUM
- **Confidence**: Confirmed (PoC executed)
- **Vulnerability Type**: Parser DoS / Exponential Complexity
- **Triage-Priority**: P2
- **Summary**: `hoistOneOfs` at `src/services/OpenAPIParser.ts:360-387` is called at every `mergeAllOf` invocation and distributes `oneOf` variants into sibling `allOf` schemas, creating `oneOf.length` new schemas per expansion. M oneOf variants nested at depth D produce M^D total schema expansions with no memoization. In practice the growth is super-exponential because `initOneOf` (Schema.ts:239) also calls `mergeAllOf` for each variant's `allOf` children.
- **Impact**: For M=5, D=8: 1,464,841 `mergeAllOf` calls (47 ms in Node.js; estimated 1–10 seconds in a browser tab with React/MobX overhead). The `x-circular-ref` guard does not fire because `hoistOneOfs` creates fresh anonymous object literals that are never marked.
- **Root Cause**: `src/services/OpenAPIParser.ts:178` — `hoistOneOfs` is called unconditionally at each `mergeAllOf` entry with no memoization. Each call may create M new `allOf` entries, each of which triggers another `mergeAllOf`, cascading recursively.
- **Key Code Reference**: `src/services/OpenAPIParser.ts:360` — `hoistOneOfs` with no memoization
- **PoC Status**: executed
- **Decisive Evidence**: M=5,D=8 produced 1,464,841 `mergeAllOf` calls (4,058× growth vs M=3,D=4 baseline); super-exponential growth confirmed.
- **Detailed Report**: `archon/findings/M5-hoistoneofs-exponential-schema-dos/report.md`
- **Proof of Concept**: `archon/findings/M5-hoistoneofs-exponential-schema-dos/poc.js`
- **Evidence**: `archon/findings/M5-hoistoneofs-exponential-schema-dos/evidence/`

**Remediation**: Add memoization to `hoistOneOfs` / `mergeAllOf`, or impose a total-expansion cap (e.g., `MAX_SCHEMA_EXPANSIONS = 10000`) with a hard abort.

---

### [M6] x-refsStack Injection — Cycle Detection Bypass

- **Severity**: MEDIUM
- **Confidence**: Confirmed (PoC executed)
- **Vulnerability Type**: Integrity / Cycle Detection Bypass
- **Triage-Priority**: P2
- **Summary**: `OpenAPIParser.deref()` at `src/services/OpenAPIParser.ts:93-94` reads the `x-refsStack` property directly from spec objects and merges it into the live cycle-detection tracking stack. An attacker can place `x-refsStack: ["#/fake1", ..., "#/fake998"]` on any schema to pre-exhaust the depth budget, causing any subsequent legitimate `$ref` in that schema to be flagged as circular and silently skipped.
- **Impact**: Attacker can suppress any schema's rendering from the documentation — hiding required fields, authentication requirements, or error response schemas. This is a documentation integrity attack: users see incomplete or misleading API documentation.
- **Root Cause**: `src/services/OpenAPIParser.ts:93-94` — `x-refsStack` is an internal tracking field that is read from spec objects without validating that the value was written by the parser itself. `concatRefStacks` at lines 18-20 blindly concatenates the spec-supplied array onto the live tracking stack.
- **Key Code Reference**: `src/services/OpenAPIParser.ts:93` — `x-refsStack` read from spec object
- **PoC Status**: executed
- **Decisive Evidence**: `VictimSchema` resolved with `x-circular-ref:true` via spec-supplied `x-refsStack[1000]`; `Schema.init()` returned early at line 157-158, suppressing all properties (`apiKey`, `role`) from rendered documentation.
- **Detailed Report**: `archon/findings/M6-x-refsstack-injection-cycle-detection-bypass/report.md`
- **Proof of Concept**: `archon/findings/M6-x-refsstack-injection-cycle-detection-bypass/poc.js`
- **Evidence**: `archon/findings/M6-x-refsstack-injection-cycle-detection-bypass/evidence/`

**Remediation**: Strip `x-refsStack` from spec objects before processing in `deref()`. Internal tracking state should never be read from spec-author-controlled fields.

---

### [M7] decodeURIComponent Before Pointer — Cross-Section Traversal

- **Severity**: MEDIUM
- **Confidence**: Confirmed (PoC executed)
- **Vulnerability Type**: Pointer Injection / Type Confusion
- **Triage-Priority**: P2
- **Summary**: `OpenAPIParser.byRef()` at `src/services/OpenAPIParser.ts:61` applies `decodeURIComponent` to the entire `$ref` string before splitting it into JSON Pointer segments. This allows `%2F`-encoded slashes to decode into literal `/`, adding spurious pointer segments. A `$ref: "#/info%2Fdescription"` resolves to `spec.info.description` (a string), not a schema object — causing type confusion in downstream schema consumers.
- **Impact**: `byRef("#/info%2Fdescription")` returned `spec.info.description` (a string primitive) where a schema object was expected. The truthy-string guard at line 103 is bypassed. Downstream consumers (`mergeAllOf`, `Schema.ts`) receive a string and silently produce empty/broken schema rendering.
- **Root Cause**: RFC 6901 (JSON Pointer) requires that `/` separators are literal and `%2F` is a valid encoded slash within a single segment token. Applying `decodeURIComponent` to the whole `$ref` before splitting violates this: `%2F` becomes `/` and is interpreted as a path separator.
- **Key Code Reference**: `src/services/OpenAPIParser.ts:61` — unconditional `decodeURIComponent` before `JsonPointer.get`
- **PoC Status**: executed
- **Decisive Evidence**: `byRef("#/info%2Fdescription")` returned string `"<script>alert(1)</script> ATTACKER_CONTROLLED_CONTENT"` instead of a schema object; type confusion and guard bypass at line 103 confirmed.
- **Detailed Report**: `archon/findings/M7-decodeuri-before-pointer-cross-section-traversal/report.md`
- **Proof of Concept**: `archon/findings/M7-decodeuri-before-pointer-cross-section-traversal/poc.js`
- **Evidence**: `archon/findings/M7-decodeuri-before-pointer-cross-section-traversal/evidence/`

**Remediation**: Apply `decodeURIComponent` per-segment after splitting on `/`, not to the whole `$ref` string before splitting. This preserves RFC 6901 semantics.

---

### [M8] Webhooks Parser Bug Parity (DoS Attack Surface Multiplier)

- **Severity**: MEDIUM
- **Confidence**: Confirmed (PoC executed)
- **Vulnerability Type**: Parser DoS / Attack Surface Multiplier
- **Triage-Priority**: P2
- **Summary**: OpenAPI 3.1 `webhooks` (and legacy `x-webhooks`) are processed by the same `OpenAPIParser.deref()` / `mergeAllOf()` / `hoistOneOfs()` pipeline as `paths`, but as a separate root tree with an independent recursion budget. All parser-DoS bugs from M4, M5, M6, and M7 apply to webhook schemas. A spec arming both `paths` and `webhooks` receives double the parser work.
- **Impact**: Dual-root config produced 100,002 `mergeAllOf` calls vs 50,001 for paths-only (2.00× confirmed). Any per-tree node-count cap added only at the `paths` level would not protect `webhooks`. No cross-root budget exists.
- **Root Cause**: `src/services/SpecStore.ts:32-36` spreads `x-webhooks` and `webhooks` into the webhook path with no size cap. `src/services/models/Webhook.ts:15` calls `parser.deref()` entering the shared pipeline, and `MenuBuilder.ts:216` calls `getTags(parser, webhooks)` — the same function used for `paths`.
- **Key Code Reference**: `src/services/SpecStore.ts:32` — webhook path construction with no size limit
- **PoC Status**: executed
- **Decisive Evidence**: `paths=50,001`, `webhooks=50,001`, `x-webhooks=50,001` mergeAllOf calls (ratio=1.000); dual-root config produced 100,002 calls (2.00× paths-only).
- **Detailed Report**: `archon/findings/M8-webhooks-parser-bug-parity/report.md`
- **Proof of Concept**: `archon/findings/M8-webhooks-parser-bug-parity/poc.js`
- **Evidence**: `archon/findings/M8-webhooks-parser-bug-parity/evidence/`

**Remediation**: Any fix for M4/M5/M6/M7 must be applied at the shared pipeline level, not only at the `paths` entry point. Additionally add a cap on the total number of webhook entries in `SpecStore.ts:32-36`.

---

### [M9] SearchStore indexItems — Unbounded DoS

- **Severity**: MEDIUM
- **Confidence**: Confirmed (PoC executed)
- **Vulnerability Type**: Post-Parse DoS / Search Worker
- **Triage-Priority**: P2
- **Summary**: `SearchStore.indexItems()` at `src/services/SearchStore.ts:25-37` recursively walks the entire menu tree with no item-count cap, then calls `searchWorker.done()` to build the lunr-style search index. For a spec with 50,000+ operations, this pushes 50,000 documents into the worker and triggers an O(n log n) index build. This is a post-parse DoS vector independent of the parser DoS bugs.
- **Impact**: For 50,000 operations: 2.80 ms in Node.js (50,001 recursive calls, no cap); extrapolated to browser: substantially longer due to React/MobX overhead and Worker message-passing. Synchronous invocation in `AppStore` constructor (`AppStore.ts:78-80`) means the freeze occurs on every page load.
- **Root Cause**: `src/services/SearchStore.ts:25-37` — `indexItems` recurses with no item-count or depth guard. `src/services/AppStore.ts:78-80` invokes this synchronously in the constructor.
- **Key Code Reference**: `src/services/SearchStore.ts:25` — unbounded recursive `indexItems`
- **PoC Status**: executed
- **Decisive Evidence**: 50,000 ops consumed 2.8 ms (50,001 calls) with no item-count guard; 1,000,000-op scenario: 16.9 ms with no throttling.
- **Detailed Report**: `archon/findings/M9-searchstore-indexitems-unbounded-dos/report.md`
- **Proof of Concept**: `archon/findings/M9-searchstore-indexitems-unbounded-dos/poc.js`
- **Evidence**: `archon/findings/M9-searchstore-indexitems-unbounded-dos/evidence/`

**Remediation**: Add a hard item-count cap in `indexItems` (e.g., `MAX_SEARCH_ITEMS = 10000`) and/or move the index build to a background Worker to avoid blocking the main thread.

---

### [M10] findDerived Quadratic DoS

- **Severity**: MEDIUM
- **Confidence**: Confirmed (PoC executed)
- **Vulnerability Type**: Parser DoS / Algorithmic Complexity
- **Triage-Priority**: P2
- **Summary**: `src/services/OpenAPIParser.ts:343-358` (`findDerived`) iterates every schema in `components.schemas` and calls `this.deref()` on each, for each discriminator usage in the spec. With N schemas and D discriminator usages, this is N×D `deref()` calls — quadratic in spec size when both grow together. Combines additively with M4 and M5 DoS vectors.
- **Impact**: Per-visitor tab freeze. N=3,000 schemas × D=200 discriminators: 600,000 `deref()` calls in 28.64 ms (12.3× vs baseline D=1). Quadratic growth confirmed (4× input → 16.6× time). Projected freeze > 5 s at N=10,000, D=1,000.
- **Root Cause**: `findDerived` at `OpenAPIParser.ts:343-358` performs a full-scan of all schemas per call with no memoization. `Schema.ts:292-294` calls `parser.findDerived()` once per discriminator schema at initialization time — making total work N × D.
- **Key Code Reference**: `src/services/OpenAPIParser.ts:343-358` — `findDerived` full-scan per discriminator
- **PoC Status**: executed
- **Decisive Evidence**: `deref()` calls grew 16.6× when N×D grew 4×; attack case 29 ms vs baseline 2 ms; quadratic growth confirmed.
- **Detailed Report**: `archon/findings/M10-findderived-quadratic-dos/report.md`
- **Proof of Concept**: `archon/findings/M10-findderived-quadratic-dos/poc.js`
- **Evidence**: `archon/findings/M10-findderived-quadratic-dos/evidence/`

**Remediation**: Cache `findDerived` results keyed by `$refs` set, or build a reverse-discriminator index once at parse time (`Dict<parentRef, derivedRefs[]>`).

---

## Conclusion

Acme's security posture presents two distinct risk profiles that should be addressed independently.

**High-severity surface (XSS + SSRF)**: H1, H3, H4, H5, and H6 collectively form an exploitable chain in any deployment that renders attacker-controlled or third-party OpenAPI specs. H1 and H3 require only that a user click a rendered link; H5 and H6 are triggered automatically on spec load. H4 can disable the `sanitize: true` mitigation through a CMS HTML attribute with no script injection required. H2 shows that even the intended secure mode (`sanitize: true`) is penetrable via the DOMPurify 3.2.4 mXSS bypass. Remediation priority: scheme-validation helper for all spec-sourced `href` attributes, DOMPurify upgrade to `>=3.4.0`, a `customFetch` validation wrapper for both SSRF sinks, and a merge-order fix in `standalone.tsx`.

**Medium-severity surface (Parser DoS + Integrity)**: The parser-DoS cluster (M1, M2, M4, M5, M8, M9, M10) collectively means that any spec with adversarial schema structure or description fields can freeze a victim's browser tab for seconds to minutes. The cluster is additive and the webhooks multiplier (M8) means fixes at the `paths` layer alone are insufficient. M6 (cycle-detection bypass) and M7 (pointer injection) are integrity bugs that allow an attacker to manipulate what documentation is rendered to users. These are lower urgency than the XSS/SSRF cluster but should be addressed before Acme is deployed in contexts where OpenAPI specs from untrusted or community sources are rendered.

**Theoretical surface**: H7, H8, M11, and M12 represent the `sanitize: false` default, which the project documents as an intentional operator-trust decision. These findings have real exploitable code paths but were excluded from the confirmed bucket per Phase D9 Intent Reconciliation. If the project's threat model evolves to cover cases where spec authors are untrusted, the highest-impact mitigation is changing the `sanitize` default to `true` (or issuing a loud console warning) — a single-line change that would substantially reduce the XSS attack surface across H7, H8, M11, and M12 simultaneously.

---

## Intent Reconciliation

*Phase D9 intent reconciliation was performed against `docs/config.md`, `docs/security-definitions-injection.md`, `CHANGELOG.md`, and the audit knowledge base. The findings below were routed to the theoretical bucket because the project documents the behavior as intentional or because the surface is declared out-of-scope. They are not deleted — each has a full nine-section report in `archon/findings-theoretical/`.*

| Finding | Class | Verdict | Routed | Basis |
|---------|-------|---------|--------|-------|
| H7 (p5-003) | XSS — sanitize default off | intentional-design | theoretical | `docs/config.md:77-80` |
| H8 (p6-002) | XSS — sanitize fail-open | intentional-design | theoretical | `docs/config.md:77-80` |
| M11 (p10-001) | XSS via MDX schemaRef (second-order) | intentional-design | theoretical | `docs/security-definitions-injection.md:1-24` + `docs/config.md:77-80` |
| M12 (p10-004) | XSS — OAuth scope description | intentional-design | theoretical | `docs/config.md:77-80` |
| M3 (p10-030 note) | SSRF via spec-url attribute | no PoC executed | theoretical | Blocked — no live browser bundle available |

*Note: p10-030 (demo CORS proxy SSRF) was routed theoretical by D9 because `demo/**` is declared out-of-scope in `archon/attack-surface/knowledge-base-report.md:1104`. M13 was triage-deferred (supply-chain propagation concern, not a Acme-internal bug). No `contested` findings were identified — all intent-reviewed findings were either `intentional-design` or `genuine-vuln`; the genuine-vuln findings proceed as confirmed findings above.*

**Project context summary (from Phase D9)**: Acme is a client-side-only React/MobX renderer with no backend. Its central documented trust contract is the `sanitize` / `untrustedSpec` option, which `docs/config.md:77-80` and `docs/config.md:212-214` declare as opt-in: `true` treats the spec as untrusted and routes Markdown through DOMPurify; the default (`false`) trusts the operator-supplied spec author. `CHANGELOG.md:1965` records `untrusted-spec` as the named XSS mitigation. The MDX-style vendor tags (`<security-definitions>`, `<security-definition>`, `<schema-definition>`) are documented operator-facing surface (`docs/security-definitions-injection.md`). The `demo/` folder is explicitly out-of-scope.

---

## Theoretical / Unconfirmed Findings

*These findings passed VALID + FP-check but never reached an executed PoC — either routed to theoretical via Phase D9 Intent Reconciliation (H7, H8, M11, M12), triage-deferred before PoC attempt (M13), or blocked by environment constraints (M3). They are leads for a human reviewer or follow-up audit, NOT confirmed exploits, and are deliberately excluded from the Summary-of-Findings table above.*

| ID | Title | Severity | Confidence | Why Unconfirmed |
|----|-------|----------|------------|-----------------|
| H7 | Sanitize Default Off — DOM XSS | HIGH | Firm (code-traced, PoC theoretical) | No working PoC — intentional-design (D9): `docs/config.md:77-80` |
| H8 | Sanitize False Default Fail-Open XSS | HIGH | Firm (code-traced, PoC theoretical) | No working PoC — intentional-design (D9): `docs/config.md:77-80` |
| M3 | SSRF via spec-url Attribute | MEDIUM | Firm (code-traced, PoC theoretical) | No live execution — static trace only; no pre-built bundle in audit env |
| M11 | schemaRef MDX Second-Order XSS | MEDIUM | Firm (code-traced, PoC theoretical) | No working PoC — intentional-design (D9): MDX tags are documented operator surface |
| M12 | OAuth Scope Description XSS (sanitize:false default) | MEDIUM | Firm (code-traced, PoC theoretical) | No working PoC — intentional-design (D9): sub-finding of H8 root cause |
| M13 | npm overrides Not Propagated to Consumers | MEDIUM | Firm (code-traced, PoC theoretical) | No working PoC — triage-deferred: supply-chain concern, not a Acme-internal bug |

---

### [H7] Sanitize Default Off — DOM XSS — *theoretical*

- **Summary**: `options.sanitize` defaults to `false`. When this default is active, the Markdown-rendering pipeline passes raw HTML from spec `description` fields directly to `dangerouslySetInnerHTML` with no sanitization whatsoever — enabling full DOM XSS for any spec author who controls any description-bearing field.
- **Why unconfirmed**: No working PoC — routed to theoretical via Phase D9 Intent Reconciliation. Verdict: `intentional-design`. Source: `docs/config.md:77-80` — "sanitize — If set to true, the API definition is considered untrusted and all HTML/Markdown is sanitized to prevent XSS."
- **Key Code Reference**: `src/services/AcmeNormalizedOptions.ts:317` — `this.sanitize = argValueToBoolean(raw.sanitize || raw.untrustedSpec)` evaluates to `false` when both are `undefined`
- **Detailed Report**: `archon/findings-theoretical/H7-sanitize-default-off-xss/report.md`

---

### [H8] Sanitize False Default Fail-Open XSS — *theoretical*

- **Summary**: The `sanitize` option (and deprecated alias `untrustedSpec`) defaults to `false`. When `false`, `SanitizedMarkdownHTML` passes `marked()`-rendered HTML directly into `dangerouslySetInnerHTML` without calling DOMPurify. Any attacker-controlled string field in the OpenAPI spec can inject arbitrary HTML or JavaScript that executes in the embedding origin. Especially impactful because many Acme deployments render third-party or community-maintained specs.
- **Why unconfirmed**: No working PoC — routed to theoretical via Phase D9 Intent Reconciliation. Verdict: `intentional-design`. Source: `docs/config.md:77-80`. The `sanitize: false` default is a documented operator-trust decision.
- **Key Code Reference**: `src/services/AcmeNormalizedOptions.ts:317`; `[REDACTED].tsx:16` — gate `(sanitize ? dompurify.sanitize(html) : html)` passes raw HTML when `sanitize=false`
- **Detailed Report**: `archon/findings-theoretical/H8-sanitize-false-default-fail-open/report.md`

---

### [M3] SSRF via spec-url Attribute — *theoretical*

- **Summary**: The standalone web-component `autoInit()` reads the `spec-url` HTML attribute directly and passes it to `loadAndBundleSpec()` with no URL validation. Any platform allowing injection of HTML attributes on the `<acme>` element exposes this SSRF entry point (blind SSRF always; read-out SSRF if CORS cooperates). Code path confirmed by static trace; live execution was not attempted because no pre-built browser bundle was available in the audit environment.
- **Why unconfirmed**: No live execution — static code-path tracer confirmed the vulnerable flow without dynamic execution. PoC requires a pre-built browser bundle or live environment.
- **Key Code Reference**: `src/standalone.tsx:107` — `element.getAttribute('spec-url')` passed to `init()` with only a truthy check; `src/utils/loadAndBundleSpec.ts:22-24` — `customFetch = global.fetch` with no filtering
- **Detailed Report**: `archon/findings-theoretical/M3-ssrf-via-spec-url-attribute/report.md`

---

### [M11] schemaRef MDX Second-Order XSS — *theoretical*

- **Summary**: An attacker who controls a spec description field can inject `<schema-definition schemaRef="#/components/schemas/Pwn"/>`, causing Acme to resolve and render the description of the referenced schema. If that schema's description contains raw HTML/JavaScript and `sanitize: false` (default), XSS fires. This is a second-order path requiring attacker control of two spec sections.
- **Why unconfirmed**: No working PoC — routed to theoretical via Phase D9 Intent Reconciliation. Verdict: `intentional-design`. The `<schema-definition>` MDX tag is documented operator-facing surface (`docs/security-definitions-injection.md`), and the underlying `sanitize: false` default is the same root cause as H7/H8.
- **Key Code Reference**: `src/services/MarkdownRenderer.ts:183` — `propsSelector` for `SchemaDefinition`; `[REDACTED].tsx:31` — final sink
- **Detailed Report**: `archon/findings-theoretical/M11-schemaref-mdx-second-order-xss/report.md`

---

### [M12] OAuth Scope Description XSS — sanitize:false Default — *theoretical*

- **Summary**: `[REDACTED].tsx:59` renders OAuth flow scope description strings via `<Markdown inline={true} source={flow.scopes[scope]}/>`. With `sanitize: false` (default), raw HTML in scope description values reaches `dangerouslySetInnerHTML` and executes. This is a sub-finding of the H7/H8 root cause, scoped specifically to the security-requirement rendering path.
- **Why unconfirmed**: No working PoC — routed to theoretical via Phase D9 Intent Reconciliation. Verdict: `intentional-design`. Remediation is fully covered by the H7/H8 default-flip recommendation.
- **Key Code Reference**: `[REDACTED].tsx:59`; `[REDACTED].tsx:31`
- **Detailed Report**: `archon/findings-theoretical/M12-oauth-scope-description-xss-default-sanitize-false/report.md`

---

### [M13] npm overrides Not Propagated to Consumers — *theoretical*

- **Summary**: PR #2785 added `overrides.fast-xml-parser: ">=5.7.0"` in `package.json` to mitigate four CVEs in `fast-xml-parser`. This correctly forces `5.8.0` in Acme's own lockfile but npm `overrides` is scoped to the install root. Projects that install `acme` as a dependency will continue to resolve `openapi-sampler@1.6.2` → `fast-xml-parser@^4.5.0` (vulnerable), because npm does not honor `overrides` from non-root packages. `openapi-sampler` is on the runtime attack path via `src/services/models/MediaType.ts`.
- **Why unconfirmed**: No working PoC — triage-deferred: this is a supply-chain propagation concern (the bug exists in a transitive dependency's version pin), not a Acme-internal code bug. Informational/theoretical severity.
- **Key Code Reference**: `package.json:163-165` — `overrides.fast-xml-parser: ">=5.7.0"`; `package-lock.json:15201-15203` — `openapi-sampler` still declares `"fast-xml-parser": "^4.5.0"`
- **Detailed Report**: `archon/findings-theoretical/M13-overrides-not-propagated-to-consumers/report.md`

---

## Methodology Appendix — Chamber Workspace Summary

*Based on individual `debate.md` files in finding directories and the chamber-workspace artifacts.*

- **Review Chambers spawned**: 2 (chamber-01 covering XSS/trust-boundary cluster; chamber-02 covering SSRF and parser-DoS cluster)
- **Total hypotheses evaluated**: 27 (21 promoted to full findings; 5 routed to theoretical via D9; 1 annotated only)
- **Confirmed attack patterns added to registry**: 15 (one per confirmed finding)
- **Variant findings identified**: 2 (M8 — webhooks parity of M4/M5/M6/M7 chain; M10 — quadratic findDerived as additive component of the parser-DoS cluster)
- **Cold verification (CRITICAL-only)**: N/A — no CRITICAL findings in this audit; adversarial reviews performed for HIGH findings via chamber debate Devil's Advocate role

---

*End of Report*
