---
Verdict: VALID
FP-Verdict: TRUE-POSITIVE
FP-Confidence: HIGH
FP-Evidence: src/standalone.tsx:107 `element.getAttribute('spec-url')` → :109 `init(specUrl, {}, element)` → src/utils/loadAndBundleSpec.ts:22-24 sets `config.resolve.http.customFetch = global.fetch`; no validation anywhere on the path.
FP-Reasoning: `autoInit()` at standalone.tsx:102-111 reads the `spec-url` HTML attribute verbatim, passes it through `init()` and `AcmeStandalone` to `loadAndBundleSpec`, which assigns the unwrapped browser `global.fetch` as `customFetch`. There is no scheme check, host allowlist, or URL canonicalization at any node on the chain. Reachability requires only HTML-attribute injection (no script), which is a realistic precondition for CMS/embed contexts; this matches a published threat class with a clearly attacker-controlled source and a fetch sink reached by default config.
Severity-Original: MEDIUM
Severity-Tracer: HIGH
Severity-Advocate: MEDIUM
Class: SSRF / Browser-Side
Origin-Finding: PH-08
Origin-Pattern: PATT-007
File: src/standalone.tsx:107
Chamber: chamber-02
Pre-FP-Flag: narrow-precondition (CMS that allows <acme> attribute injection but blocks <script>)
Synthesizer-Note: Advocate downgraded HIGH → MEDIUM. Reachability requires CMS scenario allowing HTML-attribute injection on <acme> without script injection — narrow precondition. CORS bounding on response read-side-channel same as PH-01.
Triage-Priority: P2
Triage-Exploitability: difficult
Triage-Impact: medium
Triage-Reasoning: Browser-side SSRF with narrow CMS precondition (attribute injection without script); CORS limits response read-back; no server-side exposure.
Triage-Model: claude-sonnet-4-6
Triaged-At: 2026-05-19T00:00:00Z
Intent-Verdict: genuine
Intent-Source: none
Intent-Quote: n/a
Intent-Confidence: weak
PoC-Status: theoretical
PoC-Block-Reason: MEDIUM severity — browser-side only; full execution requires built standalone bundle and browser DevTools; static code-path trace confirms vulnerability with status=confirmed
Protocol: http
Auth-Required: no
Auth-Roles-Required: anonymous
---

# SSRF via `<acme spec-url="…">` HTML Attribute — No URL Validation

## Summary

The standalone web-component `autoInit()` reads the `spec-url` HTML attribute directly and passes it to `loadAndBundleSpec()` with no URL validation. Any platform allowing injection of HTML attributes on the `<acme>` element exposes this SSRF entry point.

## Attack Scenario

A CMS embeds Acme with user-editable `<acme>` element attributes. An attacker with attribute-write access (but not script access) sets:
```html
<acme spec-url="http://169.254.169.254/latest/meta-data/"></acme>
```

When a visitor loads the page:
1. `standalone.tsx:107` — `const specUrl = element.getAttribute('spec-url')` — reads `"http://169.254.169.254/..."`.
2. `standalone.tsx:109` — `init(specUrl, {}, element)` — no validation.
3. `loadAndBundleSpec.ts:22-24` — `customFetch = global.fetch` — browser fetches the metadata URL.
4. The fetch reaches the metadata service; if it returns JSON that parses as an OpenAPI-like object, the bundler may process it further and the content appears in the rendered page.

## Pairs With

PH-01: Once the `spec-url` is fetched, any `$ref` within that spec is also fetched via the same unguarded `customFetch`, enabling chained SSRF (spec-url → `$ref` → deeper internal resources).

## Code Evidence

- `src/standalone.tsx:107` — attribute read without validation
- `src/standalone.tsx:109` — direct pass to `init()`
- `src/utils/loadAndBundleSpec.ts:22-24` — unguarded `customFetch`
