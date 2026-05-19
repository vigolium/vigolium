# [H8] Sanitize False Default Fail Open

## Summary

The `sanitize` option (and its deprecated alias `untrustedSpec`) defaults to `false`. When `false`, the `SanitizedMarkdownHTML` component passes the `marked`-rendered HTML directly into `dangerouslySetInnerHTML` without calling DOMPurify. Any Markdown or inline HTML present in the OpenAPI spec (descriptions, summaries, schema field descriptions, OAuth scope descriptions, etc.) is rendered as raw HTML in the visitor's browser. An attacker who controls any string field in the OpenAPI spec can inject arbitrary HTML or JavaScript that executes in the origin of the embedding page.

This is the primary XSS attack surface in Acme. It is especially impactful because:
1. Acme is widely embedded in public-facing API documentation portals.
2. Many deployments use third-party or community-maintained API specs (e.g., OpenAPI specs from npm packages, public API directories like apis.guru) where spec content is not fully controlled by the embedder.
3. DOMPurify 3.2.4 (the installed version) is itself unpatched against 7 active advisories (requiring 3.3.2–3.4.0), meaning even when `sanitize: true` IS set, the sanitizer may be bypassable. But with `sanitize: false` (the default), DOMPurify is not invoked at all.

## Severity, Confidence, Vulnerability Type

- **Severity**: High
- **Confidence**: Firm (code-traced, PoC theoretical)
- **Vulnerability Type**: XSS
- **Intent-Verdict**: intentional-design
- **Triage-Priority**: skip

## Impact

See draft.md for full impact analysis on `src/services/AcmeNormalizedOptions.ts:317`.

## Affected Component

- **File**: `src/services/AcmeNormalizedOptions.ts:317`
- **Source**: spec.info.description | spec.info.summary | scheme.description | OAuth flow scope descriptions | every schema description rendered via <Markdown>
- **Sink**: [REDACTED].tsx:31 (dangerouslySetInnerHTML, ungated when options.sanitize=false; SanitizedMdBlock.tsx:16 gate)
- **Chamber**: chamber-01

## Source to Sink Flow

Primary site: `src/services/AcmeNormalizedOptions.ts:317`. See draft.md for the full trace.

## Vulnerable Code

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

## Proof of concept & Evidence

No working PoC — routed to theoretical via Phase D9 Intent Reconciliation. Verdict: `intentional-design`. Source: `docs/config.md:77-80`. Quote: "sanitize — If set to true, the API definition is considered untrusted and all HTML/Markdown is sanitized to prevent XSS.". HIGH XSS via fail-open sanitize default; attacker controls spec content, executes JS in embedding origin for any visitor; no auth required on target app.

## Preconditions

- **Auth-Required**: no
- **Auth-Roles**: anonymous
- **Attack vector**: Remote (network); attacker must control or influence the OpenAPI spec rendered by Acme.

## Remediation

Change the `sanitize` default to `true`. If backward compatibility is a concern, keep `sanitize: false` as the documented default but add a console warning when Acme is initialized without an explicit `sanitize` value and a network-fetched spec URL is provided. Alternatively, promote `untrustedSpec`/`sanitize` to a required option with no default, forcing every embedder to make an explicit trust decision.

In all cases, upgrade DOMPurify from 3.2.4 to at minimum 3.3.2 (ideally 3.4.0) to close the 7 active advisory window, so that `sanitize: true` provides the protection users expect.
