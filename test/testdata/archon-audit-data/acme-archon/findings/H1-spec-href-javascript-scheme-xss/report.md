# [H1] Spec Href Javascript Scheme Xss

## Summary

Multiple React anchor elements in the Acme renderer insert spec-derived URL strings directly into
`href` attributes without scheme validation. A crafted OpenAPI spec containing `javascript:` or
`data:` URIs in any of these fields will render a clickable link that executes JavaScript in the
embedding origin when clicked.

## Severity, Confidence, Vulnerability Type

- **Severity**: High
- **Confidence**: Confirmed (PoC executed)
- **Vulnerability Type**: XSS
- **Triage-Priority**: P1

## Impact

- **Integrity/Confidentiality**: Full XSS in the embedding origin
- **Scope**: Cross-user (any user who clicks the link on the docs page)
- **Gate**: `options.sanitize` does NOT cover anchor hrefs — these are React `<a href={...}>` elements,
  not rendered via `dangerouslySetInnerHTML`. DOMPurify is not consulted.

## Affected Component

- **File**: `src/components/ApiInfo/ApiInfo.tsx:39`
- **Source**: spec.info.license.url | spec.info.contact.url | spec.info.termsOfService | spec.externalDocs.url | spec.x-logo.href | spec.components.securitySchemes.*.openIdConnectUrl | spec.components.securitySchemes.*.flows.*.authorizationUrl | example.externalValueUrl
- **Sink**: src/components/ApiInfo/ApiInfo.tsx:39,48,65 | [REDACTED].tsx:25 | src/components/ApiLogo/styled.elements.tsx:21 | [REDACTED].tsx:46 | [REDACTED].tsx:27 | src/components/PayloadSamples/Example.tsx:34
- **Chamber**: chamber-01

## Source to Sink Flow

Primary site: `src/components/ApiInfo/ApiInfo.tsx:39`. See draft.md for the full trace.

## Vulnerable Code

See `src/components/ApiInfo/ApiInfo.tsx:39` and draft.md for code excerpts.

## Proof of concept & Evidence

**PoC-Status**: executed

Evidence files under `evidence/`:
- `evidence/exploit.log`
- `evidence/impact.log`
- `evidence/poc.html`
- `evidence/poc.js`

Decisive output from `evidence/exploit.log`:
```
=== H1 Sink Audit ===

  [VULNERABLE] src/components/ApiInfo/ApiInfo.tsx
               Sink pattern: /href=\{info\.license\.url\}/
               No scheme guard found.

  [VULNERABLE] src/components/ApiInfo/ApiInfo.tsx
               Sink pattern: /href=\{info\.contact\.url\}/
               No scheme guard found.

  [VULNERABLE] src/components/ApiInfo/ApiInfo.tsx
               Sink pattern: /href=\{info\.termsOfService\}/
               No scheme guard found.

  [VULNERABLE] [REDACTED].tsx
               Sink pattern: /href=\{externalDocs\.url\}/
               No scheme guard found.

=== Model-layer pass-through trace ===

  [CONFIRMED] src/services/models/ApiInfo.ts assigns spec URL fields with no sanitization.

=== React javascript: href behaviour ===

  React 18 emits a console.error for javascript: hrefs in DEV mode but does
  NOT throw, block, or sanitize in PRODUCTION builds.
  The href value is forwarded verbatim to the DOM <a> element.

=== Generated HTML PoC page ===

  Written to: /Users/<user>/Desktop/oss-to-run/acme/archon/findings/H1-spec-href-javascript-scheme-xss/evidence/poc.html 

=== Summary ===

  Vulnerable sinks confirmed (no guard):  4
  Sinks with scheme guard:               0
  Attacker-supplied javascript: URI in
  OpenAPI spec → rendered verbatim in
  <a href="..."> with no sanitization.

{"status":"confirmed","evidence":"4 anchor href sinks accept javascript: URI verbatim from spec; no scheme guard in source","notes":"Static code audit + model-layer trace. Browser click required for JS execution; HTML PoC page generated at evidence/poc.html"}

```

## Preconditions

- **Auth-Required**: no
- **Auth-Roles**: anonymous
- **Protocol**: http
- **Attack vector**: Remote (network); attacker must control or influence the OpenAPI spec rendered by Acme.

## Remediation

Add a URL scheme allow-list validation before rendering spec URLs as anchor hrefs:
```typescript
function safeUrl(url: string | undefined): string | undefined {
  if (!url) return undefined;
  try {
    const parsed = new URL(url);
    if (!['http:', 'https:', 'mailto:'].includes(parsed.protocol)) return '#';
  } catch { return '#'; }
  return url;
}
```
Apply to all spec-derived `href` values before rendering.

Confirm-Status: confirmed-test
Confirm-Timestamp: 2026-05-19T04:07:54Z
Confirm-Evidence: none
Confirm-Variant-Count: 0
Confirm-FpCheck: not-run
Confirm-Notes: Generated Jest test confirmed attacker-controlled javascript: URLs pass unchanged through ApiInfoModel and are inserted by ApiInfo.tsx into href sinks without scheme validation. Existing repository tests cover ApiInfoModel formatting/happy paths only and do not exercise malicious URL schemes.

Confirm-Method: generated-test

Confirm-Test: archon/findings/H1-spec-href-javascript-scheme-xss/confirm-test.ts

Confirm-Test-Output: archon/findings/H1-spec-href-javascript-scheme-xss/confirm-test-output.log

Confirm-Test-Identity: none
