# [H7] Sanitize Default Off Xss

## Summary

`options.sanitize` defaults to `false`. When this default is active (i.e., the embedding app does
not explicitly set `sanitize: true` or `untrustedSpec: true`), the Markdown-rendering pipeline
passes raw HTML from spec `description` fields directly to `dangerouslySetInnerHTML` with no
sanitization whatsoever.

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
- **Source**: spec.*.description (and 12+ Markdown-bearing fields incl. info.description, info.summary, operation/parameter/response/schema description, OAuth scope description per H-00-D, security scheme description, server description, callback description, media-type example description, enum value descriptions)
- **Sink**: [REDACTED].tsx:31 (dangerouslySetInnerHTML, ungated when options.sanitize=false)
- **Chamber**: chamber-01

## Source to Sink Flow

Primary site: `src/services/AcmeNormalizedOptions.ts:317`. See draft.md for the full trace.

## Vulnerable Code

```
spec.*.description (attacker-controlled Markdown/HTML)
  → MarkdownRenderer.ts:renderMd() → marked()  [Markdown→HTML, allows raw HTML by default]
  → SanitizedMdBlock.tsx:16: sanitize(options.sanitize, html)
      → options.sanitize === false → returns raw html unchanged
  → SanitizedMdBlock.tsx:30: dangerouslySetInnerHTML={{ __html: html }}
  → DOM (XSS)
```

## Proof of concept & Evidence

No working PoC — routed to theoretical via Phase D9 Intent Reconciliation. Verdict: `intentional-design`. Source: `docs/config.md:77-80`. Quote: "sanitize — If set to true, the API definition is considered untrusted and all HTML/Markdown is sanitized to prevent XSS.". sanitize=false default enables DOM XSS via attacker-controlled spec content; cookie exfiltration on page load with concrete PoC payload

## Preconditions

- **Auth-Required**: no
- **Auth-Roles**: anonymous
- **Attack vector**: Remote (network); attacker must control or influence the OpenAPI spec rendered by Acme.

## Remediation

Consider changing the default of `options.sanitize` to `true`. If backward compatibility prevents
this, provide a prominent documentation warning and consider a console.warn when untrusted spec
content is detected rendered with `sanitize: false`. A CSP `script-src` policy in the embedding
application is the strongest compensating control.
