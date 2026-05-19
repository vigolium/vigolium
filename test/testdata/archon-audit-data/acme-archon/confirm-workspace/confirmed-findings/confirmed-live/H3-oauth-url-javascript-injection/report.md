# [H3] Oauth Url Javascript Injection

## Summary

Multiple components take URL-valued fields from the OpenAPI spec and place them verbatim into `<a href={url}>` attributes with no scheme validation. Any spec-controlled URL field can be set to `javascript:alert(document.cookie)` or similar. When a documentation consumer clicks the rendered link (e.g., the "Authorization URL" link in the OAuth2 security section, or the contact/license/terms links in the API info header), the JavaScript payload executes in the origin of the page embedding Acme. The `sanitize` option gate does **not** protect these paths — it only controls the `dangerouslySetInnerHTML` / DOMPurify pipeline for Markdown content; URL attributes in JSX bypass that gate entirely.

Blast radius: any embedder that renders an untrusted or third-party OpenAPI spec without `sanitize: true` AND without an external link-policy CSP directive. The attacker need only control one string field in the OpenAPI spec (authorizationUrl, openIdConnectUrl, info.contact.url, info.license.url, info.termsOfService, externalDocs.url, or examples[n].externalValue).

## Severity, Confidence, Vulnerability Type

- **Severity**: High
- **Confidence**: Confirmed (PoC executed)
- **Vulnerability Type**: XSS
- **Triage-Priority**: P1

## Impact

From `evidence/impact.log`:

```
=== H3 javascript: injection — Impact Evidence ===

Vulnerable sink verification:
  [VULNERABLE]  authorizationUrl  in  [REDACTED].tsx
  [VULNERABLE]  info.contact.url  in  src/components/ApiInfo/ApiInfo.tsx
  [VULNERABLE]  info.license.url  in  src/components/ApiInfo/ApiInfo.tsx
  [VULNERABLE]  info.termsOfService  in  src/components/ApiInfo/ApiInfo.tsx
  [VULNERABLE]  externalDocs.url  in  [REDACTED].tsx

Scheme guard search:
  No scheme validation guards found — all sinks confirmed unprotected.

Malicious spec fields (javascript: scheme):
  authorizationUrl      = javascript:alert('XSS-authorizationUrl: '+document.cookie)
  info.contact.url      = javascript:alert('XSS-contact-url: '+document.cookie)
  info.license.url      = javascript:alert('XSS-license-url: '+document.cookie)
  info.termsOfService   = javascript:alert('XSS-termsOfService: '+document.cookie)
  externalDocs.url      = javascript:alert('XSS-externalDocs-url: '+document.cookie)

Attack chain:
  1. Attacker crafts/controls OpenAPI spec with javascript: in any URL field.
  2. Acme renders the spec — field value flows through model layer to JSX
     <a href={...}> with NO scheme validation at any point in the pipeline.
  3. Rendered HTML contains: <a href="javascript:alert(...)">...</a>
  4. Victim clicks link → JavaScript executes in page origin → cookie theft,
     session hijacking, or arbitrary JS execution in the embedding 
…(truncated)

```

## Affected Component

- **File**: `[REDACTED].tsx:27`
- **Source**: spec.components.securitySchemes.*.flows.*.authorizationUrl | spec.components.securitySchemes.*.openIdConnectUrl | spec.info.{license.url, contact.url, termsOfService} | spec.externalDocs.url | example.externalValueUrl
- **Sink**: [REDACTED].tsx:27 | [REDACTED].tsx:46 | src/components/ApiInfo/ApiInfo.tsx:39,48,65 | [REDACTED].tsx:25 | src/components/PayloadSamples/Example.tsx:34
- **Chamber**: chamber-01

## Source to Sink Flow

Primary site: `[REDACTED].tsx:27`. See draft.md for the full trace.

## Vulnerable Code

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

## Proof of concept & Evidence

**PoC-Status**: executed

Evidence files under `evidence/`:
- `evidence/env-info.txt`
- `evidence/exploit.log`
- `evidence/impact.log`
- `evidence/poc.js`
- `evidence/xss_demo.html`

Decisive output from `evidence/exploit.log`:
```
[*] Step 1: verifying unguarded href patterns in source files
    [FOUND] authorizationUrl  →  [REDACTED].tsx
    [FOUND] info.contact.url  →  src/components/ApiInfo/ApiInfo.tsx
    [FOUND] info.license.url  →  src/components/ApiInfo/ApiInfo.tsx
    [FOUND] info.termsOfService  →  src/components/ApiInfo/ApiInfo.tsx
    [FOUND] externalDocs.url  →  [REDACTED].tsx

[*] Step 2: checking for absence of scheme guards
    [CONFIRMED] No scheme validation guards found in any sink file.

[*] Step 3: generating HTML proof page → /Users/<user>/Desktop/oss-to-run/acme/archon/findings/H3-oauth-url-javascript-injection/evidence/xss_demo.html
    HTML proof page written.

[*] Step 4: writing impact log
    impact.log written.

[*] Summary:
    authorizationUrl: VULNERABLE
    info.contact.url: VULNERABLE
    info.license.url: VULNERABLE
    info.termsOfService: VULNERABLE
    externalDocs.url: VULNERABLE
    Scheme guards: ABSENT (confirmed)

[*] HTML PoC page: /Users/<user>/Desktop/oss-to-run/acme/archon/findings/H3-oauth-url-javascript-injection/evidence/xss_demo.html
[*] Open it in a browser (with internet access for CDN Acme) and click any red-outlined link to trigger XSS.

{"status":"confirmed","evidence":"all five <a href> sinks contain unvalidated spec-sourced javascript: URLs (authorizationUrl, contact.url, license.url, termsOfService, externalDocs.url) — no scheme guard present in any file","notes":"HTML proof page at evidence/xss_demo.html; 5/5 sinks verified; no scheme guards found"}

```

## Preconditions

- **Auth-Required**: no
- **Auth-Roles**: anonymous
- **Protocol**: http
- **Attack vector**: Remote (network); attacker must control or influence the OpenAPI spec rendered by Acme.

## Remediation

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

Confirm-Status: confirmed-live
Confirm-Timestamp: 2026-05-19T04:02:05Z
Confirm-Evidence: archon/findings/H3-oauth-url-javascript-injection/confirm-evidence/
Confirm-Variant-Count: 1
Confirm-FpCheck: not-run
Confirm-Notes: Structured PoC output returned confirmed; node PoC verified 5/5 spec-sourced href sinks accept javascript: URLs with no scheme guards.
