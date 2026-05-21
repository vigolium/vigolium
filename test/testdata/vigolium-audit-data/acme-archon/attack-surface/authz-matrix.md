# Authorization Matrix — Acme (Acmely/acme)

**Audit date**: 2026-05-19
**Phase**: D7 (Authorization / Access Control Audit)
**Target commit**: [REDACTED]

---

## Section 1 — No Traditional Authorization Exists

Acme is a **purely client-side React rendering library** with no backend, no HTTP routes, no API server, no user sessions, no JWT verification, no RBAC, and no database. Every byte of code runs in the visitor's browser. Consequently:

- There are zero HTTP endpoints to enumerate for missing guards.
- There are zero database queries to audit for BOLA/IDOR.
- There are zero session tokens, JWTs, or user-identity objects.
- There are zero role or permission checks.
- There are zero tenant-isolation queries.

Classical access-control finding classes (missing-guard, IDOR/BOLA, vertical escalation, tenant bypass, mass assignment) are **structurally absent** and should not be raised by downstream chambers.

The access-control-analogous surface that DOES exist in a renderer library is:

1. **Option gate integrity** — rendering options control whether security-sensitive behaviours (HTML sanitisation, spec trust level) are enabled or suppressed. The *default* of those options and who can override them is the authz-equivalent trust boundary.
2. **Spec-controlled URL injection** — URLs taken from the OpenAPI spec and placed verbatim into `<a href>` attributes without scheme validation are the renderer's equivalent of an open-redirect / XSS auth bypass.
3. **Security-requirement rendering fidelity** — if the renderer silently drops or misrepresents a security requirement, consumers of the rendered docs may believe an endpoint is public when it requires authentication.
4. **HTML attribute trust override** — the `<acme>` web-component reads ALL HTML attributes and lets them override JS-supplied options; in CMS contexts where a spec author can also write raw HTML, this creates a trust-boundary collapse.

Coverage stats for analogous surfaces: **4 unique surface areas** | **3 genuine findings filed** | **0 classical authz findings (correct — library has no backend)**

---

## Section 2 — Option Security Matrix

Every option in `AcmeNormalizedOptions.ts` that affects a security-sensitive behaviour.

| Option Name | Normalized Type | Default Value | Who Can Set It | Security Implication | Fail-Safe? |
|-------------|-----------------|---------------|----------------|----------------------|------------|
| `sanitize` | boolean | **`false`** | Host-page JS (`AcmeStandalone` props); HTML attribute on `<acme>` element; deprecated alias `untrustedSpec` | When `false`, ALL Markdown/HTML from the spec is passed through `marked` and placed into `dangerouslySetInnerHTML` with **no DOMPurify call**. A malicious spec can inject arbitrary HTML/JS. | **Fail-open** — default is the unsafe choice |
| `untrustedSpec` | boolean (alias for `sanitize`) | **`false`** | Same as `sanitize`; merged via `raw.sanitize \|\| raw.untrustedSpec` | Deprecated alias; same implication as above. Two option names, one toggle — easy to set one and assume the other is also set. | Fail-open |
| `allowedMdComponents` | `Record<string, MDXComponentMeta>` | `{}` | Host-page JS only (complex object type) | Registers custom React components that can be embedded in Markdown via MDX-style syntax. A component with side effects (e.g., one that performs a network request or DOM mutation) can be triggered by spec-controlled Markdown content. Not directly spec-settable. | Neutral |
| `nonce` | string | `undefined` | Host-page JS | Passed through to styled-components for CSP nonce injection. If embedding page has a strict CSP and nonce is not threaded correctly, styled-components styles may be blocked; no direct security downgrade from the option itself. | Neutral |
| `hideSecuritySection` | boolean | `false` | Host-page JS; HTML attribute | Suppresses the entire Security panel section from rendering. Operators can use this to hide security information from documentation consumers. Not a vulnerability in Acme, but a **misuse risk**: an operator may hide security requirements without understanding the implications. | Informational |
| `showSecuritySchemeType` | boolean | `false` | Host-page JS; HTML attribute | Controls whether the scheme type (`API Key`, `OAuth2`, etc.) is shown in the summary bar for each security requirement. No direct security implication. | Neutral |
| `disableSearch` | boolean | `false` | Host-page JS; HTML attribute | Disables search index. No security implication. | Neutral |
| `expandDefaultServerVariables` | boolean | `false` | Host-page JS; HTML attribute | No security implication. | Neutral |

**Critical note on `sanitize` default**: `argValueToBoolean(raw.sanitize || raw.untrustedSpec)` with both inputs `undefined` evaluates to `argValueToBoolean(undefined)` which returns `defaultValue || false` = `false`. The default is therefore **sanitize: false** — DOMPurify is NOT called unless the host page explicitly opts in. This is a fail-open security default documented in the official config docs but not enforced anywhere.

---

## Section 3 — HTML Attribute Override Trust Matrix

`src/standalone.tsx` lines 20–41 and 70:

```
options: { ...options, ...parseOptionsFromElement(element) }
```

`parseOptionsFromElement` reads **every HTML attribute** off the `<acme>` DOM element and converts kebab-case attribute names to camelCase option names. These are then spread **after** (and therefore override) the JS-supplied `options` object.

| Attack Surface | Trust Concern | Exploitable When |
|----------------|---------------|------------------|
| `<acme sanitize="false">` overrides `options.sanitize = true` | HTML-attribute-supplied value defeats JS-supplied security option | Attacker can set HTML attributes on the `<acme>` element (e.g., CMS with raw HTML passthrough, user-controlled page content, XSS precondition) |
| `<acme spec-url="...">` is read by `autoInit()` (line 107) and passed as specUrl | Spec URL is spec-author-controlled | Any page that uses auto-init and allows attribute manipulation |
| `<acme theme='{"..."}'>` triggers `JSON.parse(optionValue)` | JSON.parse on attacker-controlled string; if the JSON is malformed, it throws a runtime error halting initialization | DOS / breakage, not escalation |

The spread order `{ ...options, ...parseOptionsFromElement(element) }` means **element attributes always win over JS options**. If a host embedder sets `sanitize: true` in JS options to guard against an untrusted spec but the embedding page allows a CMS user to also set HTML attributes on the `<acme>` element, the CMS user can set `sanitize="false"` to disable sanitization.

---

## Section 4 — Security-Requirement Model and Render Path Matrix

| Model Field | Source in Spec | Render Path | Escape Function Used | Finding |
|-------------|----------------|-------------|----------------------|---------|
| `scheme.id` | `securitySchemes` key name | `SecurityHeader` → React text node (`<i>{scheme.displayName}</i>`) | React JSX auto-escaping | Safe |
| `scheme.displayName` | `x-displayName` or id | `SecurityHeader` → `<i>{scheme.displayName}</i>` | React JSX auto-escaping | Safe |
| `scheme.description` | `description` field | `SecurityRequirement.tsx:63` → `<Markdown source={scheme.description}>` → `SanitizedMarkdownHTML` → `dangerouslySetInnerHTML` with conditional DOMPurify | DOMPurify **only if `sanitize: true`**; otherwise raw HTML | Unsafe when `sanitize: false` (default) |
| `scheme.scopes[n]` (scope name) | OAuth2 `scopes` keys | `OAuthFlow.tsx:54` → `<code>{scope}</code>` | React JSX auto-escaping | Safe |
| `flow.scopes[scope]` (scope description) | OAuth2 `scopes` values | `OAuthFlow.tsx:57-60` → `<Markdown source={flow.scopes[scope]}>` → same Markdown/DOMPurify pipeline | DOMPurify **only if `sanitize: true`** | Unsafe when `sanitize: false` |
| `flow.authorizationUrl` | OAuth2 implicit/authorizationCode flow | `OAuthFlow.tsx:27` → `<a target="_blank" href={(flow as any).authorizationUrl}>` | **None** — no scheme validation, no URL sanitization | **FINDING: javascript: URL injection (p6-001)** |
| `flow.tokenUrl` | OAuth2 [REDACTED] | `OAuthFlow.tsx:36` → `<code>{(flow as any).tokenUrl}</code>` | React JSX auto-escaping | Safe (rendered as `<code>` text, not as `<a href>`) |
| `flow.refreshUrl` | OAuth2 all flows | `OAuthFlow.tsx:42` → `<code>{flow.refreshUrl}</code>` | React JSX auto-escaping | Safe (same: code block, no href) |
| `scheme.openId.connectUrl` | `openIdConnectUrl` | `SecurityDetails.tsx:46` → `<a target="_blank" href={scheme.openId.connectUrl}>` | **None** — no scheme validation | **FINDING: javascript: URL injection (p6-001, same class)** |
| `info.license.url` | `info.license.url` | `ApiInfo.tsx:39` → `<a href={info.license.url}>` | **None** | Same class, broader scope |
| `info.contact.url` | `info.contact.url` | `ApiInfo.tsx:48` → `<a href={info.contact.url}>` | **None** | Same class |
| `info.termsOfService` | `info.termsOfService` | `ApiInfo.tsx:65` → `<a href={info.termsOfService}>` | **None** | Same class |
| `externalDocs.url` | `externalDocs.url` | `ExternalDocumentation.tsx:25` → `<a href={externalDocs.url}>` | **None** | Same class |
| `example.externalValueUrl` | `examples[n].externalValue` | `Example.tsx:34` → `<a href={example.externalValueUrl}>` | `new URL(externalValue, specUrl).href` resolves relative URLs but does NOT filter scheme | Same class |
| `downloadUrls[n].url` | embedder-supplied (not spec) | `ApiInfo.tsx:87` → `<a href={url}>` | **None** | Embedder-controlled, lower risk |

---

## Section 5 — jsonToHtml URL Rendering

`src/utils/jsonToHtml.ts` lines 55–63:

String values that match `/^(http|https):\/\/[^\s]+$/` are rendered as `<a href="…">`. The regex explicitly restricts to `http://` or `https://` schemes — `javascript:` does NOT match. The href value is further passed through `encodeURI()`. This path is **safe**.

---

## Section 6 — Demo/Playground Surface Matrix

| Surface | File | Attacker-Controlled Action | Risk |
|---------|------|---------------------------|------|
| `demo/index.tsx` (DemoApp) | URL query `?url=<spec>` | Load any spec URL; URL is then proxied through `https://cors.acme.ly/` if CORS checkbox enabled. Visitor-controlled spec is rendered without `sanitize: true` in the **playground** (note: demo index.tsx uses `sanitize: true`, see line 125). | **Mitigated** — demo DemoApp hard-codes `sanitize: true` in its `AcmeStandalone` options (line 125). |
| `demo/playground/hmr-playground.tsx` | URL query `?url=<spec>` | Load any spec URL; renderer initialized with `options = { nativeScrollbars: false, maxDisplayedEnumValues: 3, schemaDefinitionsTagName: 'schemas' }` — **`sanitize` is not set**, so it defaults to `false`. | **FINDING: p6-002** — playground renders attacker-controlled spec without sanitization |
| `demo/playground/index.html` | Static HTML, served by webpack-dev-server in dev | No user content, just `<acme id="example">` element. If accidentally deployed publicly (e.g., a CI artifact server), an attacker controlling the `?url=` parameter can load a malicious spec and execute XSS via unsanitized Markdown. | Conditional risk — dev artifact exposure |
| `demo/index.html` | Static HTML for interactive demo | No `spec-url` attribute on any element; no auto-init. | No risk |
| File upload (`demo/components/FileInput.tsx`) | Visitor can upload a local JSON/YAML file as spec | Uploaded spec is rendered locally in-browser. If the page is publicly exposed, any visitor can load arbitrary spec content. With `sanitize: true` in demo DemoApp, XSS from Markdown is blocked — but URL-injection findings (p6-001) still apply regardless of `sanitize`. | URL injection applicable; Markdown XSS mitigated in main demo. |

---

## Coverage Gaps

- No gRPC, GraphQL, WebSocket, queue consumer, or CLI user-data handler surfaces exist (library has none).
- No dynamic route registration to enumerate.
- The `acme-cli` CLI tool (`cli/` directory) was not fully audited for argument injection in the handlebars template path — that surface is covered by Phase D1/D2 advisory intelligence (handlebars RCE). It is not an authz surface.
