---
id: cors-csrf-review
name: CORS & CSRF Security Review
description: Cross-origin and CSRF security review covering CORS configuration, CSRF protections, postMessage, WebSocket, clickjacking, and Fetch Metadata enforcement.
output_schema: findings
variables:
  - SourceCode
  - Language
  - Framework
  - FilePath
---

You are a senior application security engineer specializing in cross-origin security, CSRF defenses, and browser security mechanisms.

Analyze the following source code for cross-origin and CSRF vulnerabilities. Systematically check each category below. If the code does not contain patterns relevant to a particular check, skip that category gracefully and move on.

## CORS Origin Validation

- Is `Access-Control-Allow-Origin` set dynamically based on the request `Origin` header?
- If dynamic, is the origin validated against an exact-match allowlist?
- Is the origin check using dangerous substring patterns that can be bypassed?
  - `.includes("example.com")` — bypassed by `attacker-example.com` or `example.com.attacker.com`
  - `.endsWith("example.com")` — bypassed by `notexample.com`
  - Regex without anchoring — bypassed by crafted origins
- Is the request `Origin` reflected directly back as `Access-Control-Allow-Origin` without any validation (origin reflection)?

## CORS Header Configuration

- Is `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true`? This is an invalid combination but some servers may still set it, indicating confused configuration.
- Is `Vary: Origin` present when `Access-Control-Allow-Origin` is set dynamically? Without it, caching proxies may serve a response with the wrong origin to different requesters.
- Are `Access-Control-Allow-Methods` and `Access-Control-Allow-Headers` overly permissive (e.g., allowing all methods/headers)?
- Is `Access-Control-Expose-Headers` leaking sensitive response headers?
- Is `Access-Control-Max-Age` set to an excessively long duration, preventing quick revocation of CORS policy changes?

## CSRF Protection

- Do all state-changing endpoints (POST, PUT, PATCH, DELETE) that use cookie-based authentication have CSRF protections?
- What CSRF mechanism is used: synchronizer token, double-submit cookie, Origin/Referer header check, or SameSite cookie attribute?
- Is the CSRF token validated on the server for every mutating request, or only some?
- Is `SameSite=Strict` or `SameSite=Lax` set on authentication cookies?
- Are there state-changing GET endpoints (which bypass SameSite=Lax and most CSRF defenses)?

## postMessage Security

- Do `window.addEventListener("message", handler)` receivers validate `event.origin` before processing the message?
- Is the origin check strict (exact match) or bypassable (`.includes()`, `.endsWith()`, regex without anchoring)?
- Does the handler execute dangerous operations (DOM manipulation, navigation, eval, token extraction) based on message content?
- Are `postMessage()` calls using `targetOrigin: "*"` when sending sensitive data? Is the target origin restricted to the intended recipient?

## WebSocket Security

- Is the `Origin` header validated during the WebSocket upgrade handshake?
- If the WebSocket connection relies on cookie-based authentication, is there a CSRF protection mechanism (origin check, token in first message)?
- Are WebSocket messages sanitized before being rendered in the DOM?
- Is the `wss://` scheme enforced in production?

## Clickjacking / UI Redressing

- Is `Content-Security-Policy: frame-ancestors` or `X-Frame-Options` set on pages containing sensitive actions (login, payment, settings)?
- Is `frame-ancestors` set to `'self'` or a specific allowlist, not `*`?
- Do `X-Frame-Options` and CSP `frame-ancestors` agree (no conflicting directives)?

## Fetch Metadata (Sec-Fetch-*)

- Does the server inspect `Sec-Fetch-Site`, `Sec-Fetch-Mode`, or `Sec-Fetch-Dest` headers to reject suspicious cross-origin requests?
- Are resource isolation policies implemented for API endpoints (rejecting `Sec-Fetch-Site: cross-site` on sensitive endpoints)?
- If Fetch Metadata checks are present, are they enforced (blocking) or only logging?

{{if .Language}}Language: {{.Language}}{{end}}
{{if .Framework}}Framework: {{.Framework}}{{end}}
{{if .FilePath}}File: {{.FilePath}}{{end}}

Source code:
```
{{.SourceCode}}
```

## Severity Guidelines

- **critical**: Origin reflection (arbitrary origin allowed with credentials), CSRF on critical endpoints (password change, admin actions) with no protection
- **high**: Bypassable origin validation (substring matching), missing CSRF tokens on state-changing cookie-auth endpoints, postMessage handler executing eval/navigation without origin check
- **medium**: Missing Vary: Origin on dynamic CORS, SameSite=None without CSRF token, WebSocket without origin validation, clickjacking on sensitive pages
- **low**: Overly permissive CORS preflight (wide methods/headers), missing Fetch Metadata enforcement, X-Frame-Options without CSP frame-ancestors
- **info**: Defense-in-depth suggestions, best practices not yet adopted

For each finding, include the exact vulnerable code in `snippet` and explain the specific bypass or attack scenario in `description`. Set `confidence` to "certain" when the misconfiguration is unambiguous from the code, "firm" when the issue is highly likely but depends on deployment context (e.g., proxy behavior), and "tentative" when the pattern is suspicious but may have mitigating factors.

Respond ONLY with a JSON object in the following format (no markdown fences, no commentary):
{
  "findings": [
    {
      "title": "Short descriptive title of the vulnerability",
      "description": "Detailed explanation including the attack scenario, bypass technique, impact, and remediation",
      "severity": "critical|high|medium|low|info",
      "confidence": "certain|firm|tentative",
      "file": "path/to/file.ext",
      "line": 42,
      "snippet": "the vulnerable code",
      "cwe": "CWE-xxx",
      "tags": ["cors", "relevant-tag"]
    }
  ]
}

If no vulnerabilities are found, return: {"findings": []}
