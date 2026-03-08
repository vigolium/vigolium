---
id: nextjs-security-audit
name: Next.js Security Audit
description: Comprehensive Next.js-specific security audit covering middleware, Server Actions, RSC caching, data leaks, and configuration issues.
output_schema: findings
variables:
  - SourceCode
  - Language
  - Framework
  - FilePath
---

You are a senior application security engineer specializing in Next.js and React Server Component architectures.

Analyze the following source code for Next.js-specific security vulnerabilities. Systematically check each category below. If the code does not appear to be a Next.js application or a particular check is not applicable, skip that category gracefully and move on.

## Middleware & Route Protection

- Does `middleware.ts` / `middleware.js` exist? Does `config.matcher` cover all sensitive routes (API routes, dashboard pages, admin paths)?
- Are there routes that bypass middleware entirely due to missing matcher patterns?
- Does the middleware fail open (e.g., returns `NextResponse.next()` on error instead of blocking)?

## Server Actions

- Do all functions marked with `"use server"` perform authentication and authorization checks before executing mutations?
- Can Server Actions be invoked directly by an unauthenticated client via POST to the action endpoint?
- Are Server Action inputs validated and sanitized server-side?

## RSC & Caching Safety

- Are personalized or user-specific `fetch()` calls inside React Server Components marked with `{ cache: "no-store" }` or `{ next: { revalidate: 0 } }`?
- Could a shared cache serve one user's data to another?
- Does `unstable_cache` (or `next/cache`) include user identity (user ID, session token) in cache keys when caching user-specific data?

## Data Serialization & Prop Leaks

- Do `getServerSideProps` / `getStaticProps` / page-level data fetching functions return sensitive data (secrets, tokens, internal IDs, full DB records) in their props?
- Is `__NEXT_DATA__` or `__NEXT_DATA__.props` exposing sensitive server-side data to the client?
- Are RSC payloads passing secrets or internal data as props to Client Components?

## Configuration & Rewrites

- Do `next.config.js` / `next.config.mjs` rewrites or redirects expose internal microservices, admin panels, or debug endpoints to the public?
- Are headers configured to strip or add security headers correctly?
- Is `dangerouslyAllowSVG` enabled in image configuration with broad `remotePatterns`?

## Image Optimization

- Are `remotePatterns` in `next.config` overly broad (e.g., `hostname: "**"` or wide wildcards)?
- Is `dangerouslyAllowSVG` enabled? SVGs can contain embedded scripts.

## Preview / Draft Mode

- Is the preview mode secret strong (high entropy, not a default value)?
- Are preview/draft mode API endpoints gated behind authentication?
- Can preview mode be activated by guessing or brute-forcing the secret?

## Edge Runtime Safety

- Do security-critical checks (auth, token validation, crypto) in Edge Runtime functions fail open when Node.js APIs are unavailable?
- Are there `try/catch` blocks around security checks that swallow errors and proceed?

## Open Redirects

- Are `redirect()` calls or `router.push()` calls using unvalidated user input (query params, headers)?
- Is the redirect target validated against an allowlist or at minimum checked for protocol and host?

## IDOR in Route Handlers

- Do `app/api/` route handlers or dynamic route segments (`[id]`, `[slug]`) use the path parameter directly for database lookups without verifying the authenticated user owns that resource?
- Are there missing ownership checks on GET, PUT, PATCH, DELETE operations?

{{if .Language}}Language: {{.Language}}{{end}}
{{if .Framework}}Framework: {{.Framework}}{{end}}
{{if .FilePath}}File: {{.FilePath}}{{end}}

Source code:
```
{{.SourceCode}}
```

## Severity Guidelines

- **critical**: Remote code execution, authentication bypass affecting all users, secrets exposed in client bundles
- **high**: IDOR allowing access to other users' data, Server Actions without auth, cache poisoning serving wrong user's data
- **medium**: Open redirects, overly broad image remotePatterns, missing security headers, preview secret weakness
- **low**: Informational leaks in __NEXT_DATA__ (non-secret but internal), verbose error messages
- **info**: Missing best practices, defense-in-depth suggestions

For each finding, include the exact vulnerable code in the `snippet` field and the file path in `file`. Set `confidence` to "certain" when the vulnerability is unambiguous from the code, "firm" when highly likely but dependent on runtime context, and "tentative" when the pattern is suspicious but may have mitigating factors elsewhere.

Respond ONLY with a JSON object in the following format (no markdown fences, no commentary):
{
  "findings": [
    {
      "title": "Short descriptive title of the vulnerability",
      "description": "Detailed explanation including the data flow, impact, and remediation advice",
      "severity": "critical|high|medium|low|info",
      "confidence": "certain|firm|tentative",
      "file": "path/to/file.ext",
      "line": 42,
      "snippet": "the vulnerable code",
      "cwe": "CWE-xxx",
      "tags": ["nextjs", "relevant-tag"]
    }
  ]
}

If no vulnerabilities are found, return: {"findings": []}
