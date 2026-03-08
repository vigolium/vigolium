# Whitebox JS/TS Framework Security Scanning Enhancement Plan

This plan covers new modules, improvements to existing modules, agent prompt templates,
and SAST infrastructure work needed to cover the security pitfalls documented in
`whitebox-next.js.md` and `whitebox-vuln-ts.md` from a whitebox (source-code-available)
scanner perspective.

---

## Context

Vigolium has 75 DAST modules (50 active, 25 passive) that work on HTTP request/response
traffic. For whitebox scanning, it relies on:
- ast-grep route extraction (7 frameworks, Next.js at ~40% coverage)
- SARIF ingestion from Semgrep/Trivy
- Generic agent prompts (`security-code-review.md`, `injection-sinks.md`)

The gap: many modern JS/TS framework vulnerabilities are **only detectable from source
code** — they cannot be found by sending HTTP requests. The scanner has no static
analysis modules that read source files and emit findings directly.

---

## Tier 1: New Whitebox Modules (Source-Code-Only Detection)

These are new modules that analyze source code, config files, and project structure to
find vulnerabilities that DAST cannot detect. Each would be implemented as a new module
type (or a passive module variant that operates on source files rather than HTTP traffic).

### 1.1 Public Environment Secret Exposure

**What it detects:** Secrets accidentally exposed to client-side bundles via framework-
specific public env var mechanisms.

**Why DAST can't find this:** The secrets are baked into JS bundles at build time. DAST
would need to reverse-engineer minified bundles. Whitebox scanning can directly read
`.env*` files and code references.

**Detection logic:**
1. Scan all `.env`, `.env.local`, `.env.production`, `.env.development` files in project root.
2. Extract variables matching public-env prefixes:
   - Next.js: `NEXT_PUBLIC_*`
   - Vite: `VITE_*`
   - CRA: `REACT_APP_*`
   - Nuxt: keys under `runtimeConfig.public` in `nuxt.config.*`
3. Classify each value against a secret-detection ruleset (API key patterns, tokens,
   passwords, connection strings, private endpoints). Use the existing Kingfisher
   ruleset or a lightweight subset.
4. Cross-reference: find where these vars are used in code (`process.env.NEXT_PUBLIC_*`,
   `import.meta.env.VITE_*`) to confirm they're actually consumed client-side.

**Findings emitted:**
- CWE-200 (Information Exposure) — severity High if value matches API key / token
  pattern, Medium if it's an internal URL or non-public config value.

**Evidence format:**
```
File: .env.production
Variable: NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_...
Used in: src/lib/stripe.ts:14 → process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY
```

**Covers:** Next.js research #1, Vuln-TS §8.2

---

### 1.2 Server-Side Secret Leak via Props / Serialized State

**What it detects:** Server-only secrets that leak to the client through SSR props,
serialized page data (`__NEXT_DATA__`), or server component return values.

**Why DAST can't find this reliably:** DAST can see `__NEXT_DATA__` in rendered HTML but
can't distinguish intentional public data from leaked secrets without knowing the server
code. Whitebox analysis can trace what `getServerSideProps` / `getStaticProps` / server
components actually return.

**Detection logic:**
1. AST scan for `getServerSideProps` and `getStaticProps` exports.
2. Analyze the returned `props` object:
   - Flag if `process.env` (or a config object importing it) is spread into props.
   - Flag if a full database record is returned without field filtering (e.g.,
     `return { props: { user } }` where `user` comes from a DB query that includes
     `password_hash`, `api_key`, `secret`, etc.).
3. For App Router: scan server components that pass data to client components via props.
   If a `"use client"` component receives a prop whose value is derived from `process.env`
   or a DB record with sensitive-looking fields, flag it.
4. Heuristic for "sensitive fields": match field names against patterns like `password`,
   `secret`, `token`, `api_key`, `hash`, `ssn`, `credit_card`, `private_key`.

**Findings emitted:**
- CWE-200 (Information Exposure) — severity High.

**Covers:** Next.js research #2, #57, Vuln-TS §5.6

---

### 1.3 Unsafe Raw HTML Sinks (Framework-Specific XSS Vectors)

**What it detects:** Usage of framework-specific mechanisms that bypass automatic HTML
escaping, when the value originates from an untrusted source.

**Why DAST can't find this reliably:** DAST can detect reflected XSS by injecting
payloads, but stored XSS through CMS/Markdown/API content and client-side-only rendering
paths are often invisible to traffic-based scanning. Whitebox analysis can trace data
flow from source to sink.

**Detection logic per framework:**

React/Next.js:
- Search: `dangerouslySetInnerHTML={{ __html:` — extract the value expression.
- Trace backward: is it from `props`, `searchParams`, API response, CMS field, Markdown
  render output? If so, check for sanitizer call (DOMPurify, sanitize-html, etc.).
- Also flag: `<Script dangerouslySetInnerHTML={{__html: ...}} />` (next/script).

Vue/Nuxt:
- Search templates: `v-html="..."` — extract the bound expression.
- Trace: is it from `data()`, `computed`, `props`, API response?
- Check for sanitizer in the data flow.

Svelte/SvelteKit:
- Search: `{@html ...}` — extract the expression.
- Trace: is it from `data`, `load()` function, prop, store?

Angular:
- Search: `bypassSecurityTrustHtml(`, `bypassSecurityTrustUrl(`,
  `bypassSecurityTrustResourceUrl(`, `bypassSecurityTrustScript(`,
  `bypassSecurityTrustStyle(`
- Flag any usage where the argument is not a hardcoded string.

Generic (all frameworks):
- `.innerHTML =`, `.outerHTML =`, `insertAdjacentHTML(`, `document.write(`
- Flag when assigned value is not a constant.

**Findings emitted:**
- CWE-79 (XSS) — severity High if source is clearly untrusted (URL params, API
  response, user input), Medium if source is CMS/Markdown (may be trusted).

**Covers:** Next.js research #23-26, Vuln-TS §1.1-1.6, §1.9

---

### 1.4 Server Action Missing Authorization

**What it detects:** Next.js Server Actions (functions marked with `"use server"`) that
perform state-changing operations without verifying the caller's identity or privileges.

**Why this matters:** Server Actions are directly callable as HTTP POST endpoints. If
they lack auth checks, any user (or unauthenticated attacker) can invoke them. This is
a growing attack surface with App Router adoption.

**Detection logic:**
1. Find all functions/files with `"use server"` directive.
2. For each exported function:
   a. Check if the function body contains auth verification patterns:
      - `getSession()`, `getServerSession()`, `auth()`, `currentUser()`,
        `cookies().get('session')`, or similar auth library calls.
      - `if (!session)` / `if (!user)` guard patterns.
   b. Check if the function performs state-changing operations:
      - DB writes: `create`, `update`, `delete`, `insert`, `upsert`, `$executeRaw`
      - External calls: `fetch` with POST/PUT/DELETE method
      - Email/notification sends
   c. Flag if state-changing operations exist but auth checks are absent.
3. Also flag IDOR patterns: action reads `formData.get('userId')` and uses it in DB
   query without comparing against authenticated user.

**Findings emitted:**
- CWE-862 (Missing Authorization) — severity High for DB mutations, Medium for reads.

**Covers:** Next.js research #16, #15

---

### 1.5 Middleware Matcher Gap Detection

**What it detects:** Next.js middleware auth bypass caused by `config.matcher` patterns
that don't cover all sensitive routes.

**Why this matters:** Middleware is the primary auth enforcement point in many Next.js
apps. If the matcher is too narrow, sensitive API routes or pages bypass auth entirely.

**Detection logic:**
1. Find `middleware.ts` / `middleware.js` in project root or `src/`.
2. Extract `config.matcher` patterns (array of path globs).
3. Enumerate all actual routes from:
   - `app/**/route.ts` files (App Router API routes)
   - `app/**/page.tsx` files (App Router pages)
   - `pages/api/**` files (Pages Router API routes)
   - `pages/**` files (Pages Router pages)
4. For each route, check if it matches at least one matcher pattern.
5. Flag routes that:
   - Are under `/api/` and unmatched by middleware
   - Contain state-changing handlers (POST/PUT/DELETE exports) and are unmatched
   - Are pages that appear to require auth (contain auth-related imports) but are
     unmatched
6. Special case: if middleware has no matcher (applies to all routes), skip this check.
   If middleware file is absent entirely, flag that separately.

**Findings emitted:**
- CWE-863 (Incorrect Authorization) — severity High for unprotected API routes with
  mutations, Medium for unprotected pages.

**Covers:** Next.js research #13-14, Vuln-TS §5.5

---

### 1.6 Client-Only Auth Guard Detection

**What it detects:** Pages that enforce authentication only via client-side redirects
(e.g., `useEffect → router.push('/login')`) while their corresponding server endpoints
or data fetching have no server-side auth check.

**Detection logic:**
1. Find components/pages with client-side auth redirect patterns:
   - `useEffect(() => { ... router.push('/login') ... })`
   - `useEffect(() => { ... router.replace('/login') ... })`
   - `useEffect(() => { ... window.location = '/login' ... })`
   - `if (!user) redirect('/login')` in client components
2. For each such page, identify the data source:
   - Does it call API routes? Check those API routes for server-side auth.
   - Does it use `getServerSideProps`? Check for auth there.
   - Does it use server components? Check for auth in the component tree.
3. Flag if the data source (API route / server function) lacks auth checks while the
   page relies solely on client-side auth redirection.

**Findings emitted:**
- CWE-862 (Missing Authorization) — severity High. Client-side auth is not auth.

**Covers:** Next.js research #12, Vuln-TS §3.4

---

### 1.7 localStorage/sessionStorage Token Storage

**What it detects:** Authentication tokens stored in web storage, which makes any XSS
vulnerability escalate to full account takeover.

**Detection logic:**
1. Search for `localStorage.setItem(` and `sessionStorage.setItem(` calls.
2. Check if the key argument matches sensitive patterns:
   - Exact: `token`, `jwt`, `auth`, `session`, `access_token`, `refresh_token`,
     `id_token`, `bearer`, `api_key`
   - Fuzzy: contains `token`, `auth`, `session`, `jwt`, `credential`
3. Also search for `localStorage.getItem(` with same keys used in `Authorization`
   headers or `fetch` calls — confirms the stored value is a bearer token.
4. Skip if the stored value is clearly not a credential (e.g., theme preference,
   locale).

**Findings emitted:**
- CWE-922 (Insecure Storage of Sensitive Information) — severity Medium. Not a
  vulnerability itself, but a severity amplifier for any XSS.

**Covers:** Next.js research #22, Vuln-TS §2.1

---

### 1.8 Build and Deployment Misconfiguration

**What it detects:** Build/deployment configurations that weaken security in production.

**Detection logic (config file scanning):**

Source maps in production:
- `next.config.*`: `productionBrowserSourceMaps: true` → CWE-615, severity Medium
- `vite.config.*`: `build.sourcemap: true` (or `'inline'`, `'hidden'` without access
  restriction) → CWE-615, severity Medium
- `webpack.config.*`: production mode with `devtool: 'source-map'` → CWE-615

Dev mode in production:
- `Dockerfile` / `docker-compose.yml`: CMD/ENTRYPOINT contains `next dev` or
  `vite dev` or `NODE_ENV=development` → CWE-489, severity High
- `package.json`: `"start": "next dev"` or `"start": "vite dev"` → CWE-489

Public directory leaks:
- Scan `public/` directory for files matching `*.env`, `*.pem`, `*.key`, `*.p12`,
  `*.pfx`, `*.json` (if containing keys/secrets), `*.sql`, `*.dump`, `*.bak`,
  `*.old` → CWE-538, severity High

**Findings emitted:**
- CWE-615 (Source maps), CWE-489 (Dev mode), CWE-538 (File disclosure) — varies.

**Covers:** Next.js research #3-5, Vuln-TS §8.1, §8.3, §8.4

---

### 1.9 Unsafe Image Proxy / Optimization Configuration

**What it detects:** Next.js image optimization misconfiguration that enables SSRF or
XSS via SVG.

**Detection logic:**
1. Parse `next.config.*` (JS/TS/MJS).
2. Check `images.remotePatterns`:
   - Flag if `hostname` uses wildcard `**` or very broad patterns (e.g., `*.com`).
   - Flag if `protocol` allows `http` (non-HTTPS).
   - Flag if patterns include internal/cloud metadata hostnames.
3. Check `images.domains` (legacy): flag if it includes `*` or untrusted domains.
4. Check `images.dangerouslyAllowSVG`:
   - Flag `dangerouslyAllowSVG: true` combined with remote image sources (SVG can
     contain `<script>` and event handlers).
5. Check for custom `loader` functions that proxy arbitrary URLs.

**Findings emitted:**
- CWE-918 (SSRF) for overly broad remote patterns — severity High
- CWE-79 (XSS) for `dangerouslyAllowSVG: true` — severity Medium

**Covers:** Next.js research #28-29, Vuln-TS §5.2

---

### 1.10 Static Generation / Cache Data Leak

**What it detects:** User-specific or auth-gated data baked into statically generated
pages or improperly cached by RSC/ISR.

**Detection logic:**

Static generation leaks:
1. Find pages with `getStaticProps` or `generateStaticParams`.
2. Check if the data fetching inside uses auth headers, cookies, or session tokens.
3. Flag if auth-scoped data is fetched at build time (it will be the build-time user's
   data, or fail, or be empty — all wrong).
4. Also flag `export const dynamic = 'force-static'` on pages that import auth
   utilities.

Cache leaks (App Router):
1. Find `fetch()` calls in server components.
2. Flag if the fetch includes `Authorization` header or `cookies()` but does NOT set
   `cache: 'no-store'` or `next: { revalidate: 0 }`.
3. Find `unstable_cache()` calls — flag if the cache key does not include user/session
   identity when the wrapped function accesses user-specific data.

**Findings emitted:**
- CWE-524 (Cacheable sensitive data) — severity High for auth data, Medium for
  potentially-personalized data.

**Covers:** Next.js research #14, #43-45, Vuln-TS §5.6, §5.7

---

## Tier 2: Whitebox Enhancements to Existing DAST Modules

These add source-level detection to modules that currently only work on HTTP traffic.

### 2.1 Enhanced DOM XSS Detection (source-level taint tracking)

**Current state:** `dom_xss_detect` passive module extracts `<script>` blocks from HTTP
response bodies and runs regex-based source/sink analysis.

**Enhancement:** Add a whitebox variant that scans `.js`/`.ts`/`.tsx`/`.vue`/`.svelte`
source files directly:

1. Identify sources: `searchParams.get()`, `useSearchParams()`, `location.hash`,
   `location.search`, `window.name`, `document.cookie`, `postMessage` event data,
   `localStorage.getItem()`, API response fields.
2. Identify sinks: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`,
   `eval`, `new Function`, `setTimeout(string)`, `location.href = `, `window.open()`.
3. Perform intra-file taint tracking: follow variable assignments from source to sink.
4. For cross-file flows (import/export), flag if a source is exported and imported by a
   file that uses it in a sink — mark as "potential" with lower confidence.

**Advantage over DAST:** Finds DOM XSS in client-rendered paths that never appear in
server-rendered HTML (e.g., SPA routes, conditional rendering branches, error handlers).

**Covers:** Next.js research #23-26, Vuln-TS §1.1-1.8, §1.11

---

### 2.2 Enhanced Open Redirect Detection (source pattern matching)

**Current state:** `open_redirect` active module injects redirect payloads into URL
parameters.

**Enhancement:** Add whitebox detection for redirect patterns in code:

1. Find redirect calls: `NextResponse.redirect()`, `res.redirect()`, `redirect()`,
   `router.push()`, `router.replace()`, `location.assign()`, `location.replace()`.
2. Check if the redirect target is derived from request input (`searchParams`, `query`,
   `body`, `headers`).
3. Check for validation: same-origin check, URL allowlist, path-only enforcement,
   `new URL(input, base).origin === base` pattern.
4. Flag if validation is absent or uses weak patterns (e.g., `startsWith('/')` alone
   allows `//evil.com`).

**Covers:** Next.js research #11, #46, Vuln-TS §5.3

---

### 2.3 Enhanced Secret Detection (config-aware)

**Current state:** `secret_detect` passive module runs Kingfisher on HTTP response
bodies.

**Enhancement:** Add whitebox scanning for secret patterns in source/config:

1. Hardcoded fallback secrets: `process.env.SECRET || 'fallback'` patterns where the
   fallback is a weak/guessable string.
2. Secrets in code: hardcoded API keys, connection strings, private keys in `.ts`/`.js`
   files.
3. `.env` file secrets in public env vars (overlaps with §1.1 but uses Kingfisher rules
   for classification).
4. Secrets in `vercel.json`, `netlify.toml`, CI configs (`.github/workflows/*.yml`).

**Covers:** Next.js research #1-2, Vuln-TS §2.4, §8.2

---

### 2.4 Enhanced JWT Audit (code-level)

**Current state:** `jwt_weak_secret` passive module checks JWT tokens in HTTP traffic.
`jwt_vulnerability` active module tests for known JWT attacks.

**Enhancement:** Add whitebox detection:

1. Find `jwt.verify()` / `jwt.sign()` calls.
2. Check if `algorithms` option is specified (missing = accepts all algorithms).
3. Check if secret is a hardcoded string or has a weak fallback.
4. Check for `ignoreExpiration: true` or missing expiration enforcement.
5. Check for `jwt.decode()` used without subsequent `verify()` (signature not checked).

**Covers:** Next.js research #21, Vuln-TS §2.5

---

### 2.5 Enhanced CORS Validation (origin check weakness)

**Current state:** `cors_misconfiguration` active module and `cors_headers_detect`
passive module check CORS headers in HTTP responses.

**Enhancement:** Add whitebox detection for flawed origin validation logic:

1. Find CORS middleware or manual `Access-Control-Allow-Origin` header setting.
2. Flag reflective origin: `res.setHeader('ACAO', req.headers.origin)` without
   allowlist.
3. Flag weak allowlist patterns:
   - `origin.includes('trusted.com')` — matches `eviltrusted.com`
   - `origin.endsWith('trusted.com')` — matches `evil-trusted.com`
   - Regex without anchoring: `/trusted\.com/` — matches substrings
4. Flag `ACAO: *` combined with `Access-Control-Allow-Credentials: true` (browser
   rejects this, but indicates confused configuration).

**Covers:** Next.js research #18-19, Vuln-TS §4.3-4.5

---

### 2.6 Enhanced Prototype Pollution (deep merge pattern detection)

**Current state:** `prototype_pollution` active module sends `__proto__` payloads and
checks for behavior change.

**Enhancement:** Add whitebox detection for vulnerable merge patterns:

1. Find deep merge calls: `lodash.merge()`, `_.merge()`, `_.defaultsDeep()`,
   `deepmerge()`, `Object.assign()` where source is from request.
2. Check if the merged object later influences security decisions (auth checks, query
   construction, configuration).
3. Check for `__proto__` / `constructor` / `prototype` key filtering.
4. Flag: `deepmerge(defaults, req.body)` without key sanitization.

**Covers:** Next.js research #59, Vuln-TS §1.15

---

### 2.7 Enhanced Mass Assignment (spread-into-DB detection)

**Current state:** `mass_assignment` active module injects privilege keys into JSON
requests and checks if they echo back.

**Enhancement:** Add whitebox detection:

1. Find ORM/DB calls where the data object comes directly from request:
   - Prisma: `prisma.user.create({ data: req.body })`,
     `prisma.user.update({ data: body })`
   - Mongoose: `new User(req.body)`, `User.findByIdAndUpdate(id, req.body)`
   - Sequelize: `User.create(req.body)`, `user.update(req.body)`
   - Drizzle: `db.insert(users).values(req.body)`
2. Check if there's an explicit field allowlist (pick/omit of allowed fields).
3. Flag if sensitive fields (`role`, `isAdmin`, `admin`, `permissions`, `verified`,
   `email_verified`, `access_level`, `credits`, `balance`) could be set.

**Covers:** Next.js research #38, Vuln-TS §3.3

---

### 2.8 Enhanced CSRF Detection (cookie + missing token analysis)

**Current state:** `csrf_verify` active module and `csrf_detect` passive module check
forms and responses.

**Enhancement:** Add whitebox detection:

1. Find state-changing endpoints (POST/PUT/DELETE handlers).
2. Check if they rely on cookie-based authentication (session cookies, auth cookies).
3. Check for CSRF protection:
   - CSRF token validation in request handler
   - `Origin` / `Referer` header validation
   - `SameSite=Strict` on auth cookies
4. Flag endpoints that: (a) mutate state, (b) use cookie auth, (c) lack CSRF defenses.
5. Special case: Next.js Server Actions — these have built-in CSRF protection via
   action ID header, so don't flag them (reduce false positives).

**Covers:** Next.js research #17, Vuln-TS §4.1

---

## Tier 3: Specialized Agent Prompt Templates

These are new prompt templates for AI-driven analysis of complex, context-dependent
security issues that are hard to encode as rigid AST rules.

### 3.1 `nextjs-security-audit.md`

**Scope:** Comprehensive Next.js-specific security review.

**Template variables:** `{{SourceCode}}`, `{{Language}}`, `{{PreviousFindings}}`

**Analysis areas (instruct the agent to check):**
- Middleware coverage: does `config.matcher` cover all sensitive routes?
- Server Actions: auth checks present on all `"use server"` mutations?
- RSC caching: are personalized fetches correctly marked `no-store`?
- `unstable_cache`: do cache keys include user identity for user-specific data?
- `__NEXT_DATA__` / props: do `getServerSideProps`/`getStaticProps` leak secrets?
- `next.config.*` rewrites/redirects: do they expose internal APIs?
- Image optimization: are `remotePatterns` / `dangerouslyAllowSVG` safe?
- Preview/Draft Mode: is the preview secret strong and endpoints gated?
- Edge runtime: do security checks fail open when Node APIs unavailable?

**Output schema:** `findings` (CWE, severity, location, evidence, remediation).

**Covers:** Next.js research #13-14, #28-29, #42-45, #47, #53-54

---

### 3.2 `react-xss-audit.md`

**Scope:** React/JSX-specific XSS and injection review.

**Analysis areas:**
- `dangerouslySetInnerHTML` usage with untrusted content
- Markdown/MDX render pipelines: is `rehypeRaw`/`allowDangerousHtml` enabled with
  user content?
- `next/script` with dynamic HTML injection
- URL scheme injection: `href={userInput}` without protocol allowlist
- SSR state injection: `__INITIAL_STATE__` / `__NEXT_DATA__` serialization safety
- Sanitizer usage audit: is DOMPurify/sanitize-html configured correctly? Is output
  mutated after sanitization?

**Covers:** Vuln-TS §1.1, §1.9-1.11, §1.14

---

### 3.3 `auth-session-review.md`

**Scope:** Authentication and session management across any JS/TS framework.

**Analysis areas:**
- Token storage: `localStorage`/`sessionStorage` vs `httpOnly` cookies
- Cookie flags: `Secure`, `HttpOnly`, `SameSite` on auth cookies
- JWT configuration: algorithm pinning, secret strength, expiration
- Session rotation: is session ID regenerated on login/privilege change?
- Logout: does it revoke server-side session or just clear client storage?
- OAuth implementation: state validation, redirect_uri enforcement, token logging
- Auth middleware coverage: are all sensitive endpoints protected server-side?

**Covers:** Vuln-TS §2.1-2.8, Next.js research #12, #20-22, #56

---

### 3.4 `cors-csrf-review.md`

**Scope:** Cross-origin and cross-site request security.

**Analysis areas:**
- CORS configuration: is origin validated with exact match? Reflective origin?
- CORS allowlist strength: no `.includes()` / `.endsWith()` bypasses?
- `Vary: Origin` present when ACAO is dynamic?
- CSRF defenses: token, Origin/Referer check, or SameSite on all mutating endpoints?
- `postMessage` receivers: `event.origin` check present and strict?
- `postMessage` senders: targetOrigin not `"*"` with sensitive data?
- WebSocket upgrade: Origin validation? Cookie auth without CSRF defense?
- Clickjacking: `frame-ancestors` / `X-Frame-Options` on auth pages?

**Covers:** Vuln-TS §4.1-4.10, Next.js research #8, #17-19

---

### 3.5 `build-config-audit.md`

**Scope:** Build tooling and deployment configuration security.

**Analysis areas:**
- Source maps: enabled in production? Accessible publicly?
- Public env vars: secrets in `NEXT_PUBLIC_*` / `VITE_*` / `REACT_APP_*`?
- Dev mode: `next dev` / `vite dev` in production Dockerfile/scripts?
- `public/` directory: sensitive files (`.env`, keys, backups, SQL dumps)?
- CSP configuration: present? Does it allow `unsafe-inline` / `unsafe-eval`?
- Security headers: HSTS, X-Content-Type-Options, Referrer-Policy?
- Dependency risks: install scripts, lockfile enforcement, unscoped internal packages?

**Covers:** Vuln-TS §6.1-6.8, §8.1-8.4, §9.1-9.3, Next.js research #3-7

---

## Tier 4: SAST Infrastructure Improvements

### 4.1 Expand Next.js ast-grep Rules

**Current state:** 3 rules (api-route-handler, pages-api-handler, dynamic-route).
Coverage is ~40% — detects route handlers but misses parameter extraction from request
objects.

**New rules needed:**

App Router parameter binding:
- `request.nextUrl.searchParams.get('...')` / `.has('...')` / `.getAll('...')`
- `await request.json()` — JSON body extraction
- `await request.formData()` — form data extraction
- `cookies().get('...')` / `headers().get('...')`
- `params` destructuring in route handler signature

Server Actions:
- `"use server"` directive detection
- Exported async functions in `"use server"` files
- `formData.get('...')` parameter extraction in server actions

Route Groups and Layouts:
- `app/(group)/` route group detection
- `layout.tsx` / `template.tsx` identification
- `loading.tsx` / `error.tsx` / `not-found.tsx` boundary detection

Middleware:
- `middleware.ts` detection and `config.matcher` extraction
- `NextResponse.redirect()` / `NextResponse.rewrite()` / `NextResponse.next()` usage

**Expected outcome:** Coverage from ~40% to ~85%.

---

### 4.2 Add Next.js Handoff Test Definitions

**Current state:** Handoff tests exist for Gin, Express, FastAPI — but not Next.js.
This means the whitebox→DAST pipeline (extract routes → generate HTTP requests → run
active modules) cannot be validated for Next.js.

**New definitions needed:**
- `nextjs-handoff.yaml` — validate that extracted App Router and Pages API routes
  correctly convert to `HttpRequestResponse` objects with proper method, URI, headers,
  and body.

---

### 4.3 Add Next.js Agent Quality Benchmarks

**Current state:** Agent quality benchmarks exist for Gin, Flask, FastAPI, Express,
Django — but not Next.js.

**New definitions needed:**
- `nextjs-security-review-quality.yaml` — run `security-code-review.md` template
  against Next.js test fixtures, validate expected CWEs are found.
- Requires creating a Next.js test fixture (`test/testdata/sast-stubs/nextjs/`) with
  intentional vulnerabilities covering the patterns from Tier 1.

---

### 4.4 Fix Existing Next.js Test Stubs

**Current issue:** `test/testdata/sast-stubs/nextjs/pages/api/health.ts` uses
`useRouter()` and `useSearchParams()` in a Pages API handler, which is semantically
incorrect (those are React hooks, not available in API routes).

**Fix:** Replace with correct Pages API patterns:
```typescript
import type { NextApiRequest, NextApiResponse } from 'next'

export default function handler(req: NextApiRequest, res: NextApiResponse) {
  const { id } = req.query
  res.status(200).json({ status: 'ok', id })
}
```

---

### 4.5 Expand Next.js Test Fixtures for Whitebox

**New fixtures needed in `test/testdata/sast-stubs/nextjs/`:**

```
nextjs/
├── .env.local                          # Public env secrets
├── next.config.ts                      # Misconfigs (source maps, SVG, broad patterns)
├── middleware.ts                        # Matcher with gaps
├── app/
│   ├── api/
│   │   ├── users/route.ts              # Existing (keep)
│   │   ├── admin/route.ts              # Missing auth check
│   │   └── webhook/route.ts            # Missing signature validation
│   ├── dashboard/page.tsx              # Client-only auth guard
│   └── profile/page.tsx                # SSR props leaking user secrets
├── pages/
│   └── api/
│       └── health.ts                   # Fixed legacy handler
├── lib/
│   ├── actions.ts                      # Server actions without auth
│   ├── auth.ts                         # JWT with weak config
│   └── cors.ts                         # Weak origin validation
└── components/
    └── RichText.tsx                     # dangerouslySetInnerHTML with CMS content
```

---

## Implementation Priority

Ordered by (value to users) x (feasibility) / (effort):

### Phase 1 — Quick Wins (config scanning, no AST needed)
1. **1.8 Build/Deploy Misconfig** — file/config pattern matching only
2. **1.1 Public Env Secret Exposure** — .env file scanning + string matching
3. **1.9 Unsafe Image Proxy Config** — next.config parsing
4. **4.4 Fix Next.js test stubs** — correctness fix

### Phase 2 — AST-Based Detection
5. **4.1 Expand Next.js ast-grep rules** — prerequisite for Tier 1 AST modules
6. **1.3 Unsafe Raw HTML Sinks** — highest-value XSS detection
7. **1.7 localStorage Token Storage** — simple AST pattern
8. **1.4 Server Action Missing Auth** — Next.js-specific, high impact

### Phase 3 — Complex Analysis
9. **1.2 Server-Side Secret Leak via Props** — requires data flow analysis
10. **1.5 Middleware Matcher Gap** — requires route enumeration + pattern matching
11. **1.6 Client-Only Auth Guard** — requires cross-file correlation
12. **1.10 Static Generation / Cache Data Leak** — requires understanding of caching

### Phase 4 — Agent Prompts and Benchmarks
13. **3.1 nextjs-security-audit.md** prompt template
14. **3.5 build-config-audit.md** prompt template
15. **3.2-3.4** remaining prompt templates
16. **4.2-4.3** handoff tests and quality benchmarks
17. **4.5** expanded test fixtures

### Phase 5 — DAST Module Enhancements
18. **2.1-2.8** whitebox enhancements to existing modules (as source-code analysis
    variants alongside existing traffic-based detection)

---

## Architecture Decision: How Whitebox Modules Fit In

The existing module system (`ActiveModule` / `PassiveModule`) operates on
`HttpRequestResponse` objects — it expects HTTP traffic. Whitebox modules need a
different input: source files and project structure.

**Options:**

A. **New `WhiteboxModule` interface** — parallel to Active/Passive, takes a
   `ProjectContext` (file tree, parsed configs, AST results) instead of HTTP traffic.
   Registered separately, run during a "whitebox scan" phase.

B. **Agent-only approach** — all whitebox detection runs through agent prompts. No new
   module type. Simpler but less deterministic and reproducible.

C. **Hybrid** — simple pattern-based checks (env scanning, config parsing) as
   `WhiteboxModule`. Complex context-dependent analysis (data flow, cross-file
   correlation) as agent prompts.

**Recommendation: Option C (Hybrid).** Config/pattern checks are fast, deterministic,
and don't need AI. Complex taint tracking and context analysis benefit from agent
intelligence. This also maps naturally to the phased implementation above: Phase 1-3
are modules, Phase 4 is agent prompts.
