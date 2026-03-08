# Scan Scope — How Modules Are Dispatched

Every scanner module declares a **scan scope** that tells the executor *when* and *how often* to invoke it. The scan scope determines the granularity at which the module operates: per parameter, per request, or per host.

```go
type ScanScope uint8

const (
    ScanScopeInsertionPoint ScanScope = 1 << iota  // per parameter
    ScanScopeRequest                                // per request
    ScanScopeHost                                   // per host
)
```

Scopes are a bitmask. A module can declare multiple scopes (e.g., `ScanScopeRequest | ScanScopeInsertionPoint`).

---

## Overview Diagram

```
                        Incoming HttpRequestResponse
                                    │
                                    ▼
                    ┌───────────────────────────────┐
                    │         Executor               │
                    │  (scope filtering + dispatch)  │
                    └───────┬───────┬───────┬────────┘
                            │       │       │
              ┌─────────────┘       │       └──────────────┐
              ▼                     ▼                      ▼
   ┌─────────────────┐   ┌──────────────────┐   ┌──────────────────┐
   │  ScanScopeHost   │   │ ScanScopeRequest  │   │ScanScopeInsertion│
   │                  │   │                   │   │     Point        │
   │  Runs ONCE per   │   │  Runs ONCE per    │   │  Runs ONCE per   │
   │  unique host     │   │  unique request   │   │  PARAMETER in    │
   │                  │   │                   │   │  the request     │
   │  e.g. only 1x    │   │  e.g. 1x for      │   │                  │
   │  for example.com │   │  GET /api?id=1    │   │  e.g. 3x for     │
   │  even with 500   │   │                   │   │  ?a=1&b=2&c=3    │
   │  requests        │   │                   │   │                  │
   └─────────────────┘   └──────────────────┘   └──────────────────┘
          │                       │                       │
          ▼                       ▼                       ▼
   CORS misconfig          403 bypass            SQLi on param "a"
   Default creds           Host header inj       SQLi on param "b"
   Sensitive files         JWT manipulation      SQLi on param "c"
   GraphQL introspect      Method tampering      SSTI on param "a"
                           Cache poisoning       SSTI on param "b"
                                                 ...
```

---

## The Three Scopes

### ScanScopeInsertionPoint

**Invoked once for each parameter (insertion point) in the request.**

The executor parses the raw HTTP request, extracts every injectable location, and hands them to the module one at a time. The module receives a single `InsertionPoint` with a `BuildRequest(payload)` method to inject its payload at that exact position.

#### How it works step by step

Given this request:

```http
POST /api/search?lang=en HTTP/1.1
Host: example.com
Cookie: session=abc123
Content-Type: application/x-www-form-urlencoded

query=test&page=1
```

**Step 1 — The executor calls `CreateAllInsertionPoints()` and finds 5 insertion points:**

```
┌─────┬──────────────┬────────────┬──────────┐
│  #  │  Name        │  Type      │  Value   │
├─────┼──────────────┼────────────┼──────────┤
│  1  │  lang        │  URL_PARAM │  en      │
│  2  │  session     │  COOKIE    │  abc123  │
│  3  │  query       │  BODY_PARAM│  test    │
│  4  │  page        │  BODY_PARAM│  1       │
│  5  │  Host        │  HEADER    │  exampl… │
└─────┴──────────────┴────────────┴──────────┘
```

**Step 2 — For each insertion point, the executor runs all compatible modules in parallel:**

```
Insertion Point #1: lang=en (URL_PARAM)
  ├── sqli_error_based  →  lang=' OR 1=1--     → check response for SQL errors
  ├── ssti_detection    →  lang={{7*7}}         → check response for "49"
  ├── lfi_generic       →  lang=../../etc/passwd → check response for "root:"
  ├── crlf_injection    →  lang=%0d%0aX:injected → check response headers
  └── ... (all PER_INSERTION_POINT modules that accept URL_PARAM)

Insertion Point #2: session=abc123 (COOKIE)
  ├── sqli_error_based  →  session=' OR 1=1--  → check response
  ├── ssti_detection    →  session={{7*7}}      → check response
  └── ... (only modules that accept COOKIE type)

Insertion Point #3: query=test (BODY_PARAM)
  ├── sqli_error_based  →  query=' OR 1=1--    → check response
  ├── ssti_detection    →  query={{7*7}}        → check response
  ├── ssrf_detection    →  query=http://burp.co → check for OOB callback
  └── ...

... and so on for each insertion point
```

**Step 3 — Each module uses `BuildRequest(payload)` to construct the modified request.** Only the target parameter changes; everything else stays the same:

```
Original:  POST /api/search?lang=en HTTP/1.1  ...  query=test&page=1
Injected:  POST /api/search?lang=en HTTP/1.1  ...  query=' OR 1=1--&page=1
                                                          ^^^^^^^^^^^^
                                                    only this changed
```

**What counts as an insertion point:**

| Type | Example | What gets tested |
|------|---------|-----------------|
| URL parameter | `?id=123` | The value `123` |
| Body parameter | `username=admin` | The value `admin` |
| JSON value | `{"user":"admin"}` | The value `"admin"` |
| Cookie | `session=abc` | The value `abc` |
| HTTP header | `Host: example.com` | The value `example.com` |
| XML element | `<id>5</id>` | The value `5` |
| XML attribute | `<tag attr="val">` | The value `val` |
| Multipart field | `Content-Disposition: name="file"` | The field value |
| URL path folder | `/api/users/123` | The segment `123` |
| URL path filename | `/api/report.pdf` | The filename `report.pdf` |
| Parameter name (URL) | `?id=123` | The key `id` itself |
| Parameter name (body) | `username=admin` | The key `username` itself |
| Entire body | Full POST body | The whole body as one blob |

With `includeNested=true` (the default), the executor also discovers **nested structures** — for example, a URL parameter whose value is Base64-encoded JSON will produce additional insertion points for each key inside that JSON.

Each module also declares which `InsertionPointType`s it accepts (via `AllowedInsertionPointTypes()`), so an SQLi module might only test URL params, body params, and JSON values, while skipping cookies and headers.

**Typical vulnerabilities found:**
- SQL injection (error-based, blind)
- Cross-site scripting (XSS)
- Server-side template injection (SSTI)
- Command injection
- Path traversal / LFI
- SSRF
- CRLF injection
- NoSQL injection
- XML/SAML injection
- Insecure deserialization

**Active modules using this scope (18):**
`sqli_error_based`, `ssti_detection`, `reflected_ssti`, `csti_detection`, `ssrf_detection`, `lfi_generic`, `lfi_path_traversal`, `crlf_injection`, `nosqli_error_based`, `nosqli_operator_injection`, `xml_saml_security`, `insecure_deserialization`, `backslash_transformation`, `suspect_transform`, `smart_behavior_detection`, `input_behavior_probe`, `race_interference`, `oast_probe` (hybrid)

---

### ScanScopeRequest

**Invoked once per unique request/response pair.**

The module receives the entire `HttpRequestResponse` and decides on its own what to modify. It is not given a specific parameter — it has full control over the request structure.

This scope is used for vulnerabilities that:
- Don't map to a single parameter (e.g., changing the HTTP method, adding new headers)
- Need cross-parameter context (e.g., comparing timing across multiple params)
- Test request-level properties (e.g., JWT tokens, CSRF tokens, caching behavior)
- Internally manage their own parameter iteration for specialized logic

#### How it works step by step

Given this request that returns a 403:

```http
GET /admin/dashboard HTTP/1.1
Host: example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
```

**The `forbidden_bypass` module receives the whole request and tries multiple attack vectors itself:**

```
Original request → 403 Forbidden

Attempt 1: Path tricks
  GET /./admin/dashboard       → 403  (no bypass)
  GET /admin/dashboard/./      → 403  (no bypass)
  GET /admin/dashboard..;/     → 200  ← BYPASS FOUND!

Attempt 2: Header injection (if path tricks fail)
  GET /anything
  X-Original-URL: /admin/dashboard  → check status

Attempt 3: Method tampering (if headers fail)
  PUT /admin/dashboard         → check status
  PATCH /admin/dashboard       → check status
  DELETE /admin/dashboard      → check status

Attempt 4: Method override headers
  POST /admin/dashboard
  X-HTTP-Method-Override: GET  → check status
```

**The `host_header_injection` module tests header reflection:**

```
Original:
  Host: example.com                     → response body

Test 1:
  Host: evil.attacker.com               → does "evil.attacker.com" appear in response?

Test 2:
  X-Forwarded-Host: evil.attacker.com   → reflected in Location header?

Test 3:
  Forwarded: host=evil.attacker.com     → reflected anywhere?
```

**The `jwt_vulnerability` module manipulates the JWT token:**

```
Original token:    eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiam9obiJ9.signature
                   │                     │                      │
                   header                payload                signature

Test 1 — Algorithm confusion:
  Change alg: HS256 → none, send without signature → still accepted?

Test 2 — Weak key:
  Try signing with common secrets ("secret", "password", "") → accepted?
```

Notice how none of these attacks target a single parameter — they modify the request structure, headers, method, or tokens. That's why they use `ScanScopeRequest` instead of `ScanScopeInsertionPoint`.

**Typical vulnerabilities found:**
- 403/401 bypass (path tricks, method tampering, header injection)
- Host header injection
- Open redirect
- JWT vulnerabilities (algorithm confusion, weak secrets)
- CSRF verification bypass
- Web cache poisoning
- Prototype pollution
- XXE (full-body injection)
- HTTP method override
- Swagger/API documentation exposure
- File upload vulnerabilities
- JSONP callback injection
- Nginx path escape

**Active modules using this scope (24):**
`forbidden_bypass`, `host_header_injection`, `open_redirect`, `jwt_vulnerability`, `csrf_verify`, `web_cache_poisoning`, `prototype_pollution`, `client_prototype_pollution`, `xxe_generic`, `xss_scanner`, `xss_light_scanner` (3 sub-modules), `sqli_boolean_blind`, `sqli_time_based_params`, `sqli_time_based_header`, `code_exec`, `file_upload_scan`, `swagger_disclose`, `spring_actuator_misconfig`, `nginx_path_escape`, `path_normalization`, `jsonp_callback`, `oast_probe` (hybrid)

**Passive modules using this scope (19):**
`info_disclosure_detect`, `secret_detect`, `cookie_security_detect`, `cors_headers_detect`, `content_type_mismatch`, `dom_xss_detect`, `csrf_detect`, `mixed_content_detect`, `auth_headers_detect`, `jwt_weak_secret`, `oauth_facebook_detect`, `openredirect_params`, `sensitive_url_params`, `sourcemap_detect`, `sql_syntax_detect`, `serialized_object_detect`, `crypto_weakness_detect`, `anomaly_ranking`, `idor_params_detect`

---

### ScanScopeHost

**Invoked once per unique host.**

The executor deduplicates by hostname — if 500 requests arrive for `example.com`, the module runs only once. This scope is for expensive one-time checks that apply to the entire host, not to individual pages or parameters.

#### How it works step by step

Given 500 different requests to `example.com`:

```
Request #1:   GET /api/users HTTP/1.1        Host: example.com
Request #2:   POST /api/login HTTP/1.1       Host: example.com
Request #3:   GET /products?id=42 HTTP/1.1   Host: example.com
...
Request #500: GET /about HTTP/1.1            Host: example.com
```

**The executor runs each `ScanScopeHost` module only on the first request it sees for that host. The remaining 499 requests are skipped:**

```
Request #1 arrives for example.com (first time seen)
  ├── sensitive_file_discovery
  │     GET /.env               → 404
  │     GET /.git/config        → 200 ← FOUND!
  │     GET /robots.txt         → 200
  │     GET /.DS_Store          → 404
  │     GET /wp-config.php      → 404
  │
  ├── cors_misconfiguration
  │     GET / with Origin: https://evil.com
  │     → Check Access-Control-Allow-Origin header
  │     → Reflected "evil.com"? ← CORS MISCONFIGURATION!
  │
  ├── default_credentials
  │     POST /login with admin:admin      → 401
  │     POST /login with admin:password   → 401
  │     POST /login with root:root        → 200 ← DEFAULT CREDS!
  │
  ├── graphql_scan
  │     POST /graphql with introspection query
  │     → Schema returned? ← INTROSPECTION ENABLED!
  │
  └── http_request_smuggling
        CL.TE and TE.CL desync probes

Request #2-500 arrive for example.com
  └── Host already seen → all ScanScopeHost modules SKIPPED
```

**Typical vulnerabilities found:**
- CORS misconfiguration
- Default credentials
- GraphQL introspection enabled
- HTTP request smuggling
- Sensitive file discovery (`.env`, `.git/config`, `robots.txt`)
- Missing security headers

**Active modules using this scope (5):**
`cors_misconfiguration`, `default_credentials`, `graphql_scan`, `http_request_smuggling`, `sensitive_file_discovery`

**Passive modules using this scope (1):**
`security_headers_missing`

---

## Hybrid Scope

A module can declare multiple scopes. Currently, **`oast_probe`** is the only module that does this:

```go
ScanScopeRequest | ScanScopeInsertionPoint
```

This means it runs in both modes for maximum coverage:

```
Request: POST /api/webhook?url=https://example.com HTTP/1.1
         Host: target.com
         X-Callback: https://app.internal

─── As ScanScopeInsertionPoint ───

  Insertion Point #1: url=https://example.com (URL_PARAM)
    → url=https://<oast-callback-id>.oast.vigolium.io
    → Wait for DNS/HTTP callback...

  Insertion Point #2: X-Callback (HEADER)
    → X-Callback: https://<oast-callback-id>.oast.vigolium.io
    → Wait for DNS/HTTP callback...

─── As ScanScopeRequest ───

  Replace Host header:
    → Host: <oast-callback-id>.oast.vigolium.io
    → Wait for DNS/HTTP callback...

  Add Referer header:
    → Referer: https://<oast-callback-id>.oast.vigolium.io
    → Wait for DNS/HTTP callback...
```

OAST callbacks can trigger from either parameter-level vectors (SSRF via URL param) or request-level vectors (blind SSRF via Host header), so it needs both scopes.

---

## What Happens With Different Inputs

### Full request with parameters

```http
POST /api/login?ref=home HTTP/1.1
Host: example.com
Cookie: lang=en
Content-Type: application/json

{"username":"admin","password":"secret"}
```

```
┌──────────────────┬──────────────────────────────────────────────────────────┐
│ Scope            │ What happens                                            │
├──────────────────┼──────────────────────────────────────────────────────────┤
│ InsertionPoint   │ 5 insertion points found:                               │
│                  │   1. ref=home           (URL_PARAM)                     │
│                  │   2. lang=en            (COOKIE)                        │
│                  │   3. username=admin     (JSON_PARAM)                    │
│                  │   4. password=secret    (JSON_PARAM)                    │
│                  │   5. Host=example.com   (HEADER)                        │
│                  │ Each tested by all compatible modules (SQLi, SSTI, …)   │
├──────────────────┼──────────────────────────────────────────────────────────┤
│ Request          │ Full request handed to each module. Tests:              │
│                  │   - Method tampering (POST → PUT, DELETE)               │
│                  │   - JWT in headers? Algorithm confusion                 │
│                  │   - CSRF token present? Try removing it                 │
│                  │   - Host header reflection                              │
├──────────────────┼──────────────────────────────────────────────────────────┤
│ Host             │ First time seeing example.com?                          │
│                  │   YES → sensitive file probe, CORS check, etc.          │
│                  │   NO  → skipped entirely                                │
└──────────────────┴──────────────────────────────────────────────────────────┘
```

### Simple URL with no parameters

```http
GET /admin HTTP/1.1
Host: example.com
```

```
┌──────────────────┬──────────────────────────────────────────────────────────┐
│ Scope            │ What happens                                            │
├──────────────────┼──────────────────────────────────────────────────────────┤
│ InsertionPoint   │ CreateAllInsertionPoints returns EMPTY list.            │
│                  │ No query params, no body, no cookies.                   │
│                  │ *** ALL insertion-point modules are SKIPPED ***         │
│                  │ No SQLi, XSS, SSTI, or injection testing occurs.       │
├──────────────────┼──────────────────────────────────────────────────────────┤
│ Request          │ Modules still run:                                      │
│                  │   - forbidden_bypass: response is 403?                  │
│                  │     Try /./admin, /admin..;/, PUT /admin                │
│                  │   - host_header_injection: swap Host header             │
│                  │   - path_normalization: /admin vs /Admin vs /ADMIN      │
│                  │   - sensitive files, swagger discovery, etc.            │
├──────────────────┼──────────────────────────────────────────────────────────┤
│ Host             │ Same as above — runs once if host is new.              │
└──────────────────┴──────────────────────────────────────────────────────────┘
```

### Static file URL

```http
GET /assets/style.css HTTP/1.1
Host: example.com
```

```
┌──────────────────┬──────────────────────────────────────────────────────────┐
│ Scope            │ What happens                                            │
├──────────────────┼──────────────────────────────────────────────────────────┤
│ InsertionPoint   │ Empty insertion point list. Skipped.                    │
├──────────────────┼──────────────────────────────────────────────────────────┤
│ Request          │ Active: most modules skip via CanProcess() — the       │
│                  │   default filters out .css/.js/.png/.jpg extensions.    │
│                  │ Passive: still runs — e.g. secret_detect checks for    │
│                  │   leaked API keys, sourcemap_detect looks for .map     │
│                  │   references in JS bundles.                             │
├──────────────────┼──────────────────────────────────────────────────────────┤
│ Host             │ Runs once if host is new.                              │
└──────────────────┴──────────────────────────────────────────────────────────┘
```

### URL with path parameters only (REST-style)

```http
GET /api/users/42/profile HTTP/1.1
Host: example.com
```

```
┌──────────────────┬──────────────────────────────────────────────────────────┐
│ Scope            │ What happens                                            │
├──────────────────┼──────────────────────────────────────────────────────────┤
│ InsertionPoint   │ Path segments extracted as insertion points:            │
│                  │   1. "42"      (PATH_FOLDER)                           │
│                  │   2. "profile" (PATH_FILENAME)                         │
│                  │ Modules accepting path types will test these:           │
│                  │   lfi_generic   → /api/users/../../etc/passwd/profile   │
│                  │   ssti_detection → /api/users/{{7*7}}/profile           │
│                  │   sqli_error    → /api/users/' OR 1=1--/profile         │
├──────────────────┼──────────────────────────────────────────────────────────┤
│ Request          │ Runs normally:                                          │
│                  │   - path_normalization: /api/users/42/../42/profile     │
│                  │   - forbidden_bypass: if 403, try path tricks           │
│                  │   - host_header_injection: test header reflection       │
├──────────────────┼──────────────────────────────────────────────────────────┤
│ Host             │ Runs once if host is new.                              │
└──────────────────┴──────────────────────────────────────────────────────────┘
```

### JSON API with nested structures

```http
POST /api/graphql HTTP/1.1
Host: example.com
Content-Type: application/json

{"query":"{ user(id: 1) { name } }","variables":{"token":"eyJhbGci..."}}
```

```
┌──────────────────┬──────────────────────────────────────────────────────────┐
│ Scope            │ What happens                                            │
├──────────────────┼──────────────────────────────────────────────────────────┤
│ InsertionPoint   │ JSON values extracted as insertion points:              │
│                  │   1. query = "{ user(id: 1)…"  (JSON_PARAM)            │
│                  │   2. token = "eyJhbGci..."      (JSON_PARAM)           │
│                  │ With includeNested=true, the executor also detects     │
│                  │   that "token" contains a Base64/JWT value and creates  │
│                  │   nested insertion points inside it.                    │
├──────────────────┼──────────────────────────────────────────────────────────┤
│ Request          │   - jwt_vulnerability: detects JWT in body, tries      │
│                  │     algorithm confusion and weak key attacks            │
│                  │   - xxe_generic: if Content-Type were XML, test XXE    │
│                  │   - prototype_pollution: inject __proto__ in JSON      │
├──────────────────┼──────────────────────────────────────────────────────────┤
│ Host             │ graphql_scan runs once: introspection query,           │
│                  │   batching abuse, field suggestion enumeration          │
└──────────────────┴──────────────────────────────────────────────────────────┘
```

---

## Execution Order

For each incoming request, the executor runs scopes in this order:

```
HttpRequestResponse arrives
│
├── Phase 1: Passive modules (no network I/O — sequential)
│   │
│   ├── 1. ScanScopeHost     →  security_headers_missing (once per host)
│   │
│   └── 2. ScanScopeRequest  →  secret_detect, cookie_security_detect,
│                                cors_headers_detect, info_disclosure_detect,
│                                dom_xss_detect, csrf_detect, ...
│
├── Phase 2: Active modules (network I/O — all three run in parallel)
│   │
│   ├── 3a. ScanScopeHost
│   │       cors_misconfiguration, default_credentials, ...
│   │       (runs only if host not seen before)
│   │
│   ├── 3b. ScanScopeRequest                ─┐
│   │       forbidden_bypass,                 │
│   │       host_header_injection,            ├── all three scope
│   │       jwt_vulnerability, ...            │   categories run
│   │                                         │   CONCURRENTLY
│   └── 3c. ScanScopeInsertionPoint          ─┘
│           for each param:
│             sqli_error_based,
│             ssti_detection,
│             lfi_generic, ...
│
└── Phase 3: Wait for all active modules to finish
             Collect ResultEvent findings
```

Passive modules run first (sequentially, since they do no network I/O), then all three active scope categories run concurrently.

---

## Choosing a Scope for New Modules

| Question | Recommended Scope |
|----------|------------------|
| Does the vulnerability live in a specific parameter value? | `ScanScopeInsertionPoint` |
| Does it require modifying the request structure (method, path, headers)? | `ScanScopeRequest` |
| Does it need custom parameter iteration logic? | `ScanScopeRequest` |
| Is it a one-time check per target host? | `ScanScopeHost` |
| Does it need both parameter-level and request-level testing? | Combine with `\|` (e.g., `ScanScopeRequest \| ScanScopeInsertionPoint`) |

The scope is set in the module constructor:

```go
func New() *Module {
    return &Module{
        BaseActiveModule: modkit.NewBaseActiveModule(
            ModuleID, ModuleName, ModuleDesc, ModuleShort,
            ModuleConfirmation, ModuleSeverity, ModuleConfidence,
            modkit.ScanScopeInsertionPoint,    // <-- scope goes here
            modkit.AllInsertionPointTypes,
        ),
    }
}
```
