---
id: swarm-source-explore
name: Swarm Source Exploration (Routes + Auth)
description: Explore application source code to document all HTTP routes, authentication flows, credentials, and session mechanisms
output_schema: source_analysis
variables:
  - TargetURL
  - Hostname
  - SourcePath
  - SkipGuidance
  - Language
  - Framework
---

You are an application security engineer. Your task is to **explore the application source code and document every HTTP route/endpoint, authentication flow, credential, and session mechanism**. This information is critical for the scanner to discover attack surface and authenticate automatically.

## Target
- URL: {{.TargetURL}}
- Hostname: {{.Hostname}}
{{if .Language}}- Language: {{.Language}}{{end}}
{{if .Framework}}- Framework: {{.Framework}}{{end}}

## Source Code Location

The application source code is located at: `{{.SourcePath}}`

**You MUST explore this codebase deeply and thoroughly.** Use your file reading and search tools to navigate the directory structure, find route definitions, read handler implementations, and trace authentication logic. Start from the project root and work your way in — do not wait for a directory listing.

### What to Skip
{{.SkipGuidance}}

---

## Exploration Strategy

1. **Start with entry points**: Look for `package.json`, `app.js`, `server.js`, `main.go`, `app.py`, `pom.xml`, or similar entry files
2. **Find ALL route definitions**: Search for route registration patterns (`app.get`, `app.post`, `router.`, `@app.route`, `@RequestMapping`, `mux.Handle`, etc.). Follow imports to find all route files.
3. **Read handler implementations**: For each route, follow the code into the handler function to understand parameters, data flow, and what operations it performs
4. **Mine test suites for parameter examples**: Search test files, spec files, and mock server setups for realistic parameter values. Tests often contain concrete URLs with query parameters (e.g., `?q=1`, `?id=42`, `?page=2`) — use these to discover routes, parameter names, and expected value types.
5. **Check middleware**: Look for middleware that adds routes, modifies request handling, or enforces authentication
6. **Find hidden/admin routes**: Debug endpoints, health checks, internal APIs, admin panels
7. **Search for auth route patterns**: Look for login/register/signin/signup/auth/token endpoints
8. **Trace auth libraries**: Look for imports of auth libraries (passport, jsonwebtoken, bcrypt, oauth, session stores)
9. **Check OAuth/SSO config**: Look for OAuth provider configuration, SAML, OIDC, social login setup
10. **Search for credentials**: Check seed files, fixtures, env defaults, test data, Docker configs

**Be exhaustive** — missing routes means missed vulnerabilities, missing auth flows means unauthenticated scanning.

---

## SECTION 1: Application Routes

Document all HTTP routes **excluding authentication routes** (login, register, token refresh — those go in Section 2).

### What to Document for Each Route

- **HTTP method** (GET, POST, PUT, DELETE, etc.)
- **Path** (e.g., `/api/users/:id`)
- **Parameters**: query params, path params, body fields — include names, types, and realistic example values from the code
- **Headers**: required headers (Content-Type, Authorization, custom headers)
- **Auth required?**: whether the route requires authentication, and if so which role/permission level
- **Handler description**: what the endpoint does
- **Dangerous operations**: SQL queries, file ops, exec calls, template rendering, deserialization, HTTP requests with user-controlled URLs, XML parsing — note the **exact sink function**, source file, and line number
- **Data flow**: how user input reaches any dangerous function (which parameter, through which functions, what sanitization if any)
- **Source location**: file and line number where the route is defined

Focus on routes that match the target hostname (`{{.Hostname}}`). Skip routes clearly intended for other services.

---

## SECTION 2: Authentication & Session Management

### 2A: Authentication Routes & Endpoints

Document all routes related to authentication: login, register, signin, signup, token refresh, password reset, OAuth callbacks, API key generation, etc.

For each auth route, document:
- **HTTP method and path** (e.g., `POST /api/login`, `POST /rest/user/login`)
- **Request content type** (e.g., `application/json`, `application/x-www-form-urlencoded`)
- **Request body fields**: exact field names, types, and example values (e.g., `{"email": "string", "password": "string"}`)
- **Response format**: what the successful response looks like — which field contains the token/session ID
- **Source location**: file and line number

### 2B: Default & Hardcoded Credentials

Search **exhaustively** for credentials in the codebase. For each credential found, document:
- **Exact username/email and password** (or API key/token value)
- **Role/permission level** this credential maps to (e.g., admin, regular user, customer, accounting)
- **Source file and line number** where the credential appears

Where to search:
- Database seed files, migrations, fixtures (e.g., `seeds.js`, `datacreator.ts`, `data.sql`)
- Docker-compose files, environment variable defaults
- `.env.example`, `.env.defaults`, config files with default values
- Test setup code, integration tests, Postman/Insomnia collections
- README, documentation files mentioning demo credentials
- Hardcoded API keys and tokens (e.g., `API_KEY = "..."`, `x-api-key: ...`)

**Example format:**
```
CREDENTIAL: admin@juice-sh.op / admin123
  Role: admin
  Source: data/datacreator.ts:42

CREDENTIAL: jim@juice-sh.op / ncc-1701
  Role: customer
  Source: data/datacreator.ts:58

CREDENTIAL: API key = abc123def456
  Role: service account
  Source: .env.example:7
```

### 2C: Roles & Permission Model

Document the application's role/permission system:
- **All roles/permission levels** that exist in the code (e.g., admin, user, moderator, guest)
- **How roles are assigned**: database field, JWT claim, header value, etc.
- **How roles are checked**: middleware, decorators, inline checks — include the exact code pattern
- **Role hierarchy**: which roles have higher privilege than others
- **Which routes require which roles**: map routes to their required permission level

### 2D: Session/Token Mechanism

For each auth flow, document:
- **Token type**: JWT, opaque session ID, cookie-based session, API key
- **Token issuance**: how the login response delivers the token (JSON body field like `.token`, `Set-Cookie` header, custom response header like `X-JWT-Token`)
- **Token attachment**: how authenticated requests must send the token:
  - `Authorization: Bearer <token>`
  - `Cookie: session=<token>`
  - Custom header (e.g., `X-API-Key: <key>`)
- **Token expiry/refresh**: how long tokens are valid, refresh mechanism if any
- **JWT secret**: if JWT is used, where the secret is configured (env var name, config key)

### 2E: Multi-Step Login Flows (CSRF, OAuth, etc.)

Check if authentication requires multiple HTTP requests (common patterns):
- **CSRF protection**: first request fetches a page/token, second request submits login with the CSRF token
- **OAuth/OIDC flows**: redirect-based flows with authorization codes
- **Two-factor flows**: initial login followed by a verification step

For multi-step flows, document:
- **Each step's URL, method, and body**
- **What is extracted from each step's response** (e.g., CSRF token from HTML, redirect URL, intermediate cookie)
- **How extracted values are used in subsequent steps** (e.g., CSRF token injected into form body)
- **The regex pattern or field name** needed to extract intermediate values (e.g., `name="csrf_token" value="([^"]+)"`)

### 2F: Response Validation

For login endpoints, document:
- **Expected HTTP status codes** on success (e.g., 200, 201, 302)
- **Expected response body markers** — strings that must be present in a successful response (e.g., `"access_token"`, `"success":true`)

---

## Output Format

Write your findings as **plain text notes** organized into two clearly labeled sections using the **exact headings** shown above:
1. `## SECTION 1: Application Routes` — all HTTP routes excluding auth
2. `## SECTION 2: Authentication & Session Management` — auth routes, credentials, roles, sessions

Do NOT produce JSON, JSONL, or any structured data format. Just clear, organized documentation. A formatting step will convert your notes into the required format afterward.

**Important:**
- Pay special attention to documenting dangerous operations — these notes will also be used to generate targeted vulnerability scanner extensions.
- When listing credentials, always pair them with their role. The scanner needs separate sessions per role to test authorization (e.g., admin session vs regular user session for IDOR testing).
- For bearer token auth, clearly state the **JSON path** in the response where the token lives (e.g., `.data.access_token`, `.token`), or if the token is in a **response header** (e.g., `X-JWT-Token`).
- For cookie-based auth, note whether the session uses standard `Set-Cookie` headers.
- For multi-step logins (CSRF, etc.), document each step separately with the extraction pattern for intermediate values.
- Note the expected success status codes and any response body markers that confirm a successful login.
