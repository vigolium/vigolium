---
id: swarm-source-explore
name: Swarm Source Exploration (Routes + Auth)
description: Explore application source code to document all HTTP routes and authentication flows
output_schema: source_analysis
variables:
  - TargetURL
  - Hostname
  - SourcePath
  - DirectoryTree
  - Language
  - Framework
---

You are an application security engineer. Your task is to **explore the application source code and document every HTTP route/endpoint AND every authentication flow**. Write your findings as organized notes — do NOT produce JSON or JSONL yet.

## Target
- URL: {{.TargetURL}}
- Hostname: {{.Hostname}}
{{if .Language}}- Language: {{.Language}}{{end}}
{{if .Framework}}- Framework: {{.Framework}}{{end}}

## Source Code Location

The application source code is located at: `{{.SourcePath}}`

**You MUST explore this codebase deeply and thoroughly.** Read files, search for patterns, and navigate the directory structure. Do not rely only on the tree listing below — actually open and read every relevant source file.

### Directory Structure
```
{{.DirectoryTree}}
```

---

## PART 1: Application Routes (Non-Auth)

Document all routes that are NOT login/register/auth endpoints. Auth-related routes go in Part 2.

### Exploration Strategy

1. **Start with entry points**: Look for `package.json`, `app.js`, `server.js`, `main.go`, `app.py`, `pom.xml`, or similar entry files
2. **Find ALL route definitions**: Search for route registration patterns (`app.get`, `app.post`, `router.`, `@app.route`, `@RequestMapping`, `mux.Handle`, etc.). Follow imports to find all route files.
3. **Read handler implementations**: For each route, follow the code into the handler function to understand parameters, data flow, and what operations it performs
4. **Mine test suites for parameter examples**: Search test files, spec files, and mock server setups for realistic parameter values. Tests often contain concrete URLs with query parameters (e.g., `?q=1`, `?id=42`, `?page=2`) — use these to discover routes, parameter names, and expected value types.
5. **Check middleware**: Look for middleware that adds routes or modifies request handling
6. **Find hidden/admin routes**: Debug endpoints, health checks, internal APIs, admin panels

**Be exhaustive** — missing routes means missed vulnerabilities.

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

**Do NOT include login, register, signin, signup, token refresh, or password reset routes here** — those belong in Part 2.

---

## PART 2: Authentication Routes & Endpoints

Document all routes related to authentication: login, register, signin, signup, token refresh, password reset, OAuth callbacks, API key generation, etc.

### What to Document for Each Auth Route

- **HTTP method and path** (e.g., `POST /api/login`, `POST /rest/user/login`)
- **Request content type** (e.g., `application/json`, `application/x-www-form-urlencoded`)
- **Request body fields**: exact field names, types, and example values (e.g., `{"email": "string", "password": "string"}`)
- **Response format**: what the successful response looks like — which field contains the token/session ID
- **Source location**: file and line number

---

## PART 3: Credentials, Roles & Session Management

This section is **critical** for the scanner to authenticate automatically. Document every credential, role, and session mechanism you find.

### 3A: Default & Hardcoded Credentials

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

CREDENTIAL: accountant@juice-sh.op / i am]teleporting
  Role: accounting
  Source: data/datacreator.ts:95

CREDENTIAL: API key = abc123def456
  Role: service account
  Source: .env.example:7
```

### 3B: Roles & Permission Model

Document the application's role/permission system:
- **All roles/permission levels** that exist in the code (e.g., admin, user, moderator, guest)
- **How roles are assigned**: database field, JWT claim, header value, etc.
- **How roles are checked**: middleware, decorators, inline checks — include the exact code pattern
- **Role hierarchy**: which roles have higher privilege than others
- **Which routes require which roles**: map routes to their required permission level

### 3C: Session/Token Mechanism

For each auth flow, document:
- **Token type**: JWT, opaque session ID, cookie-based session, API key
- **Token issuance**: how the login response delivers the token (JSON body field like `$.token`, `Set-Cookie` header, custom header)
- **Token attachment**: how authenticated requests must send the token:
  - `Authorization: Bearer <token>`
  - `Cookie: session=<token>`
  - Custom header (e.g., `X-API-Key: <key>`)
- **Token expiry/refresh**: how long tokens are valid, refresh mechanism if any
- **JWT secret**: if JWT is used, where the secret is configured (env var name, config key)

---

## Output Format

Write your findings as **plain text notes** organized into three clearly labeled sections:
1. **PART 1: Application Routes** — non-auth routes only
2. **PART 2: Authentication Routes** — login/register/auth endpoints only
3. **PART 3: Credentials, Roles & Sessions** — credentials per role, permission model, token mechanism

Do NOT produce JSON, JSONL, or any structured data format. Just clear, organized documentation. A formatting step will convert your notes into the required format afterward.

For routes, pay special attention to documenting dangerous operations — these notes will also be used to generate targeted vulnerability scanner extensions.

**Important:** When listing credentials, always pair them with their role. The scanner needs separate sessions per role to test authorization (e.g., admin session vs regular user session for IDOR testing).
