---
id: swarm-source-format
name: Format Source Analysis Results (Routes + Auth)
description: Convert route and auth analysis notes into JSONL HTTP records and session config JSON
output_schema: source_analysis
variables:
  - TargetURL
  - Hostname
---

You previously analyzed the application source code and documented:
- **Part 1**: Application routes (non-auth)
- **Part 2**: Authentication routes (login/register/auth endpoints)
- **Part 3**: Credentials, roles, and session mechanisms

Now convert your findings into the required structured format.

## Output Format

Your output has **two parts** in a single response:

### Part 1: HTTP Records (JSONL)

Output **all routes** (both application routes from Part 1 AND auth routes from Part 2) as **JSONL** (one JSON object per line) wrapped in a ` ```jsonl ` fenced code block. Each line is a standalone HTTP record.

```jsonl
{"method":"POST","url":"{{.TargetURL}}/api/login","headers":{"Content-Type":"application/json"},"body":"{\"email\":\"admin@test.com\",\"password\":\"admin123\"}","notes":"Login endpoint — returns JWT token"}
{"method":"GET","url":"{{.TargetURL}}/api/products?q=test&page=1","headers":{},"notes":"List products — uses raw SQL query (sqli sink)"}
{"method":"POST","url":"{{.TargetURL}}/api/endpoint","headers":{"Content-Type":"application/json"},"body":"{\"param\":\"value\",\"name\":\"test\"}","notes":"Description of endpoint and relevant sinks"}
{"method":"PUT","url":"{{.TargetURL}}/api/users/1","headers":{"Content-Type":"application/json"},"body":"{\"name\":\"test\",\"email\":\"user@test.com\"}","notes":"Update user by ID — requires auth"}
{"method":"DELETE","url":"{{.TargetURL}}/api/items/1?force=true","headers":{},"notes":"Delete item — admin only"}
```

### Part 2: Session Config (JSON)

Output a JSON object wrapped in a ` ```json ` code block containing the `session_config`. **Create one session entry per role/credential found in the analysis.** The highest-privilege account should be `"primary"` (used for scanning), and lower-privilege accounts should be `"compare"` (used for authorization/IDOR testing).

**Multi-role example (this is the expected pattern when multiple roles exist):**

```json
{"http_records":[],"session_config":{"sessions":[{"name":"admin","role":"primary","login":{"url":"{{.TargetURL}}/api/login","method":"POST","content_type":"application/json","body":"{\"email\":\"admin@juice-sh.op\",\"password\":\"admin123\"}","extract":[{"source":"json","path":"$.authentication.token","apply_as":"Authorization: Bearer {value}"}]}},{"name":"regular_user","role":"compare","login":{"url":"{{.TargetURL}}/api/login","method":"POST","content_type":"application/json","body":"{\"email\":\"jim@juice-sh.op\",\"password\":\"ncc-1701\"}","extract":[{"source":"json","path":"$.authentication.token","apply_as":"Authorization: Bearer {value}"}]}}]}}
```

#### Session Entry Fields

- `name`: Descriptive role name (e.g., `"admin"`, `"regular_user"`, `"api_service"`, `"accountant"`)
- `role`: Session role for the scanner:
  - `"primary"` — highest-privilege account, used as the main scanning session. **Only one session should be primary.**
  - `"compare"` — lower-privilege accounts, used to replay requests and detect authorization flaws (IDOR, privilege escalation). **Create one compare session per additional role.**
- `headers`: Static auth headers if applicable (e.g., API key: `{"X-API-Key": "abc123"}`)
- `login`: Login flow definition (omit if using static headers):
  - `url`: Full login URL (use `{{.TargetURL}}` as base)
  - `method`: HTTP method (usually POST)
  - `content_type`: Content-Type header value
  - `body`: Request body with the **actual credentials found in the source code**
  - `extract`: Rules for extracting tokens from the login response:
    - `source`: `"json"`, `"cookie"`, or `"header"`
    - `path`: JSONPath for json source (e.g., `$.authentication.token`, `$.access_token`)
    - `name`: Cookie or header name (for cookie/header sources)
    - `apply_as`: How to attach the token to subsequent requests (e.g., `"Authorization: Bearer {value}"`, `"Cookie: session={value}"`)

#### Multi-Role Guidelines

- **Always create multiple sessions when multiple roles/credentials were found** — this enables authorization testing
- **Primary = highest privilege**: admin or superuser account should be primary (scans with maximum access)
- **Compare = each other role**: regular user, guest, service account, etc. — each gets its own compare session
- **Use real credentials from the source code** (seed data, defaults, test fixtures) — not placeholder values
- If only one credential was found, make it `"primary"` with no compare sessions
- If auth uses static API keys/tokens instead of login flows, use `"headers"` instead of `"login"`

**Rules:**
- `session_config` is required — include at least one session if any auth was found
- If no authentication was found, output `{"http_records":[],"session_config":{"sessions":[]}}`
- Use the target URL `{{.TargetURL}}` as base for login URLs

## OUTPUT REMINDER — Read This Last

Before writing your response, verify against these rules:

1. **JSONL block** → ` ```jsonl ` (NOT ` ```json `). One JSON object per line. No JSON array wrapper.
2. **JSON block** → ` ```json ` block containing session config.
3. **Body fields** → MUST be **escaped JSON strings**, NOT nested objects.
   - CORRECT: `"body":"{\"email\":\"a@b.com\",\"password\":\"test\"}"`
   - WRONG:   `"body":{"email":"a@b.com","password":"test"}`
4. **Every POST/PUT/PATCH** route MUST have a non-empty `body` with all parameters from the handler code.
5. **Every GET/DELETE** route MUST have query parameters in the URL string (e.g., `?q=test&page=1`).
6. **extract rules** → Each must have `source`, `path` (for json) or `name` (for cookie/header), and `apply_as`.
7. Each line/block must be **valid, parseable JSON** — no trailing commas, no comments.
8. **Multiple roles** → If the analysis found multiple credential/role pairs, there MUST be multiple session entries (one primary + one compare per additional role).
