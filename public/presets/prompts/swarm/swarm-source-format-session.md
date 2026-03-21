---
id: swarm-source-format-session
name: Format Session Analysis Results
description: Convert auth and session analysis notes into session config JSON
output_schema: source_analysis
variables:
  - TargetURL
  - Hostname
---

You are given notes from a source code analysis documenting authentication routes, credentials, roles, and session mechanisms. Convert these notes into a structured session configuration.

## Output Format

Output a JSON object wrapped in a ` ```json ` code block containing the `session_config`. **Create one session entry per role/credential found in the analysis.** The highest-privilege account should be `"primary"` (used for scanning), and lower-privilege accounts should be `"compare"` (used for authorization/IDOR testing).

**Multi-role example (this is the expected pattern when multiple roles exist):**

```json
{"http_records":[],"session_config":{"sessions":[{"name":"admin","role":"primary","login":{"url":"{{.TargetURL}}/api/login","method":"POST","content_type":"application/json","body":"{\"email\":\"admin@juice-sh.op\",\"password\":\"admin123\"}","extract":[{"source":"json","path":"$.authentication.token","apply_as":"Authorization: Bearer {value}"}]}},{"name":"regular_user","role":"compare","login":{"url":"{{.TargetURL}}/api/login","method":"POST","content_type":"application/json","body":"{\"email\":\"jim@juice-sh.op\",\"password\":\"ncc-1701\"}","extract":[{"source":"json","path":"$.authentication.token","apply_as":"Authorization: Bearer {value}"}]}}]}}
```

### Session Entry Fields

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

### Multi-Role Guidelines

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

1. **JSON block** → ` ```json ` block containing session config with `{"http_records":[],"session_config":{...}}` wrapper.
2. **Body fields** → MUST be **escaped JSON strings**, NOT nested objects.
   - CORRECT: `"body":"{\"email\":\"a@b.com\",\"password\":\"test\"}"`
   - WRONG:   `"body":{"email":"a@b.com","password":"test"}`
3. **extract rules** → Each must have `source`, `path` (for json) or `name` (for cookie/header), and `apply_as`.
4. Each block must be **valid, parseable JSON** — no trailing commas, no comments.
5. **Multiple roles** → If the analysis found multiple credential/role pairs, there MUST be multiple session entries (one primary + one compare per additional role).
