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

**Bearer token example (preferred shorthand — use this when the login returns a JSON token):**

```json
{"http_records":[],"session_config":{"sessions":[{"name":"admin","role":"primary","login":{"url":"{{.TargetURL}}/api/login","method":"POST","body":"{\"email\":\"admin@juice-sh.op\",\"password\":\"admin123\"}","type":"bearer","token_path":".authentication.token","expect":{"status":[200]}}},{"name":"regular_user","role":"compare","login":{"url":"{{.TargetURL}}/api/login","method":"POST","body":"{\"email\":\"jim@juice-sh.op\",\"password\":\"ncc-1701\"}","type":"bearer","token_path":".authentication.token"}}]}}
```

**Cookie-based example (use when the app uses session cookies):**

```json
{"http_records":[],"session_config":{"sessions":[{"name":"admin","role":"primary","login":{"url":"{{.TargetURL}}/login","method":"POST","content_type":"application/x-www-form-urlencoded","body":"username=admin&password=admin123","type":"cookie"}},{"name":"regular_user","role":"compare","login":{"url":"{{.TargetURL}}/login","method":"POST","content_type":"application/x-www-form-urlencoded","body":"username=user1&password=pass123","type":"cookie"}}]}}
```

**Multi-step login example (CSRF token + form login):**

```json
{"http_records":[],"session_config":{"sessions":[{"name":"csrf_user","role":"primary","login":{"steps":[{"url":"{{.TargetURL}}/login","method":"GET","extract":[{"source":"regex","pattern":"name=\"csrf_token\" value=\"([^\"]+)\"","apply_as":"var:csrf"}]},{"url":"{{.TargetURL}}/login","method":"POST","content_type":"application/x-www-form-urlencoded","body":"username=admin&password=admin123&csrf_token={csrf}","extract":[{"source":"cookie"}]}]}}]}}
```

### Session Entry Fields

- `name`: Descriptive role name (e.g., `"admin"`, `"regular_user"`, `"api_service"`, `"accountant"`)
- `role`: Session role for the scanner:
  - `"primary"` — highest-privilege account, used as the main scanning session. **Only one session should be primary.**
  - `"compare"` — lower-privilege accounts, used to replay requests and detect authorization flaws (IDOR, privilege escalation). **Create one compare session per additional role.**
- `headers`: Static auth headers if applicable (e.g., API key: `{"X-API-Key": "abc123"}`)
- `login`: Login flow definition (omit if using static headers). Two styles:

#### Style 1: Type Shorthand (preferred for simple login flows)

Use `type` + `token_path` instead of explicit `extract` rules:
- `url`: Full login URL (use `{{.TargetURL}}` as base)
- `method`: HTTP method (usually POST)
- `content_type`: Content-Type header (omit for JSON bodies — auto-detected)
- `body`: Request body with the **actual credentials found in the source code**
- `type`: Auth type shorthand:
  - `"bearer"` — extracts a token from the JSON response and sets `Authorization: Bearer <token>`. Requires `token_path`.
  - `"cookie"` — captures all `Set-Cookie` headers from the response. No `token_path` needed.
- `token_path`: Where to find the token (only for `type: "bearer"`):
  - JSON body path: `".token"`, `".data.access_token"`, `".authentication.token"` (dot-notation, leading `$.` or `.` are both accepted)
  - Response header: `"header:X-JWT-Token"` — extracts from a named response header
- `expect`: Optional response validation:
  - `status`: Array of acceptable HTTP status codes (e.g., `[200]`, `[200, 201]`)
  - `body_contains`: String that must appear in the response body (e.g., `"access_token"`)

#### Style 2: Explicit Extract Rules (for advanced/non-standard flows)

Use `extract` rules when the shorthand doesn't fit:
- `extract`: Array of extraction rules:
  - `source`: `"json"`, `"cookie"`, `"header"`, or `"regex"`
  - `path`: Dot-notation JSON path (for `"json"` source, e.g., `.authentication.token`)
  - `name`: Cookie or header name (for `"cookie"`/`"header"` sources)
  - `pattern`: Regex pattern with capture group (for `"regex"` source, e.g., `token="([^"]+)"`)
  - `apply_as`: How to set the extracted value as a header (e.g., `"Authorization: Bearer {value}"`)

#### Style 3: Multi-Step Login (for CSRF, OAuth, or multi-request flows)

Use `steps` when login requires multiple HTTP requests:
- `steps`: Array of login steps executed in sequence. Each step has:
  - `url`, `method`, `content_type`, `body`: Same as single-step login
  - `extract`: Extract rules for this step. Use `"apply_as": "var:varname"` to store a value as a variable for use in subsequent steps (referenced as `{varname}` in URL/body)
  - `expect`: Optional response validation for this step
- Variables extracted in step N are available as `{varname}` placeholders in step N+1's URL and body
- The last step's extract rules set the final session credentials

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
- **Prefer type shorthand** (`type`/`token_path`) over explicit `extract` rules when possible — it's simpler and less error-prone

## OUTPUT REMINDER — Read This Last

Before writing your response, verify against these rules:

1. **JSON block** → ` ```json ` block containing session config with `{"http_records":[],"session_config":{...}}` wrapper.
2. **Body fields** → MUST be **escaped JSON strings**, NOT nested objects.
   - CORRECT: `"body":"{\"email\":\"a@b.com\",\"password\":\"test\"}"`
   - WRONG:   `"body":{"email":"a@b.com","password":"test"}`
3. **Type shorthand** → Use `"type":"bearer"` + `"token_path"` for bearer auth, `"type":"cookie"` for cookie auth. Do NOT combine `type` with `extract`.
4. **token_path format** → Use dot-notation (`.token`, `.data.access_token`) or `"header:HeaderName"`. NOT JSONPath `$` prefix.
5. **content_type** → Omit for JSON bodies (auto-detected). Only set explicitly for `application/x-www-form-urlencoded` or other non-JSON types.
6. **Multi-step** → Use `"steps"` array. Intermediate values use `"apply_as":"var:name"`, referenced as `{name}` in later steps.
7. Each block must be **valid, parseable JSON** — no trailing commas, no comments.
8. **Multiple roles** → If the analysis found multiple credential/role pairs, there MUST be multiple session entries (one primary + one compare per additional role).
