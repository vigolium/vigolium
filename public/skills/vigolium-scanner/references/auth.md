# Session / Auth Configuration

> **Related:** [scanning.md](scanning.md) for where `--auth-file` applies · [agent-modes.md](agent-modes.md) for agent-generated sessions · [cookies.md](cookies.md) to borrow a session the local browser already holds

## Before writing a login config

If the operator's own browser is already signed in to the target, `vigolium kit
cookies app.target.example --with-storage --as playwright -o state.json` takes
that session (also a curl jar or a `Cookie:` header) with no credential, MFA
prompt or flow to maintain — for your own tooling as well as vigolium's. Load
the file; under a coding agent the values never reach the transcript. See
[cookies.md](cookies.md). Prefer a scripted session config when the scan must
**re-authenticate**: a borrowed cookie expires and cannot be renewed, while a
`login:` block logs in again mid-scan.

Session configuration enables authenticated scanning across all agent modes and standalone scans. Pipeline Phase 0 (source analysis) can auto-generate this configuration, or it can be provided manually via the repeatable `--auth-file` and `--auth` flags.

| Flag | Accepts | Repeatable |
|------|---------|------------|
| `--auth-file <path>` | YAML/JSON file (single session **or** `sessions:` bundle), or a bare name resolved against `scanning_strategy.session.session_dir` | yes |
| `--auth <name:Header:value>` | Inline session — name and header injected as static headers | yes |

Both work on `scan`, `run`, `scan-url` and `scan-request` (one definition, aliases `--session` / `--session-file`). On `scan-url` / `scan-request` they route the request through the runner, which hydrates the session; a header also given with `-H` keeps the `-H` value.

## Session Config Format

Session configs can be written in **YAML or JSON** — the format is auto-detected by file extension or content sniffing.

**YAML:**

```yaml
sessions:
  - name: default_user
    role: primary        # "primary" or "compare"
    login:
      url: http://localhost:3000/rest/user/login
      method: POST
      content_type: application/json
      body: '{"email":"test@test.com","password":"testpassword"}'
      extract:
        - source: json          # "json", "cookie", "header", or "regex"
          path: "$.authentication.token"  # JSONPath (for json source)
          apply_as: "Authorization: Bearer {value}"
  - name: admin_user
    role: compare
    headers:
      Authorization: "Bearer admin-static-token"
```

**JSON:**

```json
{
  "sessions": [
    {
      "name": "default_user",
      "role": "primary",
      "login": {
        "url": "http://localhost:3000/rest/user/login",
        "method": "POST",
        "content_type": "application/json",
        "body": "{\"email\":\"test@test.com\",\"password\":\"testpassword\"}",
        "extract": [
          {
            "source": "json",
            "path": "$.authentication.token",
            "apply_as": "Authorization: Bearer {value}"
          }
        ]
      }
    },
    {
      "name": "admin_user",
      "role": "compare",
      "headers": {
        "Authorization": "Bearer admin-static-token"
      }
    }
  ]
}
```

## Session Fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Session identity name |
| `role` | string | `"primary"` (main session) or `"compare"` (for auth-diff testing) |
| `headers` | map | Static auth headers (alternative to login flow) |
| `login.url` | string | Login endpoint URL |
| `login.method` | string | HTTP method for login |
| `login.content_type` | string | Request content type |
| `login.body` | string | Login request body |
| `login.type` | string | Shorthand preset: `"bearer"` (JSON body → Authorization header) or `"cookie"` (capture all Set-Cookie headers), auto-expanded into extract rules; or an OAuth2 grant, `"oauth2_client_credentials"` / `"oauth2_refresh_token"` (see below) |
| `login.token_path` | string | JSONPath for token extraction (used with `type` shorthand) |
| `login.extract` | []object | How to extract auth token from login response |
| `login.expect` | object | Response validation: `status` ([]int) and/or `body_contains` (string) |
| `login.steps` | []object | Multi-step login flow. When set, parent URL/Method/Body/Extract are ignored |
| `login.headers` / `login.steps[].headers` | map | Extra request headers: the flow's on every login request (single request, each step, OAuth2 token request), a step's after them (step wins). Values take `{var}` and templates |
| `login.token_url`, `client_id`, `client_secret`, `scope`, `audience`, `refresh_token`, `auth_style` | string | OAuth2 token endpoint fields (`auth_style`: `header` = Basic, `body` = form fields, empty tries both; `scope`/`audience` are sent with client credentials only) |
| `login_request` | string | Raw HTTP request string for the login flow (alternative to structured login). Logs in at scan start; the token is auto-discovered from the response (JSON token field, cookies, auth headers) |
| `check.url` | string | Protected URL that tells logged-in from anonymous. A `/path` resolves against the target origin. Required unless `logged_out` has `status` or `redirect_regex` |
| `check.method` | string | Method for the check request (default `GET`) |
| `check.logged_in` | object | ALL must hold on a logged-in response: `status` ([]int), `body_contains`, `body_regex`, `header_regex` (matched against `Name: value`) |
| `check.logged_out` | object | ANY marks a response logged out: `status` ([]int), `redirect_regex` (matched against `Location`), `body_regex` |
| `check.sample_every` | int | Evaluate `logged_out.body_regex` on 1 in N scan responses (default 50) |
| `check.interval` | duration | Proactive logged-in probe at most this often (`2m`; 0 = only reactive) |
| `reauth.enabled` | bool | Re-login when the check says logged out (default true when `check` is set) |
| `reauth.max_attempts` / `reauth.backoff` | int / duration | Consecutive failed re-logins before giving up (default 3); first wait, doubling (default `10s`) |
| `reauth.on_failure` | string | `continue` (default: keep scanning unauthenticated, phase partial) or `abort` |
| `reauth.pause_traffic` | bool | Hold the session's requests from the first logged-out match until the confirm probe and re-login end (default true) |

`scanning_strategy.session.validate_url`, `reauth_on_status` and
`reauth_interval` fill `check.url`, `check.logged_out.status` and
`check.interval` for sessions that leave them unset. `check` drives
`auth check` and in-scan re-login: during a scan, responses are matched
against `logged_out` (status/Location on every response, body on 1 in
`sample_every`); a match is confirmed with the `check.url` probe (or 3 matches
in 10s without one), then the login re-runs once for all workers (events
`auth.session_suspect`, `auth.relogin{session,gen,ok}`). Re-login that keeps
failing marks phases partial with `auth_lost` (or exits 1 `login_failed` under
`on_failure: abort`); responses received while logged out are reported as the
`responses_while_logged_out` limit and count, not re-queued. An explicit `-H`
of the same header always wins over the session. An OAuth2 session whose token
reports `expires_in` is refreshed shortly before it expires (no `check` needed,
traffic not paused; `auth.session_suspect` detail `expiry`).

### Templates and OAuth2

Login `url`, `body`, header values and OAuth2 fields accept templates evaluated
at every login (so re-logins get a fresh TOTP code):
`{{env:NAME}}` (env var at login time), `{{totp:NAME}}` (TOTP code for the
base32 secret in `$NAME`), `{{totp_secret_file:PATH}}`. Unset variables or bad
secrets fail the login (`invalid_flow`); `auth lint` warns on a literal base32
secret inside `{{totp:...}}`. Templates expand before `{var}` step variables.

```yaml
sessions:
  - name: svc
    role: primary
    login:
      type: oauth2_client_credentials      # or oauth2_refresh_token (+ refresh_token)
      token_url: https://idp.example.com/oauth/token
      client_id: scanner
      client_secret: "{{env:SCANNER_SECRET}}"
      scope: "read write"
      audience: https://api.example.com
      auth_style: header
  - name: mfa_user
    role: compare
    login:
      headers: { Origin: "https://app.example.com" }
      steps:
        - url: https://app.example.com/login
          method: POST
          body: '{"u":"{{env:APP_USER}}","p":"{{env:APP_PASS}}"}'
          extract: [{source: json, path: .ticket, apply_as: "var:ticket"}]
        - url: https://app.example.com/login/mfa
          method: POST
          headers: { X-OTP: "{{totp:APP_TOTP_SECRET}}" }
          body: '{"ticket":"{ticket}"}'
          extract: [{source: cookie}]
```

The token is sent as `Authorization: Bearer <access_token>`; `auth load -j`
reports `expires_at`. A rotated refresh token replaces the configured one.

## Extract Rule Fields

| Field | Type | Description |
|-------|------|-------------|
| `source` | string | Where to extract from: `"json"`, `"cookie"`, `"header"`, `"regex"` |
| `name` | string | Cookie name or header name (for cookie/header sources) |
| `path` | string | JSONPath expression (for json source) |
| `pattern` | string | Regex pattern with capture group (for regex source) |
| `group` | int | Capture group index, default 1 (for regex source) |
| `apply_as` | string | Header template such as `"Authorization: Bearer {value}"`, or `"var:name"` for use by a later login step |

## Managing Sessions with `vigolium auth`

The `vigolium auth` command manages session configs in the database. `auth load`,
`auth lint` and `--auth-file` share one parser, so they accept the same three
forms: a `sessions:` bundle, a single session at the top level, and an agent
`session-config.json`.

```bash
# Load session config from a file (logs in first; see below)
vigolium auth load auth-config.yaml --host example.com

# Load from stdin
cat session-config.json | vigolium auth load

# Load agent-generated session config (auto-detected from path)
vigolium auth load ~/.vigolium/agent-sessions/<uuid>/session-config.json

# Load a raw HTTP login request (auto-discovers tokens from response)
cat login-req.txt | vigolium auth load --name admin --host example.com

# Skip the login check
vigolium auth load sessions.json --no-validate

# Prove a session is really logged in on a protected page (exit 0 only if so)
vigolium auth check auth-config.yaml --url https://example.com/account
vigolium auth check admin --url https://example.com/api/me -j   # stored session

# Validate one or more session configs before use
vigolium auth lint auth-config.yaml admin.yaml
cat session-config.json | vigolium auth lint --stdin
vigolium auth lint -j auth-config.yaml

# List loaded sessions
vigolium auth list
vigolium auth ls --host example.com

# Generate a TOTP code for 2FA login flows (secret from $VIGOLIUM_TOTP_SECRET)
VIGOLIUM_TOTP_SECRET=JBSWY3DPEHPK3PXP vigolium auth totp
```

### `auth load`: the login check

Unless `--no-validate` is passed, `auth load` runs each session's login exactly
as a scan does: every step of a multi-step `steps` flow, every `expect` block,
over the scan's transport (`--proxy` or the environment proxy, the scan's TLS
stance, `--timeout` per request). Static-header sessions are not contacted.

| Outcome | Saved | Exit |
|---------|-------|------|
| Login passed its `expect`, or (no `expect`) extracted a credential or redirected away from the login URL | yes | 0 |
| No `expect`, and the response cannot confirm the login (for example the password form came back): `reason: unverified` warning | yes | 0 |
| `expect` failed (`expect_status_mismatch`, `expect_body_missing`), status outside 2xx/3xx without `expect` (`unexpected_status`), `extract_failed`, `network_error`, `invalid_flow` | no (yes with `--force`) | 1, error code `login_failed` |

Add an `expect` block to every login whose failure page also answers 200: it is
the only way a wrong password becomes an error rather than a warning.

The database row has no columns for `steps`: `auth load` checks a multi-step
flow but a stored multi-step session does not round-trip. Pass multi-step
configurations to scans with `--auth-file`.

`-j` prints one mutation document. `items` holds one result per session
(`session`, `ok`, `verified`, `status`, `url`, `final_url`, `redirects`, `step`,
`extracted_headers` (names only), `reason`, `message`), plus `persisted`,
`failed` and `host`. When a login failed the document also has `ok: false` and
`error: {code: "login_failed", message, exit_code: 1}`. Human output goes to
stderr under `-j`. An unknown field in the file is a warning for `auth load`
and `--auth-file`; anything `auth lint` calls an error makes `auth load` save
nothing and exit 1 with `lint_failed` (`--force` saves anyway). Header values
and tokens are printed as `<redacted>`.

Sessions are stored per host key: the hostname, plus `:port` when the port is
not the scheme's default (`--host 127.0.0.1:28942`, or the login URL's host).
Scans of that host, `replay --auth-session` and `fuzz --auth-session` look the
key up the same way, then fall back to the bare hostname. A scan with no
`--auth`/`--auth-file` sends the sessions stored for its targets' hosts: the
banner's `Session auth:` line and `plan.auth[]` (`source: "db"`) name them, and
`--no-auth` scans without them.

### `auth lint`

Lints one or more files (or `--stdin`) without contacting any login service.
An unknown field (a typo such as `extarct:`) is an error with its line and
column, alongside the structural checks. Exits 1 with error code `lint_failed`
when any file has an error; warnings alone exit 0. `-j` items are
`{file, field, line, column, severity, message}`, with `files`, `errors` and
`warnings` counts; on failure the document carries `ok: false` and
`error.code: "lint_failed"`.

### `auth check`

`auth check <session-file|stored-session-name> [--url URL] [--session NAME]`
logs each session in exactly as a scan does, then requests the URL twice
through the scan's HTTP stack (no redirects followed): with the session's
credentials and without. The URL is `--url`, else `check.url`, else
`scanning_strategy.session.validate_url`. The session's `check.logged_in` /
`check.logged_out` rules apply first, then heuristics (status pair, redirect to
a login URL, password input, body similarity).

| Verdict | Meaning |
|---------|---------|
| `authenticated` | Credentials reached what the anonymous request did not |
| `login_wall` | Redirected to a login URL / password form / `logged_out` redirect or body |
| `unauthorized` | 401/403 with credentials, a `logged_out` status, or `logged_in` failed |
| `indistinguishable` | Same response with and without credentials: pick a protected URL or set `check.logged_in` |
| `error` | Login failed or a request did not complete |

Exit 0 only when every session is `authenticated`; otherwise exit 1 with
`login_failed` (a login failed) or `not_authenticated`. `-j` items: `session`,
`url`, `method`, `verdict`, `authenticated`, `reason`, `signals`,
`similarity`, `auth_response`/`anon_response` (`status`, `length`,
`location`, `error`), `login`. Stored sessions have no `check` columns: pass
`--url`.

### `auth totp`

Reads the base32 secret from one source: `--secret-env NAME` (default
`VIGOLIUM_TOTP_SECRET`), `--secret-file PATH`, or `--secret -` (stdin).
`--secret VALUE` still works but warns that the secret is visible in the
process list. Naming two sources, or none with the variable unset, is a usage
error (exit 2). Prints the code alone; `-j` gives
`items: [{code, expires_in, period, secret_source}]`.

### `vigolium auth load` Flags

| Flag | Description |
|------|-------------|
| `--host` | Hostname to associate sessions with (derived from the login URL, first step URL or `login_request` if omitted) |
| `--no-validate` | Skip the login check |
| `--force` | Save sessions whose login check failed (still exits 1) |
| `--timeout` | Timeout for each login request (default `30s`) |
| `--source` | Source label for the session rows (default: `"cli"`) |
| `--agent-format` | Force parsing as agent session-config.json format |
| `--name` | Session name (used with raw HTTP request input) |

## Usage

### Auto-Generated from Source Analysis

```bash
# Provide source code — the agent analyzes auth code and generates session config automatically
vigolium agent swarm --discover -t http://localhost:3000 --source ~/projects/my-app

# Session config is written to a temp file and applied to all subsequent phases
# (discovery, scanning, triage all use authenticated requests)
```

### Manual Auth File

```bash
# Pass a YAML auth file to scan or run
vigolium scan -t https://example.com --auth-file auth.yaml

# scan-url and scan-request take --auth / --auth-file too (they route the
# request through the runner, which hydrates the session)
vigolium scan-url https://example.com/api/me --auth-file auth.yaml
vigolium scan-request -i request.txt --auth 'admin:Cookie:session=abc'

# Agent modes take the same native files (repeatable; validated before the run).
# Swarm: --auth-file and --auth-config (agent format; a native file is detected)
# are mutually exclusive, and either skips --browser-auth.
vigolium agent swarm -t https://example.com --auth-file admin.yaml --auth-file user.yaml
# Autopilot: logs the sessions in, the pre-scan uses them, and they are stored for
# the target so the operator's list_auth_sessions / replay_request can use them
vigolium agent autopilot -t https://example.com --auth-file admin.yaml

# JSON format works the same way
vigolium scan -t https://example.com --auth-file auth.json
```

### Inline Sessions

The `--auth` flag accepts inline `name:Header:value` strings.

```bash
# Simple inline session (name:Header:value format)
vigolium scan -t https://example.com --auth "admin:Cookie:session_id=abc123"

# Bearer token
vigolium scan -t https://example.com --auth "user1:Authorization:Bearer eyJhbGciOi..."

# Multiple sessions for IDOR testing
vigolium scan -t https://example.com \
  --auth "admin:Authorization:Bearer admin-token" \
  --auth "user:Authorization:Bearer user-token"
```

## Examples

### Cookie-Based Authentication

```yaml
sessions:
  - name: user_session
    role: primary
    login:
      url: https://example.com/login
      method: POST
      content_type: application/x-www-form-urlencoded
      body: "username=admin&password=secret"
      extract:
        - source: cookie
          name: session_id
```

### JWT Bearer Token

```yaml
sessions:
  - name: api_user
    role: primary
    login:
      url: https://api.example.com/auth/token
      method: POST
      content_type: application/json
      body: '{"client_id":"app","client_secret":"secret","grant_type":"client_credentials"}'
      extract:
        - source: json
          path: "$.access_token"
          apply_as: "Authorization: Bearer {value}"
```

### Bearer Token (Shorthand)

The `type` shorthand auto-expands into extract rules:

```yaml
sessions:
  - name: api_user
    role: primary
    login:
      url: https://api.example.com/auth/token
      method: POST
      content_type: application/json
      body: '{"email":"user@test.com","password":"secret"}'
      type: bearer
      token_path: "$.access_token"
```

### Static API Key (No Login Required)

```yaml
sessions:
  - name: api_key_user
    role: primary
    headers:
      X-API-Key: "my-api-key-here"
```

**JSON equivalent:**

```json
{
  "sessions": [
    {
      "name": "api_key_user",
      "role": "primary",
      "headers": {
        "X-API-Key": "my-api-key-here"
      }
    }
  ]
}
```

### Multi-Session Auth-Diff Testing

```yaml
sessions:
  - name: regular_user
    role: primary
    login:
      url: https://example.com/api/login
      method: POST
      content_type: application/json
      body: '{"email":"user@test.com","password":"userpass"}'
      extract:
        - source: json
          path: "$.token"
          apply_as: "Authorization: Bearer {value}"
  - name: admin_user
    role: compare
    login:
      url: https://example.com/api/login
      method: POST
      content_type: application/json
      body: '{"email":"admin@test.com","password":"adminpass"}'
      extract:
        - source: json
          path: "$.token"
          apply_as: "Authorization: Bearer {value}"
```

### Multi-Step Login Flow

Steps execute in sequence with a shared cookie jar. Extract an intermediate
value with `apply_as: "var:name"`, then reference it as `{name}` in a later
step's URL or body. The last step must extract the headers or cookies used by
scan requests.

This example models an identity-provider login followed by an application token
exchange, including Stytch-style `intermediate_session_token` flows:

```yaml
sessions:
  - name: dev_user
    role: primary
    login:
      steps:
        - url: https://identity.example.com/passwords/discovery/authenticate
          method: POST
          content_type: application/json
          body: >-
            {"email_address":"${TEST_EMAIL}","password":"${TEST_PASSWORD}"}
          expect:
            status: [200]
            body_contains: "intermediate_session_token"
          extract:
            - source: json
              path: "$.intermediate_session_token"
              apply_as: "var:intermediate_session_token"

        - url: https://api.example.com/auth/stytch/exchange
          method: POST
          content_type: application/json
          body: >-
            {"intermediate_session_token":"{intermediate_session_token}"}
          expect:
            status: [200]
            body_contains: "token"
          extract:
            - source: json
              path: "$.token"
              apply_as: "Authorization: Bearer {value}"
            - source: json
              path: "$.token"
              apply_as: "Cookie: token={value}"
```

Stytch's browser SDK bootstrap request initializes the SDK; it is not normally
one of the authentication steps. A later `/auth/me` request is useful for
manual verification, but it is not part of the token exchange.

If the exchange response contains JSON rather than a `Set-Cookie` header, use
`source: json`. `source: cookie` cannot observe a cookie created later by
frontend JavaScript.

### Current Limitations

- Only sessions with a `check` block (own or from the
  `scanning_strategy.session` defaults), or an OAuth2 login with `expires_in`,
  re-login mid-scan; the others, and sessions loaded from the DB, hydrate once
  at scan start. The spidering browser and a running nuclei phase keep the
  credentials they started with.
- `auth load` stores multi-step and OAuth2 sessions as the headers their last
  login produced; pass those files with `--auth-file` to keep them re-loggable.
- No browser-driven login type: for a login that needs a real browser, use
  `agent swarm --browser --browser-auth` (writes an `auth-config.yaml` the scan
  phases use) or pass captured static headers.

### Multiple Extract Rules

```yaml
sessions:
  - name: complex_auth
    role: primary
    login:
      url: https://example.com/auth
      method: POST
      content_type: application/json
      body: '{"user":"admin","pass":"secret"}'
      extract:
        - source: json
          path: "$.token"
          apply_as: "Authorization: Bearer {value}"
        - source: cookie
          name: csrf_token
        - source: header
          name: X-Request-Id
```

### Response Validation

Verify login succeeded before proceeding:

```yaml
sessions:
  - name: validated_login
    role: primary
    login:
      url: https://example.com/api/login
      method: POST
      content_type: application/json
      body: '{"email":"user@test.com","password":"pass"}'
      expect:
        status: [200, 201]
        body_contains: "token"
      extract:
        - source: json
          path: "$.token"
          apply_as: "Authorization: Bearer {value}"
```

### Environment Variable Expansion

Session configs support `${VAR}` syntax for credentials:

```yaml
sessions:
  - name: env_user
    role: primary
    login:
      url: https://example.com/api/login
      method: POST
      content_type: application/json
      body: '{"email":"${TEST_EMAIL}","password":"${TEST_PASSWORD}"}'
      extract:
        - source: json
          path: "$.token"
          apply_as: "Authorization: Bearer {value}"
```
