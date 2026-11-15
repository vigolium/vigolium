# Authenticated Scanning

Vigolium supports multi-session authenticated scanning via two repeatable flags, `--auth-file` and `--auth`. This enables scanning behind login walls and detecting authorization bypass vulnerabilities (IDOR/BOLA).

Auth files can be written in **YAML or JSON** — the format is auto-detected by file extension (`.json`) or by content sniffing (leading `{` or `[`).

## Quick Start

```bash
# Inline session (simplest)
vigolium scan https://app.com --auth "admin:Cookie:session_id=abc123"

# Single-session file (YAML or JSON)
vigolium scan https://app.com --auth-file ./admin-session.yaml
vigolium scan https://app.com --auth-file ./admin-session.json

# Bare name resolved against scanning_strategy.session.session_dir
vigolium scan https://app.com --auth-file admin-session

# Bundle file with multiple sessions
vigolium scan https://app.com --auth-file ./auth-config.yaml
vigolium scan https://app.com --auth-file ./auth-config.json

# Mix and match — both flags are repeatable
vigolium scan https://app.com --auth-file admin --auth "compare:Cookie:sid=xyz"
```

## The Auth Flags

| Flag | Accepts | Repeatable |
|------|---------|------------|
| `--auth-file <path>` | YAML/JSON file (single session **or** `sessions:` bundle), or a bare name resolved against `scanning_strategy.session.session_dir` | yes |
| `--auth <name:Header:value>` | Inline session — name and header injected as static headers | yes |

If no session is explicitly marked as `primary`, the first session loaded is used as the primary.

With neither flag given, sessions are loaded from the project's
`authentication_hostnames` rows for the target hostnames. A stored session that
carries a **login flow** re-runs that login, rather than reusing the token the
flow produced in an earlier scan — a stored token is usually expired, and a scan
that reused it collected 401s. A stored session with only **static headers**
sends them as-is; there is nothing to re-run.

## Session Roles

Each session has a **role** that determines how it is used during the scan:

- **`primary`** — The main session. Used for discovery, spidering, and as the default requester during the dynamic-assessment phase. There should be exactly one primary session.
- **`compare`** — Comparison sessions for IDOR/BOLA testing. During the dynamic-assessment phase, every request made by the primary session is replayed with each compare session's credentials. If a compare session can access resources it shouldn't, the `authz-compare` module flags it.

## Inline Sessions

The `--auth` flag accepts inline sessions in `name:Header:value` format:

```bash
# Single session with a cookie
vigolium scan https://app.com --auth "admin:Cookie:session_id=abc123"

# Bearer token
vigolium scan https://app.com --auth "user1:Authorization:Bearer eyJhbGciOi..."

# Multiple sessions for IDOR testing
vigolium scan https://app.com \
  --auth "admin:Cookie:session=admin_token" \
  --auth "regular:Cookie:session=user_token"
```

Values containing colons in the `value` part are handled correctly — only the first two colons are used as delimiters.

## Session Files

For sessions with multiple headers or login flows, use files. Both YAML and JSON formats are supported. A file may contain a single session at the top level **or** a `sessions:` list — the loader auto-detects the shape.

### Static Headers

**YAML:**

```yaml
name: admin
role: primary
headers:
  Cookie: "session_id=abc123"
  Authorization: "Bearer mytoken"
```

**JSON:**

```json
{
  "name": "admin",
  "role": "primary",
  "headers": {
    "Cookie": "session_id=abc123",
    "Authorization": "Bearer mytoken"
  }
}
```

Use with:

```bash
vigolium scan https://app.com --auth-file ./admin-session.yaml
vigolium scan https://app.com --auth-file ./admin-session.json
```

Session files are resolved from the configured `session_dir` (default `~/.vigolium/sessions/`) if the path is not absolute. See [Session Strategy Configuration](#session-strategy-configuration) below.

### Login Flows

Session files can define automated login flows. The scanner executes the login request at scan start and extracts credentials from the response.

**YAML:**

```yaml
name: admin
role: primary
login:
  url: "https://app.com/api/auth/login"
  method: POST
  content_type: "application/json"
  body: '{"username":"${ADMIN_USER}","password":"${ADMIN_PASS}"}'
  extract:
    - source: json
      path: "$.token"
      apply_as: "Authorization: Bearer {value}"
```

**JSON:**

```json
{
  "name": "admin",
  "role": "primary",
  "login": {
    "url": "https://app.com/api/auth/login",
    "method": "POST",
    "content_type": "application/json",
    "body": "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}",
    "extract": [
      {
        "source": "json",
        "path": "$.token",
        "apply_as": "Authorization: Bearer {value}"
      }
    ]
  }
}
```

### Multi-Step Login Flows

Use `login.steps` when authentication requires more than one HTTP request. Steps
run in order with a shared cookie jar. To pass a value to a later step, extract
it with `apply_as: "var:<name>"`, then reference it as `{name}` in a later
step's URL or body. The final step must extract at least one credential that
Vigolium can apply to scan requests.

The following provider-backed flow models applications that first receive a
short-lived identity-provider token and then exchange it for an application
token. Stytch B2B password discovery uses this shape: the authenticate response
contains `intermediate_session_token`, and the application exchange endpoint
returns the application's final token.

```yaml
sessions:
  - name: dev_user
    role: primary
    login:
      steps:
        # Step 1: authenticate with the identity provider.
        - url: "https://identity.example.com/passwords/discovery/authenticate"
          method: POST
          content_type: "application/json"
          body: >-
            {"email_address":"${TEST_EMAIL}","password":"${TEST_PASSWORD}"}
          expect:
            status: [200]
            body_contains: "intermediate_session_token"
          extract:
            - source: json
              path: "$.intermediate_session_token"
              apply_as: "var:intermediate_session_token"

        # Step 2: exchange the intermediate token for the app token.
        - url: "https://api.example.com/auth/stytch/exchange"
          method: POST
          content_type: "application/json"
          body: >-
            {"intermediate_session_token":"{intermediate_session_token}"}
          expect:
            status: [200]
            body_contains: "token"
          extract:
            - source: json
              path: "$.token"
              apply_as: "Authorization: Bearer {value}"

            # Keep this rule only when the application also requires a cookie.
            - source: json
              path: "$.token"
              apply_as: "Cookie: token={value}"
```

In a browser trace, calls such as Stytch's `sdk/v1/projects/bootstrap` initialize
the browser SDK and do not produce the authenticated application session. Do
not add them as login steps unless a later authentication request genuinely
depends on a value they return. Likewise, an `/auth/me` request verifies the
finished session; it is not part of the token exchange itself.

Each step may use `expect.status` and `expect.body_contains` to fail early when
the remote service changes behavior. `vigolium auth lint` checks the file's
structure only (including unknown fields, reported with their line); `vigolium
auth load` runs the whole flow, every step and `expect`, before saving the
session, and exits 1 (`login_failed`) without saving it when the login fails.

```bash
vigolium auth lint ./multi-step-token-exchange.yaml
vigolium scan \
  https://app.example.com \
  https://api.example.com \
  --auth-file ./multi-step-token-exchange.yaml \
  --scope-origin strict
```

### Login Request Headers

`login.headers` adds request headers to every request the login sends (the
single request, each step, or the OAuth2 token request). A step's own
`headers` are added after the flow's, so a step header wins on a clash. Header
values take `{name}` step variables and the templates below, like `url` and
`body`. A `Host` header sets the request's Host.

```yaml
login:
  headers:
    Origin: https://app.example.com
    X-Client-Version: "4.2"
  steps:
    - url: https://identity.example.com/sdk/authenticate
      method: POST
      headers:
        Authorization: "Basic {{env:SDK_BASIC_AUTH}}"
      body: '{"email":"${TEST_EMAIL}","password":"${TEST_PASSWORD}"}'
      extract:
        - source: json
          path: .intermediate_token
          apply_as: "var:intermediate"
    - url: https://api.example.com/auth/exchange
      method: POST
      headers:
        X-Intermediate-Token: "{intermediate}"
      extract:
        - source: json
          path: .token
          apply_as: "Authorization: Bearer {value}"
```

### Templates: Environment and TOTP

Login `url`, `body`, header values and the OAuth2 fields accept function
templates. They are evaluated every time the login runs (including an in-scan
re-login), so a TOTP code is always current and a secret never has to be
written into the file:

| Template | Value |
|----------|-------|
| `{{env:NAME}}` | Environment variable `NAME`, read when the login runs |
| `{{totp:NAME}}` | Current 6-digit TOTP code (RFC 6238, SHA-1, 30 s) for the base32 secret in `$NAME` |
| `{{totp_secret_file:PATH}}` | The same, for the base32 secret stored in file `PATH` (`~/` expands) |

```yaml
login:
  steps:
    - url: https://app.example.com/login
      method: POST
      body: '{"user":"{{env:APP_USER}}","password":"{{env:APP_PASS}}"}'
      extract:
        - source: json
          path: .mfa_ticket
          apply_as: "var:ticket"
    - url: https://app.example.com/login/mfa
      method: POST
      body: '{"ticket":"{ticket}","code":"{{totp:APP_TOTP_SECRET}}"}'
      extract:
        - source: cookie
```

A variable that is not set, an unreadable secret file or an invalid secret
fails the login and names the template; nothing is sent with an empty value.
Templates are expanded before `{name}` step variables, so a value the server
returned is never itself treated as a template. `vigolium auth lint` reports
an unknown template function or a malformed name as an error, and warns when
`{{totp:...}}` holds what looks like a literal base32 secret instead of the
name of a variable. `${NAME}` keeps working; it is expanded once, when the file
is loaded. `vigolium auth totp` prints the code a template would produce.

### OAuth2 Token Endpoints

`type: oauth2_client_credentials` and `type: oauth2_refresh_token` log in
against an OAuth2 token endpoint instead of a login form:

```yaml
sessions:
  - name: service
    role: primary
    login:
      type: oauth2_client_credentials
      token_url: https://idp.example.com/oauth/token
      client_id: vigolium-scanner
      client_secret: "{{env:SCANNER_CLIENT_SECRET}}"
      scope: "read:orders write:orders"
      audience: https://api.example.com
      auth_style: header        # or body; omit to try header, then body

  - name: user
    role: compare
    login:
      type: oauth2_refresh_token
      token_url: https://idp.example.com/oauth/token
      client_id: vigolium-scanner
      client_secret: "{{env:SCANNER_CLIENT_SECRET}}"
      refresh_token: "{{env:USER_REFRESH_TOKEN}}"
```

| Field | Meaning |
|-------|---------|
| `token_url` | Token endpoint (required) |
| `client_id`, `client_secret` | Client credentials (both required for `oauth2_client_credentials`) |
| `scope` | Space- or comma-separated scopes (client credentials only) |
| `audience` | Sent as the `audience` parameter (client credentials only) |
| `refresh_token` | Required for `oauth2_refresh_token` |
| `auth_style` | `header` (HTTP Basic) or `body` (form fields); empty tries header, then body |

The access token is sent as `Authorization: <token_type> <access_token>`
(`Bearer` for a bearer token). The response's `expires_in` is kept as the
session's expiry: during a native scan the token is refreshed shortly before
it expires (a tenth of its lifetime, between 5 s and 60 s ahead, at most half
of it), without waiting for a 401 and without holding scan traffic, even when
the session has no `check` block. A refresh token the server rotates replaces
the configured one for the next refresh. `auth load -j` reports the expiry as
`expires_at`. A token endpoint error (`invalid_client`, `invalid_grant`, ...)
fails the login with that error. `auth lint` checks the required fields, the
`token_url` scheme and `auth_style`, and warns about request-flow fields
(`url`, `method`, `body`, `extract`, ...) that an OAuth2 login ignores.

### Extraction Sources

| Source | Description | Example |
|--------|-------------|---------|
| `json` | Extract a value from the JSON response body using dot-notation. | `path: "$.token"` |
| `cookie` | Extract cookies from `Set-Cookie` response headers. Omit `name` to extract all cookies. | `name: "session_id"` |
| `header` | Extract a value from a response header. | `name: "X-Auth-Token"` |
| `regex` | Extract a capture group from the response body. Group 1 is used by default. | `pattern: 'token="([^"]+)"'` |

The `apply_as` field defines how the extracted value is used. A header template
such as `Authorization: Bearer {value}` applies it to scan requests. In a
multi-step flow, `var:name` stores it for `{name}` substitution in later step
URLs and bodies.

`source: cookie` reads `Set-Cookie` response headers. It cannot observe a cookie
created later by frontend JavaScript. If an exchange endpoint returns a token
in JSON and the frontend turns it into a cookie, extract the JSON value and use
`apply_as: "Cookie: token={value}"` instead.

## Bundle Files

A bundle file defines multiple sessions in one place under a top-level `sessions:` key. Pass it via `--auth-file`.

### YAML Format

```yaml
sessions:
  # Primary session: JSON API login
  - name: admin
    role: primary
    login:
      url: "https://app.com/api/auth/login"
      method: POST
      content_type: "application/json"
      body: '{"username":"${ADMIN_USER}","password":"${ADMIN_PASS}"}'
      extract:
        - source: json
          path: "$.token"
          apply_as: "Authorization: Bearer {value}"

  # Compare session: form-based login
  - name: regular_user
    role: compare
    login:
      url: "https://app.com/login"
      method: POST
      content_type: "application/x-www-form-urlencoded"
      body: "username=${USER_NAME}&password=${USER_PASS}"
      extract:
        - source: cookie

  # Compare session: static API key (no login needed)
  - name: api_key_user
    role: compare
    headers:
      X-API-Key: "${API_KEY}"
```

### JSON Format

```json
{
  "sessions": [
    {
      "name": "admin",
      "role": "primary",
      "login": {
        "url": "https://app.com/api/auth/login",
        "method": "POST",
        "content_type": "application/json",
        "body": "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}",
        "extract": [
          {
            "source": "json",
            "path": "$.token",
            "apply_as": "Authorization: Bearer {value}"
          }
        ]
      }
    },
    {
      "name": "regular_user",
      "role": "compare",
      "login": {
        "url": "https://app.com/login",
        "method": "POST",
        "content_type": "application/x-www-form-urlencoded",
        "body": "username=${USER_NAME}&password=${USER_PASS}",
        "extract": [
          {
            "source": "cookie"
          }
        ]
      }
    },
    {
      "name": "api_key_user",
      "role": "compare",
      "headers": {
        "X-API-Key": "${API_KEY}"
      }
    }
  ]
}
```

Use with:

```bash
vigolium scan https://app.com --auth-file ./auth-config.yaml
vigolium scan https://app.com --auth-file ./auth-config.json
```

### When to Use JSON

JSON is a good choice when:

- **AI agents generate session configs** — most LLMs produce cleaner JSON than YAML, and agent modes (swarm, autopilot) already output session config as JSON natively.
- **Programmatic generation** — scripts, CI pipelines, or tools that build session configs are often simpler in JSON.
- **Embedding in other JSON payloads** — e.g., the REST API `POST /api/agent/run/autopilot` body includes session config as a nested JSON object.

YAML remains convenient for hand-written configs where comments and multi-line strings help readability.

### Format Detection

The format is detected automatically:

1. **File extension** — `.json` files are parsed as JSON; `.yaml` / `.yml` as YAML.
2. **Content sniffing** — if the extension is ambiguous (or missing), content starting with `{` or `[` (after whitespace trimming) is parsed as JSON.
3. **Fallback** — everything else is parsed as YAML.

This means extensionless files work too — pipe JSON directly and it will be detected:

```bash
# Generate config from a script, write to a temp file, scan
./gen-auth-config.sh > /tmp/auth-config
vigolium scan https://app.com --auth-file /tmp/auth-config
```

## Session Config Schema Reference

Both YAML and JSON use the same field names. Here is the full schema:

```
SessionConfig
├── sessions[]              # Array of session definitions
│   ├── name                # (string, required) Unique session name
│   ├── role                # (string) "primary" or "compare"
│   ├── headers             # (map) Static headers, e.g. {"Cookie": "sid=abc"}
│   ├── login               # (object) Automated login flow
│   │   ├── url             # (string) Single-step login endpoint URL
│   │   ├── method          # (string) Single-step HTTP method
│   │   ├── content_type    # (string) Request Content-Type
│   │   ├── body            # (string) Request body
│   │   ├── type            # (string) "bearer", "cookie", "oauth2_client_credentials", "oauth2_refresh_token"
│   │   ├── token_path      # (string) Token path used by bearer shorthand
│   │   ├── headers         # (map) Extra headers on every login request; templates allowed
│   │   ├── expect          # (object) status[] and/or body_contains
│   │   ├── token_url       # (string) OAuth2 token endpoint (oauth2_* types)
│   │   ├── client_id       # (string) OAuth2 client id
│   │   ├── client_secret   # (string) OAuth2 client secret
│   │   ├── scope           # (string) OAuth2 scopes, space/comma separated
│   │   ├── audience        # (string) OAuth2 audience parameter
│   │   ├── refresh_token   # (string) OAuth2 refresh token (oauth2_refresh_token)
│   │   ├── auth_style      # (string) "header" or "body"; empty tries both
│   │   ├── extract[]       # (array) Credential extraction rules
│   │   │   ├── source      # (string) "json", "cookie", "header", or "regex"
│   │   │   ├── name        # (string) Cookie/header name to extract
│   │   │   ├── path        # (string) JSON path for json source
│   │   │   ├── pattern     # (string) Pattern for regex source
│   │   │   ├── group       # (int) Regex capture group; defaults to 1
│   │   │   └── apply_as    # (string) Header template or "var:name"
│   │   └── steps[]         # (array) Sequential multi-step flow
│   │       ├── url         # (string, required) Step endpoint URL
│   │       ├── method      # (string, required) Step HTTP method
│   │       ├── content_type # (string) Step request Content-Type
│   │       ├── headers     # (map) Step headers (win over login.headers); {name} and templates
│   │       ├── body        # (string) Supports {name} variables
│   │       ├── expect      # (object) status[] and/or body_contains
│   │       └── extract[]   # (array; required on the final step)
│   ├── login_request       # (string) Raw HTTP request for login (alternative to login)
│   ├── check               # (object) How to tell the session is still logged in
│   │   ├── url             # (string) Protected URL probe; a path resolves against the target origin
│   │   ├── method          # (string) Probe method; default GET
│   │   ├── logged_in       # (object) ALL must hold: status[], body_contains, body_regex, header_regex
│   │   ├── logged_out      # (object) ANY marks logged out: status[], redirect_regex (Location), body_regex
│   │   ├── sample_every    # (int) Evaluate logged_out.body_regex on 1 in N scan responses; default 50
│   │   └── interval        # (duration) Proactive probe at most this often; 0 = only reactive
│   └── reauth              # (object) What a scan does once check finds the session logged out
│       ├── enabled         # (bool) Default true when check is present
│       ├── max_attempts    # (int) Consecutive failed re-logins before giving up; default 3
│       ├── backoff         # (duration) Wait after a failure, doubling each time; default 10s
│       ├── on_failure      # (string) "continue" (default: unauthenticated, phase partial) or "abort"
│       └── pause_traffic   # (bool) Hold this session's requests while a logout is confirmed and re-logged in; default true
```

Only one of `headers`, `login`, or `login_request` can be set per session.

A `login_request` session logs in when the scan starts, like a `login` flow: the raw
request is sent with its own headers, and the credential is discovered from the
response the same way `vigolium auth load` does it (a known token field in a JSON
body becomes `Authorization: Bearer …`, cookies the login set become `Cookie`, and
known auth response headers are copied). A response with none of those fails the
login. The URL comes from the request line, or from `Host` with `https` (or `http`
when the port is 80); write an absolute request line such as
`POST http://localhost:3000/login HTTP/1.1` for a cleartext target on another port.

## Logged-in Check

A session's optional `check` block says what "logged in" looks like on the
target, and `reauth` says what to do once it is not:

```yaml
sessions:
  - name: admin
    role: primary
    login: { ... }
    check:
      url: /api/me                 # a path resolves against the target origin
      method: GET
      logged_in:                   # ALL listed conditions must hold
        status: [200]
        body_contains: '"email"'
        header_regex: '(?i)^content-type: application/json'
      logged_out:                  # ANY match means logged out
        status: [401, 419, 440]
        redirect_regex: '(?i)/(login|signin|sso)\b'
        body_regex: '(?i)(session (has )?expired|please (log|sign) in)'
      sample_every: 50
      interval: 2m
    reauth:
      enabled: true
      max_attempts: 3
      backoff: 10s
      on_failure: continue         # or abort
      pause_traffic: true
```

Durations are Go durations (`90s`, `2m`, `1h30m`); a bare number is seconds.
`header_regex` is matched against each response header written as
`Name: value`. `scanning_strategy.session.validate_url`, `reauth_on_status` and
`reauth_interval` fill `check.url`, `check.logged_out.status` and
`check.interval` for every session that leaves them unset (see
[Session Strategy Configuration](#session-strategy-configuration)).

Validation (`auth lint`, and every loader before a session is used):

- `check.url` must be an `http(s)` URL or a path starting with `/`. It is
  required unless `logged_out` has a `status` or `redirect_regex`.
- Every regex must compile; status codes must be 100-599.
- `sample_every`, `interval`, `max_attempts` and `backoff` must not be
  negative; `on_failure` is `continue` or `abort`.
- Warnings: an empty `logged_in`/`logged_out` block, `logged_in` with no
  `check.url` to evaluate it on, `reauth` with no `check`, and `reauth` on a
  static-header session (nothing to re-run).

The `check` block drives `vigolium auth check` and, during a native scan,
in-scan re-login (below).

### In-scan re-login

A session with a `check` block (its own, or one the `scanning_strategy.session`
defaults give it) is kept live for the whole scan:

1. **Sampling.** Every response the scan receives with the session's
   credentials is matched against `logged_out`: `status` and `redirect_regex`
   (against `Location`) on every response, `body_regex` on one response in
   `sample_every` (first 64 KiB). Responses served from the request cache are
   not fresh evidence and are not sampled.
2. **Confirming.** A match marks the session *suspect* and emits
   `auth.session_suspect`. With a `check.url`, one probe is sent with the
   current credentials: if it is still logged in (`logged_in` holds, or with
   no `logged_in` rule the probe is not refused, redirected to a login page or
   matched by `logged_out`), the session stays valid, which is the common case
   of a module that provoked a 401 on purpose. Without a `check.url`, three
   matches within 10 seconds confirm the logout.
3. **Re-login.** The login flow runs again on a copy of the session, through
   the same login transport (proxy, TLS stance, the egress gate's priority
   lane, so it never waits behind the scan's own requests). Up to
   `reauth.max_attempts` attempts, waiting `backoff` after the first failure
   and doubling it after each one. Success publishes the new credentials as
   the next *generation* and emits `auth.relogin` with `ok: true`.
4. **One login per expiry.** However many workers see the 401 at once, only
   the first starts the confirm and the re-login. A response to an older
   generation's credentials (in flight before the re-login) is never evidence
   against the new ones.
5. **Pausing.** With `pause_traffic: true` (the default) requests for this
   session wait from the first logged-out match, through the confirm probe and
   the re-login, at most the login budget (2 minutes), and leave with the new
   credentials (or the old ones, when the probe found the session still
   logged in). Only the requests already in flight when the match arrived come
   back logged out, so the `responses_while_logged_out` count per expiry stays
   within the scan's concurrency. With `false` they keep going with the old
   ones.
6. **Proactive probe.** `check.interval` re-runs the `check.url` probe at most
   that often even when no response looked logged out.
7. **Expiry.** When the login reported when its credentials expire (an OAuth2
   token's `expires_in`), the session is kept live even without a `check`
   block, and the re-login runs shortly before that time (a tenth of the
   token's lifetime ahead, between 5 s and 60 s, at most half of it). It emits
   `auth.session_suspect` with detail `expiry`, skips the confirm probe and
   does not pause traffic, since the old token is still valid.

When every attempt fails (or `reauth.enabled` is false, or the session has
static headers and nothing to re-run) the session is *lost*: `auth.relogin`
reports `ok: false` with the error, the running phase and every later phase
that sends with that session are recorded partial with the reason `auth_lost`,
and the scan carries on unauthenticated. With `reauth.on_failure: abort` the
scan stops instead: the remaining phases are skipped with `auth_lost` and the
command exits 1 with `error.code` `login_failed`.

Responses received while a session was logged out (logged-out matches, plus
every response once the session is lost) ran their work unauthenticated. The
phase reports them as the `responses_while_logged_out` limit with the number
under `counts.responses_while_logged_out`; they are not re-queued.

Credential precedence: the live session's current headers are applied after
the scan's frozen copies, so a re-login takes effect on every requester that
carries the session (discovery and spidering's requester when
`use_in_discovery` is true, the assessment view otherwise, and each compare
session's own requester). A header you set explicitly with `-H` is never taken
over by the session: the explicit value is sent.

`check.url`, when relative, resolves against the first scan target (else the
login URL). Credential-stripped requests (the authorization-differential
modules' anonymous replays) are never sampled, so their deliberate 401s cannot
trigger a re-login. Events: `auth.session_suspect` carries `session`, `gen`
(the suspected credential generation, from 1) and `detail` (`status`,
`redirect`, `body`, `interval`); `auth.relogin` carries `session`, `gen` (the
new generation when `ok`), `ok`, `count` (logins tried) and `message` on
failure.

### `vigolium auth check`

```bash
vigolium auth check sessions.yaml --url https://app.example.com/account
vigolium auth check admin --url https://app.example.com/api/me -j   # a stored session
vigolium auth check sessions.yaml --session admin                    # uses check.url
```

The argument is a session file (any form `--auth-file` accepts, including a
bare name in `session_dir`) or the name of a session stored with `auth load` in
the current project. It logs each session in exactly as a scan does (the scan's
login transport: `--proxy`, the scan's TLS stance, `--timeout`), then requests
the URL twice through the scan's HTTP stack, with and without the session's
credentials, without following redirects. The URL is `--url`, else
`check.url`, else `validate_url`; a path resolves against the login URL's
origin.

| Verdict | Meaning |
|---------|---------|
| `authenticated` | The session reached what the anonymous request did not (status pair, the anonymous request redirected to a login page or shown a password form, different content), or `check.logged_in` held with credentials and failed without them. |
| `login_wall` | The authenticated request was redirected to a login URL, got a password form, or matched `check.logged_out` by redirect or body. |
| `unauthorized` | 401/403 with credentials, a `check.logged_out` status, or `check.logged_in` failed. |
| `indistinguishable` | Same status and the same body (volatile tokens such as nonces and timestamps ignored) with and without credentials, or `check.logged_in` also held anonymously. Use a page only a logged-in user sees, or configure `check.logged_in`. |
| `error` | The login failed (see `login`) or a request did not complete. |

Exits 0 only when every checked session is `authenticated`. Otherwise exit 1
with error code `login_failed` (a login did not work) or `not_authenticated`
(any other verdict). `-j` prints a read document; each item has `session`,
`url`, `method`, `verdict`, `authenticated`, `reason`, `signals` (`name`,
`side`, `detail`), `similarity`, `auth_response` and `anon_response`
(`status`, `length`, `location`, `error`), and `login` (the `auth load` login
result). A failing run's document carries `ok: false` and the coded `error`.

The database has no columns for `check`/`reauth`, so a stored session is
checked with `--url` (or `validate_url`) and the heuristics only.

## Environment Variables

Session files (both YAML and JSON) support `${VAR}` syntax for secrets. This keeps credentials out of config files:

```bash
export ADMIN_USER=admin
export ADMIN_PASS=s3cret
vigolium scan https://app.com --auth-file ./auth-config.json
```

All `${VAR}` references are expanded from the environment at load time, before format parsing.
Login fields also take `{{env:NAME}}`, `{{totp:NAME}}` and
`{{totp_secret_file:PATH}}`, evaluated each time the login runs (see
[Templates: Environment and TOTP](#templates-environment-and-totp)).

## IDOR/BOLA Testing

To test for authorization bypass vulnerabilities, define at least two sessions — one primary and one or more compare sessions.

**YAML:**

```yaml
sessions:
  - name: admin
    role: primary
    headers:
      Cookie: "${ADMIN_SESSION_COOKIE}"

  - name: regular_user
    role: compare
    headers:
      Cookie: "${USER_SESSION_COOKIE}"

  # Optional: unauthenticated session
  - name: unauthenticated
    role: compare
```

**JSON:**

```json
{
  "sessions": [
    {
      "name": "admin",
      "role": "primary",
      "headers": {
        "Cookie": "${ADMIN_SESSION_COOKIE}"
      }
    },
    {
      "name": "regular_user",
      "role": "compare",
      "headers": {
        "Cookie": "${USER_SESSION_COOKIE}"
      }
    },
    {
      "name": "unauthenticated",
      "role": "compare"
    }
  ]
}
```

The built-in `authz-compare` module automatically activates when compare sessions are present. It replays primary session requests with compare session credentials and flags responses that indicate broken access control.

### How Detection Works

1. The primary session makes a request and gets a response (e.g., `GET /api/users/42` -> 200 OK with user data).
2. The same request is replayed with each compare session's credentials.
3. If a compare session also receives a successful response with similar content, the module reports a potential IDOR/BOLA finding with **High** severity.

### Filtering to Auth Modules Only

To run only authorization testing without other active modules:

```bash
vigolium scan https://app.com \
  --auth-file ./auth-config.json \
  --module-tag access-control
```

## How Sessions Affect Scan Phases

| Phase | Session Usage |
|-------|---------------|
| Discovery / Spidering | Primary session only (controlled by `use_in_discovery`) |
| DynamicAssessment | Primary session for main scanning; compare sessions for IDOR/BOLA replay (controlled by `compare_enabled`) |
| KnownIssueScan | Primary session headers (nuclei runs its own HTTP stack and receives the headers directly, as of the phase start: a re-login during the phase does not reach it) |

With `use_in_discovery: false`, Discovery and Spidering run unauthenticated and
DynamicAssessment and KnownIssueScan still authenticate — the setting keeps the
credentials out of discovery, it does not turn authentication off. The
assessment phases send through a view of the same requester, so they share its
connection pool, rate limiter and carried browser sessions but keep their own
cookie jar and response-cache partition.

Compare-session requesters carry the operator's own `-H` headers plus their own
session's credentials, never the primary session's.

In the browser crawl, session cookies keep their Domain/Path and auth headers
are sent only while the crawl stays on a host the scope admits. Each target
reports `auth_state` (`applied` or `failed`, never "verified"); a `failed`
target is crawled unauthenticated unless `spidering.require_auth` /
`--require-auth` makes it fail. See
[Browser policy](../guides/browser-policy.md#credentials-and-scope).

## Validation and Troubleshooting

| Symptom | Meaning and next step |
|---------|-----------------------|
| `auth lint` succeeds but scan hydration fails | Lint validates structure without contacting the login services. Check the failing step's status, response shape, and extraction path. |
| `auth check` says `indistinguishable` | The URL answers the same with and without credentials: it is public, or the server ignores the credentials. Pick a page only a logged-in user sees, or add `check.logged_in` describing it. |
| `auth check` says `login_wall` but `auth load` passed | The login returned a credential, but the app does not accept it on that URL (wrong cookie scope, an extra CSRF/header requirement, or a token for another audience). |
| `auth load` reports `unverified` | The login ran but had no `expect` block, and the response could not confirm it (for example the password form came back). Add `expect.status` / `expect.body_contains` so a wrong password fails. |
| `cookie "token" not found in login response` | The response did not include a matching `Set-Cookie` header. If it returned JSON, use `source: json`; if browser JavaScript creates the cookie, build the `Cookie` header with `apply_as`. |
| A later request still contains `{name}` | The earlier rule did not use `apply_as: "var:name"`, or its extraction path did not match. Variable names are case-sensitive. |
| `last step must have at least one extract rule` | Add a final extraction that produces an application header or cookie. Intermediate variables alone are not scan credentials. |
| The banner prints a scan ID, then `session initialization failed` | The scan stopped before discovery or assessment. The scan ID does not mean findings were produced. |
| Requests include another environment | Use `--scope-origin strict`, especially when the active project already contains records from several environments. |

Do not print response bodies while debugging production credentials. Prefer a
dedicated test account and rotate credentials that have appeared in shell
history, logs, or support transcripts.

## Login Request Lifecycle

A login request goes to the host the scan is about to attack, so it is treated
as target traffic:

- It follows `--proxy` (and `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` minus
  `NO_PROXY`), resolved exactly as the scan's own requests are, so a
  `localhost` target is proxied too unless `NO_PROXY` names it. A proxy log therefore shows the login alongside the
  scan it authenticated.
- It accepts self-signed, expired and wrong-host certificates, like every other
  request to the target.
- It is cancellable: Ctrl-C during setup aborts the in-flight login instead of
  waiting out its timeout.

Two bounds apply. Each login request has its own 30s timeout, and **all** login
flows together — every session, every step — share a total budget of 2 minutes.
A flow that exceeds the total fails naming the session and step it stopped on,
rather than letting six three-step flows spend nine silent minutes before the
first scan request.

When a login fails and the scan continues anyway (`--auth-best-effort`, or a
session loaded from the database), DynamicAssessment prints
`configured authentication could not be applied — assessment runs
unauthenticated` and the phase is recorded as partial with the reason
`auth_unavailable`, plus `login_budget`, `cancelled` or `scan_budget` naming the
cause. See [Scan completeness](../api-references/scan.md#scan-completeness).

## Current Authentication Limitations

- Only sessions with a `check` block, or an OAuth2 login whose token reports
  `expires_in`, are re-logged in mid-scan (see
  [In-scan re-login](#in-scan-re-login)); others log in once during scan
  initialization, so a token's lifetime must cover the scan.
- There is no browser-driven login type in the session schema. For a login
  that only works in a browser (JavaScript SDKs, CAPTCHA-free SSO redirects),
  use the agent swarm's browser auth phase (`vigolium agent swarm --browser
  --browser-auth`), which writes an `auth-config.yaml` the scan phases then
  use, or capture a session and pass it as static headers.
- Re-login does not reach the spidering browser, which keeps the credentials it
  launched with, nor a known-issue scan already running: nuclei takes a
  snapshot of the headers when its phase starts (it gets the newest generation
  at that point).
- Work lost while a session was logged out is counted
  (`responses_while_logged_out`), not re-queued.
- Sessions loaded from the database have no `check`/`reauth` columns, so they
  are never re-logged in.
- Pass multi-step and OAuth2 configurations directly with `--auth-file`.
  `vigolium auth load` currently persists only single-step login fields, so a
  stored multi-step or OAuth2 session comes back as the static headers its
  last login produced, and is not re-logged in.

## Session Strategy Configuration

Session behavior is configured under `scanning_strategy.session` in `vigolium-configs.yaml` (see `public/vigolium-configs.example.yaml` for the full annotated example).

```yaml
scanning_strategy:
  session:
    # Directory where session files are stored.
    # When --auth-file receives a bare name (e.g. "myapp"), the scanner
    # resolves it as <session_dir>/myapp.yaml (or .yml, .json).
    # Default: ~/.vigolium/sessions/
    session_dir: ~/.vigolium/sessions/

    # Apply primary session headers during discovery and spidering phases.
    # When false, those phases run unauthenticated and credentials are only
    # used during the dynamic-assessment phase.
    # Default: true
    use_in_discovery: true

    # Enable cross-session IDOR/BOLA replay with compare sessions.
    # When true and multiple sessions are defined, the authz-compare module
    # replays primary-session requests with each compare session's credentials.
    # When false, compare sessions are ignored even if defined.
    # Default: true
    compare_enabled: true

    # Defaults for every session's `check` block: each fills the value a
    # session leaves unset (a session's own value always wins).
    # check.interval: proactive logged-in probe at most this often ("2m").
    reauth_interval: ""

    # check.logged_out.status: statuses that mean "logged out" (e.g. [401, 440]).
    reauth_on_status: []

    # check.url: the protected URL `vigolium auth check` probes when --url is
    # not given. A path resolves against the target origin.
    validate_url: ""
```

### Field Reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `session_dir` | string | `~/.vigolium/sessions/` | Directory for session file lookup. `--auth-file myapp` (bare name) resolves to `<session_dir>/myapp.yaml` (tries `.yaml`, `.yml`, `.json` in order). Supports `~` expansion. |
| `use_in_discovery` | bool | `true` | When `true`, the primary session's headers are injected into the requester used for discovery and spidering. When `false`, those phases run unauthenticated — useful for mapping the public attack surface first, then scanning authenticated. |
| `compare_enabled` | bool | `true` | When `true`, compare sessions are created and the `authz-compare` module is activated for IDOR/BOLA testing. When `false`, compare sessions are ignored even if defined — handy when you only need authenticated scanning without authorization comparison. |
| `reauth_interval` | duration | `""` | Default `check.interval` for sessions that do not set one. Must parse as a Go duration. |
| `reauth_on_status` | []int | `[]` | Default `check.logged_out.status` for sessions that do not set one. |
| `validate_url` | string | `""` | Default `check.url`: an `http(s)` URL or a `/path`. `vigolium auth check` uses it when `--url` is not given. |

These three are defaults for the [logged-in check](#logged-in-check), and so
for [in-scan re-login](#in-scan-re-login): a session that gets a `check` block
from them is sampled and re-logged in like one that declares it.

### Session Directory Resolution

When `--auth-file` receives a bare name (no path separators, no extension, fewer than 3 colon-separated parts), the scanner resolves it from `session_dir`. Extensions are tried in order: `.yaml`, `.yml`, `.json`.

```bash
# These are all equivalent when session_dir is ~/.vigolium/sessions/
vigolium scan https://app.com --auth-file myapp
vigolium scan https://app.com --auth-file ~/.vigolium/sessions/myapp.yaml
vigolium scan https://app.com --auth-file ~/.vigolium/sessions/myapp.json
```

If the bare name has no matching file with any extension, `.yaml` is appended as the default. Absolute paths and relative paths with directory separators (e.g. `./sessions/myapp.json`) bypass `session_dir` and are used as-is.

To change the lookup directory:

```yaml
scanning_strategy:
  session:
    session_dir: /opt/vigolium/shared-sessions/
```

### Common Patterns

**Unauthenticated discovery, authenticated scanning:**

```yaml
scanning_strategy:
  session:
    use_in_discovery: false
```

Crawls the public-facing site first, then applies session headers only during the dynamic-assessment phase. This is useful when you want to see what an unauthenticated attacker can discover before testing the authenticated surface.

**Authenticated scanning without IDOR testing:**

```yaml
scanning_strategy:
  session:
    compare_enabled: false
```

Useful when you only need to scan behind a login wall but don't have multiple user roles to compare. The primary session's credentials are applied to all phases, but no compare requesters are created and the `authz-compare` module stays inactive.

**Team shared sessions directory:**

```yaml
scanning_strategy:
  session:
    session_dir: /shared/team/vigolium-sessions/
```

Point all team members to a shared directory so `--auth-file staging-admin` resolves the same file for everyone.

Scanning profiles (`~/.vigolium/profiles/`) can also override session strategy values — useful for having a "quick unauthenticated" profile alongside a "deep authenticated" profile.

## Using Session Config with Agent Modes

Agent modes (`swarm`, `autopilot`) can prepare authentication from source
analysis or explicit credentials. Swarm persists generated native-session
configuration as `auth-config.yaml` in its session directory.

With `--source`, Swarm can discover login flows and feed the generated config
into recon, discovery, and native scanning automatically.

`agent swarm` and `agent autopilot` take the native `--auth-file` (repeatable,
`--session-file` alias, bare names resolved against
`scanning_strategy.session.session_dir`), with the same loader and validation
as `vigolium scan`, so a file that works for a scan works here and a broken one
fails before the run starts:

```bash
# Swarm with native session files (multi-step, OAuth2, check/reauth all kept)
vigolium agent swarm \
  --target https://app.com \
  --auth-file ./admin.yaml --auth-file ./user.yaml

# Autopilot: the sessions log in before the run, the pre-scan uses them, and
# they are stored for the target so the operator's list_auth_sessions and
# replay_request tools can use them
vigolium agent autopilot --target https://app.com --auth-file ./admin.yaml
```

Swarm hands one file to its native phases as is and merges several into
`auth-config.yaml` in its session directory (native format, mode 0600,
`${ENV}` left for the loader to expand). Static headers of the primary session
also go to recon. `--auth-file` and `--auth-config` are mutually exclusive;
either one skips `--browser-auth` and the `--cookie`/`--header`/`--login-curl`
synthesis.

Swarm's older `--auth-config` takes an agent-format `auth-config.yaml` as is.
A native session file given to `--auth-config` is detected and loaded as
`--auth-file`:

```bash
vigolium agent swarm \
  --target https://app.com \
  --auth-config ./auth-config.yaml
```

## Examples

### Scan a REST API with Bearer Token

```bash
vigolium scan https://api.example.com \
  --auth "admin:Authorization:Bearer eyJhbG..."
```

### Scan with Cookie-Based Auth

```bash
vigolium scan https://app.example.com \
  --auth "user:Cookie:PHPSESSID=abc123; csrftoken=xyz"
```

### Full IDOR Test with Login Automation (YAML)

```bash
export ADMIN_USER=admin ADMIN_PASS=admin123
export USER_NAME=user1 USER_PASS=user123

vigolium scan https://app.example.com \
  --auth-file ./auth-config.yaml \
  --module-tag access-control
```

### Full IDOR Test with Login Automation (JSON)

```bash
export ADMIN_USER=admin ADMIN_PASS=admin123
export USER_NAME=user1 USER_PASS=user123

vigolium scan https://app.example.com \
  --auth-file ./auth-config.json \
  --module-tag access-control
```

### Combine with Other Scan Options

Auth flags work with all other scan options:

```bash
vigolium scan https://app.example.com \
  --auth-file ./auth-config.json \
  --strategy lite \
  --only dynamic-assessment \
  --concurrency 10 \
  --format html -o report.html
```

### One-Liner JSON Auth Config

For quick testing or CI scripts, you can write a JSON config inline:

```bash
echo '{"sessions":[{"name":"admin","role":"primary","headers":{"Authorization":"Bearer '"$TOKEN"'"}}]}' > /tmp/auth.json
vigolium scan https://app.com --auth-file /tmp/auth.json
```

### Agent-Generated Session Config

When an AI agent discovers auth flows in source code, it produces JSON like:

```json
{
  "sessions": [
    {
      "name": "default_user",
      "role": "primary",
      "login": {
        "url": "https://app.com/api/login",
        "method": "POST",
        "content_type": "application/json",
        "body": "{\"email\":\"test@test.com\",\"password\":\"testpassword\"}",
        "extract": [
          {
            "source": "json",
            "path": "$.token",
            "apply_as": "Authorization: Bearer {value}"
          }
        ]
      }
    }
  ]
}
```

This can be saved and reused across scans:

```bash
vigolium scan https://app.com --auth-file ./agent-generated-auth.json
```
