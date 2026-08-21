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
structure only; the remote requests and extraction rules are exercised when a
scan hydrates the session.

```bash
vigolium auth lint ./multi-step-token-exchange.yaml
vigolium scan \
  https://app.example.com \
  https://api.example.com \
  --auth-file ./multi-step-token-exchange.yaml \
  --scope-origin strict
```

> **Per-step header limitation:** a multi-step login step currently supports
> `url`, `method`, `content_type`, `body`, `extract`, and `expect`, but not
> arbitrary request headers. Browser SDK endpoints that require Basic auth,
> `Origin`, or SDK-specific headers cannot always be reproduced directly. Use
> an authorized server-side test endpoint or a pre-acquired static token rather
> than putting secrets in the URL.

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
│   │   ├── type            # (string) "bearer" or "cookie" shorthand
│   │   ├── token_path      # (string) Token path used by bearer shorthand
│   │   ├── expect          # (object) status[] and/or body_contains
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
│   │       ├── body        # (string) Supports {name} variables
│   │       ├── expect      # (object) status[] and/or body_contains
│   │       └── extract[]   # (array; required on the final step)
│   └── login_request       # (string) Raw HTTP request for login (alternative to login)
```

Only one of `headers`, `login`, or `login_request` can be set per session.

## Environment Variables

Session files (both YAML and JSON) support `${VAR}` syntax for secrets. This keeps credentials out of config files:

```bash
export ADMIN_USER=admin
export ADMIN_PASS=s3cret
vigolium scan https://app.com --auth-file ./auth-config.json
```

All `${VAR}` references are expanded from the environment at load time, before format parsing.

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

## Validation and Troubleshooting

| Symptom | Meaning and next step |
|---------|-----------------------|
| `auth lint` succeeds but scan hydration fails | Lint validates structure without contacting the login services. Check the failing step's status, response shape, and extraction path. |
| `cookie "token" not found in login response` | The response did not include a matching `Set-Cookie` header. If it returned JSON, use `source: json`; if browser JavaScript creates the cookie, build the `Cookie` header with `apply_as`. |
| A later request still contains `{name}` | The earlier rule did not use `apply_as: "var:name"`, or its extraction path did not match. Variable names are case-sensitive. |
| `last step must have at least one extract rule` | Add a final extraction that produces an application header or cookie. Intermediate variables alone are not scan credentials. |
| The banner prints a scan ID, then `session initialization failed` | The scan stopped before discovery or assessment. The scan ID does not mean findings were produced. |
| Requests include another environment | Use `--scope-origin strict`, especially when the active project already contains records from several environments. |

Do not print response bodies while debugging production credentials. Prefer a
dedicated test account and rotate credentials that have appeared in shell
history, logs, or support transcripts.

## Current Authentication Limitations

- Login flows are hydrated once during scan initialization. The configured
  `reauth_interval`, `reauth_on_status`, and `validate_url` fields are reserved
  but are not currently enforced during native scans. Ensure a token's lifetime
  covers the scan or divide a long scan into shorter runs.
- Pass multi-step configurations directly with `--auth-file`. `vigolium auth
  load` currently validates and persists only single-step login fields, so a
  stored multi-step flow will not round-trip correctly.
- Multi-step variables are substituted only in subsequent step URLs and bodies.
  Arbitrary per-step headers are not part of the current schema.

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

    # Reserved for future runtime reauthentication; currently not enforced.
    reauth_interval: ""

    # Reserved for future runtime reauthentication; currently not enforced.
    reauth_on_status: []

    # Reserved for future post-login validation; currently not enforced.
    validate_url: ""
```

### Field Reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `session_dir` | string | `~/.vigolium/sessions/` | Directory for session file lookup. `--auth-file myapp` (bare name) resolves to `<session_dir>/myapp.yaml` (tries `.yaml`, `.yml`, `.json` in order). Supports `~` expansion. |
| `use_in_discovery` | bool | `true` | When `true`, the primary session's headers are injected into the requester used for discovery and spidering. When `false`, those phases run unauthenticated — useful for mapping the public attack surface first, then scanning authenticated. |
| `compare_enabled` | bool | `true` | When `true`, compare sessions are created and the `authz-compare` module is activated for IDOR/BOLA testing. When `false`, compare sessions are ignored even if defined — handy when you only need authenticated scanning without authorization comparison. |
| `reauth_interval` | duration | `""` | Reserved; currently not enforced during native scans. |
| `reauth_on_status` | []int | `[]` | Reserved; currently not enforced during native scans. |
| `validate_url` | string | `""` | Reserved; currently not enforced during native scans. |

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

Swarm's equivalent of native `--auth-file` is `--auth-config`:

```bash
# Swarm with pre-configured auth
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
