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

### Extraction Sources

| Source | Description | Example |
|--------|-------------|---------|
| `json` | Extract a value from the JSON response body using dot-notation. | `path: "$.token"` |
| `cookie` | Extract cookies from `Set-Cookie` response headers. Omit `name` to extract all cookies. | `name: "session_id"` |
| `header` | Extract a value from a response header. | `name: "X-Auth-Token"` |

The `apply_as` field defines how the extracted value is applied as a request header. Use `{value}` as a placeholder.

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
│   │   ├── url             # (string, required) Login endpoint URL
│   │   ├── method          # (string, required) HTTP method (POST, GET, etc.)
│   │   ├── content_type    # (string) Request Content-Type
│   │   ├── body            # (string) Request body
│   │   └── extract[]       # (array, required) Credential extraction rules
│   │       ├── source      # (string) "json", "cookie", or "header"
│   │       ├── name        # (string) Cookie/header name to extract
│   │       ├── path        # (string) JSONPath for json source
│   │       └── apply_as    # (string) Header template, e.g. "Authorization: Bearer {value}"
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

    # Re-execute login flows at this interval to refresh expiring tokens.
    # Format: Go duration string (e.g. "15m", "1h", "30m").
    # Default: "" (disabled — login once at scan start)
    reauth_interval: ""

    # Trigger reactive re-authentication when the primary session receives
    # one of these HTTP status codes. The login flow is re-executed immediately
    # and the failed request is retried.
    # Default: [] (disabled)
    reauth_on_status: []

    # URL to GET after login to verify that extracted credentials work.
    # The scanner checks for a 2xx response before proceeding.
    # Can be a relative path (resolved against the target) or absolute URL.
    # Default: "" (disabled)
    validate_url: ""
```

### Field Reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `session_dir` | string | `~/.vigolium/sessions/` | Directory for session file lookup. `--auth-file myapp` (bare name) resolves to `<session_dir>/myapp.yaml` (tries `.yaml`, `.yml`, `.json` in order). Supports `~` expansion. |
| `use_in_discovery` | bool | `true` | When `true`, the primary session's headers are injected into the requester used for discovery and spidering. When `false`, those phases run unauthenticated — useful for mapping the public attack surface first, then scanning authenticated. |
| `compare_enabled` | bool | `true` | When `true`, compare sessions are created and the `authz-compare` module is activated for IDOR/BOLA testing. When `false`, compare sessions are ignored even if defined — handy when you only need authenticated scanning without authorization comparison. |
| `reauth_interval` | duration | `""` (disabled) | Go duration string (e.g. `"15m"`, `"1h"`). When set, login flows are re-executed at this interval to refresh tokens that expire mid-scan. |
| `reauth_on_status` | []int | `[]` (disabled) | HTTP status codes that trigger reactive re-authentication. When the primary session receives one of these codes, its login flow is re-executed immediately and the request is retried. |
| `validate_url` | string | `""` (disabled) | Relative or absolute URL to GET after login. The scanner checks for a 2xx response to confirm credentials are working before proceeding. Catches bad credentials early. |

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

**Long-running scan with token refresh:**

```yaml
scanning_strategy:
  session:
    reauth_interval: "30m"
    reauth_on_status: [401, 403]
    validate_url: "/api/whoami"
```

Re-executes login flows every 30 minutes proactively, and also reactively when a 401 or 403 is received. The `validate_url` confirms credentials work after each login before resuming scanning.

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
