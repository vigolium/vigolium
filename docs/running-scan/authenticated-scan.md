# Authenticated Scanning

Vigolium supports multi-session authenticated scanning via the `--session`, `--session-file`, and `--auth-config` flags. This enables scanning behind login walls and detecting authorization bypass vulnerabilities (IDOR/BOLA).

## Quick Start

```bash
# Inline session (simplest)
vigolium scan https://app.com --session "admin:Cookie:session_id=abc123"

# Session YAML file
vigolium scan https://app.com --session-file ./admin-session.yaml

# Full auth config with multiple sessions
vigolium scan https://app.com --auth-config ./auth-config.yaml
```

## Authentication Flags

| Flag | Description |
|------|-------------|
| `--session` | Inline session in `name:Header:value` format. Repeatable. |
| `--session-file` | Path to an individual session YAML file. Repeatable. |
| `--auth-config` | Path to auth-config YAML file with all session definitions. |

All three flags can be combined. If no session is explicitly marked as `primary`, the first session loaded is used as the primary.

## Session Roles

Each session has a **role** that determines how it is used during the scan:

- **`primary`** — The main session. Used for discovery, spidering, and as the default requester during dynamic assessment. There should be exactly one primary session.
- **`compare`** — Comparison sessions for IDOR/BOLA testing. During dynamic assessment, every request made by the primary session is replayed with each compare session's credentials. If a compare session can access resources it shouldn't, the `authz-compare` module flags it.

## Inline Sessions

The `--session` flag accepts sessions in `name:Header:value` format:

```bash
# Single session with a cookie
vigolium scan https://app.com --session "admin:Cookie:session_id=abc123"

# Bearer token
vigolium scan https://app.com --session "user1:Authorization:Bearer eyJhbGciOi..."

# Multiple sessions for IDOR testing
vigolium scan https://app.com \
  --session "admin:Cookie:session=admin_token" \
  --session "regular:Cookie:session=user_token"
```

Values containing colons are handled correctly — only the first two colons are used as delimiters.

## Session YAML Files

For sessions with multiple headers or login flows, use YAML files.

### Static Headers

The simplest session file provides fixed headers:

```yaml
name: admin
role: primary
headers:
  Cookie: "session_id=abc123"
  Authorization: "Bearer mytoken"
```

Use with:

```bash
vigolium scan https://app.com --session-file ./admin-session.yaml
```

Session files are resolved from the configured `session_dir` (default `~/.vigolium/sessions/`) if the path is not absolute. See [Session Strategy Configuration](#session-strategy-configuration) below.

### Login Flows

Session files can define automated login flows. The scanner executes the login request at scan start and extracts credentials from the response:

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

#### Extraction Sources

| Source | Description | Example |
|--------|-------------|---------|
| `json` | Extract a value from the JSON response body using dot-notation. | `path: "$.token"` |
| `cookie` | Extract cookies from `Set-Cookie` response headers. Omit `name` to extract all cookies. | `name: "session_id"` |
| `header` | Extract a value from a response header. | `name: "X-Auth-Token"` |

The `apply_as` field defines how the extracted value is applied as a request header. Use `{value}` as a placeholder.

## Auth Config File

An auth-config YAML file defines all sessions in one place under a `sessions` key:

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

Use with:

```bash
vigolium scan https://app.com --auth-config ./auth-config.yaml
```

## Environment Variables

Session YAML files support `${VAR}` syntax for secrets. This keeps credentials out of config files:

```bash
export ADMIN_USER=admin
export ADMIN_PASS=s3cret
vigolium scan https://app.com --auth-config ./auth-config.yaml
```

All `${VAR}` references in session files are expanded from the environment at load time.

## IDOR/BOLA Testing

To test for authorization bypass vulnerabilities, define at least two sessions — one primary and one or more compare sessions:

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

The built-in `authz-compare` module automatically activates when compare sessions are present. It replays primary session requests with compare session credentials and flags responses that indicate broken access control.

### How Detection Works

1. The primary session makes a request and gets a response (e.g., `GET /api/users/42` → 200 OK with user data).
2. The same request is replayed with each compare session's credentials.
3. If a compare session also receives a successful response with similar content, the module reports a potential IDOR/BOLA finding with **High** severity.

### Filtering to Auth Modules Only

To run only authorization testing without other active modules:

```bash
vigolium scan https://app.com \
  --auth-config ./auth-config.yaml \
  --module-tag access-control
```

## How Sessions Affect Scan Phases

| Phase | Session Usage |
|-------|---------------|
| Discovery / Spidering | Primary session only (controlled by `use_in_discovery`) |
| Dynamic Assessment | Primary session for main scanning; compare sessions for IDOR/BOLA replay (controlled by `compare_enabled`) |

## Session Strategy Configuration

Session behavior is configured under `scanning_strategy.session` in `vigolium-configs.yaml` (see `public/vigolium-configs.example.yaml` for the full annotated example).

```yaml
scanning_strategy:
  session:
    # Directory where session YAML files are stored.
    # When --session-file receives a bare name (e.g. "myapp"), the scanner
    # resolves it as <session_dir>/myapp.yaml.
    # Default: ~/.vigolium/sessions/
    session_dir: ~/.vigolium/sessions/

    # Apply primary session headers during discovery and spidering phases.
    # When false, those phases run unauthenticated and credentials are only
    # used during dynamic assessment.
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
| `session_dir` | string | `~/.vigolium/sessions/` | Directory for session YAML file lookup. `--session-file myapp` resolves to `<session_dir>/myapp.yaml`. Supports `~` expansion. |
| `use_in_discovery` | bool | `true` | When `true`, the primary session's headers are injected into the requester used for discovery and spidering. When `false`, those phases run unauthenticated — useful for mapping the public attack surface first, then scanning authenticated. |
| `compare_enabled` | bool | `true` | When `true`, compare sessions are created and the `authz-compare` module is activated for IDOR/BOLA testing. When `false`, compare sessions are ignored even if defined — handy when you only need authenticated scanning without authorization comparison. |
| `reauth_interval` | duration | `""` (disabled) | Go duration string (e.g. `"15m"`, `"1h"`). When set, login flows are re-executed at this interval to refresh tokens that expire mid-scan. |
| `reauth_on_status` | []int | `[]` (disabled) | HTTP status codes that trigger reactive re-authentication. When the primary session receives one of these codes, its login flow is re-executed immediately and the request is retried. |
| `validate_url` | string | `""` (disabled) | Relative or absolute URL to GET after login. The scanner checks for a 2xx response to confirm credentials are working before proceeding. Catches bad credentials early. |

### Session Directory Resolution

When `--session-file` receives a bare name (no path separators), the scanner resolves it from `session_dir`:

```bash
# These are equivalent when session_dir is ~/.vigolium/sessions/
vigolium scan https://app.com --session-file myapp
vigolium scan https://app.com --session-file ~/.vigolium/sessions/myapp.yaml
```

The `.yaml` extension is appended automatically if missing. Absolute paths and relative paths with directory separators (e.g. `./sessions/myapp.yaml`) bypass `session_dir` and are used as-is.

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

Crawls the public-facing site first, then applies session headers only during dynamic assessment. This is useful when you want to see what an unauthenticated attacker can discover before testing the authenticated surface.

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

Point all team members to a shared directory so `--session-file staging-admin` resolves the same file for everyone.

Scanning profiles (`~/.vigolium/profiles/`) can also override session strategy values — useful for having a "quick unauthenticated" profile alongside a "deep authenticated" profile.

## Examples

### Scan a REST API with Bearer Token

```bash
vigolium scan https://api.example.com \
  --session "admin:Authorization:Bearer eyJhbG..."
```

### Scan with Cookie-Based Auth

```bash
vigolium scan https://app.example.com \
  --session "user:Cookie:PHPSESSID=abc123; csrftoken=xyz"
```

### Full IDOR Test with Login Automation

```bash
export ADMIN_USER=admin ADMIN_PASS=admin123
export USER_NAME=user1 USER_PASS=user123

vigolium scan https://app.example.com \
  --auth-config ./auth-config.yaml \
  --module-tag access-control
```

### Combine with Other Scan Options

Auth flags work with all other scan options:

```bash
vigolium scan https://app.example.com \
  --auth-config ./auth-config.yaml \
  --strategy blackbox \
  --only dynamic-assessment \
  --concurrency 10 \
  --format html -o report.html
```
