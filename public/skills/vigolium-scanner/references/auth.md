# Session / Auth Configuration

> **Related:** [scanning.md](scanning.md) for where `--auth-file` applies · [agent-modes.md](agent-modes.md) for agent-generated sessions

Session configuration enables authenticated scanning across all agent modes and standalone scans. Pipeline Phase 0 (source analysis) can auto-generate this configuration, or it can be provided manually via the repeatable `--auth-file` and `--auth` flags.

| Flag | Accepts | Repeatable |
|------|---------|------------|
| `--auth-file <path>` | YAML/JSON file (single session **or** `sessions:` bundle), or a bare name resolved against `scanning_strategy.session.session_dir` | yes |
| `--auth <name:Header:value>` | Inline session — name and header injected as static headers | yes |

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
| `login.type` | string | Shorthand preset: `"bearer"` (JSON body → Authorization header) or `"cookie"` (capture all Set-Cookie headers). Auto-expands into extract rules |
| `login.token_path` | string | JSONPath for token extraction (used with `type` shorthand) |
| `login.extract` | []object | How to extract auth token from login response |
| `login.expect` | object | Response validation: `status` ([]int) and/or `body_contains` (string) |
| `login.steps` | []object | Multi-step login flow. When set, parent URL/Method/Body/Extract are ignored |
| `login_request` | string | Raw HTTP request string for the login flow (alternative to structured login) |

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

The `vigolium auth` command manages session configs in the database:

```bash
# Load session config from a file
vigolium auth load auth-config.yaml --host example.com

# Load from stdin
cat session-config.json | vigolium auth load

# Load agent-generated session config (auto-detected from path)
vigolium auth load ~/.vigolium/agent-sessions/<uuid>/session-config.json

# Load a raw HTTP login request (auto-discovers tokens from response)
cat login-req.txt | vigolium auth load --name admin --host example.com

# Skip login flow validation
vigolium auth load sessions.json --no-validate

# Validate session config syntax before use
vigolium auth lint auth-config.yaml
cat session-config.json | vigolium auth lint --stdin

# List loaded sessions
vigolium auth list
vigolium auth ls --host example.com

# Generate TOTP code for 2FA login flows
vigolium auth totp --secret JBSWY3DPEHPK3PXP
```

`auth lint` validates the configuration structure without executing remote
login requests. Pass multi-step configurations directly to scans with
`--auth-file`; `auth load` currently validates and persists only single-step
login fields, so a stored multi-step flow will not round-trip correctly.

### `vigolium auth load` Flags

| Flag | Description |
|------|-------------|
| `--host` | Hostname to associate sessions with (derived from login URL if omitted) |
| `--no-validate` | Skip executing login flows for validation |
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
# Pass a YAML auth file to any scan command
vigolium scan -t https://example.com --auth-file auth.yaml

# Works with scan-url too
vigolium scan-url https://example.com/api/admin --auth-file auth.yaml

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

- Login flows hydrate once when a native scan starts. The configured
  `reauth_interval`, `reauth_on_status`, and `validate_url` fields are reserved
  but are not currently enforced.
- Multi-step requests cannot define arbitrary per-step headers. Provider
  endpoints requiring Basic auth, `Origin`, or SDK-specific headers may need an
  authorized server-side test endpoint or a pre-acquired static token. Do not
  put provider secrets in the URL.
- Variable substitution applies to subsequent step URLs and bodies only.

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
