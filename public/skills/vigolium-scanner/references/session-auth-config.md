# Session / Auth Configuration

Session configuration enables authenticated scanning across all agent modes and standalone scans. Pipeline Phase 0 (source analysis) can auto-generate this configuration, or it can be provided manually via `--auth-config`.

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
| `apply_as` | string | Header template, e.g. `"Authorization: Bearer {value}"` |

## Managing Sessions with `vigolium session`

The `vigolium session` command manages session configs in the database:

```bash
# Load session config from a file
vigolium session load auth-config.yaml --host example.com

# Load from stdin
cat session-config.json | vigolium session load

# Load agent-generated session config (auto-detected from path)
vigolium session load ~/.vigolium/agent-sessions/agt-xxx/session-config.json

# Load a raw HTTP login request (auto-discovers tokens from response)
cat login-req.txt | vigolium session load --name admin --host example.com

# Skip login flow validation
vigolium session load sessions.json --no-validate

# Validate session config syntax before loading
vigolium session lint auth-config.yaml
cat session-config.json | vigolium session lint --stdin

# List loaded sessions
vigolium session list
vigolium session ls --host example.com

# Generate TOTP code for 2FA login flows
vigolium session totp --secret JBSWY3DPEHPK3PXP
```

### `vigolium session load` Flags

| Flag | Description |
|------|-------------|
| `--host` | Hostname to associate sessions with (derived from login URL if omitted) |
| `--no-validate` | Skip executing login flows for validation |
| `--source` | Source label for the session rows (default: `"cli"`) |
| `--agent-format` | Force parsing as agent session-config.json format |
| `--name` | Session name (used with raw HTTP request input) |

## Usage

### Auto-Generated from Source Analysis (Pipeline Phase 0)

```bash
# Provide source code — the agent analyzes auth code and generates session config automatically
vigolium agent pipeline -t http://localhost:3000 --source ~/projects/my-app

# Session config is written to a temp file and applied to all subsequent phases
# (discovery, scanning, triage all use authenticated requests)
```

### Manual Auth Config File

```bash
# Pass a YAML auth config file to any scan command
vigolium scan -t https://example.com --auth-config auth.yaml

# Works with scan-url too
vigolium scan-url https://example.com/api/admin --auth-config auth.yaml

# JSON format works the same way
vigolium scan -t https://example.com --auth-config auth.json
```

### Inline Sessions

```bash
# Simple inline session (name:Header:value format)
vigolium scan -t https://example.com --session "admin:Cookie:session_id=abc123"

# Bearer token
vigolium scan -t https://example.com --session "user1:Authorization:Bearer eyJhbGciOi..."

# Multiple sessions for IDOR testing
vigolium scan -t https://example.com \
  --session "admin:Authorization:Bearer admin-token" \
  --session "user:Authorization:Bearer user-token"
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

For applications requiring multiple requests to authenticate (e.g., CSRF token + login):

```yaml
sessions:
  - name: csrf_login
    role: primary
    login:
      steps:
        - url: https://example.com/login
          method: GET
          extract:
            - source: regex
              pattern: 'name="csrf_token" value="([^"]+)"'
              apply_as: "X-CSRF-Token: {value}"
            - source: cookie
              name: session_id
        - url: https://example.com/login
          method: POST
          content_type: application/x-www-form-urlencoded
          body: "username=admin&password=secret&csrf_token={csrf_token}"
          extract:
            - source: cookie
              name: session_id
```

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
