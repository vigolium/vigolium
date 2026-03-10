# Session / Auth Configuration

Session configuration enables authenticated scanning across all agent modes and standalone scans. Pipeline Phase 0 (source analysis) can auto-generate this configuration, or it can be provided manually via `--auth-config`.

## Session Config Format

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
        - source: json          # "json", "cookie", or "header"
          path: "$.authentication.token"  # JSONPath (for json source)
          apply_as: "Authorization: Bearer {value}"
  - name: admin_user
    role: compare
    headers:
      Authorization: "Bearer admin-static-token"
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
| `login.extract` | []object | How to extract auth token from login response |

## Extract Rule Fields

| Field | Type | Description |
|-------|------|-------------|
| `source` | string | Where to extract from: `"json"`, `"cookie"`, `"header"` |
| `name` | string | Cookie name or header name (for cookie/header sources) |
| `path` | string | JSONPath expression (for json source) |
| `apply_as` | string | Header template, e.g. `"Authorization: Bearer {value}"` |

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

### Static API Key (No Login Required)

```yaml
sessions:
  - name: api_key_user
    role: primary
    headers:
      X-API-Key: "my-api-key-here"
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
