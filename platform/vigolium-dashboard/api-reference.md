# Vigolium API Reference

Base URL: `http://localhost:9002` (default)

## Starting the Server

```bash
# No authentication (development)
vigolium server -A

# With API key
vigolium server --api-key "my-secret-key"

# Custom host/port
vigolium server -A --host 127.0.0.1 --service-port 8080
```

## Authentication

All endpoints registered after the auth middleware require a Bearer token when the server is started with `--api-key`. This includes `GET /`, `GET /health`, `GET /server-info`, and all `/api/*` routes.

```bash
curl -H "Authorization: Bearer my-secret-key" http://localhost:9002/api/stats
```

Public endpoints (no auth required): `GET /swagger/*`, `GET /metrics`.

---

## Endpoints

### GET / — App Info

Returns basic application metadata.

```bash
curl -s http://localhost:9002/ | jq .
```

```json
{
  "name": "vigolium",
  "version": "v0.0.1-alpha",
  "author": "@j3ssie",
  "docs": "https://docs.vigolium.io",
  "build_time": "2026-02-16T15:22:43Z",
  "commit": "67bdce4"
}
```

---

### GET /health — Health Check

Returns server health status.

```bash
curl -s http://localhost:9002/health | jq .
```

```json
{
  "status": "healthy",
  "timestamp": "2026-02-16T15:30:00Z"
}
```

---

### GET /server-info — Server Info

Returns detailed server information including uptime, database driver, queue depth, and record/finding totals.

```bash
curl -s http://localhost:9002/server-info | jq .
```

```json
{
  "name": "vigolium",
  "version": "v0.0.1-alpha",
  "author": "@j3ssie",
  "docs": "https://docs.vigolium.io",
  "build_time": "2026-02-16T15:22:43Z",
  "commit": "67bdce4",
  "uptime": "5m32s",
  "service_addr": "0.0.0.0:9002",
  "proxy_addr": "",
  "db_driver": "sqlite",
  "queue_depth": 0,
  "total_records": 1234,
  "total_findings": 42
}
```

---

### GET /swagger/* — Swagger UI

Interactive API documentation. Open in a browser.

```
http://localhost:9002/swagger/
```

The raw OpenAPI 3.0 spec is available at:

```bash
curl -s http://localhost:9002/swagger/doc.json | jq .info
```

---

### GET /metrics — Prometheus Metrics

Returns Prometheus-formatted metrics. No authentication required. Only available when the server is started with `--enable-metrics`.

```bash
curl -s http://localhost:9002/metrics
```

---

### GET /api/modules — List Modules

Returns all registered scanner modules (active and passive).

**Query parameters:**

| Parameter | Type   | Description                        |
|-----------|--------|------------------------------------|
| `search`  | string | Filter by module name, ID, or description |

```bash
# List all modules
curl -s http://localhost:9002/api/modules | jq .

# Search for XSS modules
curl -s 'http://localhost:9002/api/modules?search=xss' | jq .
```

```json
{
  "modules": [
    {
      "id": "xss-scanner",
      "name": "XSS Scanner",
      "description": "...",
      "short_description": "Reflected XSS detection",
      "confirmation_criteria": "Reflected payload appears unescaped in response body",
      "severity": "high",
      "type": "active"
    }
  ],
  "total": 1
}
```

---

### GET /api/http-records — List HTTP Records

Returns paginated HTTP request/response records stored in the database. Response and request bodies are excluded from list responses for performance.

**Query parameters:**

| Parameter      | Type   | Default | Description                                  |
|----------------|--------|---------|----------------------------------------------|
| `limit`        | int    | 50      | Number of records to return (max 500)        |
| `offset`       | int    | 0       | Offset for pagination                        |
| `domain`       | string |         | Filter by hostname (supports `*` wildcards)  |
| `method`       | string |         | Filter by HTTP method (comma-separated)      |
| `path`         | string |         | Filter by path (supports `*` wildcards)      |
| `status_code`  | string |         | Filter by status code (comma-separated)      |
| `content_type` | string |         | Filter by response content type              |
| `search`       | string |         | Search across URL and path                   |
| `source`       | string |         | Filter by ingestion source (e.g. `ingest-server`, `cli`) |
| `min_risk`     | int    |         | Filter by minimum risk score                 |
| `remark`       | string |         | Filter by remark                             |
| `sort`         | string | `created_at` | Sort field: `created_at`, `sent_at`, `method`, `path`, `status_code`, `response_time` |
| `order`        | string | `desc`  | Sort order: `asc` or `desc`                  |

```bash
# List recent records
curl -s http://localhost:9002/api/http-records | jq .

# Filter by domain
curl -s 'http://localhost:9002/api/http-records?domain=example.com' | jq .

# Filter by status code and method
curl -s 'http://localhost:9002/api/http-records?status_code=200,301&method=GET' | jq .

# Paginate
curl -s 'http://localhost:9002/api/http-records?limit=10&offset=20' | jq .

# Sort by response time descending
curl -s 'http://localhost:9002/api/http-records?sort=response_time&order=desc' | jq .

# Wildcard domain search
curl -s 'http://localhost:9002/api/http-records?domain=*.example.com' | jq .
```

```json
{
  "data": [
    {
      "uuid": "abc-123",
      "scheme": "https",
      "hostname": "example.com",
      "port": 443,
      "ip": "93.184.216.34",
      "method": "GET",
      "path": "/api/users",
      "url": "https://example.com/api/users",
      "http_version": "HTTP/1.1",
      "request_headers": {
        "User-Agent": ["Mozilla/5.0"],
        "Accept": ["application/json"]
      },
      "request_content_type": "",
      "request_content_length": 0,
      "request_hash": "a1b2c3d4",
      "status_code": 200,
      "status_phrase": "OK",
      "response_content_type": "application/json",
      "response_content_length": 512,
      "response_time_ms": 145,
      "response_words": 48,
      "has_response": true,
      "response_title": "User List",
      "parameters": [
        {
          "name": "page",
          "value": "1",
          "type": "url"
        }
      ],
      "sent_at": "2026-02-16T15:00:00Z",
      "source": "ingest-server",
      "remarks": ["has-auth-header"],
      "risk_score": 3,
      "created_at": "2026-02-16T15:00:00Z"
    }
  ],
  "total": 1234,
  "limit": 50,
  "offset": 0,
  "has_more": true
}
```

> **Note:** The fields `raw_request`, `raw_response`, `request_body`, and `response_body` are excluded from list responses for performance. Use `GET /api/http-records/:uuid` to access full bodies.

---

### GET /api/http-records/:uuid — Get HTTP Record Detail

Returns a single HTTP record by UUID, including full blob fields (`raw_request`, `raw_response`, `request_body`, `response_body`).

```bash
curl -s http://localhost:9002/api/http-records/abc-123 | jq .
```

```json
{
  "uuid": "abc-123",
  "scheme": "https",
  "hostname": "example.com",
  "port": 443,
  "method": "POST",
  "path": "/api/login",
  "url": "https://example.com/api/login",
  "status_code": 200,
  "raw_request": "POST /api/login HTTP/1.1\r\nHost: example.com\r\n...",
  "raw_response": "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n...",
  "request_body": "{\"user\":\"admin\",\"pass\":\"test\"}",
  "response_body": "{\"token\":\"eyJ...\"}",
  "created_at": "2026-02-16T15:00:00Z"
}
```

**Error responses:**

| Code | Condition            |
|------|----------------------|
| 400  | Missing UUID         |
| 404  | Record not found     |
| 503  | Database unavailable |

---

### GET /api/findings — List Findings

Returns paginated vulnerability findings.

**Query parameters:**

| Parameter     | Type   | Default    | Description                                       |
|---------------|--------|------------|---------------------------------------------------|
| `limit`       | int    | 50         | Number of findings to return (max 500)            |
| `offset`      | int    | 0          | Offset for pagination                             |
| `domain`      | string |            | Filter by hostname (supports `*` wildcards)       |
| `severity`    | string |            | Filter by severity (comma-separated): `critical`, `high`, `medium`, `low`, `info` |
| `scan_id`     | string |            | Filter by scan UUID                               |
| `module_name` | string |            | Filter by module name                             |
| `search`      | string |            | Search across description, module ID, matched_at  |
| `sort`        | string | `found_at` | Sort field: `found_at`, `created_at`, `severity`, `module_name`, `module_id`, `confidence` |
| `order`       | string | `desc`     | Sort order: `asc` or `desc`                       |

```bash
# List all findings
curl -s http://localhost:9002/api/findings | jq .

# Filter by severity
curl -s 'http://localhost:9002/api/findings?severity=critical,high' | jq .

# Filter by domain and module
curl -s 'http://localhost:9002/api/findings?domain=example.com&module_name=xss' | jq .

# Search findings
curl -s 'http://localhost:9002/api/findings?search=reflected' | jq .
```

```json
{
  "data": [
    {
      "id": 1,
      "http_record_uuids": ["abc-123"],
      "scan_uuid": "scan-456",
      "module_id": "xss-scanner",
      "module_name": "XSS Scanner",
      "description": "Reflected XSS via parameter 'q'",
      "severity": "high",
      "confidence": "firm",
      "tags": ["xss", "reflected"],
      "matched_at": ["https://example.com/search?q=test"],
      "extracted_results": ["<script>alert(1)</script>"],
      "request": "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\r\nHost: example.com\r\n\r\n",
      "response": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n...",
      "finding_hash": "e3b0c44298fc1c14",
      "found_at": "2026-02-16T15:05:00Z",
      "created_at": "2026-02-16T15:05:00Z"
    }
  ],
  "total": 42,
  "limit": 50,
  "offset": 0,
  "has_more": false
}
```

---

### GET /api/findings/:id — Get Finding Detail

Returns a single finding by its numeric ID.

```bash
curl -s http://localhost:9002/api/findings/1 | jq .
```

```json
{
  "id": 1,
  "http_record_uuids": ["abc-123"],
  "scan_uuid": "scan-456",
  "module_id": "xss-scanner",
  "module_name": "XSS Scanner",
  "description": "Reflected XSS via parameter 'q'",
  "severity": "high",
  "confidence": "firm",
  "tags": ["xss", "reflected"],
  "matched_at": ["https://example.com/search?q=test"],
  "extracted_results": ["<script>alert(1)</script>"],
  "request": "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\r\nHost: example.com\r\n\r\n",
  "response": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n...",
  "finding_hash": "e3b0c44298fc1c14",
  "found_at": "2026-02-16T15:05:00Z",
  "created_at": "2026-02-16T15:05:00Z"
}
```

**Error responses:**

| Code | Condition                      |
|------|--------------------------------|
| 400  | Invalid ID (not a number)      |
| 404  | Finding not found              |
| 503  | Database unavailable           |

---

### POST /api/ingest-http — Ingest HTTP Data

Import HTTP request/response data into the database for scanning. Supports multiple input formats.

**Request body:**

| Field                  | Type   | Required | Description                              |
|------------------------|--------|----------|------------------------------------------|
| `input_mode`           | string | Yes      | Input format (see modes below)           |
| `url`                  | string | No       | Override URL (used as base URL for some modes) |
| `content`              | string | No       | Raw content (plaintext)                  |
| `content_base64`       | string | No       | Base64-encoded content                   |
| `http_request_base64`  | string | No       | Base64-encoded raw HTTP request (for `burp_base64`) |
| `http_response_base64` | string | No       | Base64-encoded raw HTTP response (for `burp_base64`) |

**Input modes:**

| Mode                  | Description                          | Content field  |
|-----------------------|--------------------------------------|----------------|
| `url`                 | Single URL                           | `content`      |
| `url_file`            | Newline-separated list of URLs       | `content`      |
| `curl`                | Single curl command                  | `content`      |
| `burp_base64`         | Base64 raw HTTP request (+response)  | `http_request_base64` |
| `openapi` / `swagger` | OpenAPI/Swagger spec (JSON or YAML)  | `content`      |
| `postman_collection`  | Postman Collection v2                | `content`      |

#### Ingest a URL

```bash
curl -s -X POST http://localhost:9002/api/ingest-http \
  -H "Content-Type: application/json" \
  -d '{
    "input_mode": "url",
    "content": "https://example.com/api/users?id=1"
  }' | jq .
```

#### Ingest a curl command

```bash
curl -s -X POST http://localhost:9002/api/ingest-http \
  -H "Content-Type: application/json" \
  -d '{
    "input_mode": "curl",
    "content": "curl -X POST https://example.com/login -d \"user=admin&pass=test\""
  }' | jq .
```

#### Ingest a list of URLs

```bash
curl -s -X POST http://localhost:9002/api/ingest-http \
  -H "Content-Type: application/json" \
  -d '{
    "input_mode": "url_file",
    "content": "https://example.com/page1\nhttps://example.com/page2\nhttps://example.com/page3"
  }' | jq .
```

#### Ingest a raw HTTP request (base64)

```bash
# Base64-encode a raw HTTP request
REQ_B64=$(echo -n "GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n" | base64)

curl -s -X POST http://localhost:9002/api/ingest-http \
  -H "Content-Type: application/json" \
  -d "{
    \"input_mode\": \"burp_base64\",
    \"http_request_base64\": \"$REQ_B64\"
  }" | jq .
```

#### Ingest a raw HTTP request with a URL hint (base64)

Raw HTTP requests don't contain the scheme (`https` vs `http`) and the `Host` header alone may not reflect the actual target (e.g. behind a reverse proxy). Provide `url` alongside `http_request_base64` so the parser can resolve the correct scheme and hostname.

```bash
REQ_B64=$(echo -n "POST /api/login HTTP/1.1\r\nHost: internal-lb\r\nContent-Type: application/json\r\n\r\n{\"user\":\"admin\"}" | base64)

curl -s -X POST http://localhost:9002/api/ingest-http \
  -H "Content-Type: application/json" \
  -d "{
    \"input_mode\": \"burp_base64\",
    \"url\": \"https://app.example.com\",
    \"http_request_base64\": \"$REQ_B64\"
  }" | jq .
```

The `url` field provides the scheme (`https`) and the public hostname (`app.example.com`), overriding whatever `Host` header appeared in the raw request.

#### Ingest an OpenAPI spec

```bash
curl -s -X POST http://localhost:9002/api/ingest-http \
  -H "Content-Type: application/json" \
  -d "{
    \"input_mode\": \"openapi\",
    \"content_base64\": \"$(base64 < openapi.json)\"
  }" | jq .
```

**Response:**

```json
{
  "imported": 15,
  "skipped": 0,
  "errors": [],
  "message": "imported 15 requests from OpenAPI spec"
}
```

---

### GET /api/stats — Scan Statistics

Returns aggregated statistics about HTTP records, modules, and findings.

```bash
curl -s http://localhost:9002/api/stats | jq .
```

```json
{
  "http_records": {
    "total": 1234
  },
  "modules": {
    "active": { "total": 18, "enabled": 15 },
    "passive": { "total": 4, "enabled": 4 }
  },
  "findings": {
    "total": 42,
    "by_severity": {
      "critical": 2,
      "high": 10,
      "medium": 15,
      "low": 10,
      "info": 5
    }
  }
}
```

---

### GET /api/scope — View Scope Config

Returns the current scope configuration that controls which HTTP records are in scope for scanning.

```bash
curl -s http://localhost:9002/api/scope | jq .
```

```json
{
  "host": { "include": ["*"], "exclude": [] },
  "path": { "include": ["*"], "exclude": [] },
  "status_code": { "include": ["*"], "exclude": [] },
  "request_content_type": { "include": ["*"], "exclude": [] },
  "response_content_type": { "include": ["*"], "exclude": [] },
  "request_string": { "include": [], "exclude": [] },
  "response_string": { "include": [], "exclude": [] }
}
```

---

### POST /api/scope — Update Scope Config

Partially updates the scope configuration. Only provided fields are overwritten; omitted fields keep their current values. Changes are persisted to the config file on disk.

**Scope rules:**

Each scope rule has `include` and `exclude` lists. Exclude takes priority over include. Patterns support `*` wildcards.

```bash
# Exclude internal hosts
curl -s -X POST http://localhost:9002/api/scope \
  -H "Content-Type: application/json" \
  -d '{
    "host": {
      "exclude": ["*.internal.com", "localhost"]
    }
  }' | jq .

# Exclude specific status codes
curl -s -X POST http://localhost:9002/api/scope \
  -H "Content-Type: application/json" \
  -d '{
    "status_code": {
      "exclude": ["404", "500"]
    }
  }' | jq .

# Restrict scanning to specific hosts
curl -s -X POST http://localhost:9002/api/scope \
  -H "Content-Type: application/json" \
  -d '{
    "host": {
      "include": ["*.example.com", "api.target.io"],
      "exclude": ["cdn.example.com"]
    }
  }' | jq .

# Exclude static assets by path
curl -s -X POST http://localhost:9002/api/scope \
  -H "Content-Type: application/json" \
  -d '{
    "path": {
      "exclude": ["*.css", "*.js", "*.png", "*.jpg", "*.svg", "*.woff*"]
    }
  }' | jq .
```

**Response:**

```json
{
  "message": "Scope updated successfully",
  "scope": {
    "host": { "include": ["*"], "exclude": ["*.internal.com", "localhost"] },
    "path": { "include": ["*"], "exclude": [] },
    "status_code": { "include": ["*"], "exclude": [] },
    "request_content_type": { "include": ["*"], "exclude": [] },
    "response_content_type": { "include": ["*"], "exclude": [] },
    "request_string": { "include": [], "exclude": [] },
    "response_string": { "include": [], "exclude": [] }
  }
}
```

---

### GET /api/config — View Configuration

Returns the full server configuration as flattened dot-notation key-value pairs. Sensitive values (API keys, passwords, tokens) are redacted by default.

**Query parameters:**

| Parameter        | Type   | Default | Description                                  |
|------------------|--------|---------|----------------------------------------------|
| `filter`         | string |         | Substring match on key name                  |
| `show_sensitive` | string | `false` | Set to `true` to show unredacted sensitive values |

```bash
# View all config
curl -s http://localhost:9002/api/config | jq .

# Filter by section
curl -s 'http://localhost:9002/api/config?filter=scope' | jq .

# Show sensitive values
curl -s 'http://localhost:9002/api/config?show_sensitive=true' | jq .
```

```json
{
  "entries": [
    {
      "key": "database.driver",
      "value": "sqlite"
    },
    {
      "key": "database.enabled",
      "value": "true"
    },
    {
      "key": "notify.enabled",
      "value": "false"
    },
    {
      "key": "scope.applied_on_ingest",
      "value": "false"
    },
    {
      "key": "server.auth_api_key",
      "value": "********",
      "sensitive": true
    }
  ],
  "total": 5
}
```

---

### POST /api/config — Update Configuration

Updates one or more configuration values using dot-notation keys. Values are coerced to match the existing field type (bool, int, float, string, or comma-separated list). Changes are persisted to the config file on disk.

Reloadable sections (scope, notify, dynamic_assessment, mutation_strategy) take effect immediately. Server and database changes require a restart.

**Request body:** JSON object mapping dot-notation keys to string values.

```bash
# Update a single value
curl -s -X POST http://localhost:9002/api/config \
  -H "Content-Type: application/json" \
  -d '{
    "notify.enabled": "true"
  }' | jq .

# Update multiple values at once
curl -s -X POST http://localhost:9002/api/config \
  -H "Content-Type: application/json" \
  -d '{
    "notify.enabled": "true",
    "scope.applied_on_ingest": "true",
    "dynamic_assessment.extensions.enabled": "false"
  }' | jq .

# Update a list value (comma-separated)
curl -s -X POST http://localhost:9002/api/config \
  -H "Content-Type: application/json" \
  -d '{
    "dynamic_assessment.enabled_modules.active_modules": "xss-scanner,sqli-error-based,lfi-path-traversal"
  }' | jq .
```

**Response (success):**

```json
{
  "message": "Config updated successfully",
  "updated": [
    { "key": "notify.enabled", "value": "true" },
    { "key": "scope.applied_on_ingest", "value": "true" }
  ]
}
```

**Response (partial success):**

If some keys are valid and others are not, valid keys are still applied. The response includes both the updated entries and any errors.

```json
{
  "message": "Config partially updated",
  "updated": [
    { "key": "notify.enabled", "value": "true" }
  ],
  "errors": [
    "invalid.key: key \"invalid\" not found (unknown segment \"invalid\")"
  ]
}
```

---

### Config Hot Reload

The server watches the config file (`~/.vigolium/vigolium-configs.yaml`) for changes. When the file is modified — whether by a text editor, the CLI (`vigolium config set`), or any other tool — reloadable sections are automatically applied without restarting the server.

**Reloadable sections:** `scope`, `notify`, `dynamic_assessment`, `mutation_strategy`

**Non-reloadable sections:** `server`, `database` (a warning is logged; restart required)

Changes made via the API (`POST /api/config`, `POST /api/scope`) do not trigger a redundant reload.

---

### Single-Target Scans

#### POST /api/scan-url — Scan a URL

Starts an asynchronous scan of a single URL. Equivalent to the CLI `scan-url` command. Returns `202 Accepted` immediately with a scan ID.

**Request body:**

| Field       | Type              | Required | Description                               |
|-------------|-------------------|----------|-------------------------------------------|
| `url`       | string            | Yes      | Target URL to scan                        |
| `method`    | string            | No       | HTTP method (default: `GET`)              |
| `body`      | string            | No       | Request body                              |
| `headers`   | map[string]string | No       | Custom request headers                    |
| `modules`   | string            | No       | Comma-separated module IDs to run         |
| `no_passive`| bool              | No       | Skip passive modules                      |

```bash
# Simple GET scan
curl -s -X POST http://localhost:9002/api/scan-url \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com/api/users?id=1"
  }' | jq .

# POST with body and specific modules
curl -s -X POST http://localhost:9002/api/scan-url \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com/api/login",
    "method": "POST",
    "body": "{\"user\":\"admin\",\"pass\":\"test\"}",
    "headers": {
      "Content-Type": "application/json"
    },
    "modules": "xss-scanner,sqli-error-based"
  }' | jq .
```

**Response (202):**

```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "running",
  "message": "scan-url started for https://example.com/api/users?id=1"
}
```

---

#### POST /api/scan-request — Scan a Raw HTTP Request

Starts an asynchronous scan from a base64-encoded raw HTTP request. Equivalent to the CLI `scan-request` command. Returns `202 Accepted` immediately with a scan ID.

**Request body:**

| Field         | Type   | Required | Description                                          |
|---------------|--------|----------|------------------------------------------------------|
| `raw_request` | string | Yes      | Base64-encoded raw HTTP request                      |
| `target_url`  | string | No       | Override target URL (scheme://host) for the request  |
| `modules`     | string | No       | Comma-separated module IDs to run                    |
| `no_passive`  | bool   | No       | Skip passive modules                                 |

```bash
# Base64-encode a raw HTTP request
REQ_B64=$(echo -n "POST /api/login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{\"user\":\"admin\"}" | base64)

curl -s -X POST http://localhost:9002/api/scan-request \
  -H "Content-Type: application/json" \
  -d "{
    \"raw_request\": \"$REQ_B64\",
    \"target_url\": \"https://example.com\"
  }" | jq .
```

**Response (202):**

```json
{
  "scan_id": "661f9511-f3ac-52e5-b827-557766551111",
  "status": "running",
  "message": "scan-request started for https://example.com/api/login"
}
```

**Error responses (both endpoints):**

| Code | Condition                            |
|------|--------------------------------------|
| 400  | Missing required fields or invalid input |

Use `GET /api/scan/status` to check the progress of the scan.

---

### Source Repos — CRUD API

Manage links between application source code and target hostnames. Source repos enable source-aware JS extensions to read, list, and search source files during scanning.

#### GET /api/source-repos — List Source Repos

**Query parameters:**

| Parameter  | Type   | Default | Description                                  |
|------------|--------|---------|----------------------------------------------|
| `hostname` | string |         | Filter by exact hostname                     |
| `limit`    | int    | 50      | Number of repos to return (max 500)          |
| `offset`   | int    | 0       | Offset for pagination                        |

```bash
# List all source repos
curl -s http://localhost:9002/api/source-repos | jq .

# Filter by hostname
curl -s 'http://localhost:9002/api/source-repos?hostname=app.example.com' | jq .
```

```json
{
  "data": [
    {
      "id": 1,
      "hostname": "app.example.com",
      "name": "my-app",
      "root_path": "/home/user/src/my-app",
      "repo_type": "git",
      "language": "python",
      "framework": "django",
      "endpoints": ["/api/users", "/api/login"],
      "route_params": ["id", "uuid"],
      "sinks": ["sql.exec"],
      "tags": ["backend"],
      "third_party_scan_status": "completed",
      "third_party_scan_at": "2026-02-19T11:00:00Z",
      "created_at": "2026-02-19T10:00:00Z",
      "updated_at": "2026-02-19T11:00:00Z"
    }
  ],
  "total": 1,
  "limit": 50,
  "offset": 0,
  "has_more": false
}
```

---

#### POST /api/source-repos — Create Source Repo

**Request body:**

| Field         | Type     | Required | Description                                           |
|---------------|----------|----------|-------------------------------------------------------|
| `hostname`    | string   | Yes      | Target hostname to link                               |
| `root_path`   | string   | Yes      | Absolute filesystem path to source root               |
| `name`        | string   | No       | Display name (defaults to hostname)                   |
| `repo_type`   | string   | No       | `git`, `folder`, or `archive` (defaults to `folder`)  |
| `language`    | string   | No       | Primary programming language                          |
| `framework`   | string   | No       | Framework (e.g. express, django, spring)              |
| `scan_uuid`   | string   | No       | Link to a specific scan UUID                          |
| `endpoints`   | string[] | No       | Known application endpoints                           |
| `route_params`| string[] | No       | Known route parameters                                |
| `sinks`       | string[] | No       | Known dangerous sinks                                 |
| `tags`        | string[] | No       | Tags for categorization                               |
| `metadata`    | object   | No       | Arbitrary metadata                                    |

```bash
curl -s -X POST http://localhost:9002/api/source-repos \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "app.example.com",
    "root_path": "/home/user/src/my-app",
    "repo_type": "git",
    "language": "python",
    "framework": "django"
  }' | jq .
```

```json
{
  "id": 1,
  "hostname": "app.example.com",
  "name": "app.example.com",
  "root_path": "/home/user/src/my-app",
  "repo_type": "git",
  "language": "python",
  "framework": "django",
  "third_party_scan_status": "",
  "created_at": "2026-02-19T10:00:00Z",
  "updated_at": "2026-02-19T10:00:00Z"
}
```

---

#### GET /api/source-repos/:id — Get Source Repo

```bash
curl -s http://localhost:9002/api/source-repos/1 | jq .
```

---

#### PUT /api/source-repos/:id — Update Source Repo

Partially updates a source repo. Only provided fields are overwritten.

```bash
curl -s -X PUT http://localhost:9002/api/source-repos/1 \
  -H "Content-Type: application/json" \
  -d '{
    "language": "go",
    "framework": "fiber",
    "tags": ["backend", "api"]
  }' | jq .
```

---

#### DELETE /api/source-repos/:id — Delete Source Repo

```bash
curl -s -X DELETE http://localhost:9002/api/source-repos/1 | jq .
```

```json
{
  "message": "source repo deleted",
  "id": 1
}
```

---

### OAST Interactions

Out-of-band Application Security Testing (OAST) interactions recorded from interactsh callbacks. These represent DNS, HTTP, or other protocol interactions triggered by payloads injected during active scanning.

#### GET /api/oast-interactions — List OAST Interactions

Returns paginated OAST interactions. Heavy fields (`raw_request`, `raw_response`) are excluded from list responses for performance.

**Query parameters:**

| Parameter   | Type   | Default | Description                                         |
|-------------|--------|---------|-----------------------------------------------------|
| `limit`     | int    | 50      | Number of interactions to return (max 500)          |
| `offset`    | int    | 0       | Offset for pagination                               |
| `scan_id`   | string |         | Filter by scan UUID                                 |
| `protocol`  | string |         | Filter by protocol (e.g. `dns`, `http`, `smtp`)     |
| `module_id` | string |         | Filter by module ID                                 |
| `search`    | string |         | Search across target URL, parameter name, unique ID |

```bash
# List all OAST interactions
curl -s http://localhost:9002/api/oast-interactions | jq .

# Filter by protocol
curl -s 'http://localhost:9002/api/oast-interactions?protocol=dns&limit=5' | jq .

# Filter by scan
curl -s 'http://localhost:9002/api/oast-interactions?scan_id=scan-456' | jq .

# Search by target URL
curl -s 'http://localhost:9002/api/oast-interactions?search=example.com' | jq .
```

```json
{
  "data": [
    {
      "id": 1,
      "scan_uuid": "scan-456",
      "unique_id": "abc123def456",
      "full_id": "abc123def456.oast.fun",
      "protocol": "dns",
      "q_type": "A",
      "remote_address": "203.0.113.42",
      "interacted_at": "2026-02-16T15:10:00Z",
      "target_url": "https://example.com/api/users?id=1",
      "parameter_name": "id",
      "injection_type": "param_value",
      "module_id": "ssrf-detection",
      "created_at": "2026-02-16T15:10:01Z"
    }
  ],
  "total": 12,
  "limit": 50,
  "offset": 0,
  "has_more": false
}
```

> **Note:** The fields `raw_request` and `raw_response` are excluded from list responses. Use `GET /api/oast-interactions/:id` to access full interaction data.

---

#### GET /api/oast-interactions/:id — Get OAST Interaction Detail

Returns a single OAST interaction by its numeric ID, including full `raw_request` and `raw_response` fields.

```bash
curl -s http://localhost:9002/api/oast-interactions/1 | jq .
```

```json
{
  "id": 1,
  "scan_uuid": "scan-456",
  "unique_id": "abc123def456",
  "full_id": "abc123def456.oast.fun",
  "protocol": "http",
  "q_type": "",
  "raw_request": "GET / HTTP/1.1\r\nHost: abc123def456.oast.fun\r\n\r\n",
  "raw_response": "HTTP/1.1 200 OK\r\n\r\n<html>...</html>",
  "remote_address": "203.0.113.42",
  "interacted_at": "2026-02-16T15:10:00Z",
  "target_url": "https://example.com/api/users?id=1",
  "parameter_name": "id",
  "injection_type": "param_value",
  "module_id": "ssrf-detection",
  "created_at": "2026-02-16T15:10:01Z"
}
```

**Error responses:**

| Code | Condition                      |
|------|--------------------------------|
| 400  | Invalid ID (not a number)      |
| 404  | OAST interaction not found     |
| 503  | Database unavailable           |

---

### Scan Management

#### POST /api/scan — Trigger Scan

Triggers a background scan over ingested HTTP records. Returns `202 Accepted` on success or `409 Conflict` if a scan is already running.

**Request body:**

| Field            | Type     | Required | Description                                     |
|------------------|----------|----------|-------------------------------------------------|
| `force`          | bool     | No       | Re-scan records that were previously scanned     |
| `enable_modules` | string[] | No       | Restrict scan to specific module IDs             |

```bash
# Trigger a full scan
curl -s -X POST http://localhost:9002/api/scan \
  -H "Content-Type: application/json" \
  -d '{}' | jq .

# Scan with specific modules only
curl -s -X POST http://localhost:9002/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "force": true,
    "enable_modules": ["xss-scanner", "sqli-error-based"]
  }' | jq .
```

**Response (202):**

```json
{
  "scan_id": "scan-abc123",
  "status": "started",
  "message": "scan started",
  "records_to_scan": 150
}
```

**Response (409):**

```json
{
  "error": "a scan is already running",
  "code": 409
}
```

---

#### GET /api/scan/status — Scan Status

Returns the status of the current or most recent scan.

```bash
curl -s http://localhost:9002/api/scan/status | jq .
```

```json
{
  "scan_id": "scan-abc123",
  "running": true,
  "status": "running",
  "message": "scanning 150 records"
}
```

When no scan is running:

```json
{
  "running": false,
  "status": "idle"
}
```

---

#### DELETE /api/scan — Cancel Scan

Cancels a running scan.

```bash
curl -s -X DELETE http://localhost:9002/api/scan | jq .
```

```json
{
  "scan_id": "scan-abc123",
  "running": true,
  "status": "cancelling",
  "message": "scan cancellation requested"
}
```

---

### Scan History

#### GET /api/scans — List Scans

Returns paginated scan history ordered by creation date (newest first).

**Query parameters:**

| Parameter | Type | Default | Description                          |
|-----------|------|---------|--------------------------------------|
| `limit`   | int  | 50      | Number of scans to return (max 500)  |
| `offset`  | int  | 0       | Offset for pagination                |

```bash
# List recent scans
curl -s http://localhost:9002/api/scans | jq .

# Paginate
curl -s 'http://localhost:9002/api/scans?limit=10&offset=0' | jq .
```

```json
{
  "data": [
    {
      "uuid": "scan-abc123",
      "name": "api-scan",
      "status": "completed",
      "scan_source": "api",
      "scan_mode": "incremental",
      "modules": "all",
      "total_findings": 5,
      "processed_count": 150,
      "started_at": "2026-02-16T15:00:00Z",
      "finished_at": "2026-02-16T15:05:00Z",
      "created_at": "2026-02-16T15:00:00Z"
    }
  ],
  "total": 12,
  "limit": 50,
  "offset": 0,
  "has_more": false
}
```

---

#### GET /api/scans/:uuid — Get Scan Detail

Returns a single scan by UUID.

```bash
curl -s http://localhost:9002/api/scans/scan-abc123 | jq .
```

**Error responses:**

| Code | Condition            |
|------|----------------------|
| 400  | Missing UUID         |
| 404  | Scan not found       |
| 503  | Database unavailable |

---

#### DELETE /api/scans/:uuid — Delete Scan

Deletes a scan record by UUID.

```bash
curl -s -X DELETE http://localhost:9002/api/scans/scan-abc123 | jq .
```

```json
{
  "message": "scan deleted",
  "uuid": "scan-abc123"
}
```

**Error responses:**

| Code | Condition            |
|------|----------------------|
| 400  | Missing UUID         |
| 404  | Scan not found       |
| 503  | Database unavailable |

---

#### POST /api/scans/:uuid/stop — Stop a Running Scan

Stops a specific running scan by UUID. The scan must be the currently active scan. Workers finish their current tasks before fully stopping.

```bash
curl -s -X POST http://localhost:9002/api/scans/scan-abc123/stop | jq .
```

```json
{
  "scan_id": "scan-abc123",
  "running": true,
  "status": "cancelling",
  "message": "scan stop requested, workers finishing current tasks"
}
```

**Error responses:**

| Code | Condition                                  |
|------|--------------------------------------------|
| 400  | Missing UUID                               |
| 409  | No scan running, or UUID is not the active scan |

---

### Selective Record Scan

#### POST /api/scan-records — Scan Specific HTTP Records

Starts an asynchronous scan on specific HTTP records identified by UUID. Returns `202 Accepted` on success or `409 Conflict` if a scan is already running. Only one scan can run at a time.

**Request body:**

| Field            | Type     | Required | Description                               |
|------------------|----------|----------|-------------------------------------------|
| `record_uuids`   | string[] | Yes      | UUIDs of HTTP records to scan             |
| `enable_modules` | string[] | No       | Restrict scan to specific module IDs      |

```bash
# Scan specific records
curl -s -X POST http://localhost:9002/api/scan-records \
  -H "Content-Type: application/json" \
  -d '{
    "record_uuids": ["abc-123", "def-456", "ghi-789"]
  }' | jq .

# Scan with specific modules
curl -s -X POST http://localhost:9002/api/scan-records \
  -H "Content-Type: application/json" \
  -d '{
    "record_uuids": ["abc-123"],
    "enable_modules": ["xss-scanner", "sqli-error-based"]
  }' | jq .
```

**Response (202):**

```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "running",
  "message": "selective scan started",
  "records_to_scan": 3
}
```

**Error responses:**

| Code | Condition                                    |
|------|----------------------------------------------|
| 400  | Missing `record_uuids` or no valid records found |
| 409  | A scan is already running                    |
| 503  | Database unavailable                         |

Use `GET /api/scan/status` or `GET /api/scans/:uuid` to check scan progress.

---

### Delete Operations

#### DELETE /api/http-records — Delete HTTP Records

Deletes HTTP records matching the given filters. Associated findings and junction rows are also removed. Supports dry-run mode to preview the deletion count without actually deleting.

**Request body (JSON):**

| Field         | Type   | Required | Description                                      |
|---------------|--------|----------|--------------------------------------------------|
| `domain`      | string | No       | Filter by hostname (supports `*` wildcards)      |
| `method`      | string | No       | Filter by HTTP method (comma-separated)          |
| `path`        | string | No       | Filter by path (supports `*` wildcards)          |
| `source`      | string | No       | Filter by record source                          |
| `status_code` | string | No       | Filter by status code (comma-separated)          |
| `date_from`   | string | No       | Start date (RFC3339 or `YYYY-MM-DD`)             |
| `date_to`     | string | No       | End date (RFC3339 or `YYYY-MM-DD`)               |
| `search`      | string | No       | Search across URL and path                       |
| `dry_run`     | bool   | No       | Preview deletion count without deleting          |

```bash
# Dry run: see how many records would be deleted
curl -s -X DELETE http://localhost:9002/api/http-records \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "old.example.com",
    "dry_run": true
  }' | jq .

# Delete records by domain
curl -s -X DELETE http://localhost:9002/api/http-records \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "old.example.com"
  }' | jq .

# Delete by status code and method
curl -s -X DELETE http://localhost:9002/api/http-records \
  -H "Content-Type: application/json" \
  -d '{
    "status_code": "404,500",
    "method": "GET"
  }' | jq .

# Delete by date range
curl -s -X DELETE http://localhost:9002/api/http-records \
  -H "Content-Type: application/json" \
  -d '{
    "date_from": "2026-01-01",
    "date_to": "2026-01-31"
  }' | jq .
```

**Response:**

```json
{
  "deleted": 42,
  "dry_run": false,
  "message": "records deleted"
}
```

**Dry-run response:**

```json
{
  "deleted": 42,
  "dry_run": true,
  "message": "dry run: records would be deleted"
}
```

---

#### DELETE /api/findings — Delete Findings

Deletes findings matching the given filters. Junction rows linking findings to HTTP records are also removed. Supports dry-run mode.

**Request body (JSON):**

| Field         | Type   | Required | Description                                      |
|---------------|--------|----------|--------------------------------------------------|
| `severity`    | string | No       | Filter by severity (comma-separated): `critical`, `high`, `medium`, `low`, `info` |
| `module_name` | string | No       | Filter by module name                            |
| `scan_uuid`   | string | No       | Filter by scan UUID                              |
| `domain`      | string | No       | Filter by hostname (supports `*` wildcards)      |
| `date_from`   | string | No       | Start date (RFC3339 or `YYYY-MM-DD`)             |
| `date_to`     | string | No       | End date (RFC3339 or `YYYY-MM-DD`)               |
| `search`      | string | No       | Search across description, module ID, matched_at |
| `dry_run`     | bool   | No       | Preview deletion count without deleting          |

```bash
# Dry run: see how many findings would be deleted
curl -s -X DELETE http://localhost:9002/api/findings \
  -H "Content-Type: application/json" \
  -d '{
    "severity": "info",
    "dry_run": true
  }' | jq .

# Delete info-level findings
curl -s -X DELETE http://localhost:9002/api/findings \
  -H "Content-Type: application/json" \
  -d '{
    "severity": "info"
  }' | jq .

# Delete findings from a specific scan
curl -s -X DELETE http://localhost:9002/api/findings \
  -H "Content-Type: application/json" \
  -d '{
    "scan_uuid": "scan-abc123"
  }' | jq .

# Delete findings by module and domain
curl -s -X DELETE http://localhost:9002/api/findings \
  -H "Content-Type: application/json" \
  -d '{
    "module_name": "xss",
    "domain": "old.example.com"
  }' | jq .
```

**Response:**

```json
{
  "deleted": 15,
  "dry_run": false,
  "message": "findings deleted"
}
```

---

### Agent — AI Agent Runs

#### POST /api/agent/run — Trigger Agent Run

Starts an asynchronous AI agent run. Requires at least one of `prompt_template`, `prompt_file`, or `prompt`. Returns `202 Accepted` on success or `409 Conflict` if an agent is already running.

**Request body:**

| Field              | Type     | Required | Description                                                    |
|--------------------|----------|----------|----------------------------------------------------------------|
| `agent`            | string   | No       | Agent backend name (e.g. `claude`, `opencode`, `gemini`)       |
| `prompt_template`  | string   | No       | Name of a prompt template (from `~/.vigolium/prompts/`)        |
| `prompt_file`      | string   | No       | Path to a prompt file on disk                                  |
| `prompt`           | string   | No       | Inline prompt text                                             |
| `repo_path`        | string   | No       | Path to source code repository for context                     |
| `files`            | string[] | No       | Specific files to include as context                           |
| `append`           | string   | No       | Additional text appended to the prompt                         |
| `source`           | string   | No       | Source label for findings                                      |
| `scan_uuid`        | string   | No       | Link results to a specific scan UUID                           |
| `stream`           | bool     | No       | If `true`, returns an SSE stream instead of 202 async response |

```bash
# Run with a prompt template
curl -s -X POST http://localhost:9002/api/agent/run \
  -H "Content-Type: application/json" \
  -d '{
    "agent": "claude",
    "prompt_template": "code-review",
    "repo_path": "/home/user/src/my-app"
  }' | jq .

# Run with an inline prompt
curl -s -X POST http://localhost:9002/api/agent/run \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "Analyze the authentication flow for vulnerabilities",
    "repo_path": "/home/user/src/my-app",
    "files": ["src/auth/login.py", "src/auth/session.py"]
  }' | jq .
```

**Response (202):**

```json
{
  "run_id": "agt-550e8400-e29b-41d4-a716-446655440000",
  "status": "running",
  "message": "agent run started"
}
```

**Response (SSE stream, when `stream: true`):**

When `stream` is `true`, the response is a `text/event-stream` (Server-Sent Events). Each event is a JSON object on a `data:` line:

```
data: {"type":"chunk","text":"Analyzing authentication flow..."}

data: {"type":"chunk","text":" found potential issue in session handling."}

data: {"type":"done","result":{"agent_name":"claude","findings":[...],"saved_count":3}}

```

Event types:

| Type    | Description                                  |
|---------|----------------------------------------------|
| `chunk` | Incremental text output from the agent       |
| `done`  | Final event with the complete `result` object |
| `error` | Agent run failed; includes `error` message   |

**Response (409):**

```json
{
  "error": "an agent run is already in progress",
  "code": 409
}
```

---

#### GET /api/agent/status/list — List Agent Runs

Returns all agent runs.

```bash
curl -s http://localhost:9002/api/agent/status/list | jq .
```

```json
[
  {
    "run_id": "agt-550e8400-e29b-41d4-a716-446655440000",
    "status": "completed",
    "agent_name": "claude",
    "template_id": "code-review",
    "finding_count": 3,
    "record_count": 0,
    "saved_count": 3,
    "completed_at": "2026-02-16T15:10:00Z"
  },
  {
    "run_id": "agt-661f9511-f3ac-52e5-b827-557766551111",
    "status": "running",
    "agent_name": "opencode"
  }
]
```

---

#### GET /api/agent/status/:id — Agent Run Status

Returns the status of a specific agent run.

```bash
curl -s http://localhost:9002/api/agent/status/agt-550e8400-e29b-41d4-a716-446655440000 | jq .
```

```json
{
  "run_id": "agt-550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "agent_name": "claude",
  "template_id": "code-review",
  "finding_count": 3,
  "record_count": 0,
  "saved_count": 3,
  "completed_at": "2026-02-16T15:10:00Z",
  "result": {
    "agent_name": "claude",
    "template_id": "code-review",
    "findings": [],
    "http_records": [],
    "saved_count": 3,
    "raw_output": "..."
  }
}
```

For a failed run:

```json
{
  "run_id": "agt-661f9511-f3ac-52e5-b827-557766551111",
  "status": "failed",
  "agent_name": "opencode",
  "error": "agent process exited with code 1",
  "completed_at": "2026-02-16T15:08:00Z"
}
```

---

#### POST /api/agent/chat/completions — OpenAI-Compatible Chat Completions

Accepts an OpenAI-compatible Chat Completions request and returns an OpenAI-compatible response. This allows any OpenAI-compatible client or tool to use Vigolium agents by changing the base URL.

The `model` field maps to agent names in config. If `model` matches a configured agent name (e.g. `"claude"`, `"opencode"`, `"gemini"`), that agent is used. Unrecognized model names fall back to the default agent.

This endpoint is **synchronous** — it blocks until the agent completes. It shares the concurrency lock with `/api/agent/run` (returns `409 Conflict` if an agent is already running).

**Request body:**

| Field      | Type   | Required | Description                                      |
|------------|--------|----------|--------------------------------------------------|
| `model`    | string | Yes      | Agent name or any string (falls back to default) |
| `messages` | array  | Yes      | Array of `{role, content}` message objects       |

```bash
curl -s -X POST http://localhost:9002/api/agent/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <api-key>" \
  -d '{
    "model": "claude",
    "messages": [
      { "role": "user", "content": "What are common JWT vulnerabilities?" }
    ]
  }' | jq .
```

**Response (200):**

```json
{
  "id": "chatcmpl-550e8400-e29b-41d4-a716-446655440000",
  "object": "chat.completion",
  "created": 1708531200,
  "model": "claude",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "Common JWT vulnerabilities include..."
      },
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 150,
    "completion_tokens": 200,
    "total_tokens": 350
  }
}
```

**Response (409):**

```json
{
  "error": "an agent run is already in progress"
}
```

**Using with OpenAI-compatible clients:**

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:9002/api/agent",
    api_key="<api-key>",
)
response = client.chat.completions.create(
    model="claude",
    messages=[{"role": "user", "content": "Explain CSRF attacks"}],
)
print(response.choices[0].message.content)
```

See [Agent Mode](agent-mode.md) for full agent documentation.

---

## CORS

CORS can be enabled via the `cors_allowed_origins` server config:

| Value              | Behavior                                              |
|--------------------|-------------------------------------------------------|
| `*`                | Allow all origins                                     |
| `reflect-origin`   | Reflect the request's `Origin` header (allows credentials) |
| `origin1,origin2`  | Allow specific origins (comma-separated, allows credentials) |
| *(empty/omitted)*  | CORS disabled                                         |

Allowed methods: `GET`, `POST`, `PUT`, `DELETE`, `OPTIONS`. Allowed headers: `Content-Type`, `Authorization`.

---

## Error Responses

All errors follow a consistent format:

```json
{
  "error": "error message",
  "code": 400,
  "details": "optional additional details"
}
```

**Common error codes:**

| Code | Meaning                                      |
|------|----------------------------------------------|
| 400  | Bad request (invalid JSON, missing fields)   |
| 401  | Unauthorized (missing or invalid Bearer token) |
| 404  | Not found (e.g. agent run ID not found)      |
| 409  | Conflict (scan or agent already running)     |
| 500  | Internal server error                         |
| 503  | Database not available                        |
