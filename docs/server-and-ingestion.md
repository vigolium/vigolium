# Server Mode: Ingesting Data via the API

This guide covers how to start Vigolium in server mode and ingest HTTP traffic into the database using the REST API and CLI.

## Starting the Server

```bash
# Start with an API key
export VIGOLIUM_API_KEY=my-secret-key
vigolium server

# Custom host and port
export VIGOLIUM_API_KEY=my-secret-key
vigolium server --host 127.0.0.1 --service-port 9002

# With transparent HTTP proxy for recording traffic
export VIGOLIUM_API_KEY=my-secret-key
vigolium server --ingest-proxy-port 9003

# Without authentication (development only)
vigolium server -A
```

The server listens on `0.0.0.0:9002` by default.

## CORS Configuration

The server's CORS behavior is controlled by `cors_allowed_origins` in `~/.vigolium/vigolium-configs.yaml`:

```yaml
server:
  cors_allowed_origins: reflect-origin
```

| Value | Behavior |
|-------|----------|
| `reflect-origin` (default) | Echoes the requesting `Origin` header back. Allows credentials. |
| `*` | Allows all origins without credentials (standard wildcard). |
| _(empty string)_ | Disables CORS middleware entirely. |
| `https://app.example.com, https://admin.example.com` | Comma-separated allowlist. Allows credentials. |

## Project Scoping

All server operations are scoped to a project via the `X-Project-UUID` request header. If omitted, the default project is used.

```bash
# Ingest into a specific project
curl -X POST http://localhost:9002/api/ingest-http \
  -H "Authorization: Bearer my-secret-key" \
  -H "X-Project-UUID: a1b2c3d4-..." \
  -H "Content-Type: application/json" \
  -d '{"input_mode": "url", "content": "https://example.com"}'
```

All queries (findings, HTTP records, stats, scans) return data scoped to the project specified in the header. See [Projects](projects.md) for the full multi-tenancy reference.

## Authentication

All API requests (except `/health`) require a Bearer token:

```
Authorization: Bearer my-secret-key
```

API key resolution order: `VIGOLIUM_API_KEY` env var > `server.auth_api_key` in config file.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | App info (no auth required) |
| GET | `/health` | Health check (no auth required) |
| GET | `/metrics` | Prometheus metrics (no auth required) |
| GET | `/swagger/*` | Swagger UI and OpenAPI spec (no auth required) |
| GET | `/server-info` | Server status, queue depth, record/finding counts |
| GET | `/api/modules` | List available scanner modules |
| GET | `/api/http-records` | Query stored HTTP records |
| GET | `/api/findings` | Query scan findings |
| POST | `/api/ingest-http` | Ingest HTTP traffic into the database |
| GET | `/api/stats` | Aggregated scan statistics |
| GET | `/api/scope` | View scope configuration |
| POST | `/api/scope` | Update scope configuration |
| GET | `/api/config` | View server configuration |
| POST | `/api/config` | Update server configuration |
| POST | `/api/scan` | Trigger a background scan |
| GET | `/api/scan/status` | Check scan status |
| DELETE | `/api/scan` | Cancel a running scan |
| GET | `/api/source-repos` | List source repos |
| POST | `/api/source-repos` | Create a source repo |
| GET | `/api/source-repos/:id` | Get a source repo |
| PUT | `/api/source-repos/:id` | Update a source repo |
| DELETE | `/api/source-repos/:id` | Delete a source repo |
| POST | `/api/agent/run/query` | Single-shot agent prompt execution |
| POST | `/api/agent/run/autopilot` | Autonomous AI-driven scanning session |
| POST | `/api/agent/run/swarm` | AI-guided targeted vulnerability swarm |
| GET | `/api/agent/status/list` | List agent runs |
| GET | `/api/agent/status/:id` | Get agent run status (includes full result when completed) |

## Ingesting Data via API

The `/api/ingest-http` endpoint accepts multiple input modes. All requests use `POST` with a JSON body.

### Ingest a Single URL

```bash
curl -X POST http://localhost:9002/api/ingest-http \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d '{
    "input_mode": "url",
    "content": "https://example.com/api/users?id=1"
  }'
```

### Ingest Multiple URLs (url_file mode)

Pass a newline-separated list of URLs. Lines starting with `#` are treated as comments.

```bash
curl -X POST http://localhost:9002/api/ingest-http \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d '{
    "input_mode": "url_file",
    "content": "https://example.com/api/users?id=1\nhttps://example.com/api/posts?page=2\nhttps://example.com/login"
  }'
```

### Ingest a curl Command

```bash
curl -X POST http://localhost:9002/api/ingest-http \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d '{
    "input_mode": "curl",
    "content": "curl -X POST https://example.com/api/login -H \"Content-Type: application/json\" -d \"{\\\"username\\\":\\\"admin\\\",\\\"password\\\":\\\"test\\\"}\""
  }'
```

Using `content_base64` to avoid JSON escaping issues:

```bash
# Encode the curl command
ENCODED=$(echo -n 'curl -X POST https://example.com/api/login -H "Content-Type: application/json" -d "{\"username\":\"admin\",\"password\":\"test\"}"' | base64)

curl -X POST http://localhost:9002/api/ingest-http \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d "{
    \"input_mode\": \"curl\",
    \"content_base64\": \"$ENCODED\"
  }"
```

### Ingest a Raw HTTP Request (Burp-style)

Send a base64-encoded raw HTTP request, optionally with its response:

```bash
# Encode raw request
RAW_REQ=$(printf 'GET /api/users?id=1 HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc123\r\n\r\n' | base64)

curl -X POST http://localhost:9002/api/ingest-http \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d "{
    \"input_mode\": \"burp_base64\",
    \"http_request_base64\": \"$RAW_REQ\"
  }"
```

With both request and response:

```bash
RAW_REQ=$(printf 'POST /api/login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{"username":"admin","password":"test"}' | base64)
RAW_RESP=$(printf 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"token":"eyJhbGciOiJIUzI1NiJ9..."}' | base64)

curl -X POST http://localhost:9002/api/ingest-http \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d "{
    \"input_mode\": \"burp_base64\",
    \"http_request_base64\": \"$RAW_REQ\",
    \"http_response_base64\": \"$RAW_RESP\"
  }"
```

### Ingest a Raw HTTP Request with a URL Hint

Raw HTTP requests don't contain the scheme (`https` vs `http`), and the `Host` header may not match the public hostname (e.g. behind a load balancer). Use the `url` field to provide the correct scheme and host:

```bash
RAW_REQ=$(printf 'POST /api/login HTTP/1.1\r\nHost: internal-lb\r\nContent-Type: application/json\r\n\r\n{"user":"admin"}' | base64)

curl -X POST http://localhost:9002/api/ingest-http \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d "{
    \"input_mode\": \"burp_base64\",
    \"url\": \"https://app.example.com\",
    \"http_request_base64\": \"$RAW_REQ\"
  }"
```

### Ingest an OpenAPI / Swagger Spec

```bash
curl -X POST http://localhost:9002/api/ingest-http \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d '{
    "input_mode": "openapi",
    "content": "{\"openapi\":\"3.0.0\",\"info\":{\"title\":\"Example\",\"version\":\"1.0\"},\"servers\":[{\"url\":\"https://api.example.com\"}],\"paths\":{\"/users\":{\"get\":{\"summary\":\"List users\"}},\"/users/{id}\":{\"get\":{\"summary\":\"Get user\",\"parameters\":[{\"name\":\"id\",\"in\":\"path\",\"required\":true,\"schema\":{\"type\":\"integer\"}}]}}}}"
  }'
```

Using base64 for larger specs:

```bash
SPEC=$(base64 < openapi.yaml)

curl -X POST http://localhost:9002/api/ingest-http \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d "{
    \"input_mode\": \"openapi\",
    \"content_base64\": \"$SPEC\"
  }"
```

### Ingest a Postman Collection

```bash
COLLECTION=$(base64 < collection.json)

curl -X POST http://localhost:9002/api/ingest-http \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d "{
    \"input_mode\": \"postman_collection\",
    \"content_base64\": \"$COLLECTION\"
  }"
```

## Ingesting Data via CLI

The `vigolium ingest` command supports both remote (server) and local (direct-to-database) modes.

### Remote Ingestion (to a running server)

```bash
export VIGOLIUM_API_KEY=my-secret-key

# Pipe URLs from stdin
cat urls.txt | vigolium ingest -s http://localhost:9002

# From a file
vigolium ingest -s http://localhost:9002 --input targets.txt

# OpenAPI spec with a base URL
vigolium ingest -s http://localhost:9002 \
  --input api.yaml -I openapi -t https://api.example.com

# Control submission rate
vigolium ingest -s http://localhost:9002 \
  --input urls.txt --concurrency 20 -r 200
```

### Local Ingestion (direct to database)

When `--server` is omitted, requests are fetched and stored directly in the local database:

```bash
# Ingest URLs (fetches each and stores request + response)
cat urls.txt | vigolium ingest

# From an OpenAPI spec
vigolium ingest --input api.yaml -I openapi -t https://api.example.com

# With a custom scan ID for tagging
vigolium ingest --input urls.txt --scan-id recon-2026-02

# Use a specific database file
vigolium ingest --input urls.txt --db ./project.db

# Ingest into a specific project
vigolium ingest --input urls.txt --project-id a1b2c3d4-...
```

## Ingesting via Transparent Proxy

Start the server with a proxy port to passively record HTTP traffic:

```bash
export VIGOLIUM_API_KEY=my-secret-key
vigolium server --ingest-proxy-port 9003
```

Then route your tools through the proxy:

```bash
# curl through the proxy
curl -x http://localhost:9003 https://example.com/api/users

# httpx through the proxy
echo "https://example.com" | httpx -proxy http://localhost:9003

# nuclei through the proxy
nuclei -u https://example.com -proxy http://localhost:9003
```

All proxied HTTP traffic is automatically recorded in the database. HTTPS CONNECT tunneling is passed through without recording.

## Querying Ingested Data

### List HTTP Records

```bash
# All records (paginated, default limit=50)
curl -s http://localhost:9002/api/http-records \
  -H "Authorization: Bearer my-secret-key" | jq .

# Filter by domain
curl -s "http://localhost:9002/api/http-records?domain=example.com" \
  -H "Authorization: Bearer my-secret-key" | jq .

# Filter by status code and method
curl -s "http://localhost:9002/api/http-records?status_code=200,302&method=GET,POST" \
  -H "Authorization: Bearer my-secret-key" | jq .

# Search across URLs and headers
curl -s "http://localhost:9002/api/http-records?search=admin&limit=10" \
  -H "Authorization: Bearer my-secret-key" | jq .

# Pagination
curl -s "http://localhost:9002/api/http-records?limit=20&offset=40" \
  -H "Authorization: Bearer my-secret-key" | jq .
```

### List Findings

```bash
# All findings
curl -s http://localhost:9002/api/findings \
  -H "Authorization: Bearer my-secret-key" | jq .

# Filter by severity
curl -s "http://localhost:9002/api/findings?severity=high,critical" \
  -H "Authorization: Bearer my-secret-key" | jq .

# Filter by module
curl -s "http://localhost:9002/api/findings?module_name=xss-reflected" \
  -H "Authorization: Bearer my-secret-key" | jq .

# Filter by domain
curl -s "http://localhost:9002/api/findings?domain=example.com" \
  -H "Authorization: Bearer my-secret-key" | jq .
```

### Server Info

```bash
curl -s http://localhost:9002/server-info \
  -H "Authorization: Bearer my-secret-key" | jq .
```

Response:

```json
{
  "version": "0.1.0",
  "uptime": "2h15m30s",
  "service_addr": "0.0.0.0:9002",
  "proxy_addr": "0.0.0.0:9003",
  "db_driver": "sqlite",
  "queue_depth": 0,
  "total_records": 1542,
  "total_findings": 23
}
```

## Scan Management via API

After ingesting HTTP records, trigger a vulnerability scan via the API.

### Trigger a Scan

```bash
curl -s -X POST http://localhost:9002/api/scan \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d '{}' | jq .
```

Force re-scan with specific modules:

```bash
curl -s -X POST http://localhost:9002/api/scan \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d '{
    "force": true,
    "enable_modules": ["xss-scanner", "sqli-error-based"]
  }' | jq .
```

Returns `202 Accepted` on success, `409 Conflict` if a scan is already running.

### Check Scan Status

```bash
curl -s http://localhost:9002/api/scan/status \
  -H "Authorization: Bearer my-secret-key" | jq .
```

### Cancel a Running Scan

```bash
curl -s -X DELETE http://localhost:9002/api/scan \
  -H "Authorization: Bearer my-secret-key" | jq .
```

See the [API Reference](api-references/scan.md) for full request/response details.

## Running AI Agents via API

The agent API provides three run modes that mirror the `vigolium agent` CLI subcommands. Only one agent run can be active at a time (returns `409 Conflict` if busy).

### Query — Single-Shot Agent Run

```bash
curl -s -X POST http://localhost:9002/api/agent/run/query \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d '{
    "agent": "claude",
    "prompt_template": "code-review",
    "source": "/home/user/src/my-app"
  }' | jq .
```

At least one of `prompt_template`, `prompt_file`, or `prompt` is required. Returns `202 Accepted` on success. Set `"stream": true` for real-time SSE output.

### Autopilot — Autonomous Scanning

```bash
curl -s -X POST http://localhost:9002/api/agent/run/autopilot \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "focus": "API injection",
    "stream": true
  }'
```

### Swarm — AI-Guided Scanning

```bash
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d '{
    "input": "https://example.com",
    "discover": true,
    "profile": "thorough",
    "stream": true
  }'
```

SSE events are `data:` lines with JSON payloads: `{"type":"chunk","text":"..."}` for real-time output, `{"type":"phase","phase":"..."}` for swarm phase transitions, `{"type":"done","result":{...}}` on completion, or `{"type":"error","error":"..."}` on failure.

### List All Agent Runs

```bash
curl -s http://localhost:9002/api/agent/status/list \
  -H "Authorization: Bearer my-secret-key" | jq .
```

### Check Agent Run Status

```bash
curl -s http://localhost:9002/api/agent/status/agt-550e8400... \
  -H "Authorization: Bearer my-secret-key" | jq .
```

Once the run completes, the response includes a `result` field with the full agent output (raw text, findings, HTTP records).

See [Agent Mode](agent-mode.md) for the full agent documentation (including autopilot, swarm, context enrichment, and prompt templates) and the [API Reference](api-references/agent.md) for request/response details.

## Input Modes Reference

| Mode | Content Field | Description |
|------|--------------|-------------|
| `url` | `content` | A single URL |
| `url_file` | `content` | Newline-separated list of URLs |
| `curl` | `content` or `content_base64` | A curl command string |
| `burp_base64` | `http_request_base64` | Base64-encoded raw HTTP request |
| `openapi` / `swagger` | `content` or `content_base64` | OpenAPI/Swagger spec (JSON or YAML) |
| `postman_collection` | `content` or `content_base64` | Postman Collection (JSON) |

For `burp_base64` mode, you can also include `http_response_base64` to store the response alongside the request.

For modes that accept large payloads, prefer `content_base64` to avoid JSON escaping issues.
