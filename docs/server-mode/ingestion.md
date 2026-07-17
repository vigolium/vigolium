# Ingesting HTTP Traffic

## Overview

Before Vigolium can scan for vulnerabilities, it needs HTTP traffic data. Ingestion is the process of getting HTTP requests (and optionally responses) into Vigolium's database. There are three ingestion methods:

1. **API ingestion** -- POST to `/api/ingest-http` on a running server
2. **CLI ingestion** -- Use `vigolium ingest` to send to a server or store directly in the local database
3. **Transparent proxy** -- Route traffic through Vigolium's built-in proxy (see [Proxy](proxy.md))

## API Ingestion

The `/api/ingest-http` endpoint accepts multiple input modes. All requests use `POST` with a JSON body. It is project-scoped: use `X-Project-UUID` to override the default/active project selected by the server middleware. Unless the server was started with `--no-auth`, send a bearer token as shown below.

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
ENCODED=$(printf '%s' 'curl -X POST https://example.com/api/login -H "Content-Type: application/json" -d "{\"username\":\"admin\",\"password\":\"test\"}"' | base64)

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

### Ingest a HAR file

```bash
ARCHIVE=$(base64 < traffic.har)

curl -X POST http://localhost:9002/api/ingest-http \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d "{
    \"input_mode\": \"har\",
    \"content_base64\": \"$ARCHIVE\"
  }"
```

`http_archive` is an alias for `har`.

## CLI Ingestion

The `vigolium ingest` command supports both remote (server) and local (direct-to-database) modes.

### Remote Ingestion (to a running server)

Use the `-s` flag to send traffic to a running Vigolium server:

```bash
export VIGOLIUM_API_KEY=my-secret-key

# Pipe URLs from stdin
cat urls.txt | vigolium ingest -s http://localhost:9002

# From a file
vigolium ingest -s http://localhost:9002 --input targets.txt

# One or more URL-list files
vigolium ingest -s http://localhost:9002 -T public.txt -T api.txt

# OpenAPI spec with a base URL
vigolium ingest -s http://localhost:9002 \
  --input api.yaml -I openapi -t https://api.example.com

# Control submission rate
vigolium ingest -s http://localhost:9002 \
  --input urls.txt --concurrency 20 -r 200
```

### Local Ingestion (direct to database)

When `-s`/`--server` is omitted, requests are fetched and stored directly in the local database:

```bash
# Ingest URLs (fetches each and stores request + response)
cat urls.txt | vigolium ingest

# From an OpenAPI spec
vigolium ingest --input api.yaml -I openapi -t https://api.example.com

# With a custom scan ID for tagging
vigolium ingest --input urls.txt --scan-uuid recon-2026-02

# Use a specific database file
vigolium ingest --input urls.txt --db ./project.db

# Ingest into a specific project
vigolium ingest --input urls.txt --project-uuid a1b2c3d4-...
```

Inputs containing a response (a Burp request/response pair separated by `***`, HAR, and similar formats) preserve that response instead of fetching it again. For request-only inputs, local mode fetches a baseline response unless `--disable-fetch-response` is set.

### Scan on receive

Local ingestion can feed records directly into a long-running scanner:

```bash
# Dynamic assessment on records as they arrive
cat traffic.txt | vigolium ingest -S -m xss,sqli

# Run the full native pipeline instead of dynamic assessment alone
vigolium ingest -T targets.txt -S --full-native-scan-on-receive

# Apply module and scope controls to the continuous scanner
vigolium ingest -T targets.txt -S \
  --module-tag injection --scope-origin balanced
```

`-S`/`--scan-on-receive` is a local-mode feature. It is ignored with a warning when `--server` is used because the remote server controls its own scan-on-receive behavior.

## REST Input Modes Reference

| Mode | Content Field | Description |
|------|--------------|-------------|
| `url` | `content` | A single URL |
| `url_file` | `content` | Newline-separated list of URLs |
| `curl` | `content` or `content_base64` | A curl command string |
| `burp_base64` | `http_request_base64` | Base64-encoded raw HTTP request |
| `openapi` / `swagger` | `content` or `content_base64` | OpenAPI/Swagger spec (JSON or YAML) |
| `postman_collection` | `content` or `content_base64` | Postman Collection (JSON) |
| `har` / `http_archive` | `content` or `content_base64` | HTTP Archive (HAR 1.2 JSON) |

For `burp_base64` mode, you can also include `http_response_base64` to store the response alongside the request.

For modes that accept large payloads, prefer `content_base64` to avoid JSON escaping issues.

The CLI's `-I`/`--input-mode` vocabulary is broader and is intentionally different from the REST envelope names: `urls` (`url`, `list`), `nuclei-output` (`nuclei`), `openapi` (`swagger`), `postman`, `curl`, `burpraw` (`burp-raw`, `raw`), `burpxml` (`burp-xml`, `burp`, `burpstate`), `har` (`http-archive`), and `deparos` (`deparos-output`). Run `vigolium --list-input-mode` for examples generated by the current binary.
