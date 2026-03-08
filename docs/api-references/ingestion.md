# Vigolium API Reference — Ingestion

## POST /api/ingest-http — Ingest HTTP Data

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

### Ingest a URL

```bash
curl -s -X POST http://localhost:9002/api/ingest-http \
  -H "Content-Type: application/json" \
  -d '{
    "input_mode": "url",
    "content": "https://example.com/api/users?id=1"
  }' | jq .
```

### Ingest a curl command

```bash
curl -s -X POST http://localhost:9002/api/ingest-http \
  -H "Content-Type: application/json" \
  -d '{
    "input_mode": "curl",
    "content": "curl -X POST https://example.com/login -d \"user=admin&pass=test\""
  }' | jq .
```

### Ingest a list of URLs

```bash
curl -s -X POST http://localhost:9002/api/ingest-http \
  -H "Content-Type: application/json" \
  -d '{
    "input_mode": "url_file",
    "content": "https://example.com/page1\nhttps://example.com/page2\nhttps://example.com/page3"
  }' | jq .
```

### Ingest a raw HTTP request (base64)

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

### Ingest a raw HTTP request with a URL hint (base64)

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

### Ingest an OpenAPI spec

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
