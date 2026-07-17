# Vigolium API Reference — Scope

## GET /api/scope — View Scope Config

Returns the current scope configuration that controls which HTTP records are in scope for scanning.

```bash
curl -s http://localhost:9002/api/scope | jq .
```

```json
{
  "applied_on_ingest": false,
  "cli_origin_mode": "relaxed",
  "host": { "include": ["*"], "exclude": [] },
  "path": { "include": ["*"], "exclude": [] },
  "status_code": { "include": ["*"], "exclude": [] },
  "request_content_type": { "include": ["*"], "exclude": [] },
  "response_content_type": { "include": ["*"], "exclude": [] },
  "request_string": { "include": [], "exclude": [] },
  "response_string": { "include": [], "exclude": [] },
  "max_request_body_size": 1048576,
  "max_response_body_size": 524288000,
  "body_size_exceeded_action": "truncate",
  "ignore_static_file": true,
  "ignore_static_content_type": {
    "images": [".jpg", ".jpeg", ".png", ".gif"],
    "fonts": [".ttf", ".otf", ".woff", ".woff2"]
  }
}
```

The `ignore_static_content_type` object contains the complete configured
extension catalog; the response above abbreviates two categories.

---

## POST /api/scope — Update Scope Config

Partially updates the seven include/exclude rules and, when explicitly present,
`applied_on_ingest`. Omitted rule slices keep their current values. Changes are
persisted to the config file on disk. Use `POST /api/config` for
`cli_origin_mode`, body-size limits, and static-file settings.

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

# Reject out-of-scope traffic during ingestion instead of only skipping it at scan time
curl -s -X POST http://localhost:9002/api/scope \
  -H "Content-Type: application/json" \
  -d '{"applied_on_ingest": true}' | jq .
```

**Response:**

```json
{
  "message": "Scope updated successfully",
  "scope": {
    "applied_on_ingest": false,
    "cli_origin_mode": "relaxed",
    "host": { "include": ["*"], "exclude": ["*.internal.com", "localhost"] },
    "path": { "include": ["*"], "exclude": [] },
    "status_code": { "include": ["*"], "exclude": [] },
    "request_content_type": { "include": ["*"], "exclude": [] },
    "response_content_type": { "include": ["*"], "exclude": [] },
    "request_string": { "include": [], "exclude": [] },
    "response_string": { "include": [], "exclude": [] },
    "max_request_body_size": 1048576,
    "max_response_body_size": 524288000,
    "body_size_exceeded_action": "truncate",
    "ignore_static_file": true,
    "ignore_static_content_type": {}
  }
}
```

The response returns the full static-extension catalog even though the example
uses an empty object for brevity.
