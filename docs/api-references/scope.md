# Vigolium API Reference — Scope

## GET /api/scope — View Scope Config

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

## POST /api/scope — Update Scope Config

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
