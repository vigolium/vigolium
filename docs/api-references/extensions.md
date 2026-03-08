# Vigolium API Reference — Extensions

Manage JavaScript (`.js`) and YAML (`.vgm.yaml`) extensions that add custom scanning logic. Extensions must be enabled and configured in `vigolium-configs.yaml` under `dynamic_assessment.extensions`.

## GET /api/extensions — List Extensions

Returns metadata for all loaded extensions. Raw file content is excluded — use `GET /api/extensions/:name` to fetch the content of a specific extension.

**Query parameters:**

| Parameter | Type   | Description                                              |
|-----------|--------|----------------------------------------------------------|
| `type`    | string | Filter by type: `active`, `passive`, `pre_hook`, `post_hook` |
| `search`  | string | Filter by ID, name, description, or tag                  |

```bash
# List all extensions
curl -s http://localhost:9002/api/extensions | jq .

# Filter by type
curl -s 'http://localhost:9002/api/extensions?type=active' | jq .

# Search by keyword (also matches tags)
curl -s 'http://localhost:9002/api/extensions?search=xss' | jq .
```

**Response (200):**

```json
{
  "extensions": [
    {
      "id": "reflected-param-scanner",
      "name": "Reflected Parameter Scanner",
      "language": "js",
      "type": "active",
      "severity": "medium",
      "confidence": "firm",
      "scan_types": ["per_insertion_point"],
      "tags": ["injection", "xss", "moderate"],
      "description": "Injects a canary value into each parameter and checks if the response reflects it back",
      "file": "/home/user/.vigolium/extensions/reflected_param_scanner.js",
      "file_name": "reflected_param_scanner.js"
    },
    {
      "id": "sensitive-header-leak-yaml",
      "name": "Sensitive Header Leak (YAML)",
      "language": "yaml",
      "type": "passive",
      "severity": "info",
      "confidence": "certain",
      "scan_types": ["per_request"],
      "tags": ["info-disclosure", "header-security", "light"],
      "scope": "response",
      "description": "Detects responses that expose server technology details through HTTP headers",
      "file": "/home/user/.vigolium/extensions/sensitive_header_leak.vgm.yaml",
      "file_name": "sensitive_header_leak.vgm.yaml"
    }
  ],
  "total": 2,
  "extensions_enabled": true
}
```

When extensions are not configured, returns `extensions_enabled: false` and an empty list.

### Declaring Tags in Extensions

**JavaScript extensions** — add a `tags` array to `module.exports`:

```js
module.exports = {
  id: "my-scanner",
  type: "active",
  tags: ["injection", "xss", "moderate"],
  // ...
};
```

**YAML extensions** — add a `tags` list:

```yaml
id: my-scanner
type: active
tags:
  - injection
  - xss
  - moderate
```

---

## GET /api/extensions/:name — Get Extension

Returns full metadata plus raw file content for a single extension, looked up by filename.

**Path parameters:**

| Parameter | Description                                    |
|-----------|------------------------------------------------|
| `name`    | Filename of the extension (e.g. `reflected_param_scanner.js` or `sensitive_header_leak.vgm.yaml`) |

```bash
curl -s http://localhost:9002/api/extensions/reflected_param_scanner.js | jq .
curl -s http://localhost:9002/api/extensions/sensitive_header_leak.vgm.yaml | jq .
```

**Response (200):**

```json
{
  "id": "reflected-param-scanner",
  "name": "Reflected Parameter Scanner",
  "language": "js",
  "type": "active",
  "severity": "medium",
  "confidence": "firm",
  "scan_types": ["per_insertion_point"],
  "tags": ["injection", "xss", "moderate"],
  "description": "Injects a canary value into each parameter and checks if the response reflects it back",
  "file": "/home/user/.vigolium/extensions/reflected_param_scanner.js",
  "file_name": "reflected_param_scanner.js",
  "raw_content": "// reflected_param_scanner.js\nmodule.exports = { id: \"reflected-param\", ... }"
}
```

**Error responses:**

| Code | Reason                                      |
|------|---------------------------------------------|
| 404  | Extension not found among loaded extensions |

---

## PUT /api/extensions/:name — Edit Extension

Overwrites the content of an extension file identified by its filename (e.g. `reflected_param_scanner.js` or `my_check.vgm.yaml`). The file must already exist as a loaded extension.

**Path parameters:**

| Parameter | Description                                               |
|-----------|-----------------------------------------------------------|
| `name`    | Filename of the extension (must end in `.js` or `.vgm.yaml`) |

**Request body:**

| Field     | Type   | Required | Description                       |
|-----------|--------|----------|-----------------------------------|
| `content` | string | Yes      | New full content for the file     |

```bash
# Edit a JS extension
curl -s -X PUT http://localhost:9002/api/extensions/reflected_param_scanner.js \
  -H "Content-Type: application/json" \
  -d '{
    "content": "module.exports = { id: \"reflected-param-scanner\", type: \"active\", scan: function(ctx) { /* ... */ } };"
  }' | jq .

# Edit a YAML extension
curl -s -X PUT http://localhost:9002/api/extensions/ai_xss_scanner.vgm.yaml \
  -H "Content-Type: application/json" \
  -d '{"content": "id: ai-xss-scanner\ntype: active\n..."}' | jq .
```

**Response (200):**

```json
{
  "message": "extension updated",
  "file": "/home/user/.vigolium/extensions/reflected_param_scanner.js",
  "file_name": "reflected_param_scanner.js"
}
```

**Error responses:**

| Code | Reason                                                  |
|------|---------------------------------------------------------|
| 400  | Name does not end in `.js` or `.vgm.yaml`, or bad JSON |
| 404  | Extension not found among loaded extensions             |
| 500  | File write failed                                       |

---

## GET /api/extensions/docs — List JS API Functions

Returns the full JS extension API catalog — all built-in `vigolium.*` functions available to extension scripts.

**Query parameters:**

| Parameter | Type   | Description                                    |
|-----------|--------|------------------------------------------------|
| `search`  | string | Filter by function name, namespace, or description |

```bash
# List all API functions
curl -s http://localhost:9002/api/extensions/docs | jq .

# Search for HTTP-related functions
curl -s 'http://localhost:9002/api/extensions/docs?search=http' | jq .
```

**Response (200):**

```json
{
  "functions": [
    {
      "category": "Logging",
      "namespace": "vigolium.log",
      "name": "info",
      "full_name": "vigolium.log.info",
      "signature": ".info(msg: string)",
      "returns": "void",
      "description": "Log an informational message.",
      "example": "vigolium.log.info(\"scanning \" + ctx.request.url)"
    },
    {
      "category": "HTTP",
      "namespace": "vigolium.http",
      "name": "send",
      "full_name": "vigolium.http.send",
      "signature": ".send(req: HttpRequest): HttpResponse",
      "returns": "HttpResponse",
      "description": "Send an HTTP request and return the response."
    }
  ],
  "total": 42,
  "namespaces": [
    "vigolium.log",
    "vigolium.utils",
    "vigolium.http",
    "vigolium.scan",
    "vigolium.ingest",
    "vigolium.source",
    "vigolium.config"
  ]
}
```
