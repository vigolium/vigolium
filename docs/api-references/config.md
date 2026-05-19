# Vigolium API Reference — Config

## GET /api/config — View Configuration

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

## POST /api/config — Update Configuration

Updates one or more configuration values using dot-notation keys. Values are coerced to match the existing field type (bool, int, float, string, or comma-separated list). Changes are persisted to the config file on disk.

Reloadable sections (scope, notify, audit, mutation_strategy) take effect immediately. Server and database changes require a restart.

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
    "audit.extensions.enabled": "false"
  }' | jq .

# Update a list value (comma-separated)
curl -s -X POST http://localhost:9002/api/config \
  -H "Content-Type: application/json" \
  -d '{
    "audit.enabled_modules.active_modules": "xss-scanner,sqli-error-based,lfi-path-traversal"
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

## Config Hot Reload

The server watches the config file (`~/.vigolium/vigolium-configs.yaml`) for changes. When the file is modified — whether by a text editor, the CLI (`vigolium config set`), or any other tool — reloadable sections are automatically applied without restarting the server.

**Reloadable sections:** `scope`, `notify`, `audit`, `mutation_strategy`

**Non-reloadable sections:** `server`, `database` (a warning is logged; restart required)

Changes made via the API (`POST /api/config`, `POST /api/scope`) do not trigger a redundant reload.
