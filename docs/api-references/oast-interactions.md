# Vigolium API Reference — OAST Interactions

Out-of-band Application Security Testing (OAST) interactions recorded from interactsh callbacks. These represent DNS, HTTP, or other protocol interactions triggered by payloads injected during active scanning.

## GET /api/oast-interactions — List OAST Interactions

Returns paginated OAST interactions. Heavy fields (`raw_request`, `raw_response`) are excluded from list responses for performance.

**Query parameters:**

| Parameter   | Type   | Default | Description                                         |
|-------------|--------|---------|-----------------------------------------------------|
| `limit`     | int    | 50      | Number of interactions to return (max 500)          |
| `offset`    | int    | 0       | Offset for pagination                               |
| `scan_uuid`   | string |         | Filter by scan UUID                                 |
| `protocol`  | string |         | Filter by protocol (e.g. `dns`, `http`, `smtp`)     |
| `module_id` | string |         | Filter by module ID                                 |
| `search`    | string |         | Search across target URL, parameter name, unique ID |

```bash
# List all OAST interactions
curl -s http://localhost:9002/api/oast-interactions | jq .

# Filter by protocol
curl -s 'http://localhost:9002/api/oast-interactions?protocol=dns&limit=5' | jq .

# Filter by scan
curl -s 'http://localhost:9002/api/oast-interactions?scan_uuid=scan-456' | jq .

# Search by target URL
curl -s 'http://localhost:9002/api/oast-interactions?search=example.com' | jq .
```

```json
{
  "project_uuid": "my-project-uuid",
  "data": [
    {
      "id": 1,
      "project_uuid": "my-project-uuid",
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
      "finding_id": 42,
      "payload": "abc123def456.oast.fun",
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

## GET /api/oast-interactions/:id — Get OAST Interaction Detail

Returns a single OAST interaction by its numeric ID, including full `raw_request` and `raw_response` fields.

```bash
curl -s http://localhost:9002/api/oast-interactions/1 | jq .
```

```json
{
  "id": 1,
  "project_uuid": "my-project-uuid",
  "scan_uuid": "scan-456",
  "unique_id": "abc123def456",
  "full_id": "abc123def456.oast.fun",
  "protocol": "http",
  "raw_request": "GET / HTTP/1.1\r\nHost: abc123def456.oast.fun\r\n\r\n",
  "raw_response": "HTTP/1.1 200 OK\r\n\r\n<html>...</html>",
  "remote_address": "203.0.113.42",
  "interacted_at": "2026-02-16T15:10:00Z",
  "target_url": "https://example.com/api/users?id=1",
  "parameter_name": "id",
  "injection_type": "param_value",
  "module_id": "ssrf-detection",
  "finding_id": 42,
  "payload": "abc123def456.oast.fun",
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

## DELETE /api/oast-interactions/:id — Delete OAST Interaction

Deletes a single OAST interaction by its numeric ID. Returns `404` if the interaction does not exist.

```bash
curl -s -X DELETE http://localhost:9002/api/oast-interactions/1 | jq .
```

**Response (200):**

```json
{
  "message": "OAST interaction deleted",
  "id": 1
}
```

**Error responses:**

| Code | Condition                      |
|------|--------------------------------|
| 400  | Invalid ID (not a number)      |
| 404  | OAST interaction not found     |
| 503  | Database unavailable           |
