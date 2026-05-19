# Vigolium API Reference — Scan

## Project Scoping

All scan endpoints support multi-tenancy via the `X-Project-UUID` header. When provided, scans are created and queried within the specified project. Responses include the `project_uuid` field to confirm the project context.

```bash
# Scope a request to a specific project
curl -s -X POST http://localhost:9002/api/scans/run \
  -H "Content-Type: application/json" \
  -H "X-Project-UUID: my-project-uuid" \
  -d '{}' | jq .
```

If the header is omitted, the default project is used.

---

## Single-Target Scans

### POST /api/scan-url — Scan a URL

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
  -H "X-Project-UUID: my-project-uuid" \
  -d '{
    "url": "https://example.com/api/users?id=1"
  }' | jq .

# POST with body and specific modules
curl -s -X POST http://localhost:9002/api/scan-url \
  -H "Content-Type: application/json" \
  -H "X-Project-UUID: my-project-uuid" \
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
  "project_uuid": "my-project-uuid",
  "scan_uuid": "550e8400-e29b-41d4-a716-446655440000",
  "status": "running",
  "message": "scan-url started for https://example.com/api/users?id=1"
}
```

---

### POST /api/scan-request — Scan a Raw HTTP Request

Starts an asynchronous scan from a base64-encoded raw HTTP request, optionally paired with a base64-encoded raw HTTP response (Burp-style). Equivalent to the CLI `scan-request` command. Returns `202 Accepted` immediately with a scan ID.

**Request body:**

| Field                  | Type   | Required | Description                                                                                           |
|------------------------|--------|----------|-------------------------------------------------------------------------------------------------------|
| `http_request_base64`  | string | Yes*     | Base64-encoded raw HTTP request (preferred field name)                                                |
| `raw_request`          | string | Yes*     | Alias for `http_request_base64` (accepted for backward compatibility)                                 |
| `http_response_base64` | string | No       | Base64-encoded raw HTTP response — when provided, it's attached to the request for passive analysis instead of re-fetching |
| `raw_response`         | string | No       | Alias for `http_response_base64` (accepted for backward compatibility)                                |
| `target_url`           | string | No       | Override target URL (scheme://host) for the request                                                   |
| `modules`              | string | No       | Comma-separated module IDs to run                                                                     |
| `no_passive`           | bool   | No       | Skip passive modules                                                                                  |

> \* Exactly one of `http_request_base64` or `raw_request` is required. If both are set, `http_request_base64` wins. The same precedence applies to `http_response_base64` / `raw_response`.

> **Paired response behavior:** When `http_response_base64` is provided, passive modules analyze the supplied response directly (no extra traffic sent). Active modules still send their own probe requests — that's the nature of active scanning — but the supplied response is used for baseline passive analysis. When omitted, the scanner fetches the response itself before scanning.

```bash
# Request-only scan (scanner fetches the response)
REQ_B64=$(echo -n "POST /api/login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{\"user\":\"admin\"}" | base64)

curl -s -X POST http://localhost:9002/api/scan-request \
  -H "Content-Type: application/json" \
  -H "X-Project-UUID: my-project-uuid" \
  -d "{
    \"http_request_base64\": \"$REQ_B64\",
    \"target_url\": \"https://example.com\"
  }" | jq .

# Burp-style paired request + response
REQ_B64=$(base64 -i request.txt)
RESP_B64=$(base64 -i response.txt)

curl -s -X POST http://localhost:9002/api/scan-request \
  -H "Content-Type: application/json" \
  -H "X-Project-UUID: my-project-uuid" \
  -d "{
    \"http_request_base64\": \"$REQ_B64\",
    \"http_response_base64\": \"$RESP_B64\",
    \"target_url\": \"https://example.com\",
    \"modules\": \"all\"
  }" | jq .

# Legacy alias — still works
curl -s -X POST http://localhost:9002/api/scan-request \
  -H "Content-Type: application/json" \
  -d "{
    \"raw_request\": \"$REQ_B64\",
    \"raw_response\": \"$RESP_B64\"
  }" | jq .
```

**Response (202):**

```json
{
  "project_uuid": "my-project-uuid",
  "scan_uuid": "661f9511-f3ac-52e5-b827-557766551111",
  "status": "running",
  "message": "scan-request started for https://example.com/api/login"
}
```

**Error responses (both endpoints):**

| Code | Condition                                                      |
|------|----------------------------------------------------------------|
| 400  | Missing required fields, invalid base64, or unparseable request |

Use `GET /api/scan/status` to check the progress of the scan.

---

## Scan Management

### POST /api/scans/run — Run Target Scan

Triggers a background scan against target URLs. Equivalent to `vigolium scan -t <url>`. At least one target URL is required — use `POST /api/scan-all-records` to scan existing DB records.

Returns `202 Accepted` on success, `200 OK` for dry runs, or `409 Conflict` if a scan is already running.

**Request body:**

| Field                  | Type              | Required | Description                                                                 |
|------------------------|-------------------|----------|-----------------------------------------------------------------------------|
| `targets`              | string[]          | Yes*     | Target URLs (like `-t`). At least one target or url is required.            |
| `urls`                 | string[]          | Yes*     | Alias for `targets`. Both fields are merged if provided.                    |
| `dry_run`              | bool              | No       | Validate params and create scan record without launching the runner         |
| `strategy`             | string            | No       | Strategy preset: `lite`, `balanced`, `deep`                                 |
| `only`                 | string            | No       | Single phase isolation (like `--only`). Accepts aliases.                    |
| `skip`                 | string[]          | No       | Skip specific phases (like `--skip`). Accepts aliases.                      |
| `modules`              | string[]          | No       | Module IDs with fuzzy match (like `-m`)                                     |
| `module_tags`          | string[]          | No       | Filter modules by tag (like `--module-tag`)                                 |
| `concurrency`          | int               | No       | Number of parallel workers                                                  |
| `timeout`              | string            | No       | Request timeout as Go duration (e.g. `"30s"`)                               |
| `max_per_host`         | int               | No       | Maximum concurrent requests per host                                        |
| `rate_limit`           | int               | No       | Maximum request submissions per second                                      |
| `scanning_max_duration`| string            | No       | Global max scan duration as Go duration (like `--scanning-max-duration`). Per-phase durations are derived automatically using `duration_factor` from the scanning pace config (e.g. spidering gets `0.15 × max_duration`). |
| `scope_origin`         | string            | No       | Scope origin mode: `all`, `relaxed`, `balanced`, `strict`                   |
| `heuristics_check`     | string            | No       | Heuristics check level: `none`, `basic`, `advanced`                         |
| `headers`              | map[string]string | No       | Custom HTTP headers included in all requests                                |
| `scanning_profile`     | string            | No       | Scanning profile name or path                                               |
| `intensity`            | string            | No       | Scan intensity preset: `"quick"`, `"balanced"`, or `"deep"`. Resolves to `scanning_profile` + `strategy`. Explicit `scanning_profile` or `strategy` fields override intensity. |

**Phase duration factors:**

The `scanning_max_duration` field sets the global max duration. Each phase derives its own limit by multiplying the global value by its `duration_factor` from the scanning pace config. Default factors:

| Phase              | Default Factor | Example (2h global) |
|--------------------|---------------|---------------------|
| Spidering          | 0.15          | 18m                 |
| External Harvester | 0.20          | 24m                 |
| Audit              | 1.00          | 2h                  |
| KnownIssueScan     | 3.00          | 6h                  |

Per-phase `max_duration` overrides in the YAML config take precedence over the factor calculation.

**Phase names and aliases:**

| Canonical name       | Aliases                  |
|----------------------|--------------------------|
| `discovery`          | `deparos`, `discover`    |
| `spidering`          | `spitolas`               |
| `extension`          | `ext`                    |
| `ingestion`          | —                        |
| `external-harvest`   | —                        |
| `known-issue-scan`   | —                        |
| `dynamic-assessment` | `dast`, `audit`, `assessment` |

> **Note:** `only` and `skip` are mutually exclusive — providing both returns `400`.

```bash
# Scan a target with default strategy
curl -s -X POST http://localhost:9002/api/scans/run \
  -H "Content-Type: application/json" \
  -H "X-Project-UUID: my-project-uuid" \
  -d '{
    "targets": ["https://example.com"]
  }' | jq .

# Using "urls" alias
curl -s -X POST http://localhost:9002/api/scans/run \
  -H "Content-Type: application/json" \
  -d '{
    "urls": ["https://example.com", "https://api.example.com"]
  }' | jq .

# Lite strategy, discovery only, with custom headers
curl -s -X POST http://localhost:9002/api/scans/run \
  -H "Content-Type: application/json" \
  -H "X-Project-UUID: my-project-uuid" \
  -d '{
    "targets": ["https://example.com"],
    "strategy": "lite",
    "only": "discovery",
    "headers": {"Authorization": "Bearer tok123"},
    "concurrency": 20,
    "timeout": "10s"
  }' | jq .

# Dry run — validate params without launching the scan
curl -s -X POST http://localhost:9002/api/scans/run \
  -H "Content-Type: application/json" \
  -H "X-Project-UUID: my-project-uuid" \
  -d '{
    "targets": ["https://example.com"],
    "strategy": "deep",
    "dry_run": true
  }' | jq .
```

**Response (202):**

```json
{
  "project_uuid": "my-project-uuid",
  "scan_uuid": "550e8400-e29b-41d4-a716-446655440000",
  "status": "running",
  "message": "scan started",
  "targets_count": 1,
  "scan_mode": "target"
}
```

**Response — queued (202):**

When the scan queue is enabled and another scan is already running, new scans are queued instead of returning `409`:

```json
{
  "project_uuid": "my-project-uuid",
  "scan_uuid": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued",
  "message": "scan queued (position 2)",
  "targets_count": 1,
  "scan_mode": "target"
}
```

**Response — dry run (200):**

```json
{
  "project_uuid": "my-project-uuid",
  "scan_uuid": "550e8400-e29b-41d4-a716-446655440000",
  "status": "dry_run",
  "message": "scan record created (dry run)",
  "targets_count": 1,
  "scan_mode": "target"
}
```

**Scan Configuration output:**

When a scan starts (via API or CLI), the runner logs a configuration summary to stderr showing the effective settings. This is useful for verifying that `scanning_max_duration` and per-phase duration factors are applied correctly.

```
✦ Scan Configuration
  ℹ Project: my-project-uuid
  ℹ Strategy: balanced
  ℹ Phases: ✓ ExternalHarvest (24m0s, x0.2) | ✓ Spidering (18m0s, x0.2) | ✓ Discovery
            ✓ KnownIssueScan (6h0m0s, x3.0) | ✓ Audit (2h0m0s, x1.0)
  ℹ Speed: concurrency=50 | rate-limit=100 | max-per-host=10
  ℹ Modules: 42 active, 12 passive
```

**Error responses:**

| Code | Condition                                                                 |
|------|---------------------------------------------------------------------------|
| 400  | Missing targets, invalid parameters, or missing DB                         |
| 409  | A scan is already running                                                 |
| 500  | Failed to create scan runner                                              |

---

### GET /api/scan/status — Scan Status

Returns the status of the current or most recent scan. The `status` field reflects pause state when applicable.

```bash
curl -s http://localhost:9002/api/scan/status \
  -H "X-Project-UUID: my-project-uuid" | jq .
```

**Running:**

```json
{
  "project_uuid": "my-project-uuid",
  "scan_uuid": "scan-abc123",
  "running": true,
  "status": "running"
}
```

**Paused:**

```json
{
  "project_uuid": "my-project-uuid",
  "scan_uuid": "scan-abc123",
  "running": true,
  "status": "paused"
}
```

**Idle (no scan running):**

```json
{
  "project_uuid": "my-project-uuid",
  "running": false,
  "status": "idle"
}
```

---

## Scan Modes

Every scan record has a `scan_mode` field that indicates how the scan was triggered. This helps distinguish between different scanning workflows when reviewing scan history.

| Mode          | Origin                                   | Description                                                                                    |
|---------------|------------------------------------------|------------------------------------------------------------------------------------------------|
| `full`        | `vigolium scan`, `vigolium run`          | Batch scan over all in-scope HTTP records in the database                                      |
| `target`      | `POST /api/scans/run`                    | API-initiated scan targeting a specific URL or scope                                           |
| `incremental` | Server scan-on-receive                   | Continuous scan that processes each HTTP record as it is ingested into the server (proxy, Burp, etc.) |
| `single`      | `POST /api/scan-url`                     | One-off scan of a single URL with optional method, body, and headers                           |
| `selective`   | `POST /api/scan/records`                 | Scan a specific set of HTTP records by UUID                                                    |

---

## Scan History

### GET /api/scans — List Scans

Returns paginated scan history ordered by creation date (newest first).

**Query parameters:**

| Parameter | Type | Default | Description                          |
|-----------|------|---------|--------------------------------------|
| `limit`   | int  | 50      | Number of scans to return (max 500)  |
| `offset`  | int  | 0       | Offset for pagination                |

```bash
# List recent scans
curl -s http://localhost:9002/api/scans \
  -H "X-Project-UUID: my-project-uuid" | jq .

# Paginate
curl -s 'http://localhost:9002/api/scans?limit=10&offset=0' \
  -H "X-Project-UUID: my-project-uuid" | jq .
```

```json
{
  "project_uuid": "my-project-uuid",
  "data": [
    {
      "uuid": "scan-abc123",
      "name": "api-scan",
      "status": "completed",
      "scan_source": "api",
      "scan_mode": "incremental",
      "source_type": "local",
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

### GET /api/scans/:uuid — Get Scan Detail

Returns a single scan by UUID.

```bash
curl -s http://localhost:9002/api/scans/scan-abc123 \
  -H "X-Project-UUID: my-project-uuid" | jq .
```

**Error responses:**

| Code | Condition            |
|------|----------------------|
| 400  | Missing UUID         |
| 404  | Scan not found       |
| 503  | Database unavailable |

---

### DELETE /api/scans/:uuid — Delete Scan

Deletes a scan record by UUID.

```bash
curl -s -X DELETE http://localhost:9002/api/scans/scan-abc123 \
  -H "X-Project-UUID: my-project-uuid" | jq .
```

```json
{
  "project_uuid": "my-project-uuid",
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

### POST /api/scans/:uuid/stop — Stop a Running Scan

Stops a specific running scan by UUID. The scan must be the currently active scan. Workers finish their current tasks before fully stopping.

```bash
curl -s -X POST http://localhost:9002/api/scans/scan-abc123/stop \
  -H "X-Project-UUID: my-project-uuid" | jq .
```

```json
{
  "project_uuid": "my-project-uuid",
  "scan_uuid": "scan-abc123",
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

### POST /api/scans/:uuid/pause — Pause a Running Scan

Pauses a running scan. Workers finish their current item then block until resumed. The scan status is set to `"paused"` in the database.

```bash
curl -s -X POST http://localhost:9002/api/scans/scan-abc123/pause \
  -H "X-Project-UUID: my-project-uuid" | jq .
```

```json
{
  "project_uuid": "my-project-uuid",
  "scan_uuid": "scan-abc123",
  "running": true,
  "status": "paused",
  "message": "scan paused, workers finishing current items"
}
```

**Error responses:**

| Code | Condition                                        |
|------|--------------------------------------------------|
| 400  | Missing UUID                                     |
| 409  | No scan running, UUID is not the active scan, or scan is already paused |

---

### POST /api/scans/:uuid/resume — Resume a Paused Scan

Resumes a previously paused scan. Blocked workers continue processing items and the scan status is set back to `"running"`.

```bash
curl -s -X POST http://localhost:9002/api/scans/scan-abc123/resume \
  -H "X-Project-UUID: my-project-uuid" | jq .
```

```json
{
  "project_uuid": "my-project-uuid",
  "scan_uuid": "scan-abc123",
  "running": true,
  "status": "running",
  "message": "scan resumed"
}
```

**Error responses:**

| Code | Condition                                        |
|------|--------------------------------------------------|
| 400  | Missing UUID                                     |
| 409  | No scan running, UUID is not the active scan, or scan is not paused |

---

### GET /api/scans/:uuid/logs — Get Scan Logs

Returns log output for a scan. The endpoint serves one of two response formats depending on what the server has on disk:

1. **`text/plain` runtime.log (preferred)** — When the scan's session directory contains a `runtime.log` file (the default for scans launched via the server today, including `/api/scan-url`, `/api/scan-request`, and `/api/scans/run`), the raw log is streamed as `text/plain; charset=utf-8`. ANSI color codes are preserved by default; pass `?strip=1` to strip them. This matches what the CLI `vigolium log` command streams.
2. **JSON envelope (legacy fallback)** — When no `runtime.log` exists (older scans that predate runtime.log persistence), the endpoint falls back to the `scan_logs` database table and returns the structured JSON envelope (`{"project_uuid": "...", "logs": [...], "total": N}`). The `level`, `phase`, `limit`, and `offset` query parameters apply only to this fallback path.

The structured `scan_logs` table captures log entries at multiple levels:

- **Structured events** (`info`, `warn`, `error`): Phase lifecycle events (start, complete, fail, skip), scan start/finish, pause/resume, configuration snapshots, and panic recovery.
- **Raw console output** (`trace`): Every line printed to the terminal during the scan, with ANSI color codes stripped. This includes phase headers, traffic lines (`❯ spider │ [200] GET ...`), progress feedback, and scan configuration banners.

**Query parameters:**

| Parameter | Type   | Default | Description                                                                                                   |
|-----------|--------|---------|---------------------------------------------------------------------------------------------------------------|
| `strip`   | bool   | `false` | (runtime.log path only) Strip ANSI color codes from the plain-text output                                     |
| `limit`   | int    | 100     | (JSON fallback only) Number of log entries to return                                                          |
| `offset`  | int    | 0       | (JSON fallback only) Offset for pagination                                                                    |
| `level`   | string |         | (JSON fallback only) Filter by log level: `trace`, `info`, `warn`, `error`. Use `trace` to replay raw console output. |
| `phase`   | string |         | (JSON fallback only) Filter by scan phase: `config`, `heuristics`, `harvest`, `spidering`, `discovery`, `known-issue-scan`, `audit`, `seed`. Use `config` to retrieve the scan configuration snapshot. |

```bash
# Stream the runtime.log (preferred, plain text)
curl -s http://localhost:9002/api/scans/scan-abc123/logs \
  -H "X-Project-UUID: my-project-uuid"

# Same, but strip ANSI color codes
curl -s 'http://localhost:9002/api/scans/scan-abc123/logs?strip=1' \
  -H "X-Project-UUID: my-project-uuid"

# Legacy JSON fallback — only used when runtime.log is not on disk

# Filter by level with pagination
curl -s 'http://localhost:9002/api/scans/scan-abc123/logs?level=error&limit=20' \
  -H "X-Project-UUID: my-project-uuid" | jq .

# Replay raw console output (terminal log)
curl -s 'http://localhost:9002/api/scans/scan-abc123/logs?level=trace' \
  -H "X-Project-UUID: my-project-uuid" | jq .

# Get only spidering phase logs
curl -s 'http://localhost:9002/api/scans/scan-abc123/logs?phase=spidering' \
  -H "X-Project-UUID: my-project-uuid" | jq .

# Get scan configuration snapshot
curl -s 'http://localhost:9002/api/scans/scan-abc123/logs?phase=config' \
  -H "X-Project-UUID: my-project-uuid" | jq .

# Combine filters: structured discovery events only
curl -s 'http://localhost:9002/api/scans/scan-abc123/logs?level=info&phase=discovery' \
  -H "X-Project-UUID: my-project-uuid" | jq .
```

**Response — runtime.log (`Content-Type: text/plain`):**

```
✦ Scan Configuration
  ℹ Project: my-project-uuid
  ℹ Strategy: balanced
  ℹ Phases: ✓ Spidering | ✓ Discovery | ✓ Audit
✦ Spidering  browser-based crawling to discover dynamic content and API endpoints
❯ spider │ [200] GET text/html http://localhost:3000/
❯ spider │ [200] GET application/json http://localhost:9002/api/projects
✦ Discovery  ingest input + content discovery into database
...
```

**Response — structured events (`level=info`, JSON fallback):**

```json
{
  "project_uuid": "my-project-uuid",
  "logs": [
    {
      "id": 1,
      "scan_uuid": "scan-abc123",
      "level": "info",
      "message": "scan started",
      "created_at": "2026-02-16T15:00:00Z"
    },
    {
      "id": 2,
      "scan_uuid": "scan-abc123",
      "level": "info",
      "phase": "config",
      "message": "scan configuration snapshot",
      "metadata": "{\"project_uuid\":\"my-project-uuid\",\"targets\":[\"https://example.com\"],\"strategy\":\"balanced\",\"concurrency\":50,\"rate_limit\":100,\"max_per_host\":10,\"active_modules\":152,\"passive_modules\":93,\"spidering_enabled\":true,\"discovery_enabled\":true,\"known_issue_scan_enabled\":false}",
      "created_at": "2026-02-16T15:00:00Z"
    },
    {
      "id": 3,
      "scan_uuid": "scan-abc123",
      "level": "info",
      "phase": "heuristics",
      "message": "phase started",
      "created_at": "2026-02-16T15:00:01Z"
    },
    {
      "id": 4,
      "scan_uuid": "scan-abc123",
      "level": "info",
      "phase": "heuristics",
      "message": "phase completed",
      "created_at": "2026-02-16T15:00:02Z"
    },
    {
      "id": 5,
      "scan_uuid": "scan-abc123",
      "level": "info",
      "phase": "spidering",
      "message": "phase started",
      "created_at": "2026-02-16T15:00:02Z"
    },
    {
      "id": 6,
      "scan_uuid": "scan-abc123",
      "level": "info",
      "phase": "spidering",
      "message": "phase completed",
      "created_at": "2026-02-16T15:01:30Z"
    },
    {
      "id": 7,
      "scan_uuid": "scan-abc123",
      "level": "info",
      "phase": "discovery",
      "message": "phase started",
      "created_at": "2026-02-16T15:01:31Z"
    },
    {
      "id": 8,
      "scan_uuid": "scan-abc123",
      "level": "info",
      "phase": "discovery",
      "message": "soft-deduplicated 42 similar records",
      "created_at": "2026-02-16T15:02:30Z"
    },
    {
      "id": 9,
      "scan_uuid": "scan-abc123",
      "level": "info",
      "phase": "discovery",
      "message": "phase completed",
      "created_at": "2026-02-16T15:03:00Z"
    },
    {
      "id": 10,
      "scan_uuid": "scan-abc123",
      "level": "info",
      "phase": "audit",
      "message": "phase started",
      "metadata": "{\"active_modules\":127,\"passive_modules\":85}",
      "created_at": "2026-02-16T15:03:01Z"
    },
    {
      "id": 11,
      "scan_uuid": "scan-abc123",
      "level": "info",
      "phase": "audit",
      "message": "phase completed",
      "created_at": "2026-02-16T15:10:00Z"
    },
    {
      "id": 12,
      "scan_uuid": "scan-abc123",
      "level": "info",
      "message": "scan finished",
      "created_at": "2026-02-16T15:10:01Z"
    }
  ],
  "total": 12
}
```

**Response — raw console output (`level=trace`, JSON fallback):**

```json
{
  "project_uuid": "my-project-uuid",
  "logs": [
    {
      "id": 100,
      "scan_uuid": "scan-abc123",
      "level": "trace",
      "phase": "heuristics",
      "message": "✦ HeuristicsCheck  probing CLI target root pages to optimize phase selection",
      "created_at": "2026-02-16T15:00:01Z"
    },
    {
      "id": 101,
      "scan_uuid": "scan-abc123",
      "level": "trace",
      "phase": "heuristics",
      "message": "◆ Level: basic | Targets: 1",
      "created_at": "2026-02-16T15:00:01Z"
    },
    {
      "id": 102,
      "scan_uuid": "scan-abc123",
      "level": "trace",
      "phase": "spider",
      "message": "✦ Spidering  browser-based crawling to discover dynamic content and API endpoints",
      "created_at": "2026-02-16T15:00:02Z"
    },
    {
      "id": 103,
      "scan_uuid": "scan-abc123",
      "level": "trace",
      "phase": "spider",
      "message": "❯ spider │ [200] GET text/html http://localhost:3000/",
      "created_at": "2026-02-16T15:00:03Z"
    },
    {
      "id": 104,
      "scan_uuid": "scan-abc123",
      "level": "trace",
      "phase": "spider",
      "message": "❯ spider │ [200] GET application/json http://localhost:9002/api/projects",
      "created_at": "2026-02-16T15:00:04Z"
    },
    {
      "id": 105,
      "scan_uuid": "scan-abc123",
      "level": "trace",
      "phase": "discovery",
      "message": "✦ Discovery  ingest input + content discovery into database",
      "created_at": "2026-02-16T15:01:31Z"
    }
  ],
  "total": 580
}
```

**Response — configuration snapshot (`phase=config`, JSON fallback):**

```json
{
  "project_uuid": "my-project-uuid",
  "logs": [
    {
      "id": 2,
      "scan_uuid": "scan-abc123",
      "level": "info",
      "phase": "config",
      "message": "scan configuration snapshot",
      "metadata": "{\"project_uuid\":\"my-project-uuid\",\"targets\":[\"https://example.com\"],\"strategy\":\"balanced\",\"scanning_profile\":\"\",\"concurrency\":50,\"rate_limit\":100,\"max_per_host\":10,\"heuristics_check\":\"basic\",\"scope_origin_mode\":\"relaxed\",\"active_modules\":152,\"passive_modules\":93,\"spidering_enabled\":true,\"discovery_enabled\":true,\"known_issue_scan_enabled\":false,\"external_harvest\":false,\"skip_dynamic\":false}",
      "created_at": "2026-02-16T15:00:00Z"
    }
  ],
  "total": 1
}
```

**Log entry fields:**

| Field        | Type   | Description                                                                                       |
|--------------|--------|---------------------------------------------------------------------------------------------------|
| `id`         | int    | Auto-incrementing log entry ID                                                                    |
| `scan_uuid`  | string | UUID of the scan this log belongs to                                                              |
| `level`      | string | Log level: `trace`, `info`, `warn`, or `error`                                                    |
| `phase`      | string | Scan phase (see table below), or empty for global events (scan start/finish, pause/resume)        |
| `message`    | string | Human-readable log message. For `trace` entries, this is the raw console line with ANSI codes stripped. |
| `metadata`   | string | Optional JSON blob with structured context. Present on config snapshots and phase-start events.   |
| `created_at` | string | ISO 8601 timestamp                                                                                |

**Phase values:**

| Phase                | Description                                                       |
|----------------------|-------------------------------------------------------------------|
| `config`             | Scan configuration snapshot (logged once at scan start)           |
| `heuristics`         | Target root page probing to optimize phase selection              |
| `harvest`            | External URL harvesting from intelligence sources                 |
| `spidering`          | Browser-based crawling                                            |
| `discovery`          | Input ingestion + content discovery                               |
| `seed`               | CLI target seeding (when discovery is skipped)                    |
| `known-issue-scan`   | Known issue scan (Nuclei + Kingfisher)                            |
| `audit`              | Active/passive module scanning                                    |

**Log levels:**

| Level   | Description                                                                                       |
|---------|---------------------------------------------------------------------------------------------------|
| `trace` | Raw console output lines (ANSI-stripped). High volume — includes traffic lines, phase banners, progress feedback. Buffered and batch-inserted every 2 seconds. |
| `info`  | Structured lifecycle events: phase start/complete/skip, config snapshots, scan start/finish.       |
| `warn`  | Non-fatal issues: phase deduplication failures, heuristics warnings.                              |
| `error` | Phase failures, panic recovery, critical errors.                                                  |

**Error responses:**

| Code | Condition            |
|------|----------------------|
| 400  | Missing UUID         |
| 404  | Scan not found       |
| 503  | Database unavailable |

---

## Selective Record Scan

### POST /api/scan-records — Scan Specific HTTP Records

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
  -H "X-Project-UUID: my-project-uuid" \
  -d '{
    "record_uuids": ["abc-123", "def-456", "ghi-789"]
  }' | jq .

# Scan with specific modules
curl -s -X POST http://localhost:9002/api/scan-records \
  -H "Content-Type: application/json" \
  -H "X-Project-UUID: my-project-uuid" \
  -d '{
    "record_uuids": ["abc-123"],
    "enable_modules": ["xss-scanner", "sqli-error-based"]
  }' | jq .
```

**Response (202):**

```json
{
  "project_uuid": "my-project-uuid",
  "scan_uuid": "550e8400-e29b-41d4-a716-446655440000",
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

### POST /api/scan-all-records — Scan All DB Records

Scans existing HTTP records from the database with optional filtering. Equivalent to the DB-record scan mode, but as a dedicated route with rich filtering options.

Returns `202 Accepted` on success, `200 OK` for dry runs, or `409 Conflict` if a scan is already running.

**Request body:**

| Field                  | Type              | Required | Description                                                                 |
|------------------------|-------------------|----------|-----------------------------------------------------------------------------|
| `hostname`             | string            | No       | Hostname filter (supports `*` wildcards, e.g. `*.example.com`)             |
| `methods`              | string[]          | No       | HTTP methods filter (e.g. `["GET", "POST"]`)                               |
| `path`                 | string            | No       | Path filter (supports `*` wildcards, e.g. `/api/*`)                        |
| `status_codes`         | int[]             | No       | Status code filter (e.g. `[200, 301]`)                                     |
| `source`               | string            | No       | Record source filter (e.g. `ingest-server`, `scanner`)                     |
| `search`               | string            | No       | Search across URL and path                                                 |
| `min_risk_score`       | int               | No       | Minimum risk score filter                                                  |
| `remark`               | string            | No       | Remark substring filter                                                    |
| `force`                | bool              | No       | Force full rescan (scan mode `full` vs `incremental`)                      |
| `dry_run`              | bool              | No       | Count matching records without launching the scan                          |
| `modules`              | string[]          | No       | Module IDs with fuzzy match (like `-m`)                                     |
| `module_tags`          | string[]          | No       | Filter modules by tag (like `--module-tag`)                                 |
| `concurrency`          | int               | No       | Number of parallel workers                                                  |
| `timeout`              | string            | No       | Request timeout as Go duration (e.g. `"30s"`)                               |
| `max_per_host`         | int               | No       | Maximum concurrent requests per host                                        |
| `rate_limit`           | int               | No       | Maximum request submissions per second                                      |
| `scanning_max_duration`| string            | No       | Global max scan duration as Go duration. Per-phase durations are derived using `duration_factor` (see [phase duration factors](#post-apiscanrun--run-target-scan) above). |
| `heuristics_check`     | string            | No       | Heuristics check level: `none`, `basic`, `advanced`                         |
| `headers`              | map[string]string | No       | Custom HTTP headers included in all requests                                |
| `scanning_profile`     | string            | No       | Scanning profile name or path                                               |
| `intensity`            | string            | No       | Scan intensity preset: `"quick"`, `"balanced"`, or `"deep"`. Resolves to `scanning_profile` + `strategy`. |

```bash
# Scan all records (no filters)
curl -s -X POST http://localhost:9002/api/scan-all-records \
  -H "Content-Type: application/json" \
  -H "X-Project-UUID: my-project-uuid" \
  -d '{}' | jq .

# Scan only records matching a hostname
curl -s -X POST http://localhost:9002/api/scan-all-records \
  -H "Content-Type: application/json" \
  -H "X-Project-UUID: my-project-uuid" \
  -d '{
    "hostname": "*.example.com",
    "modules": ["xss-scanner", "sqli-error-based"]
  }' | jq .

# Scan POST requests with high risk score
curl -s -X POST http://localhost:9002/api/scan-all-records \
  -H "Content-Type: application/json" \
  -d '{
    "methods": ["POST", "PUT"],
    "min_risk_score": 5,
    "force": true
  }' | jq .

# Dry run — count matching records without scanning
curl -s -X POST http://localhost:9002/api/scan-all-records \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "api.example.com",
    "dry_run": true
  }' | jq .
```

**Response (202):**

```json
{
  "project_uuid": "my-project-uuid",
  "scan_uuid": "550e8400-e29b-41d4-a716-446655440000",
  "status": "running",
  "message": "all-records scan started",
  "records_to_scan": 142,
  "scan_mode": "full"
}
```

**Response — dry run (200):**

```json
{
  "project_uuid": "my-project-uuid",
  "scan_uuid": "550e8400-e29b-41d4-a716-446655440000",
  "status": "dry_run",
  "message": "scan record created (dry run)",
  "records_to_scan": 142,
  "scan_mode": "incremental"
}
```

**Error responses:**

| Code | Condition                                    |
|------|----------------------------------------------|
| 400  | No records match filters, or invalid params  |
| 409  | A scan is already running                    |
| 503  | Database unavailable                         |

