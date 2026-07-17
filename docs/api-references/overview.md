# Vigolium API Reference — Overview

Base URL: `http://localhost:9002` (default)

## Starting the Server

```bash
# No authentication (development)
vigolium server -A

# With API key
export VIGOLIUM_API_KEY="my-secret-key"
vigolium server

# Custom host/port
vigolium server -A --host 127.0.0.1 --service-port 8080
```

## Authentication

Protected routes require a Bearer token when the server is started normally.
The key comes from `VIGOLIUM_API_KEY` or `server.auth_api_key`; file-backed
users can also log in at `POST /api/auth/login`. Pass `-A/--no-auth` only for a
trusted local development server.

```bash
curl -H "Authorization: Bearer my-secret-key" http://localhost:9002/api/stats
```

Public endpoints (no auth required): the dashboard/static assets at `/`,
`GET /health`, `GET /ready`, `GET /swagger/*`, `GET /metrics`, and
`POST /api/auth/login`. `/server-info` and other `/api/*` routes are protected.

## Project Scoping

Data API operations are scoped to a project via the `X-Project-UUID` request
header. If the header is omitted, the default project
(`00000000-0000-0000-defa-c01001000001`) is used.

```bash
# Scope requests to a specific project
curl -H "Authorization: Bearer my-secret-key" \
     -H "X-Project-UUID: a1b2c3d4-..." \
     http://localhost:9002/api/findings
```

This applies to data endpoints such as ingestion, findings, HTTP records,
stats, scans, storage, agent runs, and OAST interactions. See
[Projects](../projects.md) for the full multi-tenancy reference.

---

## GET / — Dashboard

Serves the dashboard HTML and its static assets. Application metadata is
available from the authenticated `GET /api/info` endpoint.

```bash
curl -s http://localhost:9002/ | head
```

## GET /api/info — App Info

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:9002/api/info | jq .
```

```json
{
  "name": "vigolium",
  "version": "v0.3.2",
  "author": "@j3ssie",
  "docs": "https://docs.vigolium.com",
  "build_time": "2026-07-14T08:08:41Z",
  "commit": "c50ba85"
}
```

---

## GET /api/diagnostics — System Readiness Check

Returns a diagnostic report checking database, agent backend, third-party tools, queue health, and directory configuration. See [Diagnostics](diagnostics.md) for full details.

```bash
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:9002/api/diagnostics | jq .status
```

```json
"ready"
```

---

## GET /health — Health Check

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

## GET /ready — Readiness Check

Returns `200` when the server is ready to accept work and `503` when its
database is unavailable. Unlike `/health`, this endpoint performs a database
ping.

```bash
curl -s http://localhost:9002/ready | jq .
```

---

## GET /server-info — Server Info

Returns detailed server information including uptime, database driver, queue depth, and record/finding totals.

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:9002/server-info | jq .
```

```json
{
  "name": "vigolium",
  "version": "v0.3.2",
  "author": "@j3ssie",
  "docs": "https://docs.vigolium.com",
  "build_time": "2026-07-14T08:08:41Z",
  "commit": "c50ba85",
  "uptime": "5m32s",
  "service_addr": "0.0.0.0:9002",
  "proxy_addr": "",
  "queue_depth": 0,
  "total_records": 1234,
  "total_findings": 42,
  "license": "community-demo",
  "demo_only": true,
  "view_only": false
}
```

`license`, `demo_only`, and `view_only` are omitted when unset/false. Configure `license` under `server.license` in `vigolium-configs.yaml`; `demo_only` / `view_only` reflect the `--demo-only` / `--view-only` server flags.

---

## GET /swagger/* — Swagger UI

Interactive API documentation. Open in a browser.

```
http://localhost:9002/swagger/
```

The raw OpenAPI 3.0 spec is available at:

```bash
curl -s http://localhost:9002/swagger/doc.json | jq .info
```

---

## GET /metrics — Prometheus Metrics

Returns Prometheus-formatted metrics without authentication when
`server.enable_metrics` is enabled (the default).

```bash
curl -s http://localhost:9002/metrics
```

---

## CORS

CORS can be enabled via the `cors_allowed_origins` server config:

| Value              | Behavior                                              |
|--------------------|-------------------------------------------------------|
| `*`                | Allow all origins                                     |
| `reflect-origin`   | Reflect the request's `Origin` header (allows credentials) |
| `origin1,origin2`  | Allow specific origins (comma-separated, allows credentials) |
| *(empty/omitted)*  | CORS disabled                                         |

Allowed methods: `GET`, `POST`, `PUT`, `DELETE`, `OPTIONS`. Allowed headers:
`Content-Type`, `Authorization`, `X-Project-UUID`, and `X-User-Email`.

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
| 403  | Authenticated but role/mode does not allow the operation |
| 404  | Not found (e.g. agent run ID not found)      |
| 409  | Conflict (for example, a project scan is already running) |
| 429  | Agent concurrency pool or per-project quota is saturated |
| 500  | Internal server error                         |
| 503  | Database not available                        |
