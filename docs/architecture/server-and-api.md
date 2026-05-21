# Server & API Architecture

> _Architecture series: [overview](overview.md) · [native-scan](native-scan.md) · [agentic-scan](agentic-scan.md) · [data-and-storage](data-and-storage.md) · **server-and-api**_

Vigolium runs as a long-lived service via `vigolium server`: a Fiber REST API that ingests traffic, triggers native and agentic scans, and serves results — all sharing the same project-scoped persistence layer as the CLI. This document explains the service's shape and request lifecycle. For curl-by-curl recipes see [server-and-ingestion.md](../server-and-ingestion.md); for the full endpoint catalogue see [api-overview.md](../api-overview.md) and [api-references/](../api-references/).

---

## 1. Process model

```
                         vigolium server
   ┌───────────────────────────────────────────────────────────┐
   │  Fiber HTTP server            :9002 (0.0.0.0 default)       │
   │    middleware: CORS → auth (Bearer) → project resolve       │
   │                                                             │
   │  ┌─────────────┐  ┌──────────────┐  ┌───────────────────┐  │
   │  │ Ingestion   │  │ Scan control │  │ Agent run API     │  │
   │  │ handlers    │  │ handlers     │  │ handlers_agent.go │  │
   │  └──────┬──────┘  └──────┬───────┘  └─────────┬─────────┘  │
   │         └──────────┬─────┴────────────────────┘            │
   │                    ▼                                        │
   │            shared Repository (SQLite / PostgreSQL)          │
   └───────────────────────────────────────────────────────────┘
            ▲                                  ▲
            │ optional transparent proxy       │ vigolium-ingestor
            │ (--ingest-proxy-port :9003)      │ (remote client)
```

The server is `pkg/server/` (Fiber). It owns no scan logic of its own — it wraps the same `internal/runner` native pipeline and the same `pkg/agent` orchestrators the CLI uses, so behavior is identical whichever entry point launches a scan. Three traffic sources feed the same `RecordWriter` → repository path: the `/api/ingest-http` endpoint, the optional transparent HTTP proxy, and the standalone `vigolium-ingestor` client.

### Middleware chain

Every request (except `/`, `/health`, `/metrics`, `/swagger/*`) passes:

1. **CORS** — `server.cors_allowed_origins`: `reflect-origin` (default, credentialed echo), `*` (wildcard, no credentials), explicit comma-separated allowlist, or empty (disabled).
2. **Auth** — `Authorization: Bearer <key>`; key resolves `VIGOLIUM_API_KEY` env > `server.auth_api_key` config. `vigolium server -A` disables auth (development only).
3. **Project resolution** — `X-Project-UUID` header selects the tenant (default project if absent); `X-User-Email` drives optional per-project access control (`403` on denial). See [data-and-storage.md](data-and-storage.md#1-multi-tenancy-the-project_uuid-spine).

---

## 2. Traffic ingestion

`POST /api/ingest-http` is the universal entry point. A single endpoint accepts many `input_mode`s, normalizes them into `HttpRequestResponse` items, and hands them to the async `RecordWriter`:

| `input_mode` | Payload field | Source |
|---|---|---|
| `url` / `url_file` | `content` | One URL / newline-separated list |
| `curl` | `content` or `content_base64` | A curl command string |
| `burp_base64` | `http_request_base64` (+ optional `http_response_base64`, `url` hint) | Raw HTTP request |
| `openapi` / `swagger` | `content` or `content_base64` | OpenAPI/Swagger spec |
| `postman_collection` | `content_base64` | Postman collection |

Large payloads should use the `*_base64` fields to avoid JSON escaping. The same parsers back the `vigolium ingest` CLI, which runs in two modes: **remote** (`-s http://server` → POSTs to `/api/ingest-http`) or **local** (`--server` omitted → fetches and writes straight to the DB).

### Transparent proxy

`vigolium server --ingest-proxy-port 9003` opens a recording HTTP proxy. Plain HTTP traffic routed through it is captured into the DB; HTTPS `CONNECT` tunnels pass through **without** recording. This is the zero-instrumentation path for capturing traffic from arbitrary tools (`curl -x`, `httpx -proxy`, `nuclei -proxy`).

---

## 3. The REST surface

Endpoints group by concern; each group has a dedicated page under [api-references/](../api-references/).

| Group | Representative endpoints | Purpose |
|---|---|---|
| Meta (no auth) | `GET /`, `/health`, `/metrics`, `/swagger/*`, `/server-info` | Liveness, Prometheus, OpenAPI UI |
| Auth/user | `POST /api/auth/login`, `GET /api/user/info` | Token issue, identity |
| Ingestion | `POST /api/ingest-http` | Traffic in (see §2) |
| HTTP records | `GET/DELETE /api/http-records[/:uuid]` | Query/inspect captured traffic |
| Findings | `GET /api/findings`, `PATCH /api/findings/:id/status` | Query/triage results |
| Scan control | `POST /api/scan-url`, `/api/scan-request`, `/api/scans/run`, `/api/scans/:uuid/{stop,pause,resume}` | Trigger & manage native scans |
| Scope / config | `GET/POST /api/scope`, `/api/config` | Live scope & config |
| Projects | `GET/POST/PUT/DELETE /api/projects[/:uuid]`, `/domain-map` | Multi-tenancy management |
| Storage | `/api/storage/{source,results,upload-source,presign}` | Cloud bundles (storage enabled) |
| DB browse | `/api/db/tables/...` | Generic table inspection (admin) |
| Agent | `POST /api/agent/run/{query,autopilot,swarm,audit,audit}`, sessions/status | AI runs (see §4) |

### Asynchronous job pattern

Scan and agent runs are long-lived, so the API is **launch-and-poll**, not request/response:

1. `POST /api/scans/run` or `/api/agent/run/*` → `202 Accepted` with a UUID (`409 Conflict` if one is already active — only one agent run at a time).
2. Poll `GET /api/scan/status` or `GET /api/agent/status/:id` until status leaves `running`.
3. Fetch artifacts: `GET /api/agent/sessions/:id/{logs,artifacts,artifacts/*}` (logs SSE-capable; artifact reads support nested paths and a `?max_bytes=` cap).

Opting into `"stream": true` on a run endpoint switches to Server-Sent Events instead — `data:` lines carrying `{"type":"chunk|phase|done|error", …}`. Most consumers should prefer the async poll-and-tail flow to keep warm sessions and prompt caches stable.

---

## 4. Agent run API

`pkg/server/handlers_agent.go` mirrors the `vigolium agent` subcommands over HTTP. It does not re-implement agent logic — it invokes the same orchestrators documented in [agentic-scan.md](agentic-scan.md), with one deliberate constraint:

- **Provider is server-config only.** The CLI's per-invocation provider flags (`--provider`, `--model`, `--oauth-token`, …) are *not* mirrored on the REST schemas. The server resolves the provider once from `agent.olium.*` in `vigolium-configs.yaml` and reuses it, keeping warm sessions and prompt caches stable. Switching providers means editing YAML and reloading.
- **Backward-compatible source field.** Request types expose `EffectiveSourcePath()` to accept both `source` and legacy `repo_path` JSON keys.
- **Audit driver dispatch.** `POST /api/agent/run/audit` takes `driver: "auto"|"both"|"audit"|"piolium"`; multi-driver modes run sequentially and multiplex SSE chunks with a `driver` field when streaming.

---

## Related

- [server-and-ingestion.md](../server-and-ingestion.md) — startup flags, curl recipes per input mode
- [api-overview.md](../api-overview.md) · [api-references/](../api-references/) — full endpoint catalogue and request/response schemas
- [agentic-scan.md](agentic-scan.md) — the orchestrators the agent endpoints invoke
- [data-and-storage.md](data-and-storage.md) — project scoping and the persistence layer the handlers share
