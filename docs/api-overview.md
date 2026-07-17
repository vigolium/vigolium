# Vigolium API Reference

Base URL: `http://localhost:9002` (default)

For detailed documentation on each endpoint category, see the individual reference pages below.

## Endpoint Index

### [Overview](api-references/overview.md)

Server startup, authentication, and general endpoints.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Dashboard UI |
| GET | `/health` | Health check |
| GET | `/ready` | Readiness check (database ping) |
| GET | `/server-info` | Server info (uptime, DB driver, queue depth) |
| GET | `/swagger/*` | Swagger UI |
| GET | `/metrics` | Prometheus metrics |
| POST | `/api/auth/login` | Username/password login (issues bearer token) |
| GET | `/api/user/info` | Authenticated user info |
| GET | `/api/info` | Application info |
| GET | `/api/diagnostics` | Diagnostic counters |

### [HTTP Records](api-references/http-records.md)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/http-records` | List HTTP records (paginated, filterable) |
| GET | `/api/http-records/:uuid` | Get HTTP record detail |
| DELETE | `/api/http-records/:uuid` | Delete HTTP record |

### [Findings](api-references/findings.md)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/findings` | List findings (paginated, filterable) |
| GET | `/api/findings/:id` | Get finding detail |
| PATCH | `/api/findings/:id/status` | Update finding status |
| DELETE | `/api/findings/:id` | Delete finding |

### [Ingestion](api-references/ingestion.md)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/ingest-http` | Ingest HTTP data (URL, curl, OpenAPI, Burp, Postman) |

### [Scan](api-references/scan.md)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scan-url` | Scan a single URL |
| POST | `/api/scan-request` | Scan a raw HTTP request |
| POST | `/api/scans/run` | Trigger a target-based background scan |
| GET | `/api/scan/status` | Current scan status |
| POST | `/api/scan-records` | Scan specific HTTP records by UUID |
| POST | `/api/scan-all-records` | Scan all in-scope HTTP records |
| GET | `/api/scans` | List scan history |
| GET | `/api/scans/:uuid` | Get scan detail |
| GET | `/api/scans/:uuid/logs` | Stream scan logs |
| DELETE | `/api/scans/:uuid` | Delete scan |
| POST | `/api/scans/:uuid/stop` | Stop a running scan |
| POST | `/api/scans/:uuid/pause` | Pause a running scan |
| POST | `/api/scans/:uuid/resume` | Resume a paused scan |

### [Stats](api-references/stats.md)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/stats` | Aggregated scan statistics |

### [Scope](api-references/scope.md)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/scope` | View scope config |
| POST | `/api/scope` | Update scope config |

### [Config](api-references/config.md)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/config` | View configuration |
| POST | `/api/config` | Update configuration |

### [Modules](api-references/modules.md)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/modules` | List scanner modules |

### [Projects](api-references/projects.md)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/projects` | List projects |
| POST | `/api/projects` | Create project |
| GET | `/api/projects/:uuid` | Get project |
| PUT | `/api/projects/:uuid` | Update project |
| DELETE | `/api/projects/:uuid` | Delete project |
| GET | `/api/projects/:uuid/stats` | Project statistics |

### [OAST Interactions](api-references/oast-interactions.md)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/oast-interactions` | List OAST interactions |
| GET | `/api/oast-interactions/:id` | Get OAST interaction detail |
| DELETE | `/api/oast-interactions/:id` | Delete OAST interaction |

### [Extensions](api-references/extensions.md)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/extensions` | List extensions |
| GET | `/api/extensions/:name` | Get extension (with raw content) |
| PUT | `/api/extensions/:name` | Edit extension |
| GET | `/api/extensions/docs` | List JS API functions |

### [Database](api-references/database.md)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/db/tables` | List database tables |
| GET | `/api/db/tables/:table/columns` | Describe table columns |
| GET | `/api/db/tables/:table/records` | List records (filterable) |
| GET | `/api/db/tables/:table/records/:id` | Get record detail |
| POST | `/api/db/tables/:table/records` | Create record (admin) |
| PUT | `/api/db/tables/:table/records/:id` | Update record (admin) |
| DELETE | `/api/db/tables/:table/records/:id` | Delete record (admin) |

### [Storage](api-references/storage.md)

Cloud-storage endpoints for source bundles and result archives. Require `storage` to be enabled in `vigolium-configs.yaml`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/storage/source/:key` | Download a source bundle |
| GET | `/api/storage/results/:scan_uuid` | Download result archive for a scan |
| POST | `/api/storage/upload-source` | Upload a source bundle |
| POST | `/api/storage/presign` | Mint a presigned upload URL |

### [Agent](api-references/agent.md)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/agent/run/query` | Single-shot agent prompt execution |
| POST | `/api/agent/run/autopilot` | Autonomous AI-driven scanning session |
| POST | `/api/agent/run/swarm` | AI-guided targeted vulnerability swarm |
| POST | `/api/agent/run/audit` | Unified audit dispatcher (`auto`, `both`, `audit`, or `piolium`) |
| POST | `/api/agent/chat/completions` | OpenAI-compatible chat completions |
| GET | `/api/agent/status/list` | List agent runs |
| GET | `/api/agent/status/:id` | Agent run status |
| GET | `/api/agent/sessions` | Paginated session history |
| GET | `/api/agent/sessions/:id` | Full session detail |
| GET | `/api/agent/sessions/:id/logs` | Tail or stream `runtime.log` (SSE-capable) |
| GET | `/api/agent/sessions/:id/artifacts` | List session artifact files |
| GET | `/api/agent/sessions/:id/artifacts/*` | Read a specific artifact file |
