# Vigolium API Reference

Base URL: `http://localhost:9002` (default)

For detailed documentation on each endpoint category, see the individual reference pages below.

## Endpoint Index

### [Overview](api-references/overview.md)

Server startup, authentication, and general endpoints.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | App info |
| GET | `/health` | Health check |
| GET | `/server-info` | Server info (uptime, DB driver, queue depth) |
| GET | `/swagger/*` | Swagger UI |
| GET | `/metrics` | Prometheus metrics |

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
| POST | `/api/scan` | Trigger scan over ingested records |
| GET | `/api/scan/status` | Current scan status |
| DELETE | `/api/scan` | Cancel running scan |
| POST | `/api/scan-records` | Scan specific HTTP records by UUID |
| GET | `/api/scans` | List scan history |
| GET | `/api/scans/:uuid` | Get scan detail |
| DELETE | `/api/scans/:uuid` | Delete scan |
| POST | `/api/scans/:uuid/stop` | Stop a running scan |

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

### [Source Repos](api-references/source-repos.md)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/source-repos` | List source repos |
| POST | `/api/source-repos` | Create source repo |
| GET | `/api/source-repos/:id` | Get source repo |
| PUT | `/api/source-repos/:id` | Update source repo |
| DELETE | `/api/source-repos/:id` | Delete source repo |

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

### [Agent](api-references/agent.md)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/agent/run/query` | Single-shot agent prompt execution |
| POST | `/api/agent/run/autopilot` | Autonomous AI-driven scanning session |
| POST | `/api/agent/run/swarm` | AI-guided targeted vulnerability swarm |
| GET | `/api/agent/status/list` | List agent runs |
| GET | `/api/agent/status/:id` | Agent run status |
| POST | `/api/agent/chat/completions` | OpenAI-compatible chat completions |
