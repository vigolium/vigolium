# Running the Server

## What is Server Mode

Vigolium can run as a persistent REST API server, accepting traffic ingestion, scan triggers, and agent runs via HTTP endpoints. Server mode is useful for team workflows where multiple users share a scanning backend, CI/CD integration where automated pipelines submit traffic and retrieve findings, and building custom tooling on top of Vigolium's API.

## Starting the Server

```bash
# Start with an API key
export VIGOLIUM_API_KEY=my-secret-key
vigolium server

# Custom host and port
export VIGOLIUM_API_KEY=my-secret-key
vigolium server --host 127.0.0.1 --service-port 9002

# With an upstream proxy for outgoing scanner traffic
export VIGOLIUM_API_KEY=my-secret-key
vigolium server --proxy http://corporate-proxy:8080

# Without authentication (development only)
vigolium server -A
```

The server listens on `0.0.0.0:9002` by default.

## Authentication

All API requests (except `/health`) require a Bearer token:

```
Authorization: Bearer my-secret-key
```

API key resolution order: `VIGOLIUM_API_KEY` env var > `server.auth_api_key` in config file (`~/.vigolium/vigolium-configs.yaml`).

## CORS Configuration

The server's CORS behavior is controlled by `cors_allowed_origins` in `~/.vigolium/vigolium-configs.yaml`:

```yaml
server:
  cors_allowed_origins: reflect-origin
```

| Value | Behavior |
|-------|----------|
| `reflect-origin` (default) | Echoes the requesting `Origin` header back. Allows credentials. |
| `*` | Allows all origins without credentials (standard wildcard). |
| _(empty string)_ | Disables CORS middleware entirely. |
| `https://app.example.com, https://admin.example.com` | Comma-separated allowlist. Allows credentials. |

## Project Scoping

All server operations are scoped to a project via the `X-Project-UUID` request header. If omitted, the default project is used.

```bash
curl -X POST http://localhost:9002/api/ingest-http \
  -H "Authorization: Bearer my-secret-key" \
  -H "X-Project-UUID: a1b2c3d4-..." \
  -H "Content-Type: application/json" \
  -d '{"input_mode": "url", "content": "https://example.com"}'
```

All queries (findings, HTTP records, stats, scans) return data scoped to the project specified in the header. See [Projects](../projects.md) for the full multi-tenancy reference.

## API Endpoint Overview

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | App info (no auth required) |
| GET | `/health` | Health check (no auth required) |
| GET | `/metrics` | Prometheus metrics (no auth required) |
| GET | `/swagger/*` | Swagger UI and OpenAPI spec (no auth required) |
| GET | `/server-info` | Server status, queue depth, record/finding counts |
| GET | `/api/modules` | List available scanner modules |
| GET | `/api/http-records` | Query stored HTTP records |
| GET | `/api/findings` | Query scan findings |
| POST | `/api/ingest-http` | Ingest HTTP traffic into the database |
| GET | `/api/stats` | Aggregated scan statistics |
| GET | `/api/scope` | View scope configuration |
| POST | `/api/scope` | Update scope configuration |
| GET | `/api/config` | View server configuration |
| POST | `/api/config` | Update server configuration |
| POST | `/api/scan` | Trigger a background scan |
| GET | `/api/scan/status` | Check scan status |
| DELETE | `/api/scan` | Cancel a running scan |
| GET | `/api/source-repos` | List source repos |
| POST | `/api/source-repos` | Create a source repo |
| GET | `/api/source-repos/:id` | Get a source repo |
| PUT | `/api/source-repos/:id` | Update a source repo |
| DELETE | `/api/source-repos/:id` | Delete a source repo |
| POST | `/api/agent/run/query` | Single-shot agent prompt execution |
| POST | `/api/agent/run/autopilot` | Autonomous AI-driven scanning session |
| GET | `/api/agent/status/list` | List agent runs |
| GET | `/api/agent/status/:id` | Get agent run status (includes full result when completed) |

## Scan Management via API

After ingesting HTTP records, trigger a vulnerability scan via the API.

### Trigger a Scan

```bash
curl -s -X POST http://localhost:9002/api/scan \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d '{}' | jq .
```

Force re-scan with specific modules:

```bash
curl -s -X POST http://localhost:9002/api/scan \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d '{
    "force": true,
    "enable_modules": ["xss-scanner", "sqli-error-based"]
  }' | jq .
```

Returns `202 Accepted` on success, `409 Conflict` if a scan is already running.

### Check Scan Status

```bash
curl -s http://localhost:9002/api/scan/status \
  -H "Authorization: Bearer my-secret-key" | jq .
```

### Cancel a Running Scan

```bash
curl -s -X DELETE http://localhost:9002/api/scan \
  -H "Authorization: Bearer my-secret-key" | jq .
```

See the [API Reference](../api-references/scan.md) for full request/response details.

## Running AI Agents via API

The server exposes agent endpoints that mirror the `vigolium agent` CLI subcommands (query, autopilot, pipeline). Only one agent run can be active at a time (returns `409 Conflict` if busy). Set `"stream": true` for real-time SSE output.

For full details on agent modes, prompt templates, and API request/response schemas, see the [Agent Mode](../agents/agent-mode.md) documentation and the [Agent API Reference](../api-references/agent.md).
