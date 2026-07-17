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

Useful server controls:

```bash
# Mirror every persisted record/finding to a live filesystem tree
vigolium server --mirror-fs ./live-export

# Read-only API/UI, or the narrower public demo allowlist
vigolium server --view-only
vigolium server --demo-only

# Disable agent endpoints or Swagger
vigolium server --no-agent --no-swagger
```

`--full-native-scan-on-receive` expands `--scan-on-receive` from the
dynamic-assessment path to the full native pipeline; `--passive-only` prevents
active requests.

## Live Burp Traffic

When the Vigolium Burp extension's Bridge listener is enabled, the server can
include live Burp Proxy history in the ordinary HTTP-records API:

```bash
vigolium server --burp-bridge-url http://127.0.0.1:9009
```

`GET /api/http-records` then returns one globally sorted and paginated result
containing both persisted database records and current Burp traffic. Live rows
have `"source": "burp"` and temporary UUIDs beginning with `burp:`; the normal
detail route, `GET /api/http-records/:uuid`, also resolves those live UUIDs.
Existing filters such as `domain`, `method`, `path`, `status_code`, `search`,
sorting, and `source=burp` apply without a separate bridge API workflow.

The bridge is optional. If Burp is closed or its listener is unavailable, the
server continues returning database records and sets
`X-Vigolium-Burp-Bridge: unavailable` on the response. The URL must be an
HTTP loopback address with an explicit port. It can also be supplied through
`VIGOLIUM_BURP_BRIDGE_URL`.

The server flag is a live, read-only view. To persist Proxy history into the
database, use either import workflow:

```bash
# Import all traffic visible through the Bridge listener
vigolium import --burp-bridge-url http://127.0.0.1:9009

# Import only the traffic page selected by filters; add --all for all matches
vigolium traffic --burp-bridge-url http://127.0.0.1:9009 \
  --host example.com --save-to-vigolium-db
```

Imports are idempotent: new requests are inserted, changed responses refresh
their existing record, and unchanged requests are left alone. Persisted rows
retain `source=burp` and remain available after Burp or the bridge stops.

The bridge also supports the reverse direction into Burp's Target Site map:

```bash
# Copy the selected database page into Burp without replaying the requests
vigolium traffic --burp-bridge-url http://127.0.0.1:9009 \
  --host example.com --save-to-burp

# Replay a request, then save the mutated request and fresh response to Burp
vigolium replay --record-uuid <uuid> --save-to-burp \
  --burp-bridge-url http://127.0.0.1:9009
```

`traffic --save-to-burp` reads only persisted database records and honors its
active filters, offset, and limit; add `--all` for every match. It calls
Montoya's Site map insertion API and does not issue target network requests.
Individual requests or responses larger than 8 MiB are skipped and reported.

## Authentication

Protected API routes require a Bearer token. Health/metrics, login, Swagger,
and static UI routes are public:

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
| GET | `/` | Dashboard UI (no auth required) |
| GET | `/health` | Health check (no auth required) |
| GET | `/ready` | Readiness check (no auth required) |
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
| POST | `/api/scans/run` | Trigger a target-based background scan |
| GET | `/api/scan/status` | Check scan status |
| POST | `/api/scans/:uuid/stop` | Stop a running scan |
| POST | `/api/agent/run/query` | Single-shot agent prompt execution |
| POST | `/api/agent/run/autopilot` | Autonomous AI-driven scanning session |
| POST | `/api/agent/run/swarm` | AI-guided multi-phase vulnerability swarm |
| POST | `/api/agent/run/audit` | Unified audit dispatcher (`auto`, `both`, `audit`, or `piolium`) |
| GET | `/api/agent/status/list` | List agent runs |
| GET | `/api/agent/status/:id` | Get agent run status (includes full result when completed) |
| GET | `/api/agent/sessions` | Paginated session history |
| GET | `/api/agent/sessions/:id` | Full session detail |
| GET | `/api/agent/sessions/:id/logs` | Tail or stream `runtime.log` |
| GET | `/api/agent/sessions/:id/artifacts` | List session artifact files |

## Scan Management via API

After ingesting HTTP records, trigger a vulnerability scan via the API.

### Trigger a Scan

```bash
curl -s -X POST http://localhost:9002/api/scans/run \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d '{"targets":["https://example.com"]}' | jq .
```

Force re-scan with specific modules:

```bash
curl -s -X POST http://localhost:9002/api/scans/run \
  -H "Authorization: Bearer my-secret-key" \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["https://example.com"],
    "modules": ["xss-scanner", "sqli-error-based"]
  }' | jq .
```

Returns `202 Accepted` on success. Use `POST /api/scan-all-records` instead when
the intended inputs are HTTP records already stored in the database.

### Check Scan Status

```bash
curl -s http://localhost:9002/api/scan/status \
  -H "Authorization: Bearer my-secret-key" | jq .
```

### Stop a Running Scan

```bash
curl -s -X POST http://localhost:9002/api/scans/<scan-uuid>/stop \
  -H "Authorization: Bearer my-secret-key" | jq .
```

See the [API Reference](../api-references/scan.md) for full request/response details.

## Running AI Agents via API

The server exposes query, autopilot, swarm, and unified audit endpoints. Agent
runs use separate light/heavy concurrency pools; when a pool remains saturated
past the queue timeout the server returns `429 Too Many Requests`. Set
`"stream": true` for real-time SSE output.

For full details on agent modes, prompt templates, and API request/response schemas, see the [Agent Mode](../agentic-scan/agent-mode.md) documentation and the [Agent API Reference](../api-references/agent.md).
