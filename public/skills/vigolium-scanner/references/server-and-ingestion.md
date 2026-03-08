# Server & Ingestion Reference

Complete flag reference for `server`, `ingest`, and `traffic` commands.

## Table of Contents

- [server](#server)
- [ingest](#ingest)
- [traffic](#traffic)
- [traffic replay](#traffic-replay)

---

## server

**Usage:** `vigolium server [flags]`

Start the API server with Swagger UI, ingestion endpoints, and optional scan-on-receive mode.

### server-specific flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--host` | — | string | `0.0.0.0` | Host address to listen on |
| `--service-port` | — | int | `9002` | API service port |
| `--ingest-proxy-port` | — | int | `0` (disabled) | Transparent HTTP proxy port for recording traffic |
| `--alternative-ingest-key` | — | []string | — | Secondary ingest API key (repeatable) |
| `--no-auth` | `-A` | bool | `false` | Run without API key authentication |
| `--mem-buffer` | — | int | `10000` | In-memory buffer size for hybrid queue |
| `--output` | `-o` | string | — | Write findings to output file |
| `--catchup-threads` | — | int | `4` | Workers for background catchup scan |
| `--disable-catchup` | — | bool | `false` | Disable automatic catchup scan |

### Server Authentication

API key resolution priority (highest to lowest):
1. `--no-auth` / `-A` flag — disables auth entirely
2. `--alternative-ingest-key` flag
3. `VIGOLIUM_API_KEY` environment variable
4. `server.auth_api_key` in config file

### Key Global Flags for Server

| Flag | Description |
|------|-------------|
| `-t <url>` | Target URL (used with `-S` for scope) |
| `-S` / `--scan-on-receive` | Auto-scan every ingested request |
| `-c` / `--concurrency` | Worker pool size |
| `--proxy` | Proxy for outgoing requests |
| `--disable-fetch-response` | Store requests without fetching responses |

### Examples

```bash
# Basic server
vigolium server

# Custom port, no auth
vigolium server --service-port 8443 --no-auth

# With scan-on-receive
vigolium server -t https://example.com --scan-on-receive

# With transparent proxy
vigolium server --ingest-proxy-port 8080

# High concurrency server
vigolium server -c 200 --mem-buffer 50000
```

### REST API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/ingest` | Submit HTTP records for ingestion |
| `POST` | `/api/agent/run/query` | Single-shot agent prompt execution |
| `POST` | `/api/agent/run/autopilot` | Autonomous AI-driven scanning session |
| `POST` | `/api/agent/run/pipeline` | Multi-phase scanning pipeline |
| `GET` | `/api/agent/status/list` | List agent runs |
| `GET` | `/api/agent/status/:id` | Check agent run status |
| `GET` | `/` | Swagger UI dashboard |

---

## ingest

**Usage:** `vigolium ingest [flags]`

Ingest HTTP requests into the database, either locally or via a remote server.

### ingest-specific flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--server` | `-s` | string | — | Server URL for remote ingestion (omit for local) |

### Key Global Flags for Ingest

| Flag | Description |
|------|-------------|
| `-t <url>` | Base URL / target for the ingested data |
| `-i <file>` | Input file path |
| `-I <format>` | Input format (urls, openapi, burp, curl, har, etc.) |
| `-S` | After ingesting, scan the records (local mode only) |
| `--spec-url` | Use server URLs from OpenAPI spec |
| `--spec-header` | HTTP headers for OpenAPI requests |
| `--spec-var` | OpenAPI parameter values as key=value |
| `--spec-default` | Default value for required parameters (default: `1`) |
| `--disable-fetch-response` | Store request-only (don't fetch responses) |
| `--scope-origin` | Origin scope mode for filtering |

### Local vs Remote Mode

- **Local mode** (default): Ingests directly into the local SQLite database, fetches HTTP responses
- **Remote mode** (`--server <url>`): Sends records to a running vigolium server via API
- `--scan-on-receive` is ignored in remote mode (server handles scanning)

### Examples

```bash
# Local ingest from OpenAPI spec
vigolium ingest -t https://api.example.com -I openapi -i spec.yaml

# Local ingest from Burp export
vigolium ingest -t https://example.com -I burp -i export.xml

# Pipe URLs from stdin
cat urls.txt | vigolium ingest -i -

# Ingest + auto-scan
vigolium ingest -t https://example.com -I openapi -i spec.yaml -S

# Remote ingest to server
vigolium ingest -s http://localhost:9002 -I openapi -i spec.yaml

# Request-only (no response fetching)
vigolium ingest -t https://example.com -I burp -i export.xml --disable-fetch-response
```

---

## traffic

**Usage:** `vigolium traffic [search-term] [flags]`

**Aliases:** `traffics`, `tf`

Browse stored HTTP traffic. Shortcut for `vigolium db ls --table http_records`.

### Filter flags (persistent, inherited by replay)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--host` | string | — | Filter by hostname pattern (wildcard supported) |
| `--method` | []string | — | Filter by HTTP method |
| `--status` | []int | — | Filter by HTTP status code |
| `--path` | string | — | Filter by URL path pattern |
| `--from` | string | — | Records after this date (YYYY-MM-DD or RFC3339) |
| `--to` | string | — | Records before this date |
| `--search` | string | — | Search across URLs and paths |
| `--header` | string | — | Search in HTTP headers |
| `--body` | string | — | Search in request/response body |
| `--source` | string | — | Filter by source (scanner, ingest-cli, ingest-server, etc.) |
| `--sort` | string | `created_at` | Sort field: uuid, created_at, sent_at, method, status, time |
| `--asc` | bool | `false` | Sort ascending |
| `--limit` | `-n` | int | `100` | Max records to display |
| `--offset` | `-o` | int | `0` | Records to skip |

### Display flags (traffic only)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--tree` | bool | `false` | Hierarchical tree format |
| `--raw` | bool | `false` | Full raw HTTP request and response |
| `--burp` | bool | `false` | Burp Suite-style colored format |
| `--columns` | []string | — | Columns to include (comma-separated) |
| `--exclude-columns` | []string | — | Columns to exclude |

### Available Columns

UUID, HOST, METHOD, PATH, STATUS, TIME, SIZE, WORDS, CONTENT_TYPE, SENT_AT, TITLE, AUTH, STATUS_PHRASE, REQ_HEADERS, RESP_HEADERS, SOURCE, REMARKS

Default columns: HOST, METHOD, PATH, STATUS, CONTENT_TYPE, SIZE, WORDS, TIME, TITLE, SOURCE

### Argument Routing

- `vigolium traffic` — default table view
- `vigolium traffic <term>` — fuzzy search
- `vigolium traffic tree` — tree view
- `vigolium traffic list` or `ls` — default table view

### Examples

```bash
# Browse all traffic
vigolium traffic

# Fuzzy search
vigolium traffic login
vigolium traffic api/v2

# Tree view
vigolium traffic --tree

# Burp-style output
vigolium traffic --burp

# Filter by host and method
vigolium traffic --host api.example.com --method POST,PUT

# Filter by status code
vigolium traffic --status 200,301

# Date range
vigolium traffic --from 2024-01-01 --to 2024-06-30

# Custom columns
vigolium traffic --columns HOST,METHOD,PATH,STATUS,AUTH

# Watch mode (auto-refresh)
vigolium traffic --watch 5s
```

---

## traffic replay

**Usage:** `vigolium traffic replay [search-term] [flags]`

Re-send stored HTTP requests and compare original vs new responses.

### replay-specific flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--in-replace` | bool | `false` | Replace stored response with the replay response |

Inherits all filter flags from the `traffic` command.

### Examples

```bash
# Replay all matching requests
vigolium traffic replay login

# Replay and replace stored responses
vigolium traffic replay --host api.example.com --in-replace

# Replay with proxy
vigolium traffic replay --host example.com --proxy http://127.0.0.1:8080
```
