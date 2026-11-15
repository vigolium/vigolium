# Server Reference

> **Related:** [ingest.md](ingest.md) for feeding traffic into the server ·
> [loop-read.md](loop-read.md) for `--mirror-fs` consumption, [loop-confirm.md](loop-confirm.md) for bulk replay ·
> [burp.md](burp.md) for the Burp bridge · [data.md](data.md) for browsing what landed

Complete flag reference for `vigolium server` — the REST API server with Swagger
UI, ingestion endpoints, an optional recording proxy, and optional
scan-on-receive mode.

To *push* traffic into a running server (or ingest locally without a server), see
[ingest.md](ingest.md).

## Table of Contents

- [server](#server)
- [Authentication](#server-authentication)
- [Key global flags](#key-global-flags-for-server)
- [Recording proxy (`--ingest-proxy-port`)](#recording-proxy)
- [Proxy access control (`--proxy-token`, `--proxy-allow`)](#proxy-access-control)
- [HTTPS interception (`--proxy-mitm`, `server ca`)](#https-interception)
- [Disk-spill queue](#disk-spill-queue)
- [Live filesystem mirror (`--mirror-fs`)](#live-filesystem-mirror---mirror-fs)
- [REST API endpoints](#rest-api-endpoints)
- [Examples](#examples)

---

## server

**Usage:** `vigolium server [flags]`

Start the API server. By default it exposes the Swagger UI, the `/api/ingest-http`
endpoint, and the agent endpoints, all behind API-key auth. It does **not** scan
anything until you either call an endpoint or pass `--scan-on-receive`.

**Both listeners bind `127.0.0.1` by default.** Pass `--host 0.0.0.0` (or set
`VIGOLIUM_SERVER_HOST=0.0.0.0`, which the Docker images do) to expose the API.
The ingest proxy has its own `--ingest-proxy-host`; a non-loopback proxy bind
needs `--proxy-token` and/or `--proxy-allow`, or the server exits 2 before
listening.

### server-specific flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--alternative-ingest-key` | — | []string | — | Additional API key for ingestion endpoints (repeatable) |
| `--burp-bridge-url` | `-B` | string | `$VIGOLIUM_BURP_BRIDGE_URL` | Merge live Burp traffic from this loopback bridge URL into `/api/http-records` |
| `--catchup-threads` | — | int | `4` | **Deprecated: no-op** (catch-up scanning is disabled; the live scan-on-receive scanner covers post-cursor records) |
| `--demo-only` | — | bool | `false` | Expose only the demo allowlist (GET `/api/findings`, `/api/http-records`, `/api/modules`, `/api/stats`, `/api/extensions`) |
| `--disable-catchup` | — | bool | `false` | **Deprecated: no-op** (catch-up scanning is already disabled) |
| `--disable-warm-session` | — | bool | `false` | Disable agent warm session pooling |
| `--discard-queued` | — | bool | `false` | Drop tasks a previous run left in the disk-spill queue instead of resuming them (tasks older than 24h are always dropped) |
| `--host` | — | string | `127.0.0.1` | Bind address for the API server (`$VIGOLIUM_SERVER_HOST` when unset; `0.0.0.0` exposes it) |
| `--ingest-proxy-host` | — | string | `127.0.0.1` | Bind address for the ingest proxy (config `server.ingest_proxy_host`); non-loopback needs `--proxy-token` or `--proxy-allow` |
| `--ingest-proxy-port` | — | int | `0` (disabled) | Transparent HTTP proxy port for recording traffic |
| `--mem-buffer` | — | int | `10000` | In-memory queue capacity before spilling to disk |
| `--mirror-fs` | — | string | — | Mirror ingested traffic + findings to a live flat file tree under this dir (`<dir>/traffic`, `<dir>/findings`), in addition to the DB (config `server.mirror_fs_path`) |
| `--no-agent` | — | bool | `false` | Disable all agent endpoints and warm session pooling |
| `--no-auth` | `-A` | bool | `false` | Run server without API key authentication |
| `--no-swagger` | — | bool | `false` | Disable the Swagger UI and API spec endpoint |
| `--output` | `-o` | string | — | Write findings to specified output file |
| `--passive-only` | — | bool | `false` | With `--scan-on-receive`, run passive modules only (no active scan traffic; includes secret detection) |
| `--proxy-allow` | — | []string | — | Accept ingest-proxy clients only from this CIDR or IP (repeatable; config `server.ingest_proxy_allow`) |
| `--proxy-insecure` | — | bool | `false` | When intercepting HTTPS (`--proxy-mitm`), skip verification of the upstream server's TLS certificate |
| `--proxy-mitm` | — | bool | `false` | Intercept HTTPS through `--ingest-proxy-port` using a generated CA so TLS traffic is recorded (trust it with `vigolium server ca install`) |
| `--proxy-token` | — | string | — | Require this secret on every ingest-proxy request as `Proxy-Authorization` (Basic with any username, or Bearer); config `server.ingest_proxy_token` |
| `--service-port` | — | int | `9002` | Port for the REST API server |
| `--timeout` | — | duration | `15s` | HTTP request timeout for background scan workers (e.g. `30s`, `1m`) |
| `--view-only` | — | bool | `false` | Run server in read-only mode (disables scanning, ingestion, agent, and all write endpoints) |

(`--disable-fetch-response` is an **ingest-only** flag — it is not registered on
`server`. See [ingest.md](ingest.md). `--export-ca <file>` still works as a
hidden alias of `server ca print --out <file>`.)

### Server Authentication

API key resolution priority (highest to lowest):
1. `--no-auth` / `-A` flag — disables auth entirely
2. `--alternative-ingest-key` flag
3. `VIGOLIUM_API_KEY` environment variable
4. `server.auth_api_key` in config file

`--alternative-ingest-key` is repeatable, so you can hand different feeders
(a Burp extension, a CI job, a proxy client) their own key without sharing the
primary one:

```bash
vigolium server \
  --alternative-ingest-key ci-runner-key \
  --alternative-ingest-key burp-plugin-key
```

### Key Global Flags for Server

| Flag | Description |
|------|-------------|
| `-t <url>` | Target URL (used with `--scan-on-receive` for scope) |
| `--scan-on-receive` | Auto-scan every ingested request (`-S` is rejected here with exit 2) |
| `--full-native-scan-on-receive` | Run the full native pipeline (discovery + spidering + dynamic-assessment) on received records, not dynamic-assessment only |
| `-c` / `--concurrency` | Worker pool size |
| `--proxy` | Proxy for outgoing requests |

**Write `--scan-on-receive`, not `-S`.** `-S` means `--stateless` on every other
command; on `server` and `ingest` it is a usage error (exit 2) naming
`--scan-on-receive`. `server` takes no target: the project's `scope.*` rules
(`vigolium scope view`) bound the auto-scan, and without any it scans every
host it receives.

---

## Recording proxy

`--ingest-proxy-port <port>` starts a transparent HTTP proxy. Point a browser or
tool at it and every request/response it sees is stored as an HTTP record (source
`ingest-proxy`), ready to scan or browse:

```bash
# Terminal 1 — capture.
vigolium server --ingest-proxy-port 8080

# Terminal 2 — drive traffic through it, then scan what was captured.
curl -x http://127.0.0.1:8080 http://target.example/
vigolium scan --only dynamic-assessment -t http://target.example
```

For an all-in-one capture-and-scan, add `--scan-on-receive -t <url>` so each request is scanned
as it arrives.

## Proxy access control

The proxy listens on `--ingest-proxy-host` (default `127.0.0.1`), independent of
the API's `--host`. To capture from another machine, bind it to a routable
address **and** gate it — the server refuses to start an open proxy on a
non-loopback address:

```bash
# Token: clients send Proxy-Authorization (Basic, any username, token as password; or Bearer).
vigolium server --ingest-proxy-port 8080 --ingest-proxy-host 0.0.0.0 --proxy-token "$TOKEN"
curl -x "http://vigolium:$TOKEN@proxy-host:8080" http://target.example/

# Allow-list: only these client networks (repeatable). With a token too, both must pass.
vigolium server --ingest-proxy-port 8080 --ingest-proxy-host 0.0.0.0 --proxy-allow 10.0.0.0/8
```

A missing or wrong token gets `407 Proxy Authentication Required` with
`Proxy-Authenticate: Basic realm="vigolium"`; a client outside the allow-list
gets `403`. The `Proxy-Authorization` header is stripped before the request is
forwarded or recorded. `/server-info` reports the mode as `proxy_auth`.

## HTTPS interception

Plain `--ingest-proxy-port` records HTTP only; HTTPS passes through opaquely. Add
`--proxy-mitm` to decrypt TLS with a generated CA (`~/.vigolium/ca`, created on
first use). Manage it with `vigolium server ca`:

```bash
vigolium server ca path                # where the certificate lives
vigolium server ca print > ca.pem      # PEM to stdout (or --out ca.pem)
vigolium server ca print -j            # {path, sha256, subject, not_after}
vigolium server ca install             # print the trust commands for this OS
vigolium server ca install --yes       # ...and run them (may prompt for sudo)
vigolium server ca uninstall           # print the commands that remove that trust
vigolium server ca uninstall --yes     # ...and run them

# Then run the intercepting proxy.
vigolium server --ingest-proxy-port 8080 --proxy-mitm

# Skip upstream TLS verification (self-signed / staging origins).
vigolium server --ingest-proxy-port 8080 --proxy-mitm --proxy-insecure
```

`install` covers macOS (login keychain), Debian/Ubuntu
(`update-ca-certificates`), Fedora/RHEL (`update-ca-trust`) and Windows
(`certutil -user`); Firefox and Linux Chrome keep their own NSS store, which it
prints as a note rather than changing.

## Disk-spill queue

With `--scan-on-receive`, work beyond `--mem-buffer` spills to a LevelDB queue in
`~/.vigolium/server-queue/<hash of the database>` (mode 0700, locked with a
`LOCK` file). A restart against the same database resumes what was left queued
(logging `recovered N queued tasks`); tasks older than 24h are dropped, and
`--discard-queued` drops them all. A second server on the same database uses a
PID-suffixed sibling for that run. Per-PID `$TMPDIR/vigolium-server-queue-<pid>`
directories left by older versions are removed once their process is gone.

## Live Filesystem Mirror (`--mirror-fs`)

`--mirror-fs <dir>` (config `server.mirror_fs_path`) mirrors every saved HTTP
record and finding to `<dir>/traffic/` + `<dir>/findings/` as they are persisted
— in addition to the database — so an external agent can read ingested
Burp/proxy traffic as files in real time (`ls`/`grep`/`jq`).

- **Same layout as `--format fs`**: per-host subdirs with `0001.req` (a leading `@target <scheme>://<authority>` line then the raw request), `0001.resp.headers`, `0001.resp.body` (gzip-decoded), and `0001.md` for findings cross-linked to their `.req`. Full layout + consumption walkthrough: [loop-read.md → Filesystem tree output](loop-read.md#filesystem-tree-output).
- **Append-only index**: writes `<root>/traffic/index.jsonl` + `<root>/findings/index.jsonl` (one JSON object per line), vs the one-shot export's single `index.json` array — so you can `tail -f` it while traffic lands.
- **Owner-only, atomic**: files are written 0600 through a temp file and rename (a reader never sees a half-written file), directories 0700.
- **Bounded, never silent**: a background goroutine does all disk I/O. When its buffer is full a save waits up to 2s, then the job is dropped (the database is unaffected), counted in `/server-info` as `mirror_dropped`, and logged at most once a minute.
- **Resumes across restarts**: per-host id numbering continues from the highest existing `.req`/`.md` file (or index entry); a torn last index line from a crash is trimmed.
- **Server-ingestion-only**: wired via the repository's `OnRecordSaved`/`OnFindingSaved` callbacks, which fire only on genuinely new inserts (deduplicated saves do not). CLI scans and other repo users are unaffected. Setup is best-effort — a failure logs a warning and the server continues without it.

## REST API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/ingest-http` | Submit HTTP records for ingestion |
| `POST` | `/api/scan-url` / `/api/scan-request` | Scan one URL / raw request (scope enforced: out of scope is `422`; schemeless requests are settled like the CLI) |
| `POST` | `/api/scan-records` / `/api/scan-all-records` / `/api/scans/run` | Scan selected stored records / every record / a full native scan |
| `GET` | `/api/scans[/:uuid[/logs]]` | List / inspect scans and their logs |
| `POST` | `/api/scans/:uuid/{pause,resume,stop}` | Control a running scan |
| `GET` | `/api/findings[/:id]` | List / get findings |
| `PATCH` | `/api/findings/:id/status` | Set a finding's status |
| `POST` | `/api/findings/:id/verify` | Re-run the finding's module to confirm it (as `vigolium finding verify`) |
| `GET` | `/api/http-records[/:uuid]` | List / get stored traffic |
| `GET` / `POST` | `/api/scope` | Read / update the project's scope |
| `POST` | `/api/agent/run/query` | Single-shot agent prompt execution |
| `POST` | `/api/agent/run/autopilot` | Autonomous AI-driven scanning session |
| `POST` | `/api/agent/run/swarm` | AI-guided targeted / full-scope scan |
| `POST` | `/api/agent/run/audit` | Whitebox audit (`driver: auto\|both\|audit\|piolium`) |
| `POST` | `/api/agent/chat/completions` | OpenAI-compatible chat completions |
| `GET` | `/api/agent/status/list` | List agent runs |
| `GET` | `/api/agent/status/:id` | Check agent run status |
| `GET` | `/api/agent/sessions[/:id[/logs\|/artifacts]]` | List / inspect agent sessions, logs, and artifacts |
| `GET` | `/` | Swagger UI dashboard |

All data endpoints are project-scoped via the `X-Project-UUID` header (mirrors
the CLI `--project-uuid` / `--project-name` flags). An unknown UUID is
`404 project_not_found` unless the request sends `X-Project-Create: 1`; a
non-UUID is `400 invalid_project_uuid`. Ingestion endpoints additionally accept
any `--alternative-ingest-key`.

Every error body carries a string code: `error_code` in the default v1 shape,
`error.code` in v2 (`Vigolium-Api-Version: 2`, which also puts every list
under `items` in the CLI's envelope). Branch on the code, not the message.

## Examples

```bash
# Basic server (Swagger UI at http://localhost:9002/, API-key auth on).
vigolium server

# Custom port, no auth (dev only).
vigolium server --service-port 8443 --no-auth

# Scan every ingested request. `server` has no target flag: what gets scanned
# is limited by the project's scope.* rules (`vigolium scope view`).
vigolium server --scan-on-receive

# Passive-only scan-on-receive (no active traffic; secret detection still runs).
vigolium server --scan-on-receive --passive-only

# Full native pipeline (discovery + spidering + assessment) on each record.
vigolium server --scan-on-receive --full-native-scan-on-receive

# Transparent recording proxy (loopback only).
vigolium server --ingest-proxy-port 8080

# Recording proxy reachable from the LAN (token required).
vigolium server --ingest-proxy-port 8080 --ingest-proxy-host 0.0.0.0 --proxy-token "$TOKEN"

# Expose the API itself (e.g. in a container).
vigolium server --host 0.0.0.0

# Intercepting HTTPS proxy (records TLS traffic under a generated CA).
vigolium server --ingest-proxy-port 8080 --proxy-mitm

# High-throughput ingestion server (bigger in-memory queue before spilling to disk).
vigolium server --mem-buffer 50000

# Mirror ingested traffic + findings to a live browsable file tree.
vigolium server --ingest-proxy-port 8080 --mirror-fs ./mirror

# Read-only dashboard for sharing results (no scanning, ingestion, or writes).
vigolium server --view-only

# Public demo: only the read-only allowlist is exposed.
vigolium server --demo-only

# Merge live Burp Proxy history into /api/http-records.
vigolium server -B http://127.0.0.1:9009
```

To send records to a running server from another host or a CI job, use the
remote ingest client — see [ingest.md → Local vs Remote Mode](ingest.md#local-vs-remote-mode).
