# Vigolium API Reference — Scan with Storage

End-to-end guide for running scans (native + agentic) and shipping results to a cloud storage bucket. Covers every endpoint that supports `upload_results`, the on-bucket layout, how to retrieve bundles afterwards, and the matching CLI flags.

For storage configuration (GCS / S3 / MinIO setup, presigned URLs, source uploads), see [storage.md](./storage.md). For the agent endpoints themselves, see [agent.md](./agent.md). For native scan options, see [scan.md](./scan.md).

---

## At a Glance

Every scan mode supports an opt-in result-upload flow. When `upload_results: true` is sent, the server tar.gzs the relevant artifacts after the scan completes successfully and uploads them to a project-scoped object key. The DB row's `storage_url` column is populated so the bundle can be retrieved later.

| Mode                                | Endpoint                          | CLI flag           | Bundle key                                                      |
|-------------------------------------|-----------------------------------|--------------------|------------------------------------------------------------------|
| Native scan                         | `POST /api/scans/run`             | `--upload-results` | `<project>/native-scans/<scan-uuid>/results.tar.gz`             |
| Agent query                         | `POST /api/agent/run/query`       | `--upload-results` | `<project>/agentic-scans/<agentic-scan-uuid>/results.tar.gz`             |
| Agent autopilot                     | `POST /api/agent/run/autopilot`   | `--upload-results` | `<project>/agentic-scans/<agentic-scan-uuid>/results.tar.gz`             |
| Agent swarm                         | `POST /api/agent/run/swarm`       | `--upload-results` | `<project>/agentic-scans/<agentic-scan-uuid>/results.tar.gz`             |
| Agent archon                        | `POST /api/agent/run/archon`      | `--upload-results` | `<project>/agentic-scans/<agentic-scan-uuid>/results.tar.gz`             |

All bundles live under `<bucket>/<project-uuid>/...`; the project UUID comes from the `X-Project-UUID` header (or the request body's `project_uuid`) — see [storage.md → Security](./storage.md#security).

Every endpoint above also accepts an optional `scan_uuid` field (CLI flag `--scan-uuid`). When supplied, the server pins the scan/run UUID to that value instead of minting a fresh one — this is what makes cross-node sync work, see [Pinning Scan UUIDs](#pinning-scan-uuids-cross-node-sync) below.

---

## Prerequisites

### 1. Configure storage

Storage is **disabled by default**. Without it, `upload_results: true` is a silent no-op (a warning is logged). Enable it in `~/.vigolium/vigolium-configs.yaml`:

```yaml
storage:
  enabled: true
  driver: gcs                     # or s3, minio
  bucket: ${VIGOLIUM_STORAGE_BUCKET_NAME}
  region: asia-southeast1
  access_key: ${VIGOLIUM_STORAGE_ACCESS_KEY}
  secret_key: ${VIGOLIUM_STORAGE_SECRET_KEY}
  use_ssl: true
```

Full setup steps (HMAC keys, bucket creation, IAM bindings) are in [storage.md → GCP Setup](./storage.md#gcp-setup).

### 2. Start the server

```bash
vigolium server -A
```

### 3. Verify storage is reachable

```bash
curl -s -X POST http://localhost:9002/api/storage/upload-source \
  -H "Authorization: Bearer <token>" \
  -H "X-Project-UUID: <project-uuid>" \
  -F "file=@README.md" | jq .
```

A `storage_url` in the response confirms credentials are working.

---

## Native Scan

### Run with upload

```bash
curl -s -X POST http://localhost:9002/api/scans/run \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -H "X-Project-UUID: <project-uuid>" \
  -d '{
    "targets": ["https://example.com"],
    "strategy": "balanced",
    "upload_results": true,
    "output_formats": ["jsonl", "html"],
    "scan_uuid": "550e8400-e29b-41d4-a716-446655440000"
  }' | jq .
```

`scan_uuid` is optional. Omit it and the server mints a fresh one. Supply it (CLI: `--scan-uuid`) when a different node already created the scan record and this run should attach to it — see [Pinning Scan UUIDs](#pinning-scan-uuids-cross-node-sync).

**Response (202):**

```json
{
  "project_uuid": "<project-uuid>",
  "scan_uuid": "550e8400-e29b-41d4-a716-446655440000",
  "status": "running",
  "message": "scan started"
}
```

### What gets uploaded

By default the bundle contains the per-scan `runtime.log` only. Pass `output_formats` (currently `jsonl` and/or `html`) on the request to also materialize and bundle the rendered findings — these land at `<sessions_dir>/<scan-uuid>/output.{jsonl,html}` on the server and are added to the tar.gz alongside `runtime.log`. CLI runs that pass `--output` and `--format` get the same shape.

```
<bucket>/<project-uuid>/native-scans/<scan-uuid>/results.tar.gz
├── runtime.log
├── output.jsonl   # only when output_formats includes "jsonl"
└── output.html    # only when output_formats includes "html"
```

### CLI equivalent

```bash
vigolium scan -t https://example.com \
  -o results --format jsonl,html \
  --upload-results
```

---

## Agent Query

Single-shot prompt execution. Useful for code review, secret discovery, endpoint extraction. The bundle captures the agent session directory (`runtime.log`, `output.md`, any extracted artifacts).

```bash
curl -s -X POST http://localhost:9002/api/agent/run/query \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -H "X-Project-UUID: <project-uuid>" \
  -d '{
    "prompt_template": "security-code-review",
    "source": "/path/to/repo",
    "scan_uuid": "550e8400-e29b-41d4-a716-446655440000",
    "upload_results": true
  }' | jq .
```

`scan_uuid` is optional — supply it to attach this query run to a UUID a different node already created (the response's `agentic_scan_uuid` will echo back the same value). Omit it for a freshly minted UUID.

### CLI equivalent

```bash
vigolium agent query --prompt-template security-code-review \
  --source /path/to/repo \
  --scan-uuid 550e8400-e29b-41d4-a716-446655440000 \
  --upload-results
```

---

## Agent Autopilot

Autonomous agentic scan. Useful for blackbox + greybox testing where the agent drives the whole pipeline.

```bash
curl -s -X POST http://localhost:9002/api/agent/run/autopilot \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -H "X-Project-UUID: <project-uuid>" \
  -d '{
    "target": "http://localhost:3000",
    "source": "/home/user/src/my-app",
    "intensity": "balanced",
    "scan_uuid": "550e8400-e29b-41d4-a716-446655440000",
    "upload_results": true
  }' | jq .
```

For agentic endpoints, `scan_uuid` pins `AgenticScan.uuid` (the run identity) — the response surfaces it as `agentic_scan_uuid`, and any native scans the autopilot spawns inherit the same value so findings, http_records, and the uploaded bundle all key off one UUID.

### CLI equivalent

```bash
vigolium agent autopilot \
  --target http://localhost:3000 \
  --source /home/user/src/my-app \
  --intensity balanced \
  --scan-uuid 550e8400-e29b-41d4-a716-446655440000 \
  --upload-results
```

The bundle is the full session directory: `runtime.log`, `archon-audit/` artifacts, operator transcripts, frozen context, and any findings emitted by the agent.

---

## Agent Swarm

AI-guided targeted swarm scan. Good for focused per-vulnerability runs.

```bash
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -H "X-Project-UUID: <project-uuid>" \
  -d '{
    "input": "https://example.com/api/users?id=1",
    "source": "/path/to/repo",
    "code_audit": true,
    "triage": true,
    "scan_uuid": "550e8400-e29b-41d4-a716-446655440000",
    "upload_results": true
  }' | jq .
```

A pinned `scan_uuid` lets a dispatcher pre-create the agentic_scans row (e.g. via a 1-record `dry_run` scan or a direct DB insert) and have the swarm worker attach to it. If the UUID already exists under a *different* project, the API returns **409 Conflict** instead of corrupting tenant isolation — see [Pinning Scan UUIDs](#pinning-scan-uuids-cross-node-sync).

### CLI equivalent

```bash
vigolium agent swarm \
  --input "https://example.com/api/users?id=1" \
  --source /path/to/repo \
  --code-audit --triage \
  --scan-uuid 550e8400-e29b-41d4-a716-446655440000 \
  --upload-results
```

---

## Agent Archon

Foreground archon-audit (multi-phase source code security audit).

```bash
curl -s -X POST http://localhost:9002/api/agent/run/archon \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -H "X-Project-UUID: <project-uuid>" \
  -d '{
    "source": "https://github.com/example/myapp",
    "intensity": "deep",
    "platform": "claude",
    "scan_uuid": "550e8400-e29b-41d4-a716-446655440000",
    "upload_results": true
  }' | jq .
```

Archon runs are typically long-lived (`deep` mode can run for hours), so pinning `scan_uuid` is especially useful when a dispatcher wants to surface the run's UUID to end users *before* the audit starts — the same UUID will be returned as `agentic_scan_uuid` and used as the bundle key under `<project-uuid>/agentic-scans/<scan_uuid>/results.tar.gz`.

### CLI equivalent

```bash
vigolium agent archon \
  --source https://github.com/example/myapp \
  --mode deep \
  --upload-results
```

The bundle contains `runtime.log`, `audit-stream.jsonl`, `archon-audit-output.md`, and the synced `archon-audit/` artifact tree (per-phase reports, advisory matrices, audit-state.json).

---

## On-Bucket Layout

```
<bucket>/
  <project-uuid>/
    ugc/                                # uploaded source archives (input)
      my-app.tar.gz
    native-scans/
      <scan-uuid>/
        results.tar.gz                  # runtime.log + output.{jsonl,html} when output_formats requested
    agentic-scans/
      <agentic-scan-uuid>/
        results.tar.gz                  # full session dir for query/autopilot/swarm/archon
```

Both native and agentic scan trees are flat: one directory per UUID, one bundle per scan.

---

## Retrieving Results

### Via the API

`GET /api/storage/results/:scan-uuid` searches `native-scans/` first, then `agentic-scans/`:

```bash
curl -s -o results.tar.gz \
  http://localhost:9002/api/storage/results/<uuid> \
  -H "Authorization: Bearer <token>" \
  -H "X-Project-UUID: <project-uuid>"

tar xzf results.tar.gz
```

### Via the CLI

```bash
vigolium storage results <uuid>
# Downloads to ./results-<uuid>.tar.gz
```

### Via presigned URL (large files / external clients)

```bash
curl -s -X POST http://localhost:9002/api/storage/presign \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -H "X-Project-UUID: <project-uuid>" \
  -d '{
    "key": "agentic-scans/<agentic-scan-uuid>/results.tar.gz",
    "method": "GET",
    "expiry_seconds": 3600
  }' | jq -r .url
```

The returned URL is a direct GCS/S3 download that bypasses the API server.

### From the DB row

When `upload_results` succeeds, the scan's `storage_url` column is set:

```bash
# Native scan
curl -s http://localhost:9002/api/scans/<scan-uuid> \
  -H "Authorization: Bearer <token>" | jq .storage_url
# "gs://<project-uuid>/native-scans/<scan-uuid>/results.tar.gz"

# Agentic scan (query / autopilot / swarm / archon)
curl -s http://localhost:9002/api/agent/sessions/<agentic-scan-uuid> \
  -H "Authorization: Bearer <token>" | jq .storage_url
# "gs://<project-uuid>/agentic-scans/<agentic-scan-uuid>/results.tar.gz"
```

---

## Pinning Scan UUIDs (Cross-Node Sync)

Every native and agentic endpoint accepts a `scan_uuid` request field (CLI: `--scan-uuid`). When supplied, the server uses it as the scan/run identity instead of generating one. This unlocks the **remote-create + remote-run** pattern: one node creates a placeholder scan record, another node runs the actual work and pushes results under the same UUID — useful for serverless dispatch, queue-based fan-out, or any setup where the dispatcher and the runner are different processes.

### Same field, both endpoint families

| Endpoint family | Where the pinned UUID lands              | Response field |
|-----------------|------------------------------------------|----------------|
| Native scan     | `Scan.uuid` (the scan record's PK)       | `scan_uuid`    |
| Agentic scan    | `AgenticScan.uuid` (the run record's PK) | `agentic_scan_uuid`       |

In other words, `request.scan_uuid` becomes `response.scan_uuid` for native and `response.agentic_scan_uuid` for agentic. Findings, http_records, and OAST interactions written by either run carry that same value in their `scan_uuid` foreign-key column, so a join across nodes always lines up.

### Get-or-create semantics

When the supplied `scan_uuid` already exists in the database:

- **Same `project_uuid`** — the existing row is reused; no duplicate is inserted. The runner proceeds and writes its results against the existing record. This is the cross-node attach case.
- **Different `project_uuid`** — the API returns **HTTP 409 Conflict** with `error: "scan UUID exists under a different project: ..."`. This guard prevents serverless nodes from accidentally corrupting another tenant's data when UUIDs collide.

Per-tenant UUID collisions across unrelated scans are statistically negligible (UUID v4), so the 409 path should only ever fire on a real mistake.

### Worked example: dispatch on Node A, run on Node B

**Node A** — dispatcher creates the placeholder via the API:

```bash
SCAN_UUID=$(uuidgen | tr '[:upper:]' '[:lower:]')

curl -s -X POST http://node-a:9002/api/scans/run \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -H "X-Project-UUID: <project-uuid>" \
  -d "{
    \"targets\": [\"https://example.com\"],
    \"scan_uuid\": \"$SCAN_UUID\",
    \"dry_run\": true
  }"
# Returns 200 with status=dry_run; scan record is now persisted.

# Hand off SCAN_UUID via your queue / message bus
publish-job --scan-uuid "$SCAN_UUID" --target https://example.com
```

**Node B** — worker picks up the job and runs the scan against the same UUID:

```bash
vigolium scan -t https://example.com \
  --project-uuid "<project-uuid>" \
  --scan-uuid "$SCAN_UUID" \
  --upload-results
```

Findings and http_records emitted by Node B carry `scan_uuid = $SCAN_UUID` — exactly what Node A's UI is already querying for. The bundle uploaded by Node B lands at `<project-uuid>/native-scans/$SCAN_UUID/results.tar.gz`, the same key any consumer would expect from a single-node run.

### Agentic equivalent

The same pattern applies to `vigolium agent autopilot|swarm|query|archon` and `POST /api/agent/run/*` — `--scan-uuid` (or the request body's `scan_uuid` field) pins `AgenticScan.uuid` instead of `Scan.uuid`. The response surfaces the pinned value as `agentic_scan_uuid`.

**Node A** — dispatcher pre-creates an autopilot run (e.g. so a UI can show the run UUID before the worker picks it up). Pre-creation is most ergonomic via the agentic API itself with `dry_run: true` (avoids spending agent budget on an empty run):

```bash
RUN_UUID=$(uuidgen | tr '[:upper:]' '[:lower:]')

curl -s -X POST http://node-a:9002/api/agent/run/autopilot \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -H "X-Project-UUID: <project-uuid>" \
  -d "{
    \"target\": \"https://example.com\",
    \"source\": \"/work/my-app\",
    \"scan_uuid\": \"$AGENTIC_SCAN_UUID\",
    \"dry_run\": true
  }"

publish-job --run-uuid "$AGENTIC_SCAN_UUID" --target https://example.com --source /work/my-app
```

**Node B** — worker runs the actual autopilot pipeline against the same UUID:

```bash
vigolium agent autopilot \
  --target https://example.com \
  --source /work/my-app \
  --project-uuid "<project-uuid>" \
  --scan-uuid "$AGENTIC_SCAN_UUID" \
  --upload-results
```

Or, equivalently against a remote server:

```bash
curl -s -X POST http://node-b:9002/api/agent/run/autopilot \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -H "X-Project-UUID: <project-uuid>" \
  -d "{
    \"target\": \"https://example.com\",
    \"source\": \"/work/my-app\",
    \"scan_uuid\": \"$AGENTIC_SCAN_UUID\",
    \"upload_results\": true
  }"
# Response: { "agentic_scan_uuid": "$AGENTIC_SCAN_UUID", "status": "running", ... }
```

Both nodes' findings, http_records, and OAST interactions carry `scan_uuid = $AGENTIC_SCAN_UUID`. Node A's `GET /api/agent/sessions/$AGENTIC_SCAN_UUID` returns the in-progress status (Node B updates the same row), and the uploaded bundle ends up at `<project-uuid>/agentic-scans/$AGENTIC_SCAN_UUID/results.tar.gz`.

The same flow works for `swarm`, `query`, and `archon` — substitute the endpoint and the relevant request fields. For `archon`, pinning is especially useful because deep-mode runs can take hours and the dispatcher often wants to surface the run UUID immediately.

---

## End-to-End Example: Upload Source → Scan → Download Bundle

```bash
PROJECT="<project-uuid>"
TOKEN="<api-token>"
BASE="http://localhost:9002"

# 1. Upload local source to storage (one-time)
SRC_URL=$(curl -s -X POST "$BASE/api/storage/upload-source" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Project-UUID: $PROJECT" \
  -F "file=@my-app.tar.gz" | jq -r .storage_url)

echo "Source uploaded: $SRC_URL"

# 2. Launch swarm scan against the uploaded source
RUN_ID=$(curl -s -X POST "$BASE/api/agent/run/swarm" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Project-UUID: $PROJECT" \
  -d "{
    \"input\": \"https://example.com\",
    \"source\": \"$SRC_URL\",
    \"upload_results\": true,
    \"triage\": true
  }" | jq -r .agentic_scan_uuid)

echo "Run started: $RUN_ID"

# 3. Poll until completed
while true; do
  STATUS=$(curl -s "$BASE/api/agent/status/$RUN_ID" \
    -H "Authorization: Bearer $TOKEN" | jq -r .status)
  echo "Status: $STATUS"
  [[ "$STATUS" == "completed" || "$STATUS" == "failed" ]] && break
  sleep 10
done

# 4. Download and extract the bundle
curl -s -o results.tar.gz "$BASE/api/storage/results/$RUN_ID" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Project-UUID: $PROJECT"

tar xzf results.tar.gz
ls -la
```

---

## Behavior Notes

- **Storage disabled** — When `storage.enabled` is `false`, `upload_results: true` is a silent no-op. The server logs `"upload_results requested but storage is not enabled"` at warn level. Scans still complete normally.
- **Scan failure** — Bundles are uploaded only on successful completion. Failed/cancelled scans skip the upload (the runtime.log is still on disk under the session/scan-logs directory).
- **No output to upload** — If a native scan has neither output files nor a runtime.log on disk (e.g. `persist_logs` disabled and no `--output`), the upload step logs `"storage: no native scan files to upload"` and exits cleanly.
- **Bundle size** — Agentic bundles include the full session dir, which can grow large (archon-audit deep mode produces 10s of MB of phase reports). Use presigned URLs for large downloads.
- **Project scoping** — All keys are prefixed with the project UUID. A bundle uploaded under project A is not visible to project B even if the run UUID is known.
- **Idempotency** — Re-running a scan with the same UUID overwrites the previous bundle. UUIDs are server-generated by default; clients deliberately pin them via `scan_uuid` / `--scan-uuid` for cross-node sync, in which case attaching to an existing record under the same project is the intended path (see [Pinning Scan UUIDs](#pinning-scan-uuids-cross-node-sync)). A pinned UUID that exists under a *different* project returns HTTP 409 instead of overwriting.

---

## Related

- [storage.md](./storage.md) — full storage API reference (upload-source, presign, GCS/S3/MinIO setup)
- [agent.md](./agent.md) — agent run endpoints (query, autopilot, swarm, archon, status, sessions, logs)
- [scan.md](./scan.md) — native scan run/list/status endpoints
- [projects.md](./projects.md) — project scoping and multi-tenancy
- Run `make sanity-check` to exercise this entire flow end-to-end against real targets (ginandjuice.shop / VAmPI / juice-shop).
