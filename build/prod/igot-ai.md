# Vigolium Scanner — iGot AI Access

## Console Access

| | |
|---|---|
| **URL** | https://igot-ai.vigolium.com/ |
| **Showcases** | https://igot-ai.vigolium.com/showcases?view_key=6bcdad3c885db9d0 |
| **Email** | `admin@igot.ai` |
| **Password** | `fb420c419283f0b5a3803a54e3963c03` |

## Scanner API Key

```
VIGOLIUM_API_KEY=7336b4213333afcaa960afedd9c85a45
```

All API requests require the `Authorization: Bearer` header with this key.

---

## API Examples


### Quick Start — 2 Commands

Start an autopilot scan and tail its live console output. That's it.

**1. Kick off the scan** (returns a `run_id`):

```bash
curl -X POST https://igot-ai-api.vigolium.com/api/agent/run/autopilot \
  -H "Authorization: Bearer 7336b4213333afcaa960afedd9c85a45" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "~/Desktop/demo/repo",
    "intensity": "balanced"
  }'
```

Response:

```json
{ "run_id": "f7a8b9c0-1234-5678-abcd-ef9876543210", "status": "running" }
```

**2. Follow the live console log** (same output the CLI shows; includes phase progression, findings, and status). Stream until the run finishes:

```bash
curl -N \
  -H "Authorization: Bearer 7336b4213333afcaa960afedd9c85a45" \
  -H "Accept: text/event-stream" \
  https://igot-ai-api.vigolium.com/api/agent/sessions/f7a8b9c0-1234-5678-abcd-ef9876543210/logs
```

Drop the `-H "Accept: text/event-stream"` flag to get a one-shot plain-text
dump instead of a live tail, or append `?strip=1` to remove ANSI color codes.
For the structured result (findings, attack plan, triage) after the run ends,
hit `GET /api/agent/sessions/:id`.


### Autopilot Scan with Source Code

**Scan with a Git URL as source (e.g., private repo via GitHub personal access token):**

```bash
curl -X POST https://igot-ai-api.vigolium.com/api/agent/run/autopilot \
  -H "Authorization: Bearer 7336b4213333afcaa960afedd9c85a45" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "https://ghp_xxxxxxxxxxxx@github.com/org/my-app.git",
    "intensity": "balanced"
  }'
```

**Example response:**

```json
{
  "run_id": "f7a8b9c0-1234-5678-abcd-ef9876543210",
  "status": "running",
  "message": "autopilot scan started"
}
```


### Upload Source Code Archive

**Upload a .zip file and get a source path for scanning:**

```bash
curl -X POST https://igot-ai-api.vigolium.com/api/repos/upload \
  -H "Authorization: Bearer 7336b4213333afcaa960afedd9c85a45" \
  -F "file=@my-app.zip"
```

**Example response:**

```json
{
  "repo_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "source": "/home/vigolium/.vigolium/repo-uploads/a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "message": "repository uploaded and extracted"
}
```

**Then use the `source` path from the response to start an autopilot scan:**

```bash
curl -X POST https://igot-ai-api.vigolium.com/api/agent/run/autopilot \
  -H "Authorization: Bearer 7336b4213333afcaa960afedd9c85a45" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://app.example.com",
    "source": "/home/vigolium/.vigolium/repo-uploads/a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "intensity": "balanced"
  }'
```

**Example response:**

```json
{
  "run_id": "b2c3d4e5-6789-0abc-def1-234567890abc",
  "status": "running",
  "message": "autopilot scan started"
}
```


### Start an Autopilot Scan

**Basic scan against a target URL:**

```bash
curl -X POST https://igot-ai-api.vigolium.com/api/agent/run/autopilot \
  -H "Authorization: Bearer 7336b4213333afcaa960afedd9c85a45" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "/local/path/to/your/repo",
    "intensity": "deep"
  }'
```

**Example response:**

```json
{
  "run_id": "c3d4e5f6-7890-1bcd-ef23-456789abcdef",
  "status": "running",
  "message": "autopilot scan started"
}
```

### Fetch Findings

**List all findings:**

```bash
curl https://igot-ai-api.vigolium.com/api/findings \
  -H "Authorization: Bearer 7336b4213333afcaa960afedd9c85a45"
```

**Example response:**

```json
{
  "data": [
    {
      "id": 1,
      "url": "https://app.example.com/api/users",
      "hostname": "app.example.com",
      "module_id": "sqli-error-based",
      "module_name": "SQL Injection (Error Based)",
      "module_type": "active",
      "finding_source": "agent",
      "severity": "high",
      "confidence": "confirmed",
      "description": "SQL injection via error-based technique in 'id' parameter",
      "repo_name": "my-app",
      "matched_at": ["id"],
      "finding_hash": "a1b2c3d4e5f6",
      "found_at": "2026-04-10T12:00:00Z",
      "created_at": "2026-04-10T12:00:00Z"
    }
  ],
  "total": 1,
  "limit": 50,
  "offset": 0,
  "has_more": false
}
```

**Filter by severity:**

```bash
curl "https://igot-ai-api.vigolium.com/api/findings?severity=high,critical" \
  -H "Authorization: Bearer 7336b4213333afcaa960afedd9c85a45"
```

> Response format: same paginated response as above, filtered to high/critical findings only.

**Filter by domain:**

```bash
curl "https://igot-ai-api.vigolium.com/api/findings?domain=app.example.com" \
  -H "Authorization: Bearer 7336b4213333afcaa960afedd9c85a45"
```

> Response format: same paginated response, filtered by hostname.

**Filter by repository name:**

```bash
curl "https://igot-ai-api.vigolium.com/api/findings?repo_name=my-app" \
  -H "Authorization: Bearer 7336b4213333afcaa960afedd9c85a45"
```

> Response format: same paginated response, filtered by `repo_name` field (exact match).

**Filter by scan ID:**

```bash
curl "https://igot-ai-api.vigolium.com/api/findings?scan_id=abc-123" \
  -H "Authorization: Bearer 7336b4213333afcaa960afedd9c85a45"
```

> Response format: same paginated response, filtered by scan UUID.

**Paginate results:**

```bash
curl "https://igot-ai-api.vigolium.com/api/findings?limit=100&offset=0" \
  -H "Authorization: Bearer 7336b4213333afcaa960afedd9c85a45"
```

> Response format: same paginated response with `limit: 100` and `offset: 0`.

**Get a single finding by ID:**

```bash
curl https://igot-ai-api.vigolium.com/api/findings/42 \
  -H "Authorization: Bearer 7336b4213333afcaa960afedd9c85a45"
```

**Example response:**

```json
{
  "id": 42,
  "url": "https://app.example.com/api/login",
  "hostname": "app.example.com",
  "module_id": "xss-reflected",
  "module_name": "Cross-Site Scripting (Reflected)",
  "module_type": "active",
  "finding_source": "agent",
  "severity": "medium",
  "confidence": "confirmed",
  "description": "Reflected XSS in 'redirect' parameter",
  "repo_name": "my-app",
  "cwe_id": "CWE-79",
  "matched_at": ["redirect"],
  "finding_hash": "d4e5f6a7b8c9",
  "found_at": "2026-04-10T14:30:00Z",
  "created_at": "2026-04-10T14:30:00Z"
}
```

### Agent Sessions

> **Note:** The `run_id` returned by every agent run endpoint is a bare UUID
> that maps 1:1 to the on-disk session directory at
> `~/.vigolium/agent-sessions/<run_id>/`. Use it to locate the live `run.log`,
> `output.md`, and `archon-audit/` artifacts for that run.

**List all agent sessions (lightweight status):**

```bash
curl https://igot-ai-api.vigolium.com/api/agent/status/list \
  -H "Authorization: Bearer 7336b4213333afcaa960afedd9c85a45"
```

**Example response:**

```json
[
  {
    "run_id": "f7a8b9c0-1234-5678-abcd-ef9876543210",
    "mode": "autopilot",
    "status": "completed",
    "finding_count": 5,
    "record_count": 12,
    "completed_at": "2026-04-10T13:45:00Z"
  },
  {
    "run_id": "c3d4e5f6-7890-1bcd-ef23-456789abcdef",
    "mode": "autopilot",
    "status": "running",
    "current_phase": "scanning",
    "finding_count": 2,
    "record_count": 8
  }
]
```

**Get status of a specific agent session:**

```bash
curl https://igot-ai-api.vigolium.com/api/agent/status/f7a8b9c0-1234-5678-abcd-ef9876543210 \
  -H "Authorization: Bearer 7336b4213333afcaa960afedd9c85a45"
```

**Example response:**

```json
{
  "run_id": "f7a8b9c0-1234-5678-abcd-ef9876543210",
  "mode": "autopilot",
  "status": "completed",
  "finding_count": 5,
  "record_count": 12,
  "saved_count": 5,
  "phases_run": ["discovery", "scanning", "triage"],
  "completed_at": "2026-04-10T13:45:00Z"
}
```

**Get full session details (including session dir, source path, raw agent output):**

```bash
curl https://igot-ai-api.vigolium.com/api/agent/sessions/f7a8b9c0-1234-5678-abcd-ef9876543210 \
  -H "Authorization: Bearer 7336b4213333afcaa960afedd9c85a45"
```

**Example response:**

```json
{
  "uuid": "f7a8b9c0-1234-5678-abcd-ef9876543210",
  "mode": "autopilot",
  "status": "completed",
  "agent_name": "claude",
  "target_url": "https://app.example.com",
  "source_path": "/home/vigolium/.vigolium/repo-uploads/a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "session_dir": "/home/vigolium/.vigolium/agent-sessions/f7a8b9c0-1234-5678-abcd-ef9876543210",
  "current_phase": "autopilot",
  "phases_run": ["archon", "autopilot"],
  "finding_count": 5,
  "record_count": 12,
  "saved_count": 5,
  "duration_ms": 692739,
  "started_at": "2026-04-10T13:34:06Z",
  "completed_at": "2026-04-10T13:45:39Z",
  "created_at": "2026-04-10T13:34:06Z",
  "agent_raw_output": "...full agent output captured from output.md..."
}
```

The `session_dir` field always equals `~/.vigolium/agent-sessions/<uuid>/`, so
clients can derive it from `run_id` alone. The directory contains:

- `run.log` — live stream of the autopilot/swarm + archon output. Tail this for
  real-time progress while a run is in flight.
- `output.md` — final agent transcript (also returned inline as
  `agent_raw_output` after completion).
- `archon-audit/` — archon-audit findings, `audit-state.json`, and
  `audit-stream.jsonl` (live JSONL feed of the parallel security audit).
- `extensions/` — generated JS scanner extensions (swarm only).

**Get the live console log (`run.log`) over HTTP:**

```bash
# Plain text dump (ANSI preserved)
curl https://igot-ai-api.vigolium.com/api/agent/sessions/f7a8b9c0-1234-5678-abcd-ef9876543210/logs \
  -H "Authorization: Bearer 7336b4213333afcaa960afedd9c85a45"

# Plain text with ANSI escape codes stripped
curl "https://igot-ai-api.vigolium.com/api/agent/sessions/f7a8b9c0-1234-5678-abcd-ef9876543210/logs?strip=1" \
  -H "Authorization: Bearer 7336b4213333afcaa960afedd9c85a45"

# Live tail via Server-Sent Events (follows the run until it finishes)
curl -N \
  -H "Authorization: Bearer 7336b4213333afcaa960afedd9c85a45" \
  -H "Accept: text/event-stream" \
  https://igot-ai-api.vigolium.com/api/agent/sessions/f7a8b9c0-1234-5678-abcd-ef9876543210/logs
```

This endpoint returns exactly what the CLI user would see in their terminal
(including colors). Default response is `text/plain; charset=utf-8`; with
`Accept: text/event-stream` it tails the file as SSE `chunk` events until the
run reaches a terminal status, then emits a final `done` event. Works for
all three agent modes (query, autopilot, swarm), both during and after the
run. Structured fields (findings, attack plan, triage result) remain on
`/api/agent/sessions/:id`.
