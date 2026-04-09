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

**List all agent sessions:**

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
curl https://igot-ai-api.vigolium.com/api/agent/status/abc-123 \
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
