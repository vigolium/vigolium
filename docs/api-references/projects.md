# Vigolium API Reference — Projects

Manage projects for multi-tenant data isolation. All scan data (HTTP records, findings, scopes, scans) is scoped to a project via `project_uuid`. Projects can optionally carry `allowed_emails` (exact addresses) and `allowed_domains` (email domain patterns) to control access.

> **Note:** These endpoints manage project records themselves. To scope API operations to a specific project, use the `X-Project-UUID` request header on other endpoints.

## Access Control via `X-User-Email`

When a request includes both `X-Project-UUID` and `X-User-Email` headers, the server checks whether the user is allowed to access the project:

1. If the project has `allowed_emails` set, the user's email must match exactly (case-insensitive).
2. Otherwise, if the project has `allowed_domains` set, the user's email domain (e.g. `@acme.com`) must match one of the entries.
3. If both lists are empty, the project is open — any user can access it.
4. If `X-User-Email` is not sent, the access check is skipped entirely.

Denied requests receive a `403 Forbidden` response.

```bash
# Request with project access check
curl -s http://localhost:9002/api/findings \
  -H 'X-Project-UUID: a1b2c3d4-e5f6-7890-abcd-ef1234567890' \
  -H 'X-User-Email: alice@acme.com' | jq .
```

## GET /api/projects — List Projects

Returns all projects with aggregated statistics. Optionally filter by owner UUID.

**Query parameters:**

| Parameter | Type   | Default | Description                        |
|-----------|--------|---------|------------------------------------|
| `owner`   | string |         | Filter by owner UUID               |

```bash
# List all projects
curl -s http://localhost:9002/api/projects | jq .

# Filter by owner
curl -s 'http://localhost:9002/api/projects?owner=00000000-0000-0000-0000-000000000001' | jq .
```

```json
[
  {
    "uuid": "00000000-0000-0000-0000-000000000001",
    "name": "default",
    "description": "Default project",
    "owner_uuid": "00000000-0000-0000-0000-000000000001",
    "allowed_domains": ["@acme.com", "@partner.io"],
    "allowed_emails": ["alice@external.com"],
    "created_at": "2026-02-19T10:00:00Z",
    "updated_at": "2026-02-19T10:00:00Z",
    "stats": {
      "http_records": {
        "total": 1234,
        "success": 980,
        "redirect": 54,
        "client_err": 180,
        "server_err": 20
      },
      "findings": {
        "total": 42,
        "critical": 2,
        "high": 10,
        "medium": 15,
        "low": 10,
        "info": 5
      },
      "scans": 3,
      "agent_runs": 7,
      "source_repos": 2,
      "oast_interactions": 12
    }
  }
]
```

**Stats fields:**

| Field                      | Type  | Description                              |
|----------------------------|-------|------------------------------------------|
| `stats.http_records.total` | int   | Total HTTP records in the project        |
| `stats.http_records.success` | int | 2xx status code count                    |
| `stats.http_records.redirect` | int | 3xx status code count                   |
| `stats.http_records.client_err` | int | 4xx status code count                 |
| `stats.http_records.server_err` | int | 5xx status code count                 |
| `stats.findings.total`    | int   | Total findings                           |
| `stats.findings.critical` | int   | Critical severity count                  |
| `stats.findings.high`     | int   | High severity count                      |
| `stats.findings.medium`   | int   | Medium severity count                    |
| `stats.findings.low`      | int   | Low severity count                       |
| `stats.findings.info`     | int   | Info severity count                      |
| `stats.scans`             | int   | Total scan sessions                      |
| `stats.agent_runs`        | int   | Total agent runs                         |
| `stats.source_repos`      | int   | Total linked source repositories         |
| `stats.oast_interactions` | int   | Total OAST (out-of-band) interactions    |

**Errors:**

| Code | Condition              |
|------|------------------------|
| 503  | Database not connected |

---

## POST /api/projects — Create Project

**Request body:**

| Field             | Type     | Required | Description                                      |
|-------------------|----------|----------|--------------------------------------------------|
| `name`            | string   | Yes      | Project name                                     |
| `description`     | string   | No       | Project description                              |
| `owner_uuid`      | string   | No       | UUID of the owning user                          |
| `allowed_domains` | string[] | No       | Email domains allowed to access this project (e.g. `["@acme.com"]`) |
| `allowed_emails`  | string[] | No       | Exact email addresses allowed to access this project |

```bash
curl -s -X POST http://localhost:9002/api/projects \
  -H 'Content-Type: application/json' \
  -d '{"name": "my-project", "description": "Web app audit", "allowed_domains": ["@acme.com"], "allowed_emails": ["alice@external.com"]}' | jq .
```

```json
{
  "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "name": "my-project",
  "description": "Web app audit",
  "allowed_domains": ["@acme.com"],
  "allowed_emails": ["alice@external.com"],
  "created_at": "2026-03-06T12:00:00Z",
  "updated_at": "2026-03-06T12:00:00Z"
}
```

**Errors:**

| Code | Condition              |
|------|------------------------|
| 400  | Missing `name` field   |
| 400  | Invalid request body   |
| 503  | Database not connected |

---

## GET /api/projects/:uuid — Get Project

Retrieve a single project by UUID with aggregated statistics.

```bash
curl -s http://localhost:9002/api/projects/a1b2c3d4-e5f6-7890-abcd-ef1234567890 | jq .
```

```json
{
  "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "name": "my-project",
  "description": "Web app audit",
  "owner_uuid": "00000000-0000-0000-0000-000000000001",
  "allowed_domains": ["@acme.com", "@partner.io"],
  "allowed_emails": ["alice@external.com"],
  "created_at": "2026-03-06T12:00:00Z",
  "updated_at": "2026-03-06T12:00:00Z",
  "stats": {
    "http_records": {
      "total": 567,
      "success": 450,
      "redirect": 30,
      "client_err": 72,
      "server_err": 15
    },
    "findings": {
      "total": 18,
      "critical": 1,
      "high": 4,
      "medium": 6,
      "low": 5,
      "info": 2
    },
    "scans": 2,
    "agent_runs": 3,
    "source_repos": 1,
    "oast_interactions": 5
  }
}
```

**Errors:**

| Code | Condition              |
|------|------------------------|
| 404  | Project not found      |
| 503  | Database not connected |

---

## PUT /api/projects/:uuid — Update Project

Update fields on an existing project. Only non-empty fields are applied.

**Request body:**

| Field             | Type     | Required | Description                                      |
|-------------------|----------|----------|--------------------------------------------------|
| `name`            | string   | No       | New project name                                 |
| `description`     | string   | No       | New description                                  |
| `owner_uuid`      | string   | No       | New owner UUID                                   |
| `allowed_domains` | string[] | No       | Replace allowed domains list (send `[]` to clear)|
| `allowed_emails`  | string[] | No       | Replace allowed emails list (send `[]` to clear) |

```bash
curl -s -X PUT http://localhost:9002/api/projects/a1b2c3d4-e5f6-7890-abcd-ef1234567890 \
  -H 'Content-Type: application/json' \
  -d '{"allowed_domains": ["@acme.com"], "allowed_emails": ["bob@external.com"]}' | jq .
```

```json
{
  "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "name": "my-project",
  "description": "Web app audit",
  "owner_uuid": "00000000-0000-0000-0000-000000000001",
  "allowed_domains": ["@acme.com"],
  "allowed_emails": ["bob@external.com"],
  "created_at": "2026-03-06T12:00:00Z",
  "updated_at": "2026-03-06T12:30:00Z"
}
```

**Errors:**

| Code | Condition              |
|------|------------------------|
| 400  | Invalid request body   |
| 404  | Project not found      |
| 503  | Database not connected |

---

## GET /api/projects/domain-map — Domain-to-Project Mapping

Returns a mapping of email domains and exact email addresses to project UUIDs. Useful for frontend middleware to resolve which projects a user has access to in a single call.

```bash
curl -s http://localhost:9002/api/projects/domain-map | jq .
```

```json
{
  "domains": {
    "@acme.com": [
      "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "b2c3d4e5-f6a7-8901-bcde-f12345678901"
    ],
    "@partner.io": [
      "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    ]
  },
  "emails": {
    "alice@external.com": [
      "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    ]
  }
}
```

The frontend middleware can check access by looking up the user's exact email in `emails`, then falling back to their email domain in `domains`. Projects without any `allowed_domains` or `allowed_emails` are omitted from the respective maps.

**Errors:**

| Code | Condition              |
|------|------------------------|
| 503  | Database not connected |

---

## DELETE /api/projects/:uuid — Delete Project

Delete a project by UUID. The default project (`00000000-0000-0000-0000-000000000001`) cannot be deleted. All data (scans, HTTP records, findings, scopes, source repos, OAST interactions, scan logs) belonging to the deleted project is automatically reassigned to the default project.

```bash
curl -s -X DELETE http://localhost:9002/api/projects/a1b2c3d4-e5f6-7890-abcd-ef1234567890 | jq .
```

```json
{
  "message": "project deleted",
  "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```

**Errors:**

| Code | Condition                            |
|------|--------------------------------------|
| 400  | Attempting to delete default project |
| 500  | Database deletion failed             |
| 503  | Database not connected               |
