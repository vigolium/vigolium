# Vigolium API Reference — Projects

Manage projects for multi-tenant data isolation. All scan data (HTTP records, findings, scopes, scans) is scoped to a project via `project_uuid`.

> **Note:** These endpoints manage project records themselves. To scope API operations to a specific project, use the `X-Project-UUID` request header on other endpoints.

## GET /api/projects — List Projects

Returns all projects. Optionally filter by owner UUID.

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
    "created_at": "2026-02-19T10:00:00Z",
    "updated_at": "2026-02-19T10:00:00Z"
  }
]
```

**Errors:**

| Code | Condition              |
|------|------------------------|
| 503  | Database not connected |

---

## POST /api/projects — Create Project

**Request body:**

| Field         | Type   | Required | Description                  |
|---------------|--------|----------|------------------------------|
| `name`        | string | Yes      | Project name                 |
| `description` | string | No       | Project description          |
| `owner_uuid`  | string | No       | UUID of the owning user      |

```bash
curl -s -X POST http://localhost:9002/api/projects \
  -H 'Content-Type: application/json' \
  -d '{"name": "my-project", "description": "Web app audit"}' | jq .
```

```json
{
  "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "name": "my-project",
  "description": "Web app audit",
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

Retrieve a single project by UUID.

```bash
curl -s http://localhost:9002/api/projects/a1b2c3d4-e5f6-7890-abcd-ef1234567890 | jq .
```

```json
{
  "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "name": "my-project",
  "description": "Web app audit",
  "owner_uuid": "00000000-0000-0000-0000-000000000001",
  "created_at": "2026-03-06T12:00:00Z",
  "updated_at": "2026-03-06T12:00:00Z"
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

| Field         | Type   | Required | Description                  |
|---------------|--------|----------|------------------------------|
| `name`        | string | No       | New project name             |
| `description` | string | No       | New description              |
| `owner_uuid`  | string | No       | New owner UUID               |

```bash
curl -s -X PUT http://localhost:9002/api/projects/a1b2c3d4-e5f6-7890-abcd-ef1234567890 \
  -H 'Content-Type: application/json' \
  -d '{"description": "Updated description"}' | jq .
```

```json
{
  "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "name": "my-project",
  "description": "Updated description",
  "owner_uuid": "00000000-0000-0000-0000-000000000001",
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
