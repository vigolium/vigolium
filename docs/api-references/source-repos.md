# Vigolium API Reference — Source Repos

Manage links between application source code and target hostnames. Source repos enable source-aware JS extensions to read, list, and search source files during scanning.

## GET /api/source-repos — List Source Repos

**Query parameters:**

| Parameter  | Type   | Default | Description                                  |
|------------|--------|---------|----------------------------------------------|
| `hostname` | string |         | Filter by exact hostname                     |
| `limit`    | int    | 50      | Number of repos to return (max 500)          |
| `offset`   | int    | 0       | Offset for pagination                        |

```bash
# List all source repos
curl -s http://localhost:9002/api/source-repos | jq .

# Filter by hostname
curl -s 'http://localhost:9002/api/source-repos?hostname=app.example.com' | jq .
```

```json
{
  "data": [
    {
      "id": 1,
      "hostname": "app.example.com",
      "name": "my-app",
      "root_path": "/home/user/src/my-app",
      "repo_type": "git",
      "language": "python",
      "framework": "django",
      "endpoints": ["/api/users", "/api/login"],
      "route_params": ["id", "uuid"],
      "sinks": ["sql.exec"],
      "tags": ["backend"],
      "third_party_scan_status": "completed",
      "third_party_scan_at": "2026-02-19T11:00:00Z",
      "created_at": "2026-02-19T10:00:00Z",
      "updated_at": "2026-02-19T11:00:00Z"
    }
  ],
  "total": 1,
  "limit": 50,
  "offset": 0,
  "has_more": false
}
```

---

## POST /api/source-repos — Create Source Repo

**Request body:**

| Field         | Type     | Required | Description                                           |
|---------------|----------|----------|-------------------------------------------------------|
| `hostname`    | string   | Yes      | Target hostname to link                               |
| `root_path`   | string   | Yes      | Absolute filesystem path to source root               |
| `name`        | string   | No       | Display name (defaults to hostname)                   |
| `repo_type`   | string   | No       | `git`, `folder`, or `archive` (defaults to `folder`)  |
| `language`    | string   | No       | Primary programming language                          |
| `framework`   | string   | No       | Framework (e.g. express, django, spring)              |
| `scan_uuid`   | string   | No       | Link to a specific scan UUID                          |
| `endpoints`   | string[] | No       | Known application endpoints                           |
| `route_params`| string[] | No       | Known route parameters                                |
| `sinks`       | string[] | No       | Known dangerous sinks                                 |
| `tags`        | string[] | No       | Tags for categorization                               |
| `metadata`    | object   | No       | Arbitrary metadata                                    |

```bash
curl -s -X POST http://localhost:9002/api/source-repos \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "app.example.com",
    "root_path": "/home/user/src/my-app",
    "repo_type": "git",
    "language": "python",
    "framework": "django"
  }' | jq .
```

```json
{
  "id": 1,
  "hostname": "app.example.com",
  "name": "app.example.com",
  "root_path": "/home/user/src/my-app",
  "repo_type": "git",
  "language": "python",
  "framework": "django",
  "third_party_scan_status": "",
  "created_at": "2026-02-19T10:00:00Z",
  "updated_at": "2026-02-19T10:00:00Z"
}
```

---

## GET /api/source-repos/:id — Get Source Repo

```bash
curl -s http://localhost:9002/api/source-repos/1 | jq .
```

---

## PUT /api/source-repos/:id — Update Source Repo

Partially updates a source repo. Only provided fields are overwritten.

```bash
curl -s -X PUT http://localhost:9002/api/source-repos/1 \
  -H "Content-Type: application/json" \
  -d '{
    "language": "go",
    "framework": "fiber",
    "tags": ["backend", "api"]
  }' | jq .
```

---

## DELETE /api/source-repos/:id — Delete Source Repo

```bash
curl -s -X DELETE http://localhost:9002/api/source-repos/1 | jq .
```

```json
{
  "message": "source repo deleted",
  "id": 1
}
```
