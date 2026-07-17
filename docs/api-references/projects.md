# Projects API

Projects isolate scans, traffic, findings, scopes, OAST interactions, and agent
runs by `project_uuid`. Use `X-Project-UUID` to scope other API requests. If it
is omitted, Vigolium uses the default project
`00000000-0000-0000-defa-c01001000001`.

Project selection does not implement an email allowlist. Authentication and
server roles are described in [Authentication](authentication.md).

## Project Schema

Project responses may contain:

| Field | Type | Description |
|---|---|---|
| `uuid` | string | Project UUID |
| `name` | string | Project name |
| `description` | string | Optional description |
| `owner_uuid` | string | Optional owner UUID |
| `config_path` | string | Optional configuration path |
| `tags` | string[] | Optional tags |
| `default_target` | string | Optional default target |
| `last_scan_at` | timestamp | Most recent scan time, when known |
| `created_at` | timestamp | Creation time |
| `updated_at` | timestamp | Last update time |

List and detail responses also contain `stats`:

```json
{
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
  "agentic_scans": 3,
  "oast_interactions": 5
}
```

## List Projects

```http
GET /api/projects
GET /api/projects?owner=<owner-uuid>
```

Returns an array of project objects with `stats`. The optional `owner` query
parameter filters by owner UUID.

```bash
curl -s http://localhost:9002/api/projects \
  -H 'Authorization: Bearer my-secret-key' | jq .
```

## Create a Project

```http
POST /api/projects
```

Request fields:

| Field | Required | Description |
|---|---|---|
| `name` | yes | Project name |
| `uuid` | no | Client-supplied UUID; the server generates one when omitted |
| `description` | no | Project description |
| `owner_uuid` | no | Owner UUID |

Supplying an existing `uuid` is idempotent: the server returns the existing
project.

```bash
curl -s -X POST http://localhost:9002/api/projects \
  -H 'Authorization: Bearer my-secret-key' \
  -H 'Content-Type: application/json' \
  -d '{"name":"my-project","description":"Web application audit"}' | jq .
```

Successful creation returns `201 Created`. An idempotent existing-UUID request
returns `200 OK`.

## Get a Project

```http
GET /api/projects/:uuid
```

Returns the project and its aggregate `stats`, or `404` when the UUID does not
exist.

```bash
curl -s http://localhost:9002/api/projects/a1b2c3d4-e5f6-7890-abcd-ef1234567890 \
  -H 'Authorization: Bearer my-secret-key' | jq .
```

## Get Project Statistics

```http
GET /api/projects/:uuid/stats
```

Returns only the aggregate statistics object. This is useful for refreshing a
dashboard without fetching project metadata.

## Update a Project

```http
PUT /api/projects/:uuid
```

The request accepts `name`, `description`, and `owner_uuid`. Only non-empty
fields are applied.

```bash
curl -s -X PUT \
  http://localhost:9002/api/projects/a1b2c3d4-e5f6-7890-abcd-ef1234567890 \
  -H 'Authorization: Bearer my-secret-key' \
  -H 'Content-Type: application/json' \
  -d '{"description":"Updated engagement scope"}' | jq .
```

## Delete a Project

```http
DELETE /api/projects/:uuid
```

The API reassigns the project's data to the default project before deleting
the project record. The default project cannot be deleted.

```bash
curl -s -X DELETE \
  http://localhost:9002/api/projects/a1b2c3d4-e5f6-7890-abcd-ef1234567890 \
  -H 'Authorization: Bearer my-secret-key' | jq .
```

Common errors are `400` for an invalid request or an attempt to delete the
default project, `404` for a missing project, and `503` when the server has no
database connection.
