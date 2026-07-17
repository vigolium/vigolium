# Projects: Multi-Tenant Data Isolation

Projects isolate scan data in a shared Vigolium database. Scans, HTTP records,
findings, scopes, OAST interactions, scan logs, authentication mappings, and
agentic scans carry a `project_uuid`.

The built-in default project UUID is
`00000000-0000-0000-defa-c01001000001`.

## Project Commands

Create and list projects:

```bash
vigolium project create my-engagement \
  --description "Q3 application assessment"
vigolium project list
vigolium project ls --json
```

`project create` generates a UUID unless the global `--project-uuid` flag is
set explicitly.

Select a project:

```bash
eval "$(vigolium project use a1b2c3d4-e5f6-7890-abcd-ef1234567890)"
```

`project use` does two things:

- prints an `export VIGOLIUM_PROJECT_UUID=...` command for the current shell;
- persists the selection in `~/.vigolium/active-project` for future commands.

If the UUID is valid but unknown, `project use` creates it. Use `--name` and
`--description` to customize an auto-created project.

Show the project configuration path:

```bash
vigolium project config
vigolium project config a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

Delete a project and its project-scoped data:

```bash
vigolium project delete a1b2c3d4-e5f6-7890-abcd-ef1234567890
vigolium project rm a1b2c3d4-e5f6-7890-abcd-ef1234567890 --force
vigolium project delete a1b2c3d4-e5f6-7890-abcd-ef1234567890 \
  --keep-config --force
```

The CLI refuses to delete the default project. Set
`VIGOLIUM_PROJECT_READONLY=true` to disable mutating project commands in a
shared or production environment.

## Selecting a Project

The CLI resolves the active project in this order:

1. `--project-uuid`
2. `--project-name`
3. `VIGOLIUM_PROJECT_UUID`
4. legacy `VIGOLIUM_PROJECT`
5. `~/.vigolium/active-project`
6. the built-in default project

`--project-uuid` and `--project-name` are mutually exclusive.

```bash
# Scan by project name
vigolium scan https://example.com --project-name my-engagement

# Query and export by project UUID
vigolium finding --project-uuid a1b2c3d4-e5f6-7890-abcd-ef1234567890
vigolium export --project-uuid a1b2c3d4-e5f6-7890-abcd-ef1234567890 \
  --format jsonl -o project.jsonl
```

For server requests, use `X-Project-UUID`:

```bash
curl http://localhost:9002/api/findings \
  -H 'Authorization: Bearer my-secret-key' \
  -H 'X-Project-UUID: a1b2c3d4-e5f6-7890-abcd-ef1234567890'
```

If the header is omitted, the server uses the default project. Project
selection is data scoping; it is not an email-domain authorization mechanism.

## Per-Project Configuration

The project overlay lives at:

```text
~/.vigolium/projects/<uuid>/config.yaml
```

It uses the same partial YAML shape as a scanning profile. Only specified
values override the global settings.

```yaml
scope:
  hosts:
    - "*.example.com"

scanning_pace:
  concurrency: 30
  rate_limit: 50
```

Configuration precedence is:

```text
built-in defaults
  -> ~/.vigolium/vigolium-configs.yaml
  -> ~/.vigolium/projects/<uuid>/config.yaml
  -> --scanning-profile
  -> CLI flags
```

## Project REST API

The current endpoints are:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/projects` | List projects with aggregate statistics |
| `POST` | `/api/projects` | Create a project |
| `GET` | `/api/projects/:uuid` | Get one project with statistics |
| `GET` | `/api/projects/:uuid/stats` | Get statistics only |
| `PUT` | `/api/projects/:uuid` | Update name, description, or owner |
| `DELETE` | `/api/projects/:uuid` | Delete a project after reassigning its data to the default project |

Create a project with either a server-generated UUID or a client-supplied UUID:

```bash
curl -X POST http://localhost:9002/api/projects \
  -H 'Authorization: Bearer my-secret-key' \
  -H 'Content-Type: application/json' \
  -d '{
    "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "name": "my-engagement",
    "description": "Q3 application assessment"
  }'
```

The accepted project fields are `uuid` (create only), `name`, `description`,
and `owner_uuid`. See the [Projects API reference](api-references/projects.md)
for response schemas and error behavior.
