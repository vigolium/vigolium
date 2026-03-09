# Projects: Multi-Tenant Data Isolation

Vigolium supports project-based data isolation. Every scan record, finding, scope rule, source repo, and OAST interaction is tagged with a `project_uuid`, so multiple engagements can share the same database without data leaking across boundaries.

## Concepts

- **Project** — A named container for all scan data. Each project has a UUID, name, description, and optional per-project config overlay.
- **Default project** — A built-in project (`00000000-0000-0000-0000-000000000001`) created during `vigolium init`. All data belongs to this project unless you specify otherwise.
- **Project config** — An optional YAML overlay at `~/.vigolium/projects/<uuid>/config.yaml` that merges on top of the global config.

## CLI Usage

### Create a project

```bash
vigolium project create my-engagement
# Created project my-engagement
#   UUID: a1b2c3d4-...
#   Config: ~/.vigolium/projects/a1b2c3d4-.../config.yaml

# With a description
vigolium project create client-app --description "Q1 2026 pentest for client-app"
```

### List projects

```bash
vigolium project list
# or
vigolium project ls
```

The active project is marked with `*`.

### Set the active project

```bash
eval $(vigolium project use a1b2c3d4-...)
# Active project: my-engagement (a1b2c3d4-...)
```

This exports the `VIG_PROJECT_UUID` environment variable in your shell. All subsequent commands in that shell session will use this project.

### View project config path

```bash
vigolium project config
# or for a specific project
vigolium project config a1b2c3d4-...
```

## Scoping Operations to a Project

There are several ways to scope operations to a project, listed by precedence (highest first):

| Method | Example |
|--------|---------|
| `--project-id` flag | `vigolium scan -t https://example.com --project-id a1b2c3d4-...` |
| `--project-name` flag | `vigolium scan -t https://example.com --project-name my-engagement` |
| `VIG_PROJECT_UUID` env var | `export VIG_PROJECT_UUID=a1b2c3d4-...` |
| `VIGOLIUM_PROJECT` env var (legacy) | `export VIGOLIUM_PROJECT=a1b2c3d4-...` |
| Default project | Used when no flag or env var is set |

`--project-id` and `--project-name` are mutually exclusive. The deprecated `--project` flag is an alias for `--project-id`.

### CLI examples

```bash
# Scan within a project (by UUID)
vigolium scan -t https://example.com --project-id a1b2c3d4-...

# Scan within a project (by name)
vigolium scan -t https://example.com --project-name my-engagement

# Ingest into a project
vigolium ingest --input urls.txt --project-id a1b2c3d4-...

# List findings for a project
vigolium db list findings --project-name my-engagement

# Export project data
vigolium db export --project-id a1b2c3d4-... -o findings.jsonl
```

### Server API

When using the REST API, set the `X-Project-UUID` header to scope all operations to a project:

```bash
curl -X POST http://localhost:9002/api/ingest-http \
  -H "Authorization: Bearer my-secret-key" \
  -H "X-Project-UUID: a1b2c3d4-..." \
  -H "Content-Type: application/json" \
  -d '{"input_mode": "url", "content": "https://example.com"}'
```

If the header is omitted, the default project is used.

## Config Merge Strategy

Configuration is resolved in layers (later layers override earlier ones):

```
Built-in defaults
  → ~/.vigolium/vigolium-configs.yaml          (global config)
    → ~/.vigolium/projects/<uuid>/config.yaml  (project config overlay)
      → --scanning-profile flag                (scanning profile)
        → CLI flags                            (highest precedence)
```

The project config file uses the same format as scanning profiles — a partial YAML overlay. Only the fields you specify are overridden:

```yaml
# ~/.vigolium/projects/a1b2c3d4-.../config.yaml
scope:
  hosts:
    - "*.example.com"

scanning_pace:
  concurrency: 30
  rate_limit: 50

dynamic_assessment:
  extensions:
    enabled: true
    variables:
      auth_token: "Bearer project-specific-token"
```

## Database Isolation

All major data tables include a `project_uuid` column:

- `scans`
- `http_records`
- `findings`
- `scopes`
- `source_repos`
- `oast_interactions`
- `scan_logs`

Queries from the CLI, server API, and internal pipeline filter by the active project UUID. Existing databases are automatically migrated — the `project_uuid` column is added with the default project UUID as the default value.
