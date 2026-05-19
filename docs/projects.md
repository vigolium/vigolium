# Projects: Multi-Tenant Data Isolation

Vigolium supports project-based data isolation. Every scan record, finding, scope rule, source repo, and OAST interaction is tagged with a `project_uuid`, so multiple engagements can share the same database without data leaking across boundaries.

## Concepts

- **Project** — A named container for all scan data. Each project has a UUID, name, description, optional access control lists, and optional per-project config overlay.
- **Default project** — A built-in project (`00000000-0000-0000-0000-000000000001`) created during `vigolium init`. All data belongs to this project unless you specify otherwise.
- **Project config** — An optional YAML overlay at `~/.vigolium/projects/<uuid>/config.yaml` that merges on top of the global config.
- **Access control** — Projects can carry `allowed_domains` (email domain patterns like `@acme.com`) and `allowed_emails` (exact addresses like `alice@acme.com`) to control who can access them. See [Access Control](#access-control) below.

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

This exports the `VIGOLIUM_PROJECT_UUID` environment variable in your shell. All subsequent commands in that shell session will use this project.

### View project config path

```bash
vigolium project config
# or for a specific project
vigolium project config a1b2c3d4-...
```

### Manage project access

```bash
# Add allowed domains and emails (auto-detected)
vigolium project allow a1b2c3d4-... @acme.com @partner.io alice@external.com
# ✓ Added 2 domain(s) and 1 email(s) to project my-engagement
#   Allowed domains: @acme.com, @partner.io
#   Allowed emails:  alice@external.com

# Mix freely — @-prefixed values go to domains, the rest to emails
vigolium project allow a1b2c3d4-... @newdomain.io bob@contractor.com

# Remove entries from both lists
vigolium project remove-access a1b2c3d4-... @partner.io alice@external.com
# ✓ Removed 2 entry/entries from project my-engagement
```

### Readonly failsafe

Set `VIGOLIUM_PROJECT_READONLY=true` to prevent all mutating project commands (`create`, `allow`, `remove-access`) from the CLI. Read-only commands (`list`, `use`, `config`) still work.

```bash
export VIGOLIUM_PROJECT_READONLY=true

vigolium project allow a1b2c3d4-... @evil.com
# Error: project management is disabled (VIGOLIUM_PROJECT_READONLY=true)

vigolium project list
# still works
```

This is useful in production or shared environments where projects should only be managed through the REST API.

## Scoping Operations to a Project

There are several ways to scope operations to a project, listed by precedence (highest first):

| Method | Example |
|--------|---------|
| `--project-uuid` flag | `vigolium scan -t https://example.com --project-uuid a1b2c3d4-...` |
| `--project-name` flag | `vigolium scan -t https://example.com --project-name my-engagement` |
| `VIGOLIUM_PROJECT_UUID` env var | `export VIGOLIUM_PROJECT_UUID=a1b2c3d4-...` |
| `VIGOLIUM_PROJECT` env var (legacy) | `export VIGOLIUM_PROJECT=a1b2c3d4-...` |
| Default project | Used when no flag or env var is set |

`--project-uuid` and `--project-name` are mutually exclusive.

### CLI examples

```bash
# Scan within a project (by UUID)
vigolium scan -t https://example.com --project-uuid a1b2c3d4-...

# Scan within a project (by name)
vigolium scan -t https://example.com --project-name my-engagement

# Ingest into a project
vigolium ingest --input urls.txt --project-uuid a1b2c3d4-...

# List findings for a project
vigolium db list findings --project-name my-engagement

# Export project data
vigolium db export --project-uuid a1b2c3d4-... -o findings.jsonl
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

dynamic-assessment:
  extensions:
    enabled: true
    variables:
      auth_token: "Bearer project-specific-token"
```

## Access Control

Projects can restrict access by email domain or exact email address using the `allowed_domains` and `allowed_emails` fields.

### How it works

When a request includes both `X-Project-UUID` and `X-User-Email` headers, the server checks access:

1. If `allowed_emails` is non-empty → the user's email must match exactly (case-insensitive).
2. Otherwise, if `allowed_domains` is non-empty → the user's email domain (e.g. `@acme.com`) must match.
3. If both lists are empty → the project is open to anyone.
4. If `X-User-Email` is not sent → the check is skipped entirely.

Denied requests receive a `403 Forbidden` response.

### Managing via CLI

```bash
# Add domains and emails (auto-detected by format)
vigolium project allow <project-uuid> @acme.com alice@external.com

# Remove entries
vigolium project remove-access <project-uuid> @acme.com alice@external.com
```

### Managing via API

```bash
# Set access lists on create
curl -X POST http://localhost:9002/api/projects \
  -H "Content-Type: application/json" \
  -d '{"name":"restricted","allowed_domains":["@acme.com"],"allowed_emails":["alice@ext.com"]}'

# Update access lists
curl -X PUT http://localhost:9002/api/projects/a1b2c3d4-... \
  -H "Content-Type: application/json" \
  -d '{"allowed_domains":["@acme.com","@partner.io"]}'

# Clear restrictions (project becomes open)
curl -X PUT http://localhost:9002/api/projects/a1b2c3d4-... \
  -H "Content-Type: application/json" \
  -d '{"allowed_domains":[],"allowed_emails":[]}'

# Get domain-to-project mapping (for frontend middleware)
curl http://localhost:9002/api/projects/domain-map
```

The `domain-map` endpoint returns:

```json
{
  "domains": {
    "@acme.com": ["project-uuid-1", "project-uuid-2"]
  },
  "emails": {
    "alice@ext.com": ["project-uuid-1"]
  }
}
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
