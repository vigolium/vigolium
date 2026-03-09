# Data & Management Commands Reference

Complete reference for `db`, `finding`, `module`, `extensions`, `config`, `scope`, `source`, `strategy`, `export`, and `version` commands.

## Table of Contents

- [db](#db)
- [db list / ls](#db-list)
- [db stats](#db-stats)
- [db export](#db-export)
- [db clean](#db-clean)
- [finding](#finding)
- [export (top-level)](#export)
- [module](#module)
- [extensions](#extensions)
- [config](#config)
- [scope](#scope)
- [source](#source)
- [strategy](#strategy)
- [version](#version)

---

## db

**Usage:** `vigolium db <subcommand> [flags]`

Manage database records. Parent command for `list`, `stats`, `export`, and `clean`.

### Shared db flags (persistent)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--table` | string | — | Database table: http_records, findings, scans |
| `--search` | string | — | Quick search across record fields |

---

## db list

**Usage:** `vigolium db list [flags]` (aliases: `ls`)

List database records with filtering, sorting, and display options.

### Display flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--tree` | bool | `false` | Hierarchical tree format |
| `--raw` | bool | `false` | Full raw HTTP request and response |
| `--list-tables` | bool | `false` | List all database table names |
| `--list-columns` | bool | `false` | List column names for the current table |

### Pagination flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--limit` | `-n` | int | `100` | Max records to display |
| `--offset` | `-o` | int | `0` | Records to skip |

### Column selection flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--columns` | []string | — | Columns to include |
| `--exclude-columns` | []string | — | Columns to exclude |

### Filter flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--host` | string | — | Filter by hostname pattern |
| `--method` | []string | — | Filter by HTTP method |
| `--status` | []int | — | Filter by HTTP status code |
| `--path` | string | — | Filter by URL path pattern |
| `--scan-id` | string | — | Filter by scan session ID |
| `--severity` | string | — | Filter findings by severity |
| `--min-risk` | int | `0` | Show only records with risk score at or above this value |
| `--remark` | string | — | Filter records containing this text in remarks |
| `--from` | string | — | Records after date (YYYY-MM-DD) |
| `--to` | string | — | Records before date |
| `--header` | string | — | Search within HTTP header names and values |
| `--body` | string | — | Search in request/response body |

### Sorting flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--sort` | string | `created_at` | Sort field |
| `--asc` | bool | `false` | Sort ascending |

### Examples

```bash
vigolium db ls
vigolium db ls --table findings
vigolium db ls --table scans
vigolium db ls --table findings --severity critical,high
vigolium db ls --host example.com --method POST --status 200
vigolium db ls --list-tables
vigolium db ls --list-columns --table findings
vigolium db ls --tree
vigolium db ls --raw --limit 5
```

---

## db stats

**Usage:** `vigolium db stats [flags]`

Show database statistics including record counts, finding breakdowns, and host summaries.

### stats-specific flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--detailed` | bool | `false` | Show per-host and per-module breakdown |
| `--scan-id` | string | — | Stats for a specific scan session |
| `--host` | string | — | Stats for a specific hostname |

### Examples

```bash
vigolium db stats
vigolium db stats --detailed
vigolium db stats --host example.com
vigolium db stats --watch 10s
```

---

## db export

**Usage:** `vigolium db export [flags]`

Export database records in various formats.

### export-specific flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--format` | `-f` | string | `jsonl` | Export format: jsonl, json, raw, csv, markdown, markdown-table |
| `--output` | `-o` | string | stdout | Output file path |
| `--host` | — | string | — | Filter by hostname |
| `--method` | — | []string | — | Filter by HTTP method |
| `--status` | — | []int | — | Filter by status code |
| `--path` | — | string | — | Filter by URL path |
| `--scan-id` | — | string | — | Filter by scan ID |
| `--severity` | — | string | — | Filter by severity |
| `--from` | — | string | — | Records after date |
| `--to` | — | string | — | Records before date |
| `--limit` | — | int | `0` (unlimited) | Max records to export |
| `--offset` | — | int | `0` | Records to skip |
| `--uuid` | — | string | — | Export single record by UUID |
| `--request-only` | — | bool | `false` | Export only HTTP requests, omitting responses (raw format only) |

### Examples

```bash
vigolium db export -f jsonl -o records.jsonl
vigolium db export -f csv -o records.csv --host example.com
vigolium db export -f markdown -o report.md
vigolium db export -f raw --request-only -o requests.txt
vigolium db export --uuid abc12345
```

---

## db clean

**Usage:** `vigolium db clean [flags]`

Delete database records with filtering. Destructive operations require `--force`.

### clean-specific flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--all` | bool | `false` | Delete all records (requires `--force`) |
| `--host` | string | — | Delete records matching hostname |
| `--scan-id` | string | — | Delete records by scan session |
| `--before` | string | — | Delete records before date (YYYY-MM-DD) |
| `--status` | []int | — | Delete by HTTP status code |
| `--severity` | string | — | Delete findings by severity |
| `--dry-run` | bool | `false` | Show what would be deleted without deleting |
| `--vacuum` | bool | `false` | Reclaim disk space after deletion (SQLite) |
| `--orphans` | bool | `false` | Delete findings with no matching HTTP record |
| `--findings-only` | bool | `false` | Delete findings only, keep HTTP records |

### Special behavior

- `--force` with no filter flags: resets the entire SQLite database (deletes file + recreates)
- `--all` without `--force`: error
- Without `--force`: interactive confirmation prompt

### Examples

```bash
vigolium db clean --scan-id my-scan
vigolium db clean --host old-target.com --force
vigolium db clean --before 2024-01-01 --dry-run
vigolium db clean --all --force
vigolium db clean --orphans
vigolium db clean --findings-only --severity info
vigolium db clean --vacuum
vigolium db clean --force  # reset entire database
```

---

## finding

**Usage:** `vigolium finding [flags]` (aliases: `findings`)

Browse vulnerability findings. Shortcut for `vigolium db ls --table findings`. Accepts all the same flags as `db list`.

### Examples

```bash
vigolium finding
vigolium finding --severity high,critical
vigolium finding --search "sql injection"
vigolium finding --sort severity --asc
vigolium finding --watch 5s
```

---

## export

**Usage:** `vigolium export [flags]`

Top-level export command. Exports database tables and module registry as JSONL or HTML.

### export flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--format` | — | string | `jsonl` | Export format: html, jsonl |
| `--output` | `-o` | string | — | Output file (required for html) |
| `--only` | — | []string | all | Export only these tables (repeatable: http, findings, scans, modules, oast, source-repos, scopes) |
| `--lite` | — | bool | `false` | Export summary fields only, omit raw HTTP data and headers |
| `--search` | — | string | — | Fuzzy search filter |
| `--limit` | — | int | `0` (unlimited) | Max records per table |

### Examples

```bash
vigolium export --format jsonl -o full-export.jsonl
vigolium export --format jsonl --only findings
vigolium export --format jsonl --only findings,http
vigolium export --format html -o report.html
vigolium export --only modules
vigolium export --lite --only http -o urls.jsonl
vigolium export --search "example.com" -o filtered.jsonl
```

---

## module

**Usage:** `vigolium module [flags]` (aliases: `mo`)

Manage scanner modules. Lists active and passive modules with their scan scope, severity, and enabled status.

### Subcommands

| Command | Aliases | Description |
|---------|---------|-------------|
| `module ls [filter]` | `list` | List available modules (optional fuzzy filter) |
| `module enable <search>` | `e` | Enable modules matching search |
| `module disable <search>` | `d` | Disable modules matching search |

### module ls flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--type` | string | `all` | Filter: all, active, passive |
| `--list-enabled` | bool | `false` | Show only enabled modules |
| `--verbose` / `-v` | bool | `false` | Show long description and confirmation criteria |

### module enable/disable flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--id` | bool | `false` | Match exact module ID instead of fuzzy |

### Examples

```bash
vigolium module ls
vigolium module ls xss                 # fuzzy filter
vigolium module ls --type active
vigolium module ls --list-enabled
vigolium module ls -v                  # verbose with descriptions
vigolium module enable xss             # enable all xss modules
vigolium module disable sqli           # disable all sqli modules
vigolium module enable active-xss-reflected --id  # exact ID
vigolium scan -M                       # shortcut to list modules
```

---

## extensions

**Usage:** `vigolium extensions [filter]` (aliases: `ext`)

Manage JavaScript extensions for custom scanning logic.

### Subcommands

| Command | Aliases | Description |
|---------|---------|-------------|
| `ext ls [filter]` | `list` | List loaded extensions |
| `ext docs [function]` | `doc`, `api` | Show API reference |
| `ext preset [name]` | `presets`, `init` | Install example presets |
| `ext eval [code]` | `run`, `exec` | Evaluate JavaScript code |

### ext ls flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--type` | string | `all` | Filter: all, active, passive, pre_hook, post_hook |

### ext docs flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--example` | bool | `false` | Show usage examples for each function |

### ext eval flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--stdin` | bool | `false` | Read JS code from stdin |
| `--ext-file` | string | — | Path to JS file to evaluate |

### Examples

```bash
vigolium ext ls
vigolium ext ls --type active
vigolium ext docs
vigolium ext docs http             # filter API docs by namespace
vigolium ext docs --example        # with code examples
vigolium ext preset                # install all presets
vigolium ext preset my-scanner     # install specific preset
vigolium ext eval 'vigolium.log.info("hello")'
vigolium ext eval --ext-file script.js
echo 'vigolium.utils.md5("hello")' | vigolium ext eval --stdin
```

---

## config

**Usage:** `vigolium config <subcommand>`

Manage configuration settings.

### Subcommands

| Command | Aliases | Description |
|---------|---------|-------------|
| `config ls [filter]` | `list`, `view` | Display current configuration |
| `config set <key> <value>` | — | Set a configuration value |
| `config clean` | — | Clean/reset configuration |

### Examples

```bash
vigolium config ls
vigolium config ls scope           # filter by section
vigolium config ls scanning_pace
vigolium config ls server          # view server config
vigolium config ls --force         # show sensitive values (unredacted)

vigolium config set scanning_strategy.default_strategy deep
vigolium config set scope.origin.mode strict
vigolium config set dynamic_assessment.extensions.enabled true
vigolium config set notify.enabled true
```

Config file location: `~/.vigolium/vigolium-configs.yaml`

---

## scope

**Usage:** `vigolium scope [flags]` (aliases: `sc`)

Manage scan scope rules for filtering traffic.

### Subcommands

| Command | Aliases | Description |
|---------|---------|-------------|
| `scope view [component]` | `ls`, `list` | Display current scope configuration |
| `scope set <key> <value>` | — | Set a scope configuration value |

### Scope Components

host, path, status_code, request_content_type, response_content_type, request_string, response_string

### Examples

```bash
vigolium scope view
vigolium scope view host           # view host scope only
vigolium scope set origin.mode strict
```

---

## source

**Usage:** `vigolium source [flags]` (aliases: `src`)

Manage application source code links for whitebox scanning and SAST.

### Subcommands

| Command | Aliases | Description |
|---------|---------|-------------|
| `source ls` | `list` | List linked source repos |
| `source add` | — | Link source code to a hostname |
| `source rm <id>` | — | Remove a source repo link |
| `source scan <id>` | — | Run third-party security tools |

### source add flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--hostname` | `-H` | string | — | Target hostname (**required**) |
| `--path` | `-p` | string | — | Filesystem path to source root |
| `--git` | `-g` | string | — | Git URL to clone |
| `--name` | `-n` | string | dir basename | Display name |
| `--language` | `-l` | string | — | Primary language |
| `--framework` | `-f` | string | — | Framework (express, django, spring, etc.) |
| `--repo-type` | — | string | auto-detected | Type: git, folder, archive |
| `--scan-uuid` | — | string | — | Link to specific scan UUID |
| `--tag` | — | []string | — | Tags (repeatable) |

Note: `--path` and `--git` are mutually exclusive; one is required.

### Examples

```bash
vigolium source ls
vigolium source add --hostname api.example.com --path ./api-source
vigolium source add --hostname example.com --git https://github.com/org/repo
vigolium source add --hostname api.example.com --path ./src -l go -f gin
vigolium source scan 1
vigolium source rm 2
```

---

## strategy

**Usage:** `vigolium strategy [flags]` (aliases: `st`, `phase`)

Display scanning strategies and their phase configurations.

### Subcommands

| Command | Aliases | Description |
|---------|---------|-------------|
| `strategy ls` | `list` | List available strategies |

### Examples

```bash
vigolium strategy
vigolium strategy ls
vigolium phase              # alias for strategy
```

---

## version

**Usage:** `vigolium version`

Show version, build time, commit, and author information. Supports `--json` for machine-readable output.
