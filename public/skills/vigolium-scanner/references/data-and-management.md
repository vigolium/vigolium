# Data & Management Commands Reference

Complete reference for `db`, `finding`, `module`, `extensions`, `js`, `config`, `scope`, `source`, `session`, `project`, `strategy`, `export`, and `version` commands.

## Table of Contents

- [db](#db)
- [db list / ls](#db-list)
- [db stats](#db-stats)
- [db export](#db-export)
- [db clean](#db-clean)
- [db seed](#db-seed)
- [finding](#finding)
- [finding load](#finding-load)
- [export (top-level)](#export)
- [module](#module)
- [extensions](#extensions)
- [js](#js)
- [config](#config)
- [scope](#scope)
- [source](#source)
- [session](#session)
- [project](#project)
- [strategy](#strategy)
- [version](#version)

---

## db

**Usage:** `vigolium db <subcommand> [flags]`

Manage database records. Parent command for `clean`, `export`, `list` (`ls`), `seed`, and `stats`.

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
| `--host` | string | — | Filter by hostname pattern (wildcard supported) |
| `--method` | []string | — | Filter by HTTP method |
| `--status` | []int | — | Filter by HTTP status code |
| `--path` | string | — | Filter by URL path pattern |
| `--scan-id` | string | — | Filter by scan session ID |
| `--severity` | string | — | Filter findings by severity |
| `--min-risk` | int | `0` | Show only records with risk score at or above this value |
| `--remark` | string | — | Filter records containing this text in remarks |
| `--module-type` | string | — | Filter findings by module type (active, passive, nuclei, secret-scan, agent, source-tools, oast, extension) |
| `--finding-source` | string | — | Filter findings by source (audit, spa, agent, oast, source-tools, extension) |
| `--from` | string | — | Records after date (YYYY-MM-DD or RFC3339) |
| `--to` | string | — | Records before date (YYYY-MM-DD or RFC3339) |
| `--header` | string | — | Search within HTTP header names and values |
| `--body` | string | — | Search in request/response body |

### Sorting flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--sort` | string | `created_at` | Sort field: uuid, created_at, sent_at, method, status_code, response_time |
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
| `--host` | — | string | — | Filter by hostname pattern |
| `--method` | — | []string | — | Filter by HTTP method |
| `--status` | — | []int | — | Filter by status code |
| `--path` | — | string | — | Filter by URL path pattern |
| `--scan-id` | — | string | — | Filter by scan session ID |
| `--severity` | — | string | — | Filter by severity level |
| `--from` | — | string | — | Export records created after this date (YYYY-MM-DD) |
| `--to` | — | string | — | Export records created before this date (YYYY-MM-DD) |
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

## db seed

**Usage:** `vigolium db seed [flags]`

Populate database with sample data for development and testing.

### Examples

```bash
vigolium db seed
```

---

## finding

**Usage:** `vigolium finding [search-term] [flags]` (aliases: `findings`)

Browse vulnerability findings with fuzzy search, filtering, raw display, and column selection.

### Finding-specific filter flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--severity` | — | string | — | Filter by severity (comma-separated: critical,high,medium,low,info) |
| `--scan-id` | — | string | — | Filter by scan session ID |
| `--module-type` | — | string | — | Filter by module type (active, passive, nuclei, secret-scan, agent, source-tools, oast, extension) |
| `--finding-source` | — | string | — | Filter by finding source (audit, spa, agent, oast, source-tools, extension) |
| `--id` | — | int | `0` | Filter by finding ID |

### Display flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--raw` | bool | `false` | Show full raw HTTP request and response for each finding |
| `--burp` | bool | `false` | Display in Burp Suite-style format (colored request/response) |
| `--columns` | []string | — | Columns to show (comma-separated, e.g. ID,SEVERITY,MODULE) |
| `--exclude-columns` | []string | — | Columns to hide (comma-separated) |

### Pagination and sorting flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--limit` | `-n` | int | `100` | Maximum findings to display |
| `--offset` | `-o` | int | `0` | Number of findings to skip (for pagination) |
| `--sort` | — | string | `found_at` | Sort by: found_at, created_at, severity, module, confidence |
| `--asc` | — | bool | `false` | Sort in ascending order |

### Additional filter flags

Also accepts: `--host`, `--method`, `--status`, `--path`, `--from`, `--to`, `--search`, `--header`, `--body`, `--source`.

### Available columns

ID, SEVERITY, CONFIDENCE, MODULE, MODULE_ID, SHORT_DESC, DESCRIPTION, TYPE, SOURCE, MATCHED_AT, FOUND_AT, SCAN_UUID, TAGS

Default columns: ID, SEVERITY, MODULE, SHORT_DESC, TYPE, SOURCE, MATCHED_AT

### Examples

```bash
vigolium finding
vigolium finding --severity high,critical
vigolium finding --search "sql injection"
vigolium finding --module-type active
vigolium finding --finding-source audit
vigolium finding --id 42
vigolium finding --burp
vigolium finding --raw
vigolium finding --columns ID,SEVERITY,MODULE,MATCHED_AT,TAGS
vigolium finding --sort severity --asc
vigolium finding --watch 5s
```

---

## finding load

**Usage:** `vigolium finding load [file] [flags]`

Import findings from a file or stdin.

### Examples

```bash
vigolium finding load findings.jsonl
cat findings.jsonl | vigolium finding load
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
| `--search` | — | string | — | Fuzzy search filter across URLs, paths, hostnames, methods, content types, and sources |
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
| `--tags` | bool | `false` | Show only unique module tags |
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
| `ext docs [function]` | `doc`, `api` | Show API reference |
| `ext eval [code]` | `run`, `exec` | Evaluate JavaScript code with vigolium.* APIs available |
| `ext lint [file]` | — | Validate extension files for syntax errors and unknown API calls |
| `ext ls [filter]` | `list` | List loaded extensions |
| `ext preset [name]` | `presets`, `init` | Install example presets |

### ext ls flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--type` | string | `all` | Filter: all, active, passive, pre_hook, post_hook |

### ext docs flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--example` | bool | `false` | Show usage examples for each function |

### ext lint flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--ext-file` | string | — | Path to extension file to validate |

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

## js

**Usage:** `vigolium js [flags]`

Execute JavaScript code with access to the full `vigolium.*` API surface. Reads from stdin by default, or use `--code` / `--code-file` for inline or file input. TypeScript files (`.ts`) are auto-transpiled.

### Input methods (mutually exclusive, in order of precedence)

1. `--code` — Inline JavaScript code
2. `--code-file` — Path to JavaScript/TypeScript file
3. stdin (default) — Read JS code from piped input

### js flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--code` | string | — | Inline JavaScript code to execute |
| `--code-file` | string | — | Path to JavaScript/TypeScript file (auto-transpiles `.ts`) |
| `--target` | string | — | Set TARGET variable in JS scope (URL string) |
| `--timeout` | duration | `30s` | Execution timeout (e.g., `60s`, `2m`) |
| `--format` | string | `json` | Output format: `json` or `text` |

### Available API

The JS VM provides access to all `vigolium.*` namespaces:

| Namespace | Description |
|-----------|-------------|
| `vigolium.http` | HTTP requests, sessions, batch, replay, sequence, auth testing, GraphQL, caching |
| `vigolium.utils` | Encoding, hashing, diff, similarity, JWT, CSS selectors, multipart, file I/O |
| `vigolium.parse` | URL, HTTP request/response, HTML, headers, cookies, query, JSON, form parsing |
| `vigolium.scan` | Module listing, scope, finding creation, scan control |
| `vigolium.db` | HTTP record and finding queries, annotations, comparison |
| `vigolium.ingest` | URL, curl, raw HTTP, OpenAPI, Postman ingestion |
| `vigolium.source` | Source code file listing, reading, searching |
| `vigolium.agent` | AI-augmented analysis (ask, chat, complete, generatePayloads, analyzeResponse, confirmFinding) |
| `vigolium.oast` | Out-of-band testing (enabled, payload, poll) |
| `vigolium.log` | Logging (info, warn, error, debug) |
| `vigolium.config` | Read-only config variables |
| `vigolium.payloads(type)` | Built-in payload wordlists (xss, sqli, ssti, ssrf, lfi, etc.) |

### Return value

- Returns `undefined`/`null` → no output
- Otherwise → JSON-stringified return value on stdout
- With `--format text` → JSON strings are unquoted

### Examples

```bash
# Inline code
vigolium js --code 'vigolium.http.get("https://example.com/api/health")'

# From a file
vigolium js --code-file scanner-script.js

# TypeScript auto-transpilation
vigolium js --code-file scanner.ts

# From stdin (ideal for agent/pipe workflows)
echo 'vigolium.utils.md5("password123")' | vigolium js

# With target context (accessible as TARGET variable)
vigolium js --target https://example.com --code 'vigolium.http.get(TARGET + "/api/users")'

# Custom timeout and text output
vigolium js --timeout 60s --format text --code 'vigolium.utils.sha256("hello")'

# Query database records
vigolium js --code 'JSON.stringify(vigolium.db.records.query({ hostname: "example.com", limit: 5 }))'

# Ingest and scan
vigolium js --code 'vigolium.ingest.url("https://example.com/api/users"); vigolium.scan.startNewScan({ targets: ["https://example.com"] })'

# Use AI to generate payloads
vigolium js --code 'JSON.stringify(vigolium.agent.generatePayloads({ type: "xss", context: "HTML attribute", count: 5 }))'
```

### Differences from `vigolium ext eval`

| Feature | `vigolium js` | `vigolium ext eval` |
|---------|---------------|---------------------|
| Input methods | `--code`, `--code-file`, stdin | positional arg, `--ext-file`, `--stdin` |
| Target context | `--target` sets `TARGET` variable | Not available |
| Timeout | Configurable via `--timeout` | Not configurable |
| Output format | `--format json\|text` | Direct output |
| Use case | General scripting, automation | Quick extension testing |

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
vigolium config set audit.extensions.enabled true
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

## session

**Usage:** `vigolium session <subcommand> [flags]`

Manage session authentication configurations and utilities.

### Subcommands

| Command | Aliases | Description |
|---------|---------|-------------|
| `session lint` | — | Validate session auth config files for errors and warnings |
| `session list` | `ls` | List session authentication configs |
| `session load` | — | Load session auth configs from a file or stdin into the database |
| `session totp` | — | Generate a TOTP code from a base32 secret |

### Examples

```bash
vigolium session list
vigolium session lint auth-config.yaml
vigolium session load auth-config.yaml
vigolium session totp --secret JBSWY3DPEHPK3PXP
```

---

## project

**Usage:** `vigolium project <subcommand> [flags]`

Manage projects for multi-tenancy scan data scoping.

### Subcommands

| Command | Aliases | Description |
|---------|---------|-------------|
| `project config` | — | View or update project configuration |
| `project create` | — | Create a new project |
| `project list` | `ls` | List all projects |
| `project use` | — | Switch to a project |

### Examples

```bash
vigolium project list
vigolium project create --name my-project
vigolium project use my-project
vigolium project config
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
