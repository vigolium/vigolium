# Complete Flag Index

Alphabetical index of all vigolium CLI flags across all commands.

## Table of Contents

- [Global Flags (all commands)](#global-flags)
- [Scan Flags](#scan-flags)
- [Scan-URL Flags](#scan-url-flags)
- [Scan-Request Flags](#scan-request-flags)
- [Server Flags](#server-flags)
- [Ingest Flags](#ingest-flags)
- [Agent Flags](#agent-flags)
- [Agent Autopilot Flags](#agent-autopilot-flags)
- [Agent Pipeline Flags](#agent-pipeline-flags)
- [Agent Swarm Flags](#agent-swarm-flags)
- [Traffic Flags](#traffic-flags)
- [DB Flags](#db-flags)
- [Export Flags](#export-flags)
- [Module Flags](#module-flags)
- [Extensions Flags](#extensions-flags)
- [JS Flags](#js-flags)
- [Source Add Flags](#source-add-flags)

---

## Global Flags

Persistent flags available on every command.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--concurrency` | `-c` | int | `50` | Concurrent scan workers |
| `--config` | — | string | `~/.vigolium/vigolium-configs.yaml` | Config file path |
| `--db` | — | string | `~/.vigolium/database-vgnm.sqlite` | SQLite database path |
| `--debug` | — | bool | `false` | Dump raw HTTP request and response traffic |
| `--disable-fetch-response` | — | bool | `false` | Store requests without fetching responses during ingestion |
| `--dump-traffic` | — | bool | `false` | Print every HTTP pair to stderr |
| `--ext` | — | []string | — | Load JavaScript extension script (repeatable) |
| `--ext-dir` | — | string | — | Override extension scripts directory |
| `--force` | `-F` | bool | `false` | Skip confirmation prompts |
| `--format` | — | string | `console` | Output format: console, jsonl, html |
| `--full-example` | — | bool | `false` | Show full example commands |
| `--heuristics-check` | — | string | `basic` | Pre-scan heuristics level: none, basic, advanced |
| `--input` | `-i` | string | `-` | Input file path or spec (use - for stdin) |
| `--input-mode` | `-I` | string | `urls` | Input format: urls, openapi, swagger, burp, curl, nuclei, har |
| `--input-read-timeout` | — | duration | `3m` | Timeout for reading input |
| `--json` | `-j` | bool | `false` | Format output as JSONL (one JSON object per line) |
| `--ci-output-format` | — | bool | `false` | CI-friendly output: JSONL findings only, no color, no banners |
| `--list-input-mode` | — | bool | `false` | List supported input modes |
| `--list-modules` | `-M` | bool | `false` | List scanner modules |
| `--log-file` | — | string | — | Write logs to file (JSON format) |
| `--max-host-error` | — | int | `30` | Skip host after N consecutive errors |
| `--max-per-host` | — | int | `2` | Max concurrent requests per host |
| `--max-findings-per-module` | — | int | `15` | Stop reporting after N findings per module (0 = unlimited) |
| `--module-tag` | — | []string | — | Filter modules by tag (OR condition, repeatable) |
| `--modules` | `-m` | []string | `all` | Scanner modules to enable |
| `--no-clustering` | — | bool | `false` | Disable deduplication of identical concurrent HTTP requests |
| `--only` | — | string | — | Run only this phase |
| `--project-id` | — | string | — | Project UUID to scope all operations |
| `--project-name` | — | string | — | Project name to scope all operations (must match exactly one) |
| `--proxy` | — | string | — | Route all requests through this proxy (HTTP/SOCKS5 URL) |
| `--rate-limit` | `-r` | int | `100` | Maximum HTTP requests per second |
| `--scan-id` | — | string | — | Scan session label |
| `--scan-on-receive` | `-S` | bool | `false` | Continuously scan new HTTP records as they arrive in the database |
| `--scanning-max-duration` | — | duration | `0` | Maximum total scan duration (overrides config, e.g. 1h, 30m) |
| `--scanning-profile` | — | string | — | Scanning profile name or YAML file path |
| `--scope-origin` | — | string | — | Host scope strictness: all, relaxed, balanced, strict |
| `--silent` | — | bool | `false` | Suppress output except findings |
| `--skip` | — | []string | — | Skip phases |
| `--skip-heuristics` | — | bool | `false` | Disable pre-scan heuristics (equivalent to --heuristics-check=none) |
| `--source` | — | string | — | Source code path |
| `--source-url` | — | string | — | Git URL to clone for source-aware scanning |
| `--spec-default` | — | string | `1` | Fallback value for required OpenAPI parameters that lack examples |
| `--spec-header` | — | []string | — | Add HTTP header to OpenAPI-generated requests (repeatable) |
| `--spec-url` | — | bool | `false` | Use base URLs from the OpenAPI spec's servers field |
| `--spec-var` | — | []string | — | Set OpenAPI parameter value as key=value (repeatable) |
| `--strategy` | — | string | — | Scanning strategy preset |
| `--target` | `-t` | []string | — | Target URL (repeatable) |
| `--target-file` | `-T` | string | — | File containing target URLs (one per line) |
| `--timeout` | — | duration | `15s` | HTTP request timeout |
| `--verbose` | `-v` | bool | `false` | Verbose logging |
| `--watch` | — | string | — | Re-run on interval (e.g. 10s, 1m, 5m) |
| `--width` | — | int | `70` | Max column width for tables |

---

## Scan Flags

Flags specific to `vigolium scan` and `vigolium run`.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--advanced-options` | `-a` | map | — | Module-specific options as key=value (e.g. -a xss.dom=true) |
| `--browser-engine` | `-E` | string | `chromium` | Browser engine |
| `--browsers` | `-b` | int | `1` | Number of parallel browser instances for spidering |
| `--discover` | — | bool | `false` | Enable content discovery phase before scanning |
| `--discover-max-time` | — | duration | `1h` | Discovery timeout per target |
| `--external-harvest` | — | bool | `false` | Enable external intelligence gathering phase (Wayback, CT logs, etc.) |
| `--header` | `-H` | []string | — | Add custom HTTP header (repeatable, e.g. -H 'Auth: Bearer token') |
| `--headless` | — | bool | `true` | Headless browser mode |
| `--include-response` | — | bool | `false` | Include response in output |
| `--no-cdp` | — | bool | `false` | Disable Chrome DevTools Protocol event listener detection |
| `--no-forms` | — | bool | `false` | Disable automatic form detection and filling during spidering |
| `--oast-url` | — | string | — | Fixed out-of-band callback URL (overrides auto-generated interactsh URL) |
| `--output` | `-o` | string | — | Output file path |
| `--sast-adhoc` | — | string | — | Ad-hoc SAST scan: local path or git URL (auto-detected) |
| `--required-only` | — | bool | `false` | Parse only required fields from input format (ignore optional) |
| `--retries` | — | int | `1` | Retry attempts |
| `--rule` | — | string | — | SAST rule filter |
| `--skip-format-validation` | — | bool | `false` | Skip format validation |
| `--spa-exclude-tags` | — | []string | — | Nuclei exclude tags |
| `--spa-severities` | — | []string | — | Nuclei severity filter |
| `--spa-tags` | — | []string | — | Nuclei include tags |
| `--spa-templates-dir` | — | string | — | Custom templates dir |
| `--spider` | — | bool | `false` | Enable browser-based spidering phase before scanning |
| `--spider-max-time` | — | duration | `30m` | Spidering timeout |
| `--stats` | — | bool | `false` | Show live progress stats during scanning |
| `--stream` | — | bool | `false` | Process targets as a stream without buffering or deduplication |

---

## Scan-URL Flags

Flags specific to `vigolium scan-url`.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--body` | — | string | — | Request body |
| `--discover` | — | bool | `false` | Run content discovery |
| `--external-harvest` | — | bool | `false` | Run external harvest |
| `--header` | `-H` | []string | — | Custom header |
| `--method` | — | string | `GET` | HTTP method |
| `--no-insertion-points` | — | bool | `false` | Skip insertion points |
| `--no-passive` | — | bool | `false` | Skip passive modules |
| `--spa` | — | bool | `false` | Run SPA assessment |
| `--spider` | — | bool | `false` | Run spidering |

---

## Scan-Request Flags

Flags specific to `vigolium scan-request`.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--discover` | — | bool | `false` | Run content discovery |
| `--external-harvest` | — | bool | `false` | Run external harvest |
| `--input` | `-i` | string | `-` | Input file or stdin |
| `--no-insertion-points` | — | bool | `false` | Skip insertion points |
| `--no-passive` | — | bool | `false` | Skip passive modules |
| `--spa` | — | bool | `false` | Run SPA assessment |
| `--spider` | — | bool | `false` | Run spidering |
| `--target` | — | string | — | Override target URL |

---

## Server Flags

Flags specific to `vigolium server`.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--alternative-ingest-key` | — | []string | — | Additional API key for ingestion endpoints (repeatable) |
| `--catchup-threads` | — | int | `4` | Workers for background scanning of unscanned records |
| `--disable-catchup` | — | bool | `false` | Disable automatic background scanning of unscanned records |
| `--disable-warm-session` | — | bool | `false` | Disable agent subprocess warm session pooling |
| `--host` | — | string | `0.0.0.0` | Bind address for the API server |
| `--ingest-proxy-port` | — | int | `0` | Proxy port (0=disabled) |
| `--mem-buffer` | — | int | `10000` | In-memory queue capacity before spilling to disk |
| `--no-auth` | `-A` | bool | `false` | Disable authentication |
| `--output` | `-o` | string | — | Findings output file |
| `--service-port` | — | int | `9002` | Port for the REST API server |

---

## Ingest Flags

Flags specific to `vigolium ingest`.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--server` | `-s` | string | — | Remote server URL |

---

## Agent Flags

Flags specific to `vigolium agent`.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--agent` | string | from config | Agent backend |
| `--agent-timeout` | duration | `5m` | Maximum time for agent execution (0 = no limit) |
| `--append` | string | — | Append extra text to the rendered prompt |
| `--dry-run` | bool | `false` | Print the rendered prompt without executing |
| `--files` | []string | — | Specific files |
| `--list-agents` | bool | `false` | List agent backends |
| `--list-templates` | bool | `false` | List templates |
| `--output` | string | — | Output file |
| `--prompt-file` | string | — | Prompt template file |
| `--prompt-template` | string | — | Prompt template ID |
| `--source` | string | — | Path to application source code |

Flags specific to `vigolium agent query`.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--agent` | — | string | from config | Agent backend |
| `--agent-timeout` | — | duration | `5m` | Maximum time for agent execution (0 = no limit) |
| `--output` | — | string | — | Output file |
| `--prompt` | `-p` | string | — | Prompt text to send to the agent |
| `--source` | — | string | — | Path to application source code |
| `--stdin` | — | bool | `false` | Read from stdin |

---

## Agent Autopilot Flags

Flags specific to `vigolium agent autopilot`.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--target` | `-t` | string | — | Target URL (required) |
| `--agent` | — | string | from config | Agent backend |
| `--source` | — | string | — | Path to application source code |
| `--files` | — | []string | — | Specific files to include |
| `--focus` | — | string | — | Focus area hint |
| `--system-prompt` | — | string | — | Custom system prompt file |
| `--timeout` | — | duration | `30m` | Maximum duration for the autopilot session |
| `--max-commands` | — | int | `100` | Max CLI commands to execute |
| `--dry-run` | — | bool | `false` | Preview system prompt |

---

## Agent Pipeline Flags

Flags specific to `vigolium agent pipeline`.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--target` | `-t` | string | — | Target URL (required) |
| `--agent` | — | string | from config | Agent backend |
| `--source` | — | string | — | Path to application source code (enables Phase 0) |
| `--files` | — | []string | — | Specific files to include |
| `--focus` | — | string | — | Focus area hint for planning |
| `--timeout` | — | duration | `1h` | Maximum total pipeline duration |
| `--max-rescan-rounds` | — | int | `2` | Max triage→rescan iterations |
| `--skip-phase` | — | []string | — | Skip phases (source-analysis, discover, plan, scan, triage, rescan, report) |
| `--start-from` | — | string | — | Resume from a specific phase |
| `--profile` | — | string | — | Scanning profile for scan phases |
| `--dry-run` | — | bool | `false` | Preview agent prompts |

---

## Agent Swarm Flags

Flags specific to `vigolium agent swarm`.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--target` | `-t` | string | — | Target URL (required when `--source` is used without other inputs) |
| `--input` | — | string | — | Raw input (curl, raw HTTP, Burp XML, URL). Use `-` for stdin |
| `--record-uuid` | — | string | — | HTTP record UUID from database |
| `--source` | — | string | — | Path to application source code for route discovery |
| `--files` | — | []string | — | Specific source files to include (relative to `--source`) |
| `--vuln-type` | — | string | — | Vulnerability type focus (e.g., sqli, xss, ssrf, auth, idor) |
| `--modules` | `-m` | []string | — | Explicit module names to include |
| `--max-iterations` | — | int | `3` | Maximum triage-rescan iterations |
| `--agent` | — | string | from config | Agent backend |
| `--agent-acp-cmd` | — | string | — | Custom ACP agent command override (overrides `--agent`) |
| `--timeout` | — | duration | `15m` | Maximum swarm duration |
| `--profile` | — | string | — | Scanning profile |
| `--only` | — | string | — | Run only this scanning phase |
| `--skip` | — | []string | — | Skip specific scanning phases |
| `--dry-run` | — | bool | `false` | Render prompts without executing |
| `--show-prompt` | — | bool | `false` | Print rendered prompts to stderr before executing |
| `--source-analysis-only` | — | bool | `false` | Run only source analysis phase and exit (requires `--source`) |
| `--instruction` | — | string | — | Custom instruction to guide the agent |
| `--instruction-file` | — | string | — | Path to file containing custom instructions |

---

## Finding Flags

Flags specific to `vigolium finding` (aliases: `findings`).

### Finding filter flags (persistent)

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--host` | — | string | — | Filter by hostname pattern |
| `--method` | — | []string | — | Filter by HTTP method (repeatable) |
| `--status` | — | []int | — | Filter by HTTP status code (repeatable) |
| `--path` | — | string | — | Filter by URL path pattern |
| `--from` | — | string | — | Show findings after date |
| `--to` | — | string | — | Show findings before date |
| `--search` | — | string | — | Search across descriptions, module IDs, and matched_at |
| `--header` | — | string | — | Search within HTTP header names and values |
| `--body` | — | string | — | Search within HTTP request/response body content |
| `--source` | — | string | — | Filter by record source |
| `--sort` | — | string | `found_at` | Sort by: found_at, created_at, severity, module, confidence |
| `--asc` | — | bool | `false` | Sort ascending |
| `--limit` | `-n` | int | `100` | Maximum findings to display |
| `--offset` | `-o` | int | `0` | Number of findings to skip |
| `--severity` | — | string | — | Filter by severity (comma-separated: critical,high,medium,low,info) |
| `--scan-id` | — | string | — | Filter by scan session ID |
| `--module-type` | — | string | — | Filter by module type (active, passive, nuclei, secret-scan, agent, source-tools, oast, extension) |
| `--finding-source` | — | string | — | Filter by finding source (audit, spa, agent, oast, source-tools, extension) |
| `--id` | — | int | `0` | Filter by finding ID |

### Finding display flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--raw` | bool | `false` | Show full raw HTTP request and response for each finding |
| `--burp` | bool | `false` | Display in Burp Suite-style format (colored request/response) |
| `--columns` | []string | — | Columns to show (comma-separated, e.g. ID,SEVERITY,MODULE) |
| `--exclude-columns` | []string | — | Columns to hide (comma-separated) |

### Finding available columns

ID, SEVERITY, CONFIDENCE, MODULE, MODULE_ID, SHORT_DESC, DESCRIPTION, TYPE, SOURCE, MATCHED_AT, FOUND_AT, SCAN_UUID, TAGS

Default columns: ID, SEVERITY, MODULE, SHORT_DESC, TYPE, SOURCE, MATCHED_AT

---

## Traffic Flags

Filter flags (shared with traffic replay via PersistentFlags).

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--asc` | — | bool | `false` | Sort in ascending order (default: descending) |
| `--body` | — | string | — | Search within HTTP request/response body content |
| `--from` | — | string | — | Records after date |
| `--header` | — | string | — | Search within HTTP header names and values |
| `--host` | — | string | — | Filter by hostname |
| `--limit` | `-n` | int | `100` | Max records |
| `--method` | — | []string | — | Filter by HTTP method (repeatable) |
| `--offset` | `-o` | int | `0` | Number of records to skip (for pagination) |
| `--path` | — | string | — | Filter by path |
| `--search` | — | string | — | Fuzzy search across URLs, paths, and hostnames |
| `--sort` | — | string | `created_at` | Sort field |
| `--source` | — | string | — | Filter by source |
| `--status` | — | []int | — | Filter by HTTP status code (repeatable) |
| `--to` | — | string | — | Records before date |

Display-only flags.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--burp` | bool | `false` | Burp-style format |
| `--columns` | []string | — | Columns to show (comma-separated, e.g. HOST,METHOD,PATH,STATUS) |
| `--exclude-columns` | []string | — | Columns to hide (comma-separated) |
| `--raw` | bool | `false` | Raw HTTP output |
| `--tree` | bool | `false` | Display as host/path hierarchy tree |

Traffic replay flag.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--in-replace` | bool | `false` | Replace stored response |

---

## DB Flags

Shared across db subcommands.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--table` | string | — | Table name |
| `--search` | string | — | Quick search |

DB list flags.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--tree` | — | bool | `false` | Hierarchical tree format |
| `--raw` | — | bool | `false` | Full raw HTTP request and response |
| `--list-tables` | — | bool | `false` | List all database table names |
| `--list-columns` | — | bool | `false` | List column names for the current table |
| `--limit` | `-n` | int | `100` | Max records |
| `--offset` | `-o` | int | `0` | Records to skip |
| `--columns` | — | []string | — | Columns to include |
| `--exclude-columns` | — | []string | — | Columns to exclude |
| `--host` | — | string | — | Filter by hostname |
| `--method` | — | []string | — | Filter by HTTP method |
| `--status` | — | []int | — | Filter by HTTP status code |
| `--path` | — | string | — | Filter by URL path |
| `--scan-id` | — | string | — | Filter by scan session ID |
| `--severity` | — | string | — | Filter findings by severity |
| `--min-risk` | — | int | `0` | Show only records with risk score at or above this value |
| `--remark` | — | string | — | Filter records containing this text in remarks |
| `--module-type` | — | string | — | Filter findings by module type (active, passive, nuclei, secret-scan, agent, source-tools, oast, extension) |
| `--finding-source` | — | string | — | Filter findings by source (audit, spa, agent, oast, source-tools, extension) |
| `--from` | — | string | — | Records after date |
| `--to` | — | string | — | Records before date |
| `--header` | — | string | — | Search within HTTP headers |
| `--body` | — | string | — | Search within request/response body |
| `--sort` | — | string | `created_at` | Sort field |
| `--asc` | — | bool | `false` | Sort ascending |

DB clean flags.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--all` | bool | `false` | Delete all records (requires --force) |
| `--before` | string | — | Before date |
| `--dry-run` | bool | `false` | Show what would be deleted without deleting |
| `--findings-only` | bool | `false` | Delete findings only, keep HTTP records |
| `--host` | string | — | Filter hostname |
| `--orphans` | bool | `false` | Delete findings with no matching HTTP record |
| `--scan-id` | string | — | Filter by scan ID |
| `--severity` | string | — | Filter severity |
| `--status` | []int | — | Filter status codes |
| `--vacuum` | bool | `false` | Reclaim disk space |

DB stats flags.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--detailed` | bool | `false` | Show per-host and per-module breakdown |
| `--host` | string | — | Filter hostname |
| `--scan-id` | string | — | Filter scan ID |

---

## Export Flags

Top-level `vigolium export` flags.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--format` | — | string | `jsonl` | Format: html, jsonl |
| `--limit` | — | int | `0` | Max records per table |
| `--lite` | — | bool | `false` | Export summary fields only, omit raw HTTP data and headers |
| `--only` | — | []string | all | Export only these tables (repeatable: http, findings, scans, modules, oast, source-repos, scopes) |
| `--output` | `-o` | string | — | Output file |
| `--search` | — | string | — | Fuzzy search filter |

---

## Module Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--id` | bool | `false` | Exact ID match (enable/disable) |
| `--list-enabled` | bool | `false` | Show enabled only (ls) |
| `--type` | string | `all` | Filter: all, active, passive (ls) |

---

## Extensions Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--example` | bool | `false` | Show code examples (docs) |
| `--ext-file` | string | — | JS file to evaluate (eval) |
| `--stdin` | bool | `false` | Read from stdin (eval) |
| `--type` | string | `all` | Filter type (ls) |

---

## JS Flags

Flags specific to `vigolium js`.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--code` | string | — | Inline JavaScript code to execute |
| `--code-file` | string | — | Path to JavaScript/TypeScript file (auto-transpiles `.ts`) |
| `--target` | string | — | Set TARGET variable in JS scope (URL string) |
| `--timeout` | duration | `30s` | Execution timeout (e.g., `60s`, `2m`) |
| `--format` | string | `json` | Output format: `json` or `text` |

---

## Source Add Flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--framework` | `-f` | string | — | Framework |
| `--git` | `-g` | string | — | Git URL to clone |
| `--hostname` | `-H` | string | — | Target hostname (required) |
| `--language` | `-l` | string | — | Primary language |
| `--name` | `-n` | string | dir basename | Display name |
| `--path` | `-p` | string | — | Source path |
| `--repo-type` | — | string | auto | Type: git, folder, archive |
| `--scan-uuid` | — | string | — | Link to scan UUID |
| `--tag` | — | []string | — | Tags (repeatable) |
