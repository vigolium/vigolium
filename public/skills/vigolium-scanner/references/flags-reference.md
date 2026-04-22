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
- [Agent Query Flags](#agent-query-flags)
- [Agent Autopilot Flags](#agent-autopilot-flags)
- [Agent Swarm Flags](#agent-swarm-flags)
- [Agent Archon Flags](#agent-archon-flags)
- [Agent Session Flags](#agent-session-flags)
- [Log Flags](#log-flags)
- [Import Flags](#import-flags)
- [Finding Flags](#finding-flags)
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
| `--max-per-host` | — | int | `30` | Max concurrent requests per host |
| `--max-findings-per-module` | — | int | `10` | Stop reporting after N findings per module (0 = unlimited) |
| `--intensity` | — | string | — | Scan intensity preset: `quick`, `balanced`, or `deep` (maps to scanning profile + strategy) |
| `--native-scan-on-receive` | — | bool | `false` | Run the full native scan pipeline continuously on received records |
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
| `--advanced-options` | `-a` | stringToString | — | Module-specific options as key=value (e.g. -a xss.dom=true) |
| `--auth-config` | — | string | — | Path to auth-config file with session definitions (YAML or JSON) |
| `--browser-engine` | `-E` | string | `chromium` | Browser engine |
| `--browsers` | `-b` | int | `1` | Number of parallel browser instances for spidering |
| `--discover` | — | bool | `false` | Enable content discovery phase before scanning |
| `--discover-max-time` | — | duration | `1h` | Discovery timeout per target |
| `--external-harvest` | — | bool | `false` | Enable external intelligence gathering phase (Wayback, CT logs, etc.) |
| `--header` | `-H` | []string | — | Add custom HTTP header (repeatable, e.g. -H 'Auth: Bearer token') |
| `--headless` | — | bool | `true` | Headless browser mode |
| `--include-response` | — | bool | `false` | Include full HTTP response body in output |
| `--known-issue-scan-exclude-tags` | — | []string | — | Nuclei template tags to exclude (comma-separated) |
| `--known-issue-scan-severities` | — | []string | — | Filter Nuclei templates by severity (critical,high,medium,low,info) |
| `--known-issue-scan-tags` | — | []string | — | Nuclei template tags to include (comma-separated) |
| `--known-issue-scan-templates-dir` | — | string | — | Custom Nuclei templates directory |
| `--no-cdp` | — | bool | `false` | Disable Chrome DevTools Protocol event listener detection |
| `--no-forms` | — | bool | `false` | Disable automatic form detection and filling during spidering |
| `--oast-url` | — | string | — | Fixed out-of-band callback URL (overrides auto-generated interactsh URL) |
| `--output` | `-o` | string | — | Output file path |
| `--required-only` | — | bool | `false` | Parse only required fields from input format (ignore optional) |
| `--retries` | — | int | `1` | Number of retry attempts for failed requests |
| `--rule` | — | string | — | Filter SAST rules by fuzzy name match (e.g. 'gin', 'route') |
| `--sast-adhoc` | — | string | — | Local path or git URL for ad-hoc SAST scan (auto-detected, results not saved to database) |
| `--session` | — | []string | — | Inline session for IDOR/BOLA testing (repeatable, format: name:Header:value) |
| `--session-file` | — | []string | — | Path to individual session file (YAML or JSON, repeatable) |
| `--skip-format-validation` | — | bool | `false` | Skip validation of input file format |
| `--spider` | — | bool | `false` | Enable browser-based spidering phase before scanning |
| `--spider-max-time` | — | duration | `30m` | Spidering timeout |
| `--stateless` | — | bool | `false` | Use a temporary database, export results to --output, then discard |
| `--stats` | — | bool | `false` | Show live progress stats during scanning |
| `--stream` | — | bool | `false` | Process targets as a stream without buffering or deduplication |
| `--upload-results` | — | bool | `false` | Upload scan results to cloud storage after completion (requires storage config) |
| `--fuzz-wordlist` | — | string | — | Custom fuzz wordlist path (enables fuzzing during discovery) |
| `--no-prefix-breaker` | — | bool | `false` | Disable per-prefix circuit breaker that stops trap-directory recursion |

---

## Scan-URL Flags

Flags specific to `vigolium scan-url`.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--body` | — | string | — | Request body |
| `--discover` | — | bool | `false` | Run content discovery before scanning |
| `--external-harvest` | — | bool | `false` | Run external intelligence harvesting before scanning |
| `--header` | `-H` | []string | — | Custom header (repeatable) |
| `--known-issue-scan` | — | bool | `false` | Run known issue scan (Nuclei/Kingfisher) |
| `--method` | — | string | `GET` | HTTP method |
| `--no-insertion-points` | — | bool | `false` | Skip insertion point testing |
| `--no-passive` | — | bool | `false` | Skip passive modules |
| `--spider` | — | bool | `false` | Run browser-based spidering before scanning |

---

## Scan-Request Flags

Flags specific to `vigolium scan-request`.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--discover` | — | bool | `false` | Run content discovery before scanning |
| `--external-harvest` | — | bool | `false` | Run external intelligence harvesting before scanning |
| `--input` | `-i` | string | `-` | Input file or - for stdin |
| `--known-issue-scan` | — | bool | `false` | Run known issue scan |
| `--no-insertion-points` | — | bool | `false` | Skip insertion point testing |
| `--no-passive` | — | bool | `false` | Skip passive modules |
| `--spider` | — | bool | `false` | Run browser-based spidering before scanning |
| `--target` | — | string | — | Override target URL (scheme://host) |

---

## Server Flags

Flags specific to `vigolium server`.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--alternative-ingest-key` | — | []string | — | Additional API key for ingestion endpoints (repeatable) |
| `--catchup-threads` | — | int | `4` | Workers for background scanning of unscanned records |
| `--disable-catchup` | — | bool | `false` | Disable automatic background scanning of unscanned records |
| `--disable-warm-session` | — | bool | `false` | Disable agent warm session pooling |
| `--host` | — | string | `0.0.0.0` | Bind address for the API server |
| `--ingest-proxy-port` | — | int | `0` | Transparent HTTP proxy port for recording traffic (0 = disabled) |
| `--mem-buffer` | — | int | `10000` | In-memory queue capacity before spilling to disk |
| `--no-agent` | — | bool | `false` | Disable all agent endpoints and warm session pooling |
| `--no-auth` | `-A` | bool | `false` | Run server without API key authentication |
| `--output` | `-o` | string | — | Write findings to specified output file |
| `--service-port` | — | int | `9002` | Port for the REST API server |
| `--view-only` | — | bool | `false` | Run server in read-only mode (disables scanning, ingestion, agent, and all write endpoints) |

---

## Ingest Flags

Flags specific to `vigolium ingest`.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--server` | `-s` | string | — | Remote server URL |

---

## Agent Flags

Flags specific to `vigolium agent` (parent command supports `--list-templates` and `--list-agents` only — all execution requires a subcommand).

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--list-agents` | bool | `false` | List agent backends |
| `--list-templates` | bool | `false` | List templates |

---

## Agent Query Flags

Flags specific to `vigolium agent query`.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--agent` | — | string | from config | Agent backend to use |
| `--agent-timeout` | — | duration | `5m` | Maximum time for agent execution |
| `--append` | — | string | — | Append extra text to the rendered prompt |
| `--dry-run` | — | bool | `false` | Print the rendered prompt without executing |
| `--files` | — | []string | — | Specific files to include (relative to --source) |
| `--instruction` | — | string | — | Custom instruction to guide the agent |
| `--instruction-file` | — | string | — | Path to a file containing custom instructions |
| `--output` | — | string | — | Write agent output to this file |
| `--prompt` | `-p` | string | — | Prompt text to send to the agent |
| `--prompt-file` | — | string | — | Path to a prompt template file |
| `--prompt-template` | — | string | — | Prompt template ID |
| `--show-prompt` | — | bool | `false` | Print rendered prompt to stderr before executing |
| `--source` | — | string | — | Path to source code repository |
| `--source-label` | — | string | — | Label for records ingested from agent output |
| `--stdin` | — | bool | `false` | Read prompt from stdin |

---

## Agent Autopilot Flags

Flags specific to `vigolium agent autopilot`. Also accepts a positional natural-language prompt.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--agent` | — | string | from config | Agent backend to use |
| `--archon-mode` | — | string | `lite` | Archon audit mode: `lite`, `balanced`, `deep`, `mock` |
| `--auth-required` | — | bool | `false` | Require auth/session preparation before the autonomous operator starts |
| `--browser` | — | bool | `false` | Enable agent-browser for browser-based interactions |
| `--browser-start-url` | — | string | — | Explicit browser/login start URL for auth preflight |
| `--credentials` | — | string | — | Credentials for auth preflight (e.g. `admin/admin123, compare user/user123`) |
| `--diff` | — | string | — | Focus on changed code: PR URL, git ref range, or `HEAD~N` |
| `--dry-run` | — | bool | `false` | Render the system prompt without launching the agent |
| `--files` | — | []string | — | Specific files to include (relative to `--source`) |
| `--focus` | — | string | — | Focus area hint |
| `--focus-routes` | — | []string | — | Protected or browser-focused routes to prioritize after auth |
| `--input` | — | string | — | Raw input (curl, raw HTTP, Burp XML, URL) |
| `--instruction` | — | string | — | Custom instruction to guide the agent |
| `--instruction-file` | — | string | — | Path to a file containing custom instructions |
| `--intensity` | — | string | `balanced` | Scan intensity preset: `quick`, `balanced`, or `deep` |
| `--last-commits` | — | int | `0` | Focus on last N commits (shorthand for `--diff HEAD~N`) |
| `--max-commands` | — | int | `100` | Maximum number of CLI commands the agent can execute |
| `--mcp-enabled` | — | bool | `false` | Enable MCP server passthrough |
| `--mcp-server` | — | []string | — | MCP servers to attach (`name=command,arg1,arg2` or `name=http://url`) |
| `--no-archon` | — | bool | `false` | Disable automatic archon-audit (enabled by default when `--source` is set) |
| `--requires-browser` | — | bool | `false` | Require browser-assisted auth/setup instead of HTTP-only preflight |
| `--resume` | — | string | — | Resume from a previous session directory |
| `--show-prompt` | — | bool | `false` | Print rendered prompt to stderr before executing |
| `--source` | — | string | — | Path to application source code |
| `--target` | `-t` | string | — | Target URL |
| `--timeout` | — | duration | `6h` | Maximum duration for the autopilot session |
| `--upload-results` | — | bool | `false` | Upload scan results to cloud storage after completion |

---

## Agent Swarm Flags

Flags specific to `vigolium agent swarm`. Also accepts a positional natural-language prompt.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--agent` | — | string | from config | Agent backend to use |
| `--archon` | — | string | — | Run background archon-audit in parallel: `lite` (default if bare), `scan`, `deep`. Requires `--source` |
| `--auth` | — | bool | `false` | Run browser-based auth phase before discovery (requires `--browser`) |
| `--batch-concurrency` | — | int | `0` | Max parallel master agent batches (0 = auto) |
| `--browser` | — | bool | `false` | Enable agent-browser for browser-based auth capture |
| `--code-audit` | — | bool | auto | Enable AI security code audit phase (on by default when `--source` is set) |
| `--credentials` | — | string | — | Credentials for browser auth phase |
| `--custom-agent` | — | []string | — | Custom agents the swarm can invoke (repeatable) |
| `--diff` | — | string | — | Focus on changed code: PR URL, git ref range, or `HEAD~N` |
| `--discover` | — | bool | `false` | Run discovery+spidering before master agent planning |
| `--dry-run` | — | bool | `false` | Render prompts without executing |
| `--files` | — | []string | — | Specific source files to include |
| `--focus` | — | string | — | Focus area hint for the agent |
| `--input` | — | string | — | Raw input |
| `--instruction` | — | string | — | Custom instruction to guide the agent |
| `--instruction-file` | — | string | — | Path to a file containing custom instructions |
| `--intensity` | — | string | `balanced` | Scan intensity preset: `quick`, `balanced`, or `deep` |
| `--last-commits` | — | int | `0` | Focus on last N commits |
| `--master-batch-size` | — | int | `5` | Max records per master agent batch |
| `--max-commands` | — | int | `50` | Max terminal commands per session |
| `--max-iterations` | — | int | `3` | Maximum triage-rescan iterations |
| `--max-master-retries` | — | int | `3` | Max master agent retries on parse failure |
| `--max-plan-records` | — | int | `10` | Max records sent to plan agent |
| `--max-probe-body` | — | int | `2097152` | Max response body size in bytes during probing (default 2MB) |
| `--modules` | `-m` | []string | — | Explicit module names to include |
| `--only` | — | string | — | Run only this scanning phase |
| `--probe-concurrency` | — | int | `10` | Max parallel probe requests |
| `--probe-timeout` | — | duration | `10s` | Per-request probe timeout |
| `--profile` | — | string | — | Scanning profile to use |
| `--record-uuid` | — | string | — | HTTP record UUID from database |
| `--show-prompt` | — | bool | `false` | Print rendered prompts to stderr |
| `--skip` | — | []string | — | Skip specific phases |
| `--skip-sast` | — | bool | `false` | Skip native SAST tools |
| `--source` | — | string | — | Path to application source code |
| `--source-analysis-only` | — | bool | `false` | Run only the source analysis phase and exit |
| `--start-from` | — | string | — | Resume from a specific phase |
| `--sub-agent-concurrency` | — | int | `3` | Max parallel source analysis sub-agents |
| `--swarm-duration` | — | duration | `12h` | Maximum swarm duration (0 = unlimited) |
| `--target` | `-t` | string | — | Target URL (required when `--source` is used) |
| `--triage` | — | bool | `false` | Enable AI triage and rescan phases |
| `--upload-results` | — | bool | `false` | Upload scan results to cloud storage |
| `--vuln-type` | — | string | — | Vulnerability type focus |

---

## Agent Archon Flags

Flags specific to `vigolium agent archon`.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--agent` | — | string | `claude` | Agent platform: `claude`, `codex`, `opencode` |
| `--mode` | — | string | `deep` | Audit mode: `lite`, `balanced` (alias `scan`), `deep`, `revisit`, `confirm`, `merge`, `diff`, `status`, `mock` |
| `--no-stream` | — | bool | `false` | Don't echo agent output to the console (still written to `{session}/runtime.log`) |
| `--source` | — | string | `.` | Local directory or git URL to audit |

---

## Agent Session Flags

Flags specific to `vigolium agent session`.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--limit` | `-n` | int | `50` | Maximum number of records to display |
| `--mode` | — | string | — | Filter by mode (query, autopilot, swarm, archon) |
| `--offset` | `-o` | int | `0` | Number of records to skip |
| `--tail` | — | int | `50` | Number of raw output lines to show in detail view (0 = none, -1 = all) |
| `--full` | — | bool | `false` | Show full raw output (shortcut for `--tail -1`) |
| `--tui` / `--no-tui` | — | bool | — | Enable / force-disable interactive TUI picker |

---

## Log Flags

Flags specific to `vigolium log` and `vigolium log ls`.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--tail` | `-n` | int | `200` | Show the last N lines (0 = none, -1 = all) |
| `--full` | — | bool | `false` | Show the full log (shortcut for `--tail -1`) |
| `--follow` | `-f` | bool | `false` | Follow log output as it is written. Auto-enabled when the session is still running unless `--follow=false` is set |
| `--strip-ansi` | — | bool | `false` | Strip ANSI color codes from output |
| `--tui` / `--no-tui` | — | bool | — | Enable / force-disable the interactive picker |

---

## Import Flags

`vigolium import <path>` has no additional flags beyond the global project/JSON flags. Path may be an archon output folder (directory) or a JSONL export (file).

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
| `--from` | — | string | — | Show records after this date |
| `--header` | — | string | — | Search within HTTP header names and values |
| `--host` | — | string | — | Filter by hostname pattern |
| `--limit` | `-n` | int | `100` | Maximum records to display |
| `--method` | — | []string | — | Filter by HTTP method (repeatable) |
| `--offset` | `-o` | int | `0` | Number of records to skip |
| `--path` | — | string | — | Filter by URL path pattern |
| `--search` | — | string | — | Fuzzy search across URLs, paths, and hostnames |
| `--sort` | — | string | `created_at` | Sort by: uuid, created_at, sent_at, method, status, time |
| `--source` | — | string | — | Filter by record source |
| `--status` | — | []int | — | Filter by HTTP status code (repeatable) |
| `--to` | — | string | — | Show records before this date |

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
| `--asc` | — | bool | `false` | Sort in ascending order |
| `--body` | — | string | — | Search within request or response body content |
| `--columns` | — | []string | — | Columns to include |
| `--exclude-columns` | — | []string | — | Columns to exclude |
| `--finding-source` | — | string | — | Filter findings by source |
| `--from` | — | string | — | Show records created after this date |
| `--header` | — | string | — | Search within HTTP header names and values |
| `--host` | — | string | — | Filter records by hostname pattern |
| `--limit` | `-n` | int | `100` | Maximum number of records to display |
| `--list-columns` | — | bool | `false` | List column names for the current table |
| `--list-tables` | — | bool | `false` | List all database table names |
| `--method` | — | []string | — | Filter records by HTTP method |
| `--min-risk` | — | int | `0` | Show only records with risk score at or above this value |
| `--module-type` | — | string | — | Filter findings by module type |
| `--offset` | `-o` | int | `0` | Number of records to skip |
| `--path` | — | string | — | Filter records by URL path pattern |
| `--raw` | — | bool | `false` | Show full raw HTTP request and response |
| `--remark` | — | string | — | Filter records containing this text in remarks |
| `--scan-id` | — | string | — | Filter records by scan session ID |
| `--severity` | — | string | — | Filter findings by severity |
| `--sort` | — | string | `created_at` | Sort results by field |
| `--status` | — | []int | — | Filter records by HTTP status code |
| `--to` | — | string | — | Show records created before this date |
| `--tree` | — | bool | `false` | Display results in hierarchical tree format |

DB export flags.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--format` | `-f` | string | `jsonl` | Export format: jsonl, json, raw, csv, markdown, markdown-table |
| `--from` | — | string | — | Export records created after this date |
| `--host` | — | string | — | Filter records by hostname pattern |
| `--limit` | — | int | `0` | Maximum number of records to export (0 = unlimited) |
| `--method` | — | []string | — | Filter records by HTTP method |
| `--offset` | — | int | `0` | Number of records to skip |
| `--output` | `-o` | string | — | Output file path |
| `--path` | — | string | — | Filter records by URL path pattern |
| `--request-only` | — | bool | `false` | Export only HTTP requests (raw format only) |
| `--scan-id` | — | string | — | Filter records by scan session ID |
| `--severity` | — | string | — | Filter findings by severity level |
| `--status` | — | []int | — | Filter records by HTTP status code |
| `--to` | — | string | — | Export records created before this date |
| `--uuid` | — | string | — | Export a single record by its UUID |

DB clean flags.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--all` | bool | `false` | Delete all records (requires --force) |
| `--before` | string | — | Delete records created before this date |
| `--dry-run` | bool | `false` | Show what would be deleted without deleting |
| `--findings-only` | bool | `false` | Delete findings only, keep HTTP records |
| `--host` | string | — | Delete records matching the specified hostname |
| `--orphans` | bool | `false` | Delete findings with no matching HTTP record |
| `--scan-id` | string | — | Delete records belonging to the specified scan session |
| `--severity` | string | — | Delete findings matching the specified severity level |
| `--status` | []int | — | Delete records with matching HTTP status codes |
| `--vacuum` | bool | `false` | Reclaim disk space after deletion (SQLite) |

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

Module enable/disable flag.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--id` | bool | `false` | Exact ID match (enable/disable) |

Module ls flags.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--list-enabled` | — | bool | `false` | Show only enabled modules |
| `--tags` | — | bool | `false` | Show only unique module tags |
| `--type` | — | string | `all` | Filter modules by type: all, active, or passive |
| `--verbose` | `-v` | bool | `false` | Show long description and confirmation criteria |

---

## Extensions Flags

Subcommands: `docs`, `eval`, `lint`, `ls`, `preset`.

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
