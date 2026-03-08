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
- [Traffic Flags](#traffic-flags)
- [DB Flags](#db-flags)
- [Export Flags](#export-flags)
- [Module Flags](#module-flags)
- [Extensions Flags](#extensions-flags)
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
| `--disable-fetch-response` | — | bool | `false` | Skip fetching responses during ingestion |
| `--dump-traffic` | — | bool | `false` | Print every HTTP pair to stderr |
| `--ext` | — | []string | — | Extension script path to load (repeatable) |
| `--ext-dir` | — | string | — | Override extension scripts directory |
| `--force` | `-F` | bool | `false` | Skip confirmation prompts |
| `--format` | — | string | `console` | Output format: console, jsonl, html |
| `--full-example` | — | bool | `false` | Show full example commands |
| `--heuristics-check` | — | string | `basic` | Heuristics level: none, basic, advanced |
| `--input` | `-i` | string | `-` | Input file path |
| `--input-mode` | `-I` | string | `urls` | Input format |
| `--input-read-timeout` | — | duration | `3m` | Timeout for reading input |
| `--json` | `-j` | bool | `false` | JSON output format |
| `--list-input-mode` | — | bool | `false` | List supported input modes |
| `--list-modules` | `-M` | bool | `false` | List scanner modules |
| `--log-file` | — | string | — | Write logs to file (JSON format) |
| `--max-host-error` | — | int | `30` | Skip host after N consecutive errors |
| `--max-per-host` | — | int | `2` | Max concurrent requests per host |
| `--module-tag` | — | []string | — | Filter modules by tag (OR condition, repeatable) |
| `--modules` | `-m` | []string | `all` | Scanner modules to enable |
| `--only` | — | string | — | Run only one phase |
| `--project` | — | string | — | Project name or UUID to scope operations |
| `--proxy` | — | string | — | HTTP/SOCKS5 proxy URL |
| `--rate-limit` | `-r` | int | `100` | Max requests per second |
| `--scan-id` | — | string | — | Scan session label |
| `--scan-on-receive` | `-S` | bool | `false` | Auto-scan new records |
| `--scanning-max-duration` | — | duration | `0` | Override max scan duration |
| `--scanning-profile` | — | string | — | Scanning profile name/path |
| `--scope-origin` | — | string | — | Origin scope: all, relaxed, balanced, strict |
| `--silent` | — | bool | `false` | Suppress output except findings |
| `--skip` | — | []string | — | Skip phases |
| `--skip-heuristics` | — | bool | `false` | Disable heuristics check |
| `--source` | — | string | — | Source code path |
| `--source-url` | — | string | — | Git URL to clone for source-aware scanning |
| `--spec-default` | — | string | `1` | Default value for OpenAPI parameters |
| `--spec-header` | — | []string | — | HTTP headers for OpenAPI requests |
| `--spec-url` | — | bool | `false` | Use OpenAPI spec server URLs |
| `--spec-var` | — | []string | — | OpenAPI parameter values as key=value |
| `--strategy` | — | string | — | Scanning strategy preset |
| `--target` | `-t` | []string | — | Target URL (repeatable) |
| `--target-file` | `-T` | string | — | File with target URLs |
| `--timeout` | — | duration | `15s` | HTTP request timeout |
| `--verbose` | `-v` | bool | `false` | Verbose logging |
| `--watch` | — | string | — | Auto-refresh interval |
| `--width` | — | int | `70` | Max column width for tables |

---

## Scan Flags

Flags specific to `vigolium scan` and `vigolium run`.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--advanced-options` | `-a` | map | — | Key=value scan options |
| `--browser-engine` | `-E` | string | `chromium` | Browser engine |
| `--browsers` | `-b` | int | `1` | Browser instance count |
| `--discover` | — | bool | `false` | Enable content discovery |
| `--discover-max-time` | — | duration | `1h` | Discovery timeout per target |
| `--external-harvest` | — | bool | `false` | Enable external harvesting |
| `--header` | `-H` | []string | — | Custom HTTP header |
| `--headless` | — | bool | `true` | Headless browser mode |
| `--include-response` | — | bool | `false` | Include response in output |
| `--no-cdp` | — | bool | `false` | Disable CDP detection |
| `--no-forms` | — | bool | `false` | Disable form filling |
| `--oast-url` | — | string | — | OAST callback URL |
| `--output` | `-o` | string | — | Output file path |
| `--repo` | — | string | — | SAST repo path |
| `--required-only` | — | bool | `false` | Required fields only |
| `--retries` | — | int | `1` | Retry attempts |
| `--rule` | — | string | — | SAST rule filter |
| `--skip-format-validation` | — | bool | `false` | Skip format validation |
| `--spa-exclude-tags` | — | []string | — | Nuclei exclude tags |
| `--spa-severities` | — | []string | — | Nuclei severity filter |
| `--spa-tags` | — | []string | — | Nuclei include tags |
| `--spa-templates-dir` | — | string | — | Custom templates dir |
| `--spider` | — | bool | `false` | Enable spidering |
| `--spider-max-time` | — | duration | `30m` | Spidering timeout |
| `--stats` | — | bool | `false` | Live scan statistics |
| `--stream` | — | bool | `false` | Stream processing mode |

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
| `--alternative-ingest-key` | — | []string | — | Secondary API key |
| `--catchup-threads` | — | int | `4` | Catchup scan workers |
| `--disable-catchup` | — | bool | `false` | Disable catchup scan |
| `--host` | — | string | `0.0.0.0` | Listen address |
| `--ingest-proxy-port` | — | int | `0` | Proxy port (0=disabled) |
| `--mem-buffer` | — | int | `10000` | Queue memory buffer |
| `--no-auth` | `-A` | bool | `false` | Disable authentication |
| `--output` | `-o` | string | — | Findings output file |
| `--service-port` | — | int | `9002` | API service port |

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
| `--agent-timeout` | duration | `5m` | Execution timeout |
| `--append` | string | — | Text appended to prompt |
| `--dry-run` | bool | `false` | Preview prompt |
| `--files` | []string | — | Specific files |
| `--list-agents` | bool | `false` | List agent backends |
| `--list-templates` | bool | `false` | List templates |
| `--output` | string | — | Output file |
| `--prompt-file` | string | — | Prompt template file |
| `--prompt-template` | string | — | Prompt template ID |
| `--repo` | string | — | Source code path |
| `--source` | string | — | Source identifier |

Flags specific to `vigolium agent query`.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--agent` | — | string | from config | Agent backend |
| `--agent-timeout` | — | duration | `5m` | Execution timeout |
| `--output` | — | string | — | Output file |
| `--prompt` | `-p` | string | — | Inline prompt |
| `--source` | — | string | — | Source identifier |
| `--stdin` | — | bool | `false` | Read from stdin |

---

## Agent Autopilot Flags

Flags specific to `vigolium agent autopilot`.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--target` | `-t` | string | — | Target URL (required) |
| `--agent` | — | string | from config | Agent backend |
| `--repo` | — | string | — | Source code repository path |
| `--files` | — | []string | — | Specific files to include |
| `--focus` | — | string | — | Focus area hint |
| `--system-prompt` | — | string | — | Custom system prompt file |
| `--timeout` | — | duration | `30m` | Overall session timeout |
| `--max-commands` | — | int | `100` | Max CLI commands to execute |
| `--dry-run` | — | bool | `false` | Preview system prompt |

---

## Agent Pipeline Flags

Flags specific to `vigolium agent pipeline`.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--target` | `-t` | string | — | Target URL (required) |
| `--agent` | — | string | from config | Agent backend |
| `--repo` | — | string | — | Source code repository path |
| `--files` | — | []string | — | Specific files to include |
| `--focus` | — | string | — | Focus area hint for planning |
| `--timeout` | — | duration | `1h` | Overall pipeline timeout |
| `--max-rescan-rounds` | — | int | `2` | Max triage→rescan iterations |
| `--skip-phase` | — | []string | — | Skip phases (discover, plan, scan, triage, rescan, report) |
| `--start-from` | — | string | — | Resume from a specific phase |
| `--profile` | — | string | — | Scanning profile for scan phases |
| `--dry-run` | — | bool | `false` | Preview agent prompts |

---

## Traffic Flags

Filter flags (shared with traffic replay via PersistentFlags).

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--asc` | — | bool | `false` | Sort ascending |
| `--body` | — | string | — | Search in body |
| `--from` | — | string | — | Records after date |
| `--header` | — | string | — | Search in headers |
| `--host` | — | string | — | Filter by hostname |
| `--limit` | `-n` | int | `100` | Max records |
| `--method` | — | []string | — | Filter by method |
| `--offset` | `-o` | int | `0` | Skip records |
| `--path` | — | string | — | Filter by path |
| `--search` | — | string | — | URL/path search |
| `--sort` | — | string | `created_at` | Sort field |
| `--source` | — | string | — | Filter by source |
| `--status` | — | []int | — | Filter by status |
| `--to` | — | string | — | Records before date |

Display-only flags.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--burp` | bool | `false` | Burp-style format |
| `--columns` | []string | — | Include columns |
| `--exclude-columns` | []string | — | Exclude columns |
| `--raw` | bool | `false` | Raw HTTP output |
| `--tree` | bool | `false` | Tree format |

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

DB clean flags.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--all` | bool | `false` | Delete all records |
| `--before` | string | — | Before date |
| `--dry-run` | bool | `false` | Preview mode |
| `--findings-only` | bool | `false` | Delete findings only |
| `--host` | string | — | Filter hostname |
| `--orphans` | bool | `false` | Delete orphans |
| `--scan-id` | string | — | Filter by scan ID |
| `--severity` | string | — | Filter severity |
| `--status` | []int | — | Filter status codes |
| `--vacuum` | bool | `false` | Reclaim disk space |

DB stats flags.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--detailed` | bool | `false` | Detailed host breakdown |
| `--host` | string | — | Filter hostname |
| `--scan-id` | string | — | Filter scan ID |

---

## Export Flags

Top-level `vigolium export` flags.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--format` | — | string | `jsonl` | Format: html, jsonl |
| `--limit` | — | int | `0` | Max records per table |
| `--lite` | — | bool | `false` | Omit raw HTTP data |
| `--only` | — | []string | all | Data types to export |
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
