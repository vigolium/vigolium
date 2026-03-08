---
name: vigolium-scanner
description: >-
  Use when operating the vigolium CLI for web vulnerability scanning, security testing,
  traffic ingestion, server management, AI agent-driven scanning and code review, or
  writing custom JavaScript extensions. Invoke for scan commands, scan-url, scan-request,
  run, ingest, server, agent (run/query/autopilot/pipeline), traffic browsing, database
  queries, module management, extension scripting, export, project management, and
  configuration tuning.
license: MIT
metadata:
  version: "2.0.0"
  domain: security-tooling
  triggers: >-
    vigolium, scan, scan-url, scan-request, run, ingest, server, agent, agent query,
    agent autopilot, agent pipeline, traffic, db, module, extensions, export, strategy,
    scope, source, config, project, vulnerability scanner, security scan, DAST,
    dynamic assessment, openapi scan, burp import, HAR import, whitebox scanning, SAST,
    javascript extension, custom scanner, module-tag, run extension
  role: operator
  scope: usage
  output-format: commands
---

# Vigolium CLI

Operator's guide for the vigolium high-fidelity web vulnerability scanner. Covers every command, flag, workflow pattern, scanning strategy, AI agent modes, and JavaScript extension authoring.

## Role Definition

Vigolium is a CLI-first vulnerability scanner that operates in multiple modes:
- **Standalone scanner**: `scan`, `scan-url`, `scan-request`, `run`
- **REST API server with traffic ingestion**: `server`, `ingest`
- **AI agent integration**: `agent` (template-based), `agent query` (inline prompt), `agent autopilot` (autonomous), `agent pipeline` (multi-phase)
- **Extension runner**: `run extension --ext custom-check.js` for custom JS scanning logic

This skill helps you pick the right command, flags, and workflow for any security testing task.

## Command Decision Tree

Use this to find the right command quickly:

| I need to... | Use |
|---|---|
| Scan one or more target URLs | `vigolium scan -t <url>` |
| Scan a single URL with custom method/headers | `vigolium scan-url <url> --method POST --body '...'` |
| Scan a raw HTTP request from file/stdin | `vigolium scan-request -i request.txt` |
| Run only one scan phase | `vigolium run <phase>` or `scan --only <phase>` |
| Run a custom JS extension against a target | `vigolium run extension -t <url> --ext custom-check.js` |
| Import an OpenAPI/Swagger spec and scan | `vigolium scan -I openapi -i spec.yaml -t <base-url>` |
| Import Burp/HAR/cURL traffic | `vigolium scan -I burp -i export.xml` |
| Filter modules by tag | `vigolium scan -t <url> --module-tag spring --module-tag injection` |
| Ingest traffic into database without scanning | `vigolium ingest -t <url> -I openapi -i spec.yaml` |
| Start the API server | `vigolium server` |
| Start server and auto-scan new traffic | `vigolium server -t <url> -S` |
| Run AI code review on source code | `vigolium agent --prompt-template security-code-review --repo ./src` |
| Run AI agent with inline prompt | `vigolium agent query 'review this code for vulnerabilities'` |
| Autonomous AI-driven scanning | `vigolium agent autopilot -t <url>` |
| Multi-phase AI pipeline scan | `vigolium agent pipeline -t <url>` |
| Pipeline with focus area and source | `vigolium agent pipeline -t <url> --focus "auth bypass" --repo ./src` |
| Browse stored HTTP traffic | `vigolium traffic` or `vigolium traffic <search>` |
| Browse findings/vulnerabilities | `vigolium finding` or `vigolium db ls --table findings` |
| View database statistics | `vigolium db stats` |
| Export results to JSONL/HTML | `vigolium export --format jsonl -o results.jsonl` |
| Clean database records | `vigolium db clean --host <hostname>` |
| List available scanner modules | `vigolium module ls` or `vigolium scan -M` |
| Enable/disable specific modules | `vigolium module enable xss` / `module disable sqli` |
| Manage JavaScript extensions | `vigolium ext ls` / `ext docs` / `ext preset` |
| View/modify configuration | `vigolium config ls` / `config set <key> <value>` |
| View scanning strategies | `vigolium strategy` |
| Manage scope rules | `vigolium scope view` |
| Link source code repository | `vigolium source add --hostname <host> --path ./src` |
| Clone and scan with source code | `vigolium scan -t <url> --source-url https://github.com/org/repo` |
| Manage projects | `vigolium project create <name>` / `project list` / `project use <name>` |

## Reference Guide

Load detailed reference based on what you need:

| Topic | Reference | Load When |
|-------|-----------|-----------|
| Scanning commands | `references/scanning-commands.md` | scan, scan-url, scan-request, run flags and options |
| Server & ingestion | `references/server-and-ingestion.md` | server, ingest, traffic command flags |
| Agent commands | `references/agent-commands.md` | agent, agent query, agent autopilot, agent pipeline flags and templates |
| Data & management | `references/data-and-management.md` | db, module, extensions, config, scope, source, strategy, export, project |
| Complete flag index | `references/flags-reference.md` | Looking up any specific flag by name |
| Writing extensions | `references/writing-extensions.md` | Creating custom JS scanner modules, extension API |

## Scanning Strategies

Strategies control which phases run during a scan. Use `--strategy <name>`:

| Strategy | ExtHarvest | Discovery | Spidering | SPA | Dynamic | Source-Aware |
|----------|-----------|-----------|-----------|-----|---------|-------------|
| **lite** | no | no | no | no | yes | no |
| **balanced** | yes | yes | no | yes | yes | no |
| **deep** | yes | yes | yes | yes | yes | no |
| **whitebox** | yes | yes | yes | yes | yes | yes |

- Default strategy is set in config: `scanning_strategy.default_strategy`
- View all strategies: `vigolium strategy ls`
- Whitebox requires `--source <path>` or `--source-url <git-url>` to link application source code

## Scan Phases

Vigolium runs up to 8 phases. Use `--only <phase>` to isolate one, or `--skip <phase>` to skip phases.

| Phase | Aliases | Description |
|-------|---------|-------------|
| `ingestion` | — | Parse and store input (URLs, specs, files) into the database |
| `discovery` | `deparos`, `discover` | Adaptive content discovery (directories, files, hidden endpoints) |
| `external-harvest` | — | Aggregate URLs from Wayback Machine, Common Crawl, AlienVault OTX |
| `spidering` | `spitolas` | Headless browser crawling for JS-driven routes and dynamic content |
| `spa` | — | Security posture assessment via Nuclei templates |
| `sast` | — | Static analysis on linked source code (requires `--source`) |
| `dynamic-assessment` | `audit` | Core vulnerability scanning with active and passive modules |
| `extension` | `ext` | Run only JavaScript extension modules (enables extensions, skips built-in modules) |

- `--only` and `--skip` are **mutually exclusive**
- Phase aliases work with both flags: `--only deparos` equals `--only discovery`, `--only ext` equals `--only extension`
- Run a single phase directly: `vigolium run discover -t <url>`

## Input Formats

Use `-I <format>` to specify the input type. Auto-detection works for OpenAPI specs.

| Format | Flag | Example |
|--------|------|---------|
| URLs (default) | `-I urls` | `-t https://example.com` or `-T targets.txt` |
| OpenAPI 3.x | `-I openapi` | `-I openapi -i spec.yaml -t https://api.example.com` |
| Swagger 2.0 | `-I swagger` | `-I swagger -i swagger.json` |
| Burp XML | `-I burp` | `-I burp -i burp-export.xml` |
| cURL commands | `-I curl` | `-I curl -i requests.txt` |
| Nuclei templates | `-I nuclei` | `-I nuclei -i templates/` |
| HAR archive | `-I har` | `-I har -i traffic.har` |
| Postman collection | `-I postman` | `-I postman -i collection.json` |
| stdin | — | `cat urls.txt \| vigolium scan -i -` |

OpenAPI flags: `--spec-url` (use spec servers), `--spec-header` (auth headers), `--spec-var` (parameter values), `--spec-default` (fallback value).

## Output and Results

| Format | Flag | Notes |
|--------|------|-------|
| Console (default) | `--format console` | Human-readable tables to stderr |
| JSONL | `--format jsonl` or `-j` | Machine-readable, one JSON object per line |
| HTML report | `--format html -o report.html` | Interactive ag-grid report, requires `-o` |

- Export from database: `vigolium export --format jsonl -o full-export.jsonl`
- Export specific data: `vigolium export --only findings,http`
- Export HTML report: `vigolium export --format html -o report.html`
- DB export with filters: `vigolium db export -f csv -o records.csv --host example.com`

## Workflow Recipes

### 1. Quick Single-URL Scan
```bash
vigolium scan -t https://example.com
```

### 2. Full Pipeline Scan (Discovery + Spidering + SPA + Dynamic)
```bash
vigolium scan -t https://example.com --strategy deep
```

### 3. OpenAPI Spec Scan
```bash
# With explicit base URL
vigolium scan -I openapi -i api-spec.yaml -t https://api.example.com

# Using servers from spec
vigolium scan -I openapi -i api-spec.yaml --spec-url

# With auth header
vigolium scan -I openapi -i spec.yaml -t https://api.example.com \
  --spec-header "Authorization: Bearer <token>"
```

### 4. Burp/HAR Import and Scan
```bash
vigolium scan -I burp -i burp-export.xml -t https://example.com
vigolium scan -I har -i traffic.har
```

### 5. Raw HTTP Request Scan
```bash
# From file
vigolium scan-request -i raw-request.txt

# From stdin
echo -e "GET /api/users HTTP/1.1\r\nHost: example.com\r\n" | vigolium scan-request

# With custom method and body
vigolium scan-url https://api.example.com/login \
  --method POST --body '{"user":"admin","pass":"test"}' \
  -H "Content-Type: application/json"
```

### 6. Extensions-Only Phase
```bash
# Run only JS extension modules against DB records
vigolium scan -t https://example.com --only extension

# With a specific extension script
vigolium scan -t https://example.com --only ext --ext ./my-scanner.js

# With a custom extensions directory
vigolium scan -t https://example.com --only ext --ext-dir ./extensions/

# Run via the run command (recommended for single extensions)
vigolium run extension -t https://example.com --ext ./custom-check.js

# Run via the run command alias
vigolium run ext -t https://example.com --ext ./custom-check.js
```

### 7. Discovery-Only Phase
```bash
vigolium run discover -t https://example.com
# or
vigolium scan -t https://example.com --only discovery
```

### 8. Targeted Modules
```bash
# Run only specific modules by ID
vigolium scan -t https://example.com -m xss-reflected,sqli-error

# Filter modules by tag (OR condition — matches any tag)
vigolium scan -t https://example.com --module-tag spring --module-tag injection

# Combine -m and --module-tag (union of both)
vigolium scan -t https://example.com -m sqli-error --module-tag xss

# List available modules first
vigolium module ls
vigolium module ls xss  # filter by keyword
```

### 9. Server Mode
```bash
# Basic server
vigolium server

# Custom host/port with no auth
vigolium server --host 0.0.0.0 --service-port 8443 --no-auth

# With transparent proxy for recording traffic
vigolium server --ingest-proxy-port 8080
```

### 10. Scan-on-Receive (Ingest + Auto-Scan)
```bash
# Server mode: auto-scan every ingested request
vigolium server -t https://example.com --scan-on-receive

# Local ingest + scan
vigolium ingest -t https://example.com -I openapi -i spec.yaml -S
```

### 11. AI Agent Code Review
```bash
# Security code review
vigolium agent --prompt-template security-code-review --repo ./src

# Endpoint discovery from source
vigolium agent --prompt-template endpoint-discovery --repo ./src

# List available templates
vigolium agent --list-templates

# Custom prompt with inline text
vigolium agent query 'review this code for vulnerabilities'

# Custom prompt file
vigolium agent query --agent claude --prompt-file custom-prompt.md
```

### 12. AI Agent Autopilot (Autonomous Scanning)
```bash
# Basic autonomous scan
vigolium agent autopilot -t https://example.com

# With source code context and focus area
vigolium agent autopilot -t https://api.example.com --repo ./src --focus "auth bypass"

# Custom limits
vigolium agent autopilot -t https://example.com --max-commands 50 --timeout 15m

# Preview system prompt
vigolium agent autopilot -t https://example.com --dry-run
```

### 13. AI Agent Pipeline (Multi-Phase)
```bash
# Basic pipeline scan (discover → plan → scan → triage → rescan → report)
vigolium agent pipeline -t https://example.com

# With focus and source code
vigolium agent pipeline -t https://example.com --focus "SQL injection" --repo ./src

# Control rescan iterations
vigolium agent pipeline -t https://example.com --max-rescan-rounds 3

# Skip discovery and start from planning (use existing DB data)
vigolium agent pipeline -t https://example.com --skip-phase discover --start-from plan

# Use a scanning profile
vigolium agent pipeline -t https://example.com --profile deep

# Preview agent prompts
vigolium agent pipeline -t https://example.com --dry-run
```

### 14. Results Inspection
```bash
# Browse HTTP traffic
vigolium traffic
vigolium traffic login          # fuzzy search
vigolium traffic --tree         # hierarchical view
vigolium traffic --burp         # Burp-style colored output
vigolium traffic --host api.example.com --method POST

# Browse findings
vigolium finding
vigolium finding --severity high,critical
vigolium db ls --table findings --severity critical

# Database stats
vigolium db stats
vigolium db stats --detailed    # includes top hosts breakdown

# Watch mode (auto-refresh)
vigolium traffic --watch 5s
vigolium db stats --watch 10
```

### 15. Export and Reports
```bash
# Full JSONL export
vigolium export --format jsonl -o full-export.jsonl

# Export only findings
vigolium export --only findings -o findings.jsonl

# HTML report
vigolium export --format html -o report.html
vigolium scan -t https://example.com --format html -o report.html

# Database-level export
vigolium db export -f csv -o records.csv
vigolium db export -f markdown -o report.md
vigolium db export --host example.com --from 2024-01-01
```

### 16. Whitebox Scanning (Source-Aware)
```bash
# Link source code and scan
vigolium scan -t https://example.com --source ./src --strategy whitebox

# Clone from git URL and scan
vigolium scan -t https://example.com --source-url https://github.com/org/repo --strategy whitebox

# Or link first, then scan
vigolium source add --hostname example.com --path ./src
vigolium scan -t https://example.com --strategy whitebox

# SAST-only phase
vigolium run sast --repo /path/to/app
vigolium run sast --repo /path/to/app --rule gin
```

### 17. Configuration Tuning
```bash
# View all config
vigolium config ls

# View specific section
vigolium config ls scope
vigolium config ls scanning_pace

# Set values
vigolium config set scanning_strategy.default_strategy deep
vigolium config set scope.origin.mode strict
vigolium config set dynamic_assessment.extensions.enabled true

# Speed tuning
vigolium scan -t https://example.com -c 100 --rate-limit 200 --max-per-host 5

# Scope tuning
vigolium scan -t https://example.com --scope-origin strict

# Scanning profile
vigolium scan -t https://example.com --scanning-profile aggressive
```

### 18. Project Management
```bash
# Create a project
vigolium project create my-project

# List projects
vigolium project list

# Use a project (sets default for subsequent commands)
vigolium project use my-project

# Scope CLI operations to a project
vigolium scan -t https://example.com --project my-project

# Project-scoped database access
VIGOLIUM_PROJECT=my-project vigolium db stats
```

### 19. Writing and Running Custom Extensions
```bash
# Install preset examples
vigolium ext preset

# View API reference
vigolium ext docs
vigolium ext docs --example

# Quick-test JS code inline
vigolium ext eval 'vigolium.log.info("hello")'
vigolium ext eval --ext-file script.js

# Run a custom extension against a target
vigolium run extension -t https://example.com --ext custom-check.js

# Run during a full scan (extensions run alongside built-in modules)
vigolium scan -t https://example.com --ext custom-check.js

# Run only extensions, skip built-in modules
vigolium scan -t https://example.com --only extension --ext custom-check.js
```

## Key Global Flags

These flags are available on all commands (persistent flags on root):

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--target` | `-t` | — | Target URL (repeatable) |
| `--target-file` | `-T` | — | File containing target URLs |
| `--input` | `-i` | `-` (stdin) | Input file path |
| `--input-mode` | `-I` | `urls` | Input format (openapi, burp, curl, har, etc.) |
| `--concurrency` | `-c` | `50` | Concurrent scan workers |
| `--rate-limit` | `-r` | `100` | Max requests per second |
| `--max-per-host` | — | `2` | Max concurrent requests per host |
| `--timeout` | — | `15s` | HTTP request timeout |
| `--proxy` | — | — | HTTP/SOCKS5 proxy URL |
| `--modules` | `-m` | `all` | Scanner modules to enable |
| `--module-tag` | — | — | Filter modules by tag (OR condition, repeatable) |
| `--strategy` | — | — | Scanning strategy preset |
| `--only` | — | — | Run only a single phase |
| `--skip` | — | — | Skip specific phases |
| `--format` | — | `console` | Output format: console, jsonl, html |
| `--scan-on-receive` | `-S` | `false` | Auto-scan new database records |
| `--source` | — | — | Path to application source code |
| `--source-url` | — | — | Git URL to clone for source-aware scanning |
| `--scan-id` | — | — | Label for grouping scan session results |
| `--scanning-profile` | — | — | Scanning profile YAML name or path |
| `--scope-origin` | — | — | Origin scope: all, relaxed, balanced, strict |
| `--project` | — | — | Project name or UUID to scope operations |
| `--verbose` | `-v` | `false` | Verbose logging |
| `--silent` | — | `false` | Suppress all output except findings |
| `--json` | `-j` | `false` | JSON output format |
| `--debug` | — | `false` | Dump raw HTTP traffic |
| `--db` | — | `~/.vigolium/database-vgnm.sqlite` | SQLite database path |
| `--config` | — | `~/.vigolium/vigolium-configs.yaml` | Config file path |
| `--force` | `-F` | `false` | Skip confirmation prompts |
| `--list-modules` | `-M` | `false` | List all scanner modules |
| `--watch` | — | — | Auto-refresh interval (e.g. 5s, 1m) |
| `--width` | — | `70` | Max column width for tables |
| `--ext` | — | — | Extension script path to load (repeatable) |
| `--ext-dir` | — | — | Override extension scripts directory |

## Constraints

- `--only` and `--skip` are mutually exclusive
- `--format html` requires `-o/--output` and is only supported for discovery/spidering phases (in scan mode)
- `--target/-t` and `--spec-url` are mutually exclusive for ingest
- `--source` and `--source-url` are mutually exclusive
- Server mode requires API key auth by default (use `--no-auth` to disable, or set `VIGOLIUM_API_KEY`)
- Agent commands require agent backends configured in `vigolium-configs.yaml`
- `--scan-on-receive/-S` is ignored in remote ingest mode (server handles scanning)
- `db clean --all` requires `--force` for safety
- `db clean --force` with no filter flags resets the entire database (SQLite only)
- Whitebox/SAST phases require `--source <path>` or `--source-url <git-url>` to link application source code
- Phase aliases: `deparos`/`discover` = `discovery`, `spitolas` = `spidering`, `audit` = `dynamic-assessment`, `ext` = `extension`
- `--module-tag` uses OR logic: modules matching any specified tag are included
- `-m` and `--module-tag` merge results (union)
