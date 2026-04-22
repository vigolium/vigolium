---
name: vigolium-scanner
description: >-
  Use when operating the vigolium CLI for web vulnerability scanning, security testing,
  traffic ingestion, server management, AI agent-driven scanning and code review, or
  writing custom JavaScript extensions. Invoke for scan commands, scan-url, scan-request,
  run, ingest, server, agent (query/autopilot/swarm/archon/session), traffic browsing,
  database queries, module management, extension scripting, export, project management,
  and configuration tuning.
license: MIT
metadata:
  version: "3.1.0"
  domain: security-tooling
  triggers: >-
    vigolium, scan, scan-url, scan-request, run, ingest, server, agent, agent query,
    agent autopilot, agent swarm, agent archon, agent session, archon-audit, traffic,
    db, module, extensions, js, export, strategy, scope, source, config, project,
    vigolium init, vigolium import, vigolium log, vigolium doctor, config clean,
    vulnerability scanner, security scan, DAST, audit, openapi scan, burp import,
    HAR import, whitebox scanning, SAST, javascript extension, custom scanner,
    module-tag, run extension, vigolium js, intensity, diff scan, last commits,
    stateless scan, upload results, runtime log, session log
  role: operator
  scope: usage
  output-format: commands
---

# Vigolium CLI

Operator's guide for the [Vigolium](https://www.vigolium.com/) high-fidelity web vulnerability scanner. Covers every command, flag, workflow pattern, scanning strategy, AI agent modes, and JavaScript extension authoring. Full documentation at [docs.vigolium.com](https://docs.vigolium.com/).

## Role Definition

Vigolium is a CLI-first vulnerability scanner that operates in multiple modes:
- **Standalone scanner**: `scan`, `scan-url`, `scan-request`, `run`
- **REST API server with traffic ingestion**: `server`, `ingest`
- **AI agent integration**:
  - `agent query` — single-shot prompt (template-based or inline) for code review / endpoint discovery
  - `agent autopilot` — autonomous AI-driven scanning that drives the vigolium CLI
  - `agent swarm` — AI-guided targeted or full-scope scanning (add `--discover` for full-scope)
  - `agent archon` — foreground multi-phase AI security audit of source code
  - `agent session` — list / inspect agent run sessions
- **Extension runner**: `run extension --ext custom-check.js` for custom JS scanning logic
- **JavaScript executor**: `js` for ad-hoc scripting with full `vigolium.*` API access
- **Session log viewer**: `log <uuid>` streams `runtime.log` for native + agentic sessions (tail / follow / DB fallback)
- **Data import**: `import <path>` ingests archon audit folders and JSONL exports
- **Lifecycle**: `init` sets up `~/.vigolium/`, `config clean` wipes it back to a fresh state

Agent backends integrate with coding agent CLIs via protocol-specific communication:
- **SDK** (default): Claude Agent SDK — full CLI tool access (Read, Grep, Glob, Bash, Edit, Write)
- **Codex-SDK**: OpenAI Codex native JSON-RPC v2
- **OpenCode-SDK**: OpenCode native REST + SSE streaming
- **Pipe**: Legacy stdin/stdout fallback

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
| Run AI code review on source code | `vigolium agent query --prompt-template security-code-review --source ./src` |
| Run AI agent with inline prompt | `vigolium agent query 'review this code for vulnerabilities'` |
| Autonomous AI-driven scanning | `vigolium agent autopilot -t <url>` |
| Autopilot natural-language prompt | `vigolium agent autopilot "scan VAmPI at ~/src/VAmPI on localhost:3005"` |
| Autopilot with intensity preset | `vigolium agent autopilot -t <url> --intensity deep` |
| Autopilot scanning a PR diff | `vigolium agent autopilot -t <url> --source ./src --diff main...feature-branch` |
| Full-scope AI-driven scan (discovery → plan → scan → triage) | `vigolium agent swarm -t <url> --discover` |
| Deep targeted vulnerability scan on specific endpoint | `vigolium agent swarm -t <url>` |
| Swarm natural-language prompt | `vigolium agent swarm "scan source at ~/src/app on localhost:3005"` |
| Swarm with curl command input | `vigolium agent swarm --input "curl -X POST <url> -d '...'"` |
| Swarm with source code (route discovery + SAST + code audit) | `vigolium agent swarm -t <url> --source ./src` |
| Swarm with intensity preset | `vigolium agent swarm -t <url> --intensity quick` |
| Swarm with background archon-audit | `vigolium agent swarm -t <url> --source ./src --archon lite` |
| Swarm with custom instructions | `vigolium agent swarm -t <url> --instruction "Focus on GraphQL"` |
| Source analysis only (no scan) | `vigolium agent swarm -t <url> --source ./src --source-analysis-only` |
| Foreground archon audit (lite/balanced/deep) | `vigolium agent archon --mode deep --source .` |
| Archon audit of a remote repo | `vigolium agent archon --mode lite --source https://github.com/org/repo` |
| Archon confirm PoCs for existing findings | `vigolium agent archon --mode confirm --source ./audit-tree` |
| Browse stored HTTP traffic | `vigolium traffic` or `vigolium traffic <search>` |
| Browse findings/vulnerabilities | `vigolium finding` or `vigolium db ls --table findings` |
| Filter findings by module type or source | `vigolium finding --module-type active --finding-source audit` |
| View database statistics | `vigolium db stats` |
| Export results to JSONL/HTML | `vigolium export --format jsonl -o results.jsonl` |
| Clean database records | `vigolium db clean --host <hostname>` |
| List available scanner modules | `vigolium module ls` or `vigolium scan -M` |
| Enable/disable specific modules | `vigolium module enable xss` / `module disable sqli` |
| Manage JavaScript extensions | `vigolium ext ls` / `ext docs` / `ext preset` |
| Execute arbitrary JS with vigolium API | `vigolium js --code 'vigolium.http.get("https://example.com")'` |
| Execute JS from a file | `vigolium js --code-file script.js` |
| Execute JS from stdin | `echo 'vigolium.utils.md5("test")' \| vigolium js` |
| View/modify configuration | `vigolium config ls` / `config set <key> <value>` |
| View scanning strategies | `vigolium strategy` |
| Manage scope rules | `vigolium scope view` |
| Link source code repository | `vigolium source add --hostname <host> --path ./src` |
| Clone and scan with source code | `vigolium scan -t <url> --source-url https://github.com/org/repo` |
| Manage projects | `vigolium project create <name>` / `project list` / `project use <name>` |
| List agent sessions | `vigolium agent session` or `vigolium agent session <uuid>` |
| Seed database with sample data | `vigolium db seed` |
| Import findings from file | `vigolium finding load -i findings.jsonl` |
| Import archon audit folder or JSONL export | `vigolium import <path>` |
| View runtime logs for a scan/agent session | `vigolium log <uuid>` (add `-f` to follow, `--tail N`) |
| List all native + agentic sessions with log status | `vigolium log ls` |
| Initialize `~/.vigolium/` with defaults | `vigolium init` (add `--force` to regenerate) |
| Wipe `~/.vigolium/` and reinitialize | `vigolium config clean` |
| Validate extension files | `vigolium ext lint --ext custom-check.js` |
| Evaluate JS inline | `vigolium ext eval 'vigolium.log.info("hello")'` |
| Manage sessions (lint, list, load, totp) | `vigolium session lint` / `session list` / `session load` / `session totp` |
| Run health check on installation | `vigolium doctor` |

## Reference Guide

Load detailed reference based on what you need:

| Topic | Reference | Load When |
|-------|-----------|-----------|
| Scanning commands | `references/scanning-commands.md` | scan, scan-url, scan-request, run flags and options |
| Server & ingestion | `references/server-and-ingestion.md` | server, ingest, traffic command flags |
| Agent commands | `references/agent-commands.md` | agent, agent query, agent autopilot, agent swarm flags and templates |
| Session / auth config | `references/session-auth-config.md` | --auth-config YAML format, extract rules, authenticated scanning setup |
| Data & management | `references/data-and-management.md` | db, module, extensions, js, config, scope, source, strategy, export, project |
| Complete flag index | `references/flags-reference.md` | Looking up any specific flag by name |
| Writing extensions | `references/writing-extensions.md` | Creating custom JS scanner modules, extension API |

## Scanning Strategies

Strategies control which phases run during a scan. Use `--strategy <name>`:

| Strategy | ExtHarvest | Discovery | Spidering | KnownIssueScan | Audit | Source-Aware |
|----------|-----------|-----------|-----------|----------------|-------|-------------|
| **lite** | no | no | no | no | yes | no |
| **balanced** | no | yes | yes | yes | yes | no |
| **deep** | yes | yes | yes | yes | yes | no |
| **whitebox** | no | yes | no | yes | yes | yes |

- Default strategy is set in config: `scanning_strategy.default_strategy`
- **Balanced** is the default when `--strategy` is not specified
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
| `known-issue-scan` | — | Security posture assessment via Nuclei templates + Kingfisher secrets |
| `sast` | — | Static analysis on linked source code (requires `--source`) |
| `audit` | `dynamic-assessment` | Core vulnerability scanning with active and passive modules |
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

Multiple formats can be combined: `--format jsonl,html -o report.html`

- Export from database: `vigolium export --format jsonl -o full-export.jsonl`
- Export specific data: `vigolium export --only findings,http`
- Export HTML report: `vigolium export --format html -o report.html`
- DB export with filters: `vigolium db export -f csv -o records.csv --host example.com`

## Workflow Recipes

### 1. Quick Single-URL Scan
```bash
vigolium scan -t https://example.com
```

### 2. Full Pipeline Scan (Discovery + Spidering + KnownIssueScan + Audit)
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
vigolium server --host 0.0.0.0 --service-port 8443 -A

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

### 11. AI Agent Code Review (agent query)
```bash
# Security code review (SDK protocol by default — full tool access)
vigolium agent query --prompt-template security-code-review --source ./src

# Endpoint discovery from source
vigolium agent query --prompt-template endpoint-discovery --source ./src

# List available templates / backends (parent command helpers)
vigolium agent --list-templates
vigolium agent --list-agents

# Custom prompt with inline text
vigolium agent query 'review this code for vulnerabilities'

# Pipe a prompt from stdin
echo "check for SSRF in the URL-fetching handler" | vigolium agent query --stdin

# Custom prompt file with a specific backend
vigolium agent query --agent claude --prompt-file custom-prompt.md

# With custom instruction appended to the rendered template
vigolium agent query --prompt-template security-code-review --source ./src \
  --instruction "Focus on authentication and session management"

# Dry-run to preview the rendered prompt
vigolium agent query --prompt-template security-code-review --source ./src --dry-run

# Save output to a file
vigolium agent query --prompt-template security-code-review --source ./src \
  --output review-results.json
```

### 12. AI Agent Autopilot (Autonomous Scanning)

Autopilot runs a single autonomous operator session that drives the vigolium CLI (SDK protocol — full Read/Grep/Glob/Bash/Edit/Write tools). When `--source` is set, `archon-audit` runs first and the prepared whitebox context is fed to the operator. Disable with `--no-archon`.

Intensity presets (`--intensity`) bundle limits and archon mode into a single flag. Explicit flags always override.

| Preset | Max Commands | Timeout | Archon Mode | Browser |
|--------|-------------:|--------:|-------------|:-------:|
| `quick` | 30 | 1h | `lite` | off |
| `balanced` (default) | 100 | 6h | `balanced` (6-phase) | off |
| `deep` | 300 | 12h | `deep` (10-phase) | on |

```bash
# Basic autonomous scan (balanced by default)
vigolium agent autopilot -t https://example.com

# Natural-language prompt — target, source, focus are auto-extracted
vigolium agent autopilot "scan VAmPI source at ~/src/VAmPI on localhost:3005"
vigolium agent autopilot "test auth bypass on https://app.example.com"

# With source code context (triggers archon-audit automatically)
vigolium agent autopilot -t https://example.com --source ./src

# Specific files + custom instruction
vigolium agent autopilot -t https://example.com --source ./src \
  --files "routes/api.js,controllers/auth.js" \
  --instruction "Focus on the new payment endpoint"

# Intensity presets
vigolium agent autopilot -t https://example.com --source ./src --intensity quick  # CI/PR
vigolium agent autopilot -t https://example.com --intensity deep                   # full pentest

# Override a specific setting within a preset
vigolium agent autopilot -t https://example.com --intensity deep --timeout 4h

# Scan only a PR diff or recent commits
vigolium agent autopilot -t https://example.com --source ./src --diff main...feature-branch
vigolium agent autopilot -t https://example.com --source ./src --last-commits 3

# Custom limits (explicit override)
vigolium agent autopilot -t https://example.com --max-commands 50 --timeout 15m

# Pipe a curl command (target auto-derived)
echo "curl -X POST https://example.com/api/login -d '{\"user\":\"admin\"}'" | vigolium agent autopilot

# Browser-based auth preflight
vigolium agent autopilot -t https://example.com --browser --credentials "admin/admin123"
vigolium agent autopilot -t https://example.com --browser --auth-required \
  --browser-start-url https://example.com/login

# Disable archon when source is provided
vigolium agent autopilot -t https://example.com --source ./src --no-archon

# Choose a specific archon mode
vigolium agent autopilot -t https://example.com --source ./src --archon-mode deep

# Upload results to cloud storage after completion
vigolium agent autopilot -t https://example.com --source ./src --upload-results

# Preview rendered system prompt without launching the agent
vigolium agent autopilot -t https://example.com --dry-run

# Pick a non-default agent backend
vigolium agent autopilot -t https://example.com --agent codex

# With MCP servers
vigolium agent autopilot -t https://example.com --mcp-enabled \
  --mcp-server "playwright=npx,-y,@anthropic-ai/mcp-server-playwright"
```

### 13. AI Agent Swarm (Targeted or Full-Scope)

Swarm orchestrates: normalize → source analysis (AI, `--source`) → code audit (AI) → SAST (native) → SAST review (AI) → discover (native, `--discover`) → plan (AI) → extension (Go) → native scan → triage (AI, `--triage`) → rescan (loop).

Intensity presets (`--intensity`) bundle multiple defaults — explicit flags always override.

| Preset | Discover | Triage | Code Audit | Browser | Swarm Duration | Max Iterations |
|--------|:--------:|:------:|:----------:|:-------:|---------------:|---------------:|
| `quick` | off | off | off | off | 2h | 1 |
| `balanced` (default) | off | off | if `--source` | off | 12h | 3 |
| `deep` | on | on | on | on | 24h | 5 |

```bash
# Target a URL for deep analysis
vigolium agent swarm -t https://example.com/api/users

# Natural-language prompt — target, source, focus auto-extracted
vigolium agent swarm "scan source at ~/src/app on localhost:3005"
vigolium agent swarm "scan all source code from ~/src/crAPI, ~/src/DVWA"

# Full-scope scan with discovery
vigolium agent swarm -t https://example.com --discover

# Analyze a curl command
vigolium agent swarm --input "curl -X POST https://example.com/api/login -d '{\"user\":\"admin\"}'"

# Pipe raw HTTP request from stdin (auto-detected)
echo -e "POST /api/search HTTP/1.1\r\nHost: example.com\r\n\r\nq=test" | vigolium agent swarm

# Scan a record from the database
vigolium agent swarm --record-uuid 550e8400-e29b-41d4-a716-446655440000

# Focus on a specific vulnerability type
vigolium agent swarm -t https://example.com/api/users --vuln-type sqli

# Source-aware swarm (route extraction + code audit + SAST + scanning)
vigolium agent swarm -t http://localhost:3000 --source ./src

# Full-scope source-aware scan
vigolium agent swarm -t http://localhost:3000 --source ~/projects/express-app --discover

# Source-aware with specific files
vigolium agent swarm -t http://localhost:8080 --source ./backend \
  --files src/routes/api.js,src/models/user.js

# Source analysis only (extract routes, no scan)
vigolium agent swarm -t http://localhost:3000 --source ./src --source-analysis-only

# Intensity presets
vigolium agent swarm -t https://example.com/api/users?id=1 --intensity quick
vigolium agent swarm -t https://example.com --source ./src --intensity deep

# Override a specific setting within a preset
vigolium agent swarm -t https://example.com --intensity deep --triage=false

# Run a background archon-audit in parallel (requires --source). Bare --archon = lite.
vigolium agent swarm -t http://localhost:3000 --source ./src --archon
vigolium agent swarm -t http://localhost:3000 --source ./src --archon deep

# Scan only changed code
vigolium agent swarm -t https://example.com --source ./src --diff main...feature-branch
vigolium agent swarm -t https://example.com --source ./src --last-commits 3

# Skip SAST tools during source analysis
vigolium agent swarm -t http://localhost:3000 --source ./src --skip-sast

# Disable code audit (still runs source analysis + SAST)
vigolium agent swarm -t http://localhost:3000 --source ./src --code-audit=false

# Enable triage and rescan loop
vigolium agent swarm -t https://example.com/api/users --triage --max-iterations 5

# Browser automation + auth capture
vigolium agent swarm -t https://example.com --browser --auth \
  --credentials "username=admin,password=secret"

# Upload results to cloud storage
vigolium agent swarm -t https://example.com --source ./src --upload-results

# Custom instructions to guide the agent
vigolium agent swarm -t https://example.com/api/users --instruction "Focus on GraphQL parsing"

# Instructions from a file
vigolium agent swarm -t https://example.com/api/users --instruction-file hints.txt

# Resume from a specific phase
vigolium agent swarm -t https://example.com --start-from plan

# Specify modules explicitly
vigolium agent swarm -t https://example.com/api/search -m xss-reflected,xss-stored

# Control scanning phases
vigolium agent swarm -t https://example.com --only dynamic-assessment
vigolium agent swarm -t https://example.com --skip discovery,spidering

# Custom overall duration
vigolium agent swarm -t https://example.com --swarm-duration 24h

# Preview master agent prompt (no execution)
vigolium agent swarm -t https://example.com/api/users --dry-run

# Show rendered prompts during execution
vigolium agent swarm -t https://example.com/api/users --show-prompt
```

### 13b. AI Agent Archon (Foreground Whitebox Audit)
```bash
# Deep multi-phase audit of a local repo
vigolium agent archon --mode deep --source .

# Fast 3-phase audit of a remote repo (clones automatically)
vigolium agent archon --mode lite --source https://github.com/org/repo

# Balanced 6-phase audit with a non-default agent backend
vigolium agent archon --mode balanced --agent codex --source ~/code/myapp

# Second pass on a prior audit tree (revisit with new context)
vigolium agent archon --mode revisit --source ./prior-audit-tree

# PoC construction for previously confirmed findings
vigolium agent archon --mode confirm --source ./audit-with-findings

# Read-only progress check (no agent launched)
vigolium agent archon --mode status --source ./in-progress-audit

# Don't echo agent output to console (still saved to session runtime.log)
vigolium agent archon --mode deep --source . --no-stream
```

Valid `--mode` values: `lite` (3 phases), `balanced` (6 phases, alias `scan`), `deep` (10 phases), `revisit`, `confirm`, `merge`, `diff`, `status`, `mock`. Valid `--agent` values: `claude` (default), `codex`, `opencode`.

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
vigolium finding --module-type active
vigolium finding --finding-source audit
vigolium finding --burp         # Burp-style format
vigolium finding --id 42        # specific finding by ID
vigolium finding --columns ID,SEVERITY,MODULE,MATCHED_AT,TAGS
vigolium db ls --table findings --severity critical

# Database stats
vigolium db stats
vigolium db stats --detailed    # includes top hosts breakdown

# Watch mode (auto-refresh)
vigolium traffic --watch 5s
vigolium db stats --watch 10
```

### 16. Export and Reports
```bash
# Full JSONL export
vigolium export --format jsonl -o full-export.jsonl

# Export only findings
vigolium export --only findings -o findings.jsonl

# HTML report
vigolium export --format html -o report.html
vigolium scan -t https://example.com --format html -o report.html

# Multiple output formats at once
vigolium scan -t https://example.com --format jsonl,html -o report.html

# Database-level export
vigolium db export -f csv -o records.csv
vigolium db export -f markdown -o report.md
vigolium db export --host example.com --from 2024-01-01
```

### 17. Whitebox Scanning (Source-Aware)
```bash
# Link source code and scan
vigolium scan -t https://example.com --source ./src --strategy whitebox

# Clone from git URL and scan
vigolium scan -t https://example.com --source-url https://github.com/org/repo --strategy whitebox

# Or link first, then scan
vigolium source add --hostname example.com --path ./src
vigolium scan -t https://example.com --strategy whitebox

# SAST-only phase
vigolium run sast --sast-adhoc /path/to/app
vigolium run sast --sast-adhoc /path/to/app --rule gin

# SAST from git URL (clones automatically)
vigolium run sast --sast-adhoc https://github.com/org/repo
```

### 18. Configuration Tuning
```bash
# View all config
vigolium config ls

# View specific section
vigolium config ls scope
vigolium config ls scanning_pace

# Set values
vigolium config set scanning_strategy.default_strategy deep
vigolium config set scope.origin.mode strict
vigolium config set audit.extensions.enabled true

# Speed tuning
vigolium scan -t https://example.com -c 100 -r 200 --max-per-host 5

# Scope tuning
vigolium scan -t https://example.com --scope-origin strict

# Scanning profile
vigolium scan -t https://example.com --scanning-profile aggressive
```

### 19. Project Management
```bash
# Create a project
vigolium project create my-project

# List projects
vigolium project list

# Use a project (sets default for subsequent commands)
vigolium project use my-project

# Scope CLI operations to a project
vigolium scan -t https://example.com --project-name my-project

# Project-scoped database access
VIGOLIUM_PROJECT=my-project vigolium db stats
```

### 20. Writing and Running Custom Extensions
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

### 21. JavaScript Execution (vigolium js)
```bash
# Execute inline JS with full vigolium.* API access
vigolium js --code 'vigolium.http.get("https://example.com/api/health")'

# Execute JS from a file
vigolium js --code-file scanner-script.js

# TypeScript auto-transpilation
vigolium js --code-file scanner.ts

# From stdin (ideal for agent/pipe workflows)
echo 'vigolium.utils.md5("password123")' | vigolium js

# With target context (accessible as TARGET variable)
vigolium js --target https://example.com --code 'vigolium.http.get(TARGET + "/api/users")'

# Custom timeout and text output format
vigolium js --timeout 60s --format text --code 'vigolium.utils.sha256("hello")'

# Complex scripting: ingest, query, and annotate
vigolium js --code-file <<'EOF' > /dev/null
var records = vigolium.db.records.query({ hostname: "example.com", limit: 10 });
for (var i = 0; i < records.length; i++) {
  var parsed = vigolium.parse.url(records[i].url);
  if (vigolium.utils.hasDynamicSegment(parsed.path)) {
    vigolium.db.records.annotate(records[i].uuid, { risk_score: 50 });
    vigolium.log.info("Flagged: " + records[i].url);
  }
}
EOF
```

### 22. Session Logs (vigolium log)
```bash
# List all native + agentic sessions with log status
vigolium log ls
vigolium log                            # same as `log ls` when no UUID is given

# View a session's runtime.log (auto-follows if the session is still running)
vigolium log <scan-or-agent-uuid>

# Tail last N lines
vigolium log <uuid> --tail 500

# Show the full log
vigolium log <uuid> --full

# Follow live output (tail -f)
vigolium log <uuid> -f

# Strip ANSI color codes (useful when piping to a file)
vigolium log <uuid> --strip-ansi > run.txt

# Interactive TUI picker
vigolium log --tui
```

Log lookup order: agentic session `~/.vigolium/agent-sessions/<uuid>/runtime.log` → native session `~/.vigolium/native-sessions/<uuid>/runtime.log` → `scan_logs` DB table (fallback when `scanning_strategy.scan_logs.persist_logs` is disabled). The legacy `run.log` filename is still resolved for older sessions.

### 23. Data Import (vigolium import)
```bash
# Import an archon audit output folder (contains audit-state.json + findings-draft/)
vigolium import /path/to/archon-output-harbor/

# Import a JSONL export (supports http_record and finding envelopes)
vigolium import scan-results.jsonl
vigolium import /tmp/demo/juice-shop.jsonl
```

Archon folders create a new agentic_scan row plus findings. JSONL imports accept `{"type": "http_record", "data": {...}}` and `{"type": "finding", "data": {...}}` envelopes — the format produced by `vigolium export --format jsonl`.

### 24. Initialization & Reset
```bash
# Create ~/.vigolium with defaults (config, DB schema, profiles, prompts, extensions, SAST rules)
vigolium init

# Regenerate the API key and re-extract all preset data
vigolium init --force

# Wipe ~/.vigolium entirely and reinitialize (prompts for confirmation; use -F/--force to skip)
vigolium config clean

# Diagnose installation health (binaries, paths, permissions)
vigolium doctor
```

## Key Global Flags

These flags are available on all commands (persistent flags on root):

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--target` | `-t` | — | Target URL (repeatable) |
| `--target-file` | `-T` | — | File containing target URLs |
| `--input` | `-i` | `-` (stdin) | Input file path |
| `--input-mode` | `-I` | `urls` | Input format (openapi, burp, curl, har, etc.) |
| `--input-read-timeout` | — | `3m` | Timeout for reading input from stdin or file |
| `--concurrency` | `-c` | `50` | Concurrent scan workers |
| `--rate-limit` | `-r` | `100` | Max requests per second |
| `--max-per-host` | — | `30` | Max concurrent requests per host |
| `--max-host-error` | — | `30` | Skip host after this many consecutive errors |
| `--max-findings-per-module` | — | `10` | Stop reporting after N findings per module (0 = unlimited) |
| `--timeout` | — | `15s` | HTTP request timeout |
| `--scanning-max-duration` | — | — | Maximum total scan duration (e.g. 1h, 30m) |
| `--proxy` | — | — | HTTP/SOCKS5 proxy URL |
| `--modules` | `-m` | `all` | Scanner modules to enable (fuzzy match on ID/name) |
| `--module-tag` | — | — | Filter modules by tag (OR condition, repeatable) |
| `--strategy` | — | — | Scanning strategy preset (lite, balanced, deep, whitebox) |
| `--scanning-profile` | — | — | Scanning profile name or YAML file path |
| `--intensity` | — | — | Scan intensity preset: `quick`, `balanced`, `deep` (maps to profile + strategy) |
| `--heuristics-check` | — | `basic` | Pre-scan heuristics level: `none`, `basic`, `advanced` |
| `--skip-heuristics` | — | `false` | Disable pre-scan heuristics (same as `--heuristics-check=none`) |
| `--only` | — | — | Run only a single phase |
| `--skip` | — | — | Skip specific phases |
| `--format` | — | `console` | Output format: console, jsonl, html (comma-separated for multiple) |
| `--scan-on-receive` | `-S` | `false` | Continuously scan new HTTP records as they arrive in the database |
| `--native-scan-on-receive` | — | `false` | Run the full native scan pipeline continuously on received records |
| `--source` | — | — | Path to application source code |
| `--source-url` | — | — | Git URL to clone for source-aware scanning |
| `--scan-id` | — | — | Label for grouping scan session results |
| `--scope-origin` | — | — | Origin scope: all, relaxed, balanced, strict |
| `--project-id` | — | — | Project UUID to scope all operations to |
| `--project-name` | — | — | Project name to scope all operations to |
| `--verbose` | `-v` | `false` | Verbose logging |
| `--silent` | — | `false` | Suppress all output except findings |
| `--json` | `-j` | `false` | Format output as JSONL (one JSON object per line) |
| `--ci-output-format` | — | `false` | CI-friendly output: JSONL findings only, no color, no banners |
| `--debug` | — | `false` | Dump raw HTTP traffic |
| `--dump-traffic` | — | `false` | Print every HTTP request/response pair to stderr (Burp-style) |
| `--log-file` | — | — | Write all log output to this file (JSON format) |
| `--db` | — | `~/.vigolium/database-vgnm.sqlite` | SQLite database path |
| `--config` | — | `~/.vigolium/vigolium-configs.yaml` | Config file path |
| `--stateless` | — | `false` | Use a temporary database, export results to `--output`, then discard |
| `--no-clustering` | — | `false` | Disable de-duplication of identical concurrent HTTP requests |
| `--force` | `-F` | `false` | Skip confirmation prompts |
| `--list-modules` | `-M` | `false` | List all scanner modules |
| `--list-input-mode` | — | `false` | List all supported input modes with examples |
| `--watch` | — | — | Re-run on interval (e.g. 10s, 1m, 5m) |
| `--width` | — | `70` | Max column width for tables |
| `--ext` | — | — | Load JavaScript extension script (repeatable) |
| `--ext-dir` | — | — | Override extension scripts directory |
| `--full-example` | — | `false` | Show full example commands organized by section |

## Scan-Specific Flags

These flags apply to `scan`, `scan-url`, `scan-request`, and `run` commands:

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--output` | `-o` | — | Write findings / reports to this file path |
| `--stats` | — | `false` | Show live progress stats during scanning |
| `--include-response` | — | `false` | Include full HTTP response body in output |
| `--retries` | — | `1` | Number of retry attempts for failed requests |
| `--stream` | — | `false` | Process targets as a stream without buffering or deduplication |
| `--header` | `-H` | — | Add custom HTTP header (repeatable, e.g. `-H 'Auth: Bearer tok'`) |
| `--advanced-options` | `-a` | — | Module-specific options as key=value (e.g. `-a xss.dom=true`) |
| `--required-only` | — | `false` | Parse only required fields from input format (ignore optional) |
| `--skip-format-validation` | — | `false` | Skip validation of input file format |
| `--upload-results` | — | `false` | Upload scan results to cloud storage after completion (requires storage config) |
| `--stateless` | — | `false` | Use a temporary database, export to `--output`, then discard |
| `--auth-config` | — | — | Path to auth-config file with session definitions |
| `--session` | — | — | Inline session for IDOR/BOLA testing (format: `name:Header:value`, repeatable) |
| `--session-file` | — | — | Path to individual session file (YAML or JSON, repeatable) |
| `--oast-url` | — | — | Fixed out-of-band callback URL |
| `--discover` | — | `false` | Enable content discovery phase before scanning |
| `--discover-max-time` | — | `1h` | Max time for content discovery per target |
| `--fuzz-wordlist` | — | — | Custom fuzz wordlist path (enables fuzzing during discovery) |
| `--no-prefix-breaker` | — | `false` | Disable per-prefix circuit breaker that stops trap-directory recursion |
| `--spider` | — | `false` | Enable browser-based spidering phase before scanning |
| `--spider-max-time` | — | `30m` | Max time for spidering per target |
| `--browser-engine` | `-E` | `chromium` | Browser engine: `chromium`, `ungoogled`, `fingerprint` |
| `--browsers` | `-b` | `1` | Number of parallel browser instances for spidering |
| `--headless` | — | `true` | Run browser in headless mode |
| `--no-cdp` | — | `false` | Disable Chrome DevTools Protocol event listener detection |
| `--no-forms` | — | `false` | Disable automatic form detection and filling |
| `--external-harvest` | — | `false` | Enable external intelligence gathering (Wayback, CT logs, etc.) |
| `--known-issue-scan-tags` | — | — | Nuclei template tags to include (repeatable) |
| `--known-issue-scan-severities` | — | — | Filter Nuclei templates by severity (repeatable) |
| `--known-issue-scan-exclude-tags` | — | — | Nuclei template tags to exclude (repeatable) |
| `--known-issue-scan-templates-dir` | — | — | Custom Nuclei templates directory |
| `--sast-adhoc` | — | — | Local path or git URL for ad-hoc SAST scan (auto-detected) |
| `--rule` | — | — | Filter SAST rules by fuzzy name match |

## Constraints

- `--only` and `--skip` are mutually exclusive
- `--format html` requires `-o/--output`; multiple `--format` values also require `-o/--output`
- `--format html` is only supported for the `discovery` and `spidering` phases when combined with `--only`
- `--target/-t` and `--spec-url` are mutually exclusive for ingest
- `--source` and `--source-url` are mutually exclusive
- `--stateless` requires `-o/--output`; `--stateless` and `--db` are mutually exclusive
- `--ci-output-format` sets JSONL output, suppresses banners and color (implies `--json --silent`)
- `--skip-heuristics` is equivalent to `--heuristics-check=none`
- Server mode requires API key auth by default (use `-A`/`--no-auth` to disable, or set `VIGOLIUM_API_KEY`)
- Agent commands require agent backends configured in `vigolium-configs.yaml`. Default backend (`claude`) requires `claude` CLI in PATH
- `--scan-on-receive/-S` is ignored in remote ingest mode (server handles scanning)
- `db clean --all` requires `--force` for safety
- `db clean --force` with no filter flags resets the entire database (SQLite only)
- Whitebox/SAST phases require `--source <path>` or `--source-url <git-url>` to link application source code
- Phase aliases: `deparos`/`discover` = `discovery`, `spitolas` = `spidering`, `ext` = `extension`. The legacy alias `dynamic-assessment` is accepted for `audit`
- `--module-tag` uses OR logic: modules matching any specified tag are included
- `-m` and `--module-tag` merge results (union)
- Use `agent swarm --discover` for full-scope AI-guided scanning
- Agent swarm: `--source-analysis-only` requires `--source`; `--auth` requires `--browser`; `--archon` requires `--source`; `--target` is required when `--source` is used with a remote target
- Agent autopilot: archon-audit runs automatically when `--source` is set — use `--no-archon` to disable or `--archon-mode` to tune; `--timeout` default is `6h`
- Agent archon: `--mode` must be one of `lite`, `balanced` (alias `scan`), `deep`, `revisit`, `confirm`, `merge`, `diff`, `status`, `mock`; `--agent` must be `claude`, `codex`, or `opencode`
- Intensity presets (`--intensity quick|balanced|deep`) are shared across `scan`, `agent autopilot`, and `agent swarm`; explicit flags always override the preset
- `vigolium init` is a no-op on an existing installation unless `--force` is passed (regenerates API key + re-extracts preset data)
- `vigolium config clean` prompts for confirmation unless `-F/--force` is passed; it wipes the entire `~/.vigolium/` directory

## Resources

- **Website**: [www.vigolium.com](https://www.vigolium.com/)
- **Documentation**: [docs.vigolium.com](https://docs.vigolium.com/)
- **GitHub**: [github.com/vigolium/vigolium](https://github.com/vigolium/vigolium)
