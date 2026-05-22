---
name: vigolium-scanner
description: >-
  Use when operating the vigolium CLI for web vulnerability scanning, security testing,
  traffic ingestion, server management, AI agent-driven scanning and code review,
  cloud-storage management, or writing custom JavaScript extensions. Invoke for
  scan commands, scan-url, scan-request, run, ingest, server, agent
  (query/autopilot/swarm/olium/piolium/audit/session), traffic browsing,
  database queries, storage uploads/downloads, module management, extension
  scripting, export, project management, and configuration tuning.
license: MIT
metadata:
  version: "3.3.0"
  domain: security-tooling
  triggers: >-
    vigolium, scan, scan-url, scan-request, run, ingest, server, agent, agent query,
    agent autopilot, agent swarm, agent olium, agent piolium,
    agent audit, agent session, vigolium olium, vigolium ol, vigolium-audit,
    piolium, pi-coding-agent, traffic, db, module, extensions, js, export, strategy,
    scope, source, config, project, storage, vigolium init, vigolium import,
    vigolium log, vigolium doctor, config clean, vulnerability scanner, security
    scan, DAST, audit, openapi scan, burp import, HAR import, whitebox scanning,
    SAST, javascript extension, custom scanner, module-tag, run extension,
    vigolium js, intensity, diff scan, last commits, stateless scan,
    upload results, runtime log, session log, google-vertex, gcp-project,
    gcp-location, vertex provider, anthropic-vertex, claude-on-vertex, gemini,
    openai-compatible, ollama, audit driver
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
- **AI agent integration** (all dispatch flows through the in-process **olium** engine — no subprocess SDK backends):
  - `agent query` — single-shot prompt (template-based or inline) for code review / endpoint discovery
  - `agent autopilot` — autonomous AI-driven scanning that drives the vigolium CLI
  - `agent swarm` — AI-guided targeted or full-scope scanning (add `--discover` for full-scope)
  - `agent olium` (alias `vigolium olium` / `ol`) — interactive TUI / one-shot olium agent
  - `agent piolium` — foreground audit using the Pi-native piolium runtime
  - `agent audit` — unified driver dispatcher driving the embedded vigolium-audit harness and/or piolium (`--driver=auto|both|audit|piolium`; replaces the former `agent archon`)
  - `agent session` — list / inspect agent run sessions
- **Extension runner**: `run extension --ext custom-check.js` for custom JS scanning logic
- **JavaScript executor**: `js` for ad-hoc scripting with full `vigolium.*` API access
- **Session log viewer**: `log <uuid>` streams `runtime.log` for native + agentic sessions (tail / follow / DB fallback)
- **Data import**: `import <path>` ingests audit output folders (`vigolium-results/`) and JSONL exports
- **Cloud storage**: `storage ls/upload/download/rm/presign/results` manages per-project objects in the configured bucket
- **Lifecycle**: `init` sets up `~/.vigolium/`, `config clean` wipes it back to a fresh state

Olium provider drivers (set via `agent.olium.provider` or `--provider`):
- **`openai-compatible`** (default): any OpenAI Chat-Completions-compatible endpoint via `agent.olium.custom_provider.base_url` / `model_id` (default points at a local Ollama at `http://localhost:11434/v1`, model `gemma4:latest`)
- **`openai-codex-oauth`**: OpenAI Codex via `~/.codex/auth.json` (ChatGPT subscription)
- **`anthropic-api-key`**: Anthropic Messages API via `$ANTHROPIC_API_KEY` / `--llm-api-key`
- **`anthropic-oauth`**: Anthropic Claude via Claude Code OAuth bearer token (`claude setup-token`)
- **`openai-api-key`**: OpenAI Chat Completions via `$OPENAI_API_KEY` / `--llm-api-key`
- **`anthropic-cli`**: Shells out to the local `claude` CLI binary (Claude Max subscribers)
- **`anthropic-vertex`**: Anthropic Claude on GCP Vertex AI via service-account JSON (`--oauth-cred` / `$GOOGLE_APPLICATION_CREDENTIALS`); requires a `claude-*` model (e.g. `claude-opus-4-6`)
- **`google-vertex`**: Gemini-native on GCP Vertex AI via service-account JSON; requires a `gemini-*` model (e.g. `gemini-3.1-pro`)

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
| Swarm with background vigolium-audit | `vigolium agent swarm -t <url> --source ./src --audit lite` |
| Swarm with custom instructions | `vigolium agent swarm -t <url> --instruction "Focus on GraphQL"` |
| Source analysis only (no scan) | `vigolium agent swarm -t <url> --source ./src --source-analysis-only` |
| Foreground vigolium-audit (lite/balanced/deep) | `vigolium agent audit --driver=audit --mode deep --source .` |
| Audit a remote repo | `vigolium agent audit --driver=audit --mode lite --source https://github.com/org/repo` |
| Confirm PoCs for existing findings | `vigolium agent audit --driver=audit --mode confirm --source ./audit-tree` |
| Drive the audit yourself interactively | `vigolium agent audit -i --source ./src` |
| Foreground piolium (Pi-native) audit | `vigolium agent piolium --mode balanced --source .` |
| Piolium hail-mary file-by-file hunt | `vigolium agent piolium --mode longshot --source ./src --plm-longshot-langs python,go` |
| Piolium with custom Pi provider/model | `vigolium agent piolium --pi-provider vertex-anthropic --pi-model claude-opus-4-6 --source .` |
| Run vigolium-audit, fall back to piolium only if no claude/codex CLI | `vigolium agent audit --source .` |
| Run vigolium-audit + piolium back-to-back unconditionally | `vigolium agent audit --driver=both --source .` |
| Run only one driver under unified audit | `vigolium agent audit --driver=audit --source .` |
| Audit from a gs:// archive | `vigolium agent audit --source gs://my-project/snapshots/app.tar.gz` |
| Interactive olium TUI | `vigolium olium` (alias `vigolium ol`) |
| One-shot olium prompt to stdout | `vigolium olium -p "explain this codebase"` |
| Olium via anthropic-vertex (Claude on Vertex) | `vigolium olium --provider anthropic-vertex --gcp-project my-gcp --gcp-location us-east5 --model claude-opus-4-6` |
| Olium via google-vertex (Gemini-native) | `vigolium olium --provider google-vertex --model gemini-3.1-pro` |
| Browse stored HTTP traffic | `vigolium traffic` or `vigolium traffic <search>` |
| Browse findings/vulnerabilities | `vigolium finding` or `vigolium db ls --table findings` |
| Replay one request with mutations + baseline diff (external-agent confirm step) | `vigolium replay --record-uuid <uuid> -m 'name=id,payload=1 OR 1=1'` |
| Replay a finding's HTTP evidence with a payload | `vigolium replay --finding-id 42 -m 'name=q,payload=<svg/onload=alert(1)>'` |
| Replay an arbitrary curl/raw/burp/base64/URL input | `vigolium replay -i "curl -X POST <url> -d '...'"` |
| Persist cookies across replays (multi-step auth) | `vigolium replay --session-id login --record-uuid <uuid>` |
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
| List cloud-storage objects for current project | `vigolium storage ls` (add `--prefix ugc/` or `--tree`) |
| Upload a file to project storage | `vigolium storage upload ./report.pdf --key reports/q4.pdf` |
| Download an object | `vigolium storage download ugc/foo.tar.gz -o foo.tar.gz` |
| Download a scan's result bundle | `vigolium storage results <scan-uuid>` |
| Generate a presigned GET/PUT URL | `vigolium storage presign --key ugc/foo.tar.gz --method GET --expiry 1h` |
| Delete cloud-storage objects | `vigolium storage rm ugc/foo.tar.gz` (add `-F` to skip confirm) |
| List agent sessions | `vigolium agent session` or `vigolium agent session <uuid>` |
| Seed database with sample data | `vigolium db seed` |
| Import findings from file | `vigolium finding load -i findings.jsonl` |
| Import audit output folder or JSONL export | `vigolium import <path>` |
| View runtime logs for a scan/agent session | `vigolium log <uuid>` (add `-f` to follow, `--tail N`) |
| List all native + agentic sessions with log status | `vigolium log ls` |
| Initialize `~/.vigolium/` with defaults | `vigolium init` (add `--force` to regenerate) |
| Wipe `~/.vigolium/` and reinitialize | `vigolium config clean` |
| Validate extension files | `vigolium ext lint --ext custom-check.js` |
| Evaluate JS inline | `vigolium ext eval 'vigolium.log.info("hello")'` |
| Manage auth (lint, list, load, totp) | `vigolium auth lint` / `auth list` / `auth load` / `auth totp` |
| Run health check on installation | `vigolium doctor` |

## Reference Guide

Load detailed reference based on what you need:

| Topic | Reference | Load When |
|-------|-----------|-----------|
| Scanning commands | `references/scanning-commands.md` | scan, scan-url, scan-request, run flags and options |
| Server & ingestion | `references/server-and-ingestion.md` | server, ingest, traffic command flags |
| Agent commands | `references/agent-commands.md` | agent, agent query, agent autopilot, agent swarm, agent olium, agent piolium, agent audit, agent session — flags, intensities, providers, templates |
| Session / auth config | `references/session-auth-config.md` | --auth-file/--auth flags, YAML format, extract rules, authenticated scanning setup |
| Data & management | `references/data-and-management.md` | db, module, extensions, js, config, scope, source, strategy, export, project, storage |
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

Autopilot runs a single autonomous operator session that drives the vigolium CLI (Read/Grep/Glob/Bash/Edit/Write tools via the in-process olium engine). When `--source` is set, an audit harness runs first and the prepared whitebox context is fed to the operator.

**Audit-harness auto-pick:** when neither `--audit` nor `--piolium` is set, autopilot picks **piolium** if `pi` + the piolium extension are installed, otherwise falls back to the embedded **vigolium-audit** at its lite default. Pass `--piolium <mode>` to force piolium (auto-disables vigolium-audit for the run); pass `--audit <mode>` to force vigolium-audit; pass `--audit=off` to disable both.

Intensity presets (`--intensity`) bundle the operator command budget, audit mode, browser, and pre-scan strategy into a single flag. Explicit flags always override. The `Command Budget` is internal — there is no `--max-commands` flag.

| Preset | Command Budget | Timeout | Audit Mode | Browser |
|--------|---------------:|--------:|------------|:-------:|
| `quick` | 150 | 1h | `lite` | on |
| `balanced` (default) | 500 | 6h | `balanced` | on |
| `deep` | 1500 | 12h | `deep` | on |

```bash
# Basic autonomous scan (balanced by default)
vigolium agent autopilot -t https://example.com

# Natural-language prompt — target, source, focus are auto-extracted
vigolium agent autopilot "scan VAmPI source at ~/src/VAmPI on localhost:3005"
vigolium agent autopilot "test auth bypass on https://app.example.com"

# With source code context (triggers the audit harness automatically)
vigolium agent autopilot -t https://example.com --source ./src

# Specific files + custom instruction
vigolium agent autopilot -t https://example.com --source ./src \
  --files "routes/api.js,controllers/auth.js" \
  --instruction "Focus on the new payment endpoint"

# Intensity presets
vigolium agent autopilot -t https://example.com --source ./src --intensity quick  # CI/PR
vigolium agent autopilot -t https://example.com --intensity deep                   # full pentest

# Override a specific setting within a preset
vigolium agent autopilot -t https://example.com --intensity deep --max-duration 4h

# Scan only a PR diff or recent commits
vigolium agent autopilot -t https://example.com --source ./src --diff main...feature-branch
vigolium agent autopilot -t https://example.com --source ./src --last-commits 3

# Cap the wall-clock budget (explicit override)
vigolium agent autopilot -t https://example.com --max-duration 15m

# Pipe a curl command (target auto-derived)
echo "curl -X POST https://example.com/api/login -d '{\"user\":\"admin\"}'" | vigolium agent autopilot

# Browser-based auth preflight
vigolium agent autopilot -t https://example.com --browser --credentials "admin/admin123"
vigolium agent autopilot -t https://example.com --browser --auth-required \
  --browser-start-url https://example.com/login

# Disable the audit harness when source is provided
vigolium agent autopilot -t https://example.com --source ./src --audit=off

# Choose a specific vigolium-audit mode
vigolium agent autopilot -t https://example.com --source ./src --audit deep

# Force piolium as the audit harness (auto-disables vigolium-audit for this run)
vigolium agent autopilot -t https://example.com --source ./src --piolium balanced

# Run an AI triage pass over findings after the scan
vigolium agent autopilot -t https://example.com --triage

# Skip the prompt-safety classifier on the natural-language prompt (only when refusing a known-good prompt)
vigolium agent autopilot "scan this internal app at https://app.test" --disable-guardrail

# Upload results to cloud storage after completion
vigolium agent autopilot -t https://example.com --source ./src --upload-results

# Preview rendered system prompt without launching the agent
vigolium agent autopilot -t https://example.com --dry-run

# Override the olium provider for a single run
vigolium agent autopilot -t https://example.com --provider anthropic-api-key

# Drive autopilot through anthropic-vertex (Claude on Vertex; requires a claude-* model)
vigolium agent autopilot -t https://example.com \
  --provider anthropic-vertex --gcp-project my-gcp --gcp-location us-east5 --model claude-opus-4-6
```

### 13. AI Agent Swarm (Targeted or Full-Scope)

Swarm orchestrates: normalize → source analysis (AI, `--source`) → code audit (AI) → SAST (native) → SAST review (AI) → discover (native, `--discover`) → plan (AI) → extension (Go) → native scan → triage (AI, `--triage`) → rescan (loop).

Intensity presets (`--intensity`) bundle multiple defaults — explicit flags always override. The preset applies even without `--intensity` (`balanced` is the implicit default). Code Audit only takes effect with `--source`; Auth only with the browser enabled.

| Preset | Discover | Triage | Code Audit | Browser | Auth | Swarm Duration | Max Iterations |
|--------|:--------:|:------:|:----------:|:-------:|:----:|---------------:|---------------:|
| `quick` | on | off | off | on | off | 2h | 1 |
| `balanced` (default) | on | on | on | on | off | 12h | 3 |
| `deep` | on | on | on | on | on | 24h | 5 |

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

# Run a background vigolium-audit in parallel (requires --source). Bare --audit = lite.
vigolium agent swarm -t http://localhost:3000 --source ./src --audit
vigolium agent swarm -t http://localhost:3000 --source ./src --audit deep

# Or run piolium as the background audit harness (Pi runtime; requires --source)
vigolium agent swarm -t http://localhost:3000 --source ./src --piolium balanced

# Pull HTTP records from the active project as input
vigolium agent swarm --all-records
vigolium agent swarm --records-from "host=example.com,status=200,method=GET,path=/api,since=2026-04-01"
vigolium agent swarm --record-uuid 550e8400-...,7c9b1a2d-...   # repeatable / comma-separated

# Force the extension agent to run even when the planner picks built-in modules
vigolium agent swarm -t https://example.com/api --with-extensions

# Tune master-agent batching and probing
vigolium agent swarm --all-records --master-batch-size 10 --batch-concurrency 4 \
  --probe-concurrency 20 --probe-timeout 15s --max-plan-records 25

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
vigolium agent swarm -t https://example.com --browser --browser-auth \
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
vigolium agent swarm -t https://example.com --max-duration 24h

# Preview master agent prompt (no execution)
vigolium agent swarm -t https://example.com/api/users --dry-run

# Show rendered prompts during execution
vigolium agent swarm -t https://example.com/api/users --show-prompt
```

### 13b. AI Agent Audit — vigolium-audit harness (Foreground Whitebox Audit)

The former `agent archon` command is gone. Drive the embedded **vigolium-audit** harness directly with `vigolium agent audit --driver=audit` (`--driver=audit` pins the single harness; the dispatcher in §13d covers `auto`/`both`).

```bash
# Deep audit of a local repo
vigolium agent audit --driver=audit --mode deep --source .

# Fast lite audit of a remote repo (clones automatically)
vigolium agent audit --driver=audit --mode lite --source https://github.com/org/repo

# Balanced audit
vigolium agent audit --driver=audit --mode balanced --source ~/code/myapp

# Second pass on a prior audit tree (revisit with new context)
vigolium agent audit --driver=audit --mode revisit --source ./prior-audit-tree

# PoC construction for previously confirmed findings
vigolium agent audit --driver=audit --mode confirm --source ./audit-with-findings

# Chain modes back-to-back (audit runs them natively as one row)
vigolium agent audit --driver=audit --modes deep,refresh,confirm --source .

# Read-only progress check (no agent launched)
vigolium agent audit --driver=audit --mode status --source ./in-progress-audit

# Pick the coding agent (claude or codex) — provider implies one, --agent overrides
vigolium agent audit --driver=audit --agent codex --source .

# Drive the audit yourself interactively, then import the on-disk results
vigolium agent audit -i --source ./src
vigolium import ./src/vigolium-results --format html -o audit-report.html

# List the audit mode graph (phases, time estimates) and exit
vigolium agent audit --list-modes
```

Valid `--mode` values (audit leg): `lite`, `balanced`, `deep`, `revisit`, `confirm`, `merge` (shared) plus `reinvest`, `refresh`, `mock`, `diff`, `status` (audit-specific). The audit leg drives the `claude` or `codex` CLI directly (selected by `--provider`/`--agent`). `--no-preflight` and `--preflight-timeout` skip / tune the pre-launch CLI roundtrip; `--show-thinking` surfaces the agent's thinking blocks; `--keep-raw` preserves raw scanner output under `<source>/vigolium-results/`.

### 13c. AI Agent Piolium (Pi-Native Foreground Audit)

Drives the user's installed piolium Pi extension via `pi --mode json -p /piolium-<mode>`. Requires `pi` in PATH and `piolium` registered (install via `pi install git:git@github.com:vigolium/piolium.git`). Same on-disk schema as vigolium-audit (audit-state.json + findings-draft/), tagged separately in the DB.

```bash
# Balanced 9-phase audit of a local repo
vigolium agent piolium --mode balanced --source .

# Quick lite audit of a remote git URL (auto-clones)
vigolium agent piolium --mode lite --source https://github.com/org/repo

# Hail-mary file-by-file vulnerability hunt over Python+Go files only
vigolium agent piolium --mode longshot --source ./src \
  --plm-longshot-langs python,go --plm-longshot-limit 200

# Use a specific Pi provider/model for this run (overrides ~/.pi defaults)
vigolium agent piolium --pi-provider vertex-anthropic --pi-model claude-opus-4-6 --source .

# Full clone history (commit archaeology) via intensity preset
vigolium agent piolium --intensity deep --source https://github.com/org/repo

# Cap commit-history scan to last 60 days
vigolium agent piolium --mode balanced --source . --plm-scan-since "60 days ago"

# Resume / re-audit an existing tree (anti-anchored second pass)
vigolium agent piolium --mode revisit --source ./prior-piolium-tree

# Read-only progress check on an in-progress run
vigolium agent piolium --mode status --source ./in-progress-piolium

# Skip the pre-audit pi roundtrip check (auth + model availability)
vigolium agent piolium --mode balanced --source . --no-preflight
```

Valid `--mode` values: `lite`, `balanced`, `deep`, `revisit`, `confirm`, `merge`, `diff`, `longshot`, `status`, `smoke`. Intensity presets: `quick` (lite + shallow clone), `balanced` (default), `deep` (deep + full clone history). Piolium passthroughs (forwarded as `--plm-*` to piolium itself): `--plm-scan-limit`, `--plm-scan-since`, `--plm-phase-retries`, `--plm-command-retries`, `--plm-longshot-limit`, `--plm-longshot-timeout`, `--plm-longshot-langs`.

### 13d. AI Agent Audit (Unified Driver Dispatcher)

Drives the embedded **vigolium-audit** harness (driver name `audit`) and/or **piolium** against the same source tree under a **single parent AgenticScan UUID**. Default `--driver=auto` runs vigolium-audit and **only falls back to piolium when the resolved claude/codex CLI is missing** from PATH — a clean audit run never consults piolium, and a mid-run audit failure surfaces directly rather than silently retrying. `--driver=both` runs audit then piolium unconditionally. A project-wide post-pass findings dedup runs after the drivers finish. Per-driver child rows + session subdirs (`{session}/audit/`, `{session}/piolium/`) keep them separated on disk and in the DB while still scoring as one logical audit.

```bash
# Default: run vigolium-audit, fall back to piolium only if claude/codex CLI is missing
vigolium agent audit --source .

# Run both drivers back-to-back, unconditionally
vigolium agent audit --driver=both --source .

# Force a single driver
vigolium agent audit --driver=audit --source .
vigolium agent audit --driver=piolium --source ./src

# Driver-specific modes are only allowed when --driver is forced to that driver
vigolium agent audit --driver=piolium --source . --mode longshot
vigolium agent audit --driver=audit   --source . --mode mock

# Audit from a gs:// archive (downloaded + extracted once, shared by both drivers)
vigolium agent audit --source gs://my-project/snapshots/app.tar.gz

# Skip the post-pass project-wide findings dedup
vigolium agent audit --source . --no-dedup

# Pin the audit leg's agent + provider (anthropic-* → claude, openai-* → codex)
vigolium agent audit --source . --provider anthropic-oauth
vigolium agent audit --source . --agent codex

# BYOK auth for the run (literal, $ENV_NAME, or @path)
vigolium agent audit --source . --oauth-token "$(cat ~/.config/claude-token)"

# Override piolium's Pi defaults
vigolium agent audit --driver=piolium --source . --pi-provider google-vertex --pi-model gemini-3.1-pro

# Pass piolium-only knobs through (ignored on the audit leg)
vigolium agent audit --driver=piolium --source . --plm-scan-since "30 days ago" --plm-longshot-langs python
```

Under `--driver=auto`/`both`, `--mode` is restricted to the **shared** set: `lite`, `balanced`, `deep`, `revisit`, `confirm`, `merge`. Driver-specific modes (piolium's `longshot`/`smoke`/`diff`/`status`, audit's `reinvest`/`refresh`/`mock`/`diff`/`status`) require forcing `--driver=piolium` or `--driver=audit`. `--intensity deep` resolves to the chain `deep,confirm`; `--modes a,b,c` chains modes back-to-back. Under `--driver=both`, if one driver fails the other still runs — the parent run reports per-driver status.

### 14. Results Inspection
```bash
# Browse HTTP traffic
vigolium traffic
vigolium traffic login          # fuzzy search
vigolium traffic --tree         # hierarchical view
vigolium traffic --burp         # Burp-style colored output
vigolium traffic --host api.example.com --method POST

# JSONL output for agent / CI consumption (one JSON object per line)
vigolium traffic -j --host api.example.com
vigolium finding -j --severity high,critical
vigolium db ls -j --table findings
vigolium db stats -j

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

### 14b. External-Agent Confirm Chain (Claude Code / Cursor / Pi)

External agents driving vigolium externally (Claude Code, Cursor, Pi, CI
scripts) follow this discover → confirm → review chain:

1. **Discover** — pull what vigolium already knows in JSONL:
   ```bash
   vigolium traffic -j --host api.example.com --method POST --status 200,500
   vigolium finding -j --severity high,critical --finding-source audit
   ```
   Each line is one record/finding; pipe through `jq` to filter.

2. **Confirm** — mutate one request and diff the result:
   ```bash
   vigolium replay --record-uuid <uuid> -m 'name=id,payload=1 OR 1=1' \
                   --session-id login           # persist cookies between calls
   ```
   `vigolium replay` is the CLI surface for the in-process `replay_request`
   tool. Accepts every input shape the agents accept — `--record-uuid`,
   `--finding-id`, or `--input` for curl / raw HTTP / Burp XML / base64 /
   URL / stdin (`-`). Output is stable JSON: `result.baseline`,
   `result.replay`, `result.diff` (status delta, length delta,
   content-hash, payload reflection, interpretation). Use `--pretty` for a
   human summary.

3. **Persist auth state** — multi-step flows (login → CSRF → action) need
   cookies between calls:
   ```bash
   vigolium replay --session-id login -i curl-login.sh         # sets cookies
   vigolium replay --session-id login --record-uuid <action>   # uses cookies
   ```
   Jar lives at `~/.vigolium/replay-jars/<session-id>.json`; pass
   `--no-cookies` to opt out.

4. **Replay a finding's evidence** — when a finding came from an
   imported source (audit, JSONL) with no linked record, `--finding-id`
   falls back to the finding's stored Request/Response bytes:
   ```bash
   vigolium replay --finding-id 42 -m 'name=q,payload=<svg/onload=alert(1)>'
   ```

5. **Confirm against a different env** — `--target` rewrites the
   destination while keeping the baseline request bytes intact:
   ```bash
   vigolium replay --record-uuid <prod-uuid> --target https://staging.example.com
   ```

6. **Update the stored baseline** — `--in-replace` writes the replay's
   response back to the source record (only when the source is a stored
   HTTPRecord):
   ```bash
   vigolium replay --record-uuid <uuid> -m '...' --in-replace
   ```

Routes through `HTTP_PROXY` / `HTTPS_PROXY` (or `--proxy`) for Burp
inspection. Honors `--project-uuid` / `--project-name` for project
scoping. Mutations support both forms: `--mutate 'name=id,payload=1 OR 1=1'`
or shorthand `--mutate 'id:URL_PARAM:1 OR 1=1'`.

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

### 18b. Cloud Storage (`vigolium storage`)

Manage cloud-storage objects scoped to the active project (mirrors `/api/storage/*`). Requires `storage.enabled: true` plus `driver`, `bucket`, `access_key`, `secret_key` in `vigolium-configs.yaml` (or `VIGOLIUM_STORAGE_ENABLED=true`).

```bash
# List all objects under the active project
vigolium storage ls
vigolium storage ls --prefix ugc/                # scope to a sub-path
vigolium storage ls --tree                       # render as a directory tree
vigolium storage ls --json                       # machine-readable

# Upload a single file
vigolium storage upload ./report.pdf                       # → ugc/report.pdf
vigolium storage upload ./report.pdf --key reports/q4.pdf  # explicit key
vigolium storage upload ./report.pdf --content-type application/pdf

# Download an object (streams to stdout by default)
vigolium storage download ugc/report.pdf -o report.pdf

# Download a scan's result bundle (tries native-scans/ then agentic-scans/)
vigolium storage results 550e8400-e29b-41d4-a716-446655440000

# Generate a presigned GET or PUT URL for direct upload/download
vigolium storage presign --key ugc/foo.tar.gz --method GET --expiry 1h
vigolium storage presign --key ugc/foo.tar.gz --method PUT --expiry 30m --json

# Delete one or more objects (prompts unless -F)
vigolium storage rm ugc/foo.tar.gz
vigolium storage rm ugc/a.pdf ugc/b.pdf -F
```

Many agent and scan commands accept a `--source gs://<project>/<key>` URL for source archives — they're downloaded, extracted (`.zip / .tar.gz / .tar.bz2 / .tar.xz`), and cleaned up automatically. Use `--upload-results` on `scan`, `agent autopilot`, `agent swarm`, `agent audit`, `agent piolium`, and `agent query` to bundle the session/output and push it to storage at the end of the run.

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
# Import an audit output folder (contains audit-state.json + findings-draft/)
vigolium import /path/to/vigolium-results/

# Import a JSONL export (supports http_record and finding envelopes)
vigolium import scan-results.jsonl
vigolium import /tmp/demo/juice-shop.jsonl
```

Audit output folders (produced by `vigolium agent audit` — vigolium-audit or piolium leg) create a new agentic_scan row plus findings. JSONL imports accept `{"type": "http_record", "data": {...}}` and `{"type": "finding", "data": {...}}` envelopes — the format produced by `vigolium export --format jsonl`.

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
| `--full-native-scan-on-receive` | — | `false` | Run the full native scan pipeline (discovery + spidering + dynamic-assessment) continuously on received records |
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
| `--omit-response` | — | `false` | Omit raw HTTP request/response bytes from the output file (keeps metadata, smaller files) |
| `--retries` | — | `1` | Number of retry attempts for failed requests |
| `--stream` | — | `false` | Process targets as a stream without buffering or deduplication |
| `--header` | `-H` | — | Add custom HTTP header (repeatable, e.g. `-H 'Auth: Bearer tok'`) |
| `--advanced-options` | `-a` | — | Module-specific options as key=value (e.g. `-a xss.dom=true`) |
| `--required-only` | — | `false` | Parse only required fields from input format (ignore optional) |
| `--skip-format-validation` | — | `false` | Skip validation of input file format |
| `--upload-results` | — | `false` | Upload scan results to cloud storage after completion (requires storage config) |
| `--stateless` | — | `false` | Use a temporary database, export to `--output`, then discard |
| `--auth-file` | — | — | Path to auth file (YAML/JSON: single session or `sessions:` bundle), or bare name resolved against `scanning_strategy.session.session_dir`. Repeatable. |
| `--auth` | — | — | Inline session in `name:Header:value` format. Repeatable. |
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
- Agent commands route every dispatch through the in-process **olium** engine; configure under `agent.olium.*` in `vigolium-configs.yaml`. Default provider `openai-compatible` points at a local Ollama (`http://localhost:11434/v1`, model `gemma4:latest`) via `custom_provider`. `openai-codex-oauth` reads `~/.codex/auth.json`; `anthropic-cli` needs `claude` in PATH; `anthropic-vertex` (Claude, `claude-*` model) and `google-vertex` (Gemini, `gemini-*` model) need a GCP service-account JSON via `--oauth-cred` or `$GOOGLE_APPLICATION_CREDENTIALS`
- The `--provider`, `--model`, `--oauth-cred`, `--oauth-token`, `--llm-api-key`, `--gcp-project`, `--gcp-location` flags override `agent.olium.*` for one run on `agent query`, `agent autopilot`, `agent swarm`, and `agent olium` (and the top-level `vigolium olium` / `ol` alias)
- `--scan-on-receive/-S` is ignored in remote ingest mode (server handles scanning)
- `db clean --all` requires `--force` for safety
- `db clean --force` with no filter flags resets the entire database (SQLite only)
- Whitebox/SAST phases require `--source <path>` or `--source-url <git-url>` to link application source code
- Phase aliases: `deparos`/`discover` = `discovery`, `spitolas` = `spidering`, `ext` = `extension`. The legacy alias `dynamic-assessment` is accepted for `audit`
- `--module-tag` uses OR logic: modules matching any specified tag are included
- `-m` and `--module-tag` merge results (union)
- Use `agent swarm --discover` for full-scope AI-guided scanning
- Agent swarm: `--source-analysis-only` requires `--source`; `--browser-auth` requires `--browser`; `--audit` requires `--source`; `--target` is required when `--source` is used with a remote target
- Agent autopilot: when `--source` is set, an audit harness runs automatically — auto-picks **piolium** if `pi`+piolium are installed, otherwise the embedded **vigolium-audit** at lite. Force with `--piolium <mode>` (auto-disables vigolium-audit) or `--audit <mode>`; disable with `--audit=off`. `--max-duration` default is `6h` (there is no `--max-commands`/`--token-budget` flag — the command budget is set by `--intensity`). `--triage` runs an AI triage pass after the scan; `--disable-guardrail` skips the prompt-safety classifier on the natural-language prompt
- Agent audit: `--driver` must be `auto` (default), `both`, `audit`, or `piolium`. `auto` runs vigolium-audit and only falls back to piolium when the resolved claude/codex CLI is missing; `both` runs audit then piolium unconditionally. Under `auto`/`both`, `--mode` is restricted to the shared set (`lite`, `balanced`, `deep`, `revisit`, `confirm`, `merge`); driver-specific modes (audit's `reinvest`/`refresh`/`mock`/`diff`/`status`, piolium's `longshot`/`smoke`/`diff`/`status`) require forcing `--driver=audit|piolium`. `--intensity deep` resolves to the chain `deep,confirm`; `--modes a,b,c` chains modes. Audit-leg agent is selected by `--provider` (anthropic-*→claude, openai-*→codex) and `--agent {claude|codex}`, with BYOK via `--api-key`/`--oauth-token`/`--oauth-cred-file`. `-i/--interactive` hands you the audit harness (audit-only). `--driver=audit\|piolium` hard-errors on a missing runtime; under `both` a missing runtime is dropped with a warning. Post-pass project-wide findings dedup runs when a project UUID is set; suppress with `--no-dedup`
- Agent piolium: `--mode` must be one of `lite`, `balanced`, `deep`, `revisit`, `confirm`, `merge`, `diff`, `longshot`, `status`, `smoke`. Requires `pi` in PATH and the piolium Pi extension installed. `--no-preflight` skips the pre-audit `pi` roundtrip
- Intensity presets (`--intensity quick|balanced|deep`) are shared across `scan`, `agent autopilot`, `agent swarm`, `agent audit`, and `agent piolium`; explicit flags always override the preset
- `vigolium storage *` commands require `storage.enabled: true` (or `VIGOLIUM_STORAGE_ENABLED=true`) plus driver/bucket/access-key/secret-key configured. They scope to the active project (`--project-id` / `--project-name` / `VIGOLIUM_PROJECT`)
- `--source` accepts a local path, a git URL (auto-cloned with `--commit-depth`), a local archive (`.zip / .tar.gz / .tar.bz2 / .tar.xz` — auto-extracted), or a `gs://<project>/<key>` URI (downloaded + extracted). Applies to `agent audit` and `agent piolium`
- `vigolium init` is a no-op on an existing installation unless `--force` is passed (regenerates API key + re-extracts preset data)
- `vigolium config clean` prompts for confirmation unless `-F/--force` is passed; it wipes the entire `~/.vigolium/` directory

## Resources

- **Website**: [www.vigolium.com](https://www.vigolium.com/)
- **Documentation**: [docs.vigolium.com](https://docs.vigolium.com/)
- **GitHub**: [github.com/vigolium/vigolium](https://github.com/vigolium/vigolium)
