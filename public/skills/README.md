# vigolium-scanner

Claude Code skill for operating the [Vigolium](https://github.com/vigolium/vigolium) web vulnerability scanner CLI.

## What is Vigolium?

Vigolium is a high-fidelity web vulnerability scanner built for security professionals. It combines traditional DAST scanning with AI-powered analysis to find vulnerabilities in web applications. Key capabilities:

- **Multi-phase scanning** — discovery, spidering, SPA analysis, audit, and SAST
- **Flexible input** — scan URLs directly, or import from OpenAPI specs, Burp exports, HAR files, cURL commands, and more
- **AI agent modes** — autonomous scanning, multi-phase pipelines, and AI-assisted code review
- **Extensible** — write custom scanner modules in JavaScript
- **Source-aware** — whitebox scanning that combines static analysis with dynamic testing

---

# Using the Vigolium Scanner Skill in Claude Code, Codex or any agents

This guide explains how to install and use the `vigolium-scanner` skill (`skills/vigolium-scanner/`) with AI coding agents — Claude Code and OpenAI Codex — to operate the Vigolium CLI for web vulnerability scanning, security testing, and custom extension authoring.

## Table of Contents

- [What the Skill Does](#what-the-skill-does)
- [Skill Structure](#skill-structure)
- [Installation](#installation)
- [Usage Examples by Category](#usage-examples-by-category)
  - [Scanning](#1-scanning)
  - [Input Formats](#2-input-formats)
  - [Phase Control](#3-phase-control)
  - [Module Filtering](#4-module-filtering)
  - [Server & Ingestion](#5-server--ingestion)
  - [AI Agent Modes](#6-ai-agent-modes)
  - [Traffic & Results Browsing](#7-traffic--results-browsing)
  - [Data Management](#8-data-management)
  - [Export & Reports](#9-export--reports)
  - [Whitebox / Source-Aware Scanning](#10-whitebox--source-aware-scanning)
  - [JavaScript Extensions](#11-javascript-extensions)
  - [Configuration & Projects](#12-configuration--projects)
- [Natural Language Examples](#natural-language-examples)
- [Tips & Best Practices](#tips--best-practices)

---

## What the Skill Does

The skill teaches the AI agent how to:

1. **Pick the right vigolium command** for any security testing task
2. **Construct correct flag combinations** with proper syntax
3. **Follow scanning workflows** end-to-end (ingest → scan → triage → export)
4. **Write custom JavaScript extensions** using the `vigolium.*` API
5. **Execute ad-hoc JavaScript** with `vigolium js` for scripting and automation
6. **Operate AI agent modes** (query, autopilot, pipeline, swarm)
7. **Manage data** — browse traffic, filter findings, export reports, clean databases

The skill uses lazy-loaded references: the main `SKILL.md` stays small, and detailed docs are loaded on demand when the agent needs deep flag information or extension authoring guidance.

---

## Skill Structure

```
skills/vigolium-scanner/
├── SKILL.md                              # Main skill (decision tree, recipes, flags)
└── references/
    ├── scanning-commands.md              # scan, scan-url, scan-request, run
    ├── server-and-ingestion.md           # server, ingest, traffic, traffic replay
    ├── agent-commands.md                 # agent, agent query, autopilot, pipeline, swarm
    ├── data-and-management.md            # db, module, ext, js, config, scope, source, export
    ├── flags-reference.md                # Complete alphabetical flag index
    ├── session-auth-config.md            # Auth config YAML format, extract rules
    └── writing-extensions.md             # JS extension API and examples
```

---

## Installation

**Option A: Install via npx / bunx (recommended)**

```bash
bunx skills add vigolium/skills --skill vigolium-scanner --agent <agent-name> --yes
```

or with `npx`:

```bash
npx skills add vigolium/skills --skill vigolium-scanner --agent <agent-name> --yes
```

Replace `<agent-name>` with your agent (e.g., `claude-code`, `codex`). This fetches the skill from the [vigolium/skills](https://github.com/vigolium/skills) repository and registers it automatically.

**Option B: Clone and copy manually**

```bash
git clone https://github.com/vigolium/skills.git
cd skills
```

Then copy the skill folder to your agent's configuration directory:

```bash
# For Claude Code
cp -R vigolium-scanner ~/.claude

# For other agents
cp -R vigolium-scanner ~/.agents
```

Once installed, the skill **auto-triggers** when you mention keywords like `scan`, `vigolium`, `agent autopilot`, `vulnerability scanner`, `openapi scan`, etc. In Claude Code, you can also invoke it explicitly with `/vigolium-scanner`.

---

## Usage Examples by Category

### 1. Scanning

**Basic scan against a single target:**
```
> Scan https://example.com for vulnerabilities
```
```bash
vigolium scan -t https://example.com
```

**Multiple targets:**
```
> Scan both https://example.com and https://api.example.com
```
```bash
vigolium scan -t https://example.com -t https://api.example.com
```

**Targets from a file:**
```
> I have a list of URLs in targets.txt, scan all of them
```
```bash
vigolium scan -T targets.txt
```

**Scan with a specific strategy:**
```
> Do a deep scan of https://example.com with discovery and spidering
```
```bash
vigolium scan -t https://example.com --strategy deep
```

**Scan a single URL with custom method, headers, and body:**
```
> Test the login endpoint for vulnerabilities: POST to https://api.example.com/login with JSON credentials
```
```bash
vigolium scan-url https://api.example.com/login \
  --method POST \
  --body '{"username":"admin","password":"test123"}' \
  -H "Content-Type: application/json"
```

**Scan a raw HTTP request from a file:**
```
> I captured a raw request in request.txt, scan it
```
```bash
vigolium scan-request -i request.txt
```

**Scan a raw request from stdin:**
```
> Scan this raw request from the terminal
```
```bash
echo -e "GET /api/users?id=1 HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer tok123\r\n" | vigolium scan-request
```

**Scan with a proxy (e.g., Burp Suite):**
```
> Scan https://example.com and route traffic through Burp
```
```bash
vigolium scan -t https://example.com --proxy http://127.0.0.1:8080
```

**High-speed scan with tuned concurrency:**
```
> Scan fast — 100 workers, 200 req/s, max 5 per host
```
```bash
vigolium scan -t https://example.com -c 100 --rate-limit 200 --max-per-host 5
```

**Scan and output results as JSONL:**
```
> Scan and save results as JSON lines
```
```bash
vigolium scan -t https://example.com --format jsonl -o results.jsonl
```

**Scan and generate an HTML report:**
```
> Scan and produce an interactive HTML report
```
```bash
vigolium scan -t https://example.com --format html -o report.html
```

**Scan with CI-friendly output (for CI/CD pipelines):**
```
> Scan and output only JSONL findings, no color or banners
```
```bash
vigolium scan -t https://example.com --ci-output-format
```

**Scan with custom scanning profile:**
```
> Use the aggressive scanning profile
```
```bash
vigolium scan -t https://example.com --scanning-profile aggressive
```

**Scan with strict origin scope:**
```
> Only scan URLs on the exact same origin
```
```bash
vigolium scan -t https://example.com --scope-origin strict
```

---

### 2. Input Formats

**OpenAPI 3.x spec with explicit base URL:**
```
> Scan my API using the OpenAPI spec
```
```bash
vigolium scan -I openapi -i api-spec.yaml -t https://api.example.com
```

**OpenAPI spec using servers from the spec:**
```
> Use the server URLs defined in the spec itself
```
```bash
vigolium scan -I openapi -i api-spec.yaml --spec-url
```

**OpenAPI with auth header and parameter values:**
```
> Scan the spec with bearer auth and set the user_id parameter to 42
```
```bash
vigolium scan -I openapi -i spec.yaml -t https://api.example.com \
  --spec-header "Authorization: Bearer eyJ..." \
  --spec-var "user_id=42"
```

**Swagger 2.0 spec:**
```
> Import a Swagger 2.0 spec and scan
```
```bash
vigolium scan -I swagger -i swagger.json -t https://api.example.com
```

**Burp Suite XML export:**
```
> I exported traffic from Burp, scan it
```
```bash
vigolium scan -I burp -i burp-export.xml -t https://example.com
```

**HAR (HTTP Archive) file:**
```
> Scan my browser-recorded HAR file
```
```bash
vigolium scan -I har -i traffic.har
```

**cURL commands file:**
```
> I have a file of curl commands, scan them all
```
```bash
vigolium scan -I curl -i curl-commands.txt
```

**Postman collection:**
```
> Import and scan my Postman collection
```
```bash
vigolium scan -I postman -i collection.json -t https://api.example.com
```

**Nuclei templates:**
```
> Run these Nuclei templates against the target
```
```bash
vigolium scan -I nuclei -i templates/ -t https://example.com
```

**Piped URLs from stdin:**
```
> Pipe a list of URLs into the scanner
```
```bash
cat urls.txt | vigolium scan -i -
```

---

### 3. Phase Control

**Run only discovery (content enumeration):**
```
> Just run content discovery against the target
```
```bash
vigolium run discover -t https://example.com
# or
vigolium scan -t https://example.com --only discovery
```

**Run only spidering (headless browser crawling):**
```
> Spider the target with a headless browser
```
```bash
vigolium run spidering -t https://example.com
```

**Run only audit (vulnerability scanning):**
```
> Skip discovery, just run the vulnerability modules
```
```bash
vigolium run audit -t https://example.com
# or
vigolium scan -t https://example.com --only audit
```

**Run only SPA (security posture assessment via Nuclei):**
```
> Run Nuclei-based security posture assessment, only critical and high severity
```
```bash
vigolium run spa -t https://example.com --spa-severities critical,high
```

**Run only SAST (static analysis on source code):**
```
> Run static analysis on my Go app, filter for gin-related rules
```
```bash
vigolium run sast --repo /path/to/app --rule gin
```

**Run only external harvest (Wayback, Common Crawl, OTX):**
```
> Gather URLs from external intelligence sources
```
```bash
vigolium run external-harvest -t https://example.com
```

**Skip specific phases:**
```
> Scan but skip discovery and spidering
```
```bash
vigolium scan -t https://example.com --skip discovery,spidering
```

**Run only JavaScript extensions:**
```
> Run only my custom extension, skip built-in modules
```
```bash
vigolium scan -t https://example.com --only extension --ext ./custom-check.js
# or
vigolium run ext -t https://example.com --ext ./custom-check.js
```

**Phase aliases reference:**

| Alias | Resolves To |
|-------|-------------|
| `deparos`, `discover` | `discovery` |
| `spitolas` | `spidering` |
| `dynamic-assessment` | `audit` |
| `ext` | `extension` |

---

### 4. Module Filtering

**List all available scanner modules:**
```
> Show me all scanner modules
```
```bash
vigolium module ls
# or
vigolium scan -M
```

**Filter modules by keyword:**
```
> Show me all XSS-related modules
```
```bash
vigolium module ls xss
```

**List only active modules with verbose details:**
```
> Show active modules with descriptions
```
```bash
vigolium module ls --type active -v
```

**Scan with specific modules only:**
```
> Only run reflected XSS and error-based SQL injection modules
```
```bash
vigolium scan -t https://example.com -m xss-reflected,sqli-error
```

**Filter modules by tags (OR logic):**
```
> Scan with modules tagged 'spring' or 'injection'
```
```bash
vigolium scan -t https://example.com --module-tag spring --module-tag injection
```

**Combine module IDs and tags:**
```
> Run sqli-error plus all XSS-tagged modules
```
```bash
vigolium scan -t https://example.com -m sqli-error --module-tag xss
```

**Enable/disable modules persistently:**
```
> Disable all SQL injection modules, enable all XSS modules
```
```bash
vigolium module disable sqli
vigolium module enable xss
```

**Enable by exact module ID:**
```
> Enable only the reflected XSS module
```
```bash
vigolium module enable active-xss-reflected --id
```

---

### 5. Server & Ingestion

**Start the API server (default port 9002):**
```
> Start the vigolium server
```
```bash
vigolium server
```

**Start server on custom port without auth:**
```
> Start the server on port 8443 with no authentication
```
```bash
vigolium server --service-port 8443 --no-auth
```

**Start server with scan-on-receive (auto-scan ingested traffic):**
```
> Start the server and auto-scan every request that comes in
```
```bash
vigolium server -t https://example.com --scan-on-receive
```

**Start server with transparent proxy for recording:**
```
> Start server with a recording proxy on port 8080
```
```bash
vigolium server --ingest-proxy-port 8080
```

**High-concurrency server:**
```
> Start a high-throughput server with 200 workers
```
```bash
vigolium server -c 200 --mem-buffer 50000
```

**Ingest an OpenAPI spec locally:**
```
> Import the spec into the database without scanning
```
```bash
vigolium ingest -t https://api.example.com -I openapi -i spec.yaml
```

**Ingest and auto-scan:**
```
> Import the spec and scan immediately
```
```bash
vigolium ingest -t https://api.example.com -I openapi -i spec.yaml -S
```

**Ingest Burp export:**
```
> Import Burp traffic into the database
```
```bash
vigolium ingest -t https://example.com -I burp -i export.xml
```

**Remote ingest to a running server:**
```
> Send traffic to the vigolium server running on localhost
```
```bash
vigolium ingest -s http://localhost:9002 -I openapi -i spec.yaml
```

**Ingest without fetching responses:**
```
> Store request-only records, don't make network requests
```
```bash
vigolium ingest -t https://example.com -I burp -i export.xml --disable-fetch-response
```

---

### 6. AI Agent Modes

#### Agent (Template-Based)

**Security code review:**
```
> Review my source code for security vulnerabilities
```
```bash
vigolium agent --prompt-template security-code-review --repo ./src
```

**Endpoint discovery from source:**
```
> Find all API endpoints in my source code
```
```bash
vigolium agent --prompt-template endpoint-discovery --repo ./src
```

**Review specific files only:**
```
> Review only auth.go and middleware.go for security issues
```
```bash
vigolium agent --prompt-template security-code-review --repo ./src \
  --files "src/auth.go,src/middleware.go"
```

**Append extra instructions to a template:**
```
> Code review, but focus on authentication and authorization
```
```bash
vigolium agent --prompt-template security-code-review --repo ./src \
  --append "Focus specifically on authentication and authorization vulnerabilities"
```

**Use a custom prompt file:**
```
> Run the agent with my own prompt template
```
```bash
vigolium agent --prompt-file custom-prompt.md --repo ./src
```

**Select a specific agent backend:**
```
> Use the Claude backend for code review
```
```bash
vigolium agent --agent claude --prompt-template security-code-review --repo ./src
```

**Dry-run to preview the rendered prompt:**
```
> Show me what prompt would be sent to the agent
```
```bash
vigolium agent --prompt-template security-code-review --repo ./src --dry-run
```

**Save agent output to a file:**
```
> Save the review results to a JSON file
```
```bash
vigolium agent --prompt-template security-code-review --repo ./src \
  --output review-results.json
```

**List available templates and backends:**
```
> What prompt templates and agent backends are available?
```
```bash
vigolium agent --list-templates
vigolium agent --list-agents
```

**Built-in templates include:**
- `security-code-review` — Comprehensive security review
- `injection-sinks` — Find injection sinks
- `auth-bypass` — Auth bypass vectors
- `secret-detection` — Hardcoded secrets
- `endpoint-discovery` — API endpoints from source
- `api-input-gen` — Generate test inputs
- `curl-command-gen` — Generate cURL commands
- `attack-surface-mapper` — Map attack surface
- `nextjs-security-audit` — Next.js security review
- `react-xss-audit` — React XSS audit
- `cors-csrf-review` — CORS/CSRF config audit

#### Agent Query (Freeform Prompt)

**Inline prompt:**
```
> Ask the agent to review code for vulnerabilities
```
```bash
vigolium agent query 'review this code for SQL injection vulnerabilities'
```

**Named prompt flag:**
```
> Analyze the authentication flow
```
```bash
vigolium agent query --prompt 'analyze the authentication flow for bypass vectors'
```

**Pipe prompt from stdin:**
```
> Pipe a prompt to the agent
```
```bash
echo "check for SSRF in the URL-fetching handler" | vigolium agent query --stdin
```

**Custom prompt file with a specific backend:**
```
> Run a custom prompt file through Claude
```
```bash
vigolium agent query --agent claude --prompt-file custom-prompt.md
```

**With extended timeout:**
```
> Run a comprehensive review with extra time
```
```bash
vigolium agent query --agent-timeout 10m 'comprehensive security review of all handlers'
```

#### Agent Autopilot (Autonomous Scanning)

**Basic autonomous scan:**
```
> Let the AI autonomously scan the target
```
```bash
vigolium agent autopilot -t https://example.com
```

**With source code context and focus area:**
```
> Autonomous scan focused on auth bypass, with source code for context
```
```bash
vigolium agent autopilot -t https://api.example.com --repo ./src --focus "auth bypass"
```

**Custom limits (fewer commands, shorter timeout):**
```
> Limit the agent to 50 commands and 15 minutes
```
```bash
vigolium agent autopilot -t https://example.com --max-commands 50 --timeout 15m
```

**Preview the system prompt (dry run):**
```
> Show me what system prompt the autopilot agent would receive
```
```bash
vigolium agent autopilot -t https://example.com --dry-run
```

**Custom system prompt:**
```
> Use my own system prompt for autopilot
```
```bash
vigolium agent autopilot -t https://example.com --system-prompt my-system-prompt.md
```

**Use a different agent backend:**
```
> Run autopilot with Gemini
```
```bash
vigolium agent autopilot -t https://example.com --agent gemini
```

**Autopilot security model:**
- Only `vigolium` commands are permitted (allowlist)
- Destructive commands blocked (`db clean`, `db drop`, etc.)
- Shell metacharacters rejected (`;|&\`$(){}!><`)
- Per-command timeout: 5 minutes
- Max 100 commands by default (configurable)
- Output capped at 256KB per command

#### Agent Pipeline (Multi-Phase AI-Guided Scan)

**Basic pipeline scan (all 6 phases):**
```
> Run the full AI pipeline scan
```
```bash
vigolium agent pipeline -t https://example.com
```

The pipeline runs:
1. **Discover** — Native content discovery + spidering (no AI)
2. **Plan** — AI analyzes discovery results, produces an attack plan
3. **Scan** — Native executor with agent-selected modules (no AI)
4. **Triage** — AI reviews findings, confirms/dismisses, suggests follow-ups
5. **Rescan** — Targeted re-scanning from triage recommendations (no AI)
6. **Report** — Structured output from database (no AI)

**Pipeline with focus area and source code:**
```
> Pipeline scan focused on SQL injection, with source code
```
```bash
vigolium agent pipeline -t https://example.com --focus "SQL injection" --repo ./src
```

**Control rescan iterations:**
```
> Allow up to 3 triage→rescan iterations
```
```bash
vigolium agent pipeline -t https://example.com --max-rescan-rounds 3
```

**Skip discovery and start from planning (use existing DB data):**
```
> I already have traffic in the database, start from planning
```
```bash
vigolium agent pipeline -t https://example.com --skip-phase discover --start-from plan
```

**Skip triage (just discover → plan → scan):**
```
> Run pipeline but skip triage and rescan
```
```bash
vigolium agent pipeline -t https://example.com --skip-phase triage --skip-phase rescan
```

**Use a scanning profile:**
```
> Run pipeline with the deep scanning profile
```
```bash
vigolium agent pipeline -t https://example.com --profile deep
```

**Preview agent prompts (dry run):**
```
> Show me the prompts without executing
```
```bash
vigolium agent pipeline -t https://example.com --dry-run
```

**Specific source files for agent context:**
```
> Only include routes.go and handlers.go as context
```
```bash
vigolium agent pipeline -t https://example.com --repo ./src \
  --files "routes.go,handlers.go"
```

**Use a different agent backend:**
```
> Run pipeline with Gemini
```
```bash
vigolium agent pipeline -t https://example.com --agent gemini
```

#### Agent Swarm (Targeted Single-Request)

**Deep analysis of a single endpoint:**
```
> Deep scan the users API endpoint for vulnerabilities
```
```bash
vigolium agent swarm -t https://example.com/api/users
```

**From a curl command:**
```
> Analyze this curl command for vulnerabilities
```
```bash
vigolium agent swarm --input "curl -X POST https://example.com/api/login -d '{\"user\":\"admin\"}'"
```

**Pipe raw HTTP from stdin:**
```
> Scan this raw HTTP request
```
```bash
echo -e "POST /api/search HTTP/1.1\r\nHost: example.com\r\n\r\nq=test" | vigolium agent swarm --input -
```

**Focus on a specific vulnerability:**
```
> Focus on SQL injection in the users endpoint
```
```bash
vigolium agent swarm -t https://example.com/api/users --vuln-type sqli
```

**Source-aware swarm (discovers routes from source):**
```
> Scan my app with source code context
```
```bash
vigolium agent swarm -t http://localhost:3000 --source ~/projects/my-app
```

**Source-aware with specific files:**
```
> Analyze only the API routes and user model
```
```bash
vigolium agent swarm -t http://localhost:8080 --source ./backend \
  --files src/routes/api.js,src/models/user.js
```

**Source analysis only (extract routes, no scan):**
```
> Just extract routes from my source code
```
```bash
vigolium agent swarm -t http://localhost:3000 --source ./src --source-analysis-only
```

**Custom instructions:**
```
> Focus the agent on GraphQL parsing vulnerabilities
```
```bash
vigolium agent swarm -t https://example.com/graphql --instruction "Focus on GraphQL parsing"
```

**Preview prompts:**
```
> Show me what the swarm agent would do
```
```bash
vigolium agent swarm -t https://example.com/api/users --dry-run
```

---

### 7. Traffic & Results Browsing

**Browse all stored HTTP traffic:**
```
> Show me the HTTP traffic in the database
```
```bash
vigolium traffic
```

**Fuzzy search traffic:**
```
> Show traffic related to login
```
```bash
vigolium traffic login
```

**Tree view (hierarchical URL structure):**
```
> Show traffic as a directory tree
```
```bash
vigolium traffic --tree
```

**Burp-style colored output:**
```
> Show traffic in Burp Suite style
```
```bash
vigolium traffic --burp
```

**Filter by host, method, status:**
```
> Show POST and PUT requests to api.example.com that returned 200
```
```bash
vigolium traffic --host api.example.com --method POST,PUT --status 200
```

**Filter by date range:**
```
> Show traffic from January 2024
```
```bash
vigolium traffic --from 2024-01-01 --to 2024-01-31
```

**Search in request/response body:**
```
> Find traffic containing "password" in the body
```
```bash
vigolium traffic --body password
```

**Search in headers:**
```
> Find traffic with JWT tokens in headers
```
```bash
vigolium traffic --header "Bearer"
```

**Custom columns:**
```
> Show host, method, path, status, and auth columns
```
```bash
vigolium traffic --columns HOST,METHOD,PATH,STATUS,AUTH
```

**Watch mode (auto-refresh):**
```
> Monitor traffic in real-time, refresh every 5 seconds
```
```bash
vigolium traffic --watch 5s
```

**View raw HTTP request/response:**
```
> Show raw traffic for the last 5 records
```
```bash
vigolium traffic --raw --limit 5
```

**Browse findings:**
```
> Show all vulnerability findings
```
```bash
vigolium finding
```

**Filter findings by severity:**
```
> Show only high and critical findings
```
```bash
vigolium finding --severity high,critical
```

**Filter findings by module type or source:**
```
> Show only active module findings from audit
```
```bash
vigolium finding --module-type active --finding-source audit
```

**View a specific finding in Burp-style format:**
```
> Show finding #42 with full HTTP details
```
```bash
vigolium finding --id 42 --burp
```

**Custom finding columns:**
```
> Show findings with tags and confidence
```
```bash
vigolium finding --columns ID,SEVERITY,MODULE,MATCHED_AT,TAGS,CONFIDENCE
```

**Search findings:**
```
> Find SQL injection findings
```
```bash
vigolium finding --search "sql injection"
```

**Watch findings in real-time:**
```
> Monitor findings as they come in
```
```bash
vigolium finding --watch 5s
```

**Replay stored traffic (re-send requests):**
```
> Replay login-related requests and compare responses
```
```bash
vigolium traffic replay login
```

**Replay and replace stored responses:**
```
> Replay requests to api.example.com and update stored responses
```
```bash
vigolium traffic replay --host api.example.com --in-replace
```

---

### 8. Data Management

**Database statistics:**
```
> Show me database stats
```
```bash
vigolium db stats
```

**Detailed stats with host breakdown:**
```
> Show detailed stats broken down by host
```
```bash
vigolium db stats --detailed
```

**Stats for a specific host:**
```
> Stats for example.com only
```
```bash
vigolium db stats --host example.com
```

**Live-updating stats:**
```
> Watch database stats, refresh every 10 seconds
```
```bash
vigolium db stats --watch 10s
```

**List database records with filters:**
```
> Show findings table, critical and high severity
```
```bash
vigolium db ls --table findings --severity critical,high
```

**List available tables and columns:**
```
> What tables are in the database? What columns does findings have?
```
```bash
vigolium db ls --list-tables
vigolium db ls --list-columns --table findings
```

**Clean records by hostname:**
```
> Delete all records for old-target.com
```
```bash
vigolium db clean --host old-target.com --force
```

**Clean old records with dry-run preview:**
```
> Preview what would be deleted before January 2024
```
```bash
vigolium db clean --before 2024-01-01 --dry-run
```

**Clean only findings (keep HTTP records):**
```
> Delete info-severity findings but keep the HTTP records
```
```bash
vigolium db clean --findings-only --severity info --force
```

**Clean orphaned findings:**
```
> Remove findings without associated HTTP records
```
```bash
vigolium db clean --orphans
```

**Reset entire database:**
```
> Wipe the entire database and start fresh
```
```bash
vigolium db clean --force
```

**Reclaim disk space after deletion:**
```
> Vacuum the database to reclaim space
```
```bash
vigolium db clean --vacuum
```

---

### 9. Export & Reports

**Full JSONL export:**
```
> Export everything from the database as JSONL
```
```bash
vigolium export --format jsonl -o full-export.jsonl
```

**Export only findings:**
```
> Export just the findings
```
```bash
vigolium export --format jsonl --only findings -o findings.jsonl
```

**Export findings and HTTP records:**
```
> Export findings and associated HTTP traffic
```
```bash
vigolium export --format jsonl --only findings,http -o results.jsonl
```

**HTML report:**
```
> Generate an interactive HTML report
```
```bash
vigolium export --format html -o report.html
```

**Lite export (omit raw HTTP data):**
```
> Export URLs only, without raw request/response data
```
```bash
vigolium export --lite --only http -o urls.jsonl
```

**Export with search filter:**
```
> Export only records matching example.com
```
```bash
vigolium export --search "example.com" -o filtered.jsonl
```

**Database-level export as CSV:**
```
> Export HTTP records as CSV
```
```bash
vigolium db export -f csv -o records.csv
```

**Export as Markdown:**
```
> Export records as a Markdown report
```
```bash
vigolium db export -f markdown -o report.md
```

**Export raw requests only:**
```
> Export just the raw HTTP requests
```
```bash
vigolium db export -f raw --request-only -o requests.txt
```

**Export filtered by host and date:**
```
> Export records for example.com from 2024 onwards
```
```bash
vigolium db export -f csv -o records.csv --host example.com --from 2024-01-01
```

**Export a single record by UUID:**
```
> Export record abc12345
```
```bash
vigolium db export --uuid abc12345
```

**Export module registry:**
```
> Export all available scanner modules
```
```bash
vigolium export --only modules
```

---

### 10. Whitebox / Source-Aware Scanning

**Scan with local source code:**
```
> Whitebox scan with source code in ./src
```
```bash
vigolium scan -t https://example.com --source ./src --strategy whitebox
```

**Scan with source cloned from Git:**
```
> Clone the repo and run a whitebox scan
```
```bash
vigolium scan -t https://example.com \
  --source-url https://github.com/org/repo --strategy whitebox
```

**Link source code to a hostname first, then scan:**
```
> Link the source repo to example.com, then whitebox scan
```
```bash
vigolium source add --hostname example.com --path ./src
vigolium scan -t https://example.com --strategy whitebox
```

**Link source with metadata:**
```
> Link source with language and framework info
```
```bash
vigolium source add --hostname api.example.com --path ./src -l go -f gin
```

**Link source from Git URL:**
```
> Clone and link a GitHub repo
```
```bash
vigolium source add --hostname example.com --git https://github.com/org/repo
```

**List linked source repos:**
```
> Show all linked source repositories
```
```bash
vigolium source ls
```

**Run SAST only:**
```
> Run static analysis on the source code
```
```bash
vigolium run sast --repo /path/to/app
```

**SAST with rule filtering:**
```
> Run SAST, only gin-related rules
```
```bash
vigolium run sast --repo /path/to/app --rule gin
```

**SAST from a Git URL:**
```
> Clone a repo and run static analysis
```
```bash
vigolium run sast --repo-url https://github.com/org/repo
```

---

### 11. JavaScript Extensions

**Install preset examples:**
```
> Install the example extension scripts
```
```bash
vigolium ext preset
```

**View the extension API reference:**
```
> Show me the extension API docs
```
```bash
vigolium ext docs
vigolium ext docs --example          # with code examples
vigolium ext docs http               # filter by namespace
```

**List loaded extensions:**
```
> Show currently loaded extensions
```
```bash
vigolium ext ls
vigolium ext ls --type active        # active extensions only
```

**Quick-test JS code inline:**
```
> Test a JS expression
```
```bash
vigolium ext eval 'vigolium.log.info("hello from extension")'
vigolium ext eval 'vigolium.utils.md5("password")'
```

**Evaluate a JS file:**
```
> Run a JS script file
```
```bash
vigolium ext eval --ext-file script.js
```

**Run a custom extension against a target:**
```
> Run my custom scanner extension
```
```bash
vigolium run extension -t https://example.com --ext custom-check.js
# or
vigolium run ext -t https://example.com --ext custom-check.js
```

**Run extension alongside built-in modules:**
```
> Run built-in modules plus my custom extension
```
```bash
vigolium scan -t https://example.com --ext custom-check.js
```

**Run only extensions (skip built-in modules):**
```
> Run only my custom extensions
```
```bash
vigolium scan -t https://example.com --only extension --ext custom-check.js
```

**Load multiple extensions:**
```
> Run three extensions together
```
```bash
vigolium scan -t https://example.com --ext check1.js --ext check2.js --ext check3.js
```

**Load all extensions from a directory:**
```
> Run all extensions in my extensions folder
```
```bash
vigolium scan -t https://example.com --ext-dir ./my-extensions/
```

**Ask the agent to write an extension:**
```
> Write me a passive extension that checks for missing security headers
```

The agent will generate a JS file like:

```javascript
module.exports = {
  id: "missing-security-headers",
  name: "Missing Security Headers",
  type: "passive",
  severity: "low",
  confidence: "certain",
  scope: "response",
  tags: ["headers", "misconfiguration", "light"],
  scanTypes: ["per_request"],

  scanPerRequest: function(ctx) {
    if (!ctx.response) return null;
    var headers = ctx.response.headers;
    var missing = [];

    if (!headers["strict-transport-security"]) missing.push("HSTS");
    if (!headers["x-content-type-options"]) missing.push("X-Content-Type-Options");
    if (!headers["x-frame-options"] && !headers["content-security-policy"]) {
      missing.push("X-Frame-Options/CSP");
    }

    if (missing.length === 0) return null;

    return {
      url: ctx.request.url,
      name: "Missing Security Headers: " + missing.join(", "),
      severity: "low",
      description: "Response is missing: " + missing.join(", ")
    };
  }
};
```

**Ask the agent to write an AI-augmented extension:**
```
> Write an active extension that uses AI to generate XSS payloads
```

The agent will generate a JS file using `vigolium.agent.generatePayloads()` and `vigolium.agent.analyzeResponse()`.

**Execute ad-hoc JavaScript with vigolium js:**
```
> Run a JS script that queries the database and flags high-risk records
```
```bash
vigolium js --code 'var records = vigolium.db.records.query({ hostname: "example.com" }); records.forEach(function(r) { if (vigolium.utils.hasDynamicSegment(vigolium.parse.url(r.url).path)) vigolium.db.records.annotate(r.uuid, { risk_score: 50 }); })'
```

**Execute a JS file with target context:**
```
> Run my scanner script against example.com
```
```bash
vigolium js --target https://example.com --code-file my-scanner.js
```

**Quick hash or encode from the terminal:**
```
> MD5 hash the string "password"
```
```bash
vigolium js --format text --code 'vigolium.utils.md5("password")'
```

**YAML extension (simple pattern matching):**
```
> Write a YAML extension that detects stack traces and SQL errors
```

```yaml
id: error-pattern-detector
name: Verbose Error Pattern Detector
type: passive
severity: suspect
confidence: tentative
scope: response
tags: [error, information-disclosure, light]
scanTypes: [per_request]
patterns:
  - name: "Stack Trace Detected"
    regex: "(?:at\\s+[\\w.$]+\\(|Traceback \\(most recent|Exception in thread)"
    severity: suspect
  - name: "SQL Error Message"
    regex: "(?:mysql_|pg_|sqlite_|ORA-\\d{5}|SQLSTATE\\[)"
    severity: medium
```

---

### 12. Configuration & Projects

**View all configuration:**
```
> Show the current vigolium config
```
```bash
vigolium config ls
```

**View a specific config section:**
```
> Show scope configuration
```
```bash
vigolium config ls scope
vigolium config ls scanning_pace
vigolium config ls server
```

**Set configuration values:**
```
> Set the default strategy to deep
```
```bash
vigolium config set scanning_strategy.default_strategy deep
```

**Set scope mode:**
```
> Set origin scope to strict
```
```bash
vigolium config set scope.origin.mode strict
```

**Enable extensions globally:**
```
> Enable extensions in audit
```
```bash
vigolium config set audit.extensions.enabled true
```

**View scope rules:**
```
> Show current scope rules
```
```bash
vigolium scope view
vigolium scope view host
```

**View scanning strategies:**
```
> Show available strategies and their phases
```
```bash
vigolium strategy ls
```

**Create and manage projects:**
```
> Create a project, then switch to it
```
```bash
vigolium project create my-project
vigolium project list
vigolium project use my-project
```

**Scope CLI operations to a project:**
```
> Scan within a specific project
```
```bash
vigolium scan -t https://example.com --project-name my-project
```

**Project-scoped database access:**
```
> Show stats for my-project
```
```bash
VIGOLIUM_PROJECT=my-project vigolium db stats
```

---

## Natural Language Examples

These are examples of natural language prompts you can give to Claude Code or Codex with the skill installed. The agent will translate them into the correct vigolium commands.

| You Say | Agent Runs |
|---------|------------|
| "Scan example.com" | `vigolium scan -t https://example.com` |
| "Deep scan with spidering" | `vigolium scan -t <url> --strategy deep` |
| "Import my Burp export and scan it" | `vigolium scan -I burp -i export.xml` |
| "Scan my OpenAPI spec with auth" | `vigolium scan -I openapi -i spec.yaml -t <url> --spec-header "Authorization: Bearer ..."` |
| "Only run XSS modules" | `vigolium scan -t <url> --module-tag xss` |
| "Review my code for security issues" | `vigolium agent --prompt-template security-code-review --repo ./src` |
| "Autonomous scan focused on injection" | `vigolium agent autopilot -t <url> --focus "injection"` |
| "Run the full AI pipeline" | `vigolium agent pipeline -t <url>` |
| "Deep scan this endpoint for SQLi" | `vigolium agent swarm -t <url> --vuln-type sqli` |
| "Scan with source code context" | `vigolium agent swarm -t <url> --source ./src` |
| "Run this JS script against the API" | `vigolium js --code-file script.js --target <url>` |
| "MD5 hash this string" | `vigolium js --format text --code 'vigolium.utils.md5("...")'` |
| "Show me all critical findings" | `vigolium finding --severity critical` |
| "Show active module findings in Burp format" | `vigolium finding --module-type active --burp` |
| "Run scan for CI/CD pipeline" | `vigolium scan -t <url> --ci-output-format` |
| "Export results as HTML report" | `vigolium export --format html -o report.html` |
| "What traffic is in the database?" | `vigolium traffic` |
| "Write me an extension that checks for exposed .env files" | Generates a JS extension file |
| "Start the server with auto-scan" | `vigolium server -t <url> --scan-on-receive` |
| "Whitebox scan with my source code" | `vigolium scan -t <url> --source ./src --strategy whitebox` |
| "Clean up old scan data" | `vigolium db clean --before <date> --force` |

---

## Tips & Best Practices

1. **Start with `scan -t`** — It's the most common command. Add flags incrementally.
2. **Use strategies** — `lite` for quick checks, `balanced` for most cases, `deep` for full coverage, `whitebox` when you have source code.
3. **Phase isolation** — Use `--only` or `vigolium run <phase>` to iterate on a single phase without re-running the entire pipeline.
4. **Module tags** — Filter modules by technology (`spring`, `nodejs`) or vulnerability class (`xss`, `injection`) to reduce noise.
5. **Watch mode** — Add `--watch 5s` to `traffic`, `finding`, or `db stats` for real-time monitoring during long scans.
6. **Dry-run agents** — Always `--dry-run` first for agent commands to preview prompts before spending AI tokens.
7. **Pipeline over autopilot** — Use `agent pipeline` for structured scans (lower cost, reproducible). Use `agent autopilot` for exploratory, creative scanning.
8. **Extensions for custom logic** — Write JS extensions instead of modifying core modules. They run alongside built-in modules with `--ext`.
9. **Projects for isolation** — Use `vigolium project create` to keep scan data separate across engagements.
10. **Export early** — Run `vigolium export --format html -o report.html` to share results as interactive reports.
