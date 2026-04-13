# Agent Commands Reference

Complete flag reference for `agent`, `agent query`, `agent autopilot`, `agent swarm`, and `agent session` commands.

## Table of Contents

- [agent](#agent)
- [agent query](#agent-query)
- [agent autopilot](#agent-autopilot)
- [agent swarm](#agent-swarm)
- [agent session](#agent-session)
- [Prompt Templates](#prompt-templates)
- [Agent Configuration](#agent-configuration)
- [Output Schemas](#output-schemas)

---

## agent

**Usage:** `vigolium agent [flags]`

Run an agentic scan using AI agents (Claude, Codex, OpenCode) for intelligent vulnerability scanning with native scan support.

The parent command only supports `--list-templates` and `--list-agents` flags — all execution requires a subcommand.

### Available Subcommands

| Subcommand | Description |
|------------|-------------|
| `autopilot` | Autonomous scanning with a single operator session over prepared context |
| `query` | Single-shot prompt execution with template-based or inline prompts |
| `session` | List or inspect agent run sessions |
| `swarm` | AI-guided vulnerability scanning with native scan support |

### agent flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--list-templates` | — | bool | `false` | List available prompt templates |
| `--list-agents` | — | bool | `false` | List configured agent backends |

### Examples

```bash
# List available templates
vigolium agent --list-templates

# List configured backends
vigolium agent --list-agents
```

---

## agent query

**Usage:** `vigolium agent query [prompt] [flags]`

Send a freeform prompt to an AI agent without templates or structured output. Prompt can be passed as positional argument, via `--prompt/-p`, or piped through `--stdin`.

### agent query flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--agent` | — | string | from config | Agent backend to use |
| `--agent-timeout` | — | duration | `5m` | Maximum time for agent execution (0 = no limit) |
| `--append` | — | string | — | Append extra text to the rendered prompt |
| `--dry-run` | — | bool | `false` | Print the rendered prompt without executing |
| `--files` | — | []string | — | Specific files to include (relative to --source) |
| `--instruction` | — | string | — | Custom instruction to guide the agent (appended to prompt) |
| `--instruction-file` | — | string | — | Path to a file containing custom instructions |
| `--output` | — | string | — | Write agent output to this file |
| `--prompt` | `-p` | string | — | Prompt text to send to the agent |
| `--prompt-file` | — | string | — | Path to a prompt template file |
| `--prompt-template` | — | string | — | Prompt template ID (e.g. security-code-review) |
| `--show-prompt` | — | bool | `false` | Print rendered prompt to stderr before executing |
| `--source` | — | string | — | Path to source code repository |
| `--source-label` | — | string | — | Label for records ingested from agent output (e.g. 'agent-review') |
| `--stdin` | — | bool | `false` | Read prompt from stdin |

### Examples

```bash
# Positional argument prompt
vigolium agent query 'review this code for vulnerabilities'

# Named prompt flag
vigolium agent query --prompt 'analyze the authentication flow'

# Pipe prompt from stdin
echo "check for SQL injection in the login handler" | vigolium agent query --stdin

# With specific agent
vigolium agent query --agent claude 'find XSS vulnerabilities'

# With source code context
vigolium agent query 'explain the auth flow' --source ./src

# With timeout
vigolium agent query --agent-timeout 10m 'comprehensive security review'

# Security code review with template
vigolium agent query --prompt-template security-code-review --source ./src

# Endpoint discovery
vigolium agent query --prompt-template endpoint-discovery --source ./src

# Custom prompt file
vigolium agent query --prompt-file custom-prompt.md --source ./src

# Append instructions to prompt
vigolium agent query --prompt-template security-code-review --source ./src \
  --append "Focus on authentication and authorization issues"

# Specific files only
vigolium agent query --prompt-template security-code-review --source ./src \
  --files "src/auth.go,src/middleware.go"

# Dry run (preview prompt)
vigolium agent query --prompt-template security-code-review --source ./src --dry-run

# Save output
vigolium agent query --prompt-template security-code-review --source ./src \
  --output review-results.json
```

---

## agent autopilot

**Usage:** `vigolium agent autopilot [flags]`

Launch an AI agent that autonomously discovers, scans, and triages vulnerabilities by driving the vigolium CLI. With SDK protocol (default), the agent gets full coding agent tools (Read, Grep, Glob, Bash, Edit, Write).

Autopilot runs a **single autonomous operator session**. When source is available, Archon runs first, the whitebox context is prepared natively, and then one operator agent handles recon, validation, scanning, exploit attempts, and reporting.

### agent autopilot flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--agent` | — | string | from config | Agent backend to use |
| `--dry-run` | — | bool | `false` | Render the system prompt without launching the agent |
| `--files` | — | []string | — | Specific files to include (relative to --source) |
| `--focus` | — | string | — | Focus area hint (e.g. 'API injection', 'auth bypass') |
| `--input` | — | string | — | Raw input (curl command, raw HTTP, Burp XML, URL). Reads from stdin if piped |
| `--instruction` | — | string | — | Custom instruction to guide the agent (appended to prompt) |
| `--instruction-file` | — | string | — | Path to a file containing custom instructions |
| `--max-commands` | — | int | `100` | Maximum number of CLI commands the agent can execute |
| `--mcp-enabled` | — | bool | `false` | Enable MCP server passthrough |
| `--mcp-server` | — | []string | — | MCP servers to attach (format: name=command,arg1,arg2 or name=http://url) |
| `--resume` | — | string | — | Resume from a previous session directory |
| `--show-prompt` | — | bool | `false` | Print rendered prompt to stderr before executing |
| `--source` | — | string | — | Path to application source code for source-aware scanning |
| `--target` | `-t` | string | — | Target URL (derived from --input if not set) |
| `--timeout` | — | duration | `6h` | Maximum duration for the autopilot session |

### Examples

```bash
# Basic autonomous scan (uses SDK protocol by default)
vigolium agent autopilot -t https://example.com

# With source code context and focus area
vigolium agent autopilot -t https://api.example.com --source ./src --focus "auth bypass"

# Source-aware autonomous scan
vigolium agent autopilot -t https://example.com --source ./src --focus "auth bypass"

# Custom limits
vigolium agent autopilot -t https://example.com --max-commands 50 --timeout 15m

# Pipe a curl command (target auto-derived)
echo "curl -X POST https://example.com/api/login -d '{\"user\":\"admin\"}'" | vigolium agent autopilot

# Preview system prompt
vigolium agent autopilot -t https://example.com --dry-run

# Resume a previous session
vigolium agent autopilot --resume ~/.vigolium/agent-sessions/<uuid>

# With MCP servers
vigolium agent autopilot -t https://example.com --mcp-enabled \
  --mcp-server "playwright=npx,-y,@anthropic-ai/mcp-server-playwright"
```

---

## agent swarm

**Usage:** `vigolium agent swarm [flags]`

AI-guided targeted vulnerability scanning. A master AI agent analyzes HTTP requests, selects scanner modules, generates custom JavaScript attack extensions, executes the scan, and triages the results.

Supports both **targeted single-request scanning** and **full-scope scanning** with `--discover`. When `--discover` is enabled, swarm runs content discovery and spidering before planning, providing full-scope coverage.

When `--source` is provided, swarm runs a **consolidated source analysis** (route extraction, auth flow discovery, custom extension generation), followed by **AI code audit** and **native SAST** (ast-grep + secret detection).

### Supported Input Types

Inputs are auto-detected from their content:

| Type | Example | Detection |
|------|---------|-----------|
| **URL** | `https://example.com/api/users` | Starts with `http://` or `https://` |
| **Curl** | `curl -X POST https://...` | Starts with `curl ` |
| **Raw HTTP** | `POST /api HTTP/1.1\r\n...` | Starts with HTTP method + path |
| **Burp XML** | `<?xml...><items>...</items>` | Starts with `<?xml` or `<items` |
| **Record UUID** | `550e8400-e29b-...` | Matches UUID format (8-4-4-4-12 hex) |

### agent swarm flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--agent` | — | string | from config | Agent backend to use |
| `--batch-concurrency` | — | int | `0` | Max parallel master agent batches (0 = auto, scales with CPU count) |
| `--code-audit` | — | bool | auto | Enable AI security code audit phase (on by default when --source is provided, use `--code-audit=false` to disable) |
| `--custom-agent` | — | []string | — | Custom agents the swarm can invoke via 'vigolium agent query --agent=X' (repeatable) |
| `--discover` | — | bool | `false` | Run discovery+spidering before master agent planning to expand attack surface |
| `--dry-run` | — | bool | `false` | Render prompts without executing |
| `--files` | — | []string | — | Specific source files to include (relative to --source) |
| `--focus` | — | string | — | Focus area hint for the agent (e.g. 'API injection', 'auth bypass') |
| `--input` | — | string | — | Raw input (curl command, raw HTTP, Burp XML, URL). Reads from stdin if piped |
| `--instruction` | — | string | — | Custom instruction to guide the agent (appended to prompts) |
| `--instruction-file` | — | string | — | Path to a file containing custom instructions |
| `--master-batch-size` | — | int | `0` | Max records per master agent batch (0 = default 5) |
| `--max-commands` | — | int | `0` | Max terminal commands per session (default: 50, only applies when --custom-agent is set) |
| `--max-iterations` | — | int | `3` | Maximum triage-rescan iterations |
| `--max-master-retries` | — | int | `3` | Max master agent retries on parse failure |
| `--max-plan-records` | — | int | `10` | Max records sent to plan agent (selects most interesting; 0 = no limit) |
| `--max-probe-body` | — | int | `0` | Max response body size in bytes during probing (0 = default 2MB) |
| `--modules` | `-m` | []string | — | Explicit module names to include |
| `--only` | — | string | — | Run only this scanning phase (discovery, spidering, spa, audit, external-harvest) |
| `--probe-concurrency` | — | int | `0` | Max parallel probe requests (0 = default 10) |
| `--probe-timeout` | — | duration | `0` | Per-request probe timeout (0 = default 10s) |
| `--profile` | — | string | — | Scanning profile to use |
| `--record-uuid` | — | string | — | HTTP record UUID from database |
| `--show-prompt` | — | bool | `false` | Print rendered prompts to stderr before executing |
| `--skip` | — | []string | — | Skip specific phases (discovery, spidering, spa, audit, external-harvest, triage, rescan) |
| `--skip-sast` | — | bool | `false` | Skip native SAST tools (ast-grep, osv-scanner, semgrep) during source analysis |
| `--source` | — | string | — | Path to application source code for route discovery |
| `--source-analysis-only` | — | bool | `false` | Run only the source analysis phase and exit |
| `--start-from` | — | string | — | Resume from a specific phase (native-normalize, source-analysis, code-audit, native-sast, native-discover, plan, native-extension, native-scan, triage) |
| `--sub-agent-concurrency` | — | int | `3` | Max parallel source analysis sub-agents (routes, auth, extensions) |
| `--swarm-duration` | — | duration | `12h` | Maximum swarm duration (0 = unlimited) |
| `--target` | `-t` | string | — | Target URL (required when --source is used) |
| `--triage` | — | bool | `false` | Enable AI triage and rescan phases (disabled by default) |
| `--vuln-type` | — | string | — | Vulnerability type focus (e.g. sqli, xss, ssrf) |

At least one input is required: `--target`, `--input`, `--record-uuid`, `--source`, or piped stdin. `--source` requires `--target` for hostname filtering.

### Swarm Phases

```
Phase 1:    native-normalize    (Go)       — Parse input(s) into HttpRequestResponse objects, save to DB
Phase 2:    source-analysis     (AI)       — Extract routes, auth config, JS extensions from source (conditional: --source)
Phase 3:    code-audit          (AI)       — Deep AI security code audit for business logic flaws (conditional: --source, on by default)
Phase 4:    native-sast         (Go)       — Static analysis via ast-grep + secret detection (conditional: --source)
Phase 5:    native-sast-review  (AI)       — AI reviews SAST findings (conditional: --source)
Phase 6:    native-discover     (Go)       — Content discovery + spidering (conditional: --discover)
Phase 7:    plan                (AI)       — Master agent analyzes requests, selects modules, generates extensions
Phase 8:    native-extension    (Go)       — Write generated JS extensions to temp directory
Phase 9:    native-scan         (Go)       — Dynamic assessment with selected modules + extensions
Phase 10:   triage              (AI)       — Agent reviews extension-generated findings (conditional: --triage)
Phase 11:   rescan              (Go, loop) — Targeted rescan from triage follow-ups (conditional: --triage)
```

Phases 2-5 are automatically skipped when `--source` is not provided. Phase 6 is skipped unless `--discover` is passed. Phases 10-11 are skipped unless `--triage` is enabled.

### Swarm Output Schemas

**SwarmPlan** (plan phase output):

The master agent produces a plan with three tiers of custom checks (lightest first):

```json
{
  "module_tags": ["sqli", "injection"],
  "module_ids": ["sqli-error-based"],
  "quick_checks": [
    {
      "id": "ssti-jinja2",
      "severity": "high",
      "scan": "per_insertion_point",
      "payloads": ["{{7*7}}", "${7*7}"],
      "match": {"body_contains": "49"}
    }
  ],
  "snippets": [
    {
      "id": "idor-check",
      "severity": "high",
      "scan": "per_request",
      "body": "var related = vigolium.db.records.getRelated(ctx.record.uuid);\nvar cmp = vigolium.db.compareResponses(related);\nif (!cmp.all_similar) return [{url: ctx.request.url, matched: 'Response variance', name: 'Potential IDOR'}];\nreturn null;"
    }
  ],
  "extensions": [
    {
      "filename": "custom-json-sqli.js",
      "code": "module.exports = { id: 'custom-json-sqli', ... };",
      "reason": "JSON body with user_id parameter susceptible to SQL injection"
    }
  ],
  "focus_areas": ["SQL injection in JSON body parameters"],
  "notes": "Target uses JSON API with direct DB queries"
}
```

**Custom check tiers** (prefer the lightest format that works):

| Tier | Format | When to use |
|------|--------|-------------|
| `quick_checks` | Declarative JSON (payloads + match) | Simple "send payload, check response" patterns — zero JS |
| `snippets` | JS function body only | Need `vigolium.*` API access but no boilerplate |
| `extensions` | Full JS module | Complex multi-step logic, multiple helpers, state management |

**SwarmResult** (final output):

```json
{
  "swarm_plan": { "..." },
  "triage_results": [ "..." ],
  "total_findings": 5,
  "total_records": 3,
  "severity_counts": {"critical": 1, "high": 2, "medium": 2, "low": 0},
  "confirmed": 3,
  "false_positives": 2,
  "iterations": 2,
  "duration": "3m45s",
  "agent_run_uuid": "...",
  "session_id": "...",
  "session_dir": "~/.vigolium/agent-sessions/<uuid>"
}
```

### Examples

```bash
# Target a URL
vigolium agent swarm -t https://example.com/api/users

# Full-scope scan with discovery (replaces pipeline)
vigolium agent swarm -t https://example.com --discover

# Analyze a curl command
vigolium agent swarm --input "curl -X POST https://example.com/api/login -d '{\"user\":\"admin\"}'"

# Pipe raw HTTP request from stdin
echo -e "POST /api/search HTTP/1.1\r\nHost: example.com\r\n\r\nq=test" | vigolium agent swarm --input -

# Scan a record from the database
vigolium agent swarm --record-uuid 550e8400-e29b-41d4-a716-446655440000

# Focus on a specific vulnerability type
vigolium agent swarm -t https://example.com/api/users --vuln-type sqli

# Source-aware swarm (route extraction + code audit + SAST + scanning)
vigolium agent swarm -t http://localhost:3000 --source ~/projects/my-app

# Source-aware with specific files
vigolium agent swarm -t http://localhost:8080 --source ./backend \
  --files src/routes/api.js,src/models/user.js

# Full-scope source-aware scan (discovery + source analysis + SAST + scanning)
vigolium agent swarm -t http://localhost:3000 --source ~/projects/express-app --discover

# Source analysis only (extract routes, no scan)
vigolium agent swarm -t http://localhost:3000 --source ./src --source-analysis-only

# Skip SAST tools during source analysis
vigolium agent swarm -t http://localhost:3000 --source ./src --skip-sast

# Disable code audit (still runs source analysis + SAST)
vigolium agent swarm -t http://localhost:3000 --source ./src --code-audit=false

# Enable triage and rescan loop
vigolium agent swarm -t https://example.com/api/users --triage --max-iterations 5

# Custom instructions to guide the agent
vigolium agent swarm -t https://example.com/api/users --instruction "Focus on GraphQL parsing"

# Instructions from a file
vigolium agent swarm -t https://example.com/api/users --instruction-file custom-hints.txt

# Resume from a specific phase
vigolium agent swarm -t https://example.com --start-from plan

# Show rendered prompts during execution
vigolium agent swarm -t https://example.com/api/users --show-prompt

# Specify modules explicitly
vigolium agent swarm -t https://example.com/api/search -m xss-reflected,xss-stored

# Control scanning phases
vigolium agent swarm -t https://example.com --only audit
vigolium agent swarm -t https://example.com --skip discovery,spidering

# Preview master agent prompt
vigolium agent swarm -t https://example.com/api/users --dry-run

# With specific agent backend
vigolium agent swarm -t https://example.com/api/users --agent codex
```

---

## agent session

**Usage:** `vigolium agent session [uuid] [flags]`

**Aliases:** `session`, `sessions`

List or inspect agent run sessions. Without arguments, lists all agent run sessions. With a UUID argument, shows detailed session information.

### agent session flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--limit` | `-n` | int | `50` | Maximum number of records to display |
| `--offset` | `-o` | int | `0` | Number of records to skip |
| `--mode` | — | string | — | Filter by mode (query, autopilot, pipeline, swarm) |

### Examples

```bash
# List all agent sessions
vigolium agent session

# List with pagination
vigolium agent session -n 20 -o 40

# Filter by mode
vigolium agent session --mode swarm

# Show details for a specific session
vigolium agent session agt-550e8400-e29b-41d4-a716-446655440000
```

---

## Prompt Templates

Prompt templates are Markdown files with YAML frontmatter stored in:
- `~/.vigolium/prompts/` (user-defined)
- Embedded in the binary (`public/presets/prompts/`)

### Template Discovery

```bash
# List all available templates
vigolium agent --list-templates

# Output: ID, NAME, OUTPUT_SCHEMA, SOURCE, DESCRIPTION
```

### Template Frontmatter

Templates use YAML frontmatter with fields like:
- `name`: Display name
- `description`: What the template does
- `output_schema`: Expected output format (`findings`, `http_records`, `attack_plan`, `triage_result`, `source_analysis`)
- Variables: Populated from database context (findings, HTTP records, module registry, scan stats)

### Built-in Templates

**SAST / Code Review:**
- `security-code-review` — Comprehensive security code review
- `injection-sinks` — Find injection sinks in source code
- `auth-bypass` — Identify authentication bypass vectors
- `secret-detection` — Detect hardcoded secrets and credentials
- `nextjs-security-audit` — Next.js-specific security review
- `react-xss-audit` — React XSS vulnerability audit
- `auth-session-review` — Auth and session management review
- `cors-csrf-review` — CORS and CSRF configuration audit
- `build-config-audit` — Build and deployment config review

**Analysis / Dynamic:**
- `endpoint-discovery` — Discover API endpoints from source code
- `api-input-gen` — Generate API test inputs
- `curl-command-gen` — Generate cURL commands for testing
- `attack-surface-mapper` — Map application attack surface
- `interactive-scan` — Interactive scan template
- `targeted-retest` — Re-test specific findings

**Autopilot:**
- `autopilot-system` — System prompt for autonomous mode

**Swarm:**
- `agent-swarm-master` — Master agent prompt for swarm planning

---

## Agent Configuration

Agents are configured in `vigolium-configs.yaml` under the `agent` section:

```yaml
agent:
  default_agent: claude
  templates_dir: ~/.vigolium/prompts/
  sessions_dir: ~/.vigolium/agent-sessions/
  stream: true

  # Warm session pooling — reuses agent subprocesses across calls
  warm_session:
    enable: false
    idle_timeout: 300
    max_sessions: 2

  backends:
    # Claude Code (SDK — recommended default)
    # Full CLI tool access: Read, Grep, Glob, Bash, Edit, Write
    claude:
      command: claude
      protocol: sdk
      model: sonnet

    # Claude Code (pipe mode — simple stdin/stdout)
    claude-cli:
      command: claude
      args: ["--dangerously-skip-permissions", "-p"]

    # OpenAI Codex (native JSON-RPC v2)
    codex:
      command: codex
      protocol: codex-sdk

    # OpenCode (native SDK — REST + SSE streaming)
    opencode:
      command: opencode
      protocol: opencode-sdk
```

### Protocols

| Protocol | Tool Access | Description |
|----------|-------------|-------------|
| `sdk` | Full (Read, Grep, Glob, Bash, Edit, Write) | Claude Agent SDK — JSON-lines protocol. **Default and recommended.** Highest output quality. |
| `codex-sdk` | Full tools | Codex native JSON-RPC v2 protocol. |
| `opencode-sdk` | Full tools | OpenCode native REST + SSE streaming protocol. |
| `pipe` | None (text only) | stdin/stdout — prompt piped to stdin, output from stdout. Legacy fallback. |

### Backend Fields

| Field | Type | Description |
|-------|------|-------------|
| `command` | string | CLI command to launch the agent |
| `args` | []string | Arguments passed to the command |
| `protocol` | string | `sdk`, `codex-sdk`, `opencode-sdk`, or `pipe` |
| `model` | string | Model override (e.g. `sonnet`, `opus`, `haiku`, or full model ID) |
| `description` | string | Human-readable description |
| `env` | map | Environment variables to set |
| `enable` | bool | Enable/disable this backend |
| `mcp_servers` | list | Per-backend MCP server attachments |
| `session_meta` | object | Session metadata for Claude (thinking, effort, tools) |
| `provider_config` | object | Provider-specific config for OpenCode (thinking, permissions) |

### Listing Agents

```bash
vigolium agent --list-agents
```

---

## Output Schemas

Agent output is parsed into structured schemas:

### findings

Used for code review and security analysis. Each finding has:
- `title`, `description`, `severity`, `confidence`
- `file`, `line`, `cwe`
- Findings are saved to the database

### http_records

Used for endpoint discovery and scan target generation. Each record has:
- `url`, `method`, `headers`, `body`
- Records can be scanned by subsequent commands

### attack_plan

Used by pipeline phase 2 (Plan). Contains:
- `module_tags`, `module_ids` — which modules to run
- `focus_areas`, `skip_paths` — scanning guidance
- `endpoints` — prioritized targets with rationale

### triage_result

Used by swarm triage phase. Contains:
- `confirmed` — validated findings with reasons
- `false_positives` — dismissed findings with reasons
- `follow_up_scans` — additional targets for rescan
- `verdict` — `"done"` or `"rescan"` to control the loop

### source_analysis

Used by swarm source analysis phase. Contains:
- `http_records` — extracted routes as HTTP requests with method, URL, headers, body
- `session_config` — login flow and auth configuration (sessions with extract rules)
- `extensions` — custom JavaScript scanner extensions generated from identified sinks
