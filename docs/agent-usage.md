# Agent Usage Guide

Vigolium integrates AI agents for security analysis, code review, and autonomous scanning. This guide covers all four agent modes in detail and explains how to use Vigolium from within Claude Code or OpenCode.

---

## Table of Contents

- [Using Vigolium in Claude Code / OpenCode](#using-vigolium-in-claude-code--opencode)
- [Agent Modes Overview](#agent-modes-overview)
- [Mode 1: Template-Based Run (`vigolium agent`)](#mode-1-template-based-run)
- [Mode 2: Inline Query (`vigolium agent query`)](#mode-2-inline-query)
- [Mode 3: Autopilot (`vigolium agent autopilot`)](#mode-3-autopilot)
- [Mode 4: Pipeline (`vigolium agent pipeline`)](#mode-4-pipeline)
- [Agent Configuration](#agent-configuration)
- [Prompt Templates](#prompt-templates)
- [Output Schemas](#output-schemas)

---

## Using Vigolium in Claude Code / OpenCode

Vigolium ships a Claude Code skill that teaches the AI assistant how to operate the `vigolium` CLI. Once installed, Claude Code can run scans, review code, and triage findings on your behalf using the Bash tool.

### Setup

Copy the skill into your project's `.claude/skills/` directory:

```bash
mkdir -p .claude/skills/vigolium-cli
cp public/skills/vigolium-cli/SKILL.md .claude/skills/vigolium-cli/SKILL.md
cp -r public/skills/vigolium-cli/references .claude/skills/vigolium-cli/references
```

The resulting directory structure:

```
.claude/skills/vigolium-cli/
├── SKILL.md
└── references/
    ├── agent-commands.md
    ├── scanning-commands.md
    ├── server-and-ingestion.md
    ├── data-and-management.md
    ├── writing-extensions.md
    └── flags-reference.md
```

### Prerequisites

- The `vigolium` binary must be installed and available on your `$PATH`.
- An agent backend must be configured if you want to use agent modes (see [Agent Configuration](#agent-configuration)).

### How It Works

Once the skill is in `.claude/skills/`, Claude Code automatically discovers it. You can:

1. **Invoke it explicitly** with `/vigolium-cli` in your Claude Code session.
2. **Let it trigger automatically** — Claude Code loads the skill when your request matches its triggers (e.g., asking about scanning, vulnerabilities, security testing).

Claude Code then runs `vigolium` commands via the Bash tool, using the skill's decision tree and reference files to pick the right command and flags.

### Alternative: Personal Skill (All Projects)

To make the skill available across all your projects, install it to your personal skills directory instead:

```bash
mkdir -p ~/.claude/skills/vigolium-cli
cp public/skills/vigolium-cli/SKILL.md ~/.claude/skills/vigolium-cli/SKILL.md
cp -r public/skills/vigolium-cli/references ~/.claude/skills/vigolium-cli/references
```

---

## Agent Modes Overview

| Mode | AI Calls | Scanner Involvement | Structured Output | Default Timeout | Best For |
|------|----------|--------------------|--------------------|-----------------|----------|
| **Run** | 1 | None | Yes (findings/records) | 5m | Code review, analysis |
| **Query** | 1 | None | No (raw text) | 5m | Quick questions |
| **Autopilot** | Many (agent-driven) | Agent-driven via terminal | Yes (findings) | 30m | Creative exploration |
| **Pipeline** | 2–3 | Native Go callbacks | Yes (plan + triage + report) | 1h | Production scanning, CI/CD |

---

## Mode 1: Template-Based Run

**Command:** `vigolium agent [flags]`

Sends a prompt template to an AI agent, enriches it with database context (previous findings, discovered endpoints, scan stats), and parses the structured JSON output back into the database. The agent never touches the scanner — it only analyzes data you provide.

### Flow

```
Load template → Read source files (--repo)
→ Enrich with DB context (findings, endpoints, stats)
→ Render prompt with Go text/template
→ Send to agent via ACP or pipe protocol
→ Parse structured JSON output
→ Ingest findings/records to DB
```

### Context Enrichment

Before sending the prompt, the engine queries the database for variables declared in the template's `variables` list:

| Variable | Source | Limit |
|----------|--------|-------|
| `PreviousFindings` | Findings filtered by hostname | Top 50 |
| `DiscoveredEndpoints` | HTTP records by hostname | Top 100 |
| `HighRiskEndpoints` | Records with risk_score >= 50 | Top 20 |
| `ScanStats` | Aggregate counts | All |
| `ModuleList` | Active/passive module registry | All |
| `AvailableCommands` | Hardcoded CLI reference | All |

Only variables declared in the template are fetched — a template that only needs `SourceCode` won't trigger any DB queries.

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--prompt-template` | string | — | Template ID (e.g., `security-code-review`) |
| `--prompt-file` | string | — | Path to a custom prompt `.md` file |
| `--repo` | string | — | Source code directory to include as context |
| `--files` | []string | — | Specific files within `--repo` |
| `--agent` | string | config default | Which AI backend to use |
| `--append` | string | — | Extra text appended to the rendered prompt |
| `--output` | string | — | Write raw agent output to a file |
| `--source` | string | — | Source label for ingested records |
| `--dry-run` | bool | false | Render prompt and print it, don't execute |
| `--agent-timeout` | duration | 5m | Timeout (0 = no limit) |
| `--list-templates` | bool | false | List all available prompt templates |
| `--list-agents` | bool | false | List configured agent backends |

### Examples

```bash
# Code review with a built-in template
vigolium agent --prompt-template security-code-review --repo ./my-app

# Review specific files only
vigolium agent --prompt-template security-code-review --repo ./my-app \
  --files "auth.go,middleware.go"

# Use a custom prompt file
vigolium agent --prompt-file ./my-prompt.md --repo ./src

# Append extra instructions to the prompt
vigolium agent --prompt-template security-code-review --repo ./src \
  --append "Focus on authentication and authorization issues"

# Preview the rendered prompt without executing
vigolium agent --prompt-template security-code-review --repo ./src --dry-run

# Use a specific AI backend
vigolium agent --prompt-template security-code-review --repo ./src --agent gemini

# Save output to file
vigolium agent --prompt-template security-code-review --repo ./src --output results.json

# List available templates and backends
vigolium agent --list-templates
vigolium agent --list-agents
```

---

## Mode 2: Inline Query

**Command:** `vigolium agent query [prompt] [flags]`

A lightweight subcommand for ad-hoc questions. No template needed — you type a prompt directly. Returns raw text output with no structured parsing or DB ingestion.

### Flow

```
Resolve prompt (stdin > --prompt > positional arg)
→ Send to agent
→ Stream raw text output to stdout
```

### Prompt Resolution Priority

1. `--stdin` — read from stdin
2. `--prompt` / `-p` — inline string flag
3. Positional argument — first arg

### Flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--prompt` | `-p` | string | — | Inline prompt string |
| `--stdin` | — | bool | false | Read prompt from stdin |
| `--agent` | — | string | config default | Which AI backend |
| `--output` | — | string | — | Write output to file |
| `--source` | — | string | — | Source identifier for ingested records |
| `--agent-timeout` | — | duration | 5m | Timeout |

### Examples

```bash
# Positional argument
vigolium agent query "What are common JWT vulnerabilities in Go apps?"

# Flag-based prompt
vigolium agent query -p "Explain CSRF token bypass techniques"

# Pipe from stdin
echo "Analyze this endpoint for SSRF" | vigolium agent query --stdin

# Pipe a file as prompt
vigolium agent query --stdin < my-question.md

# Save response
vigolium agent query "List OWASP top 10" --output owasp.txt

# With specific agent and longer timeout
vigolium agent query --agent claude --agent-timeout 10m "Comprehensive security review"
```

---

## Mode 3: Autopilot

**Command:** `vigolium agent autopilot [flags]`

The most powerful mode. Gives the AI agent a sandboxed terminal where it can **autonomously run `vigolium` CLI commands**. The agent decides what to scan, reads results, pivots its strategy, and keeps going until it's done or hits the command limit.

### Flow

```
Render system prompt (with target URL, focus area, available commands)
→ Launch ACP session with terminal access
→ Agent loop:
    CreateTerminal("vigolium scan-url ...")
    → WaitForTerminalExit → Read output
    → Decide next action
    → CreateTerminal("vigolium scan-request ...")
    → ... repeat up to --max-commands times
→ Parse final output
→ Ingest findings to DB
```

### Terminal Sandbox Security

The autopilot agent executes commands within a strict sandbox:

| Control | Detail |
|---------|--------|
| **Allowlist** | Only commands starting with `vigolium` are permitted |
| **Blocklist** | `db clean`, `db seed`, `db drop` explicitly denied |
| **Injection prevention** | Shell metacharacters (`;`, `\|`, `&&`, `` ` ``, `$()`) rejected; commands run via `exec()`, not through a shell |
| **Per-command timeout** | 5 minutes |
| **Call limit** | Enforced by `--max-commands` (default 100) |
| **Output cap** | 256KB per session |
| **Process isolation** | Entire process group killed on cleanup |

### What the Agent Can Do

Inside the sandbox, the agent can run any non-destructive `vigolium` subcommand:

```bash
vigolium scan-url https://example.com/api/users --module-tag injection
vigolium scan-request -i request.txt
vigolium module ls
vigolium traffic --host example.com
vigolium finding --severity high
vigolium db stats
```

### Flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--target` | `-t` | string | **(required)** | Target URL |
| `--agent` | — | string | config default | Which AI backend |
| `--focus` | — | string | — | Focus hint (e.g., "API injection", "auth bypass") |
| `--repo` | — | string | — | Source code for whitebox context |
| `--files` | — | []string | — | Specific files to include |
| `--system-prompt` | — | string | — | Custom system prompt file (overrides default) |
| `--max-commands` | — | int | 100 | Max CLI commands the agent can execute |
| `--timeout` | — | duration | 30m | Overall session timeout |
| `--dry-run` | — | bool | false | Print system prompt without launching |

### Examples

```bash
# Basic autonomous scan
vigolium agent autopilot -t https://api.example.com

# Focused on auth bypass with source code context
vigolium agent autopilot -t https://api.example.com --repo ./src --focus "auth bypass"

# Limit agent to 30 commands, 15-minute timeout
vigolium agent autopilot -t https://example.com --max-commands 30 --timeout 15m

# Preview the system prompt the agent will receive
vigolium agent autopilot -t https://example.com --focus "XSS" --dry-run

# Use a custom system prompt
vigolium agent autopilot -t https://example.com --system-prompt ./my-autopilot-prompt.md

# Use Gemini backend
vigolium agent autopilot -t https://example.com --agent gemini
```

---

## Mode 4: Pipeline

**Command:** `vigolium agent pipeline [flags]`

A structured, cost-efficient scanning pipeline where **native Go code handles the heavy lifting** (crawling, scanning) and the AI agent only intervenes at two checkpoints: planning what to scan, and triaging the results. The AI is called only 2–3 times total.

### Phases

```
Phase 1: DISCOVER  [Native Go]  — Deparos crawling + spidering → populates DB with endpoints
Phase 2: PLAN      [AI Agent]   — Analyzes discovered endpoints → outputs AttackPlan
Phase 3: SCAN      [Native Go]  — Executor runs only the modules the AI selected
Phase 4: TRIAGE    [AI Agent]   — Reviews all findings → confirms/rejects each one
Phase 5: RESCAN    [Native Go]  — Targeted rescanning based on triage follow-ups
Phase 6: REPORT    [Native Go]  — Queries DB, aggregates finding counts by severity
```

The triage → rescan loop (phases 4–5) repeats until the agent sets verdict to `"done"` or `--max-rescan-rounds` is reached.

### How Each Phase Works

**Phase 1 — Discover (Native):** Runs the built-in deparos discovery engine and headless browser spidering. Populates the database with HTTP request/response records. No AI involved.

**Phase 2 — Plan (AI):** The agent receives discovered endpoints, high-risk endpoints, and module list as context. It outputs an `AttackPlan` specifying which module tags/IDs to run, which paths to skip, and which endpoints to prioritize. The pipeline validates module tags against the registry.

**Phase 3 — Scan (Native):** The executor runs only the modules the AI selected in the plan, plus all passive modules. Results are saved to the database as findings.

**Phase 4 — Triage (AI):** The agent receives all findings from the database. It classifies each as confirmed or false positive, and optionally recommends follow-up scans. The `verdict` field controls the loop: `"rescan"` triggers another round, `"done"` stops.

**Phase 5 — Rescan (Native):** If the triage verdict is `"rescan"`, the executor runs targeted scans against the follow-up URLs/modules the agent specified. Results flow back to Phase 4.

**Phase 6 — Report (Native):** Queries the database and aggregates finding counts by severity.

### Flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--target` | `-t` | string | **(required)** | Target URL |
| `--agent` | — | string | config default | Which AI backend |
| `--focus` | — | string | — | Focus hint for the planning agent |
| `--repo` | — | string | — | Source code for whitebox context |
| `--files` | — | []string | — | Specific files to include |
| `--profile` | — | string | — | Scanning profile for scan phases |
| `--max-rescan-rounds` | — | int | 2 | Max triage → rescan iterations |
| `--skip-phase` | — | []string | — | Skip specific phases |
| `--start-from` | — | string | — | Resume from a specific phase |
| `--timeout` | — | duration | 1h | Overall pipeline timeout |
| `--dry-run` | — | bool | false | Render agent prompts without executing |

### Examples

```bash
# Basic pipeline scan
vigolium agent pipeline -t https://example.com

# Focused pipeline with extra rescan rounds
vigolium agent pipeline -t https://api.example.com \
  --focus "injection vulnerabilities" --max-rescan-rounds 3

# Use a thorough scanning profile
vigolium agent pipeline -t https://example.com --profile deep

# With source code context
vigolium agent pipeline -t https://example.com --repo ./src \
  --files "routes.go,handlers.go"

# Skip discovery (if you already have endpoints in DB)
vigolium agent pipeline -t https://example.com --skip-phase discover

# Resume from triage (if discover + plan + scan already ran)
vigolium agent pipeline -t https://example.com --start-from triage

# Skip triage and rescan (just discover + plan + scan)
vigolium agent pipeline -t https://example.com \
  --skip-phase triage --skip-phase rescan

# Preview what the AI will receive
vigolium agent pipeline -t https://example.com --dry-run

# Long-running pipeline with generous timeout
vigolium agent pipeline -t https://example.com --timeout 2h --agent claude
```

---

## Agent Configuration

Agents are configured in `~/.vigolium/vigolium-configs.yaml` under the `agent` section:

```yaml
agent:
  default_agent: claude
  templates_dir: ~/.vigolium/prompts/
  stream: true

  warm_session:
    enable: false
    idle_timeout: 300       # seconds
    max_sessions: 2

  agents:
    claude:
      command: npx
      args: ["-y", "@zed-industries/claude-code-acp@latest"]
      description: "Anthropic Claude Code"
      protocol: acp
    opencode:
      command: opencode
      protocol: acp
      description: "OpenCode CLI"
    gemini:
      command: gemini
      protocol: acp
      description: "Gemini CLI"
```

### Protocols

| Protocol | Description | Supports Autopilot |
|----------|-------------|-------------------|
| **acp** | Agent Communication Protocol — bidirectional streaming with tool-use support | Yes |
| **pipe** | Legacy stdin/stdout — prompt piped to stdin, output read from stdout | No |

ACP is required for autopilot mode (terminal execution). Pipe mode works for run and query modes only.

### Warm Session Pooling

Agent subprocesses are expensive to start. The warm session pool reuses ACP sessions across prompts:

- Sessions are matched by agent name and working directory
- LRU eviction when at capacity
- Idle sessions are reaped after `idle_timeout` seconds (default 300)

Enable in config:

```yaml
agent:
  warm_session:
    enable: true
    idle_timeout: 300
    max_sessions: 2
```

### Listing Available Agents

```bash
vigolium agent --list-agents
```

---

## Prompt Templates

Prompt templates are Markdown files with YAML frontmatter.

### Template Locations (priority order)

1. Config `agent.templates_dir` (default `~/.vigolium/prompts/`)
2. User home `~/.vigolium/prompts/`
3. Embedded in binary (`public/presets/prompts/` and subdirectories)

### Template Structure

```markdown
---
id: my-template
name: My Custom Template
description: What this template does
output_schema: findings
variables:
  - SourceCode
  - Language
  - PreviousFindings
---

You are a security analyst. Review the following code for vulnerabilities.

## Source Code

{{.SourceCode}}

## Language

{{.Language}}

## Previous Findings

{{.PreviousFindings}}
```

### Built-in Templates

**SAST / Code Review:**
- `security-code-review` — Comprehensive security code review
- `injection-sinks` — Find injection sinks in source code
- `auth-bypass` — Identify authentication bypass vectors
- `secret-detection` — Detect hardcoded secrets and credentials
- `nextjs-security-audit` — Next.js-specific security review
- `react-xss-audit` — React XSS vulnerability audit

**Analysis / Dynamic:**
- `endpoint-discovery` — Discover API endpoints from source code
- `api-input-gen` — Generate API test inputs
- `curl-command-gen` — Generate cURL commands for testing
- `attack-surface-mapper` — Map application attack surface

**Pipeline:**
- `pipeline-plan` — Phase 2 attack planning checkpoint
- `pipeline-triage` — Phase 4 finding triage checkpoint

**Autopilot:**
- `autopilot-system` — System prompt for autonomous mode

### Listing Templates

```bash
vigolium agent --list-templates
```

---

## Output Schemas

The template's `output_schema` field determines how the agent's response is parsed.

### findings

Used for code review and security analysis. Findings are deduplicated and saved to the database.

```json
{
  "findings": [
    {
      "title": "SQL Injection in user lookup",
      "description": "User input concatenated into SQL query without parameterization",
      "severity": "high",
      "confidence": "firm",
      "file": "src/db/users.go",
      "line": 42,
      "snippet": "db.Query(\"SELECT * FROM users WHERE id=\" + userID)",
      "cwe": "CWE-89",
      "tags": ["sqli", "injection"]
    }
  ]
}
```

### http_records

Used for endpoint discovery and scan target generation. Records are saved to the database with source label `"agent"`.

```json
{
  "http_records": [
    {
      "method": "POST",
      "url": "https://api.example.com/auth/login",
      "headers": {"Content-Type": "application/json"},
      "body": "{\"username\": \"test\", \"password\": \"test\"}",
      "notes": "Login endpoint, test for credential stuffing"
    }
  ]
}
```

### attack_plan

Used by pipeline phase 2 (Plan). The AI selects which modules to run and which endpoints to prioritize.

```json
{
  "module_tags": ["injection", "xss", "auth"],
  "module_ids": ["active-sqli-error-based"],
  "focus_areas": ["SQL injection in /api/users"],
  "skip_paths": ["/static/", "/assets/"],
  "endpoints": [
    {
      "url": "https://example.com/api/users?id=1",
      "method": "GET",
      "priority": "high",
      "rationale": "User ID parameter susceptible to SQLi",
      "tags": ["sqli"]
    }
  ],
  "notes": "Focus on parameter tampering in auth endpoints"
}
```

### triage_result

Used by pipeline phase 4 (Triage). The AI classifies findings and decides whether to rescan.

```json
{
  "confirmed": [
    {
      "title": "SQL Injection in /api/users",
      "module_id": "active-sqli-error-based",
      "url": "https://example.com/api/users?id=1",
      "reason": "Error-based response confirms MySQL injection"
    }
  ],
  "false_positives": [
    {
      "title": "XSS in /static/page",
      "module_id": "active-xss",
      "url": "https://example.com/static/page",
      "reason": "Static HTML page, no user input reflected"
    }
  ],
  "follow_up_scans": [
    {
      "url": "https://example.com/api/admin",
      "method": "POST",
      "module_tags": ["auth", "injection"],
      "rationale": "Admin endpoint not covered in initial scan"
    }
  ],
  "verdict": "done",
  "notes": "All critical findings confirmed, no further scanning needed"
}
```

The `verdict` field controls the rescan loop: `"rescan"` triggers another round, `"done"` stops.
