# Agent Mode

Vigolium's agent mode lets you run AI coding agents (Claude, Codex, OpenCode, Gemini, or any custom CLI tool) to perform security analysis. Three execution modes are available:

| Mode | Command | AI Involvement | Best For |
|------|---------|----------------|----------|
| **Run** | `vigolium agent` | Single prompt → structured output | Code review, endpoint discovery |
| **Autopilot** | `vigolium agent autopilot` | Full autonomy — agent drives CLI | Exploratory scanning, ad-hoc testing |
| **Pipeline** | `vigolium agent pipeline` | Fixed phases, AI at checkpoints only | Production scanning, predictable runtime |

## Quick Start

```bash
# Code review with structured findings
vigolium agent --prompt-template security-code-review --repo ./src

# Autonomous scanning — agent decides what to do
vigolium agent autopilot -t https://example.com

# Multi-phase pipeline — AI plans and triages, scanner does the work
vigolium agent pipeline -t https://example.com
```

## CLI Commands

### `vigolium agent` — Single Run

Run a prompt template or inline prompt against an agent. Returns structured JSON (findings or HTTP records) saved to the database.

```bash
# Template-based code review
vigolium agent --prompt-template security-code-review --repo ./src

# Review specific files
vigolium agent --prompt-template injection-sinks --repo ./src --files db/query.go,api/handler.go

# Custom prompt file
vigolium agent --prompt-file my-prompt.md --repo ./src

# Dry run — render the prompt without executing
vigolium agent --prompt-template endpoint-discovery --repo ./src --dry-run

# List available templates and agents
vigolium agent --list-templates
vigolium agent --list-agents
```

**Flags:**

| Flag | Description |
|------|-------------|
| `--prompt-template` | Template ID (e.g., `security-code-review`) |
| `--prompt-file` | Path to a custom prompt markdown file |
| `--repo` | Path to source code repository |
| `--files` | Specific files to include (relative to `--repo`) |
| `--agent` | Agent backend to use (default from config) |
| `--append` | Extra text appended to the rendered prompt |
| `--output` | Write agent output to file |
| `--source` | Source identifier for saved findings |
| `--dry-run` | Render prompt without executing |
| `--agent-timeout` | Timeout for agent execution |

### `vigolium agent query` — Inline Prompt

Send a freeform prompt to an agent without templates or structured output.

```bash
vigolium agent query 'What are common JWT vulnerabilities?'
vigolium agent query --agent gemini --prompt-file question.md
echo "explain CSRF" | vigolium agent query --stdin
```

### `vigolium agent autopilot` — Autonomous Scanning

Launch an AI agent that autonomously discovers, scans, and triages vulnerabilities by running vigolium CLI commands via terminal execution.

The agent receives a system prompt with available commands and workflow guidance, then decides its own approach: discovering endpoints, running targeted scans, reviewing results, and iterating.

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

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `-t, --target` | (required) | Target URL |
| `--agent` | config default | Agent backend |
| `--repo` | | Source code path for agent context |
| `--files` | | Specific files to include |
| `--focus` | | Focus area hint (e.g., "API injection") |
| `--system-prompt` | | Custom system prompt file (overrides default) |
| `--timeout` | 30m | Overall timeout |
| `--max-commands` | 100 | Max CLI commands the agent can execute |
| `--dry-run` | | Render system prompt without launching |

#### Terminal Security Model

The autopilot agent can only execute commands within a strict sandbox:

- **Allowlist**: Only `vigolium` commands are permitted
- **Blocklist**: Destructive subcommands are blocked (`db clean`, `db seed`, `db drop`)
- **Shell injection prevention**: Shell metacharacters (`;|&\`$(){}!><`) are rejected; commands are executed directly via `exec`, not through a shell
- **Per-command timeout**: 5 minutes per command
- **Call limit**: Enforced by `--max-commands` (default 100)
- **Output cap**: 256KB per command session
- **Process isolation**: Terminal child processes run in their own process group and are killed on cleanup

### `vigolium agent pipeline` — Multi-Phase Pipeline

Run a fixed multi-phase scanning pipeline where the AI agent only intervenes at specific checkpoints. Native Go code handles the heavy lifting (discovery, scanning), while the agent provides strategic decisions (attack planning, finding triage).

```
Phase 1: Discover  → Native deparos + spidering (no AI)
Phase 2: Plan      → Agent analyzes discovery results → AttackPlan
Phase 3: Scan      → Native executor with agent-selected modules (no AI)
Phase 4: Triage    → Agent reviews findings → TriageResult
Phase 5: Rescan    → Targeted rescanning from triage recommendations (no AI)
Phase 6: Report    → Structured output from DB (no AI)
```

The triage→rescan loop (phases 4-5) repeats until the agent sets verdict to `"done"` or the max rescan rounds are reached.

```bash
# Basic pipeline scan
vigolium agent pipeline -t https://example.com

# With focus and source code
vigolium agent pipeline -t https://example.com --focus "SQL injection" --repo ./src

# Control rescan iterations
vigolium agent pipeline -t https://example.com --max-rescan-rounds 3

# Skip discovery (use existing DB records) and start from planning
vigolium agent pipeline -t https://example.com --skip-phase discover --start-from plan

# Use a scanning profile
vigolium agent pipeline -t https://example.com --profile deep

# Preview agent prompts
vigolium agent pipeline -t https://example.com --dry-run
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `-t, --target` | (required) | Target URL |
| `--agent` | config default | Agent backend |
| `--repo` | | Source code path |
| `--files` | | Specific files to include |
| `--focus` | | Focus area hint for the planning agent |
| `--timeout` | 1h | Overall pipeline timeout |
| `--max-rescan-rounds` | 2 | Max triage→rescan iterations |
| `--skip-phase` | | Skip phases (discover, plan, scan, triage, rescan, report) |
| `--start-from` | | Resume from a specific phase |
| `--profile` | | Scanning profile for scan phases |
| `--dry-run` | | Render agent prompts without executing |

#### Pipeline Output Schemas

The plan and triage agent checkpoints produce structured JSON:

**AttackPlan** (phase 2 output):

```json
{
  "module_tags": ["injection", "xss", "auth"],
  "module_ids": [],
  "focus_areas": ["SQL injection in API parameters", "XSS in search"],
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
  "notes": "Strategy summary"
}
```

**TriageResult** (phase 4 output):

```json
{
  "confirmed": [
    {
      "title": "SQL Injection in /api/users",
      "module_id": "sqli-error-based",
      "url": "https://example.com/api/users?id=1",
      "reason": "Error-based response confirms MySQL injection"
    }
  ],
  "false_positives": [
    {
      "title": "XSS in /static/page",
      "module_id": "xss",
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
  "notes": "Assessment summary"
}
```

The `verdict` field controls the rescan loop: `"rescan"` triggers another round with the specified follow-ups, `"done"` stops the loop.

## Configuration

Add an `agent` section to `~/.vigolium/vigolium-configs.yaml`:

```yaml
agent:
  default_agent: claude              # Default backend to use
  templates_dir: ~/.vigolium/prompts/  # Custom template directory
  stream: true                       # Stream agent output in real-time

  # Warm session pooling — reuses agent subprocesses across runs
  warm_session:
    enable: false                    # Enable subprocess pooling
    idle_timeout: 300                # Seconds to keep idle session alive
    max_sessions: 2                  # Max concurrent sessions per agent

  agents:
    # ACP (Agent Communication Protocol) — preferred for modern agents
    claude:
      command: npx
      args: ["-y", "@zed-industries/claude-code-acp@latest"]
      description: "Anthropic Claude Code (ACP)"
      protocol: acp

    codex:
      command: npx
      args: ["-y", "@zed-industries/codex-acp"]
      description: "OpenAI Codex CLI (ACP)"
      protocol: acp

    opencode:
      command: npx
      args: ["-y", "opencode-acp"]
      description: "OpenCode agent (ACP)"
      protocol: acp

    gemini:
      command: gemini
      args: ["--experimental-acp"]
      description: "Google Gemini CLI (ACP)"
      protocol: acp

    # Pipe mode — legacy fallback (prompt piped to stdin, output read from stdout)
    claude-cli:
      command: claude
      args: ["--dangerously-skip-permissions", "-p"]
      description: "Anthropic Claude Code (pipe mode)"
      protocol: pipe

    opencode-cli:
      command: opencode
      args: ["run"]
      description: "OpenCode agent (pipe mode)"
      protocol: pipe

    gemini-cli:
      command: gemini
      args: ["-p"]
      description: "Google Gemini CLI (pipe mode)"
      protocol: pipe
```

### Protocols

| Protocol | Description |
|----------|-------------|
| `acp` | Agent Communication Protocol — structured bidirectional communication, supports filesystem tools and terminal execution. Preferred. |
| `pipe` | Classic stdin/stdout — prompt piped to stdin, output read from stdout. Legacy fallback. |

### Warm Sessions

When enabled, vigolium keeps agent subprocesses alive between runs to avoid cold-start latency (e.g., `npx` package resolution). Sessions are matched by agent name and working directory. An idle reaper kills sessions after `idle_timeout` seconds.

```yaml
agent:
  warm_session:
    enable: true
    idle_timeout: 300    # Kill idle sessions after 5 minutes
    max_sessions: 2      # Max concurrent pooled sessions
```

### Adding a Custom Agent

Any CLI tool that reads a prompt from stdin and writes JSON to stdout can be configured as an agent backend:

```yaml
agent:
  agents:
    my-agent:
      command: my-tool
      args: ["--json", "--security-review"]
      description: "My custom security agent"
      protocol: pipe
      env:
        MY_API_KEY: "${MY_API_KEY}"
```

Then use it with `--agent my-agent` or set it as `default_agent`.

## Output Schemas

When using prompt templates, agents must write JSON to stdout matching one of these schemas. For freeform prompts (`--prompt` / `query`) the raw output is returned directly.

### Findings

```json
{
  "findings": [
    {
      "title": "SQL Injection in Query Builder",
      "description": "User input is concatenated into SQL query without parameterization.",
      "severity": "high",
      "confidence": "firm",
      "file": "db/query.go",
      "line": 42,
      "snippet": "db.Exec(\"SELECT * FROM users WHERE id=\" + userID)",
      "cwe": "CWE-89",
      "tags": ["sqli", "injection"]
    }
  ]
}
```

### HTTP Records

```json
{
  "http_records": [
    {
      "method": "POST",
      "url": "https://api.example.com/users",
      "headers": {"Content-Type": "application/json"},
      "body": "{\"name\": \"test\", \"email\": \"test@example.com\"}",
      "notes": "Create user endpoint"
    }
  ]
}
```

## Agent Instruction Presets

Vigolium ships with agent instruction files (e.g. `CLAUDE.md`, `agents.md`) that give AI agents context about the scanner's CLI commands, flags, and workflows. These are located in `public/presets/agents-md/`.

| File | Description |
|------|-------------|
| `vigolium-scanner.md` | Vigolium CLI reference for AI agents — covers `scan-url`, `scan-request`, `module ls`, `ingest`, JSON output, and common flags |

Copy the preset into your project root to give your agent automatic context:

```bash
# For Claude Code
cp public/presets/agents-md/vigolium-scanner.md /path/to/your/project/CLAUDE.md

# Or append to an existing CLAUDE.md / agents.md
cat public/presets/agents-md/vigolium-scanner.md >> /path/to/your/project/CLAUDE.md
```

## Built-in Prompt Templates

### Security Analysis (SAST)

| ID | Output Schema | Description |
|----|---------------|-------------|
| `security-code-review` | `findings` | General security code review covering OWASP categories |
| `injection-sinks` | `findings` | Identify injection sinks (SQLi, command injection, SSRF, etc.) |
| `auth-bypass` | `findings` | Detect authentication and authorization bypass patterns |
| `secret-detection` | `findings` | Find hardcoded secrets and credentials |
| `nextjs-security-audit` | `findings` | Next.js-specific security review |
| `react-xss-audit` | `findings` | React XSS pattern analysis |
| `auth-session-review` | `findings` | Authentication and session management review |
| `cors-csrf-review` | `findings` | CORS and CSRF configuration review |
| `build-config-audit` | `findings` | Build and deployment config security |

### Endpoint Discovery & Analysis

| ID | Output Schema | Description |
|----|---------------|-------------|
| `endpoint-discovery` | `http_records` | Extract API endpoints and routes from source code |
| `api-input-gen` | `http_records` | Generate HTTP requests from discovered API endpoints |
| `curl-command-gen` | `http_records` | Discover all routes and generate curl commands for each endpoint |
| `attack-surface-mapper` | `http_records` | Discover API endpoints from source code and cross-reference with existing records |

### Interactive (for autopilot / pipeline)

| ID | Output Schema | Description |
|----|---------------|-------------|
| `interactive-scan` | `findings` | Analyze source code, run targeted scans with `scan-url`, and report verified findings |
| `targeted-retest` | `findings` | Verify and retest previously discovered findings with targeted scans |
| `autopilot-system` | `text` | System prompt for autonomous CLI-driven scanning (used by `agent autopilot`) |
| `pipeline-plan` | `attack_plan` | Analyze discovery results and plan attack strategy (used by `agent pipeline`) |
| `pipeline-triage` | `triage_result` | Review findings, identify false positives, recommend follow-ups (used by `agent pipeline`) |

### Custom Templates

Templates are Markdown files with YAML frontmatter:

```markdown
---
id: my-template
name: My Custom Review
description: Custom security analysis
output_schema: findings
variables:
  - SourceCode
  - Language
  - PreviousFindings
---

You are a security reviewer. Analyze the following code:

{{.SourceCode}}

Language: {{.Language}}

{{if .PreviousFindings}}
## Previous Findings
{{.PreviousFindings}}
{{end}}

Output your findings as JSON matching the findings schema.
```

**Available template variables:**

| Variable | Description |
|----------|-------------|
| `SourceCode` | Concatenated source files from `--repo` / `--files` |
| `Language` | Detected primary language |
| `FilePath` | Primary file path |
| `TargetURL` | Target URL (from `-t`) |
| `Hostname` | Hostname derived from target URL |
| `PreviousFindings` | JSON array of findings from DB (top 50) |
| `DiscoveredEndpoints` | JSON array of HTTP records from DB (top 100) |
| `HighRiskEndpoints` | JSON array of high risk-score records from DB (top 20) |
| `ModuleList` | JSON array of available scanner modules |
| `ScanStats` | JSON object of scan statistics |
| `AvailableCommands` | Hardcoded CLI command reference |

Variables are only populated if declared in the template's `variables` list.

Templates are loaded from (highest priority first):

1. Config `agent.templates_dir` (default `~/.vigolium/prompts/`)
2. `~/.vigolium/prompts/`
3. Embedded templates bundled with the binary

## REST API

When running Vigolium in server mode, agent runs can be triggered and monitored via the API. Three run endpoints mirror the CLI subcommands:

| Endpoint                         | CLI Equivalent              | Description                              |
|----------------------------------|-----------------------------|------------------------------------------|
| `POST /api/agent/run/query`      | `vigolium agent [query]`    | Single-shot prompt execution             |
| `POST /api/agent/run/autopilot`  | `vigolium agent autopilot`  | Autonomous AI-driven scanning session    |
| `POST /api/agent/run/pipeline`   | `vigolium agent pipeline`   | Multi-phase scanning pipeline            |

Only one agent run can be active at a time (returns `409 Conflict` if busy).

### Query — Single-Shot Run

```
POST /api/agent/run/query
```

Accepts both template-based and direct-prompt requests. At least one of `prompt_template`, `prompt_file`, or `prompt` is required.

```json
{
  "agent": "claude",
  "prompt_template": "security-code-review",
  "repo_path": "/path/to/repo",
  "files": ["main.go", "handlers.go"],
  "append": "Focus on authentication logic",
  "source": "my-project"
}
```

Returns `202 Accepted` by default. Add `"stream": true` for SSE streaming.

### Autopilot — Autonomous Scanning

```
POST /api/agent/run/autopilot
```

Launches an AI agent that autonomously scans a target using vigolium CLI commands via a sandboxed terminal. Requires a `target` URL.

```json
{
  "target": "https://example.com",
  "agent": "claude",
  "focus": "API injection",
  "max_commands": 50,
  "timeout": "30m"
}
```

### Pipeline — Multi-Phase Scanning

```
POST /api/agent/run/pipeline
```

Runs the fixed multi-phase pipeline (discover → plan → scan → triage → rescan → report). AI agents are called at phases 2 (plan) and 4 (triage). Requires a `target` URL.

```json
{
  "target": "https://example.com",
  "agent": "claude",
  "focus": "auth bypass",
  "profile": "thorough",
  "skip_phases": ["rescan"],
  "timeout": "1h"
}
```

### Check Run Status

```
GET /api/agent/status/:id
```

Returns run status including a `mode` field (`"query"`, `"autopilot"`, or `"pipeline"`). Pipeline runs include `current_phase`, `phases_run`, and `pipeline_result` fields.

```json
{
  "run_id": "agt-550e8400-e29b-41d4-a716-446655440000",
  "mode": "query",
  "status": "completed",
  "agent_name": "claude",
  "template_id": "security-code-review",
  "finding_count": 5,
  "saved_count": 5,
  "result": { "..." }
}
```

Status is one of `running`, `completed`, or `failed`.

### List All Runs

```
GET /api/agent/status/list
```

Returns an array of all run statuses.

### Streaming (Server-Sent Events)

All three run endpoints support `"stream": true` for real-time SSE output. The connection stays open until the agent finishes.

```bash
curl -N http://localhost:9002/api/agent/run/query \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <api-key>" \
  -d '{"prompt": "Explain CSRF in one paragraph", "stream": true}'
```

Events are newline-delimited `data:` lines with JSON payloads:

| Event type | Description | Modes |
|------------|-------------|-------|
| `chunk` | Real-time text from the agent | All |
| `phase` | Pipeline phase transition (`{"type":"phase","phase":"discover"}`) | Pipeline |
| `done` | Agent finished successfully | All |
| `error` | Agent failed | All |

The `done` event includes `result` for query/autopilot runs and `pipeline_result` for pipeline runs.

### OpenAI-Compatible Chat Completions

```
POST /api/agent/chat/completions
```

This endpoint accepts the OpenAI Chat Completions request format and returns an OpenAI-compatible response. This lets you use Vigolium agents from any OpenAI-compatible client or tool by just changing the base URL.

The `model` field maps to agent names in your config. If `model` matches a key in `agent.agents` (e.g. `"claude"`, `"opencode"`, `"gemini"`), that agent is used. Otherwise, the default agent is used — so any unrecognized model name (e.g. `"gpt-4o"`) falls back to the default.

**Request body:**

```json
{
  "model": "claude",
  "messages": [
    { "role": "user", "content": "What are common JWT vulnerabilities?" }
  ]
}
```

| Field      | Type     | Required | Description                                      |
|------------|----------|----------|--------------------------------------------------|
| `model`    | string   | Yes      | Agent name or any string (falls back to default) |
| `messages` | array    | Yes      | Array of `{role, content}` message objects       |

**Response:**

```json
{
  "id": "chatcmpl-550e8400-e29b-41d4-a716-446655440000",
  "object": "chat.completion",
  "created": 1708531200,
  "model": "claude",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "Common JWT vulnerabilities include..."
      },
      "finish_reason": "stop"
    }
  ]
}
```

This endpoint is **synchronous** — it blocks until the agent completes and returns the full response (no streaming). It shares the same concurrency lock as the run endpoints, so only one agent run can execute at a time (returns `409 Conflict` if busy).

#### Using with OpenAI-compatible clients

```bash
# With curl (standard OpenAI format)
curl http://localhost:9002/api/agent/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <api-key>" \
  -d '{
    "model": "claude",
    "messages": [{"role": "user", "content": "Explain CSRF attacks"}]
  }'

# With OpenAI Python client
from openai import OpenAI
client = OpenAI(base_url="http://localhost:9002/api/agent", api_key="<api-key>")
response = client.chat.completions.create(
    model="claude",
    messages=[{"role": "user", "content": "Explain CSRF attacks"}],
)
print(response.choices[0].message.content)
```

### curl Examples

```bash
# Query: direct prompt (async)
curl -X POST http://localhost:9002/api/agent/run/query \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <api-key>" \
  -d '{"prompt": "How are you doing?"}'

# Query: template-based run
curl -X POST http://localhost:9002/api/agent/run/query \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <api-key>" \
  -d '{"prompt_template": "security-code-review", "repo_path": "/path/to/repo"}'

# Query: streaming
curl -N http://localhost:9002/api/agent/run/query \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <api-key>" \
  -d '{"prompt": "List common API misconfigurations", "stream": true}'

# Autopilot: autonomous scan
curl -X POST http://localhost:9002/api/agent/run/autopilot \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <api-key>" \
  -d '{"target": "https://example.com", "focus": "API injection"}'

# Pipeline: multi-phase scan with streaming
curl -N http://localhost:9002/api/agent/run/pipeline \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <api-key>" \
  -d '{"target": "https://example.com", "profile": "thorough", "stream": true}'

# OpenAI-compatible chat completion
curl http://localhost:9002/api/agent/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <api-key>" \
  -d '{"model": "claude", "messages": [{"role": "user", "content": "What is XSS?"}]}'

# Check status
curl http://localhost:9002/api/agent/status/agt-550e8400... \
  -H "Authorization: Bearer <api-key>"

# List all runs
curl http://localhost:9002/api/agent/status/list \
  -H "Authorization: Bearer <api-key>"
```

## Choosing a Mode

| Consideration | Run | Autopilot | Pipeline |
|---------------|-----|-----------|----------|
| **AI cost** | 1 call | Many calls (agent-driven) | 2-3 calls (plan + triage) |
| **Predictability** | High | Low (agent decides) | High (fixed phases) |
| **Runtime** | Seconds | Minutes | Minutes-hours |
| **Scan coverage** | Code review only | Agent-determined | Full (discover→scan→triage) |
| **Best for** | Code review, SAST | Exploratory, research | Production, CI/CD |
| **Requires target URL** | No | Yes | Yes |
| **Source code input** | Yes (`--repo`) | Optional (`--repo`) | Optional (`--repo`) |

**Use `agent` (single run)** when you want to review source code or generate endpoints from code — no target URL needed.

**Use `agent autopilot`** when you want the AI to explore freely — best for targets you haven't scanned before or when you want creative attack strategies.

**Use `agent pipeline`** when you need predictable, cost-efficient scanning — discovery and scanning run natively (fast, no AI overhead), the agent only intervenes to plan and triage.
