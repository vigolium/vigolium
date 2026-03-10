# Agent Mode

Vigolium's agent mode integrates AI agents (Claude, Codex, OpenCode, Gemini, or any custom CLI tool) into the vulnerability scanning workflow. Four execution modes are available, each with different levels of AI involvement and scope.

## Mode Overview

| Mode | Command | Scope | AI Calls | Best For |
|------|---------|-------|----------|----------|
| **Run/Query** | `vigolium agent` | Source code | 1 | Code review, endpoint discovery, SAST |
| **Autopilot** | `vigolium agent autopilot` | Entire target | Many | Exploratory scanning, ad-hoc research |
| **Pipeline** | `vigolium agent pipeline` | Entire target | 2-4 | Production scanning, CI/CD |
| **Swarm** | `vigolium agent swarm` | Single request | 2-3 | Deep targeted testing of specific endpoints |

## Quick Start

```bash
# Code review — single AI call, structured findings
vigolium agent --prompt-template security-code-review --source ./src

# Autonomous scanning — agent drives the CLI
vigolium agent autopilot -t https://example.com

# Multi-phase pipeline — AI plans and triages, scanner does the work
vigolium agent pipeline -t https://example.com

# Targeted swarm — AI generates custom payloads for one endpoint
vigolium agent swarm -t https://example.com/api/users --vuln-type sqli
```

---

## Run / Query

Single-shot prompt execution. Send a prompt template or inline prompt to an AI agent and get structured output (findings or HTTP records) saved to the database.

### What It Does

- Loads a prompt template, enriches it with source code and database context, sends it to the agent
- Agent returns structured JSON (findings or HTTP records)
- Results are parsed and saved to the database
- No network scanning — purely analyzes what you give it

### CLI

```bash
# Template-based code review
vigolium agent --prompt-template security-code-review --source ./src

# Review specific files
vigolium agent --prompt-template injection-sinks --source ./src --files db/query.go,api/handler.go

# Custom prompt file
vigolium agent --prompt-file my-prompt.md --source ./src

# Freeform question (no structured output)
vigolium agent query "What are common JWT vulnerabilities?"

# Pipe prompt from stdin
echo "explain CSRF" | vigolium agent query --stdin

# Dry run — render prompt without executing
vigolium agent --prompt-template endpoint-discovery --source ./src --dry-run

# List available templates and agents
vigolium agent --list-templates
vigolium agent --list-agents
```

**Key Flags:**

| Flag | Description |
|------|-------------|
| `--prompt-template` | Template ID (e.g., `security-code-review`) |
| `--prompt-file` | Path to a custom prompt markdown file |
| `--source` | Path to source code repository |
| `--files` | Specific files to include (relative to `--source`) |
| `--agent` | Agent backend to use (default from config) |
| `--append` | Extra text appended to the rendered prompt |
| `--output` | Write agent output to file |
| `--dry-run` | Render prompt without executing |

### API

```
POST /api/agent/run/query
```

```json
{
  "agent": "claude",
  "prompt_template": "security-code-review",
  "source": "/path/to/repo",
  "files": ["main.go", "handlers.go"],
  "append": "Focus on authentication logic",
  "stream": true
}
```

At least one of `prompt_template`, `prompt_file`, or `prompt` is required.

### Pros and Cons

| Pros | Cons |
|------|------|
| Fast — single AI call, seconds to complete | No network scanning — code analysis only |
| Low cost — one prompt, one response | Requires source code access |
| Deterministic — same template = consistent scope | Findings are unverified (no live confirmation) |
| Good for CI/CD integration | Limited to what the template asks for |

### When to Use

- **Code review** before deployment — catch injection sinks, hardcoded secrets, auth bypasses
- **Endpoint discovery** from source code — extract API routes for manual or automated testing
- **Quick triage** — ask the agent about a specific security question
- You have source code but no running target

---

## Autopilot

Full autonomous control. The AI agent drives the vigolium CLI through a sandboxed terminal, deciding what to scan, interpreting results, and iterating.

### What It Does

- Spawns an AI agent with terminal execution capability via ACP (Agent Communication Protocol)
- Agent autonomously runs vigolium commands: discovery, targeted scans, traffic browsing, finding review
- All commands execute inside a strict security sandbox (only `vigolium` commands, no shell, no destructive ops)
- Agent decides its own workflow — discover, scan, review, iterate, report

### CLI

```bash
# Basic autonomous scan
vigolium agent autopilot -t https://example.com

# With source code context
vigolium agent autopilot -t http://localhost:3000 --source ~/projects/my-app

# With focus area
vigolium agent autopilot -t https://api.example.com --focus "auth bypass"

# Custom limits
vigolium agent autopilot -t https://example.com --max-commands 50 --timeout 15m

# Preview system prompt
vigolium agent autopilot -t https://example.com --dry-run
```

**Key Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `-t, --target` | (required) | Target URL |
| `--source` | — | Path to application source code |
| `--focus` | — | Focus area hint (e.g., "API injection") |
| `--timeout` | 30m | Overall timeout |
| `--max-commands` | 100 | Maximum CLI commands the agent can execute |
| `--dry-run` | false | Render system prompt without launching |

### API

```
POST /api/agent/run/autopilot
```

```json
{
  "target": "https://example.com",
  "agent": "claude",
  "source": "/path/to/source",
  "focus": "API injection",
  "max_commands": 50,
  "timeout": "30m",
  "stream": true
}
```

### Security Sandbox

The agent can only execute `vigolium` commands. Shell metacharacters, destructive subcommands (`db clean`, `db drop`), and non-vigolium binaries are blocked. Each command has a 5-minute timeout and 256KB output cap.

### Pros and Cons

| Pros | Cons |
|------|------|
| Most flexible — agent adapts strategy dynamically | Highest AI cost — long agent session with many calls |
| Can discover unexpected attack vectors | Unpredictable runtime and coverage |
| Source-aware workflow when `--source` provided | Results depend heavily on agent quality |
| No prior knowledge of target needed | Harder to reproduce — agent may take different paths |

### When to Use

- **Exploratory testing** of unfamiliar targets — let the AI figure out what's there
- **Research and experimentation** — trying creative attack strategies
- You want **hands-off scanning** and don't mind variable runtime
- **Source-aware scanning** — agent reads code, identifies sinks, crafts targeted attacks

---

## Pipeline

Fixed 7-phase scanning workflow where native Go code does the heavy lifting and AI agents only intervene at strategic checkpoints (source analysis, planning, triage).

### What It Does

- Runs a deterministic sequence of phases: source analysis → discover → plan → scan → triage → rescan → report
- Native Go handles discovery, scanning, and reporting (fast, no AI cost)
- AI only called at 3 checkpoints: Phase 0 (source analysis), Phase 2 (planning), Phase 4 (triage)
- Phase 0 is automatic when `--source` is provided — extracts routes, auth flows, and generates custom scanner extensions from source code

### CLI

```bash
# Basic pipeline scan
vigolium agent pipeline -t https://example.com

# With source code (enables Phase 0: source analysis)
vigolium agent pipeline -t http://localhost:3000 --source ~/projects/juice-shop

# With focus area and scanning profile
vigolium agent pipeline -t https://example.com --focus "SQL injection" --profile thorough

# Control rescan iterations
vigolium agent pipeline -t https://example.com --max-rescan-rounds 3

# Skip discovery (use existing DB records)
vigolium agent pipeline -t https://example.com --skip-phase discover --start-from plan

# Preview agent prompts
vigolium agent pipeline -t https://example.com --dry-run
```

**Key Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `-t, --target` | (required) | Target URL |
| `--source` | — | Path to application source code (enables Phase 0) |
| `--focus` | — | Focus area hint for the planning agent |
| `--timeout` | 1h | Overall timeout |
| `--max-rescan-rounds` | 2 | Max triage→rescan iterations |
| `--skip-phase` | — | Skip specific phases |
| `--start-from` | — | Resume from a specific phase |
| `--profile` | — | Scanning profile name |
| `--dry-run` | false | Render prompts without executing |

### Phases

```
Phase 0: Source Analysis  (AI — conditional)  — Extract routes, session config, extensions from source
Phase 1: Discover         (Native)            — Content discovery + spidering
Phase 2: Plan             (AI)                — Agent selects modules and prioritizes targets
Phase 3: Scan             (Native)            — Dynamic assessment with selected modules
Phase 4: Triage           (AI)                — Agent classifies findings, recommends follow-ups
Phase 5: Rescan           (Native, loop)      — Targeted rescan from triage recommendations
Phase 6: Report           (Native)            — Aggregate results
```

Phase 0 is automatically skipped when `--source` is not provided.

### API

```
POST /api/agent/run/pipeline
```

```json
{
  "target": "https://example.com",
  "agent": "claude",
  "source": "/path/to/source",
  "focus": "auth bypass",
  "profile": "thorough",
  "max_rescan_rounds": 2,
  "skip_phases": ["report"],
  "timeout": "1h",
  "stream": true
}
```

### Pros and Cons

| Pros | Cons |
|------|------|
| Predictable — fixed phases, deterministic flow | Less flexible — can't adapt mid-scan |
| Cost-efficient — 2-4 AI calls, rest is native | Requires target URL |
| Full-scope — discovery through triage | Longer runtime for large targets |
| Source-aware — Phase 0 generates auth config and extensions | Phase 0 quality depends on source code complexity |
| Resumable — `--start-from` and `--skip-phase` | Triage limited by what the agent can infer from findings |
| Good for CI/CD — stable runtime envelope | |

### When to Use

- **Production scanning** — predictable cost, runtime, and coverage
- **CI/CD integration** — consistent phases with stable timeouts
- **Source-aware scanning** — have source code and want automatic route extraction, auth setup, and custom extensions
- You want **full target coverage** (discovery → scan → triage) with minimal AI overhead

---

## Swarm

Multi-agent targeted vulnerability scanning. A master AI agent analyzes a specific HTTP request, selects scanner modules, generates custom attack payloads as JavaScript extensions, and executes a focused scan.

### What It Does

- Takes heterogeneous input (URL, curl command, raw HTTP request, Burp XML export, or database record UUID)
- Master agent analyzes the request, selects modules, and generates custom JS scanner extensions
- Runs dynamic assessment with agent-selected modules + generated extensions
- Triages extension-generated findings (built-in module findings pass through as-is)
- Supports triage→rescan loop up to `--max-iterations`

### CLI

```bash
# Target a URL
vigolium agent swarm -t https://example.com/api/users

# Analyze a curl command
vigolium agent swarm --input "curl -X POST https://example.com/api/login -d '{\"user\":\"admin\"}'"

# Pipe raw HTTP request from stdin
echo -e "POST /api/search HTTP/1.1\r\nHost: example.com\r\n\r\nq=test" | vigolium agent swarm --input -

# Scan a record from the database
vigolium agent swarm --record-uuid 550e8400-e29b-41d4-a716-446655440000

# Focus on specific vulnerability type
vigolium agent swarm -t https://example.com/api/users --vuln-type sqli

# Specify modules explicitly alongside agent selections
vigolium agent swarm -t https://example.com/api/search -m xss-reflected,xss-stored

# Preview the master agent prompt
vigolium agent swarm -t https://example.com/api/users --dry-run
```

**Key Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `-t, --target` | — | Target URL |
| `--input` | — | Raw input (curl, raw HTTP, Burp XML). Use `-` for stdin |
| `--record-uuid` | — | HTTP record UUID from database |
| `--vuln-type` | — | Vulnerability type focus (e.g., `sqli`, `xss`, `ssrf`) |
| `-m, --modules` | — | Explicit module names to include |
| `--max-iterations` | 3 | Maximum triage-rescan iterations |
| `--timeout` | 15m | Maximum swarm duration |
| `--profile` | — | Scanning profile to use |
| `--dry-run` | false | Render prompts without executing |

At least one input required: `--target`, `--input`, or `--record-uuid`.

### Phases

```
Phase 1: Normalize    — Parse input(s) into HttpRequestResponse objects
Phase 2: Plan         — Master agent analyzes request, selects modules, generates extensions
Phase 3: Extension    — Write generated JS extensions to temp directory
Phase 4: Scan         — Dynamic assessment with selected modules + extensions
Phase 5: Triage       — Agent reviews extension-generated findings
Phase 6: Rescan       — Targeted rescan from triage follow-ups (loop)
```

### Supported Input Types

| Type | Example | Detection |
|------|---------|-----------|
| URL | `https://example.com/api/users` | Starts with `http://` or `https://` |
| Curl | `curl -X POST https://...` | Starts with `curl ` |
| Raw HTTP | `POST /api HTTP/1.1\r\n...` | Starts with HTTP method + path |
| Burp XML | `<?xml...><items>...</items>` | Starts with `<?xml` or `<items` |
| Record UUID | `550e8400-e29b-...` | Matches UUID format |

### API

```
POST /api/agent/run/swarm
```

```json
{
  "input": "curl -X POST https://example.com/api/login -d '{\"user\":\"admin\"}'",
  "vuln_type": "sqli",
  "module_names": ["sqli-error-based"],
  "max_iterations": 3,
  "agent": "claude",
  "stream": true,
  "timeout": "15m"
}
```

At least one of `input` or `inputs` is required. Use `inputs` (array) for multi-request flows like login + protected endpoint.

### Pros and Cons

| Pros | Cons |
|------|------|
| Deep testing — custom payloads tailored to specific endpoint | Single-endpoint scope — no discovery |
| Accepts any input format — URL, curl, raw HTTP, Burp XML, DB record | Requires meaningful input (not for broad recon) |
| AI-generated extensions catch what built-in modules miss | Extension quality depends on agent capability |
| Cost-efficient — 2-3 AI calls for focused results | Does not replace full-scope scanning |
| Fast — 15 minute default, focused scope | |
| Triage scoped to extensions — built-in findings pass through | |

### When to Use

- **Deep testing of a specific endpoint** — you found an interesting request and want to throw everything at it
- **Custom payload generation** — when built-in modules don't cover a specific pattern
- **Re-testing from Burp/curl** — paste a request from your proxy and get targeted scanning
- **Focused vulnerability hunting** — combine `--vuln-type` with agent-generated extensions
- You already know **what** to test, you want the AI to figure out **how**

---

## Side-by-Side Comparison

| Aspect | Run/Query | Autopilot | Pipeline | Swarm |
|--------|-----------|-----------|----------|-------|
| **Input** | Source code | Target URL | Target URL | URL, curl, raw HTTP, Burp XML, DB record |
| **Scope** | Code analysis | Full target | Full target | Single request/endpoint |
| **AI calls** | 1 | Many (agent-driven) | 2-4 | 2-3 |
| **AI cost** | Low | High | Low-Medium | Low |
| **Network scanning** | No | Yes (agent-driven) | Yes (native) | Yes (native) |
| **Custom payloads** | No | No | Via source analysis (Phase 0) | Yes — always generates extensions |
| **Discovery** | No | Agent decides | Yes (Phase 1) | No |
| **Triage** | No | Agent decides | Yes (Phase 4) | Yes (extension findings only) |
| **Source code support** | Required | Optional (`--source`) | Optional (`--source`) | No |
| **Default timeout** | — | 30m | 1h | 15m |
| **Predictability** | High | Low | High | Medium |
| **Runtime** | Seconds | Minutes | Minutes-hours | Minutes |

## Common API Patterns

### Streaming (Server-Sent Events)

All four run endpoints support `"stream": true` for real-time SSE output:

```bash
curl -N http://localhost:9002/api/agent/run/pipeline \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <api-key>" \
  -d '{"target": "https://example.com", "stream": true}'
```

SSE events are newline-delimited `data:` lines with JSON payloads:

| Event | Description | Modes |
|-------|-------------|-------|
| `chunk` | Real-time text from the agent | All |
| `phase` | Phase transition (e.g., `{"type":"phase","phase":"discover"}`) | Pipeline, Swarm |
| `done` | Agent finished successfully | All |
| `error` | Agent failed | All |

### Check Run Status

```
GET /api/agent/status/:id
```

```json
{
  "run_id": "agt-550e8400-e29b-41d4-a716-446655440000",
  "mode": "swarm",
  "status": "completed",
  "agent_name": "claude",
  "current_phase": "triage",
  "finding_count": 5,
  "swarm_result": { "..." }
}
```

Status is one of `running`, `completed`, or `failed`.

### List All Runs

```
GET /api/agent/status/list
```

Returns all run statuses. Active runs show real-time status from memory; completed runs are loaded from the `agent_runs` database table.

### Concurrency

Only one agent run can be active at a time across all modes. Concurrent requests return `409 Conflict`.

### OpenAI-Compatible Chat Completions

```
POST /api/agent/chat/completions
```

Accepts OpenAI Chat Completions format. The `model` field maps to agent names in config. Works with any OpenAI-compatible client:

```python
from openai import OpenAI
client = OpenAI(base_url="http://localhost:9002/api/agent", api_key="<api-key>")
response = client.chat.completions.create(
    model="claude",
    messages=[{"role": "user", "content": "Explain CSRF attacks"}],
)
```

## Decision Guide

**"I have source code and want to find vulnerabilities"**
→ Use **Run** with `--prompt-template security-code-review`

**"I have a target URL and want comprehensive scanning"**
→ Use **Pipeline** for predictable, cost-efficient coverage
→ Use **Autopilot** if you want the AI to explore creatively

**"I have source code AND a running target"**
→ Use **Pipeline** with `--source` — gets route extraction, auth config, and custom extensions automatically

**"I have a specific request I want to attack deeply"**
→ Use **Swarm** — paste the URL, curl command, or raw request

**"I found an interesting endpoint in Burp and want targeted testing"**
→ Use **Swarm** with `--input` (paste the curl/raw request) or `--record-uuid`

**"I need this in CI/CD"**
→ Use **Pipeline** (stable phases, predictable runtime) or **Run** (fast code review)

## Configuration

Agent backends are configured in `~/.vigolium/vigolium-configs.yaml`:

```yaml
agent:
  default_agent: claude
  templates_dir: ~/.vigolium/prompts/
  sessions_dir: ~/.vigolium/agent-sessions/  # directory for agent run session artifacts (extensions, auth configs, plans)
  stream: true

  warm_session:
    enable: false
    idle_timeout: 300
    max_sessions: 2

  agents:
    claude:
      command: npx
      args: ["-y", "@zed-industries/claude-code-acp@latest"]
      protocol: acp

    codex:
      command: npx
      args: ["-y", "@zed-industries/codex-acp"]
      protocol: acp

    gemini:
      command: gemini
      args: ["--experimental-acp"]
      protocol: acp
```

Two protocols are supported:

| Protocol | Description |
|----------|-------------|
| `acp` | Agent Communication Protocol — structured bidirectional communication, supports terminal execution. Preferred. |
| `pipe` | Classic stdin/stdout — prompt piped to stdin, output read from stdout. Legacy fallback. |

## Further Reading

- [Autopilot](autopilot.md) — detailed flow, security sandbox, session pooling
- [Pipeline](pipeline.md) — phase-by-phase breakdown, output schemas, source analysis
- [Swarm](swarm.md) — input normalization, master agent prompt, extension generation
