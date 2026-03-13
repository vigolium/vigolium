# Agent Mode

Vigolium's agent mode integrates AI agents (Claude, Codex, OpenCode, Gemini, or any custom CLI tool) into the vulnerability scanning workflow. One query mode and three **agentic scan** modes are available, each with different levels of AI involvement and scope.

## Mode Overview

| Mode | Command | Scope | AI Calls | Best For |
|------|---------|-------|----------|----------|
| **Run/Query** | `vigolium agent` | Source code | 1 | Code review, endpoint discovery, SAST |
| **Autopilot** | `vigolium agent autopilot` | Entire target | Many | Agentic scan: exploratory scanning, ad-hoc research |
| **Pipeline** | `vigolium agent pipeline` | Entire target | 2-4 | Agentic scan: production scanning, CI/CD |
| **Swarm** | `vigolium agent swarm` | Single request | 2-3 | Agentic scan: deep targeted testing of specific endpoints |

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

**More Examples:**

```bash
# Review only authentication-related files
vigolium agent --prompt-template security-code-review --source ./src --files auth/login.go,auth/session.go,middleware/jwt.go

# Discover API endpoints from a Django project
vigolium agent --prompt-template endpoint-discovery --source ~/projects/django-app

# Code review with additional focus instructions
vigolium agent --prompt-template security-code-review --source ./src --append "Pay special attention to deserialization and file upload handling"

# Use a specific agent backend (e.g., Gemini)
vigolium agent --prompt-template injection-sinks --source ./src --agent gemini

# Save agent output to a file for later review
vigolium agent --prompt-template security-code-review --source ./src --output review-results.json

# Review source code from a specific project
vigolium agent --prompt-template security-code-review --source ./src --project my-api

# Chain with jq — extract only high-severity findings
vigolium agent --prompt-template security-code-review --source ./src --json | jq '.[] | select(.severity == "high")'

# Quick inline question about a codebase
vigolium agent query "What authentication mechanisms does this app use?" --source ./src

# Detect hardcoded secrets in config files
vigolium agent --prompt-template secret-detection --source ./src --files config/,deploy/
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

## Autopilot (Agentic Scan)

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

**More Examples:**

```bash
# Pipe a curl command — target is auto-derived from the URL
echo "curl -X POST https://example.com/api/login -d '{\"user\":\"admin\"}'" | vigolium agent autopilot

# Pass raw input directly (Burp-style raw HTTP)
vigolium agent autopilot --input "POST /api/search HTTP/1.1\r\nHost: example.com\r\n\r\nq=test"

# Source-aware scan of specific files in a large codebase
vigolium agent autopilot -t http://localhost:8080 --source ~/projects/spring-app --files src/main/java/auth/,src/main/java/api/

# Guide the agent with custom instructions
vigolium agent autopilot -t https://staging.example.com --instruction "Test only the /admin and /api/v2 endpoints. Check for IDOR and privilege escalation."

# Load detailed pentest scope from a file
vigolium agent autopilot -t https://example.com --instruction-file scope.txt

# Quick scan with tight limits for a CI job
vigolium agent autopilot -t https://example.com --max-commands 20 --timeout 5m

# Use a different agent backend
vigolium agent autopilot -t https://example.com --agent gemini --focus "file upload vulnerabilities"

# Use a custom ACP command for a third-party agent
vigolium agent autopilot -t https://example.com --agent-acp-cmd "my-agent acp-serve"

# Override the system prompt entirely
vigolium agent autopilot -t https://example.com --system-prompt custom-autopilot.md

# Show the rendered prompt before execution for debugging
vigolium agent autopilot -t https://example.com --show-prompt --focus "SSRF via URL parameters"

# Combine source context with focus area for targeted code-informed scanning
vigolium agent autopilot -t http://localhost:3000 --source ./src --focus "SQL injection in search endpoints"
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

## Pipeline (Agentic Scan)

Fixed 7-phase agentic scan workflow where native Go code does the heavy lifting and AI agents only intervene at strategic checkpoints (source analysis, planning, triage).

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

**More Examples:**

```bash
# Pipe a curl command — target is auto-derived
echo "curl https://api.example.com/v2/users" | vigolium agent pipeline

# Pass input directly (e.g., a Burp XML export)
vigolium agent pipeline --input "curl -X POST https://example.com/api/login -d '{\"user\":\"admin\"}'"

# Source-aware scan with specific files for faster Phase 0
vigolium agent pipeline -t http://localhost:3000 --source ~/projects/express-app --files routes/,middleware/auth.js

# Guide the planning agent with custom instructions
vigolium agent pipeline -t https://example.com --instruction "Prioritize testing authentication and session management endpoints"

# Load detailed scope from a file
vigolium agent pipeline -t https://example.com --instruction-file pentest-brief.txt

# Skip source analysis and discovery — jump straight to planning with existing DB data
vigolium agent pipeline -t https://example.com --skip-phase source-analysis --skip-phase discover --start-from plan

# Skip triage and rescan — just discover + plan + scan
vigolium agent pipeline -t https://example.com --skip-phase triage --skip-phase rescan --skip-phase report

# Re-run only triage on previous scan results
vigolium agent pipeline -t https://example.com --start-from triage --skip-phase rescan

# Use a different agent backend with a longer timeout for large targets
vigolium agent pipeline -t https://large-app.example.com --agent gemini --timeout 2h

# Use a custom ACP agent command
vigolium agent pipeline -t https://example.com --agent-acp-cmd "my-agent acp-serve"

# Show rendered prompts before each AI phase for debugging
vigolium agent pipeline -t https://example.com --show-prompt --focus "IDOR in REST APIs"

# Aggressive rescan — allow up to 5 triage→rescan iterations
vigolium agent pipeline -t https://example.com --max-rescan-rounds 5 --profile thorough

# CI/CD integration — tight timeout, no rescan overhead
vigolium agent pipeline -t https://staging.example.com --timeout 20m --max-rescan-rounds 0 --profile fast
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

## Swarm (Agentic Scan)

Multi-agent targeted agentic scan. A master AI agent analyzes a specific HTTP request, selects scanner modules, generates custom attack payloads as JavaScript extensions, and executes a focused scan.

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

**More Examples:**

```bash
# Swarm with source code context for route-aware scanning
vigolium agent swarm -t http://localhost:3000 --source ~/projects/express-app

# Only run source analysis (no scanning) — useful for inspecting what the agent finds
vigolium agent swarm -t http://localhost:3000 --source ./src --source-analysis-only

# Pipe a Burp Suite exported request from a file
cat burp-request.xml | vigolium agent swarm

# Import a raw HTTP request from a file via stdin
cat login-request.txt | vigolium agent swarm -t https://example.com

# Combine curl input with explicit module selection
vigolium agent swarm --input "curl -X PUT https://api.example.com/users/1 -H 'Content-Type: application/json' -d '{\"role\":\"admin\"}'" -m idor,bola,sqli-error-based

# Focus on SSRF with a longer timeout for complex payloads
vigolium agent swarm -t https://example.com/api/fetch?url=http://internal --vuln-type ssrf --timeout 30m

# Run with discovery enabled to crawl before planning
vigolium agent swarm -t https://example.com --discover

# Source-aware swarm with custom instruction to guide the agent
vigolium agent swarm -t http://localhost:8080 --source ./src --instruction "Focus on the /admin endpoints and check for privilege escalation"

# Load instructions from a file
vigolium agent swarm -t https://example.com/api --instruction-file pentest-scope.txt

# Use a different agent backend
vigolium agent swarm -t https://example.com/api/search --agent gemini --vuln-type xss

# Scan only the audit phase (skip discovery/spidering)
vigolium agent swarm -t https://example.com/api/users --only audit

# Skip spidering during the swarm scan
vigolium agent swarm -t https://example.com --discover --skip spidering

# Use a scanning profile for stricter payloads
vigolium agent swarm -t https://staging.example.com/api --profile thorough --vuln-type sqli

# Multiple inputs: target URL + explicit modules + vulnerability focus
vigolium agent swarm -t https://example.com/api/v2/orders -m xss-reflected,xss-dom,csti --vuln-type xss --max-iterations 5

# Base64-encoded Burp request (common when copying from Burp)
vigolium agent swarm --input "UE9TVCAvYXBpL2xvZ2luIEhUVFAvMS4xDQpIb3N0OiBleGFtcGxlLmNvbQ0K..."

# Use a custom ACP command for a third-party agent
vigolium agent swarm -t https://example.com/api --agent-acp-cmd "my-agent acp-serve"

# Show rendered prompts before execution for debugging
vigolium agent swarm -t https://example.com/api/users --show-prompt --vuln-type sqli
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

| Aspect | Run/Query | Autopilot (Agentic) | Pipeline (Agentic) | Swarm (Agentic) |
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

## Mode Comparison & Overlap Analysis

### Architectural Relationships

All four modes share a common execution engine (`pkg/agent/engine.go`). Query is a standalone mode; the three agentic scan modes (autopilot, pipeline, swarm) add varying levels of orchestration on top:

```
                   Engine.Run()
                       │
        ┌──────────────┼──────────────────┐
        │              │                  │
      Query      ┌────┴─────┐        Autopilot
   (1 AI call)   │          │      (AI drives CLI)
              Pipeline    Swarm
           (7 phases,   (10 phases,
            3 AI)        4+ AI)
```

- **Query** is the primitive — Pipeline and Swarm call `Engine.Run()` at each AI checkpoint, making Query effectively their building block.
- **Autopilot** is architecturally separate — it gives the agent terminal access and lets it drive, rather than orchestrating phases programmatically.
- **Pipeline and Swarm** share the most code and patterns (see below).

### Feature Matrix

| Feature | Query | Autopilot | Pipeline | Swarm |
|---------|-------|-----------|----------|-------|
| AI-driven module selection | — | Agent decides | Phase 2 plan | Master agent plan |
| Custom extension generation | — | — | Via source analysis only | Always (quick_checks + snippets) |
| Source analysis (routes/auth) | Context only | Context + CLI | Parallel sub-agents | Parallel sub-agents |
| SAST (ast-grep) | — | — | — | Native + AI review |
| Discovery/spidering | — | Agent decides | Phase 1 (always) | Optional (`--discover`) |
| Triage + rescan loop | — | Agent decides | Phases 4-5 | Phases 9-10 |
| Input batching | — | — | — | >5 records batched |
| Terminal access | No | Yes (sandboxed) | No | No |
| Structured output schema | findings, http_records | Unstructured | AttackPlan, TriageResult | SwarmPlan, TriageResult |
| Warm session pooling | Optional | Enabled | Enabled | Forced |
| Resumable phases | — | — | `--start-from`, `--skip-phase` | `--source-analysis-only` |

### Pipeline vs Swarm: Key Overlaps

Pipeline and Swarm share the most infrastructure. Specifically:

| Shared Pattern | Pipeline | Swarm |
|----------------|----------|-------|
| Source analysis | `RunSourceAnalysisParallel()` with routes/auth/extensions sub-agents | Same `RunSourceAnalysisParallel()` call |
| Auth config flow | Source → `auth-config.yaml` → injected into scan settings | Identical flow |
| Triage loop | `TriageResult` with "done"/"rescan" verdict, max iterations | Same `TriageResult`, same loop pattern |
| Plan → scan | AI picks module tags/IDs → native executor runs them | Same pattern |
| Session artifacts | Extensions, plan.json, session-config.json in session dir | Same directory structure |

**Where they differ:**

| Aspect | Pipeline | Swarm |
|--------|----------|-------|
| Discovery | Always runs (Phase 1) | Optional (`--discover` flag) |
| Extension generation | Only from source analysis | Master agent generates quick_checks + snippets |
| Input flexibility | Target URL only | 6 formats + record UUID |
| Batching | None | Master agent batched for >5 records |
| SAST phase | None | Native ast-grep + AI review |
| Scope | Full target (broad) | Specific endpoints (targeted) |
| Default timeout | 1 hour | 15 minutes |

### Autopilot vs Pipeline/Swarm (Agentic Scan Tradeoffs)

All three are agentic scan modes. Autopilot's terminal sandbox only allows `vigolium` commands, so it effectively does what Pipeline/Swarm do — discovery, scanning, triage — but with more AI overhead and less structure. The tradeoff:

- **Autopilot advantage:** Can adapt strategy mid-scan, try creative approaches, and handle unexpected findings
- **Pipeline/Swarm advantage:** Agentic scan with native Go handling the scanning phases (faster, cheaper), AI only called at strategic points

### When Modes Genuinely Differ

Despite the overlaps, each mode has a clear sweet spot:

| Mode | Unique Value | Cannot Be Replaced By |
|------|-------------|----------------------|
| **Query** | Zero-scan code analysis, CI/CD-friendly single-shot | Any other mode (they all require a target or do more than needed) |
| **Autopilot** | Adaptive, exploratory testing with no predefined workflow | Pipeline/Swarm (they follow fixed phases) |
| **Pipeline** | Full-scope deterministic scanning with minimal AI cost | Swarm (no built-in discovery), Query (no scanning) |
| **Swarm** | Custom payload generation + SAST + multi-format input | Pipeline (no extension generation from master agent), Query (no scanning) |

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

  backends:
    claude:
      command: npx
      args: ["-y", "@zed-industries/claude-agent-acp@latest"]
      protocol: acp

    codex:
      command: codex
      args: ["app-server"]
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
