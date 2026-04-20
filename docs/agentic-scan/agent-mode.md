# Agent Mode

Vigolium's agent mode integrates AI agents (Claude, Codex, OpenCode, or any custom CLI tool) into the vulnerability scanning workflow. One query mode and two **agentic scan** modes are available, each with different levels of AI involvement and scope.

## Mode Overview

| Mode | Command | Scope | AI Calls | Best For |
|------|---------|-------|----------|----------|
| **Run/Query** | `vigolium agent query` | Source code | 1 | Code review, endpoint discovery, SAST |
| **Autopilot** | `vigolium agent autopilot` | Entire target | Many | Agentic scan: exploratory scanning, ad-hoc research |
| **Swarm** | `vigolium agent swarm` | Full target or specific endpoints | 2-4+ | Agentic scan: targeted testing, full-scope scanning with `--discover` |

## Quick Start

```bash
# Code review — single AI call, structured findings
vigolium agent query --prompt-template security-code-review --source ./src

# Autonomous scanning — agent drives the CLI
vigolium agent autopilot -t https://example.com

# Targeted swarm — AI generates custom payloads for specific endpoints
vigolium agent swarm -t https://example.com/api/users --vuln-type sqli

# Full-scope swarm with discovery
vigolium agent swarm -t https://example.com --discover
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
vigolium agent query --prompt-template security-code-review --source ./src

# Review specific files
vigolium agent query --prompt-template injection-sinks --source ./src --files db/query.go,api/handler.go

# Custom prompt file
vigolium agent query --prompt-file my-prompt.md --source ./src

# Freeform question (no structured output)
vigolium agent query "What are common JWT vulnerabilities?"

# Pipe prompt from stdin
echo "explain CSRF" | vigolium agent query --stdin

# Dry run — render prompt without executing
vigolium agent query --prompt-template endpoint-discovery --source ./src --dry-run

# List available templates and agents
vigolium agent --list-templates
vigolium agent --list-agents
```

**More Examples:**

```bash
# Review only authentication-related files
vigolium agent query --prompt-template security-code-review --source ./src --files auth/login.go,auth/session.go,middleware/jwt.go

# Discover API endpoints from a Django project
vigolium agent query --prompt-template endpoint-discovery --source ~/projects/django-app

# Code review with additional focus instructions
vigolium agent query --prompt-template security-code-review --source ./src --append "Pay special attention to deserialization and file upload handling"

# Save agent output to a file for later review
vigolium agent query --prompt-template security-code-review --source ./src --output review-results.json

# Review source code from a specific project
vigolium agent query --prompt-template security-code-review --source ./src --project my-api

# Chain with jq — extract only high-severity findings
vigolium agent query --prompt-template security-code-review --source ./src --json | jq '.[] | select(.severity == "high")'

# Quick inline question about a codebase
vigolium agent query "What authentication mechanisms does this app use?" --source ./src

# Detect hardcoded secrets in config files
vigolium agent query --prompt-template secret-detection --source ./src --files config/,deploy/
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

Full autonomous control. The AI agent drives the vulnerability scanning workflow, deciding what to scan, interpreting results, and iterating. When `--source` is provided, autopilot runs an **archon-audit first** by default, then feeds the audit findings into the agent's prompt. Use `--no-archon` to disable this, or `--archon-mode` to choose the audit depth.

See the full [Autopilot documentation](autopilot.md) for architecture diagrams, finding prompt formatting tiers, and detailed configuration.

### What It Does

- Spawns an AI agent with full CLI tool access (Read, Grep, Glob, Bash, Edit, Write)
- Agent decides its own workflow — discover, scan, review, iterate, report
- **Archon-first** (default when `--source` is set): runs archon-audit sequentially, waits for completion, then loads findings into the agent's prompt for exploitation and verification
- Without source, or with `--no-archon`: agent receives a generic security assessment brief

### CLI

```bash
# Basic autonomous scan
vigolium agent autopilot -t https://example.com

# Archon-first: deep whitebox audit, then agent exploits findings
vigolium agent autopilot -t http://localhost:3000 --source ~/projects/my-app --archon-mode deep

# Quick archon audit (3-phase) before scanning
vigolium agent autopilot -t http://localhost:3000 --source ~/projects/my-app

# With focus area
vigolium agent autopilot -t https://api.example.com --focus "auth bypass"

# Natural language prompt
vigolium agent autopilot "scan VAmPI source at ~/src/VAmPI on localhost:3005"

# Preview the prompt without executing
vigolium agent autopilot -t https://example.com --source ./src --archon-mode deep --dry-run
```

**Key Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `-t, --target` | — | Target URL (derived from `--input` if not set) |
| `--source` | — | Path to application source code |
| `--focus` | — | Focus area hint (e.g., "API injection") |
| `--archon-mode` | `lite` | Archon audit mode: `lite` (3-phase), `scan` (6-phase), or `deep` (11-phase). Used when `--source` is set |
| `--no-archon` | `false` | Disable automatic archon-audit even when `--source` is set |
| `--timeout` | 6h | Maximum session duration |
| `--max-commands` | 100 | Maximum CLI commands the agent can execute |
| `--dry-run` | false | Render prompt without launching |

### Archon-Audit Integration

When `--source` is provided, autopilot runs the archon-audit first by default. The operator session starts only after the audit output has been prepared into stable context and artifacts. Use `--no-archon` to skip this step.

| Mode | Phases | Duration | Description |
|------|--------|----------|-------------|
| `lite` | 3 | Minutes | Quick recon + secrets + fast SAST |
| `scan` | 6 | ~1 hour | Comprehensive analysis |
| `deep` | 11 | Hours | Full adversarial audit (debate chambers, cold verification, variant hunting, PoC building) |

After the audit, findings are loaded and injected into the agent prompt (tiered by count: full detail for ≤15, summary table for 16-40, top 10 for 41+). The agent can also read full finding files from the session directory. See [Archon-Audit](archon-audit.md) for audit details.

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
  "archon": "deep",
  "max_commands": 50,
  "timeout": "6h",
  "stream": true
}
```

### Pros and Cons

| Pros | Cons |
|------|------|
| Most flexible — agent adapts strategy dynamically | Highest AI cost — long agent session with many calls |
| Can discover unexpected attack vectors | Unpredictable runtime and coverage |
| Source-aware workflow when `--source` provided | Results depend heavily on agent quality |
| No prior knowledge of target needed | Harder to reproduce — agent may take different paths |
| Background archon-audit adds deep whitebox findings in parallel | Archon-audit requires `--source` and adds AI cost |

### When to Use

- **Exploratory testing** of unfamiliar targets — let the AI figure out what's there
- **Research and experimentation** — trying creative attack strategies
- You want **hands-off scanning** and don't mind variable runtime
- **Source-aware scanning** — agent reads code, identifies sinks, crafts targeted attacks
- **Deep whitebox + dynamic combo** — use `--source ... --archon-mode deep` for comprehensive coverage from both code analysis and runtime testing

---

## Swarm (Agentic Scan)

Multi-phase agentic scan that combines targeted AI-driven testing with optional full-scope discovery. A master AI agent analyzes inputs, selects scanner modules, generates custom attack payloads as JavaScript extensions, runs SAST analysis, and executes focused scans. With `--discover`, it also runs content discovery and spidering before planning.

### What It Does

- Takes heterogeneous input (URL, curl command, raw HTTP request, Burp XML export, or database record UUID)
- Optionally runs content discovery and spidering (`--discover`) for full-scope target coverage
- Runs source analysis when `--source` is provided — extracts routes, auth flows, and generates custom scanner extensions
- Runs SAST analysis (ast-grep) with AI review for source-level vulnerability detection
- Master agent analyzes requests, selects modules, and generates custom JS scanner extensions
- Runs dynamic assessment with agent-selected modules + generated extensions
- Triages extension-generated findings (built-in module findings pass through as-is)
- Supports triage-rescan loop up to `--max-iterations`

### CLI

```bash
# Target a URL
vigolium agent swarm -t https://example.com/api/users

# Full-scope scan with discovery
vigolium agent swarm -t https://example.com --discover

# Analyze a curl command
vigolium agent swarm --input "curl -X POST https://example.com/api/login -d '{\"user\":\"admin\"}'"

# Pipe raw HTTP request from stdin
echo -e "POST /api/search HTTP/1.1\r\nHost: example.com\r\n\r\nq=test" | vigolium agent swarm --input -

# Scan a record from the database
vigolium agent swarm --record-uuid 550e8400-e29b-41d4-a716-446655440000

# Focus on specific vulnerability type
vigolium agent swarm -t https://example.com/api/users --vuln-type sqli

# Broad strategic focus area
vigolium agent swarm -t https://example.com/api --focus "API injection"

# Combine focus and vuln-type for precise targeting
vigolium agent swarm -t https://example.com/api/users --focus "auth bypass" --vuln-type idor

# Specify modules explicitly alongside agent selections
vigolium agent swarm -t https://example.com/api/search -m xss-reflected,xss-stored

# Preview the master agent prompt
vigolium agent swarm -t https://example.com/api/users --dry-run
```

**More Examples:**

```bash
# Swarm with source code context for route-aware scanning
vigolium agent swarm -t http://localhost:3000 --source ~/projects/express-app

# Full-scope source-aware scan (discovery + source analysis + SAST + scanning)
vigolium agent swarm -t http://localhost:3000 --source ~/projects/express-app --discover

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

# Scan only the dynamic-assessment phase (skip discovery/spidering)
vigolium agent swarm -t https://example.com/api/users --only dynamic-assessment

# Skip spidering during the swarm scan
vigolium agent swarm -t https://example.com --discover --skip spidering

# Use a scanning profile for stricter payloads
vigolium agent swarm -t https://staging.example.com/api --profile thorough --vuln-type sqli

# Multiple inputs: target URL + explicit modules + vulnerability focus
vigolium agent swarm -t https://example.com/api/v2/orders -m xss-reflected,xss-dom,csti --vuln-type xss --max-iterations 5

# Base64-encoded Burp request (common when copying from Burp)
vigolium agent swarm --input "UE9TVCAvYXBpL2xvZ2luIEhUVFAvMS4xDQpIb3N0OiBleGFtcGxlLmNvbQ0K..."

# Show rendered prompts before execution for debugging
vigolium agent swarm -t https://example.com/api/users --show-prompt --vuln-type sqli

# Resume from a specific phase (e.g., after fixing source code issues)
vigolium agent swarm -t https://example.com --start-from plan

# CI/CD integration — discovery + tight timeout, no rescan overhead
vigolium agent swarm -t https://staging.example.com --discover --timeout 20m --max-rescan-rounds 0 --profile fast

# Guide the planning agent with custom instructions
vigolium agent swarm -t https://example.com --discover --instruction "Prioritize testing authentication and session management endpoints"

# Source-aware full scan with specific files for faster analysis
vigolium agent swarm -t http://localhost:3000 --source ~/projects/express-app --discover --files routes/,middleware/auth.js

# Aggressive rescan — allow up to 5 triage-rescan iterations
vigolium agent swarm -t https://example.com --discover --max-rescan-rounds 5 --profile thorough
```

**Key Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `-t, --target` | — | Target URL |
| `--input` | — | Raw input (curl, raw HTTP, Burp XML). Use `-` for stdin |
| `--record-uuid` | — | HTTP record UUID from database |
| `--focus` | — | Broad strategic focus area hint (e.g., "API injection", "auth bypass") |
| `--vuln-type` | — | Vulnerability type focus (e.g., `sqli`, `xss`, `ssrf`) |
| `-m, --modules` | — | Explicit module names to include |
| `--discover` | false | Run discovery + spidering before planning (enables full-scope scanning) |
| `--max-iterations` | 3 | Maximum triage-rescan iterations |
| `--max-rescan-rounds` | — | Hidden alias for `--max-iterations` |
| `--start-from` | — | Resume from a specific phase |
| `--source` | — | Path to application source code (enables source analysis + SAST) |
| `--timeout` | 15m | Maximum swarm duration |
| `--profile` | — | Scanning profile to use |
| `--dry-run` | false | Render prompts without executing |

At least one input required: `--target`, `--input`, or `--record-uuid`.

### Phases

```
Phase 1:  Normalize         — Parse input(s) into HttpRequestResponse objects
Phase 2:  Source Analysis    (AI — conditional)  — Extract routes, session config, extensions from source
Phase 3:  SAST              (Native — conditional) — Static analysis via ast-grep
Phase 4:  SAST Review       (AI — conditional)  — AI reviews SAST findings
Phase 5:  Discover          (Native — conditional) — Content discovery + spidering (requires --discover)
Phase 6:  Plan              (AI)                — Master agent analyzes requests, selects modules, generates extensions
Phase 7:  Extension         — Write generated JS extensions to temp directory
Phase 8:  Native Scan       (Native)            — Dynamic assessment with selected modules + extensions
Phase 9:  Triage            (AI)                — Agent reviews extension-generated findings
Phase 10: Rescan            (Native, loop)      — Targeted rescan from triage follow-ups
```

Phase 2-4 (source analysis, SAST, SAST review) are automatically skipped when `--source` is not provided. Phase 5 (discover) is skipped unless `--discover` is passed.

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
  "focus": "auth bypass",
  "module_names": ["sqli-error-based"],
  "discover": true,
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
| Deep testing — custom payloads tailored to specific endpoints | Extension quality depends on agent capability |
| Accepts any input format — URL, curl, raw HTTP, Burp XML, DB record | Requires meaningful input when not using `--discover` |
| AI-generated extensions catch what built-in modules miss | Longer runtime for large targets with `--discover` |
| Full-scope scanning with `--discover` — discovery through triage | |
| Source-aware — route extraction, auth config, SAST when `--source` provided | |
| Cost-efficient — 2-4 AI calls for focused results | |
| Triage scoped to extensions — built-in findings pass through | |
| Resumable — `--start-from` for phase-level control | |
| SAST integration — ast-grep + AI review for source-level findings | |

### When to Use

- **Deep testing of a specific endpoint** — you found an interesting request and want to throw everything at it
- **Full-scope scanning** with `--discover` — comprehensive target coverage with AI-driven planning and triage
- **Custom payload generation** — when built-in modules don't cover a specific pattern
- **Re-testing from Burp/curl** — paste a request from your proxy and get targeted scanning
- **Source-aware scanning** — have source code and want automatic route extraction, auth setup, SAST, and custom extensions
- **Focused vulnerability hunting** — combine `--vuln-type` or `--focus` with agent-generated extensions
- **CI/CD integration** — `--discover` mode provides stable phases with predictable runtime
- You already know **what** to test, you want the AI to figure out **how**

---

## Side-by-Side Comparison

| Aspect | Run/Query | Autopilot (Agentic) | Swarm (Agentic) |
|--------|-----------|-----------|-------|
| **Input** | Source code | Target URL | URL, curl, raw HTTP, Burp XML, DB record |
| **Scope** | Code analysis | Full target | Specific endpoints, or full target with `--discover` |
| **AI calls** | 1 | Many (agent-driven) | 2-4+ |
| **AI cost** | Low | High | Low-Medium |
| **Network scanning** | No | Yes (agent-driven) | Yes (native) |
| **Custom payloads** | No | No | Yes — always generates extensions |
| **Discovery** | No | Agent decides | Optional (`--discover`) |
| **Triage** | No | Agent decides | Yes (extension findings only) |
| **SAST** | No | No | Yes (ast-grep + AI review, with `--source`) |
| **Source code support** | Required | Optional (`--source`) | Optional (`--source`) |
| **Default timeout** | — | 30m | 15m |
| **Predictability** | High | Low | Medium-High |
| **Runtime** | Seconds | Minutes | Minutes-hours |

## Common API Patterns

### Streaming (Server-Sent Events)

All run endpoints support `"stream": true` for real-time SSE output:

```bash
curl -N http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <api-key>" \
  -d '{"target": "https://example.com", "discover": true, "stream": true}'
```

SSE events are newline-delimited `data:` lines with JSON payloads:

| Event | Description | Modes |
|-------|-------------|-------|
| `chunk` | Real-time text from the agent | All |
| `phase` | Phase transition (e.g., `{"type":"phase","phase":"discover"}`) | Swarm |
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

Returns all run statuses. Active runs show real-time status from memory; completed runs are loaded from the `agentic_scans` database table.

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
-> Use **Run** with `--prompt-template security-code-review`

**"I have a target URL and want comprehensive scanning"**
-> Use **Swarm** with `--discover` for predictable, cost-efficient full-scope coverage
-> Use **Autopilot** if you want the AI to explore creatively

**"I have source code AND a running target"**
-> Use **Swarm** with `--discover --source` — gets route extraction, auth config, SAST, and custom extensions automatically

**"I have a specific request I want to attack deeply"**
-> Use **Swarm** — paste the URL, curl command, or raw request

**"I found an interesting endpoint in Burp and want targeted testing"**
-> Use **Swarm** with `--input` (paste the curl/raw request) or `--record-uuid`

**"I need this in CI/CD"**
-> Use **Swarm** with `--discover` (stable phases, predictable runtime) or **Run** (fast code review)

## Mode Comparison & Overlap Analysis

### Architectural Relationships

All three modes share a common execution engine (`pkg/agent/engine.go`). Query is a standalone mode; the two agentic scan modes (autopilot, swarm) add varying levels of orchestration on top:

```
                   Engine.Run()
                       |
        +--------------+--------------+
        |              |              |
      Query        Autopilot       Swarm
   (1 AI call)  (AI drives CLI)  (10 phases,
                                  2-4+ AI)
```

- **Query** is the primitive — Swarm calls `Engine.Run()` at each AI checkpoint, making Query effectively its building block.
- **Autopilot** is architecturally separate — it optionally runs archon-audit first, then gives the agent terminal access with enriched findings context and lets it drive.
- **Swarm** supports both targeted and full-scope scanning. With `--discover`, it runs content discovery and spidering before planning. Without `--discover`, it focuses on targeted endpoint testing.

### Feature Matrix

| Feature | Query | Autopilot | Swarm |
|---------|-------|-----------|-------|
| AI-driven module selection | — | Agent decides | Master agent plan |
| Custom extension generation | — | — | Always (quick_checks + snippets) |
| Source analysis (routes/auth) | Context only | Context + CLI | Parallel sub-agents |
| SAST (ast-grep) | — | — | Native + AI review |
| Discovery/spidering | — | Agent decides | Optional (`--discover`) |
| Triage + rescan loop | — | Agent decides | Phases 9-10 |
| Input batching | — | — | >5 records batched |
| Full CLI tool access | Yes | Yes | Yes |
| Structured output schema | findings, http_records | Unstructured | SwarmPlan, TriageResult |
| Warm session pooling | Optional | Enabled | Forced |
| Resumable phases | — | — | `--start-from`, `--source-analysis-only` |

### Autopilot vs Swarm (Agentic Scan Tradeoffs)

Both are agentic scan modes. Autopilot agents get full CLI tool access (Read, Grep, Glob, Bash, Edit, Write) for autonomous workflows. The tradeoff:

- **Autopilot advantage:** Can adapt strategy mid-scan, try creative approaches, and exploit archon findings with full coding agent capability. With `--source`, the agent receives pre-analyzed whitebox findings by default and focuses on exploitation/verification.
- **Swarm advantage:** Agentic scan with native Go handling the scanning phases (faster, cheaper), AI only called at strategic points. Better for targeted scanning and CI pipelines.

### When Modes Genuinely Differ

Despite the overlaps, each mode has a clear sweet spot:

| Mode | Unique Value | Cannot Be Replaced By |
|------|-------------|----------------------|
| **Query** | Zero-scan code analysis, CI/CD-friendly single-shot | Any other mode (they all require a target or do more than needed) |
| **Autopilot** | Adaptive, exploratory testing with no predefined workflow | Swarm (it follows fixed phases) |
| **Swarm** | Custom payload generation + SAST + multi-format input + optional full-scope discovery | Query (no scanning), Autopilot (no extension generation, higher cost) |

## Configuration

Agent backends are configured in `~/.vigolium/vigolium-configs.yaml`:

```yaml
agent:
  default_agent: claude
  templates_dir: ~/.vigolium/prompts/
  sessions_dir: ~/.vigolium/agent-sessions/
  stream: true

  warm_session:
    enable: false
    idle_timeout: 300
    max_sessions: 2

  backends:
    # Claude Code (SDK — recommended default)
    claude:
      command: claude
      protocol: sdk
      model: sonnet

    # OpenAI Codex (native JSON-RPC v2)
    codex:
      command: codex
      protocol: codex-sdk

    # OpenCode (native SDK)
    opencode:
      command: opencode
      protocol: opencode-sdk
```

Four protocols are supported:

| Protocol | Tool Access | Description |
|----------|-------------|-------------|
| `sdk` | Full (Read, Grep, Glob, Bash, Edit, Write) | Claude Agent SDK — JSON-lines protocol. **Default and recommended.** Highest output quality. |
| `codex-sdk` | Full tools | Codex native JSON-RPC v2 protocol. |
| `opencode-sdk` | Full tools | OpenCode native REST + SSE streaming protocol. |
| `pipe` | None (text only) | Classic stdin/stdout — prompt piped to stdin, output read from stdout. Legacy fallback. |

See [How It Works](how-it-works.md) for detailed protocol comparison and backend reference.

## Further Reading

- [Autopilot](autopilot.md) — detailed flow, security sandbox, session pooling
- [Swarm](swarm.md) — input normalization, master agent prompt, extension generation, discovery mode, phase breakdown
