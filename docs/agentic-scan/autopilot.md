# Agent Autopilot

Autopilot is Vigolium's **fully autonomous agentic scan mode**. An AI agent with full CLI tool access (Bash, Read, Grep, Glob, Edit, Write) drives the vulnerability assessment workflow — reconnaissance, scanning, exploitation, and reporting — in a single command.

When `--source` is provided, archon-audit runs **first**. Autopilot prepares Archon output into a native context bundle and execution plan, then launches the autonomous operator agent against that prepared context. Use `--no-archon` to disable this behavior.

## Architecture Overview

```
              vigolium agent autopilot -t <target> --source <path> --archon-mode deep
                                          |
                                          v
                 +---------------------------------------------------+
                 |              CLI Initialization                    |
                 |  - Parse flags (--target, --source, --archon-mode)|
                 |  - Resolve --instruction / --instruction-file      |
                 |  - Create session directory                        |
                 |  - Build AutopilotPipelineConfig                   |
                 +---------------------------------------------------+
                                          |
                                          v
                 +---------------------------------------------------+
                 |        AutopilotPipelineRunner.RunAutonomous()     |
                 |  - Preflight: verify agent backend reachable       |
                 +---------------------------------------------------+
                                          |
                                          |
                                          v
                 +---------------------------------------------------+
                 |                ARCHON-AUDIT FIRST                 |
                 |  - Runs on source before operator startup         |
                 |  - Imports findings to DB                         |
                 |  - Produces isolated archon artifacts             |
                 +---------------------------------------------------+
                                          |
                                          v
                 +---------------------------------------------------+
                 |      NATIVE CONTEXT + PLAN PREPARATION            |
                 |  - Build stable context bundle                    |
                 |  - Decide browser/auth strategy                   |
                 |  - Write plan + artifact manifest                 |
                 +---------------------------------------------------+
                                          |
                                          v
                 +---------------------------------------------------+
                 |           AUTONOMOUS AGENT SESSION                |
                 |  - Full SDK tool access                           |
                 |  - Executes against prepared context              |
                 |  - Produces evidence-backed artifacts             |
                 |  - Output → autopilot/output.md                  |
                 +---------------------------------------------------+
```

When `--source` is not provided, archon is skipped and the agent receives a generic security assessment brief. Use `--no-archon` to disable archon even with source.

---

## Quick Start

```bash
# Basic autonomous scan (no source, no archon — agent drives everything)
vigolium agent autopilot -t https://example.com

# Source-aware scan (archon runs first)
vigolium agent autopilot -t http://localhost:3000 --source ~/src/my-app

# Deep archon audit mode (11-phase) for maximum coverage
vigolium agent autopilot -t http://localhost:3000 --source ~/src/my-app --archon-mode deep

# Disable archon even with source
vigolium agent autopilot -t http://localhost:3000 --source ~/src/my-app --no-archon

# Source-only code review (no live target)
vigolium agent autopilot --source ~/src/my-app

# With focus area
vigolium agent autopilot -t https://api.example.com --focus "auth bypass"

# Natural language prompt (parses target, source, focus automatically)
vigolium agent autopilot "scan VAmPI source at ~/src/VAmPI on localhost:3005"

# Preview the prompt without executing
vigolium agent autopilot -t https://example.com --source ./src --archon-mode deep --dry-run
```

### Intensity Presets

The `--intensity` flag bundles multiple settings into a single preset:

```bash
# ── Quick (CI/PR review) ─────────────────────────────────────
vigolium agent autopilot -t http://localhost:3000 --source ~/src/my-app --intensity quick

# ── Balanced (default, routine assessment) ────────────────────
vigolium agent autopilot -t http://localhost:3000 --source ~/src/my-app

# ── Deep (thorough pentest) ───────────────────────────────────
vigolium agent autopilot -t http://localhost:3000 --source ~/src/my-app --intensity deep
```

Each preset configures:

| Setting | `quick` | `balanced` (default) | `deep` |
|---|---|---|---|
| `--max-commands` | 30 | 100 | 300 |
| `--timeout` | 1h | 6h | 12h |
| `--archon-mode` | lite | scan | deep |
| `--browser` | off | off | on |

Explicit flags always override intensity presets:

```bash
# Deep intensity but with a shorter timeout
vigolium agent autopilot -t http://localhost:3000 --intensity deep --timeout 2h

# Quick intensity but allow more commands
vigolium agent autopilot -t http://localhost:3000 --intensity quick --max-commands 200
```

### Source Input Types

The `--source` flag accepts multiple input types, auto-detected:

```bash
# Local directory (most common)
vigolium agent autopilot -t http://target --source ~/src/my-app

# Git URL (cloned to session dir automatically)
vigolium agent autopilot -t http://target --source https://github.com/org/repo.git

# Private repo with OAuth token (token stripped from logs)
vigolium agent autopilot -t http://target \
  --source "https://oauth2:ghp_token123@github.com/org/private-repo.git"

# SSH URL (uses system SSH keys)
vigolium agent autopilot -t http://target --source git@github.com:org/repo.git

# Archive file (extracted to session dir)
vigolium agent autopilot -t http://target --source ./app-source.tar.gz
vigolium agent autopilot -t http://target --source ~/downloads/source.zip
```

### Diff-Focused Scanning

Focus the scan on changed code using `--diff` or `--last-commits`:

```bash
# GitHub PR — auto-fetches changed files and patch via gh CLI
vigolium agent autopilot -t http://target \
  --source ~/src/repo --diff "https://github.com/org/repo/pull/123"

# GitHub PR with OAuth token (for private repos — token used for both API auth and auto-clone)
vigolium agent autopilot -t http://target \
  --diff "https://oauth2:ghp_token123@github.com/org/private-repo/pull/42"

# Git ref range
vigolium agent autopilot -t http://target \
  --source ~/src/repo --diff "origin/main...feature-branch"

# Last N commits
vigolium agent autopilot -t http://target \
  --source ~/src/repo --last-commits 5

# PR URL without --source (auto-clones the repo)
vigolium agent autopilot -t http://target \
  --diff "https://github.com/org/repo/pull/123"

# CI/CD integration — GitHub Actions
vigolium agent autopilot -t $APP_URL \
  --source . --diff "https://github.com/$GITHUB_REPOSITORY/pull/$PR_NUMBER" \
  --archon-mode lite --max-commands 20 --timeout 10m
```

When `--diff` is used, the changed file list auto-populates `--files` (unless explicitly set), and the patch content is included in the agent prompt so it can prioritize changed code paths.

---

## How It Works

### Without Source (Generic Mode)

When no `--source` is provided, archon is skipped and autopilot launches a single autonomous agent with a generic security assessment brief:

1. **Reconnaissance** — content discovery, spidering, endpoint probing
2. **Authentication** — if `--browser` is enabled and the target has a login page, `agent-browser` can capture sessions
3. **Analysis & Scanning** — `vigolium scan-url`, `vigolium scan-request`, custom JS extensions
4. **Verification** — confirm findings with curl, test related endpoints
5. **Reporting** — summarize vulnerabilities with evidence

### With Source (Archon-First)

When `--source` is provided, archon-audit runs **before** the autonomous agent:

- **Archon-audit** runs on the source first and writes its own isolated artifacts
- **Autopilot** converts Archon output into a stable whitebox context bundle and native plan
- **The autonomous agent** starts only after that context is prepared
- The operator works from stable Archon and autopilot artifacts

The agent reviews each archon finding and decides what action to take:

- **Exploit confirmed findings** — Write PoCs using curl, custom scripts, or vigolium extensions against the live target
- **Run targeted native scans** — Use `vigolium scan-url` and `vigolium scan-request` on routes identified in findings
- **Investigate uncertain findings** — Read source code, probe endpoints, gather evidence
- **Skip low-confidence findings** — Disproved or info-level findings are deprioritized
- **Discover gaps** — Run content discovery to find endpoints the audit may have missed

### Source-Only Mode

When `--source` is provided without `--target`, autopilot runs in code review mode. Archon still runs first, and the agent performs static analysis, data flow tracing, and vulnerability assessment on the source code without sending network traffic.

### Finding Prompt Formatting

Archon findings are formatted in the agent prompt using a tiered approach based on finding count:

| Finding Count | Format |
|---------------|--------|
| 0-15 | Full detail per finding (ID, severity, verdict, PoC status, locations, body excerpt) |
| 16-40 | Summary table for all + full detail for critical/high only |
| 41+ | Summary table for all + full detail for top 10 by severity + pointer to the persisted Archon finding files |

The operator can still inspect the persisted Archon finding files directly from the session artifacts when needed.

---

## CLI

```bash
vigolium agent autopilot [prompt] [flags]
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--intensity` | balanced | Scan intensity preset: `quick`, `balanced`, or `deep` |
| `-t, --target` | — | Target URL (derived from `--input` if not set) |
| `--input` | — | Raw input (curl, raw HTTP, Burp XML, URL). Reads stdin if piped |
| `--source` | — | Path to source code, git URL, or archive file (auto-enables archon) |
| `--files` | — | Specific files to include (relative to `--source`) |
| `--diff` | — | Focus on changed code: GitHub PR URL (`github.com/.../pull/123`), git ref range (`main...branch`), or `HEAD~N` |
| `--last-commits` | 0 | Focus on last N commits (shorthand for `--diff HEAD~N`) |
| `--focus` | — | Focus area hint (e.g., "API injection", "auth bypass") |
| `--instruction` | — | Custom instruction appended to the agent prompt |
| `--instruction-file` | — | Path to a file containing custom instructions |
| `--no-archon` | false | Disable automatic archon-audit (enabled by default when `--source` is set) |
| `--archon-mode` | lite | Archon audit mode: `lite` (3-phase), `scan` (6-phase), or `deep` (11-phase) |
| `--agent` | (config) | Agent backend to use |
| `--max-commands` | 100 | Maximum CLI commands the agent can execute |
| `--timeout` | 6h | Maximum session duration |
| `--dry-run` | false | Render the prompt without launching the agent |
| `--show-prompt` | false | Print rendered prompt to stderr before executing |
| `--browser` | false | Enable agent-browser for browser-based authentication and SPA exploration |
| `--mcp-server` | — | MCP servers to attach (`name=command,arg1` or `name=http://url`) |
| `--mcp-enabled` | false | Enable MCP server passthrough to agent sessions |

**Source input types:** `--source` accepts local paths (`~/src/app`), git URLs (`https://github.com/org/repo.git`), git URLs with embedded OAuth tokens (`https://oauth2:TOKEN@github.com/...`), SSH URLs (`git@github.com:org/repo.git`), and archive files (`.zip`, `.tar.gz`, `.tgz`, `.tar.bz2`, `.tar.xz`). Git repos are cloned and archives are extracted into the session directory automatically.

**Diff types:** `--diff` accepts GitHub PR URLs, git ref ranges (`main...branch`, `abc123..def456`), and `HEAD~N`. When a PR URL is provided without `--source`, the repo is auto-cloned. Changed files auto-populate `--files` for focused archon and agent analysis. OAuth tokens embedded in PR URLs (`https://oauth2:TOKEN@github.com/.../pull/42`) are extracted and used as `Authorization: Bearer` header for the GitHub REST API. The `GITHUB_TOKEN` env var is used as a fallback when no token is in the URL.

### Examples

```bash
# Pipe a curl command — target auto-derived from URL
echo "curl -X POST https://example.com/api/login -d '{\"user\":\"admin\"}'" | vigolium agent autopilot

# Pass raw HTTP input directly
vigolium agent autopilot --input "POST /api/search HTTP/1.1\r\nHost: example.com\r\n\r\nq=test"

# Source-aware scan of specific files (archon runs automatically)
vigolium agent autopilot -t http://localhost:8080 --source ~/projects/spring-app \
  --files src/main/java/auth/,src/main/java/api/

# Deep archon-audit mode for comprehensive whitebox + dynamic coverage
vigolium agent autopilot -t http://localhost:8080 --source ~/projects/spring-app --archon-mode deep

# Guide the agent with custom instructions
vigolium agent autopilot -t https://staging.example.com \
  --instruction "Test only the /admin and /api/v2 endpoints. Check for IDOR and privilege escalation."

# Load detailed pentest scope from a file
vigolium agent autopilot -t https://example.com --instruction-file scope.txt

# Quick scan with tight limits for CI
vigolium agent autopilot -t https://example.com --max-commands 20 --timeout 5m

# Multi-app natural language prompt (fans out parallel runs)
vigolium agent autopilot "scan all source code from ~/src/crAPI, ~/src/DVWA"
```

---

## Archon-Audit Integration

When `--source` is provided, archon-audit runs **before** the autonomous agent. Autopilot prepares the resulting whitebox context into stable artifacts and a native plan, then starts the operator session. Use `--no-archon` to disable, or `--archon-mode` to select the audit depth.

### Archon Modes

| Mode | Phases | Duration | Description |
|------|--------|----------|-------------|
| `lite` | 3 | Minutes | Quick recon + secrets + fast SAST |
| `scan` | 6 | ~1 hour | Comprehensive analysis (adds enrichment, finding validation) |
| `deep` | 11 | Hours | Full adversarial audit (debate chambers, cold verification, variant hunting, PoC building) |

### Data Flow

```
archon-audit runs first
        |
        v
session/archon/
├── audit-state.json         --> phase completion status
├── findings/                --> persisted finding markdown files
└── knowledge-base-report.md --> architecture, threat model, attack surface
        |
        v
session/autopilot/
├── context.json             --> stable whitebox context bundle
├── plan.json                --> native execution plan
├── findings.json            --> confirmed findings artifact
├── dismissed.json           --> dismissed findings artifact
├── auth-state.json          --> auth status artifact
└── browser-session.json     --> browser-derived session artifact
```

Any pre-existing Archon findings are loaded before the operator starts and included in the prepared context bundle.

### Finding Fields Available to the Agent

Each archon finding in the prompt includes:

- **FindingID** — e.g., `P8-001`, `P10-003`
- **Title** — human-readable vulnerability name
- **Severity** — critical, high, medium, low, info
- **Verdict** — VALID, INVALID, CONFIRMED
- **PoC Status** — theoretical, pending, confirmed, executed
- **CWE** — e.g., CWE-89, CWE-918
- **Locations** — source code file paths and line ranges
- **Body excerpt** — first 500 characters of the finding description

Findings are also imported into the database (tags: `archon`, `phase-N`, verdict, CWE) and accessible via `vigolium finding --json`.

---

## API

```
POST /api/agent/run/autopilot
```

**Request body fields** (see [API Reference](../api-references/agent.md) for the full schema):

| Field | Type | Description |
|-------|------|-------------|
| `intensity` | string | Scan intensity preset: `"quick"`, `"balanced"` (default), or `"deep"` |
| `target` | string | Target URL |
| `source` | string | Path to source code, git URL, or archive file |
| `diff` | string | PR URL, git ref range, or `HEAD~N` for diff-focused scanning |
| `last_commits` | int | Shorthand for `--diff HEAD~N` |
| `focus` | string | Focus area hint |
| `instruction` | string | Custom instruction |
| `no_archon` | bool | Disable automatic archon-audit |
| `archon_mode` | string | `"lite"`, `"scan"`, or `"deep"` |
| `max_commands` | int | Max CLI commands (default 100) |
| `timeout` | string | Duration string (default `"6h"`) |
| `stream` | bool | Enable SSE streaming |

### Example: Quick Scan (CI/PR Review)

Fast scan with tight resource limits — ideal for CI pipelines:

```bash
curl -s -X POST http://localhost:9002/api/agent/run/autopilot \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://localhost:3000",
    "source": "/home/user/src/my-app",
    "intensity": "quick",
    "diff": "https://github.com/org/repo/pull/42"
  }' | jq .
```

### Example: Balanced Scan (Routine Assessment)

Standard scan with source context — good balance of coverage and speed. `"balanced"` is the default when `intensity` is omitted:

```bash
curl -s -X POST http://localhost:9002/api/agent/run/autopilot \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://localhost:3000",
    "source": "/home/user/src/my-app",
    "focus": "authentication bypass",
    "stream": true
  }'
```

### Example: Deep Scan (Thorough Pentest)

Maximum coverage with deep archon, browser, high command limit, and extended timeout:

```bash
curl -s -X POST http://localhost:9002/api/agent/run/autopilot \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://localhost:3000",
    "source": "/home/user/src/my-app",
    "intensity": "deep",
    "instruction": "Test all API endpoints. Focus on IDOR, auth bypass, and injection.",
    "stream": true
  }'
```

Individual fields can override intensity presets:

```bash
curl -s -X POST http://localhost:9002/api/agent/run/autopilot \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://localhost:3000",
    "intensity": "deep",
    "max_commands": 50,
    "timeout": "2h"
  }' | jq .
```

### Example: Diff-Only Scan (PR Review)

Scan focused on a GitHub PR's changed files — agent and archon prioritize the diff.

```bash
curl -s -X POST http://localhost:9002/api/agent/run/autopilot \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://staging.example.com",
    "diff": "https://github.com/org/repo/pull/123",
    "archon_mode": "lite",
    "max_commands": 25,
    "timeout": "15m"
  }' | jq .
```

### Example: Git URL with Token (Private Repo)

Source from a private GitHub repo — the OAuth token is used for cloning and stripped from logs.

```bash
curl -s -X POST http://localhost:9002/api/agent/run/autopilot \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://localhost:3000",
    "source": "https://oauth2:ghp_token123@github.com/org/private-repo.git",
    "archon_mode": "scan",
    "stream": true
  }'
```

### Response

Set `"stream": true` for SSE streaming of agent output. The response streams `chunk` events with raw agent output and a final `done` event with the result.

Non-streaming requests return `202 Accepted` with a run ID for status polling:

```json
{
  "run_id": "agt-550e8400-e29b-41d4-a716-446655440000",
  "status": "running",
  "message": "autopilot run started"
}
```

```
GET /api/agent/status/:id
```

---

## Session Artifacts

Each autopilot run creates a session directory:

```
~/.vigolium/agent-sessions/<uuid>/
├── output.md                    # Raw top-level operator output
├── archon/                      # (if source + archon enabled)
│   ├── audit-state.json         # Archon phase state + timing
│   ├── findings/                # Persisted finding markdown files
│   ├── knowledge-base-report.md # Architecture + threat model
│   └── ...                      # Other archon artifacts
├── autopilot/
│   ├── context.json             # Stable whitebox context bundle
│   ├── brief.md                 # Operator mission brief
│   ├── plan.json                # Native execution plan
│   ├── output.md                # Operator output for this run
│   ├── findings.json            # Confirmed findings artifact
│   ├── dismissed.json           # Dismissed findings artifact
│   ├── auth-state.json          # Auth/session state artifact
│   ├── browser-session.json     # Browser-derived session artifact
│   └── evidence/                # Evidence files
└── CLAUDE.md                    # System prompt (SDK mode)
```

---

## Autopilot vs Swarm

Both are agentic scan modes. Choose based on your use case:

| | Autopilot | Swarm |
|---|-----------|-------|
| **Agent involvement** | Agent drives everything autonomously | AI at strategic points, native Go for scanning |
| **Tool access** | Full SDK (Bash, Read, Grep, Glob, Edit, Write) | Limited to prompt/response per phase |
| **Archon integration** | Sequential: archon findings fed into agent prompt | Parallel: archon runs alongside swarm |
| **Best for** | Exploratory testing, exploit development, creative approaches | Targeted scanning, full-scope scanning, CI pipelines |
| **Cost** | Higher (many agent turns) | Lower (2-4 AI calls + native scanning) |
| **Speed** | Slower (agent decides pace) | Faster (native scan phases) |
| **Reproducibility** | Lower (agent may take different paths) | Higher (deterministic native phases) |

**When to use autopilot:**
- You have archon-audit findings and want an agent to exploit/verify them
- You need creative, adaptive testing (e.g., chained exploits, business logic)
- Exploratory penetration testing where the workflow isn't known upfront

**When to use swarm:**
- You have specific requests to scan with targeted vuln types
- You want fast, cost-effective scanning with AI-generated payloads
- CI/CD integration where reproducibility and speed matter
- Full-scope scanning with `--discover` for broad coverage

---

## Configuration

Autopilot uses the agent configuration from `vigolium-configs.yaml`:

```yaml
agent:
  default_agent: claude          # agent backend for autopilot
  sessions_dir: ~/.vigolium/agent-sessions/
  stream: true                   # stream agent output to stdout

  # Archon-audit defaults (overridden by --archon flag)
  archon:
    mode: lite                   # default audit mode
    platform: claude             # claude, codex, or opencode
    sync_interval: 30            # seconds between state syncs

  backends:
    claude:
      protocol: sdk              # required for autopilot
      model: claude-sonnet-4-6
```

Autopilot requires the `sdk` protocol for full tool access. Non-SDK backends will produce a warning — consider using `vigolium agent swarm` for non-SDK agents.
