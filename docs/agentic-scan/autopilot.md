# Agent Autopilot

Autopilot is Vigolium's **fully autonomous agentic scan mode**. An AI agent with full CLI tool access (Bash, Read, Grep, Glob, Edit, Write) drives the entire vulnerability scanning workflow — reconnaissance, scanning, exploitation, and reporting — in a single command.

When `--source` is provided, archon-audit runs **automatically in parallel** with the autonomous agent. The agent begins scanning immediately while archon audits the source code, picking up findings as they arrive in the session directory. Use `--no-archon` to disable this behavior.

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
                         +----------------+----------------+
                         |                                 |
                         v                                 v
           +---------------------------+     +---------------------------+
           | ARCHON-AUDIT (parallel)   |     | AUTONOMOUS AGENT SESSION  |
           | (auto when --source set)  |     |                           |
           |                           |     | - Full SDK tool access    |
           | - Launches as background  |     | - Starts immediately      |
           |   process                 |     | - Runs vigolium CLI, curl |
           | - Syncs findings to       |---->| - Monitors findings-draft |
           |   session dir every 30s   |     |   for new archon findings |
           | - Imports findings to DB  |     | - Exploits findings as    |
           |                           |     |   they arrive             |
           +---------------------------+     | - Output → output.md     |
                                             +---------------------------+
```

When `--source` is not provided, archon is skipped and the agent receives a generic security assessment brief. Use `--no-archon` to disable archon even with source.

---

## Quick Start

```bash
# Basic autonomous scan (no source, no archon — agent drives everything)
vigolium agent autopilot -t https://example.com

# Source-aware scan (archon runs automatically in parallel)
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

---

## How It Works

### Without Source (Generic Mode)

When no `--source` is provided, archon is skipped and autopilot launches a single autonomous agent with a generic security assessment brief:

1. **Reconnaissance** — content discovery, spidering, endpoint probing
2. **Authentication** — if `--browser` is enabled and the target has a login page, `agent-browser` can capture sessions
3. **Analysis & Scanning** — `vigolium scan-url`, `vigolium scan-request`, custom JS extensions
4. **Verification** — confirm findings with curl, test related endpoints
5. **Reporting** — summarize vulnerabilities with evidence

### With Source (Parallel Archon + Agent)

When `--source` is provided, archon-audit launches **in parallel** with the autonomous agent:

- **Archon-audit** runs as a background process on the source code, syncing findings to the session directory every 30 seconds
- **The autonomous agent** starts immediately — it begins reconnaissance and scanning without waiting for archon
- As archon findings arrive, the agent picks them up by reading `<session-dir>/archon-audit/findings-draft/`
- The agent's prompt includes instructions on where to find and how to monitor live findings

The agent reviews each archon finding and decides what action to take:

- **Exploit confirmed findings** — Write PoCs using curl, custom scripts, or vigolium extensions against the live target
- **Run targeted native scans** — Use `vigolium scan-url` and `vigolium scan-request` on routes identified in findings
- **Investigate uncertain findings** — Read source code, probe endpoints, gather evidence
- **Skip low-confidence findings** — Disproved or info-level findings are deprioritized
- **Discover gaps** — Run content discovery to find endpoints the audit may have missed

### Source-Only Mode

When `--source` is provided without `--target`, autopilot runs in code review mode. Archon still runs in parallel, and the agent performs static analysis, data flow tracing, and vulnerability assessment on the source code without sending network traffic.

### Finding Prompt Formatting

Archon findings are formatted in the agent prompt using a tiered approach based on finding count:

| Finding Count | Format |
|---------------|--------|
| 0-15 | Full detail per finding (ID, severity, verdict, PoC status, locations, body excerpt) |
| 16-40 | Summary table for all + full detail for critical/high only |
| 41+ | Summary table for all + full detail for top 10 by severity + pointer to findings-draft directory |

The agent always has access to the full finding files via `cat <session-dir>/archon-audit/findings-draft/<filename>.md`.

---

## CLI

```bash
vigolium agent autopilot [prompt] [flags]
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-t, --target` | — | Target URL (derived from `--input` if not set) |
| `--input` | — | Raw input (curl, raw HTTP, Burp XML, URL). Reads stdin if piped |
| `--source` | — | Path to application source code (auto-enables archon) |
| `--files` | — | Specific files to include (relative to `--source`) |
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

When `--source` is provided, archon-audit runs **automatically in parallel** with the autonomous agent. The agent starts immediately while archon audits the source code in the background, syncing findings to the session directory every 30 seconds. Use `--no-archon` to disable, or `--archon-mode` to select the audit depth.

### Archon Modes

| Mode | Phases | Duration | Description |
|------|--------|----------|-------------|
| `lite` | 3 | Minutes | Quick recon + secrets + fast SAST |
| `scan` | 6 | ~1 hour | Comprehensive analysis (adds enrichment, finding validation) |
| `deep` | 11 | Hours | Full adversarial audit (debate chambers, cold verification, variant hunting, PoC building) |

### Data Flow

```
archon-audit runs in parallel
        |
        | (syncs every 30s)
        v
session/archon-audit/
├── audit-state.json         --> phase completion status
├── findings-draft/          --> agent reads these as they appear
│   ├── p7-001-slug.md       --> SAST enrichment findings
│   ├── p8-001-slug.md       --> chamber debate findings
│   ├── p10-001-slug.md      --> variant analysis findings
│   └── ...
└── knowledge-base-report.md --> architecture, threat model, attack surface
        |
        | (agent monitors this directory)
        v
Agent reads findings via:
  ls <session-dir>/archon-audit/findings-draft/
  cat <session-dir>/archon-audit/*.md
```

Any pre-existing findings (e.g., from a resumed session) are loaded at startup and included in the initial prompt via `loadArchonContext()` with tiered formatting.

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

```json
{
  "target": "https://example.com",
  "agent": "claude",
  "source": "/path/to/source",
  "focus": "API injection",
  "instruction": "Focus on auth bypass and IDOR",
  "archon": "deep",
  "max_commands": 50,
  "timeout": "6h",
  "stream": true
}
```

Set `"stream": true` for SSE streaming of agent output. The response streams `chunk` events with raw agent output and a final `done` event with the result.

Non-streaming requests return `202 Accepted` with a run ID for status polling:

```
GET /api/agent/status/:id
```

---

## Session Artifacts

Each autopilot run creates a session directory:

```
~/.vigolium/agent-sessions/agt-<uuid>/
├── output.md                    # Raw agent output
├── archon-audit/                # (if --archon enabled)
│   ├── audit-state.json         # Archon phase state + timing
│   ├── findings-draft/          # Raw finding markdown files
│   ├── knowledge-base-report.md # Architecture + threat model
│   └── ...                      # Other archon artifacts
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
