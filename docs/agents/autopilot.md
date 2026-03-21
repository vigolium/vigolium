# Agent Autopilot

Autopilot is an **agentic scan mode** in Vigolium where AI agents autonomously drive the vigolium CLI through a sandboxed terminal. The agents decide what to discover, what to scan, how to interpret results, and when to iterate — producing a final vulnerability report with minimal human intervention.

Autopilot runs a **multi-agent specialist pipeline**. Dedicated specialists handle recon, per-vulnerability-class code analysis, native scanning, and exploit verification in parallel. Produces structured exploitation evidence with proven/unconfirmed/false-positive classifications. Best for thorough assessments where you want depth across vulnerability classes.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [CLI](#cli)
- [Key Flags](#key-flags)
- [API](#api)
- [How It Works](#how-it-works)
- [MCP Server Support](#mcp-server-support)
- [TOTP Support](#totp-support)
- [Security Sandbox](#security-sandbox)
- [Session Artifacts](#session-artifacts)
- [Checkpoint and Resume](#checkpoint-and-resume)
- [Input Types](#input-types)
- [Output](#output)
- [Comparison: Autopilot vs Swarm](#comparison-autopilot-vs-swarm)
- [When to Use](#when-to-use)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)

---

## Architecture Overview

```
              vigolium agent autopilot -t <url> --source ./app
                                        |
                                        v
              +--------------------------------------------------+
              |              CLI Initialization                    |
              |  - Parse --specialists, --resume                  |
              |  - Build AutopilotPipelineConfig                  |
              |  - Wire ScanFunc callback                         |
              |  - Enable warm session pooling                    |
              +--------------------------------------------------+
                                        |
      +---------+---------+---------+---------+---------+
      |         |         |         |         |         |
      v         v         v         v         v         v
  +-------+ +-------+ +-------+ +-------+ +-------+ +-------+
  |Phase 1| |Phase 2| |Phase 3| |Phase 4| |Phase 5| |       |
  | Recon | | Vuln  | |Native | |Exploit| |Report | |Chkpt  |
  |       | |Analyze| | Scan  | |Verify | |       | |after  |
  | (AI)  | | (AI)  | | (Go)  | | (AI)  | | (AI)  | |each   |
  | term  | | ||el  | |       | | term  | |       | |phase  |
  +-------+ +-------+ +-------+ +-------+ +-------+ +-------+
      |         |         |         |         |
      v         v         v         v         v
   Recon     VulnQueue  Findings  Evidence  Report
   Deliver-  per class  in DB     per class  .md
   able      + JS exts

  Phase 2 detail (parallel specialists):
  +----------+----------+----------+----------+----------+
  | injection|   xss    |   auth   |   ssrf   |  authz   |
  | specialist| specialist| specialist| specialist| specialist|
  |  (AI)    |  (AI)    |  (AI)    |  (AI)    |  (AI)    |
  +----------+----------+----------+----------+----------+
       |          |          |          |          |
       v          v          v          v          v
    VulnQueue  VulnQueue  VulnQueue  VulnQueue  VulnQueue
    + exts     + exts     + exts     + exts     + exts
       \          |          |          |         /
        +-------- +--------- +--------- +-------+
                             |
                          Merged
                       Extensions
```

**Key design:** The LLM does the thinking (code analysis, exploitation verification) while the native Go scanner handles bulk detection. This division of labor means the AI budget goes toward depth (understanding sinks, proving exploitability) rather than breadth (sending thousands of payloads).

---

## CLI

```bash
# Basic autonomous scan
vigolium agent autopilot -t https://example.com

# With source code context
vigolium agent autopilot -t http://localhost:3000 --source ~/projects/my-app

# Specify which vulnerability classes to analyze
vigolium agent autopilot -t https://example.com \
  --specialists injection,xss,ssrf

# All specialists with source code and focus area
vigolium agent autopilot -t http://localhost:3000 \
  --source ./src --focus "API injection in search endpoints"

# Resume a previous run from checkpoint
vigolium agent autopilot -t https://example.com \
  --resume ~/.vigolium/agent-sessions/agt-abc123

# Focus on a specific vulnerability class
vigolium agent autopilot -t https://api.example.com --focus "auth bypass"

# Pipe a curl command (target auto-derived)
echo "curl -X POST https://example.com/api/login -d '{\"user\":\"admin\"}'" \
  | vigolium agent autopilot

# Pass raw HTTP input directly
vigolium agent autopilot --input "POST /api/search HTTP/1.1\r\nHost: example.com\r\n\r\nq=test"

# Source-aware scan of specific files
vigolium agent autopilot -t http://localhost:8080 \
  --source ~/projects/spring-app \
  --files src/main/java/auth/,src/main/java/api/

# Guide the agent with custom instructions
vigolium agent autopilot -t https://staging.example.com \
  --instruction "Test only /admin and /api/v2 endpoints. Check for IDOR."

# Load pentest scope from a file
vigolium agent autopilot -t https://example.com --instruction-file scope.txt

# Quick CI scan with tight limits
vigolium agent autopilot -t https://example.com --max-commands 20 --timeout 5m

# Use a different agent backend
vigolium agent autopilot -t https://example.com --agent gemini

# Dry-run to preview the recon prompt
vigolium agent autopilot -t https://example.com --dry-run

# Show prompt before execution for debugging
vigolium agent autopilot -t https://example.com --show-prompt

# Attach a Playwright MCP server for browser-based testing
vigolium agent autopilot -t https://example.com \
  --mcp-enabled \
  --mcp-server "playwright=npx,-y,@anthropic-ai/mcp-server-playwright"

# With MCP servers and custom instructions
vigolium agent autopilot -t https://example.com \
  --source ./app \
  --mcp-enabled \
  --mcp-server "playwright=npx,-y,@anthropic-ai/mcp-server-playwright" \
  --instruction "Focus on the payment flow in /api/v2/checkout"
```

---

## Key Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-t, --target` | *(required)* | Target URL |
| `--input` | — | Raw input (curl, raw HTTP, Burp XML, URL). Reads stdin if piped |
| `--source` | — | Path to application source code |
| `--files` | — | Specific files to include (relative to `--source`) |
| `--focus` | — | Focus area hint (e.g., "auth bypass", "API injection") |
| `--instruction` | — | Custom instruction appended to the agent prompt |
| `--instruction-file` | — | Path to a file containing custom instructions |
| `--agent` | *(config)* | Agent backend to use (e.g., `claude`, `gemini`) |
| `--agent-acp-cmd` | — | Custom ACP command (overrides `--agent`) |
| `--timeout` | 30m | Maximum session duration |
| `--max-commands` | 100 | Maximum CLI commands the agent can execute |
| `--dry-run` | false | Render prompt without launching the agent |
| `--show-prompt` | false | Print rendered prompt to stderr before executing |
| `--specialists` | all 5 | Vulnerability classes to analyze: `injection`, `xss`, `auth`, `ssrf`, `authz` |
| `--resume` | — | Resume from a previous session directory |

### MCP Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--mcp-enabled` | false | Enable MCP server passthrough to ACP sessions |
| `--mcp-server` | — | MCP servers to attach (repeatable). Format: `name=command,arg1,arg2` or `name=http://url` |

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
  "max_commands": 50,
  "timeout": "30m",
  "stream": true
}
```

Check run status:

```
GET /api/agent/status/:id
```

---

## How It Works

Autopilot splits the work across specialized agents in a fixed 5-phase pipeline, trading flexibility for depth and parallelism.

### Phase 1: Recon (AI, terminal enabled)

A recon specialist discovers the target's attack surface:

- Runs content discovery and spidering via vigolium CLI
- Analyzes source code routes *(when `--source` is provided)*
- Identifies tech stack, auth flows, and API patterns
- Produces a `ReconDeliverable` JSON:

```json
{
  "endpoints": [
    {"url": "https://example.com/api/users", "method": "POST", "parameter": "username"},
    {"url": "https://example.com/api/login", "method": "POST"}
  ],
  "tech_stack": ["express", "mongodb", "jwt"],
  "auth_flows": [
    {"type": "jwt", "endpoint": "/api/login"}
  ],
  "notes": "Application uses Express.js with MongoDB."
}
```

**Prompt template:** `autopilot-recon.md`

### Phase 2: Vuln Analysis (AI, parallel, no terminal)

Specialist agents analyze the codebase for each vulnerability class **in parallel**. Each specialist:

- Reads source code via `ReadTextFile` (no terminal — pure code analysis)
- Identifies dangerous sinks specific to their vulnerability class
- Outputs a `VulnQueue` with prioritized items
- Optionally generates JavaScript scanner extensions for custom checks

```
  +-----------+  +-----------+  +-----------+  +-----------+  +-----------+
  | injection |  |    xss    |  |   auth    |  |   ssrf    |  |   authz   |
  |           |  |           |  |           |  |           |  |           |
  | SQL concat|  | innerHTML |  | JWT none  |  | HTTP call |  | No owner  |
  | exec()    |  | doc.write |  | weak hash |  | URL parse |  | check     |
  | LDAP filt |  | template  |  | session   |  | redirect  |  | mass      |
  |           |  | eval()    |  | fixation  |  | follow    |  | assign    |
  +-----------+  +-----------+  +-----------+  +-----------+  +-----------+
       |              |              |              |              |
       v              v              v              v              v
   VulnQueue      VulnQueue      VulnQueue      VulnQueue      VulnQueue
   + extensions   + extensions   + extensions   + extensions   + extensions
```

Each `VulnQueue` item contains:

```json
{
  "class": "injection",
  "items": [
    {
      "endpoint": "/api/search",
      "method": "GET",
      "parameter": "q",
      "sink_type": "sql_concat",
      "witness_payload": "' OR 1=1--",
      "context": "Parameter concatenated into SQL WHERE clause at search.js:42",
      "confidence": "high"
    }
  ]
}
```

**Prompt templates:** `autopilot-vuln-injection.md`, `autopilot-vuln-xss.md`, `autopilot-vuln-auth.md`, `autopilot-vuln-ssrf.md`, `autopilot-vuln-authz.md`

Extensions from all specialists are merged and written to `<session>/extensions/`.

### Phase 3: Native Scan (Go, no AI)

The Go scanner runs using the merged module tags and extensions from Phase 2. This is the same scanner engine used by `vigolium scan` — no LLM involvement.

```
ScanFunc(ctx, ScanRequest{
    ModuleTags:   ["injection", "xss", "auth", "ssrf", "authz"],
    ExtensionDir: "<session>/extensions/",
})
```

Findings are saved to the database.

### Phase 4: Exploit Verify (AI, parallel, terminal enabled)

For each vulnerability class that produced a `VulnQueue`, an exploit verification specialist runs **in parallel**:

- Receives the `VulnQueue` as context
- Has terminal access to run vigolium commands
- Attempts to verify each finding with targeted payloads
- Classifies each finding as `exploited`, `blocked`, or `false_positive`
- Produces `ExploitationEvidence`:

```json
{
  "evidence": [
    {
      "finding_ref": "SQLi in /api/search?q=",
      "status": "exploited",
      "vuln_class": "injection",
      "payload": "' UNION SELECT username,password FROM users--",
      "request": "GET /api/search?q=%27+UNION+SELECT+... HTTP/1.1",
      "response": "HTTP/1.1 200 OK\n...\nadmin:$2b$10$...",
      "impact": "Full database extraction via UNION-based SQL injection",
      "confidence": "proven",
      "screenshots": ["/tmp/sqli-evidence.png"]
    }
  ]
}
```

**Prompt templates:** `autopilot-exploit-injection.md`, `autopilot-exploit-xss.md`, `autopilot-exploit-auth.md`, `autopilot-exploit-ssrf.md`, `autopilot-exploit-authz.md`

### Phase 5: Report (AI, no terminal)

A report agent assembles a structured markdown report from all evidence:

- Executive summary of security posture
- Confirmed vulnerabilities with proof of exploitation
- Blocked/mitigated issues
- False positive analysis
- Prioritized remediation recommendations

The report is saved to `<session>/report.md`.

**Prompt template:** `autopilot-report.md`

---

## MCP Server Support

MCP (Model Context Protocol) servers provide additional tools to the agent — most commonly a **Playwright browser** for DOM-based testing.

### Enabling MCP

MCP servers are disabled by default. Enable via:

**CLI flag (per-run):**

```bash
vigolium agent autopilot -t https://example.com \
  --mcp-enabled \
  --mcp-server "playwright=npx,-y,@anthropic-ai/mcp-server-playwright"
```

**Config file (persistent):**

```yaml
agent:
  mcp_enabled: true
  mcp_servers:
    - name: playwright
      command: npx
      args: ["-y", "@anthropic-ai/mcp-server-playwright"]
```

### MCP Server Formats

**Stdio transport** (local command):
```
--mcp-server "name=command,arg1,arg2"
```

**HTTP transport** (remote server):
```
--mcp-server "name=http://localhost:8080/mcp"
```

### Per-Backend vs Global MCP Servers

MCP servers can be configured at two levels:

| Level | Config Key | Scope |
|-------|-----------|-------|
| Global | `agent.mcp_servers` | Attached to all ACP sessions when `mcp_enabled` is true |
| Per-backend | `agent.backends.<name>.mcp_servers` | Attached only to sessions using that backend |

Per-backend servers take precedence on name collision. CLI `--mcp-server` flags take precedence over both.

### When to Use MCP / Playwright

| Scenario | Use Playwright | Use Native Scanner |
|----------|:-:|:-:|
| DOM XSS (innerHTML, document.write) | Yes | — |
| SPA applications (client-side routing) | Yes | — |
| Form-based login with CSRF tokens | Yes | — |
| API endpoints (REST, GraphQL) | — | Yes |
| Server-side vulns (SQLi, SSRF, LFI) | — | Yes |
| Header injection | — | Yes |
| Screenshot evidence collection | Yes | — |

---

## TOTP Support

When targets require two-factor authentication, autopilot agents can generate TOTP codes:

**CLI utility:**

```bash
vigolium auth totp --secret JBSWY3DPEHPK3PXP
# Output: {"code":"735203","expires_in":18}
```

**In JavaScript extensions:**

```javascript
var otp = vigolium.utils.totpCode("JBSWY3DPEHPK3PXP");
// otp.code = "735203"
// otp.expires_in = 18
```

The TOTP utility implements RFC 6238 with a standard 30-second period. Agents in exploit verification phases are instructed to use `vigolium auth totp` when 2FA is encountered.

---

## Security Sandbox

Autopilot sessions execute commands inside a strict security sandbox enforced by the ACP terminal manager (`pkg/agent/acp_terminal.go`).

**Allowed commands:** Only `vigolium` subcommands.

**Blocked:**
- Non-vigolium binaries (`curl`, `wget`, `python`, `bash`)
- Shell metacharacters (`;`, `|`, `` ` ``, `$()`)
- Destructive subcommands (`db clean`, `db drop`)

**Limits per command:**
- 5-minute execution timeout
- 256 KB output cap

**Process isolation:**
- Each ACP session runs in its own process group
- Terminated via `SIGKILL` to the entire group on session cleanup

---

## Session Artifacts

Each autopilot run creates a session directory under `~/.vigolium/agent-sessions/agt-<uuid>/`:

```
agt-abc123-def4-5678-9012-abcdef345678/
  report.md                   # Assembled vulnerability report
  extensions/                 # Merged JS extensions from specialists
    injection-sqli-check.js
    xss-dom-sink.js
  autopilot-checkpoint.json   # Pipeline checkpoint for resume
```

The session directory is configurable via `agent.sessions_dir` in `vigolium-configs.yaml`.

---

## Checkpoint and Resume

Autopilot saves a checkpoint after each phase completes. If a run is interrupted (timeout, crash, Ctrl+C), resume from the last completed phase:

```bash
# Original run (interrupted during Phase 4)
vigolium agent autopilot -t https://example.com --source ./app
# Session: ~/.vigolium/agent-sessions/agt-abc123

# Resume — skips Phases 1-3, continues from Phase 4
vigolium agent autopilot -t https://example.com --source ./app \
  --resume ~/.vigolium/agent-sessions/agt-abc123
```

The checkpoint file (`autopilot-checkpoint.json`) contains:

```json
{
  "completed_phases": ["recon", "vuln-analysis", "native-scan"],
  "vuln_queues": {
    "injection": {"class": "injection", "items": [...]},
    "xss": {"class": "xss", "items": [...]}
  },
  "extension_dir": "~/.vigolium/agent-sessions/agt-abc123/extensions",
  "timestamp": "2026-03-21T14:30:00Z"
}
```

---

## Input Types

Autopilot accepts the same input types as other agent modes:

| Type | Example | Auto-detected |
|------|---------|:---:|
| URL | `https://example.com/api/login` | Yes |
| Curl | `curl -X POST https://example.com/api -d '{"user":"admin"}'` | Yes |
| Raw HTTP | `POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n` | Yes |
| Burp XML | `<?xml...><items><item>...</item></items>` | Yes |
| Base64 | Base64-encoded raw HTTP request | Yes |
| Stdin | `echo "curl ..." \| vigolium agent autopilot` | Yes |

When `--target` is not provided, the target URL is extracted from the input automatically.

---

## Output

Autopilot produces structured results at each phase:

| Phase | Output Type | Persisted |
|-------|-----------|-----------|
| Recon | `ReconDeliverable` JSON | In memory |
| Vuln Analysis | `VulnQueue` JSON per class | Checkpoint |
| Native Scan | Findings in DB | Database |
| Exploit Verify | `ExploitationEvidence` JSON per class | Checkpoint |
| Report | Markdown report | `<session>/report.md` |

Terminal summary on completion:

```
+ Autopilot pipeline complete: 12 findings, 8 confirmed, 2 false positives (4m32s)
```

---

## Comparison: Autopilot vs Swarm

| Aspect | Autopilot | Swarm |
|--------|-----------|-------|
| **Agent calls** | 5+ parallel specialists | 2-4 (plan + triage) |
| **AI decides workflow** | No (fixed 5-phase pipeline) | Partially (plan only) |
| **Terminal access** | Phases 1 & 4 only | No |
| **Parallelism** | Phases 2 & 4 run specialists in parallel | Batch parallelism |
| **Exploit verification** | Dedicated Phase 4 with evidence JSON | Via triage rescan |
| **Evidence format** | Structured `ExploitationEvidence` | Triage verdict |
| **Checkpoint/resume** | Yes | Yes |
| **Source code analysis** | Dedicated specialists per vuln class | Consolidated 3-call |
| **Native scanner** | Phase 3 (bulk scan with extensions) | Phase 4 (bulk scan) |
| **Best for** | Thorough multi-class assessment | Targeted request analysis |
| **AI cost** | High (many parallel calls) | Lowest (2-4 calls) |

### Decision Guide

```
Do you have specific HTTP requests to test?
  Yes --> Use Swarm (vigolium agent swarm --input <request>)
  No  --> Continue...

Do you want structured evidence with exploit verification?
  Yes --> Autopilot (vigolium agent autopilot -t <url>)
  No  --> Use Swarm with --discover for full-scope structured scanning
```

---

## When to Use

### Use Autopilot when:

- You want **depth across multiple vulnerability classes** simultaneously
- You need **structured exploitation evidence** (proven/blocked/false_positive)
- You have **source code** and want per-vulnerability-class code analysis
- You want **checkpoint/resume** for long-running assessments
- You need a **reproducible pipeline** (fixed phases, deterministic native scan)
- You're using **Playwright/MCP** for browser-based exploit verification

### Use Swarm instead when:

- You have **specific HTTP requests** to analyze (not exploratory)
- You want the **lowest AI cost** (2-4 agent calls vs many parallel)
- You want **AI-generated scanner extensions** (JS quick checks, snippets)
- You need **batch processing** of many requests

---

## Configuration

### Agent Backend (vigolium-configs.yaml)

```yaml
agent:
  default_agent: claude

  # MCP server passthrough (used by autopilot --mcp-enabled)
  mcp_enabled: false
  mcp_servers:
    - name: playwright
      command: npx
      args: ["-y", "@anthropic-ai/mcp-server-playwright"]

  # Warm session pooling (auto-enabled by autopilot)
  warm_session:
    enable: false
    idle_timeout: 300
    max_sessions: 2

  backends:
    claude:
      command: npx
      args: ["-y", "@zed-industries/claude-agent-acp@latest"]
      protocol: acp
      model: sonnet
      # Per-backend MCP servers (merged with global when mcp_enabled: true)
      # mcp_servers:
      #   - name: custom-tool
      #     url: http://localhost:9090/mcp
```

### Prompt Templates

Autopilot uses prompt templates stored in `~/.vigolium/prompts/` (user overrides) or embedded in the binary (`public/presets/prompts/autopilot/`).

| Template | Phase | Output Schema | Terminal |
|----------|-------|--------------|---------|
| `autopilot-recon` | Phase 1 | recon_deliverable | Yes |
| `autopilot-vuln-{class}` | Phase 2 | vuln_queue | No |
| `autopilot-exploit-{class}` | Phase 4 | exploitation_evidence | Yes |
| `autopilot-report` | Phase 5 | text | No |

Where `{class}` is one of: `injection`, `xss`, `auth`, `ssrf`, `authz`.

To override a template, create a file with the same `id` in your `templates_dir`.

---

## Troubleshooting

### Agent returns empty output

The LLM backend may not be processing prompts. Check:
- Agent backend is authenticated (`claude` requires login, `gemini` requires API key)
- The ACP bridge is installed (`npx @zed-industries/claude-agent-acp@latest`)
- Use `--show-prompt` to verify the prompt renders correctly

### Specialist returns empty VulnQueue

The specialist may not have found any sinks for its vulnerability class. This is normal — not every codebase has every vulnerability type. Check:
- `--source` points to the correct directory
- `--files` is not too restrictive
- The codebase language is supported by the specialist prompts

### Timeout during Phase 4 (Exploit Verify)

Exploit verification can be slow when the agent runs many CLI commands. Options:
- Increase `--timeout` (default: 30m)
- Reduce specialists with `--specialists injection,xss` (fewer parallel agents)
- Increase `--max-commands` if the agent is hitting the limit

### MCP server not connecting

- Verify the command works standalone: `npx -y @anthropic-ai/mcp-server-playwright`
- Check `--mcp-enabled` is set (MCP is off by default)
- Use `--show-prompt` to verify MCP servers appear in the ACP session config
- HTTP MCP servers must be running before the agent starts

### Resume fails with "no checkpoint found"

- The `--resume` path must point to a session directory containing `autopilot-checkpoint.json`
- Verify the path: `ls ~/.vigolium/agent-sessions/agt-<uuid>/autopilot-checkpoint.json`
