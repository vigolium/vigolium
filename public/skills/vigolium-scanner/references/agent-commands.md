# Agent Commands Reference

Complete flag reference for `agent`, `agent query`, `agent autopilot`, and `agent pipeline` commands.

## Table of Contents

- [agent](#agent)
- [agent query](#agent-query)
- [agent autopilot](#agent-autopilot)
- [agent pipeline](#agent-pipeline)
- [Prompt Templates](#prompt-templates)
- [Agent Configuration](#agent-configuration)
- [Output Schemas](#output-schemas)

---

## agent

**Usage:** `vigolium agent [flags]`

Run an AI coding agent for security code review, endpoint discovery, or custom analysis using prompt templates. Returns structured JSON (findings or HTTP records) saved to the database.

### agent flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--agent` | string | from config | Agent backend to use |
| `--prompt-template` | string | — | Prompt template ID (e.g. security-code-review) |
| `--prompt-file` | string | — | Path to a prompt template file |
| `--repo` | string | — | Path to source code repository |
| `--files` | []string | — | Specific files to include (relative to --repo) |
| `--append` | string | — | Append extra text to the rendered prompt |
| `--output` | string | — | Write agent output to this file |
| `--source` | string | — | Label for records ingested from agent output (e.g. 'agent-review') |
| `--list-templates` | bool | `false` | List available prompt templates |
| `--list-agents` | bool | `false` | List configured agent backends |
| `--dry-run` | bool | `false` | Print the rendered prompt without executing |
| `--agent-timeout` | duration | `5m` | Maximum time for agent execution (0 = no limit) |

### Examples

```bash
# Security code review
vigolium agent --prompt-template security-code-review --repo ./src

# Endpoint discovery
vigolium agent --prompt-template endpoint-discovery --repo ./src

# Custom prompt file
vigolium agent --prompt-file custom-prompt.md --repo ./src

# With specific agent backend
vigolium agent --agent claude --prompt-template security-code-review --repo ./src

# Append instructions to prompt
vigolium agent --prompt-template security-code-review --repo ./src \
  --append "Focus on authentication and authorization issues"

# Specific files only
vigolium agent --prompt-template security-code-review --repo ./src \
  --files "src/auth.go,src/middleware.go"

# Dry run (preview prompt)
vigolium agent --prompt-template security-code-review --repo ./src --dry-run

# Save output
vigolium agent --prompt-template security-code-review --repo ./src \
  --output review-results.json

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
| `--prompt` | `-p` | string | — | Prompt text to send to the agent |
| `--stdin` | — | bool | `false` | Read prompt from stdin |
| `--output` | — | string | — | Write agent output to this file |
| `--source` | — | string | — | Source identifier for ingested records |
| `--agent-timeout` | — | duration | `5m` | Maximum time for agent execution (0 = no limit) |

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

# Custom prompt file
vigolium agent query --agent claude --prompt-file custom-prompt.md

# With timeout
vigolium agent query --agent-timeout 10m 'comprehensive security review'
```

---

## agent autopilot

**Usage:** `vigolium agent autopilot [flags]`

Launch an AI agent that autonomously discovers, scans, and triages vulnerabilities by running vigolium CLI commands via terminal execution. The agent receives a system prompt with available commands and workflow guidance, then decides its own approach.

### agent autopilot flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--target` | `-t` | string | — | Target URL (**required**) |
| `--agent` | — | string | from config | Agent backend to use |
| `--repo` | — | string | — | Path to source code repository for context |
| `--files` | — | []string | — | Specific files to include (relative to --repo) |
| `--focus` | — | string | — | Focus area hint (e.g. "API injection", "auth bypass") |
| `--system-prompt` | — | string | — | Custom system prompt file (overrides default) |
| `--timeout` | — | duration | `30m` | Maximum duration for the autopilot session |
| `--max-commands` | — | int | `100` | Maximum number of CLI commands the agent can execute |
| `--dry-run` | — | bool | `false` | Render the system prompt without launching the agent |

### Terminal Security Model

The autopilot agent executes commands within a strict sandbox:

- **Allowlist**: Only `vigolium` commands are permitted
- **Blocklist**: Destructive subcommands blocked (`db clean`, `db seed`, `db drop`)
- **Shell injection prevention**: Shell metacharacters (`;|&\`$(){}!><`) rejected; commands executed directly via `exec`, not through a shell
- **Per-command timeout**: 5 minutes per command
- **Call limit**: Enforced by `--max-commands` (default 100)
- **Output cap**: 256KB per command session
- **Process isolation**: Terminal child processes run in their own process group

### Examples

```bash
# Basic autonomous scan
vigolium agent autopilot -t https://example.com

# With source code context and focus area
vigolium agent autopilot -t https://api.example.com --repo ./src --focus "auth bypass"

# Custom limits
vigolium agent autopilot -t https://example.com --max-commands 50 --timeout 15m

# Preview system prompt
vigolium agent autopilot -t https://example.com --dry-run

# Custom system prompt
vigolium agent autopilot -t https://example.com --system-prompt my-system-prompt.md

# With specific agent backend
vigolium agent autopilot -t https://example.com --agent gemini
```

---

## agent pipeline

**Usage:** `vigolium agent pipeline [flags]`

Run a fixed multi-phase scanning pipeline where native Go code handles heavy lifting and AI agents only intervene at checkpoints (phases 2 and 4). This keeps costs low while leveraging AI for strategic decisions.

### Pipeline Phases

```
Phase 1: Discover  → Native deparos + spidering (no AI)
Phase 2: Plan      → Agent analyzes discovery results → AttackPlan
Phase 3: Scan      → Native executor with agent-selected modules (no AI)
Phase 4: Triage    → Agent reviews findings → TriageResult
Phase 5: Rescan    → Targeted re-scanning from triage recommendations (no AI)
Phase 6: Report    → Structured output from DB (no AI)
```

The triage→rescan loop (phases 4-5) repeats until the agent sets verdict to `"done"` or the max rescan rounds are reached.

### agent pipeline flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--target` | `-t` | string | — | Target URL (**required**) |
| `--agent` | — | string | from config | Agent backend to use |
| `--repo` | — | string | — | Path to source code repository for agent context |
| `--files` | — | []string | — | Specific source files to include (relative to --repo) |
| `--focus` | — | string | — | Focus area hint for the planning agent |
| `--timeout` | — | duration | `1h` | Maximum total pipeline duration |
| `--max-rescan-rounds` | — | int | `2` | Maximum triage→rescan iterations |
| `--skip-phase` | — | []string | — | Skip phases (discover, plan, scan, triage, rescan, report) |
| `--start-from` | — | string | — | Resume pipeline from a specific phase |
| `--profile` | — | string | — | Scanning profile for scan phases |
| `--dry-run` | — | bool | `false` | Render agent prompts without executing |

### Pipeline Output Schemas

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
  "notes": "Assessment summary"
}
```

The `verdict` field controls the rescan loop: `"rescan"` triggers another round, `"done"` stops the loop.

### Examples

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

# Skip triage (just discover + plan + scan)
vigolium agent pipeline -t https://example.com --skip-phase triage --skip-phase rescan

# With specific agent backend
vigolium agent pipeline -t https://example.com --agent gemini

# Specific source files for agent context
vigolium agent pipeline -t https://example.com --repo ./src \
  --files "routes.go,handlers.go"
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
- `output_schema`: Expected output format (`findings`, `http_records`, `attack_plan`, `triage_result`)
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

**Pipeline:**
- `pipeline-plan` — Phase 2 attack planning checkpoint
- `pipeline-triage` — Phase 4 finding triage checkpoint

**Autopilot:**
- `autopilot-system` — System prompt for autonomous mode

---

## Agent Configuration

Agents are configured in `vigolium-configs.yaml` under the `agent` section:

```yaml
agent:
  default_agent: claude
  templates_dir: ~/.vigolium/prompts/
  stream: true

  # Warm session pooling — reuses agent subprocesses
  warm_session:
    enable: false
    idle_timeout: 300
    max_sessions: 2

  agents:
    claude:
      command: npx
      args: ["@anthropic-ai/claude-code", "--print"]
      protocol: acp
      description: "Claude Code via ACP"
    opencode:
      command: opencode
      protocol: stdin
      description: "OpenCode CLI"
    gemini:
      command: gemini
      protocol: stdin
      description: "Gemini CLI"
```

### Agent Backends

| Backend | Command | Protocol | Description |
|---------|---------|----------|-------------|
| Claude | `claude` / `npx @anthropic-ai/claude-code` | acp / stdin | Claude Code CLI |
| OpenCode | `opencode` | stdin | OpenCode CLI |
| Gemini | `gemini` | stdin | Gemini CLI |
| Custom | any | stdin / acp | Any CLI tool that reads stdin or supports ACP |

### Protocols

- **stdin**: Agent receives prompt on stdin, returns output on stdout
- **acp** (Agent Communication Protocol): Bidirectional streaming with tool-use support (required for autopilot terminal execution)

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

Used by pipeline phase 4 (Triage). Contains:
- `confirmed` — validated findings with reasons
- `false_positives` — dismissed findings with reasons
- `follow_up_scans` — additional targets for rescan
- `verdict` — `"done"` or `"rescan"` to control the loop
