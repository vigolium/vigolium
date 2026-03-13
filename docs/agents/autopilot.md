# Agent Autopilot

Autopilot gives an AI agent **full interactive control** of the vigolium scanner. The agent autonomously decides what to scan, interprets results, and iterates — all within a security sandbox.

## CLI Usage

```bash
vigolium agent autopilot -t https://target.com
```

### Source-Aware Scanning

When `--source` is provided, the agent receives the application source code in its system prompt and follows a source-aware workflow — analyzing routes, auth flows, and vulnerability sinks before scanning:

```bash
# Local source directory
vigolium agent autopilot -t http://localhost:3000 --source ~/projects/my-app

# Only include specific files for faster context loading
vigolium agent autopilot -t http://localhost:3000 --source ~/projects/my-app \
  --files src/routes/auth.js,src/routes/api.js

# Combine with a focus hint to guide the agent's strategy
vigolium agent autopilot -t http://localhost:8080 --source ./backend \
  --focus "IDOR and broken access control in REST API"

# Git URL (auto-cloned)
vigolium agent autopilot -t https://staging.example.com \
  --source https://github.com/org/repo.git

# Preview the rendered system prompt without launching
vigolium agent autopilot -t http://localhost:3000 --source ./src --dry-run
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-t, --target` | (required) | Target URL |
| `--agent` | from config | Agent backend to use |
| `--source` | — | Path to application source code for source-aware scanning |
| `--files` | — | Specific files to include (relative to `--source`) |
| `--focus` | — | Focus area hint (e.g., "API injection") |
| `--system-prompt` | — | Custom system prompt file |
| `--timeout` | 30m | Overall timeout |
| `--max-commands` | 100 | Maximum CLI commands the agent can execute |
| `--instruction` | — | Custom instruction to guide the agent (appended to prompt) |
| `--instruction-file` | — | Path to a file containing custom instructions |
| `--dry-run` | false | Render system prompt without launching |

> **Note:** `--repo` is accepted as a deprecated alias for `--source`.

## Architecture Overview

```
                              vigolium agent autopilot -t <url>
                                          |
                                          v
                  +-----------------------------------------------+
                  |              CLI Initialization                |
                  |  - Parse flags (--target, --source, --focus)  |
                  |  - Resolve instruction (--instruction[-file]) |
                  |  - Build agent.Options{Autopilot: true}       |
                  +-----------------------------------------------+
                                          |
                                          v
                  +-----------------------------------------------+
                  |           Prompt Rendering (Engine)            |
                  |  - Load autopilot-system.md template           |
                  |  - Enrich context from DB (endpoints, modules) |
                  |  - Inject source code if --source provided     |
                  |  - Append focus area + custom instructions     |
                  |  - Render via Go text/template                 |
                  +-----------------------------------------------+
                                          |
                                          v
                  +-----------------------------------------------+
                  |         ACP Agent Subprocess Spawn             |
                  |  - Start AI backend (Claude/OpenCode/Gemini)   |
                  |  - Bidirectional stdin/stdout ACP connection    |
                  |  - Initialize with Terminal: true capability    |
                  |  - Send rendered system prompt via Prompt()     |
                  +-----------------------------------------------+
                                          |
                                          v
               +----------------------------------------------------+
               |              Agent Autonomous Loop                  |
               |                                                     |
               |   +---------------------------------------------+  |
               |   | Agent decides next action                    |  |
               |   +---------------------------------------------+  |
               |        |                                            |
               |        v                                            |
               |   +---------------------------------------------+  |
               |   | ACP CreateTerminal("vigolium scan-url ...") |  |
               |   +---------------------------------------------+  |
               |        |                                            |
               |        v                                            |
               |   +---------------------------------------------+  |
               |   |         Security Sandbox                     |  |
               |   |  - Validate: allowlist + injection check     |  |
               |   |  - Execute: exec.CommandContext (no shell)    |  |
               |   |  - Enforce: max-commands, 5min/cmd timeout   |  |
               |   |  - Truncate: 256KB max output per session    |  |
               |   +---------------------------------------------+  |
               |        |                                            |
               |        v                                            |
               |   +---------------------------------------------+  |
               |   | Agent reads output, decides next action      |  |
               |   | (loops until done or --max-commands reached) |  |
               |   +---------------------------------------------+  |
               |                                                     |
               +----------------------------------------------------+
                                          |
                                          v
                  +-----------------------------------------------+
                  |                  Cleanup                        |
                  |  - Kill all orphaned terminal sessions          |
                  |  - Terminate agent subprocess                   |
                  |  - Save output to session directory             |
                  +-----------------------------------------------+
```

### Data Flow: Agent Command Execution

```
Agent                  ACP Layer              Terminal Manager           OS Process
  |                        |                        |                        |
  |-- CreateTerminal() --->|                        |                        |
  |                        |-- validateCommand() -->|                        |
  |                        |                        |-- check allowlist      |
  |                        |                        |-- check injection      |
  |                        |                        |-- check call limit     |
  |                        |                        |                        |
  |                        |-- createSession() ---->|                        |
  |                        |                        |-- exec.CommandContext ->|
  |                        |<-- terminal ID --------|                        |
  |<-- terminal ID --------|                        |                        |
  |                        |                        |                        |
  |-- WaitForExit(id) ---->|                        |                        |
  |                        |-- waitForProcess() --->|                        |
  |                        |                        |<-- process exits ------|
  |<-- exit code ----------|                        |                        |
  |                        |                        |                        |
  |-- TerminalOutput(id) ->|                        |                        |
  |<-- stdout/stderr ------|                        |                        |
  |                        |                        |                        |
  |-- ReleaseTerminal(id)->|                        |                        |
  |                        |-- cleanup() ---------->|                        |
  |                        |                        |-- kill process group ->|
```

## Step-by-Step Flow

### 1. CLI Initialization (`pkg/cli/agent_autopilot.go`)

- Resolves `--instruction` / `--instruction-file` into a single instruction string
- Builds `agent.Options{Autopilot: true}` and calls `engine.Run()`

### 2. Prompt Rendering (`pkg/agent/engine.go`)

- Loads the `autopilot-system.md` template from `public/presets/prompts/autopilot/`
- Enriches context from the database (discovered endpoints, findings, module list, scan stats)
- If `--source` is provided, collects source code and injects it into the prompt along with a source-aware workflow guide
- Appends focus area (`## Focus Area`) if `--focus` is provided
- Appends custom instructions (`## Custom Instructions`) if `--instruction` is provided
- Renders the final system prompt via Go `text/template`
- If `--dry-run`, prints rendered prompt and exits

### 3. Agent Subprocess Spawning (`pkg/agent/acp_runner.go`)

- Spawns the configured AI agent backend (Claude, OpenCode, Gemini, etc.) as a child process
- Establishes **bidirectional ACP (Agent Communication Protocol)** connection via stdin/stdout pipes
- Calls `conn.Initialize()` with `ClientCapabilities.Terminal: true` — this tells the agent it can execute commands
- Creates an ACP session and sends the prompt via `conn.Prompt()`

### 4. The Security Sandbox (`pkg/agent/acp_terminal.go`)

The `terminalManager` enforces strict controls:

| Control | Detail |
|---------|--------|
| **Command allowlist** | Only `vigolium` binary allowed (`filepath.Base(parts[0]) == "vigolium"`) |
| **Blocked subcommands** | `db clean`, `db seed`, `db drop` are rejected |
| **Shell injection prevention** | Rejects any command containing `;\|&\`$(){}!><\n` metacharacters |
| **No shell execution** | Commands run via `exec.CommandContext(args[0], args[1:]...)` — never through a shell |
| **Call limit** | Atomic counter enforces `--max-commands` (default 100) |
| **Per-command timeout** | 5 minutes per command |
| **Output truncation** | 256KB max per session to prevent context overflow |
| **Process isolation** | Each command runs in its own process group (`Setpgid: true`); cleanup kills entire group via `SIGKILL` |

### 5. Agent Autonomous Loop

The agent receives a workflow guide in the system prompt. The standard workflow (7 steps):

1. **Discover** — Run `vigolium scan --only discovery -t <target>`
2. **Enumerate** — Check results with `vigolium traffic --json`
3. **Prioritize** — Identify high-value targets (APIs, parameterized endpoints)
4. **Scan** — Run `vigolium scan-url` with targeted `--module-tag` (xss, sqli, ssrf, etc.)
5. **Review** — Check findings with `vigolium finding --json`
6. **Iterate** — Based on results, discover more or scan deeper
7. **Report** — Summarize findings

#### Source-Aware Workflow

When `--source` is provided, the system prompt includes an expanded workflow that precedes the standard steps:

1. **Analyze Routes** — Identify all routes/endpoints from framework-specific patterns (Express `app.get()`, Flask `@app.route()`, Spring `@RequestMapping`, etc.)
2. **Identify Auth Flow** — Find login/auth endpoints, understand credential format and token handling
3. **Ingest Seed Requests** — For each discovered route, create seed requests with realistic parameters using `vigolium ingest`
4. **Identify Sinks** — Look for dangerous patterns: raw SQL queries, command execution, template rendering with user input, file operations, SSRF-prone HTTP calls
5. **Targeted Scanning** — Use specific module tags based on identified sinks (e.g., SQL concatenation -> `--module-tag sqli`)
6. **Deep Testing** — Craft specific payloads using `vigolium scan-url` with `--method`, `--body`, and `-H` flags matching the exact parameter format the code expects

### 6. Cleanup

- When the agent finishes (or timeout hits), `terminalManager.killAll()` kills all orphaned sessions
- The agent subprocess is also terminated

## Session Pooling (`pkg/agent/acp_pool.go`)

For non-autopilot modes, warm ACP sessions are pooled to avoid subprocess startup overhead:

- Maintains map of `agentName -> acpSession`
- Sessions are reused if still alive, same working directory, and not in use
- LRU eviction when capacity is exceeded
- Reaper goroutine kills idle sessions every 30 seconds

## Server API

**Endpoint:** `POST /api/agent/run/autopilot`

**Request body:**
```json
{
  "target": "https://target.com",
  "agent": "claude",
  "source": "/path/to/source",
  "files": ["src/auth.go"],
  "focus": "API injection",
  "instruction": "Prioritize file upload endpoints. Test for path traversal in filenames.",
  "timeout": "30m",
  "max_commands": 100,
  "stream": true,
  "dry_run": false
}
```

> **Backward compatibility:** `repo_path` is accepted as an alias for `source`.

**Response modes:**
- **Streaming (SSE):** Real-time events of type `data: {type, text, result, error}`
- **Async (202):** Returns `run_id` for status polling via `GET /api/agent/status/:id`

**Concurrency:** Global mutex allows only 1 agent run at a time (409 Conflict if busy).

## Key Files

| File | Purpose |
|------|---------|
| `pkg/cli/agent_autopilot.go` | CLI command definition |
| `pkg/agent/acp_terminal.go` | Security sandbox (terminal manager) |
| `pkg/agent/acp_runner.go` | ACP subprocess spawning |
| `pkg/agent/acp_client.go` | ACP client interface implementation |
| `pkg/agent/acp_pool.go` | Warm session pooling |
| `pkg/agent/engine.go` | Prompt building and agent execution |
| `pkg/server/handlers_agent.go` | REST API handlers |
| `public/presets/prompts/autopilot/autopilot-system.md` | System prompt template |
