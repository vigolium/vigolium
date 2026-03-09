# Agent Autopilot

Autopilot gives an AI agent **full interactive control** of the vigolium scanner. The agent autonomously decides what to scan, interprets results, and iterates — all within a security sandbox.

## CLI Usage

```bash
vigolium agent autopilot -t https://target.com
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-t, --target` | (required) | Target URL |
| `--agent` | from config | Agent backend to use |
| `--repo` | — | Path to source code repository |
| `--files` | — | Specific files to include |
| `--focus` | — | Focus area hint (e.g., "API injection") |
| `--system-prompt` | — | Custom system prompt file |
| `--timeout` | 30m | Overall timeout |
| `--max-commands` | 100 | Maximum CLI commands the agent can execute |
| `--dry-run` | false | Render system prompt without launching |

## Step-by-Step Flow

### 1. CLI Initialization (`pkg/cli/agent_autopilot.go`)

- Builds `agent.Options{Autopilot: true}` and calls `engine.Run()`

### 2. Prompt Rendering (`pkg/agent/engine.go`)

- Loads the `autopilot-system.md` template from `public/presets/prompts/autopilot/`
- Enriches context from the database (discovered endpoints, findings, module list, scan stats)
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

The agent receives a workflow guide in the system prompt (7 steps):

1. **Discover** — Run `vigolium scan --only discovery -t <target>`
2. **Enumerate** — Check results with `vigolium traffic --json`
3. **Prioritize** — Identify high-value targets (APIs, parameterized endpoints)
4. **Scan** — Run `vigolium scan-url` with targeted `--module-tag` (xss, sqli, ssrf, etc.)
5. **Review** — Check findings with `vigolium finding --json`
6. **Iterate** — Based on results, discover more or scan deeper
7. **Report** — Summarize findings

Each time the agent wants to run a command, this happens:

```
Agent → ACP CreateTerminal("vigolium scan-url ...")
  → acpClient.CreateTerminal()
    → terminalManager.validateCommand()  // allowlist + injection check
    → terminalManager.createSession()    // exec.CommandContext, background start
  ← returns terminal ID

Agent → ACP WaitForTerminalExit(id)     // blocks until done
Agent → ACP TerminalOutput(id)          // reads output
Agent → ACP ReleaseTerminal(id)         // cleanup
```

### 6. Cleanup

- When the agent finishes (or timeout hits), `terminalManager.killAll()` kills all orphaned sessions
- The agent subprocess is also terminated

## Session Pooling (`pkg/agent/acp_pool.go`)

For non-autopilot modes, warm ACP sessions are pooled to avoid subprocess startup overhead:

- Maintains map of `agentName → acpSession`
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
  "repo": "/path/to/source",
  "files": ["src/auth.go"],
  "focus": "API injection",
  "timeout": "30m",
  "max_commands": 100,
  "stream": true,
  "dry_run": false
}
```

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
