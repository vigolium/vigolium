# Agentic Scanning: How It Works

This document covers the shared concepts and infrastructure behind Vigolium's agentic scanning modes. For mode-specific details, see the dedicated docs linked at the bottom.

## What is Agentic Scanning

Agentic scanning uses AI agents to assist or drive the vulnerability scanning process. Unlike Vigolium's native scanning pipeline -- where deterministic Go modules execute fixed detection logic against HTTP traffic -- agentic scanning leverages LLMs to:

- **Analyze source code** for routes, authentication flows, and vulnerability sinks
- **Plan attacks** by selecting modules and generating targeted scan strategies
- **Generate custom payloads** as JavaScript extensions tailored to specific endpoints
- **Triage results** to separate true positives from false positives

Native scanning and agentic scanning are complementary. In swarm mode, for example, AI handles the strategic decisions (planning, extension generation, triage) while native Go code handles the heavy lifting (discovery, spidering, HTTP scanning). In autopilot mode, the AI agent drives the entire workflow by issuing CLI commands through a sandboxed terminal.

## Communication Protocols

Vigolium integrates with coding agents through protocol-specific backends. Each protocol offers different levels of tool access and capability:

| Protocol | Tool Access | Best For |
|----------|-------------|----------|
| **`sdk`** | Full CLI tools (Read, Grep, Glob, Bash, Edit, Write) | Default; highest output quality |
| **`acp`** | ReadTextFile only | Terminal/autopilot modes; warm sessions |
| **`codex-sdk`** | Full tools (JSON-RPC v2) | OpenAI Codex CLI |
| **`opencode-sdk`** | Full tools (REST API + SSE streaming) | OpenCode agent |
| **`pipe`** | None (text only) | Legacy fallback; any CLI tool |

**SDK (Claude Agent SDK)** is the recommended default. It launches the `claude` CLI as a subprocess and communicates via JSON-lines, giving the agent access to all standard Claude Code tools. This produces significantly higher output quality than ACP, which only exposes `ReadTextFile`.

**ACP (Agent Communication Protocol)** provides bidirectional structured communication with two interaction patterns:
- **Terminal execution** (autopilot): The agent receives a sandboxed terminal and autonomously runs `vigolium` commands.
- **Prompt/response** (query, swarm checkpoints): Vigolium sends a rendered prompt and receives structured JSON output.

**Codex-SDK** and **OpenCode-SDK** are native protocol integrations for their respective coding agent CLIs, providing full tool access without going through ACP.

**Pipe** is the simplest fallback — prompt piped to stdin, output read from stdout. Works with any CLI tool but provides no tool access.

## Agent Backends

Backends are configured in `~/.vigolium/vigolium-configs.yaml` under the `agent` section:

```yaml
agent:
  default_agent: claude
  backends:
    # Claude Code (SDK — recommended default)
    claude:
      command: claude
      protocol: sdk
      model: sonnet

    # Claude Code (ACP — for autopilot terminal mode)
    claude-acp:
      command: npx
      args: ["-y", "@zed-industries/claude-agent-acp@latest"]
      protocol: acp
      model: sonnet

    # OpenAI Codex (native JSON-RPC v2)
    codex:
      command: codex
      protocol: codex-sdk

    # OpenCode (native SDK)
    opencode:
      command: opencode
      protocol: opencode-sdk

    # Google Gemini (ACP)
    gemini:
      command: gemini
      args: ["--experimental-acp"]
      protocol: acp

    # Cursor (ACP)
    cursor:
      command: cursor
      args: ["acp"]
      protocol: acp
```

Each backend entry has:

| Field | Description |
|-------|-------------|
| `command` | CLI command to launch the agent |
| `args` | Arguments passed to the command |
| `protocol` | `sdk`, `acp`, `codex-sdk`, `opencode-sdk`, or `pipe` |
| `model` | Model override (e.g., `sonnet`, `opus`, `haiku`, or full model ID) |
| `description` | Human-readable description |
| `mcp_servers` | Per-backend MCP server attachments |

**Supported backends:**

| Backend | Command | Protocol | Notes |
|---------|---------|----------|-------|
| `claude` | `claude` | `sdk` | **Default.** Full tool access. Requires `claude` CLI in PATH |
| `claude-acp` | `npx @zed-industries/claude-agent-acp` | `acp` | Limited to ReadTextFile. Supports terminal mode |
| `claude-cli` | `claude -p` | `pipe` | Simple pipe mode fallback |
| `codex` | `codex` | `codex-sdk` | Native JSON-RPC v2 protocol |
| `codex-acp` | `codex app-server` | `acp` | Legacy ACP mode |
| `opencode` | `opencode` | `opencode-sdk` | Native REST + SSE streaming |
| `opencode-acp` | `opencode acp` | `acp` | ACP mode |
| `gemini` | `gemini --experimental-acp` | `acp` | Google Gemini CLI |
| `cursor` | `cursor acp` | `acp` | Cursor AI editor |

The `--agent` flag overrides the default backend per-invocation. The `--agent-acp-cmd` flag provides an ad-hoc ACP backend without config.

## Prompt Templates

Prompt templates are Markdown files with YAML frontmatter that define the instructions sent to AI agents. They are stored in:

- `~/.vigolium/prompts/` -- user-defined templates
- Embedded in the binary at `public/presets/prompts/` -- built-in templates

Each template declares an **output schema** in its frontmatter, which tells the agent what structured format to return:

| Output Schema | Description | Used By |
|---------------|-------------|---------|
| `findings` | Vulnerability findings (severity, description, evidence) | Query (code review) |
| `http_records` | HTTP request/response pairs (route discovery) | Query (endpoint discovery) |
| `attack_plan` | Module selections and extension code | Swarm (plan phase) |
| `triage_result` | True/false positive classifications | Swarm (triage phase) |
| `source_analysis` | Routes, auth config, scanner extensions | Swarm (source analysis phase) |

List available templates:

```bash
vigolium agent --list-templates
```

## Warm Session Pooling

Agent backends can reuse subprocesses across multiple AI calls within a single run, eliminating the startup latency of launching a new agent process for each call. All protocol types (SDK, ACP, Codex-SDK, OpenCode-SDK) support warm session pooling via dedicated pool implementations.

Configured in `vigolium-configs.yaml`:

```yaml
agent:
  warm_session:
    enable: false
    idle_timeout: 300   # seconds before an idle session is terminated
    max_sessions: 2     # maximum concurrent pooled sessions
```

Swarm mode forces warm session pooling on regardless of this setting, since it makes multiple AI calls (plan, triage) within a single run. Autopilot also enables it for its multi-agent specialist pipeline.

## Session Artifacts

Each agent run creates a session directory under `agent.sessions_dir` (default: `~/.vigolium/agent-sessions/`). The directory is named by run ID and contains:

| Artifact | Description |
|----------|-------------|
| `output.txt` | Raw agent output text |
| `extensions/` | Generated JavaScript scanner extensions (`.js` files) |
| `session-config.json` | Session configuration (auth flows, cookies, headers) |
| `plan.json` | Attack plan from the master agent (swarm mode) |

Session directories persist after the run completes, allowing you to inspect what the agent produced, re-use generated extensions, or debug issues.

## Source Code Context

The `--source` flag provides source code to agents across all modes. When provided, it enables:

- **Route extraction** -- the agent reads application code and discovers HTTP endpoints (Express routes, Spring controllers, Django URL patterns, etc.)
- **Auth flow discovery** -- the agent identifies login endpoints, session management, and token handling, producing a session configuration
- **Custom extension generation** -- the agent writes JavaScript scanner extensions targeting application-specific patterns
- **SAST integration** -- in swarm mode, ast-grep runs static analysis on the source and an AI sub-agent reviews the findings

The `--files` flag narrows the source context to specific files or directories (paths relative to `--source`), which is useful for large codebases where you want to focus the agent's attention.

```bash
# Full source context
vigolium agent --prompt-template security-code-review --source ./src

# Narrow to specific files
vigolium agent --prompt-template injection-sinks --source ./src --files db/query.go,api/handler.go
```

## Three Modes at a Glance

| Mode | Command | AI Calls | Best For | Details |
|------|---------|----------|----------|---------|
| **Query** | `vigolium agent` | 1 | Code review, endpoint discovery, SAST | [query.md](query.md) |
| **Autopilot** | `vigolium agent autopilot` | Many | Exploratory scanning, ad-hoc research | [autopilot.md](autopilot.md) |
| **Swarm** | `vigolium agent swarm` | 2-4+ | Targeted testing, full-scope scanning | [swarm.md](swarm.md) |

For a detailed side-by-side comparison including feature matrices and decision guides, see [agent-mode.md](agent-mode.md).
