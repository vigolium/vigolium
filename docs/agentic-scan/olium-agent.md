# Olium Agent

`olium` is the in-process AI agent runtime that powers every agentic feature in vigolium. It ships as both:

- **A user-facing command** — `vigolium agent olium` (aliases: `vigolium olium`, `vigolium ol`) — for interactive chat in a TUI or scripted one-shot prompts.
- **A library** — `pkg/olium/` — that the autopilot, swarm, query, audit-prep, and source-analysis paths all dispatch through. There are **no subprocess SDK backends**; every AI call in vigolium goes through this engine.

This document covers what the olium agent is, what it does, and how to use it. For a higher-level comparison against the other agent subcommands, see [`agent-mode.md`](agent-mode.md).

---

## What it is

A turn-based, tool-using LLM agent written in Go. Components:

| Layer | Lives in | Responsibility |
|---|---|---|
| **Engine** | `pkg/olium/engine/` | Multi-turn loop: provider stream → tool dispatch → history append → repeat |
| **Provider** | `pkg/olium/provider/` | LLM backend — five drivers (openai-codex-oauth, anthropic-api-key, anthropic-oauth, openai-api-key, anthropic-cli) |
| **Tools** | `pkg/olium/tool/` | The eight built-in primitives the model can call (bash, file ops, search, web fetch) |
| **Skills** | `pkg/olium/skill/` | SKILL.md workflow files (agentskills.io format) discovered from project, user, and embedded scopes |
| **TUI** | `pkg/olium/tui/` | Bubble Tea front-end (inline scrollback, slash commands, live tool cards) |
| **Headless** | `pkg/olium/headless.go` | Non-interactive single-prompt runner for scripts and smoke tests |
| **Autopilot** | `pkg/olium/autopilot/` | Long-running autonomous scan loop on top of the engine, with budgets, halt signal, and `report_finding` |
| **Vigolium tools** | `pkg/olium/vigtool/` | Scanner-aware extensions: `run_scan`, `run_extension`, `list_sessions`, `list_findings`, `auth_session_lookup`, etc. |
| **Auth** | `pkg/olium/auth/` | Codex OAuth credential loading and refresh (handles `~/.codex/auth.json`) |

Entry points:

- `pkg/olium/runner.go` — `RunTUI()`, `LoadSkillsFor()`, `ResolveProvider()`, `Options`
- `pkg/olium/headless.go` — `RunHeadless()`
- `pkg/olium/autopilot/autopilot.go` — `Run()` (used by `vigolium agent autopilot`)
- `pkg/agent/olium_adapter.go` — bridge used by query/swarm/source-analysis

---

## What it does

Each invocation runs one **multi-turn loop** (`pkg/olium/engine/engine.go:171`):

1. Append the user prompt to history.
2. Stream a single provider response (text deltas, thinking deltas, tool calls).
3. Append the assistant turn to history; emit `EventTurnDone` with token usage.
4. If there are no tool calls → emit `EventRunDone` and exit.
5. Otherwise dispatch the tool calls. If **all** calls are read-only the engine fans them out in parallel (cap = 8); otherwise it runs them strictly serially so writes can't race reads. Tool results are appended to history in the model's original order regardless.
6. Loop back to step 2 — capped by `MaxTurns` (default **32** for chat / headless, **200** for autopilot).

Surrounding behavior:

- **Tool result truncation / spill** — results larger than `MaxToolResultBytes` (default 16 KiB) get head+tail truncation with an elision marker. If `SpillDir` is set (autopilot does this), the full payload spills to `<SpillDir>/tool-results/` and the model gets a head excerpt plus an on-disk path it can `read_file`.
- **Per-tool timeout** — each tool invocation gets its own deadline (default 5 minutes). A runaway `bash curl` can't hang the whole session.
- **Prompt caching** — opt-in via `EnablePromptCache`. Autopilot turns it on; the Anthropic provider then writes `cache_control: ephemeral` markers on the system prompt and tool list, cutting repeated-prefix tokens by ~90 % across long runs. Providers without caching ignore the flag.
- **Skills** — when a registry is loaded the engine injects an `<available_skills>` block into the system prompt at construction (`engine.go:97`), and registers a `load_skill` tool the model can call to fetch a skill body on demand.

---

## Modes

### Interactive TUI (default)

```bash
vigolium olium                     # chat
vigolium ol                        # alias
vigolium agent olium               # full path
vigolium ol "audit this repo"      # auto-submitted first prompt
echo "summarise" | vigolium ol     # stdin auto-detected when piped
```

Bubble Tea inline mode (no alt-screen — output appends to scrollback as it streams). Live partial line, fenced code-block highlighting via chroma, and a one-line "tool exec" card while a tool runs. Slash chooser opens on `/`:

- `/clear` — clear conversation history.
- `/skill:<name> [args]` — inline expansion of a loaded skill (`pkg/olium/skill/systemprompt.go:66`); the body is pasted into the prompt so the model doesn't have to spend a tool call to `load_skill`.

The model id, provider, and reasoning effort are shown in the banner header.

### Headless (one-shot)

Passing `-p` / `--prompt` runs a single prompt non-interactively and streams to stdout — the TUI is skipped automatically.

```bash
vigolium ol -p "list every route in this repo"
```

Prints assistant text to **stdout**; thinking deltas, tool start/end cards, and per-turn `[turn done in= out= cached=]` summaries go to **stderr**. Exits non-zero on engine error.

### Library use (autopilot, swarm, query)

`pkg/agent/olium_adapter.go` is the single dispatch path every other agent feature funnels through:

- `runOliumPrompt(ctx, cfg, prompt, streamWriter, sourcePath)` — fresh engine per call.
- `runOliumOnEngine(ctx, cfg, eng, prompt, streamWriter)` — reuses an engine so the conversation prefix stays warm (used by source-analysis to fork an explore phase into 3 parallel format calls).
- `acquireProviderSlot(ctx, cfg)` — global semaphore (size = `agent.olium.max_concurrent`, default 4) that bounds in-flight provider calls process-wide so swarm phase fan-out can't trigger 429s on tier-1 plans.
- `EffectiveCallTimeout()` — default 10 min per provider call; 0 → default, negative → no timeout.

---

## Providers

Five drivers in `pkg/olium/provider/`. The provider name spells out the auth mechanism so it's obvious which credential field applies:

| Provider | Auth | Default model | Source of credential |
|---|---|---|---|
| `openai-codex-oauth` *(default)* | OAuth credential file | `gpt-5.5` | `--oauth-cred` → `agent.olium.oauth_cred_path` → `~/.codex/auth.json` (produced by `codex login`) |
| `anthropic-api-key` | `x-api-key` header | `claude-opus-4-7` | `--llm-api-key` → `agent.olium.llm_api_key` → `$ANTHROPIC_API_KEY` |
| `anthropic-oauth` | Bearer token (Claude Code OAuth) | `claude-opus-4-7` | `--oauth-token` → `agent.olium.oauth_token` → `$ANTHROPIC_API_KEY` (produced by `claude setup-token`) |
| `openai-api-key` | `x-api-key` header | `gpt-5.5` | `--llm-api-key` → `agent.olium.llm_api_key` → `$OPENAI_API_KEY` |
| `anthropic-cli` | (none — subprocess) | `claude-opus-4-7` | `--claude-bin` (default `claude` on `$PATH`) |

Selection logic lives in `pkg/olium/runner.go:resolveProvider()` and `pkg/olium/select.go`. With no `--provider` flag and no YAML override, vigolium auto-detects to **`openai-codex-oauth`** (`select.go:78`). The `anthropic-oauth` provider also prepends a Claude Code preamble to the system prompt and adds the `oauth-2025-04-20` beta header so it's accepted on the same endpoint as `anthropic-api-key`.

Codex auth refreshes itself: `pkg/olium/auth/codex.go` parses the JWT, checks expiry with a 60 s skew, and posts to `/oauth/token` with the stored refresh token, rewriting `~/.codex/auth.json` (`0o600`).

> **Note:** the REST API does **not** mirror these per-invocation flags. The server resolves the provider once from `agent.olium.*` in `vigolium-configs.yaml` and reuses it across requests so warm caches stay stable. To switch providers server-side, edit the YAML and reload.

---

## Tools

Built-in tool registry (`pkg/olium/tool/builtin.go:6` — eight tools, registered in this order):

| Name | Read-only? | What it does |
|---|---|---|
| `bash` | no | `bash -lc <cmd>` with hard-rejects for catastrophic patterns (`rm -rf /`, `dd` to block devices, fork bombs, `mkfs` against real devices). Default timeout = engine `ToolTimeout` (5 min). |
| `read_file` | yes | Read file with line-number prefix. Params: `path`, `offset`, `limit` (default 2000). |
| `write_file` | no | Create or overwrite a file. |
| `edit_file` | no | Find-and-replace edit on a file. |
| `ls` | yes | List a directory. |
| `grep` | yes | Regex search — uses ripgrep when available, else native Go regex. Params: `pattern`, `path`, `glob`, `max_matches` (200), `ignore_case`. |
| `glob` | yes | Glob pattern → paths. |
| `web_fetch` | yes | Fetch a URL. Two modes: `http` (default, fast) and `browser` (delegates to `agent-browser` for SPA / JS-heavy pages). Params: `url`, `method`, `headers`, `body`, `max_bytes`, `mode`, `wait_selector`, `wait_ms`. |

The `IsReadOnly()` flag is what the engine uses to decide whether to fan out a turn's tool calls in parallel. `bash` runs **without an approval prompt** (yolo mode) — only the catastrophic-pattern guard prevents disasters. The `ApprovalFn` parameter on `RegisterBuiltins` is wired but unused today; it's there for future plugin-installed tools.

### Autopilot adds more

When the engine runs under `vigolium agent autopilot`, the registry also gets:

- `halt_scan` — model-driven exit. Sets a halt signal; the run loop exits after the current turn.
- `report_finding` — persists a finding to the database (title, severity, description, remediation, CWE, evidence, confidence, status). Soft-warns at 50 calls, hard-caps at 200.
- `load_skill` — fetch a skill body by name (registered whenever the skill registry is non-empty).
- **Vigtool** — `run_scan`, `run_extension`, `list_sessions`, `get_session`, `list_findings`, `list_auth_sessions`, `auth_session_lookup` (registered when `Repo` is non-nil).

---

## Skills

Skills are Markdown workflow files with YAML frontmatter, following the [agentskills.io](https://agentskills.io) convention so files written for Claude Code or pi work in olium verbatim. Format:

```markdown
---
name: triage-finding
description: Walk a candidate finding from suspicious response → root cause → PoC.
license: optional
allowed-tools: optional list
---

# Body
Instructional prose the model reads after calling load_skill.
```

`name` must match `[a-z0-9-]+` (≤64 chars); `description` ≤1024 chars.

### Discovery

`Load()` (`pkg/olium/skill/registry.go:77`) walks four scopes — first-found-by-name wins:

1. **Project** — `.agents/skills/` and `.claude/skills/` in the working directory and every ancestor, closest first.
2. **User** — `~/.vigolium/skills/` (only when `IncludeUserSkills=true`).
3. **Embedded** — shipped in the binary under `public/presets/skills/` via `go:embed`.

Two on-disk layouts are accepted: `<root>/<name>/SKILL.md` (directory skill, the agentskills.io standard) or `<root>/<name>.md` (single-file shorthand; frontmatter `name` must match the filename stem).

Generic chat (`vigolium agent olium`, headless) loads scopes 1 + 3 only. Autopilot and swarm load all three so security-specific workflows in `~/.vigolium/skills/` don't pollute casual chat (`pkg/olium/runner.go:25`).

### Use

The engine writes an `<available_skills>` block into the system prompt listing every skill's name + description + location (`skill/systemprompt.go:14`). The model fetches bodies on demand via the `load_skill` tool — progressive disclosure, so unused skills don't burn tokens.

In the TUI, type `/skill:<name> [args]` to inline-expand a skill body into your prompt directly, no tool call needed.

---

## CLI flags

```text
--provider          openai-codex-oauth | anthropic-api-key | anthropic-oauth | openai-api-key | anthropic-cli
--model             provider-specific (empty = provider default)
--oauth-cred        OAuth credential file (openai-codex-oauth; default ~/.codex/auth.json)
--oauth-token       Claude Code OAuth bearer token (anthropic-oauth)
--llm-api-key       API key for anthropic-api-key / openai-api-key
--claude-bin        Path to the `claude` binary (anthropic-cli)
--system            Override the built-in system prompt
--headless          One-shot non-interactive — print to stdout, exit
-p, --prompt        Initial prompt (alternative to a positional arg)
--stdin             Force reading the prompt from stdin
```

Precedence for the initial prompt: positional args → `-p/--prompt` → stdin (auto-detected when piped, or forced with `--stdin`). Values flow CLI → YAML → env: every CLI flag falls back to its `agent.olium.*` YAML field, which in turn falls back to the documented default or env var. See `pkg/cli/agent_olium.go`.

---

## Configuration (`vigolium-configs.yaml`)

The full `agent.olium` block (defined in `internal/config/agent.go:38`):

```yaml
agent:
  olium:
    provider: openai-codex-oauth          # openai-codex-oauth | anthropic-api-key | anthropic-oauth | openai-api-key | anthropic-cli
    model: gpt-5.5                 # empty = provider default
    oauth_cred_path: ~/.codex/auth.json
    oauth_token: ""                # anthropic-oauth; supports ${ENV_VAR}; falls back to $ANTHROPIC_API_KEY
    llm_api_key: ""                # supports ${ENV_VAR}; falls back to $ANTHROPIC_API_KEY / $OPENAI_API_KEY
    reasoning_effort: medium       # minimal|low|medium|high|xhigh (codex)
    system_prompt: ""              # empty = built-in olium prompt
    max_tokens: 1000000
    temperature: 0.0
    max_turns: 32
    cache_size: 1024               # LRU; 0 disables
    max_concurrent: 4              # global cap on simultaneous provider calls; 0 = unbounded
    call_timeout_sec: 600          # per-call deadline; negative = no timeout (parent ctx only)
```

`DefaultOliumConfig()` (agent.go:291) ships these exact defaults so `vigolium config ls olium` shows every knob without requiring user yaml.

Adjacent config blocks worth knowing:

- `agent.sessions_dir` — where per-run session directories go. Default `~/.vigolium/agent-sessions/`.
- `agent.browser` — toggles `agent-browser` integration (the binary `web_fetch` shells out to in `mode: browser`).
- `agent.audit` — controls the optional vigolium-audit prep step that autopilot/swarm can stack ahead of the olium loop.

---

## Sessions and on-disk state

Every agent run gets a session directory under `agent.sessions_dir` (default `~/.vigolium/agent-sessions/<run-uuid>/`). Bare `vigolium agent olium` chat doesn't write a session — it's only autopilot/swarm/query that materialise one.

Inside a session dir you may find:

- `runtime.log` — per-turn event log (text deltas, tool start/end, turn-done summaries).
- `tool-results/<tool>-<call-id>.txt` — spilled oversized tool outputs (when the engine's `SpillDir` is set).
- `session-config.json` — run metadata (project / scan UUIDs, options).
- `swarm-plan.json`, `master-output.md`, `audit-stream.jsonl`, `checkpoint.json` — produced by the higher-level modes that wrap olium (swarm, audit, autopilot).

Browse past runs with `vigolium agent session list` / `--full` / `--tail`.

---

## Stream events

The engine emits a unified `Event` channel (`pkg/olium/engine/event.go`) regardless of provider:

| Event | Carries |
|---|---|
| `EventTextDelta` | `Delta` — assistant text increment |
| `EventThinkingDelta` | `Delta` — reasoning content (Anthropic thinking, codex reasoning) |
| `EventToolCallStart` | `ToolName`, `ToolArgs` — the model decided to call a tool |
| `EventToolExecStart` / `EventToolExecProgress` / `EventToolExecEnd` | tool invocation lifecycle, `ToolResult`, `ToolIsErr` |
| `EventTurnDone` | `StopReason`, `Usage` (input / output / cache-read / cache-write tokens) |
| `EventRunDone` | terminal usage |
| `EventError` | `Err` — provider failure, ctx cancellation, max-turns exceeded |

Token counts on `EventTurnDone` are accumulated by every higher-level caller (autopilot for budget enforcement, the adapter for `agenttypes.TokenUsage`, the swarm for cost reporting).

---

## When to use what

| You want to... | Use |
|---|---|
| Chat / debug / explore interactively | `vigolium ol` |
| Run one prompt from a script and parse stdout | `vigolium ol -p "..."` |
| Hand the agent the wheel for an autonomous pentest | `vigolium agent autopilot` (uses olium under the hood with budgets + report_finding) |
| AI-direct the native scanner (plan → modules → triage) | `vigolium agent swarm` |
| Single-shot template-driven prompt with structured output | `vigolium agent query` |

Olium itself is the **general-purpose** chat / dev surface and the engine every other mode reuses — it is not a security scan on its own.

---

## See also

- [`agent-mode.md`](agent-mode.md) — the full agent subcommand map.
- [`autopilot.md`](autopilot.md) — autonomous scan mode built on the olium engine.
- [`swarm.md`](swarm.md) — AI-guided multi-phase scan that drives the native scanner.
- [`architecture/agentic-scan.md`](../architecture/agentic-scan.md) — provider list and the high-level dispatch story.
