# Autopilot Mode

`vigolium agent autopilot` is the **single-loop agentic scan**: one long-running
LLM session decides what to investigate, drives tools (bash, file I/O, web
fetch, vigolium CLI commands), reports findings to the database as it confirms
them, and halts on its own when it has nothing productive left to do.

It is the simplest of the agentic-scan modes — there is no master/worker
pipeline, no plan/triage phase split, just one engine running until it calls
`halt_scan`.

---

## Mental model

Think of it as a security analyst sitting at a terminal:

- The analyst is given a target URL, optionally a source tree, and a focus
  hint.
- They have shell access, file-read access, web access, and the vigolium CLI.
- They poke around, follow leads, write findings to a notebook as they confirm
  each bug, and stop when there is nothing more worth digging into.

The autopilot is exactly that, except the analyst is an LLM and the notebook is
the vigolium `findings` table.

---

## Lifecycle (high-level)

```
                  ┌──────────────────────────────────────────────┐
 vigolium agent ─►│ 1. CLI flag parsing                          │
 autopilot …      │    intensity preset → max-cmds, timeout, …   │
                  │    --input → curl/HTTP/Burp/url normalize    │
                  │    --source → resolve git URL/diff/local     │
                  │    --provider/model → olium.ResolveProvider  │
                  └──────────────────────────────────────────────┘
                                       │
                                       ▼
                  ┌──────────────────────────────────────────────┐
                  │ 2. Session bootstrap                         │
                  │    EnsureSessionDir(~/.vigolium/agent-…/UUID)│
                  │    WriteRunPID, CleanupOrphanedProcesses     │
                  │    create AgenticScan row (status=running)   │
                  │    tee stdout → {session}/runtime.log        │
                  └──────────────────────────────────────────────┘
                                       │
                                       ▼
                  ┌──────────────────────────────────────────────┐
                  │ 3. autopilot.Run (pkg/olium/autopilot)       │
                  │    build system prompt + initial user prompt │
                  │    register tools: builtins + halt_scan +    │
                  │      report_finding + load_skill             │
                  │    engine.New + engine.Run(ctx, initial)     │
                  └──────────────────────────────────────────────┘
                                       │
                       ┌───────────────┴───────────────┐
                       ▼                               ▼
              ┌────────────────┐              ┌─────────────────┐
              │ provider       │  multi-turn  │ tool registry   │
              │ (codex /       │◄────────────►│ bash, read,     │
              │  anthropic /   │   tool calls │ write, edit,    │
              │  openai / …)   │              │ ls, grep, glob, │
              └────────────────┘              │ web_fetch,      │
                                              │ load_skill,     │
                                              │ halt_scan,      │
                                              │ report_finding  │
                                              └─────────────────┘
                                       │
                                       ▼
                  ┌──────────────────────────────────────────────┐
                  │ 4. Halt → finalize                           │
                  │    halt_scan called OR ctx done OR max turns │
                  │    UPDATE AgenticScan: status, duration,     │
                  │    finding_count, error_message              │
                  │    print summary, remove run.pid             │
                  └──────────────────────────────────────────────┘
```

---

## Data flow

```
┌──────────────────────────────────────────────────────────────┐
│ user input                                                   │
│   --target / --input (curl/raw/Burp/base64) / stdin pipe     │
│   --source (local, git URL, diff, last-N commits)            │
│   --focus, --instruction, --intensity                        │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼ resolveInputAndTarget,
                                ResolveSourceAndDiff
┌──────────────────────────────────────────────────────────────┐
│ runAutopilotOlium                                            │
│   resolves olium provider+model                              │
│   creates session dir + AgenticScan parent row               │
│   constructs autopilot.Options{Target, SourcePath, Focus,    │
│     Instruction, Repo, ProjectUUID, ScanUUID, MaxTurns,      │
│     Out, ExtraSystemPrompt}                                  │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│ autopilot.Run                                                │
│   • LoadSkillsFor(includeUser=true) → ~/.vigolium/skills/    │
│   • tool registry := builtins + halt_scan + report_finding   │
│     (+ load_skill if any skills loaded)                      │
│   • system prompt := persona file + skills XML + extras      │
│   • initial prompt := target/source/scope/focus + instruct   │
│   • engine.New({Provider, Tools, Skills, MaxTurns,           │
│       EnablePromptCache: true, …})                           │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│ engine.run loop  (pkg/olium/engine)                          │
│                                                              │
│   for turn < MaxTurns:                                       │
│     ┌─ provider.Stream(System, Tools, History, CacheControl)─┐│
│     │  emits text/thinking deltas + tool-call frames         ││
│     └────────────────────────────────────────────────────────┘│
│     append assistant message (text + tool_calls) to history  │
│     emit EventTurnDone (with usage tokens)                   │
│                                                              │
│     if no tool calls:  emit EventRunDone, return             │
│                                                              │
│     for each tool call:                                      │
│       • read-only batch (read_file/ls/grep/glob/web_fetch):  │
│         dispatched in parallel (max fan-out 8)               │
│       • anything else (bash, write_file, edit_file, …):      │
│         dispatched serially                                  │
│       per-tool deadline (default 5m) layered on parent ctx   │
│       results truncated to 16 KiB head+tail before history   │
│       append RoleTool message to history                     │
│       emit EventToolExecStart / End                          │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│ side effects                                                 │
│                                                              │
│   report_finding ──► repo.SaveFindingDirect (deduped by hash)│
│                      counter++ ; soft-warn @50, hard cap @200│
│                                                              │
│   halt_scan      ──► HaltSignal.Set(reason)                  │
│                      engine sees no further tool calls and   │
│                      exits naturally                         │
│                                                              │
│   stream events  ──► stdout (tee'd to runtime.log) for text, │
│                      stderr for one-line tool activity       │
└──────────────────────────────────────────────────────────────┘
```

---

## What the agent actually has access to

The autopilot is **not** restricted to the vigolium CLI. The engine ships a
generic agentic toolset; security-specific behavior comes from the system
prompt and skills, not from the tool surface itself.

| Tool             | Source                          | Notes                                                                 |
| ---------------- | ------------------------------- | --------------------------------------------------------------------- |
| `bash`           | `pkg/olium/tool/bash.go`        | Unsandboxed shell. Catastrophic patterns (e.g. `rm -rf /`) hard-rejected. |
| `read_file`      | `pkg/olium/tool/files.go`       | Read-only. Parallelizable.                                            |
| `write_file`     | `pkg/olium/tool/files.go`       | Side-effect; serial only.                                             |
| `edit_file`      | `pkg/olium/tool/files.go`       | Side-effect; serial only.                                             |
| `ls`             | `pkg/olium/tool/files.go`       | Parallelizable.                                                       |
| `grep`           | `pkg/olium/tool/search.go`      | Parallelizable.                                                       |
| `glob`           | `pkg/olium/tool/search.go`      | Parallelizable.                                                       |
| `web_fetch`      | `pkg/olium/tool/web.go`         | Parallelizable.                                                       |
| `load_skill`     | `pkg/olium/skill/tool.go`       | Pulls a skill body by name (skills are indexed in the system prompt). |
| `halt_scan`      | `pkg/olium/autopilot/halt.go`   | Autopilot-only. Sets `HaltSignal`, engine exits naturally next turn.  |
| `report_finding` | `pkg/olium/autopilot/report_…`  | Autopilot-only. Writes a `Finding` row scoped to the AgenticScan UUID. |

The model decides when to invoke `vigolium scan-url`, `vigolium finding`, etc.
— those are **shell commands**, not first-class tools. The agent runs them via
`bash` if it judges them useful.

---

## Provider selection

`olium.ResolveProvider` picks the backend in this order:

1. CLI override (`--provider`)
2. Config file (`agent.olium.provider` in `vigolium-configs.yaml`)
3. Auto-detect → `openai-codex-oauth`

Supported provider IDs and the credential they consume:

| Provider           | Default model       | Credential                                                |
| ------------------ | ------------------- | --------------------------------------------------------- |
| `openai-codex-oauth`      | `gpt-5.5`           | OAuth cred file (`--oauth-cred` / `agent.olium.oauth_cred_path`) |
| `anthropic-api-key`| `claude-opus-4-7`   | `--llm-api-key` / `$ANTHROPIC_API_KEY`                    |
| `anthropic-oauth`     | `claude-opus-4-7`   | Bearer token from `claude setup-token` (`--oauth-token` / `$ANTHROPIC_API_KEY`) |
| `openai-api-key`   | `gpt-5.5`           | `--llm-api-key` / `$OPENAI_API_KEY`                       |
| `anthropic-cli`  | `claude-opus-4-7`   | The `claude` binary on `$PATH`                            |

`EnablePromptCache: true` is set on the engine — providers that support it
(Anthropic, Claude OAuth) cache the system prompt + tool list across turns,
which is most of the prefix on a long autopilot run.

---

## Intensity presets

`--intensity` bundles several settings; explicit flags always override.

| Preset     | `MaxCommands` | `Timeout` | `AuditMode` | `Browser` |
| ---------- | ------------- | --------- | ------------ | --------- |
| `quick`    | 30            | 1h        | `lite`       | off       |
| `balanced` (default) | 100  | 6h        | `balanced`   | off       |
| `deep`     | 300           | 12h       | `deep`       | on        |

`MaxCommands` becomes the engine's `MaxTurns` cap (one LLM→tool cycle per
turn). When the cap is hit the run ends with an error event — the model didn't
get to halt cleanly.

---

## Halt conditions

The autopilot exits in one of four ways:

1. **Natural halt** — model calls `halt_scan`. The current turn is allowed to
   finish; the engine then sees no further tool calls on the next turn and
   emits `EventRunDone`. `Result.Halted=true`, `HaltReason` populated.
2. **Quiet halt** — model finishes a turn with no tool calls and no
   `halt_scan`. Treated as a natural stop. `Result.Halted=false`,
   `HaltReason="(natural stop — engine max turns or no more tool calls)"`.
3. **Max turns** — turn count hits `MaxCommands`. Engine emits an `EventError`;
   autopilot returns a non-nil error.
4. **Context cancelled** — timeout or SIGINT/SIGTERM. Engine teardown cancels
   in-flight tools; autopilot returns the wrapped `context.DeadlineExceeded` /
   `context.Canceled` error.

A separate **finding rate-limit** lives inside `report_finding`:
- soft warning at 50 findings (still saved)
- hard cap at 200 (rejected with an `IsError` result that nudges the model
  toward `halt_scan`)

---

## Findings persistence

Every successful `report_finding` call writes a row via
`repo.SaveFindingDirect`. Key fields the autopilot stamps:

- `ProjectUUID`, `ScanUUID`, `AgenticScanUUID` — propagate the project/scan
  scope so `vigolium finding` and `vigolium agent sessions` can join back.
- `ModuleID = "olium-autopilot"`, `ModuleType = "ai-agent"`,
  `FindingSource = "autopilot"` — distinguishes agent-originated findings from
  scanner-module findings.
- `FindingHash` — SHA-256 over (title, severity, source_file, url,
  description-fingerprint), or over an explicit `dedup_key` if the model
  supplies one. The DB's `ON CONFLICT` handler squashes duplicates.

Because the autopilot writes findings as it confirms them, partial results
survive a crash or timeout — the parent `AgenticScan` row is just updated to
`status=failed` with the error message, but everything saved before that point
stays in the DB.

---

## Session artifacts

For each run, autopilot creates a UUID-named directory under the configured
`agent.sessions_dir` (default `~/.vigolium/agent-sessions/`):

```
~/.vigolium/agent-sessions/{run-uuid}/
  ├── run.pid       # pgid + start time; cleared on exit
  └── runtime.log   # tee of stdout (assistant text stream)
```

The run UUID matches the `AgenticScan.uuid` row, so `vigolium agent sessions`
and `vigolium log <uuid>` both work without extra plumbing. Stale dirs older
than 48h are swept on startup; orphan PID files (from SIGKILL'd runs) are
cleared via `agent.CleanupOrphanedProcesses`.

---

## Source-aware mode

When `--source` is set, three things change:

1. **Source resolution** — `agent.ResolveSourceAndDiff` accepts local paths,
   git URLs (cloned to a temp dir), `--diff PR-url|ref...ref|HEAD~N`, and
   `--last-commits N`. The agent gets a local path and (optionally) a list of
   changed files.
2. **Initial prompt mode hint** — the prompt switches between blackbox
   ("probe the live target"), whitebox ("navigate the source tree"), or a
   greybox blend ("read the code to find what's risky, then probe").
3. **Skill scope** — `LoadSkillsFor(includeUser=true)` adds `~/.vigolium/skills/`
   on top of the embedded set, so scan-specific skills like `audit-auth` and
   `triage-finding` become available via `load_skill`.

There is no separate code-audit pre-phase in the olium-backed autopilot — the
single agent loop handles both code reading and dynamic probing.

---

## Multi-app fan-out

When the positional prompt parses to **multiple** apps
(`vigolium agent autopilot "scan source at ~/src/A, ~/src/B"`), the package-
level autopilot flags are snapshotted and reapplied per app, then
`runAutopilotOlium` is invoked sequentially for each. Each app gets its own
session dir, AgenticScan row, and provider session.

A single-app prompt re-enters `runAgentAutopilot` directly with the parsed
flags — same code path as a flag-driven invocation.

---

## REST API

```
POST /api/agent/run/autopilot   # async kickoff, returns run UUID
GET  /api/agent/status/list     # list active/recent runs
GET  /api/agent/status/:id      # poll a single run
```

The HTTP request body mirrors the CLI flags. `EffectiveSourcePath()` accepts
either `source` or the legacy `repo_path` field. The handler resolves
provider/source the same way the CLI does, then enters `autopilot.Run` on a
goroutine; the run UUID is returned immediately.

---

## Key code references

| Concern                           | File                                                |
| --------------------------------- | --------------------------------------------------- |
| CLI command + flags               | `pkg/cli/agent_autopilot.go`                        |
| Olium-backed entry                | `pkg/cli/agent_autopilot_olium.go`                  |
| Run orchestration (Options/Run)   | `pkg/olium/autopilot/autopilot.go`                  |
| System / initial prompt builders  | `pkg/olium/autopilot/prompt.go`                     |
| `halt_scan` tool + signal         | `pkg/olium/autopilot/halt.go`                       |
| `report_finding` tool + dedup     | `pkg/olium/autopilot/report_finding.go`             |
| Engine multi-turn loop            | `pkg/olium/engine/engine.go`                        |
| Engine event types                | `pkg/olium/engine/event.go`                         |
| Built-in tool registry            | `pkg/olium/tool/builtin.go`                         |
| Provider resolution               | `pkg/olium/select.go`, `pkg/olium/runner.go`        |
| Skills loading                    | `pkg/olium/skill/`                                  |
| Intensity presets                 | `pkg/agent/agenttypes/constants.go`                 |
| System-prompt persona (override)  | `~/.vigolium/prompts/olium-system.md`               |
| System-prompt persona (embedded)  | `public/presets/prompts/autopilot/olium-system.md`  |

---

## TL;DR

Autopilot is a single LLM agent on a leash made of `MaxCommands` turns and
`Timeout` wall-clock. It gets shell, files, and the web; vigolium-specific
behavior is encoded entirely in the system prompt, two custom tools
(`halt_scan`, `report_finding`), and the optional skills under
`~/.vigolium/skills/`. Findings are written as it goes; the run ends when
the model halts itself, hits the turn cap, or gets cancelled.
