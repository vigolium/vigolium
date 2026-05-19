# Agent Mode

Vigolium ships **8 agent subcommands** under `vigolium agent`. They split into four families:

- **Agentic scan modes** — autonomous or AI-guided vulnerability scanning: `autopilot`, `swarm`
- **Source audit modes** — multi-phase AI code audit: `archon` (Claude/Codex), `piolium` (Pi-native), and `audit` (unified driver that runs both back-to-back)
- **Single-shot / interactive** — `query`, `olium`
- **Utility** — `session`

The parent `vigolium agent` command itself only supports `--list-templates` and `--list-agents`. All execution requires a subcommand.

---

## When to use what

| You want to... | Use | Why |
|---|---|---|
| Run a one-off prompt against code or a target (no scanning loop) | `query` | Single-shot, template-driven, returns structured findings or HTTP records |
| Hand the agent the wheel for a full autonomous pentest | `autopilot` | One long LLM session with full Bash/Read/Write/Grep/Glob; agent picks strategy |
| Have the AI **drive the native scanner** on a specific target | `swarm` | Master/worker pipeline: AI plans → native modules execute → optional triage+rescan |
| Audit source code deeply (secrets, SAST triage, PoC) before or alongside a scan | `archon` | Multi-phase code audit (`lite`/`balanced`/`deep`); imports findings into the DB |
| Same multi-phase audit but driven through Pi (`pi install` model) | `piolium` | Pi-native piolium harness; same output schema as archon, tagged separately in DB |
| Run a unified audit (archon, fall back to piolium on failure) on one source under one AgenticScan | `audit` | Unified driver: `--driver=auto` (default) runs archon then piolium only if archon fails; `--driver=both` runs both unconditionally; per-driver child rows + post-pass findings dedup; `--driver=piolium\|archon` to force one |
| Chat with an LLM interactively in a TUI (debug, explore, ad-hoc) | `olium` | Real-time multi-turn chat; not a security scan — general-purpose agent |
| Review past agent runs | `session` | Lists prior runs, shows raw output and artifacts |

---

## Mode reference

### `query` — single-shot prompt
- **File:** `pkg/cli/agent.go`
- **Use for:** code review, endpoint discovery, secret detection, ad-hoc prompts.
- **Not for:** network scanning or multi-phase orchestration.
- **Key flags:** `--prompt-template`, `-p/--prompt`, `--stdin`, `--source`, `--files`, `--source-label`, `--output`, `--dry-run`.

### `autopilot` — autonomous agentic scan
- **File:** `pkg/cli/agent_autopilot.go`
- **Use for:** pentest-style engagements where you want the agent to be creative and decide what to do.
- **How it works:** one long-running LLM session with full CLI tool access until the agent calls `halt_scan` or hits limits.
- **Key flags:** `-t/--target`, `--input` (curl/raw HTTP/Burp XML/URL/stdin), `--plan-file`, `--source` (auto-runs archon), `--focus`, `--max-commands`, `--max-duration`, `--intensity {quick|balanced|deep}`, `--archon` (`lite|balanced|deep|off`), `--browser`, `--credentials`, `--diff`, `--last-commits`.

### `swarm` — AI-guided multi-phase scan
- **File:** `pkg/cli/agent_swarm.go`
- **Use for:** target-specific scanning when you want structure (planning → native scan → triage), source-aware route discovery, or verification loops.
- **How it works:** 10-phase pipeline — normalize → auth (opt) → source-analysis (opt) → code-audit (opt) → discover (opt) → plan (AI) → extension (opt) → native scan → triage (opt) → rescan (opt).
- **Key flags:** `-t/--target` (required with `--source`), `--input`, `--plan-file`, `--record-uuid`, `--source`, `--discover`, `--code-audit`, `--triage`, `--max-iterations`, `-m/--modules`, `--vuln-type`, `--focus`, `--archon {lite|balanced|deep|off}`, `--intensity`, `--only`/`--skip`/`--start-from`.

### Plan file (`--plan-file`)
Both `autopilot` and `swarm` accept `--plan-file <path>`: a single file that mixes free-text guidance and raw HTTP request(s) — exactly what you'd paste into a terminal. No frontmatter or schema.

- Prose **before the first HTTP request line** becomes the instruction.
- The request region (everything from the first request line to EOF) is split on lines that are exactly `---` into independent request blocks. Fenced ` ```http ` / ` ```request ` code blocks are also recognized.
- `autopilot` is single-seed: the first request is the live seed; any extra blocks are folded into the instruction as labelled context.
- `swarm` is multi-seed: every request block is fed as an independent seed input.
- A file with no request line is treated as instruction-only (then supply `--target`/`--source`).
- `--plan-file` owns both the instruction and the seed input, so it **cannot** be combined with `--input`, `--instruction`, or `--instruction-file` (autopilot also rejects `--record-uuid`).

```
Here are the order IDs 0254685 and 0254774 — focus on IDOR.

GET /order/details?orderId=0254809 HTTP/2
Host: ginandjuice.shop
Cookie: session=...
```
Run with: `vigolium agent autopilot --plan-file ginandjuice-plan.md` (or `swarm`).

### `archon` — AI security source audit (Claude/Codex)
- **File:** `pkg/cli/agent_archon.go`
- **Use for:** deep code audit standalone, or as the source-aware companion to `autopilot`/`swarm`.
- **Modes:** `lite` (3 phases), `balanced`/`scan` (6), `deep` (10), `revisit`, `confirm`, `merge`, `diff`, `longshot`, `refresh`, `reinvest`, `status`, `mock`. `--modes a,b,c` chains modes back-to-back via archon's native `--modes` (one subprocess; stops on the first non-complete mode; `--max-cost` is an aggregate cap; later modes auto-inherit the prior `--from-audit`). `--intensity deep` resolves to the chain `deep,confirm`; `quick`→`lite` and `balanced`→`balanced` stay single-mode.
- **Key flags:** `--mode`, `--modes a,b,c`, `--list-modes` (print archon's mode graph and exit), `--source <path|git-url>`, `--archon-provider <olium-provider>` (drives the agent **and** forwards that provider's BYOK auth: `anthropic-*` → claude, `openai-*` → codex), `--agent {claude|codex}` (pure agent selector — overrides the agent implied by `--archon-provider` while keeping its resolved auth; reject-on-invalid), `--no-stream`.
- **Detail:** [`docs/agentic-scan/archon-audit.md`](archon-audit.md).

### `piolium` — AI security source audit (Pi-native)
- **File:** `pkg/cli/agent_piolium.go`
- **Use for:** the same multi-phase audit as `archon` but running through the Pi runtime + the user-installed piolium extension. Useful when the host already has Pi configured for development work.
- **Modes:** `lite` (4), `balanced` (9), `deep` (17), `revisit` (9), `confirm` (7), `merge` (7), `diff` (1), `longshot` (3), `status`, `smoke`.
- **Key flags:** `--mode`, `--intensity {quick|balanced|deep}`, `--source <path|git-url>`, `--commit-depth`, `--no-stream`, `--upload-results`, plus `--plm-*` passthroughs for piolium's session flags.
- **Detail:** [`docs/agentic-scan/piolium-audit.md`](piolium-audit.md).

### `audit` — unified driver (archon + piolium)
- **File:** `pkg/cli/agent_audit.go`
- **Use for:** scoring a single source tree under one or both audit harnesses with one AgenticScan. Default `--driver=auto` runs archon first and only falls back to piolium if archon fails (a clean archon run finishes the audit and piolium is never started — so a missing piolium runtime stays silent). `--driver=both` runs archon then piolium unconditionally. Per-driver session subdirs (`{session}/archon/`, `{session}/piolium/`), per-driver child AgenticScan rows under one parent, and a post-pass project-wide findings dedup once the drivers exit.
- **Modes:** any mode valid for a participating driver is accepted. `--modes a,b,c` chains modes back-to-back, stopping on the first non-complete mode. archon runs the chain natively (one subprocess, one row, aggregate cost); piolium chains via sequential `pi` runs in the same source tree collapsed into one aggregated child row. For `--driver=auto|both`, modes a driver can't run are skipped on that driver's leg (e.g. `--modes deep,refresh,confirm` runs all three on archon, and `deep,confirm` on piolium since `refresh` is archon-only); a mode unknown to **both** drivers is a hard error. `--intensity deep` resolves to the chain `deep,confirm` (`quick`→`lite`, `balanced`→`balanced` stay single-mode).
- **Key flags:** `--driver {auto|both|archon|piolium}` (default `auto`), `--mode`, `--modes a,b,c`, `--list-modes` (print the mode graph and exit), `--intensity`, `--source`, `--commit-depth`, `--no-stream`, `--no-dedup`, `--upload-results`, `--archon-provider <olium-provider>` and `--agent {claude|codex}` (both archon-leg only — `--agent` overrides the provider-implied agent without changing auth and warns, rather than errors, on `--driver=piolium`), plus the `--pi-*` and `--plm-*` flags inherited from `agent piolium`.
- **BYOK auth:** `--api-key` / `--oauth-token` / `--oauth-cred-file` accept literal, `$ENV`, or `@path` and apply to whichever driver(s) run. Detail: [`docs/agentic-scan/audit-byok.md`](audit-byok.md).
- **REST equivalent:** `POST /api/agent/run/audit` with `driver: "auto"|"both"|"archon"|"piolium"` (default `"auto"`).

### `olium` — interactive TUI chat
- **Aliases:** top-level `vigolium olium` / `vigolium ol`
- **File:** `pkg/cli/agent_olium.go`
- **Use for:** interactive debugging, exploration, or one-shot headless prompts. Provider-agnostic.
- **Not for:** orchestrated scanning — there are no scan phases.
- **Key flags:** `--provider`, `--model`, `--llm-api-key`, `--oauth-cred`/`--oauth-token`, `--system`, `--headless`, `-p/--prompt`, `--stdin`.

### `session` — agent run history
- **Aliases:** `sessions`, `sess`
- **File:** `pkg/cli/agent_session.go`
- **Use for:** auditing prior runs, debugging failed scans.
- **Key flags:** `--mode {query|autopilot|pipeline|swarm}`, `-n/--limit`, `-o/--offset`, `--tail`, `--full`.

---

## Picking between `autopilot` and `swarm`

Both are agentic scan modes. The distinction:

- **`autopilot`** — the agent **is** the scanner. It opens a shell, reads files, runs tools, and decides everything. Best when the target is fuzzy or you want creative, exploratory testing.
- **`swarm`** — the agent **directs** the native scanner. It plans, picks modules, generates JS extensions, and the deterministic Go pipeline does the heavy traffic. Best when you want structured, repeatable results with optional verification loops.

If you have **source code** and a **target URL**, both work; `swarm --source --target ... --code-audit --triage` gives you the most structured output, while `autopilot --source ...` gives the agent more freedom.

---

## Cross-cutting

- **Session dir:** `~/.vigolium/agent-sessions/` (override via `agent.sessions_dir` in `vigolium-configs.yaml`).
- **Prompt templates:** `~/.vigolium/prompts/` or embedded under `public/presets/prompts/`.
- **Output schemas:** `findings`, `http_records`, `attack_plan`, `triage_result`, `source_analysis`.
- **Engine:** every agent run is dispatched through the in-process olium runtime (`pkg/olium/`). Provider selection lives at `agent.olium.provider` in `vigolium-configs.yaml` — see [`docs/architecture/agentic-scan.md`](../architecture/agentic-scan.md) for the provider list.
- **Source flag:** `--source` is the canonical source-code flag across all modes; the legacy `--repo`/`--repo-url` flags have been removed.

### REST API

The server exposes the same three modes plus a status/artifact surface so a controller can launch and tail runs without the CLI.

| Method | Path                                            | Purpose                                                                  |
| ------ | ----------------------------------------------- | ------------------------------------------------------------------------ |
| POST   | `/api/agent/run/query`                          | One-shot prompt execution.                                               |
| POST   | `/api/agent/run/autopilot`                      | Launch an autopilot scan.                                                |
| POST   | `/api/agent/run/swarm`                          | Launch a swarm scan.                                                     |
| GET    | `/api/agent/status/list`                        | List active and historical runs (DB + in-memory merge).                  |
| GET    | `/api/agent/status/:id`                         | Status of a single run.                                                  |
| GET    | `/api/agent/sessions`                           | Paginated session history (richer than `/status/list`).                  |
| GET    | `/api/agent/sessions/:id`                       | Full session detail incl. raw output, plan, child runs.                  |
| GET    | `/api/agent/sessions/:id/logs`                  | Read or tail `runtime.log` (SSE when `Accept: text/event-stream`).       |
| GET    | `/api/agent/sessions/:id/artifacts`             | List files inside the session_dir (recursive, capped at 500 entries).    |
| GET    | `/api/agent/sessions/:id/artifacts/{name}`      | Read one file (`output.md`, `plan.json`, etc.). Wildcard supports nesting (`archon-audit/state.json`). Optional `?max_bytes=N` cap (default 10 MiB, hard cap 100 MiB). |

Run endpoints return `202 Accepted` with `{agentic_scan_uuid, status: "running"}` and execute in the background. The expected workflow is:

1. POST one of the `run/*` endpoints, capture `agentic_scan_uuid`.
2. Poll `GET /api/agent/status/:id` until `status` leaves `running`.
3. Fetch the session artifacts via `/api/agent/sessions/:id/logs`, `/artifacts`, or `/artifacts/{name}` for the raw outputs (`output.md`, `plan.json`, `audit-stream.jsonl`, generated extensions, etc.).

`stream: true` on the run endpoints opts into Server-Sent Events instead of the async response — most consumers should stick with the async flow and tail logs on demand.

#### Provider overrides are CLI / server-config only

The CLI exposes per-invocation provider flags (`--provider`, `--model`, `--oauth-cred`, `--oauth-token`, `--llm-api-key`, `--system`). These are **not** mirrored on the REST request schemas. The server resolves the provider once from `agent.olium.*` in `vigolium-configs.yaml` and reuses it across requests, which keeps warm sessions and prompt caches stable. To switch providers on a server-side workload, edit the YAML and reload — there is no per-request override field.
