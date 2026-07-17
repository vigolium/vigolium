# Piolium Audit

Piolium is Vigolium's **Pi-native multi-phase whitebox security audit harness**. It runs through `vigolium agent audit --driver=piolium` (the piolium audit driver — there is no standalone `agent piolium` subcommand), driving a user-installed Pi extension via `pi --mode json -p "/piolium-<mode>"`. Findings are automatically ingested into the Vigolium database alongside native scanner results.

> **Looking for the unified driver?** `vigolium agent audit` defaults to `--driver=auto`: it runs [audit](vigolium-audit.md) when the selected `claude`/`codex` CLI is available, otherwise it falls back to Piolium before launching the audit binary. A mid-run audit failure is reported and does not silently switch drivers. Use `--driver=both` for unconditional sequential execution under one parent AgenticScan, or `--driver=piolium` / `--driver=audit` to force one driver. This page focuses on the Piolium leg.

Piolium shares its on-disk schema (`audit-state.json`, finding markdown, frontmatter conventions) with [`vigolium-audit`](vigolium-audit.md) — the parser, importer, and reporting tooling are shared between the two. The differences are runtime (Pi instead of Claude Code / Codex), folder name (`piolium/` instead of `audit/`), env-var prefix (`PIOLIUM_*` instead of `ARCHON_*`), and database tagging (`mode=piolium` instead of `audit`).

## Table of Contents

- [Why & When to Use It](#why--when-to-use-it)
- [Quick Start](#quick-start)
- [Prerequisites](#prerequisites)
- [How It Works](#how-it-works)
- [Audit Modes](#audit-modes)
- [CLI](#cli)
- [REST API](#rest-api)
- [In-Pipeline Audit (autopilot / swarm)](#in-pipeline-audit-autopilot--swarm)
- [Streaming](#streaming)
- [Cost Tracking](#cost-tracking)
- [Configuration](#configuration)
- [Session Artifacts](#session-artifacts)
- [Finding Format](#finding-format)
- [Finding Ingestion](#finding-ingestion)
- [Comparison: piolium vs audit](#comparison-piolium-vs-audit)
- [Comparison with Native Scanning](#comparison-with-native-scanning)
- [End-to-End Tests](#end-to-end-tests)

---

## Why & When to Use It

Piolium and [vigolium-audit](vigolium-audit.md) share the same on-disk schema, finding format, and reporting tooling — they differ in **which model family drives the audit**. Pick based on what credentials you actually have:

- **Use [vigolium-audit](vigolium-audit.md)** when you have access to the **Claude Opus** family (Claude Code, Vertex Anthropic, Bedrock Anthropic). Audit's prompt orchestration was tuned against Opus and consistently produces the highest-quality findings on that family.
- **Use piolium** when your available provider is **OpenAI (GPT/Codex)**, **Google (Gemini)**, or any other non-Claude model. Pi's adapter layer abstracts the provider, and piolium's phase prompts are designed to extract solid audit results from non-Opus models without sacrificing the adversarial-debate / cold-verify quality controls.

### When to use it

Reach for `vigolium agent audit --driver=piolium` (piolium) when:

- You're running on an **OpenAI key** (`gpt-5.5`, Codex) and want quality comparable to a Claude-Opus audit run.
- You're using **Gemini** or another Vertex/Bedrock-hosted non-Anthropic model.
- You want a model-agnostic harness so you can swap providers (`--pi-provider` / `--pi-model`) without changing the audit pipeline.
- You need the `longshot` mode (file-by-file hail-mary hunt) — it's piolium-only and not available in audit.

Reach for [vigolium-audit](vigolium-audit.md) instead when:

- You have Claude Opus access and want the best-possible audit fidelity.
- You want to lock the swarm/autopilot audit to Claude/Codex regardless of what's installed locally — pass `--audit=<mode>` to opt out of the auto-pick.

Both harnesses can run as the in-pipeline audit during `vigolium agent autopilot` and `vigolium agent swarm`. When you don't pass `--audit` or `--piolium`, the CLI auto-picks: piolium runs if `pi`+the piolium extension are installed locally, otherwise it falls back to audit. The two are interoperable: findings from either land in the same `findings` table tagged with their source and can be reported together.

---

## Quick Start

```bash
# Default balanced audit against the current directory
vigolium agent audit --driver=piolium --source .

# Quick triage (lite, 4 phases) on a checkout
vigolium agent audit --driver=piolium --source ./backend --mode lite

# Deep audit (17 phases) on a remote repo, full clone history
vigolium agent audit --driver=piolium --source git@github.com:org/repo.git --mode deep

# Confirm an existing audit's findings live against a target
vigolium agent audit --driver=piolium --source ./backend --mode confirm

# Hail-mary file-by-file scan with a per-file budget
vigolium agent audit --driver=piolium --source ./backend --mode longshot --plm-longshot-limit 200

# Re-run with intensity preset (preset → mode + commit-depth)
vigolium agent audit --driver=piolium --source ./backend --intensity deep
```

`vigolium agent audit --driver=piolium` requires `--source` — it audits source code, not network traffic.

---

## Prerequisites

Piolium runs as a Pi extension, so two binaries must be installed on the host:

1. **Pi runtime** ([@earendil-works/pi-coding-agent](https://www.npmjs.com/package/@earendil-works/pi-coding-agent)):

   ```bash
   bun install -g @earendil-works/pi-coding-agent
   pi --version
   ```

2. **Piolium extension** ([github.com/vigolium/piolium](https://github.com/vigolium/piolium)):

   ```bash
   pi install git:git@github.com:vigolium/piolium.git
   pi list   # verify "piolium" appears
   ```

Vigolium does **not** auto-install piolium. Before any subcommand work, `vigolium agent audit --driver=piolium` resolves the active piolium install in this order, then validates the corresponding `settings.json` lists piolium under `packages`. If nothing is found it aborts with an actionable install hint — vigolium never writes to user settings or pulls node_modules.

| Order | Source | Path used | Effect at run time |
|---|---|---|---|
| 1 | `$PIOLIUM_HOME` env var (when set) | `$PIOLIUM_HOME/agent` | Vigolium injects `PI_CODING_AGENT_DIR=$PIOLIUM_HOME/agent` into the `pi` subprocess so Pi loads piolium from the system tree. |
| 2 | Auto-probe `/opt/piolium` (when `agent/` exists) | `/opt/piolium/agent` | Same injection as (1) — operators don't have to remember to export the env var when piolium is laid out at the canonical path. |
| 3 | Per-user fallback | `~/.pi/agent` | No env injection; Pi's own default. |

Vigolium **does not** auto-probe `~/.piolium/`, even though that's piolium's own standalone-launcher default (`bin/piolium.mjs`). A per-user install at `~/.piolium/` is the operator's standalone-piolium tree; quietly sharing it with vigolium runs would mix audit state across contexts. To drive vigolium against a per-user install, set `export PIOLIUM_HOME=$HOME/.piolium` explicitly.

Vigolium's per-scan session output always lands in the vigolium session directory (`<vigolium-session>/pi-session/`) regardless of how `PIOLIUM_HOME` was resolved — the install root governs piolium's *agent config*, not transcript storage.

Run with `--debug` to confirm which path won — the audit log line emits `piolium_agent_dir` (empty when (3) is in play) and prepends `PI_CODING_AGENT_DIR=...` to the rendered cmd line under (1) or (2).

Optional, for richer scans (piolium falls back to grep when these aren't on `$PATH`):

- `trufflehog`, `gitleaks` — secrets scanning
- `codeql`, `semgrep` — static analysis

---

## How It Works

When `vigolium agent audit --driver=piolium` runs:

1. Vigolium verifies `pi` is on `$PATH` and piolium is registered in `~/.pi/agent/settings.json`.
2. The session directory is created at `~/.vigolium/agent-sessions/<scan-uuid>/`.
3. `--source` is resolved (local path, git URL, `gs://` archive, or local archive) and the resolved tree becomes the cwd of the `pi` subprocess.
4. The audit banner is printed (mode, source, session dir) so the user sees the run context before any network activity.
5. **Preflight:** unless `--no-preflight` is passed, Vigolium runs a one-turn `pi --mode json -p "..."` roundtrip against the configured provider/model. The CLI prints `· Pi preflight check... ok provider=… model=… in 2.3s` on success or aborts with the captured upstream error (e.g. `No API key found for google-vertex. Use /login to log into a provider`). This catches auth/quota issues before the audit subprocess is spawned.
6. A child `AgenticScan` row is created with `mode=piolium`.
7. Vigolium spawns `pi --mode json -p "/piolium-<mode>" [--plm-* …]` with `cmd.Dir = <resolved-source>` and `PIOLIUM_*` env vars exported.
8. Pi loads the piolium extension, which writes its output under `<source>/piolium/`.
9. Vigolium tails Pi's `--mode json` stream:
   - **stdout JSONL** is decoded by `pkg/piolium/pistream` into a colored activity feed.
   - **Raw lines** are persisted to `<sessionDir>/audit-stream.jsonl` for replay (`vigolium log <uuid>`).
10. Every 30 seconds, `<source>/piolium/audit-state.json` and `<source>/piolium/findings-draft/` are synced to `<sessionDir>/piolium-audit/` so progress is visible mid-run.
11. When `pi` exits, the full `<source>/piolium/` tree is copied into `<sessionDir>/piolium-audit/`, findings are parsed and imported into the database, and the source-side `<source>/piolium/` directory is removed.
12. Cost is computed from Pi's per-cwd session transcripts and persisted on the `AgenticScan` row.

```
+-----------------------------------------------------------+
|                  vigolium agent audit --driver=piolium                      |
|                                                            |
|  +------------------+    +-----------------------------+  |
|  |   Foreground      |    |  Subprocess (`pi --mode    |  |
|  |   Vigolium        |    |  json -p /piolium-<mode>`)  |  |
|  |                   |    |                             |  |
|  |  resolve source   |    |  Pi loads piolium ext.      |  |
|  |  spawn pi         |--->|  Phase orchestrator runs    |  |
|  |  decode JSONL     |<---|  spawns sub-agents          |  |
|  |  sync every 30s   |<---|  writes <source>/piolium/   |  |
|  |  parse findings   |<---|  exits                      |  |
|  +-------+-----------+    +-------------+---------------+  |
|          |                                                  |
|          v                                                  |
|  +-----------------------------------------------------+  |
|  |                     Database                         |  |
|  |  findings (source: scanner modules + piolium)       |  |
|  |  agentic_scans (mode=piolium, parent_uuid=...)      |  |
|  +-----------------------------------------------------+  |
+-----------------------------------------------------------+
```

---

## Audit Modes

Piolium exposes 8 audit modes via `--mode`. Audit modes (`merge`, `diff`, `confirm`, `revisit`, `longshot`) outside the intensity ladder require an explicit `--mode`.

| Mode | Phases | Phase IDs | Purpose |
|---|---|---|---|
| `lite` | 4 | Q0–Q3 | Quick recon, secrets scan, fast SAST |
| `balanced` | 9 | L1–L7 (incl. L6b/L6c) | Default audit path with PoCs and report |
| `deep` | 17 | P1–P17 | Full audit including adversarial debate, cold verification, variant hunting |
| `revisit` | 9 | R5–R11c | Anti-anchored second pass over an existing audit |
| `confirm` | 7 | V1–V7 | Confirm existing findings live, optionally with tests |
| `merge` | 7 | M1–M7 | Merge and dedupe result trees from prior runs |
| `diff` | 1 | D1 | Scan changed files since an audited commit |
| `longshot` | 3 | — | Hail-mary file-by-file vulnerability hunt |

Operator commands (`/piolium-status`, `/piolium-smoke`, `/piolium-export`, `/piolium-learn`) are not exposed through `vigolium agent audit --driver=piolium` — invoke them directly with `pi -p /piolium-<cmd>`. They don't produce findings vigolium ingests, so routing them through the audit pipeline (session sync, database tagging, dedup) just adds noise.

The phase ID space is intentionally interchangeable with `vigolium-audit` (Q*, L*, P*, V*, R*, M*) so the same parser, finding format, and reporting tooling apply.

For full per-phase semantics see piolium's own [`docs/phase-reference.md`](https://github.com/vigolium/piolium/blob/main/docs/phase-reference.md) and [`docs/output-structure.md`](https://github.com/vigolium/piolium/blob/main/docs/output-structure.md).

### Intensity presets

`--intensity` bundles the audit mode and clone depth into a single flag, matching the autopilot/swarm/audit intensity model:

| Intensity | Mode | Commit depth | Use case |
|---|---|---|---|
| `quick` | `lite` | 1 (shallow) | CI/CD, routine triage |
| `balanced` | `balanced` | 1 (shallow) | Default; PoCs + report |
| `deep` | `deep` | 0 (full history) | Pre-release, compliance, commit archaeology |

Explicit `--mode` and `--commit-depth` always override the preset.

---

## CLI

```
vigolium agent audit --driver=piolium \
  [--mode {lite,balanced,deep,revisit,confirm,merge,diff,longshot}] \
  [--intensity {quick,balanced,deep}] \
  --source <path|git-url|gs://...|archive> \
  [--commit-depth N] \
  [--no-stream] \
  [--upload-results] \
  [--plm-* passthroughs]
```

### Flag reference

| Flag | Description |
|---|---|
| `--source` | Required. Local directory, git URL, `gs://<project>/<key>` archive, or local `.zip`/`.tar.gz`/`.tar.bz2`/`.tar.xz`. |
| `--mode` | Audit mode. Overrides `--intensity`. |
| `--intensity` | Preset. `quick`/`balanced`/`deep`. Defaults to `balanced`. |
| `--commit-depth` | `git clone --depth` for git URLs. `0` = full history. Overrides `--intensity`. |
| `--no-stream` | Don't echo to console. Stream is still persisted to `runtime.log` so `vigolium log <uuid>` works. |
| `--upload-results` | Upload session bundle to cloud storage after completion (requires storage config). |
| `--pi-provider` | Override pi's `defaultProvider` for this run (e.g. `vertex-anthropic`, `google-vertex`). Threaded through as `pi --provider <name>`. |
| `--pi-model` | Override pi's `defaultModel` for this run (e.g. `claude-opus-4-6`, `gemini-3.1-pro`). Threaded through as `pi --model <id>`. |
| `--no-preflight` | Skip the pre-audit pi roundtrip (auth + model availability check). |
| `--preflight-timeout` | Cap on the preflight call (default 30s). |
| `--api-key` / `--oauth-token` / `--oauth-cred-file` | Per-run BYOK auth override. See [Audit BYOK](audit-byok.md). For piolium these become env vars on the `pi` subprocess (or, for codex cred files, a temporarily-staged `<pi-agent-dir>/auth.json`). |

### `--plm-*` passthroughs

These flags map 1:1 onto piolium's own `--plm-*` session flags. Empty or zero values are dropped — piolium's defaults apply when you don't override.

| Flag | Piolium scope | Piolium default |
|---|---|---|
| `--plm-scan-limit N` | Cap commit-history scan to N commits | 500 |
| `--plm-scan-since <expr>` | git `--since` window (e.g. `"60 days ago"`) | `"60 days ago"` |
| `--plm-phase-retries N` | Per-phase retry count | 2 |
| `--plm-command-retries N` | Per-command retry count | 3 |
| `--plm-longshot-limit N` | Max files hunted in longshot mode | 1000 |
| `--plm-longshot-timeout MS` | Per-file kill timer in longshot | 21600000 (6h) |
| `--plm-longshot-langs <list>` | Comma-separated language allowlist | auto-detect |

### Examples

```bash
# Balanced audit on a remote git URL, shallow clone
vigolium agent audit --driver=piolium \
  --source git@github.com:vigolium/piolium.git \
  --intensity balanced

# Deep audit with bounded commit history scan
vigolium agent audit --driver=piolium \
  --source ./backend \
  --mode deep \
  --plm-scan-limit 250 \
  --plm-scan-since "90 days ago"

# Longshot hunt on Python and Go files only
vigolium agent audit --driver=piolium \
  --source ./mono-repo \
  --mode longshot \
  --plm-longshot-langs python,go \
  --plm-longshot-limit 200

# Pinned scan UUID for cross-node sync
vigolium --scan-uuid 019aa... agent audit --source ./backend

# Override pi's provider/model for this single run
vigolium agent audit --driver=piolium --source ./backend \
  --pi-provider vertex-anthropic \
  --pi-model claude-opus-4-6

vigolium agent audit --driver=piolium --source ./backend \
  --pi-provider google-vertex \
  --pi-model gemini-3.1-pro
```

### Running piolium and audit together

`--driver=piolium` runs piolium only — no audit, no harness fallback. To score the same source tree with both harnesses (under one AgenticScan, with per-driver child rows and a post-pass project-wide findings dedup), use the other driver modes:

```bash
# Default — run audit, falling back to piolium only if audit is unavailable
vigolium agent audit --source ./backend

# Just piolium — no audit, no fallback
vigolium agent audit --driver piolium --source ./backend --mode lite

# Just audit (no Piolium fallback)
vigolium agent audit --driver audit --source ./backend
```

A single `--mode` must be understood by every selected driver. Mode chains from
`--modes` are filtered per driver, so a driver skips chain entries it does not
support; a mode unknown to both drivers is rejected.

---

## REST API

`POST /api/agent/run/audit` is the **unified driver endpoint** — it dispatches
audit and/or piolium based on the `driver` field. The default, `"auto"`, runs
audit when its selected Claude/Codex CLI is available and otherwise falls back
to piolium. Use `"both"` to run both sequentially, `"piolium"` for piolium only,
or `"audit"` for audit only. Multi-driver runs have per-driver child rows and a
post-pass findings dedup. The existing `/agent/status/:id`,
`/agent/sessions/:id/logs`, and `/agent/sessions/:id/artifacts` endpoints work
uniformly across both harnesses.

The server-side handler does **not** run the CLI's preflight roundtrip (`pi --mode json` is started straight after request validation). Auth/quota failures surface in the SSE/runtime.log stream instead.

### Request body

| Field | Type | Description |
|---|---|---|
| `source` | string | **Required.** Local path, git URL, `gs://<bucket>/<key>` archive (auto-downloaded + extracted server-side), or local `.zip`/`.tar.gz`/`.tar.bz2`/`.tar.xz`. With `driver: "both"`, the source is resolved once and reused by both drivers. |
| `target` | string | Optional target URL stored on the run row for cross-referencing scans. |
| `intensity` | string | `quick` / `balanced` (default) / `deep`. Bundles `mode` + `timeout` + `commit_depth` (quick → `lite`/1h/depth 1, balanced → `balanced`/6h/depth 1, deep → `deep`/12h/depth 0). Explicit `mode`/`timeout`/`commit_depth` win per-field over the preset. |
| `mode` | string | Single audit mode override. With `driver: "auto"` or `"both"`, it must be supported by both drivers. Driver-specific modes require the corresponding single-driver selection. |
| `modes` | string[] | Mode chain. Overrides `mode`/`intensity`; unsupported entries are skipped per driver, while a value unknown to both drivers is rejected. |
| `timeout` | string | Go duration (e.g. `"2h"`). Overrides intensity preset. Applied per-driver under `driver: "both"` so an audit hang doesn't burn piolium's budget. |
| `diff` | string | Focus on changed code: PR URL, git ref range, or `HEAD~N`. |
| `last_commits` | int | Focus on last N commits (shorthand for `diff HEAD~N`). |
| `commit_depth` | int | `git clone --depth` for git URLs. `0` = full history. Overrides intensity. |
| `files` | string[] | Specific files to focus on. |
| `stream` | bool | Enable SSE streaming of the agent feed. With `driver: "both"`, events are tagged with a `driver` field and bracketed by `driver_start`/`driver_end` markers. |
| `upload_results` | bool | Upload session bundle to cloud storage on completion. With `driver: "both"`, skipped when any driver failed. |
| `project_uuid` | string | Project UUID for data scoping. Falls back to `X-Project-UUID` header. |
| `scan_uuid` | string | Optional scan UUID. |
| `driver` | string | `"auto"` (default), `"both"`, `"audit"`, or `"piolium"`. `auto` runs audit and falls back to piolium only when the selected audit CLI is unavailable. |
| `no_dedup` | bool | Skip the post-pass project-wide findings dedup that runs after `driver: "both"` completes. Ignored for single-driver runs (those already INSERT-time-dedup by `finding_hash`). |
| `agent` | string | Audit platform when audit participates: `claude` (default) / `codex`. Ignored when `driver: "piolium"`. |
| `pi_provider` | string | Forwarded as `pi --provider <name>`. Ignored when `driver: "audit"`. |
| `pi_model` | string | Forwarded as `pi --model <id>`. |
| `plm_scan_limit` | int | `--plm-scan-limit` passthrough. |
| `plm_scan_since` | string | `--plm-scan-since` passthrough. |
| `plm_phase_retries` | int | `--plm-phase-retries` passthrough. |
| `plm_command_retries` | int | `--plm-command-retries` passthrough. |
| `plm_longshot_limit` | int | `--plm-longshot-limit` passthrough. |
| `plm_longshot_timeout` | int | `--plm-longshot-timeout` passthrough (ms). |
| `plm_longshot_langs` | string | `--plm-longshot-langs` passthrough (comma-separated). |

All `pi_*` and `plm_*` fields are optional and only emit their flag when populated, matching the CLI's behavior.

> **`gs://` requires storage config.** The server resolves `gs://<bucket>/<key>` via `pkg/storage` using the configured GCS credentials (see `vigolium-configs.yaml` `storage.gcs.*`). Downloads land in a temp dir that's removed after the run regardless of outcome. Returns `400` if the URI is reachable but not a recognized archive, or `500` if the download itself fails.

### Examples

```bash
# Default — driver=auto with intensity=balanced (audit when available,
# otherwise piolium)
curl -s -X POST http://localhost:9002/api/agent/run/audit \
  -H "Content-Type: application/json" \
  -d '{
    "source": "/home/user/src/my-app",
    "intensity": "balanced"
  }' | jq .

# Quick triage with both drivers — intensity resolves to mode=lite,
# commit_depth=1 (resolved server-side from the preset)
curl -s -X POST http://localhost:9002/api/agent/run/audit \
  -H "Content-Type: application/json" \
  -d '{
    "source": "/home/user/src/my-app",
    "intensity": "quick",
    "driver": "both"
  }' | jq .

# Deep audit with full git history (intensity=deep → commit_depth=0)
# pinned to piolium only with a provider override
curl -s -X POST http://localhost:9002/api/agent/run/audit \
  -H "Content-Type: application/json" \
  -d '{
    "source": "git@github.com:org/repo.git",
    "intensity": "deep",
    "driver": "piolium",
    "pi_provider": "vertex-anthropic",
    "pi_model": "claude-opus-4-6"
  }' | jq .

# Source from Google Cloud Storage — server downloads + extracts the
# archive once, both drivers reuse the resolved tree (no double clone)
curl -s -X POST http://localhost:9002/api/agent/run/audit \
  -H "Content-Type: application/json" \
  -d '{
    "source": "gs://vigolium-uploads/acme/backend-2026-05-02.tar.gz",
    "intensity": "balanced",
    "project_uuid": "11111111-2222-3333-4444-555555555555"
  }' | jq .

# gs:// + driver=audit only (skip piolium even though it's installed)
curl -s -X POST http://localhost:9002/api/agent/run/audit \
  -H "Content-Type: application/json" \
  -d '{
    "source": "gs://vigolium-uploads/acme/backend-2026-05-02.zip",
    "driver": "audit",
    "agent": "claude",
    "intensity": "balanced"
  }' | jq .

# Explicit mode wins over intensity — longshot is piolium-only, so
# driver must be set to piolium (driver=both would 400)
curl -s -X POST http://localhost:9002/api/agent/run/audit \
  -H "Content-Type: application/json" \
  -d '{
    "source": "/home/user/src/mono-repo",
    "driver": "piolium",
    "mode": "longshot",
    "plm_longshot_langs": "python,go",
    "plm_longshot_limit": 200
  }' | jq .

# Skip the post-pass dedup (driver=both only — single-driver runs
# already INSERT-time-dedup by finding_hash)
curl -s -X POST http://localhost:9002/api/agent/run/audit \
  -H "Content-Type: application/json" \
  -d '{
    "source": "/home/user/src/my-app",
    "intensity": "balanced",
    "no_dedup": true
  }' | jq .
```

### Response

The endpoint returns `202 Accepted` with the **parent** run UUID; tail progress via `/api/agent/sessions/<uuid>/logs` (SSE-capable) or poll `/api/agent/status/<uuid>` for phase counters. With `driver: "both"`, child rows are exposed under the parent via `/api/agent/sessions/<uuid>` (`child_runs[]`).

```json
{
  "agentic_scan_uuid": "b1e100e5-1131-4b41-995d-f0991534ac14",
  "status": "running",
  "message": "audit (driver=both) started"
}
```

Single-driver runs (`driver: "piolium"` or `"audit"`) return `"message": "audit run started"`.

Pass `"stream": true` in the request to keep the connection open and receive an SSE stream of `chunk` / `error` / `done` events instead of the 202.

### Errors

| Status | Cause |
|---|---|
| 400 | Missing `source`; invalid `mode`/`intensity`/`driver`; a driver-specific mode (`longshot`/`mock`) under `driver: "both"`; or invalid audit `agent` (`claude`/`codex`) when audit participates. |
| 429 | Heavy-agent semaphore is full — retry after the in-flight audit completes. |
| 503 | The **single requested driver's** runtime is unavailable: `driver: "piolium"` returns 503 when `pi` isn't on `PATH` or the piolium extension isn't registered in `~/.pi/agent/settings.json`; `driver: "audit"` returns 503 when the configured platform binary (`claude`/`codex`) isn't on `PATH`. **`driver: "both"` never returns 503 for missing runtimes** — a missing `pi` or platform binary becomes a server warning log, the available driver still runs, and the failed driver surfaces as a per-driver error on the child run (parent ends `completed_with_errors`). The request only fails if both drivers turn out to be unavailable, which still produces a `202 Accepted` followed by a `completed_with_errors` parent row that names both. |

### Combined-driver SSE events

When `driver: "both"` and `stream: true`, audit-then-piolium output is multiplexed into one SSE stream. Each event includes a `driver` field (`"audit"` or `"piolium"`); `driver_start` and `driver_end` events bracket each driver's slot so clients can render per-driver progress. The `error` field on `driver_end` carries the per-driver failure (if any), and a final `done` event fires only when both drivers completed without errors.

```bash
# Run both drivers, multiplexed SSE
curl -N -s -X POST http://localhost:9002/api/agent/run/audit \
  -H "Content-Type: application/json" \
  -d '{
    "source": "/home/user/src/my-app",
    "mode": "balanced",
    "driver": "both",
    "stream": true
  }'
```

---

## In-Pipeline Audit (autopilot / swarm)

`vigolium agent autopilot` and `vigolium agent swarm` can drive piolium as the in-pipeline audit that runs alongside (and feeds findings into) the operator agent. The same CLI that historically defaulted to audit now auto-picks piolium when it's locally available.

### Auto-pick

When `--source` is set and **neither** `--audit` nor `--piolium` is passed:

- If `pi` is on `$PATH` **and** the piolium extension is registered in `~/.pi/agent/settings.json` → **piolium** runs (mode = whatever the intensity preset chose, default `lite`).
- Otherwise → **audit** runs (existing default).

This preserves the prior behavior on machines without Pi while picking up piolium automatically once a user installs it.

### Explicit override

| Flag combination | Result |
|---|---|
| `--piolium` (explicit, any mode) | Piolium runs at that mode; audit turns off. |
| `--audit` (explicit, any mode) | Audit runs at that mode; piolium stays off. |
| `--audit=off --piolium=off` | No audit. |

Only one harness runs per scan — there's no "run both" mode. If you want to compare both harnesses on the same source, run two scans.

### REST API equivalents

Both `POST /api/agent/run/autopilot` and `POST /api/agent/run/swarm` accept a new `piolium` field that mirrors the CLI flag exactly. The same auto-pick rule applies server-side: omitting both `audit` and `piolium` triggers piolium when the **server process** has pi+piolium installed, audit otherwise.

```bash
# Autopilot — explicit piolium audit
curl -s -X POST http://localhost:9002/api/agent/run/autopilot \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "source": "/home/user/src/my-app",
    "piolium": "balanced"
  }' | jq .

# Swarm — opt-in piolium audit during a targeted scan
curl -s -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -d '{
    "input": "https://example.com/api/users?id=1",
    "source": "/home/user/src/my-app",
    "discover": true,
    "piolium": "lite"
  }' | jq .

# Autopilot — let auto-pick decide; pi+piolium on this host means piolium wins
curl -s -X POST http://localhost:9002/api/agent/run/autopilot \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "source": "/home/user/src/my-app"
  }' | jq .
```

### Findings flow

Whichever harness runs:

- The audit's `audit-state.json` and `findings/` tree are synced into `<sessionDir>/<harness.SessionSubdir>/` (`vigolium-results/` or `piolium-audit/`).
- The autopilot pipeline blocks on the audit before launching the operator agent, then folds the findings into the operator's frozen context bundle (same flow that audit has used).
- Findings use `module_type = "whitebox"`; the harness-specific module-ID
  prefix and tag (`audit` or `piolium`) distinguish them. Query both together:
  ```bash
  vigolium finding --module-type whitebox
  ```

### Caveats

- **Pi-specific knobs** (`--pi-provider`, `--pi-model`, `--plm-*`) are **not** exposed on the autopilot/swarm surface. If you need those, run `vigolium agent audit --driver=piolium` (or `POST /api/agent/run/audit`) directly.
- Auto-pick is host-local. If your CLI machine has pi installed but the **server** running autopilot doesn't (or vice versa), the auto-pick decision happens where the request handler runs.

---

## Streaming

Pi's `--mode json` flag emits newline-delimited `AgentSessionEvent` objects to stdout. Vigolium's `pkg/piolium/pistream` decoder consumes them and renders a compact, colored activity feed.

### Event types rendered

| Event | Rendering |
|---|---|
| `session` | One-line header with session ID and cwd |
| `agent_start` / `agent_end` | Run lifecycle markers; `agent_end` includes elapsed duration |
| `message_end` (assistant) | Final assistant text, plus error messages on auth/quota failures |
| `tool_execution_start` | `→ tool_name (args)` |
| `tool_execution_end` | `← tool_name result` (`✗` on error) |
| `auto_retry_start` / `auto_retry_end` | Retry attempts with backoff and cause |
| `compaction_start` / `compaction_end` | Context compaction cycles |

`turn_start`, `turn_end`, `message_start`, `message_update`, `tool_execution_update`, `queue_update`, and `session_info_changed` are intentionally suppressed — they're either redundant with the `*_end` events or UI-state-only.

The raw JSONL is mirrored to `<sessionDir>/audit-stream.jsonl` regardless of `--no-stream`, so `vigolium log <uuid>` can replay the exact event stream after the fact.

---

## Cost Tracking

Pi pre-prices every assistant turn and writes the result into its session transcript. Vigolium's `pkg/piolium/picost` extracts that data after the run.

### How cost is extracted

1. After `pi` exits, `picost.BuildSummary` locates `~/.pi/agent/sessions/<encoded-cwd>/`, where `<encoded-cwd>` is `--<path>--` with `/` replaced by `-`.

   Example: `/Users/alice/Desktop/repo` → `--Users-alice-Desktop-repo--`

2. Every `<timestamp>_<sessionid>.jsonl` transcript with a `session` header timestamp inside `[startedAt - 30s, startedAt + 24h]` is scanned.
3. Each assistant `message` event carries:
   ```json
   "usage": {
     "input": 4254, "output": 14, "cacheRead": 0, "cacheWrite": 0, "totalTokens": 4268,
     "cost": { "input": 0.02127, "output": 0.00042, ..., "total": 0.02169 }
   }
   ```
   Tokens and `cost.total` are summed across all attributed transcripts.
4. Transcripts whose only assistant turn was a 401-error (auth failure) are dropped — they have zero cost and would skew the model attribution.

### Output

The CLI summary appends:

```
ℹ Cost: ~$0.02 (model gpt-5.5)
```

Multi-session runs (deep mode, longshot) annotate as `(model gpt-5.5, 23 sessions)`.

The `AgenticScan` DB row is populated with:

| Field | Source |
|---|---|
| `total_input_tokens` | Sum of `usage.input` |
| `total_output_tokens` | Sum of `usage.output` |
| `estimated_cost_usd` | Sum of `usage.cost.total` |
| `token_usage` | Full `picost.Summary` JSON (incl. per-session breakdown) |

Unlike `claudecost` and `codexcost`, `picost` has no local pricing table — Pi has already computed prices against the active provider's rates by the time the message lands in the transcript.

---

## Configuration

### YAML config

Piolium reuses the existing `agent.sessions_dir` and storage settings. There is no piolium-specific block in `vigolium-configs.yaml` — the harness ships with Pi, not Vigolium.

```yaml
agent:
  sessions_dir: ~/.vigolium/agent-sessions/   # session artifacts root
```

Pi-side configuration (provider, model, auth) lives in `~/.pi/agent/settings.json` and is set via `pi` itself:

```bash
pi config set defaultProvider openai-codex
pi config set defaultModel gpt-5.5
```

The piolium extension also reads its own `--plm-*` flags from the session, which Vigolium passes through verbatim from the matching `--plm-*` flags on `vigolium agent audit --driver=piolium`.

### Environment variables exported to `pi`

Vigolium replicates piolium's expected env contract before launching:

| Variable | Source |
|---|---|
| `PIOLIUM_REPOSITORY` | Resolved repo identity (git remote URL canonicalized to `owner/repo`, else dir basename) |
| `PIOLIUM_GIT_AVAILABLE` | `true` when `<source>` is a git work tree |
| `PIOLIUM_SESSION_UUID` | Vigolium's `AgenticScan` UUID for this run |
| `PIOLIUM_COMMIT_SCAN_LIMIT` | Set when `--plm-scan-limit > 0` |
| `PIOLIUM_COMMIT_SCAN_SINCE` | Set when `--plm-scan-since` is non-empty |

---

## Session Artifacts

### Source directory (transient, removed after import)

```
<source_path>/
└── piolium/
    ├── audit-state.json               # Phase progress (snake_case keys, audit-compatible)
    ├── attack-surface/                # Recon, KB, SAST, probe summaries
    │   ├── lite-recon.md
    │   ├── knowledge-base-report.md
    │   ├── sast-merged.sarif
    │   ├── source-sink-flows-all-severities.md
    │   ├── public-routes-authz-matrix.md
    │   └── ...
    ├── findings-draft/                # Candidate findings (filed during a run)
    │   ├── q2-001-sql-injection-user-lookup.md
    │   └── ...
    ├── findings/                      # Final consolidated findings
    │   ├── p10-001-direct-git-url-ref-…/
    │   │   ├── draft.md               # Frontmatter metadata
    │   │   ├── report.md              # Polished, structured analysis
    │   │   ├── poc.{sh,ts,py,…}       # Executable proof
    │   │   └── evidence/              # Supporting files
    │   └── ...
    ├── final-audit-report.md          # Top-level report
    ├── confirmation-report.md         # confirm-mode output
    ├── chamber-workspace/             # Adversarial debate transcripts (deep mode)
    ├── codeql-artifacts/              # CodeQL DBs, SARIF
    ├── semgrep-rules/
    └── tmp/                           # Per-sub-agent run transcripts (cleaned up)
```

### Vigolium session directory (persistent)

```
~/.vigolium/agent-sessions/<uuid>/
├── piolium-audit/                     # Synced from <source>/piolium/
│   ├── audit-state.json
│   ├── attack-surface/
│   ├── findings/
│   ├── final-audit-report.md
│   └── ...
├── audit-stream.jsonl                 # Raw Pi --mode json events
├── piolium-audit-output.md            # Captured stdout (fallback when stream is empty)
└── runtime.log                        # Replayable feed via `vigolium log <uuid>`
```

---

## Finding Format

Piolium's finding format is identical to audit's — same YAML frontmatter, same body conventions, same cold-verify overlay pattern. The only naming difference is the **directory layout**: piolium keeps the source phase ID on its promoted findings (`p10-001-<slug>/`) instead of renumbering to severity-letter format (`C1-<slug>/` in audit). Vigolium's parser handles both.

### Frontmatter (lowercase YAML, piolium-style)

```markdown
---
id: p10-001
phase: P10
source-draft: p4-001
slug: direct-git-url-ref-reaches-simple-git-clone
severity: high
verdict: VALID
debate: piolium/chamber-workspace/c01-git-and-lock-command/debate.md
---
PoC-Status: executed
Protocol: local
Auth-Required: no

# Direct git URL/ref reaches vulnerable simple-git clone boundary

## Summary
…

## Location
- Source: `src/add.ts:895-942`
- Sink:   `src/git.ts:25-62`

## Impact
…

## Evidence
…
```

The frontmatter parser is case-insensitive on field names: audit's `Phase`/`Severity-Final` and piolium's `phase`/`severity` both work. Piolium's single `severity` field is mapped onto audit's `SeverityFinal` slot so the existing "prefer final over original" resolution still applies.

For a full schema see [vigolium-audit's Finding Format section](vigolium-audit.md#finding-format) — both harnesses share it.

---

## Finding Ingestion

When the audit completes, findings are automatically parsed and stored in the Vigolium database.

### Database fields

| Piolium field | Database field | Example |
|---|---|---|
| Finding ID | `module_id` | `piolium:p10-001` |
| Title (from H1 or slug) | `module_name` | Direct git URL reaches simple-git clone |
| Slug | `module_short` | `direct-git-url-ref-reaches-…` |
| Severity (final) | `severity` | `high` (normalized) |
| Verdict | `confidence` | `firm` (`CONFIRMED`/`VALID`) or `tentative` |
| CWE | `cwe_id` | `CWE-918` |
| Full body | `description` | Markdown with evidence |
| First location | `source_file` | `src/add.ts` |
| All locations | `matched_at` | `src/add.ts:895-942` |
| Metadata | `tags` | `["piolium", "phase-P10", "valid", "poc-executed", "CWE-918"]` |

All findings are stored with:

- `finding_source`: `audit` (shared by both audit harnesses)
- `module_type`: `whitebox`
- `finding_hash`: `MD5(auditID + moduleID + findingID)` for deduplication

The associated `AgenticScan` row carries:

- `mode`: `piolium`
- `agent_name`: `piolium`
- `protocol`: `pi-sdk`
- `input_type`: `piolium`

### Querying piolium findings

```bash
# Via CLI
vigolium finding --finding-source audit --search 'piolium:'

# Via API
GET /api/findings?finding_source=audit&search=piolium%3A

# Combined with audit
vigolium finding --finding-source audit --module-type whitebox
```

### Manual import

Piolium output from external runs imports through the same path as audit — the parser detects the `findings/p<phase>-<seq>-<slug>/` directory layout and tags rows correctly:

```bash
vigolium import /path/to/piolium-output/
```

The folder must contain `audit-state.json` and either `findings/` or `findings-draft/`.

---

## Comparison: piolium vs audit

| Aspect | `vigolium agent audit` | `vigolium agent audit --driver=piolium` (piolium) |
|---|---|---|
| **Runtime** | Claude Code or Codex | Pi (`pi` CLI + piolium extension) |
| **Install model** | Embedded harness, auto-extracted at runtime | User installs piolium via `pi install` |
| **Slash command** | `/vigolium-audit:audit:<mode>` | `/piolium-<mode>` |
| **Output folder** | `<source>/vigolium-results/` → `<sessionDir>/vigolium-results/` | `<source>/piolium/` → `<sessionDir>/piolium-audit/` |
| **Env prefix** | `ARCHON_*` | `PIOLIUM_*` |
| **Session-flag prefix** | n/a | `--plm-*` (passthrough on the `pi` argv) |
| **Modes** | `lite`/`balanced`/`deep`/`revisit`/`confirm`/`merge`/`diff`/`status`/`mock` | `lite`/`balanced`/`deep`/`revisit`/`confirm`/`merge`/`diff`/`longshot` |
| **Cost source** | `claudecost` (audit-stream.jsonl), `codexcost` (~/.codex/sessions) | `picost` (~/.pi/agent/sessions) |
| **DB tagging** | `mode=audit`, `module_id=audit:…` | `mode=piolium`, `module_id=piolium:…` |
| **Audit-state.json** | Same schema (snake_case keys, interchangeable) | Same schema |
| **Finding format** | Same (YAML frontmatter + cold-verify overlays) | Same |
| **Promoted-findings layout** | `findings/C1-<slug>/` (severity-prefixed) | `findings/p<phase>-<seq>-<slug>/` (phase-prefixed) |
| **Background-during-scan** | Yes — `--audit` flag on `swarm`/`autopilot` | No — foreground driver only |

The two are intentionally interoperable. You can run a piolium audit and import the output into a project that has audit-tagged findings; the parser, finding deduplication, and reporting tooling all apply uniformly.

---

## Comparison with Native Scanning

| Aspect | Vigolium Native (Swarm/Autopilot) | Piolium |
|---|---|---|
| **Focus** | Network vulnerabilities (injection, XSS, SSRF, etc.) | Source code vulnerabilities (logic flaws, auth gaps, spec violations) |
| **Method** | Live HTTP scanning with payloads | Static analysis + AI reasoning + adversarial validation |
| **False positive handling** | AI triage phase | Multi-layer: adversarial debate chambers + cold verification (deep mode) |
| **Finding richness** | Standard severity/confidence | Adversarial verdicts, cold-verify overlays, CWE, PoC status |
| **Speed** | Minutes to hours | Minutes (lite, ~1h) to hours (deep, ~6h) |
| **Requires** | Target URL | Source code path |
| **Runs as** | Foreground (main pipeline) | Foreground subcommand |

The two approaches are complementary. Network scanning finds vulnerabilities that manifest in HTTP responses; piolium finds vulnerabilities that require understanding code semantics, business logic, and specification compliance. Running both — `vigolium agent swarm -t https://…` against a deployed instance, then `vigolium agent audit --driver=piolium --source ./repo` against the source — provides the most comprehensive assessment.

---

## End-to-End Tests

The piolium audit path has an opt-in e2e test at [`test/e2e/piolium_audit_e2e_test.go`](../../test/e2e/piolium_audit_e2e_test.go) that runs `pi --mode json -p "/piolium-lite"` against a tiny synthetic Python fixture and asserts that the session artifacts, DB row, and JSONL stream all materialize.

```bash
# Default (uses whatever pi has configured as defaultProvider/defaultModel)
make test-e2e-piolium

# Override the provider/model for the run
VIGOLIUM_E2E_PI_PROVIDER=vertex-anthropic \
VIGOLIUM_E2E_PI_MODEL=claude-opus-4-6 \
  make test-e2e-piolium

VIGOLIUM_E2E_PI_PROVIDER=google-vertex \
VIGOLIUM_E2E_PI_MODEL=gemini-3.1-pro \
  make test-e2e-piolium

# Keep the session dir for inspection
VIGOLIUM_E2E_PI_KEEP=1 \
  make test-e2e-piolium

# Custom timeout (defaults to 5m)
VIGOLIUM_E2E_PI_TIMEOUT=10m make test-e2e-piolium
```

Environment variables consumed:

| Variable | Default | Effect |
|---|---|---|
| `VIGOLIUM_E2E_PI_PROVIDER` | (pi's `defaultProvider`) | Sets `--pi-provider` for the test run |
| `VIGOLIUM_E2E_PI_MODEL` | (pi's `defaultModel`) | Sets `--pi-model` for the test run |
| `VIGOLIUM_E2E_PI_TIMEOUT` | `5m` | Audit hard timeout (Go duration syntax) |
| `VIGOLIUM_E2E_PI_KEEP` | unset | When `1`, keeps the session dir on disk after the test exits |

The test skips automatically when `pi` isn't on `$PATH` or piolium isn't registered in `~/.pi/agent/settings.json`. There's also a non-skipping companion subtest, `TestE2EPioliumAudit_PreArgsRoundtrip`, that proves the argv builder produces the exact `pi --provider X --model Y --mode json -p /piolium-<mode>` shape for each provider — useful for catching flag-plumbing regressions in CI without needing live credentials.
