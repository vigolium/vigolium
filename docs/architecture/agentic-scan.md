# Agentic Scan Architecture — How Agent Mode Works

> _Architecture series: [overview](overview.md) · [native-scan](native-scan.md) · **agentic-scan** · [data-and-storage](data-and-storage.md) · [server-and-api](server-and-api.md)_

Vigolium's agent mode runs AI-driven security scans on top of the native scanner. This document explains the architecture, the moving parts, and the flow of a typical agent run.

> **Recent shift:** the previous subprocess-based SDK backends (`claudesdk`, `codexsdk`) have been removed. All AI dispatch now goes through an in-process Go runtime called **olium** (`pkg/olium/`). One unified provider interface, one conversation state, one place to reason about timeouts and retries.

---

## 1. Subcommand surface

`vigolium agent` is a parent command with informational flags only (`--list-templates`, `--list-agents`). Real work happens in subcommands.

| Subcommand   | Purpose                                                          | Key file                    |
|--------------|------------------------------------------------------------------|-----------------------------|
| `query`      | Single-shot prompt (template or inline). Code review, secret hunt, endpoint discovery. | `pkg/cli/agent.go`          |
| `autopilot`  | Agentic scan: autonomous operator with full tool access.         | `pkg/cli/agent_autopilot.go`|
| `swarm`      | Agentic scan: 10-phase guided pipeline (plan → extension → scan → triage). | `pkg/cli/agent_swarm.go`    |
| `audit`     | Foreground vigolium-audit (multi-phase AI source-code audit).      | `pkg/cli/agent_audit.go`   |
| `olium`      | Interactive olium TUI or headless prompt.                        | `pkg/cli/agent_olium.go`    |
| `session`    | List or inspect past agent runs (sessions list / detail view).   | `pkg/cli/agent_session.go`  |

`query` is the only mode that does **not** orchestrate a scan — it's a one-shot prompt with optional source-code context. `autopilot` and `swarm` are the two **agentic scan** modes.

---

## 2. Architecture layers

```
┌─────────────────────────────────────────────────────────────────┐
│  CLI                          pkg/cli/agent_*.go                │
│  query · autopilot · swarm · audit · olium · session           │
└───────────────────────────────┬─────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────┐
│  Orchestrators                pkg/agent/                        │
│                                                                 │
│   SwarmRunner          swarm.go + swarm_pipeline.go             │
│     normalize → auth → source-analysis → code-audit →           │
│     discovery → plan → extension → scan → triage → finalize     │
│                                                                 │
│   AutopilotPipelineRunner    autopilot_pipeline.go              │
│     audit (optional, foreground) → autonomous operator         │
└───────────────────────────────┬─────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────┐
│  Engine                       pkg/agent/engine.go               │
│  Preflight → buildPrompt → enrichContext → run on olium →       │
│  parse → ingest (findings / http_records / plans / triage)      │
└───────────────────────────────┬─────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────┐
│  Olium runtime                pkg/olium/{engine,tool,skill}     │
│  Multi-turn agent loop · tool registry · event stream           │
└───────────────────────────────┬─────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────┐
│  Providers                    pkg/olium/provider/               │
│  anthropic · openai · codex (OAuth) · claudecode (CLI)          │
└─────────────────────────────────────────────────────────────────┘
```

### 2.1 Engine (`pkg/agent/engine.go`)

The engine is the seam between orchestrators and the olium runtime. Its job is to:

1. **Preflight** — validate provider/model selection (`Preflight(agentName)`).
2. **Build the prompt** — load template, parse frontmatter, render with `TemplateData`.
3. **Enrich context** — pull DB context (previous findings, discovered endpoints, high-risk endpoints, module list, scan stats) through a thread-safe LRU cache (`agentprompt.ContextCache`) that lives for one swarm/autopilot run.
4. **Dispatch** — call `runOliumOnEngineWithThinking()` against an olium engine instance.
5. **Retry** — exponential backoff on transient errors (`retry.go`, default 2 retries, 2-30s backoff) with jitter.
6. **Parse** — schema-aware JSON extraction tolerating fences, prose, and type coercion (string ↔ int, object ↔ string body).
7. **Ingest** — write parsed findings/HTTP records to the DB repository.

Key entry points:

- `Engine.Run(ctx, opts)` — one-shot prompt execution; creates a fresh olium engine.
- `Engine.RunOnOliumEngine(ctx, opts, eng)` — runs against a **shared engine instance**, preserving conversation prefix for prompt-cache hits across phases.
- `Engine.RunSourceAnalysisParallel(ctx, cfg)` — fan-out source analysis (single explore call → parallel format/extension sub-calls on the same engine).

A global semaphore (`oliumProviderSem`) caps in-flight provider calls; the value comes from `Settings.Agent.Olium.MaxConcurrent` (default 4).

### 2.2 Olium runtime (`pkg/olium/`)

Native, in-process replacement for the old SDK pool.

- **`pkg/olium/engine`** — `Engine.Run(ctx, prompt) <-chan Event` returns a stream of events: `EventTextDelta`, `EventThinkingDelta`, `EventToolCall`, `EventTurnDone` (with token usage), `EventError`. Conversation state (system prompt, tool definitions, prior turns) lives on the engine and is reused across calls when phases share an engine.
- **`pkg/olium/tool`** — registry of built-in tools (bash, file ops, grep, fetch, …) registered via `tool.NewRegistry()` + `tool.RegisterBuiltins()`. Autopilot exposes the full set; swarm uses a smaller set per phase.
- **`pkg/olium/skill`** — optional skill files (Markdown SKILL.md packages) that augment the system prompt; loaded from embedded assets and `~/.vigolium/skills/`.
- **`pkg/olium/provider`** — provider dispatch:

  | Provider              | Auth source                                           |
  |-----------------------|-------------------------------------------------------|
  | `openai-codex-oauth`         | `oauth_cred_path` (JSON from `codex login`)           |
  | `anthropic-api-key`   | `llm_api_key` or `$ANTHROPIC_API_KEY`                 |
  | `anthropic-oauth`        | `oauth_token` (from `claude setup-token`); falls back to `$ANTHROPIC_API_KEY` |
  | `openai-api-key`      | `llm_api_key` or `$OPENAI_API_KEY`                    |
  | `anthropic-cli`     | shells out to the `claude` binary                     |
  | `anthropic-vertex`   | `oauth_cred_path` (GCP SA JSON, or `$GOOGLE_APPLICATION_CREDENTIALS`) + `google_cloud_project` / `google_cloud_location` |
  | `google-vertex`      | same GCP creds; routes `gemini-*` models             |
  | `openai-compatible` | `custom_provider.base_url` (required), `custom_provider.api_key` (optional), `custom_provider.model_id`, `custom_provider.extra_headers` |

Configured in `agent.olium` of `vigolium-configs.yaml`. Per-call deadline defaults to 10m (`call_timeout_sec`).

The `openai-compatible` provider speaks the OpenAI Chat Completions wire format and works with any backend that does too — Ollama, OpenRouter, LM Studio, vLLM, Together, Groq, LocalAI, custom proxies. Set `base_url` to the endpoint (`/v1` root or full `/v1/chat/completions` URL — both work); leave `api_key` empty for unauthenticated local servers. `extra_headers` are applied after the standard headers, so they can override `Authorization` for backends that use a non-Bearer scheme.

> **Tool-calling caveat.** OpenAI-style function tools are supported by the wire format but not by every model. Local instruction-tuned models that work well: `qwen2.5-coder`, `llama3.1` instruct, `mistral-nemo`. Smaller models often silently ignore tool definitions and reply in prose. If the agent never calls tools, that's the likely cause — switch to a tool-trained model.

### 2.3 Prompt templates

Markdown files with YAML frontmatter, loaded from (in order):

1. `agent.templates_dir` (config dir)
2. `~/.vigolium/prompts/`
3. Embedded (`public/presets/prompts/` baked into the binary)

Frontmatter declares the **output schema** the agent is expected to produce:

| Schema              | Used by                                  | Parsed into                  |
|---------------------|------------------------------------------|------------------------------|
| `findings`          | code review, triage, audit               | `[]AgentFinding` → DB        |
| `http_records`      | endpoint discovery                       | `[]AgentHTTPRecord` → DB     |
| `source_analysis`   | swarm source-analysis phase              | `SourceAnalysisResult`       |
| `attack_plan` / `swarm_plan` | swarm plan + extension phases   | `SwarmPlan`                  |
| `triage_result`     | swarm triage phase                       | `TriageResult`               |

Templates render against `TemplateData` (`pkg/agent/agenttypes/types.go`), which carries: source code snippets, directory tree, target URL, hostname, previous findings (DB), discovered endpoints (DB), module list/tags, scan stats, and a free-form `Extra` map for orchestrator-injected hints.

---

## 3. Swarm pipeline

`vigolium agent swarm --target ... [--source ...]` runs a state-machine pipeline. Each step implements `swarmPhaseStep.Run(ctx, *swarmPipelineState)`.

```
        ┌────────────────────────────────────────────────────┐
        │                  agent swarm                       │
        └────────────────────────────────────────────────────┘
                                 │
                                 ▼
   ┌─────────────────────┐
   │ native-normalize    │  parse curl/raw HTTP/Burp/URL → records
   └──────────┬──────────┘
              ▼
   ┌─────────────────────┐
   │ auth (optional)     │  browser-based login (--browser-auth + --browser)
   └──────────┬──────────┘
              ▼
   ┌─────────────────────┐
   │ source-analysis (AI)│  if --source: parallel explore + format
   │                     │  emits routes, session-config, source extensions
   └──────────┬──────────┘
              ▼
   ┌─────────────────────┐
   │ code-audit (AI)     │  optional code-level audit (--code-audit)
   └──────────┬──────────┘
              ▼
   ┌─────────────────────┐
   │ native-discover     │  optional crawl/spidering (--discover or deep)
   └──────────┬──────────┘
              ▼
   ┌─────────────────────┐
   │ plan (AI)           │  master agent picks modules + extensions
   │                     │  batched (5 records/batch) for large input sets
   └──────────┬──────────┘
              ▼
   ┌─────────────────────┐
   │ native-extension    │  compile/validate JS extensions (Sobek)
   │                     │  LLM repair on syntax errors (max 5 in parallel)
   └──────────┬──────────┘
              ▼
   ┌─────────────────────┐
   │ native-scan         │  ScanFunc: native modules + custom extensions
   └──────────┬──────────┘
              ▼
   ┌─────────────────────┐
   │ triage (AI) ────────┼──→ rescan? loop up to MaxIterations
   └──────────┬──────────┘     (re-runs native-scan with targeted modules)
              ▼
   ┌─────────────────────┐
   │ finalize            │  aggregate results, token usage, DB update
   └─────────────────────┘
```

Phase names prefixed `native-` are pure-Go (no LLM). The pipeline is gated by:

- `--only` / `--skip` / `--start-from` flags (with legacy aliases via `NormalizeSwarmPhase`)
- intensity preset (`SwarmPresets[Quick|Balanced|Deep]` in `agenttypes/constants.go`)
- `cfg.SourcePath` — empty source skips source-analysis and code-audit
- `cfg.Discover`, `cfg.CodeAudit`, `cfg.Triage` toggles
- checkpoint resume — `--resume <session-dir>` skips already-completed phases

A parallel **vigolium-audit** subprocess can run in the background (`cfg.Audit != ""`) when source is provided, contributing source-code audit findings without blocking the swarm.

### Plan & extension phases

The master agent receives input records (chunked into `MasterBatchSize`, default 5) and returns a `SwarmPlan`:

```go
SwarmPlan {
    ModuleTags / ModuleIDs        // which native modules to enable
    Extensions []GeneratedExtension // custom JS extensions (full source)
    QuickChecks []QuickCheck       // shorthand → expanded JS by extensions/quickcheck_gen.go
    FocusAreas / Snippets / Hints  // free-form guidance
}
```

The extension phase compiles every JS extension through the Sobek engine. Syntax errors trigger `RepairExtensionsWithLLM()`, which fans out repair calls (max 5 parallel). Surviving extensions are written to `<session>/extensions/` with sanitized filenames; an `extensionRenames` map preserves original→renamed mapping for downstream result attribution.

### Triage loop

After the native scan, if findings exist and triage is enabled, the triage agent receives a fixture (truncated by detail tiers — 15 full-detail / 40 table-with-top-10 / etc.) and emits:

```go
TriageResult {
    Confirmed []Finding
    FalsePositive []Finding
    FollowUpScans []FollowUpScan  // optional rescans (modules + URLs)
}
```

If `FollowUpScans` is non-empty and rescan is enabled, the pipeline loops back to `native-scan` with targeted modules. Loop bounded by `MaxIterations` (default 3); early-exits when all findings have "certain" confidence.

---

## 4. Autopilot pipeline

`vigolium agent autopilot --target ... [--source ...]` is simpler — no plan/extension phases. The agent itself decides what to run.

```
   ┌─────────────────────────────────────────────┐
   │ audit (optional, foreground)               │
   │   if --source: run vigolium-audit, freeze     │
   │   findings into vigolium-results/ directory     │
   └─────────────────┬───────────────────────────┘
                     ▼
   ┌─────────────────────────────────────────────┐
   │ Context preparation                         │
   │   - load frozen audit findings             │
   │   - prepareAutopilotAuth → AuthHeaders      │
   │   - buildAutopilotContextBundle             │
   │     (routes, auth flows, browser decision)  │
   │   - buildAutopilotPlan                      │
   │     (budgets, tasks, stop criteria)         │
   └─────────────────┬───────────────────────────┘
                     ▼
   ┌─────────────────────────────────────────────┐
   │ Autonomous operator (AI)                    │
   │   olium engine with full tool access:       │
   │     Bash, Read, Grep, Glob, Edit, Write,    │
   │     vigolium scan-url, vigolium findings,   │
   │     vigolium traffic, etc.                  │
   │   bounded by MaxCommands + Timeout          │
   └─────────────────┬───────────────────────────┘
                     ▼
   ┌─────────────────────────────────────────────┐
   │ Verification                                │
   │   verifyAutopilotArtifacts → confirmed      │
   │   findings; degraded flag if warnings       │
   └─────────────────────────────────────────────┘
```

Effort level (`low`/`medium`) is picked from audit mode: `balanced`/`deep` audit → `medium` effort, else `low`. The operator stream is captured to `<session>/output.md`.

### Intensity presets (autopilot)

| Intensity | MaxCommands | Timeout | Audit mode | Browser |
|-----------|-------------|---------|-------------|---------|
| quick     | 30          | 1h      | lite        | off     |
| balanced  | 100         | 6h      | balanced    | off     |
| deep      | 300         | 12h     | deep        | on      |

---

## 5. Session directories

Every swarm and autopilot run writes a session dir under `agent.sessions_dir` (default `~/.vigolium/agent-sessions/<run-uuid>/`). Layout:

```
<session>/
├── checkpoint.json         # swarm: completed phases, record stats, last triage round
├── plan.json               # serialized SwarmPlan
├── session-config.json     # auth session definitions (login flows, token rules)
├── extensions/             # compiled JS extensions (sanitized filenames)
├── vigolium-results/         # audit subprocess output (audit-state.json + findings)
├── master-prompt.md        # rendered prompt sent to master agent (debug)
├── source-analysis-prompt.md
├── output.md               # autopilot: agent stream / final transcript
├── output.txt              # query: raw agent output
├── inputs.json             # normalized input records
└── skills/                 # copied embedded skills (vigolium-scanner, agent-browser)
```

`EnsureSessionDir(baseDir, agenticScanUUID)` in `pipeline_types.go` is the canonical creator.

---

## 6. Configuration

All agent settings live under `agent` in `vigolium-configs.yaml`:

```yaml
agent:
  default_agent: olium
  templates_dir: ~/.vigolium/prompts
  sessions_dir: ~/.vigolium/agent-sessions
  context_limits:
    max_findings: 50
    max_endpoints: 100
    max_high_risk: 20
    min_risk_score: 50
  olium:
    provider: openai-codex-oauth          # or anthropic-api-key | openai-api-key | anthropic-oauth | anthropic-cli | anthropic-vertex | google-vertex | openai-compatible
    model: gpt-5.5                 # provider default if empty
    oauth_cred_path: ~/.codex/auth.json
    llm_api_key: ${ANTHROPIC_API_KEY}
    reasoning_effort: medium
    max_tokens: 1000000
    max_turns: 32
    max_concurrent: 4              # global cap on in-flight provider calls
    call_timeout_sec: 600          # per-call deadline; -1 = no timeout
    custom_provider:               # only used when provider == openai-compatible
      base_url: http://localhost:11434/v1    # Ollama default; OpenRouter / LM Studio / vLLM also work
      model_id: gemma4:latest                # fallback for olium.model and --model
      api_key: ""                            # optional; empty = no Authorization header
      extra_headers:                         # optional; applied after standard headers
        # X-Provider: custom
  audit:
    # …
  browser:
    # optional agent-browser integration
```

CLI flags (`--provider`, `--model`, `--oauth-token`, `--llm-api-key`, `--base-url`) override the config at runtime.

---

## 7. Where things live

| What                          | Where                                           |
|-------------------------------|-------------------------------------------------|
| Subcommand wiring             | `pkg/cli/agent*.go`                             |
| Swarm orchestrator            | `pkg/agent/swarm.go`, `swarm_pipeline.go`       |
| Autopilot orchestrator        | `pkg/agent/autopilot_pipeline.go`               |
| Audit audit runner           | `pkg/agent/audit_agent.go`                      |
| Engine (prompt → dispatch)    | `pkg/agent/engine.go`                           |
| Prompt templates / rendering  | `pkg/agent/prompt/`, `public/presets/prompts/`  |
| Output parsers (JSON-tolerant)| `pkg/agent/parsing/`                            |
| Olium runtime                 | `pkg/olium/engine`, `tool`, `skill`             |
| Olium providers               | `pkg/olium/provider/`                           |
| Phase constants & presets     | `pkg/agent/agenttypes/constants.go`             |
| Core types                    | `pkg/agent/agenttypes/types.go`                 |
| Public aliases                | `pkg/agent/aliases.go`                          |
| Config schema                 | `internal/config/agent.go`                      |

---

## 8. Quick mental model

- **Engine** turns a prompt template + DB context into a structured result. One LLM call.
- **Orchestrator** sequences many engine calls plus native steps (discovery, scan), checkpoints state, and writes a session directory.
- **Olium** is the agent runtime — it holds conversation state and dispatches to a provider. One olium engine can serve many engine calls cheaply (prompt cache hits).
- **Phases** are the unit of resumable work. `--only`, `--skip`, `--start-from`, and `--resume` operate on phase names.
- **Intensity** is a single knob that hydrates a bundle of toggles (commands, timeout, audit mode, discover/audit/triage flags, browser/auth).
