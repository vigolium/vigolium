# Agent Swarm Mode

`vigolium agent swarm` is the AI-guided agentic scan mode. The master agent reads the target's request/response surface (and optionally its source code), picks the right scanner modules, generates custom JavaScript extensions when needed, runs the native scanner, and optionally triages the results in a verify-and-rescan loop.

It sits between two extremes: it is more **directed** than `autopilot` (which
gives the olium operator broad tool access) and more **flexible** than a
hand-tuned `vigolium scan` (modules and extensions are chosen by the model,
not the user).

This document covers what the pipeline looks like, how data flows between phases, and where the AI / native boundary sits.

---

## 1. When to use swarm

| Scenario | Use |
|---|---|
| You have a target URL, raw request, or HTTP record and want the agent to pick modules + write payloads | `swarm` |
| You also have the application source — want routes + auth + extensions inferred from code | `swarm --source <path>` |
| You want false-positive verification and targeted re-scans on the model's say-so | `swarm --triage` |
| You'd rather hand the agent a shell + the codebase and let it decide everything | `autopilot` |
| You want a one-shot prompt with no scanning | `agent query` |

Swarm is the right mode when you want the AI to **drive the native scanner**, not replace it.

---

## 2. Pipeline at a glance

The pipeline runs in strict order. Each phase is either **native**
(deterministic Go) or **AI** (an olium call). Most phases are conditional.

```
┌────────────────────────────────────────────────────────────────────────────┐
│                          swarm pipeline                                     │
│                                                                             │
│  [N] native-normalize ─────────────────────────────── always                │
│         │                                                                   │
│  [A] auth ─────────────────────────── if --browser-auth                     │
│         │                                                                   │
│  [A] source-analysis ─────────────── if --source  (4-call wave)             │
│  [A] code-audit ──────────────────── if --code-audit and --source           │
│         │                                                                   │
│  [N] native-discover ─────────────── if --discover                          │
│  [N] native-recon ────────────────── live stack probe without source facts │
│         │                                                                   │
│  [A] plan         ────────────────── always (master agent, may batch)       │
│  [N] native-discover-reentry ─────── probe planner-only untested paths     │
│  [N] native-extension ────────────── if plan declared extensions            │
│  [N] native-scan  ────────────────── always (hands off to scanner)          │
│  [A] replan-on-empty ─────────────── supplemental pass when signal is empty│
│         │                                                                   │
│  [A] triage       ────────────────── if --triage                            │
│  [N] native-rescan ───────────────── per round, when triage requests it     │
│         │                                                                   │
│  [N] finalize     ────────────────── always                                 │
└────────────────────────────────────────────────────────────────────────────┘

[A] = AI call    [N] = native Go
```

Phase constants: `pkg/agent/agenttypes/constants.go:52-61`. Phase ordering and dispatch: `pkg/agent/swarm_pipeline.go`.

---

## 3. Data flow

The pipeline is driven by a single `swarmPipelineState` (`pkg/agent/swarm_pipeline.go:24-44`) that all phases read from and write to. The two main payloads that move through it are **records** (HTTP request/response pairs) and the **plan** (module selection + extensions spec).

```
                 ┌────────────────────┐
   inputs ──────►│  normalize         │──► []*HttpRequestResponse
   (curl/HTTP/   └────────────────────┘            │
    burp/url/                                      │
    record uuid/                                   ▼
    stdin)                              ┌────────────────────┐
                                        │ source-analysis    │ if --source
                                        │  (4-call wave)     │──► +routes
                       ┌────────────────┤                    │   +session_cfg
                       │                │                    │   +extensions
                       │                └────────────────────┘
                       │                          │
                       │                          ▼
                       │                ┌────────────────────┐
                       │                │ native-discover    │ if --discover
                       │                └────────────────────┘
                       │                          │
                       │                          ▼   merged []records
                       │                ┌────────────────────┐
                       │                │  plan (master)     │
                       │                │  - select modules  │
                       │                │  - focus areas     │
                       │                │  - extensions spec │
                       │                └────────────────────┘
                       │                          │
                       │                          ▼ SwarmPlan
                       │                ┌────────────────────┐
                       │                │ extension          │
                       │                │ validate + persist │
                       │                └────────────────────┘
                       │                          │
                       │                          ▼ extensions/*.js
                       │                ┌────────────────────┐
                       └───────────────►│ native-scan        │
                            ScanFunc    │ runner.RunNative…  │
                          (callback)    └────────────────────┘
                                                  │
                                                  ▼ findings → DB
                                        ┌────────────────────┐
                                        │ triage (loop)      │ if --triage
                                        │ verdict per finding│
                                        │ + rescan request   │
                                        └────────────────────┘
                                                  │
                                                  ▼
                                        ┌────────────────────┐
                                        │ finalize           │
                                        │ aggregate results  │
                                        └────────────────────┘
```

Records grow as the pipeline runs: source analysis appends discovered routes, and native discovery merges crawl/spider results before planning. The plan, once produced, is the single source of truth for what the native scanner will run.

---

## 4. Phase reference

| # | Phase | Type | Purpose | Trigger |
|---|---|---|---|---|
| 1 | `native-normalize` | Native | Parse `--input`/stdin/record-uuid into `HttpRequestResponse` | Always |
| 2 | `auth` | AI/Native | Browser-driven login, writes auth headers/cookies | `--browser-auth` and enabled browser integration |
| 3 | `source-analysis` | AI | 4-call wave: explore → routes / session / extensions | `--source` |
| 4 | `code-audit` | AI | Code-level security audit, findings → DB | `--code-audit` (auto when `--source` at balanced/deep) |
| 5 | `native-discover` | Native | Crawl/spider/JS-scan to discover endpoints | `--discover` |
| 6 | `native-recon` | Native | GET-only technology probe | No usable source-analysis result |
| 7 | `plan` | AI | Pick modules, focus areas, and extension work | Always |
| 8 | `native-discover-reentry` | Native | Probe up to eight planner-referenced paths not yet tested | Planner names untested paths |
| 9 | `native-extension` | Native | Validate generated JS and persist it | Plan declares extensions |
| 10 | `native-scan` | Native | Hand off to the standard native runner | Always |
| 11 | `replan-on-empty` | AI | Try a supplemental business-logic plan | No findings but useful signal remains |
| 12 | `triage` | AI | Verify findings; mark confirmed / FP / rescan | Enabled by preset or `--triage` |
| 13 | `native-rescan` | Native | Targeted dynamic-assessment rerun | Triage asks for a rescan |

Step dispatch lives in `pkg/agent/swarm_pipeline.go`. Use `--skip` to omit
work and `--start-from` to begin a new invocation at a later phase. Swarm does
not expose a public checkpoint-resume flag.

---

## 5. Source-aware mode: the 4-call wave

When `--source <path>` is given, source analysis runs as a single explore call followed by three parallel format calls (`pkg/agent/engine.go:356-369`).

```
                 ┌──────────────────────────────────┐
                 │ Call 1  swarm-source-explore     │
                 │ reads source once → notes:       │
                 │   • routes notes                 │
                 │   • auth notes                   │
                 └────────────────┬─────────────────┘
                                  │ session history reused
                                  │ (provider-cached, not resent in full)
              ┌───────────────────┼───────────────────┐
              ▼                   ▼                   ▼
   ┌────────────────────┐ ┌────────────────────┐ ┌──────────────────────┐
   │ Call 2a            │ │ Call 2b            │ │ Call 3               │
   │ format-routes      │ │ format-session     │ │ source-extensions    │
   │ notes → JSONL      │ │ notes →            │ │ notes → JS files     │
   │ http_records       │ │ session_config     │ │                      │
   └────────────────────┘ └────────────────────┘ └──────────────────────┘
              │                   │                   │
              └─────────────┬─────┴───────┬───────────┘
                            ▼             ▼
                    appended to     written to
                    ps.records      auth-config.yaml
```

Why split it this way: explore output is large (capped at 64 KB, `engine.go:465-469`), per-topic format calls only see a 48 KB slice (`engine.go:481-489`). Provider session caching keeps the explore context cheap to reuse across the three follow-ups instead of re-paying for it.

The discovered session config can come back malformed; the engine round-trips invalid entries through the LLM for repair (`swarm_pipeline.go:293-317`) before hydration into auth headers (`swarm_pipeline.go:429-479`) and persistence to `auth-config.yaml`.

---

## 6. Master agent and batching

The `plan` phase is two sub-calls:

1. **Plan agent** (`swarm.go:737-826`) — analyses the records, returns a `SwarmPlan` with module tags/IDs, focus areas, and an extensions spec. Markdown-section output, retried up to `MaxMasterRetries` (default 3) on parse or transient errors.
2. **Extension agent** (conditional) — only fires if the plan declared extensions. Generates JS scanner code. If this call fails, the plan from step 1 is still valid (graceful degradation).

When `len(records) > MasterBatchSize` (default 5; `agenttypes/constants.go:300`), planning fans out:

```
   records ─► partition into batches of MasterBatchSize
                   │
                   ├─► batch 1 ┐
                   ├─► batch 2 │  parallel, bounded by BatchConcurrency
                   ├─► batch 3 │  goroutines via errgroup
                   └─► batch N ┘
                                  ▼
                          plan_1, plan_2, … plan_N
                                  ▼
                         merge once at the end
                          • module tags/IDs: set union
                          • focus areas: deduplicated
                          • extensions: merged by filename;
                            collisions with different code → renamed
                          • provenance: which batch contributed what
                                  ▼
                              SwarmPlan
```

Implementation: `pkg/agent/swarm.go:1374-1611`. The first batch error cancels the rest; partial-success merge is only attempted if the caller chooses to continue.

When records are filtered for the prompt, a compact summary table of all endpoints is appended so the agent still sees the full surface even if only the top-N have full headers/bodies (`swarm.go:602-627`).

---

## 7. Triage and rescan loop

Triage is preset-driven: `quick` disables it, while the default `balanced`
and `deep` presets enable it. An explicit `--triage=false` overrides those
presets.

```
   for round in 1..MaxIterations:
       ┌──────────────────────────────────┐
       │  query findings from DB           │  filter by severity / module
       │  (resume from last_finding_id)    │
       └─────────────┬────────────────────┘
                     ▼
       ┌──────────────────────────────────┐
       │  triage agent (AI)                │  per finding:
       │                                   │   confirmed | false-positive | rescan
       └─────────────┬────────────────────┘
                     ▼
            verdict == rescan?
              │              │
              │ yes          │ done / no-rescan
              ▼              ▼
       ┌──────────────┐    break
       │ native-rescan│
       │ OnlyPhase =  │
       │ dynamic-     │
       │ assessment   │
       └──────┬───────┘
              ▼
       checkpoint round, continue
```

`MaxIterations` defaults to 1 (`quick`), 3 (`balanced`), or 5 (`deep`).
Triage processes findings in batches and may request targeted rescans.

Rescans set `IsRescan=true` on the `ScanRequest`, which forces `OnlyPhase = "dynamic-assessment"` and `SkipIngestion = true` so only the targeted modules execute (`agent_swarm.go:732-750`).

---

## 8. Native scanner handoff

The swarm runner does not call modules itself — it hands off via callbacks the CLI installs on `SwarmConfig`:

| Callback | Set when | What it does |
|---|---|---|
| `ScanFunc` | always | Runs `runner.RunNativeScan()` with modules/extensions from the plan |
| `DiscoverFunc` | `--discover` | Crawl/spider/JS-scan; merges discovered records before planning |
| `SourceAnalysisCallback` | `--source` | Writes `auth-config.yaml` from session config |

`ScanFunc` is built in `pkg/cli/agent_swarm.go:714-776`:

```go
opts.Modules     = ResolveModulesFromPlan(req.ModuleTags, req.ModuleIDs)
opts.AuthConfigs = []string{generatedAuthConfigYAML} // from source analysis
opts.AuthConfigBestEffort = true                     // tolerate partial AI output
if req.IsRescan {
    opts.OnlyPhase     = "dynamic-assessment"
    opts.SkipIngestion = true
}
runner := runner.New(opts)
return runner.RunNativeScan()
```

This is the AI / native boundary: everything above is AI-shaped (prompt, plan, JS code, verdicts), everything below this call is the standard executor (`pkg/core/executor.go`) running the registered modules.

---

## 9. Session artifacts and checkpoints

A swarm run creates a session directory (default `~/.vigolium/agent-sessions/<run-id>/`):

```
<sessionDir>/
├── swarm-plan.json            ← merged SwarmPlan from master agent
├── checkpoint.json            ← phase progress, plan, triage round
├── source-analysis-prompt.md
├── source-analysis-output.md
├── source-analysis-sections.json
├── source-extensions.json
├── auth-config.yaml           ← hydrated from session_config
├── code-audit-{prompt,output}.md
├── master-{prompt,output}.md
├── auth-{prompt,output}.md
├── extensions/*.js            ← validated, persisted
├── triage/triage-round-N-{prompt,output}.md
├── transcript-*.jsonl         ← per-call Pi-compatible olium transcripts
└── runtime.log                ← tee'd LLM stream; replay with `vigolium log`
```

`checkpoint.json` is rewritten after phases for diagnostics and internal
recovery. There is no public Swarm `--resume` flag. `--start-from` creates a
new run with preceding phase names marked complete; it does not attach to an
old run or recover that run's artifacts.

---

## 10. CLI cheat sheet

```bash
# Minimum: target only — model picks modules from probed responses
vigolium agent swarm --target https://app.example.com

# Source-aware: 4-call source analysis + code audit
vigolium agent swarm --target https://app.example.com --source ./repo

# With triage and rescans (verifies findings, retries)
vigolium agent swarm --target https://… --triage --max-iterations 3

# Use a preset
vigolium agent swarm --target https://… --intensity deep

# Start a new invocation at a specific phase
vigolium agent swarm --target https://app.example.com --start-from plan

# Render prompts without calling the LLM
vigolium agent swarm --target https://… --dry-run --show-prompt
```

Important flags (`pkg/cli/agent_swarm.go:24-71`):

| Flag | Effect |
|---|---|
| `--target, -t` | Target URL for dynamic phases |
| `--input` | Raw input (curl, HTTP, Burp XML, base64, URL) — auto-detected |
| `--source` | Source-code path; enables source analysis + code-audit |
| `--code-audit` | Force code audit (auto-on with `--source` for balanced/deep) |
| `--discover` | Run native discovery before planning |
| `--triage` | Enable verify-and-rescan loop |
| `--max-iterations` | Triage rounds (preset-driven default) |
| `--master-batch-size` | Records per master-agent batch (default 5) |
| `--batch-concurrency` | Parallel master batches (`0` falls back to 3; presets use 2/3/5) |
| `--intensity` | `quick` / `balanced` / `deep` preset bundle |
| `--skip`, `--start-from` | Skip work or start a new run at a phase |
| `--source-analysis-only` | Stop after source analysis |

Intensity preset table: `pkg/agent/agenttypes/constants.go:292-338`.

---

## 11. Where things live

| Concern | File |
|---|---|
| CLI flags + callback wiring | `pkg/cli/agent_swarm.go` |
| Phase dispatch + state | `pkg/agent/swarm_pipeline.go` |
| Master agent, batching, triage | `pkg/agent/swarm.go` |
| 4-call source analysis | `pkg/agent/engine.go` (`RunSourceAnalysisParallel`) |
| Phase constants + presets | `pkg/agent/agenttypes/constants.go` |
| Native scanner entry | `pkg/core/executor.go`, `internal/runner/runner.go` |

For the broader architecture (olium runtime, providers, common engine), see [`architecture/agentic-scan.md`](../architecture/agentic-scan.md).
