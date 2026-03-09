# Agent Pipeline

Pipeline is a **fixed 6-phase scanning workflow** where native Go code does the heavy lifting and AI agents only intervene at two strategic checkpoints (planning and triage).

## CLI Usage

```bash
vigolium agent pipeline -t https://target.com
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-t, --target` | (required) | Target URL |
| `--agent` | from config | Agent backend name |
| `--repo` | — | Source code repository path |
| `--files` | — | Specific files to include (relative to repo) |
| `--focus` | — | Focus area hint for the planning agent |
| `--timeout` | 1h | Overall timeout |
| `--max-rescan-rounds` | 2 | Max triage→rescan iterations |
| `--skip-phase` | — | Skip specific phases |
| `--start-from` | — | Resume from a specific phase |
| `--profile` | — | Scanning profile name |
| `--dry-run` | false | Render prompts without executing |

## Phase Overview

```
Phase 1: Discover  (Native)          — Content discovery + spidering
Phase 2: Plan      (AI Checkpoint)   — Agent selects modules and prioritizes targets
Phase 3: Scan      (Native)          — Dynamic assessment with selected modules
Phase 4: Triage    (AI Checkpoint)   — Agent classifies findings
Phase 5: Rescan    (Native, Loop)    — Targeted rescan based on triage follow-ups
Phase 6: Report    (Native)          — Aggregate results
```

## Step-by-Step Flow

### Initialization (`pkg/cli/agent_pipeline.go`)

- Builds `PipelineConfig` with **callback functions** for native phases
- Phase resolution via `resolvePhases()` respects `--skip-phase` and `--start-from`
- Automatically removes `rescan` if `triage` is skipped
- Calls `PipelineRunner.Run()`

---

### Phase 1: Discover (Native — No AI)

```go
opts.OnlyPhase = "discovery"
opts.DiscoverEnabled = true
opts.SpideringEnabled = true
opts.HeuristicsCheck = "basic"
runPipelinePhaseRunner(opts, settings, repo)
```

- Runs the **deparos** discovery engine: content discovery, crawling, JS analysis, fingerprinting
- Populates `http_records` table in the database
- Pure Go execution — no AI cost

---

### Phase 2: Plan (AI Checkpoint)

Engine enriches prompt template (`pipeline-plan.md`) with data from the database:

- `DiscoveredEndpoints` — last 100 HTTP records
- `HighRiskEndpoints` — top 20 by risk score (min 50)
- `ModuleList` — JSON of all active/passive modules
- `SourceCode` — if `--repo` provided

Agent returns an **AttackPlan** JSON:

```json
{
  "module_tags": ["sqli", "xss", "ssrf"],
  "module_ids": [],
  "focus_areas": ["API injection points"],
  "skip_paths": ["/static/", "/assets/"],
  "endpoints": [
    {
      "url": "https://target.com/api/users",
      "method": "POST",
      "priority": "high",
      "rationale": "User input with DB interaction",
      "tags": ["sqli"]
    }
  ],
  "notes": "Focus on authenticated API endpoints"
}
```

**Validation:** Agent-suggested `module_tags` are resolved against the module registry. If none match, falls back to all modules.

---

### Phase 3: Scan (Native — No AI)

```go
opts.OnlyPhase = "dynamic-assessment"
opts.SkipIngestion = true
opts.Modules = resolveModulesFromPlan(plan.ModuleTags, plan.ModuleIDs)
opts.PassiveModules = []string{"all"}  // passive always enabled
runPipelinePhaseRunner(opts, settings, repo)
```

- Runs dynamic assessment with **only the modules the AI selected** in Phase 2
- Passive modules always run alongside
- Findings saved to database

---

### Phase 4: Triage (AI Checkpoint)

Engine enriches prompt template (`pipeline-triage.md`) with:

- `PreviousFindings` — last 50 findings from DB
- `ScanStats` — aggregated scan statistics
- `DiscoveredEndpoints`
- `SourceCode` — if available

Agent returns a **TriageResult** JSON:

```json
{
  "confirmed": [
    {
      "title": "SQL Injection in /api/users",
      "module_id": "sqli_error",
      "url": "https://target.com/api/users",
      "reason": "Error-based response confirmed"
    }
  ],
  "false_positives": [
    {
      "title": "XSS in /search",
      "module_id": "rxss",
      "url": "https://target.com/search",
      "reason": "Output is HTML-encoded"
    }
  ],
  "follow_up_scans": [
    {
      "url": "https://target.com/api/admin",
      "method": "POST",
      "module_tags": ["sqli", "auth"],
      "rationale": "Admin endpoint not yet scanned"
    }
  ],
  "verdict": "rescan",
  "notes": "Admin panel needs deeper testing"
}
```

---

### Phase 5: Rescan (Native, Conditional)

Only runs if **all three conditions** are met:

1. Triage verdict is `"rescan"`
2. `follow_up_scans` is non-empty
3. Current round < `--max-rescan-rounds` (default 2)

Flow:
- Aggregates `module_tags` and `module_ids` from all follow-up recommendations
- Runs targeted scan callback
- **Loops back to Phase 4** for another triage round
- This triage→rescan loop can repeat up to `max-rescan-rounds` times

---

### Phase 6: Report (Native — No AI)

- Queries database for findings aggregated by severity
- Populates the final `PipelineResult`

---

## Output Schemas

### AttackPlan (Phase 2)

```go
type AttackPlan struct {
    ModuleTags []string          // required, >= 1 tag
    ModuleIDs  []string
    FocusAreas []string
    SkipPaths  []string
    Endpoints  []PlannedEndpoint // prioritized targets
    Notes      string
}

type PlannedEndpoint struct {
    URL       string   // required
    Method    string
    Priority  string   // "high", "medium", "low"
    Rationale string
    Tags      []string
}
```

### TriageResult (Phase 4)

```go
type TriageResult struct {
    Confirmed      []TriagedFinding // true positives
    FalsePositives []TriagedFinding // debunked findings
    FollowUps      []FollowUpScan   // rescan recommendations
    Verdict        string           // "done" or "rescan" (required)
    Notes          string
}

type TriagedFinding struct {
    Title    string
    ModuleID string
    URL      string
    Reason   string // explanation for classification
}

type FollowUpScan struct {
    URL        string
    Method     string
    ModuleTags []string
    ModuleIDs  []string
    Rationale  string
}
```

### PipelineResult (Final)

```go
type PipelineResult struct {
    Plan           *AttackPlan
    TriageResults  []*TriageResult  // all triage rounds
    TotalFindings  int
    Confirmed      int
    FalsePositives int
    RescanRounds   int
    PhasesRun      []PipelinePhase
    Duration       time.Duration
}
```

## JSON Parsing Robustness (`pkg/agent/parser.go`)

`extractJSON()` uses a 3-tier strategy:

1. Direct parsing of raw string
2. Strip markdown fences (`` ```json...``` ``)
3. Find first `{` or `[`, extract balanced JSON block

Both `ParseAttackPlan()` and `ParseTriageResult()` support wrapped format `{"plan": {...}}` or direct format.

## Server API

**Endpoint:** `POST /api/agent/run/pipeline`

**Request body:**
```json
{
  "target": "https://target.com",
  "agent": "claude",
  "repo": "/path/to/source",
  "files": ["src/auth.go"],
  "focus": "API injection",
  "timeout": "1h",
  "max_rescan_rounds": 2,
  "skip_phases": ["report"],
  "start_from": "plan",
  "profile": "thorough",
  "stream": true,
  "dry_run": false
}
```

**Response modes:**
- **Streaming (SSE):** Events of type `phase`, `chunk`, `done`, `error`
- **Async (202):** Returns `run_id` for status polling via `GET /api/agent/status/:id`

**Concurrency:** Global mutex allows only 1 agent run at a time (409 Conflict if busy).

## Comparison: Autopilot vs Pipeline

| Aspect | Autopilot | Pipeline |
|--------|-----------|----------|
| **AI involvement** | Continuous — agent controls everything | Minimal — AI only at phases 2 and 4 |
| **Agent autonomy** | Full: decides what to run, when, how many times | Constrained: fixed phase order, structured output |
| **Cost** | High (long agent session) | Low (2-4 short agent calls) |
| **Security model** | Sandbox with allowlisted commands | No sandbox needed — AI never executes commands |
| **Flexibility** | Agent adapts strategy dynamically | Fixed workflow, AI only influences module selection and triage |
| **Default timeout** | 30 minutes | 1 hour |
| **Protocol** | ACP with terminal capability | ACP prompt-response (no terminal) |

## Key Files

| File | Purpose |
|------|---------|
| `pkg/agent/pipeline.go` | Main pipeline orchestrator |
| `pkg/agent/pipeline_types.go` | Data structures + JSON parsing |
| `pkg/cli/agent_pipeline.go` | CLI command definition + callbacks |
| `pkg/server/handlers_agent.go` | REST API handlers |
| `pkg/agent/engine.go` | Prompt building and agent execution |
| `pkg/agent/context.go` | DB context enrichment |
| `pkg/agent/prompt.go` | Template loading/caching/rendering |
| `public/presets/prompts/pipeline/pipeline-plan.md` | Phase 2 template |
| `public/presets/prompts/pipeline/pipeline-triage.md` | Phase 4 template |
