# Agent Pipeline

Pipeline is a **fixed 7-phase scanning workflow** where native Go code does the heavy lifting and AI agents only intervene at three strategic checkpoints (source analysis, planning, and triage).

## CLI Usage

```bash
vigolium agent pipeline -t https://target.com
```

### Source-Aware Scanning

When `--source` is provided, Phase 0 (Source Analysis) runs an AI agent to analyze the application source code before any network scanning begins. The agent extracts routes, generates session configuration, and writes custom scanner extensions:

```bash
vigolium agent pipeline -t http://localhost:3000 --source ~/projects/juice-shop
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-t, --target` | (required) | Target URL |
| `--agent` | from config | Agent backend name |
| `--source` | — | Path to application source code for source-aware scanning |
| `--files` | — | Specific files to include (relative to `--source`) |
| `--focus` | — | Focus area hint for the planning agent |
| `--timeout` | 1h | Overall timeout |
| `--max-rescan-rounds` | 2 | Max triage->rescan iterations |
| `--skip-phase` | — | Skip specific phases |
| `--start-from` | — | Resume from a specific phase |
| `--profile` | — | Scanning profile name |
| `--dry-run` | false | Render prompts without executing |

> **Note:** `--repo` is accepted as a deprecated alias for `--source`.

## Phase Overview

```
Phase 0: Source Analysis  (AI Checkpoint)   — Extract routes, session config, extensions from source code
Phase 1: Discover         (Native)          — Content discovery + spidering
Phase 2: Plan             (AI Checkpoint)   — Agent selects modules and prioritizes targets
Phase 3: Scan             (Native)          — Dynamic assessment with selected modules
Phase 4: Triage           (AI Checkpoint)   — Agent classifies findings
Phase 5: Rescan           (Native, Loop)    — Targeted rescan based on triage follow-ups
Phase 6: Report           (Native)          — Aggregate results
```

Phase 0 is **automatically skipped** when `--source` is not provided.

## Step-by-Step Flow

### Initialization (`pkg/cli/agent_pipeline.go`)

- Builds `PipelineConfig` with **callback functions** for native phases
- Wires `SourceAnalysisCallback` to handle generated extensions and session config
- Phase resolution via `resolvePhases()` respects `--skip-phase` and `--start-from`
- Automatically removes `rescan` if `triage` is skipped
- Automatically skips `source-analysis` when no `--source` path is provided
- Calls `PipelineRunner.Run()`

---

### Phase 0: Source Analysis (AI Checkpoint — Conditional)

Only runs when `--source` is provided. Engine enriches prompt template (`pipeline-source-analysis.md`) with:

- `TargetURL` — target URL for constructing full endpoint URLs
- `Hostname` — extracted from target URL
- `SourceCode` — collected source files from `--source` path
- `Language` — auto-detected from file extensions
- `Framework` — if provided via config

Agent returns a **SourceAnalysisResult** JSON with three outputs:

#### 1. HTTP Records (Route Extraction)

The agent extracts every route/endpoint from the source code and produces fully-formed HTTP requests with correct methods, paths, headers, parameter names, and realistic body values:

```json
{
  "http_records": [
    {
      "method": "POST",
      "url": "http://localhost:3000/api/Users",
      "headers": {"Content-Type": "application/json"},
      "body": "{\"email\":\"test@test.com\",\"password\":\"testtest\",\"passwordRepeat\":\"testtest\"}",
      "notes": "User registration endpoint"
    }
  ]
}
```

These records are **ingested into the database** with source `"source-analysis"`, providing seed requests for Phase 1 (Discover) and Phase 2 (Plan).

#### 2. Session Configuration (Auth Flow Discovery)

The agent analyzes authentication code and generates a session config YAML compatible with `--auth-config`:

```json
{
  "session_config": {
    "sessions": [
      {
        "name": "default_user",
        "role": "primary",
        "login": {
          "url": "http://localhost:3000/rest/user/login",
          "method": "POST",
          "content_type": "application/json",
          "body": "{\"email\":\"test@test.com\",\"password\":\"testpassword\"}",
          "extract": [
            {
              "source": "json",
              "path": "$.authentication.token",
              "apply_as": "Authorization: Bearer {value}"
            }
          ]
        }
      }
    ]
  }
}
```

The callback writes this to a temp YAML file and passes it to subsequent scan phases via `opts.AuthConfigPath`, enabling **authenticated scanning** throughout the pipeline.

#### 3. Custom Extensions (Vulnerability-Targeted Scanners)

For each dangerous code pattern (sink) the agent identifies, it generates a JavaScript extension:

```json
{
  "extensions": [
    {
      "filename": "agent-sqli-users.js",
      "code": "module.exports = { id: 'agent-sqli-users', ... };",
      "reason": "Raw SQL concatenation found in models/user.js:42"
    }
  ]
}
```

The callback writes these to a temp directory and adds it to `settings.DynamicAssessment.Extensions.CustomDir`, so they are **loaded by the scanner in Phase 3** alongside built-in modules.

**Cleanup:** Temp extension directory and auth config file are removed when the pipeline exits.

---

### Phase 1: Discover (Native — No AI)

```go
opts.OnlyPhase = "discovery"
opts.DiscoverEnabled = true
opts.SpideringEnabled = true
opts.HeuristicsCheck = "basic"
// If Phase 0 generated auth config, it's applied here
if authConfigPath != "" {
    opts.AuthConfigPath = authConfigPath
}
runPipelinePhaseRunner(opts, settings, repo)
```

- Runs the **deparos** discovery engine: content discovery, crawling, JS analysis, fingerprinting
- Populates `http_records` table in the database (complementing Phase 0's seed requests)
- If Phase 0 generated session config, authenticated discovery is used
- Pure Go execution — no AI cost

---

### Phase 2: Plan (AI Checkpoint)

Engine enriches prompt template (`pipeline-plan.md`) with data from the database:

- `DiscoveredEndpoints` — last 100 HTTP records (includes Phase 0 seed requests + Phase 1 discoveries)
- `HighRiskEndpoints` — top 20 by risk score (min 50)
- `ModuleList` — JSON of all active/passive modules
- `SourceCode` — if `--source` provided

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
// Auth config and generated extensions are active here
runPipelinePhaseRunner(opts, settings, repo)
```

- Runs dynamic assessment with **only the modules the AI selected** in Phase 2
- **Plus any agent-generated extensions** from Phase 0
- If Phase 0 generated session config, authenticated scanning is used
- Passive modules always run alongside
- Findings saved to database

---

### Phase 4: Triage (AI Checkpoint)

Engine enriches prompt template (`pipeline-triage.md`) with:

- `PreviousFindings` — last 50 findings from DB
- `ScanStats` — aggregated scan statistics
- `DiscoveredEndpoints`
- `SourceCode` — if available (enables cross-referencing findings with source code)

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
- This triage->rescan loop can repeat up to `max-rescan-rounds` times

---

### Phase 6: Report (Native — No AI)

- Queries database for findings aggregated by severity
- Populates the final `PipelineResult`

---

## Output Schemas

### SourceAnalysisResult (Phase 0)

```go
type SourceAnalysisResult struct {
    HTTPRecords   []AgentHTTPRecord    // extracted routes as HTTP requests
    SessionConfig *AgentSessionConfig  // login flow and auth config
    Extensions    []GeneratedExtension // custom JS scanner extensions
}

type AgentSessionConfig struct {
    Sessions []AgentSessionEntry
}

type AgentSessionEntry struct {
    Name    string            // session identity name
    Role    string            // "primary" or "compare"
    Headers map[string]string // static auth headers (alternative to login)
    Login   *AgentLoginFlow   // login-based auth
}

type AgentLoginFlow struct {
    URL         string             // login endpoint URL
    Method      string             // HTTP method
    ContentType string             // request content type
    Body        string             // request body
    Extract     []AgentExtractRule // how to extract token from response
}

type AgentExtractRule struct {
    Source  string // "cookie", "json", "header"
    Name    string // cookie name or header name
    Path    string // JSONPath for json source
    ApplyAs string // header template, e.g. "Authorization: Bearer {value}"
}

type GeneratedExtension struct {
    Filename string // JS filename (e.g. "agent-sqli-users.js")
    Code     string // JavaScript module source
    Reason   string // why this extension was generated
}
```

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
    SourceAnalysis *SourceAnalysisResult // Phase 0 results (nil when --source not used)
    Plan           *AttackPlan
    TriageResults  []*TriageResult       // all triage rounds
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

`ParseAttackPlan()`, `ParseTriageResult()`, and `ParseSourceAnalysisResult()` all support wrapped format (e.g., `{"source_analysis": {...}}`) or direct format.

## Server API

**Endpoint:** `POST /api/agent/run/pipeline`

**Request body:**
```json
{
  "target": "https://target.com",
  "agent": "claude",
  "source": "/path/to/source",
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

> **Backward compatibility:** `repo_path` is accepted as an alias for `source`.

**Response modes:**
- **Streaming (SSE):** Events of type `phase`, `chunk`, `done`, `error`
- **Async (202):** Returns `run_id` for status polling via `GET /api/agent/status/:id`

**Concurrency:** Global mutex allows only 1 agent run at a time (409 Conflict if busy).

## Comparison: Autopilot vs Pipeline

| Aspect | Autopilot | Pipeline |
|--------|-----------|----------|
| **AI involvement** | Continuous — agent controls everything | Minimal — AI only at phases 0, 2, and 4 |
| **Source analysis** | Agent manually explores code and runs ingest commands | Structured Phase 0 with typed output (routes, session config, extensions) |
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
| `public/presets/prompts/pipeline/pipeline-source-analysis.md` | Phase 0 template |
| `public/presets/prompts/pipeline/pipeline-plan.md` | Phase 2 template |
| `public/presets/prompts/pipeline/pipeline-triage.md` | Phase 4 template |
