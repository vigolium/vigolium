# Agent Swarm

Swarm is a **multi-agent targeted vulnerability scanning** mode. A master AI agent analyzes a specific HTTP request, selects scanner modules, generates custom attack payloads as JavaScript extensions, executes the scan, and triages the results — all in a single command.

Unlike pipeline (which scans an entire target), swarm focuses on a **single request** and applies deep, targeted analysis to it.

## CLI Usage

```bash
# Target a URL
vigolium agent swarm -t https://example.com/api/users

# Analyze a curl command
vigolium agent swarm --input "curl -X POST https://example.com/api/login -d '{\"user\":\"admin\"}'"

# Pipe raw HTTP request from stdin
echo -e "POST /api/search HTTP/1.1\r\nHost: example.com\r\n\r\nq=test" | vigolium agent swarm --input -

# Scan a record already in the database
vigolium agent swarm --record-uuid 550e8400-e29b-41d4-a716-446655440000

# Focus on a specific vulnerability type
vigolium agent swarm -t https://example.com/api/users --vuln-type sqli

# Specify modules explicitly
vigolium agent swarm -t https://example.com/api/search -m xss-reflected,xss-stored

# Preview what the master agent would receive
vigolium agent swarm -t https://example.com/api/users --dry-run
```

### Supported Input Types

Inputs are auto-detected from their content:

| Type | Example | Detection |
|------|---------|-----------|
| **URL** | `https://example.com/api/users` | Starts with `http://` or `https://` |
| **Curl** | `curl -X POST https://...` | Starts with `curl ` |
| **Raw HTTP** | `POST /api HTTP/1.1\r\n...` | Starts with HTTP method + path |
| **Burp XML** | `<?xml...><items>...</items>` | Starts with `<?xml` or `<items` |
| **Record UUID** | `550e8400-e29b-...` | Matches UUID format (8-4-4-4-12 hex) |

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-t, --target` | — | Target URL |
| `--input` | — | Raw input (curl command, raw HTTP, Burp XML). Use `-` for stdin |
| `--record-uuid` | — | HTTP record UUID from database |
| `--vuln-type` | — | Vulnerability type focus (e.g., `sqli`, `xss`, `ssrf`) |
| `-m, --modules` | — | Explicit module names to include alongside agent selections |
| `--max-iterations` | 3 | Maximum triage-rescan iterations |
| `--agent` | from config | Agent backend to use |
| `--timeout` | 15m | Maximum swarm duration |
| `--profile` | — | Scanning profile to use |
| `--dry-run` | false | Render prompts without executing |

At least one input is required: `--target`, `--input`, or `--record-uuid`. Multiple inputs can be combined (e.g., `--target` + `--input`) for flows that require multiple requests (like login + protected endpoint).

## Phase Overview

```
Phase 1: Normalize    — Parse input(s) into HttpRequestResponse objects
Phase 2: Plan         — Master agent analyzes request, selects modules, generates extensions
Phase 3: Extension    — Write generated JS extensions to temp directory
Phase 4: Scan         — Dynamic assessment with selected modules + extensions
Phase 5: Triage       — Agent reviews extension-generated findings
Phase 6: Rescan       — Targeted rescan based on triage follow-ups (loop)
```

The triage→rescan loop (phases 5-6) repeats until the agent sets verdict to `"done"`, there are no follow-ups, or `--max-iterations` is reached.

## Step-by-Step Flow

### Phase 1: Normalize

Input strings are converted to `HttpRequestResponse` objects using deterministic format detection (no AI needed):

- **URL** → `httpmsg.GetRawRequestFromURL()` generates a GET request
- **Curl** → Parsed using the existing `curl.ParseSingleCommand()` parser (handles `-X`, `-H`, `-d`, `-F`, `-b`, `-u`, `--url`)
- **Raw HTTP** → Parsed directly via `httpmsg.ParseRawRequest()`
- **Burp XML** → Streaming XML decoder extracts `<item>` elements with base64-encoded request/response
- **Record UUID** → Fetched from the `http_records` database table

Normalized records are saved to the database with source `"agent-swarm"`.

### Phase 2: Plan (AI Checkpoint — Master Agent)

The master agent receives the `agent-swarm-master` prompt template with:

| Variable | Content |
|----------|---------|
| `TargetURL` | Extracted from the first normalized record |
| `Hostname` | Derived from target URL |
| `ModuleList` | JSON of all available active/passive scanner modules |
| `Extra.RequestContext` | Full HTTP request/response pairs (responses truncated at 4KB) |
| `Extra.VulnType` | User-specified vulnerability focus (if any) |

The agent analyzes the request surface and returns a **SwarmPlan** JSON:

```json
{
  "module_tags": ["sqli", "injection"],
  "module_ids": ["sqli-error-based"],
  "extensions": [
    {
      "filename": "custom-json-sqli.js",
      "code": "var module = { id: 'custom-json-sqli', ... }; function scan_per_request(ctx) { ... }",
      "reason": "JSON body with user_id parameter susceptible to SQL injection via type juggling"
    }
  ],
  "focus_areas": ["SQL injection in JSON body parameters"],
  "notes": "Target uses JSON API with direct DB queries visible in error responses"
}
```

- `module_tags` (required) — scanner module tags to activate (e.g., `sqli`, `xss`, `ssrf`)
- `module_ids` — specific module IDs to include
- `extensions` — custom JavaScript scanner extensions for payloads the built-in modules won't cover
- `focus_areas` — human-readable description of attack focus
- `notes` — strategy summary

Module tags are resolved against the registry. User-specified `--modules` are merged with agent selections.

### Phase 3: Extension (Write Generated Code)

Each extension from the plan is written to a temporary directory:

```
/tmp/vigolium-swarm-ext-123456/
├── custom-json-sqli.js
├── custom-auth-bypass.js
└── custom-idor-check.js
```

The directory is passed to the scan phase and cleaned up when the swarm exits.

### Phase 4: Scan (Native — No AI)

Dynamic assessment runs with:

- **Only the modules** selected by the master agent (resolved from tags + IDs)
- **Plus the generated extensions** loaded from the temp directory
- **Plus any user-specified modules** from `--modules`
- Passive modules always run alongside

This is pure Go execution — no AI cost.

### Phase 5: Triage (AI Checkpoint)

The triage agent reviews findings, but **only extension-generated findings** — built-in module findings have their own confirmation logic and are reported as-is.

The agent returns a **TriageResult** with confirmed findings, false positives, and optional follow-up scan recommendations.

### Phase 6: Rescan (Conditional Loop)

If the triage verdict is `"rescan"` and follow-ups are recommended, a targeted rescan runs with the suggested modules. The triage→rescan loop continues up to `--max-iterations` times.

## Database Tracking

Every swarm run creates an `agent_runs` database record with:

- Run UUID (`agt-...` prefix)
- Input, input type, target URL
- Status, current phase, timing
- Attack plan and triage results (JSON)
- Finding and record counts
- Error message (on failure)

Records persist for 24 hours (cleaned up by the background DB cleanup loop). Use the agent status API to query run history.

## Server API

**Endpoint:** `POST /api/agent/run/swarm`

**Request body:**

```json
{
  "input": "curl -X POST https://example.com/api/login -H 'Content-Type: application/json' -d '{\"user\":\"admin\",\"pass\":\"test\"}'",
  "vuln_type": "sqli",
  "module_names": ["sqli-error-based"],
  "max_iterations": 3,
  "agent": "claude",
  "stream": true,
  "timeout": "15m",
  "dry_run": false
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `input` | string | Yes* | Single input (URL, curl, raw HTTP, Burp XML, or record UUID) |
| `inputs` | string[] | Yes* | Multiple inputs (for auth flows). Merged with `input` |
| `vuln_type` | string | No | Vulnerability type focus (e.g., `sqli`, `xss`) |
| `module_names` | string[] | No | Explicit module IDs to include |
| `scanning_phase` | string | No | Scan phase to run (default `dynamic-assessment`) |
| `max_iterations` | int | No | Max triage-rescan rounds (default 3) |
| `agent` | string | No | Agent backend name |
| `project_uuid` | string | No | Project UUID for data scoping |
| `scan_uuid` | string | No | Scan UUID to attach findings to |
| `stream` | bool | No | Enable SSE streaming |
| `timeout` | string | No | Go duration string (default `15m`) |
| `dry_run` | bool | No | Render prompts without executing |

\* At least one of `input` or `inputs` must be provided.

**Response modes:**

- **Streaming (SSE):** Real-time events with phase transitions, agent output chunks, and final result
- **Async (202):** Returns `run_id` for status polling via `GET /api/agent/status/:id`

**SSE event types:**

| Event | Description |
|-------|-------------|
| `phase` | Phase transition (`{"type":"phase","phase":"normalize"}`) |
| `chunk` | Real-time text from the agent |
| `done` | Swarm completed (`{"type":"done","swarm_result":{...}}`) |
| `error` | Swarm failed |

**Concurrency:** Global mutex allows only 1 agent run at a time (409 Conflict if busy).

### curl Examples

```bash
# Basic swarm with URL input
curl -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <api-key>" \
  -d '{"input": "https://example.com/api/users?id=1", "vuln_type": "sqli"}'

# Swarm with curl command input and streaming
curl -N http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <api-key>" \
  -d '{
    "input": "curl -X POST https://example.com/api/search -H \"Content-Type: application/json\" -d \"{\\\"query\\\":\\\"test\\\"}\"",
    "stream": true
  }'

# Swarm with record UUID from database
curl -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <api-key>" \
  -d '{"input": "550e8400-e29b-41d4-a716-446655440000"}'

# Check swarm status
curl http://localhost:9002/api/agent/status/<run-id> \
  -H "Authorization: Bearer <api-key>"
```

## Output Schemas

### SwarmPlan (Phase 2)

```go
type SwarmPlan struct {
    ModuleTags []string             // required, >= 1 tag
    ModuleIDs  []string             // specific module IDs
    Extensions []GeneratedExtension // custom JS scanner extensions
    FocusAreas []string             // human-readable attack focus
    Notes      string               // strategy summary
}

type GeneratedExtension struct {
    Filename string // JS filename (e.g. "custom-sqli-json-body.js")
    Code     string // JavaScript module source
    Reason   string // why this extension was generated
}
```

### SwarmResult (Final)

```go
type SwarmResult struct {
    SwarmPlan      *SwarmPlan      // master agent's plan
    TriageResults  []*TriageResult // all triage rounds
    TotalFindings  int             // findings from DB
    Confirmed      int             // confirmed by triage
    FalsePositives int             // rejected by triage
    Iterations     int             // triage rounds completed
    Duration       time.Duration
    AgentRunUUID   string          // DB tracking UUID
}
```

### TriageResult (Phase 5)

```go
type TriageResult struct {
    Confirmed      []TriagedFinding // true positives
    FalsePositives []TriagedFinding // debunked findings
    FollowUps      []FollowUpScan   // rescan recommendations
    Verdict        string           // "done" or "rescan"
    Notes          string
}
```

## Comparison: Swarm vs Pipeline vs Autopilot

| Aspect | Swarm | Pipeline | Autopilot |
|--------|-------|----------|-----------|
| **Scope** | Single request/endpoint | Entire target | Entire target |
| **Input** | URL, curl, raw HTTP, Burp XML, DB record | Target URL | Target URL |
| **AI involvement** | 2-3 calls (plan + triage) | 2-4 calls (source analysis + plan + triage) | Many calls (agent-driven) |
| **Custom payloads** | Yes — generates JS extensions | Only via source analysis (Phase 0) | No |
| **Discovery** | No — works with what you give it | Yes — full deparos + spidering | Yes — agent decides |
| **Triage scope** | Extension findings only | All findings | Agent decides |
| **Default timeout** | 15 minutes | 1 hour | 30 minutes |
| **Best for** | Deep testing of a specific endpoint | Full-scope production scanning | Exploratory research |

**Use `agent swarm`** when you have a specific request you want to attack deeply — the master agent crafts targeted payloads and modules just for that endpoint.

**Use `agent pipeline`** when you need full-scope scanning of an entire target with structured phases.

**Use `agent autopilot`** when you want the AI to explore freely and decide its own approach.

## Key Files

| File | Purpose |
|------|---------|
| `pkg/agent/swarm.go` | Swarm orchestrator (6-phase pipeline) |
| `pkg/agent/input_normalizer.go` | Input type detection and normalization |
| `pkg/agent/input_parsers.go` | Curl and Burp XML parsers |
| `pkg/agent/pipeline_types.go` | Data structures (SwarmPlan, SwarmResult, shared helpers) |
| `pkg/cli/agent_swarm.go` | CLI command definition |
| `pkg/server/handlers_agent.go` | REST API handlers |
| `pkg/database/models.go` | AgentRun model for DB tracking |
| `public/presets/prompts/swarm/agent-swarm-master.md` | Master agent prompt template |
