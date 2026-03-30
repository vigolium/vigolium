# Agent Swarm

Swarm is the **primary agentic scan mode** in Vigolium (alongside autopilot). A master AI agent analyzes HTTP requests, selects scanner modules, generates custom attack payloads as JavaScript extensions, executes the scan, and triages the results — all in a single command.

Swarm supports both **targeted single-request scanning** and **full-scope scanning** with `--discover`. When `--discover` is enabled, swarm runs the complete sequence: source analysis, SAST, discovery/spidering, AI planning, native scanning, and triage.

Swarm automatically enables **warm session pooling** for ACP agent backends, reusing subprocesses across the plan and triage phases for faster execution.

When `--source` is provided, swarm runs a **consolidated 4-call source analysis** in 2 waves: a single explore call reads the codebase and documents routes, auth flows, and vulnerability sinks, then three calls run in parallel — format-routes, format-session, and extensions — to produce structured output. When `--code-audit` is enabled (on by default when `--source` is provided), a **deep AI security code audit** identifies business logic flaws, data flow vulnerabilities, and framework misconfigurations that static analysis misses. This is followed by a **native SAST phase** (ast-grep + secret detection) and a **SAST review sub-agent** to validate all findings — before the master agent plans the attack. When `--discover` is enabled, native discovery+spidering expands the attack surface further.

## Architecture Overview

```
                         vigolium agent swarm --input <request>
                                       |
                                       v
              +------------------------------------------------+
              |               CLI Initialization                |
              |  - Parse flags (--input, --vuln-type, etc.)    |
              |  - Resolve --instruction / --instruction-file   |
              |  - Build SwarmConfig with callbacks             |
              |    (ScanFunc, DiscoverFunc, SASTFunc)           |
              |  - Enable warm ACP session pooling              |
              +------------------------------------------------+
                                       |
                                       v
              +------------------------------------------------+
              |             SwarmRunner.Run()                    |
              |  - Create agent_runs DB record (agt-<uuid>)    |
              |  - Create session directory for artifacts       |
              |  - Execute multi-phase pipeline                 |
              +------------------------------------------------+
                                       |
  +------+------+------+------+------+------+------+------+------+------+------+
  |      |      |      |      |      |      |      |      |      |      |      |
  v      v      v      v      v      v      v      v      v      v      v      v
+----+ +----+ +----+ +----+ +----+ +----+ +----+ +----+ +----+ +----+ +----+
| 1  | |1.5 | |1.6| |1.7 | |1.8 | |1.9 | | 2  | | 3  | | 4  | | 5  | |5-6 |
|Norm| |Src | |Code| |SAST| |SAST| |Disc| |Plan| |Ext | |Scan| |Tri | |Re- |
|    | |Anlz| |Aud | |    | |Rev | |over| |    | |    | |    | |age | |scan|
|(Go)| |(AI)| |(AI)| |(Go)| |(AI)| |(Go)| |(AI)| |(Go)| |(Go)| |(AI)| |(Go)|
+----+ +----+ +----+ +----+ +----+ +----+ +----+ +----+ +----+ +----+ +----+
  |      |      |      |      |      |      |      |      |      |      |
  v      v      v      v      v      v      v      v      v      v      v
HTTP   routes  find-  SAST   valid  crawl  Swarm  JS     find-  Triage target
RR     auth    ings   find-  routes HTTP   Plan   files  ings   Result rescan
in DB  exts    in DB  ings   + exts RR            disk   in DB         loop
       config        in DB        in DB
```

Phases 1.5–1.7 are conditional: source analysis runs when `--source` is provided, code-audit runs by default when `--source` is provided (disable with `--code-audit=false`), SAST runs when `--source` is provided, and discovery runs when `--discover` is enabled.

### Detailed Data Flow

```
                              User Input
                     (URL / curl / raw HTTP / Burp XML / UUID)
                                   |
                                   v
  +=======================================================================+
  |  PHASE 1: NORMALIZE (Pure Go — no AI)                                 |
  |                                                                        |
  |   Input string                                                         |
  |     |                                                                  |
  |     +-- URL?      --> httpmsg.GetRawRequestFromURL()  --> GET request  |
  |     +-- curl?     --> curl.ParseSingleCommand()       --> full request |
  |     +-- Raw HTTP? --> httpmsg.ParseRawRequest()       --> parsed req   |
  |     +-- Burp XML? --> XML decoder + base64 decode     --> req+resp     |
  |     +-- UUID?     --> database lookup                 --> stored record|
  |                                                                        |
  |   Output: []*HttpRequestResponse  -->  saved to DB (source: agent-swarm)
  |           targetURL extracted from first record                        |
  +=======================================================================+
                                   |
                                   v
  +=======================================================================+
  |  PHASE 1.5: SOURCE ANALYSIS (AI — conditional, only if --source)      |
  |                                                                        |
  |   Consolidated 4-call approach in 2 waves:                            |
  |                                                                        |
  |   Wave 1 (sequential — reads source code):                           |
  |     Call 1: Explore                                                   |
  |       Template: swarm-source-explore                                  |
  |       One pass through codebase → plain-text notes on routes,         |
  |       auth flows, and vulnerability sinks                             |
  |                                                                        |
  |   Wave 2 (parallel — consumes Wave 1 output):                        |
  |     Call 2a: Format Routes  ─┐                                        |
  |       Template: swarm-source-format-routes                            |
  |       Route notes → JSONL http_records                                |
  |       Reuses warm session from explore (has codebase context)         |
  |                               │                                       |
  |     Call 2b: Format Session  ─┤                                       |
  |       Template: swarm-source-format-session                           |
  |       Auth notes → session_config JSON                                |
  |                               │                                       |
  |     Call 3: Extensions       ─┘                                       |
  |       Template: swarm-source-extensions                               |
  |       Notes → JS scanner extensions                                   |
  |       Explore notes appended to prompt (no source code access needed)|
  |                                                                        |
  |   Without warm sessions, explore output appended to prompts (64KB).  |
  |                                                                        |
  |   Results merged with mutex protection:                                |
  |     +-- HTTP Records  --> filtered by target hostname --> appended    |
  |     +-- Session Config --> auth-config.yaml --> used by scan/discover |
  |     +-- Extensions     --> held for merge with plan extensions        |
  +=======================================================================+
                                   |
                                   v
  +=======================================================================+
  |  PHASE 1.6: CODE AUDIT (AI — on by default when --source provided)  |
  |                                                                        |
  |   Deep security code audit focusing on logic-level vulnerabilities:   |
  |     +-- Business logic flaws (IDOR, race conditions, privilege esc.) |
  |     +-- Auth/authz gaps (missing middleware, JWT issues, OAuth)       |
  |     +-- Data flow vulnerabilities (2nd-order injection, SSTI, deser) |
  |     +-- Framework misconfigurations (CORS, CSRF, debug endpoints)    |
  |                                                                        |
  |   Receives source analysis notes as context (avoids re-reading code) |
  |   Findings saved to DB with module_id="agent-swarm-code-audit"       |
  |   Reviewed by SAST review + triage phases downstream                 |
  +=======================================================================+
                                   |
                                   v
  +=======================================================================+
  |  PHASE 1.7: SAST (Go — conditional, only if --source)                |
  |                                                                        |
  |   Runs native SAST phase via runner:                                   |
  |     +-- ast-grep route extraction (discovers routes from code)        |
  |     +-- Kingfisher secret detection (hardcoded credentials, keys)     |
  |     +-- Third-party tools (semgrep, osv-scanner, CodeQL if available)       |
  |                                                                        |
  |   Findings saved to DB with module_type="sast"                        |
  |   Routes ingested with parameterized path resolution + probing        |
  |                                                                        |
  |   Auth config from source analysis applied for authenticated SAST     |
  +=======================================================================+
                                   |
                                   v
  +=======================================================================+
  |  PHASE 1.8: SAST REVIEW (AI — conditional, after SAST)             |
  |                                                                        |
  |   Prompt template: swarm-sast-review.md                                |
  |                                                                        |
  |   Inputs:                                                              |
  |     +-- SAST findings from DB (module_type="sast", up to 200)        |
  |     +-- Discovered routes from DB (by target hostname)                |
  |     +-- Target URL and hostname                                       |
  |                                                                        |
  |   Agent reviews each SAST finding and:                                 |
  |     1. Validates routes — adds new/corrected routes to http_records   |
  |     2. Assesses finding quality (high/medium/low confidence)          |
  |     3. Generates targeted extensions for dynamic verification         |
  |        (prefixed agent-sast-*, tagged "sast-verified")                |
  |                                                                        |
  |   Output: SourceAnalysisResult                                         |
  |     +-- HTTP Records  --> validated/new routes appended to inputs     |
  |     +-- Extensions    --> merged with source-analysis extensions      |
  +=======================================================================+
                                   |
                                   v
  +=======================================================================+
  |  PHASE 1.9: DISCOVERY (Go — conditional, only if --discover)          |
  |                                                                        |
  |   Runs native discovery + spidering via runner:                        |
  |     +-- Deparos crawling (link extraction, form discovery)            |
  |     +-- JavaScript analysis (jsscan)                                  |
  |     +-- Spidering (dynamic page exploration)                          |
  |                                                                        |
  |   Auth config from source analysis applied for authenticated crawling |
  |   Discovered records queried from DB and deduplicated with existing   |
  +=======================================================================+
                                   |
                                   v
  +=======================================================================+
  |  PHASE 2: PLAN (AI — Master Agent)                                    |
  |                                                                        |
  |   Prompt template: agent-swarm-plan.md                                 |
  |                                                                        |
  |   Template variables:                                                  |
  |     +-- {{.TargetURL}}            target URL                           |
  |     +-- {{.Hostname}}             extracted hostname                   |
  |     +-- {{.ModuleTags}}           available module tags (JSON)         |
  |     +-- {{.Extra.RequestContext}} full HTTP request/response pairs     |
  |     +-- {{.Extra.VulnType}}       --vuln-type value                   |
  |     +-- {{.Extra.Focus}}          --focus value                        |
  |                                                                        |
  |   Appended sections:                                                   |
  |     +-- ## Vulnerability Focus    (if --vuln-type provided)            |
  |     +-- ## Focus Area             (if --focus provided)                |
  |     +-- ## Custom Instructions    (if --instruction provided)          |
  |                                                                        |
  |   Output: SwarmPlan                                                    |
  |     +-- module_tags   ["sqli", "xss"]                                  |
  |     +-- module_ids    ["sqli-error-based"]                             |
  |     +-- extensions    [{filename, code, reason}]                       |
  |     +-- quick_checks  [{id, payloads, match_patterns}]                 |
  |     +-- snippets      [{id, function_body}]                            |
  |     +-- focus_areas   ["SQL injection in JSON body"]                   |
  |     +-- notes         "strategy summary"                               |
  |                                                                        |
  |   Retry: up to 3 attempts on JSON parse failure (with error feedback)  |
  |                                                                        |
  |   Batching: if >5 records, batched (max 5/batch), plans merged         |
  +=======================================================================+
                                   |
                                   v
  +=======================================================================+
  |  PHASE 3: EXTENSION (Pure Go — write generated code to disk)          |
  |                                                                        |
  |   Input: SwarmPlan.Extensions + QuickChecks + Snippets                 |
  |                                                                        |
  |   Processing:                                                          |
  |     +-- QuickChecks --> GenerateQuickCheckExtensions() --> full JS     |
  |     +-- Snippets    --> GenerateSnippetExtensions()    --> full JS     |
  |     +-- Extensions  --> written as-is                                  |
  |                                                                        |
  |   Output: session_dir/extensions/                                      |
  |     +-- custom-json-sqli.js                                            |
  |     +-- qc-auth-bypass.js     (generated from quick_check)            |
  |     +-- snip-idor-check.js    (generated from snippet)                |
  +=======================================================================+
                                   |
                                   v
  +=======================================================================+
  |  PHASE 4: SCAN (Pure Go — native scanner execution)                   |
  |                                                                        |
  |   ScanFunc callback invoked with:                                      |
  |     +-- moduleTags = nil  (all modules on initial scan)                |
  |     +-- moduleIDs  = nil                                               |
  |     +-- extensionDir = path to generated JS extensions                 |
  |     +-- rescan = false                                                 |
  |                                                                        |
  |   Scanner configuration:                                               |
  |     +-- opts.Modules = ["all"]                                         |
  |     +-- opts.PassiveModules = ["all"]                                  |
  |     +-- opts.HeuristicsCheck = "none"                                  |
  |     +-- settings.Audit.Extensions.CustomDir += extensionDir/*.js       |
  |     +-- --only / --skip flags applied if specified                     |
  |                                                                        |
  |   Execution: runner.New(opts) --> RunNativeScan()                     |
  |     +-- Executor distributes requests to modules via worker pool       |
  |     +-- Built-in modules + generated extensions run in parallel        |
  |     +-- Findings saved to DB with module source tags                   |
  +=======================================================================+
                                   |
                                   v
  +=======================================================================+
  |  PHASE 5-6: TRIAGE + RESCAN LOOP                                     |
  |                                                                        |
  |   +---> TRIAGE (AI)                                                    |
  |   |       Prompt: agent-swarm-triage.md                                |
  |   |       Context: PreviousFindings, ScanStats, DiscoveredEndpoints    |
  |   |       Custom instructions appended if provided                     |
  |   |                                                                    |
  |   |       Output: TriageResult                                         |
  |   |         +-- confirmed: [{title, module_id, url, reason}]          |
  |   |         +-- false_positives: [{title, module_id, url, reason}]    |
  |   |         +-- follow_ups: [{url, method, module_tags, rationale}]   |
  |   |         +-- verdict: "done" | "rescan"                            |
  |   |                                                                    |
  |   |     verdict == "rescan"                                            |
  |   |     AND follow_ups non-empty                                       |
  |   |     AND round < max_iterations                                     |
  |   |       |                                                            |
  |   |       v                                                            |
  |   |     RESCAN (Native Go)                                             |
  |   |       +-- opts.OnlyPhase = "audit"                                 |
  |   |       +-- opts.SkipIngestion = true                                |
  |   |       +-- opts.Modules = resolveModules(follow-up tags + IDs)      |
  |   |       +-- ScanFunc(ctx, tags, ids, "", rescan=true)               |
  |   |       |                                                            |
  |   +-------+  (loop back to TRIAGE)                                     |
  |                                                                        |
  |   Exit conditions:                                                     |
  |     +-- verdict == "done"                                              |
  |     +-- no follow_ups                                                  |
  |     +-- round >= max_iterations                                        |
  |     +-- context timeout                                                |
  +=======================================================================+
                                   |
                                   v
              +------------------------------------------------+
              |              Finalize & Report                  |
              |  - Count findings by severity from DB           |
              |  - Update agent_runs record (status, duration)  |
              |  - Return SwarmResult                           |
              +------------------------------------------------+
```

### Component Interaction

```
+-------------------+     +-------------------+     +-------------------+
|   CLI / API       |     |    SwarmRunner     |     |     Engine        |
|                   |     |                   |     |                   |
| - Parse input     |---->| - Orchestrate     |---->| - Load templates  |
| - Build config    |     |   phases          |     | - Render prompts  |
| - Wire callbacks  |     | - Track state     |     | - Spawn ACP agent |
|                   |     | - Save artifacts  |     | - Parse output    |
+-------------------+     +-------------------+     +-------------------+
                                |       |                    |
                                |       |                    v
                                |       |           +-------------------+
                                |       |           |   ACP Session     |
                                |       |           |                   |
                                |       |           | - Warm pool reuse |
                                |       |           | - stdin/stdout    |
                                |       |           | - Prompt/Response |
                                |       |           +-------------------+
                                |       |                    |
                                v       v                    v
                       +-------------------+     +-------------------+
                       |    Database        |     |   AI Agent        |
                       |    (SQLite/PG)     |     |   (Claude, etc.)  |
                       |                   |     |                   |
                       | - http_records    |     | - Analyze request |
                       | - findings        |     | - Select modules  |
                       | - agent_runs      |     | - Generate JS ext |
                       | - scopes          |     | - Triage findings |
                       +-------------------+     +-------------------+
                                ^
                                |
                       +-------------------+
                       |  Scanner Runner    |
                       |                   |
                       | - ScanFunc cb     |
                       | - Executor pool   |
                       | - Module dispatch |
                       | - Extension load  |
                       +-------------------+
```

### Batched Master Agent (>5 inputs)

When the swarm receives more than 5 input records, the master agent is called in batches:

```
  Records: [R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12]
                              |
              +---------------+---------------+
              |               |               |
              v               v               v
         Batch 1          Batch 2          Batch 3
         [R1..R5]         [R6..R10]        [R11..R12]
              |               |               |
              v               v               v
         SwarmPlan A      SwarmPlan B      SwarmPlan C
              |               |               |
              +-------+-------+-------+-------+
                      |               |
                      v               v
              mergeSwarmPlans()
              +-- union of module_tags
              +-- union of module_ids
              +-- union of focus_areas
              +-- extensions: identical code dropped, different code renamed (-2, -3 suffix)
              +-- concatenate notes
              +-- BatchProvenance tracks which batch contributed each item
                      |
                      v
              Merged SwarmPlan --> Phase 3 (Extension)
```

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

# Source-aware: extract routes from code, filter by target, then swarm
vigolium agent swarm -t http://localhost:3000 --source ~/projects/my-app

# Source-aware with specific files and vuln focus
vigolium agent swarm -t http://localhost:8080 --source ./backend \
  --files src/routes/api.js,src/models/user.js --vuln-type sqli

# Source-aware with a Git URL (auto-cloned)
vigolium agent swarm -t https://staging.example.com \
  --source https://github.com/org/repo.git

# Focus on a specific vulnerability type
vigolium agent swarm -t https://example.com/api/users --vuln-type sqli

# Broader focus area hint for the agent
vigolium agent swarm -t https://example.com/api/users --focus "auth bypass"

# Specify modules explicitly
vigolium agent swarm -t https://example.com/api/search -m xss-reflected,xss-stored

# Use a custom ACP agent command (overrides --agent)
vigolium agent swarm -t https://example.com/api/users --agent-acp-cmd "traecli acp"

# Preview what the master agent would receive
vigolium agent swarm -t https://example.com/api/users --dry-run

# Show rendered prompts on stderr while executing
vigolium agent swarm -t https://example.com/api/users --show-prompt

# Run only source analysis (extract routes, auth flows, extensions)
vigolium agent swarm -t http://localhost:3000 --source ~/projects/my-app --source-analysis-only

# Source-aware without code audit (code audit is on by default with --source)
vigolium agent swarm -t http://localhost:3000 --source ~/projects/my-app --code-audit=false

# Source-aware with discovery: SAST + crawling + AI planning
vigolium agent swarm -t http://localhost:3000 --source ~/projects/my-app --discover

# Source-aware without SAST (skip ast-grep, osv-scanner, semgrep)
vigolium agent swarm -t http://localhost:3000 --source ~/projects/my-app --skip-sast

# Full pipeline: source analysis + SAST + discovery + AI swarm
vigolium agent swarm -t https://staging.example.com \
  --source https://github.com/org/repo.git --discover --vuln-type sqli

# Full-scope scanning with focus area
vigolium agent swarm -t https://example.com --discover --focus "API injection"

# Skip specific scan phases
vigolium agent swarm -t https://example.com --discover --skip discovery --skip spidering

# Resume a scan from a specific phase (e.g. skip normalize and source analysis)
vigolium agent swarm -t https://example.com --start-from plan

# Resume from discovery phase (useful after editing source analysis artifacts)
vigolium agent swarm -t http://localhost:3000 --source ~/projects/my-app --start-from native-discover

# Slash commands: make a Claude Code slash command available inside the ACP session
vigolium agent swarm -t https://example.com --custom-slash-command /security-review

# Multiple slash commands
vigolium agent swarm -t https://example.com \
  --custom-slash-command /security-review --custom-slash-command /api-audit

# Custom agents: invoke a sub-agent during the swarm via terminal
vigolium agent swarm -t https://example.com --custom-agent '@my-sqli-specialist'

# Combine slash commands, custom agents, and source analysis
vigolium agent swarm -t http://localhost:3000 --source ~/projects/my-app \
  --custom-slash-command /security-review --custom-agent '@auth-checker'
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
| `-t, --target` | — | Target URL (required when `--source` is used) |
| `--input` | — | Raw input (curl command, raw HTTP, Burp XML). Use `-` for stdin |
| `--record-uuid` | — | HTTP record UUID from database |
| `--source` | — | Path to application source code for route discovery |
| `--files` | — | Specific source files to include (relative to `--source`) |
| `--vuln-type` | — | Vulnerability type focus (e.g., `sqli`, `xss`, `ssrf`) |
| `--focus` | — | Focus area hint for the agent (e.g., `API injection`, `auth bypass`). Broader than `--vuln-type` |
| `-m, --modules` | — | Explicit module names to include alongside agent selections |
| `--max-iterations` | 3 | Maximum triage-rescan iterations (hidden alias: `--max-rescan-rounds`) |
| `--code-audit` | true (when `--source`) | Enable AI security code audit phase (requires `--source`). Enabled by default when `--source` is provided; disable with `--code-audit=false` |
| `--skip-sast` | false | Skip native SAST tools (ast-grep, osv-scanner, semgrep) when `--source` is provided |
| `--start-from` | — | Resume from a specific phase (`native-normalize`, `source-analysis`, `code-audit`, `native-sast`, `native-discover`, `plan`, `native-extension`, `native-scan`, `triage`). Legacy names without `native-` prefix are also accepted |
| `--skip` | — | Skip specific phases (repeatable, e.g., `--skip discovery --skip spidering`) |
| `--agent` | from config | Agent backend to use |
| `--agent-acp-cmd` | — | Custom ACP agent command (e.g., `traecli acp`), overrides `--agent` |
| `--swarm-duration` | 12h | Maximum swarm duration |
| `--profile` | — | Scanning profile to use |
| `--dry-run` | false | Render prompts without executing |
| `--instruction` | — | Custom instruction to guide the agent (appended to all prompts) |
| `--instruction-file` | — | Path to a file containing custom instructions |
| `--show-prompt` | false | Print rendered prompts to stderr before executing |
| `--source-analysis-only` | false | Run only the source analysis phase and exit |
| `--discover` | false | Run discovery+spidering before master agent planning |
| `--batch-concurrency` | 0 (auto) | Max parallel master agent batches (0 = scales with CPU count) |
| `--max-master-retries` | 3 | Max master agent retries on JSON parse failure |
| `--sub-agent-concurrency` | 3 | Max parallel source analysis sub-agents |
| `--custom-slash-command` | — | Slash command available inside the ACP session (repeatable, e.g. `/security-review`). Auto-detected from the agent's global config (e.g. `~/.claude/commands/`) |
| `--custom-agent` | — | Custom agent the swarm can invoke via `vigolium agent query --agent=X` (repeatable, e.g. `@my-sqli-specialist`) |
| `--max-commands` | 50 | Max terminal commands per ACP session (only applies when `--custom-slash-command` or `--custom-agent` is set) |

At least one input is required: `--target`, `--input`, `--record-uuid`, or `--source`. Multiple inputs can be combined (e.g., `--target` + `--input`) for flows that require multiple requests (like login + protected endpoint).

When `--source` is provided, SAST analysis is automatically enabled (no extra flag needed). The SAST phase runs ast-grep route extraction and secret detection, then a SAST review sub-agent validates findings and generates targeted extensions.

## Custom Slash Commands & Custom Agents

Swarm supports two mechanisms for extending the ACP agent's capabilities during a run: **custom slash commands** (`/command`) and **custom agents** (`@agent`). Both enable terminal capability in the ACP session (via `CreateTerminal`), allowing the agent to execute commands mid-response.

### Custom Slash Commands

Custom slash commands make Claude Code-native `/` commands available inside the ACP session. These are prompt files that the agent can invoke by name (e.g., `/security-review`).

**How it works:**

1. You specify `--custom-slash-command /security-review` on the CLI
2. Vigolium auto-detects the agent type (e.g., Claude Code) and finds the command file in the agent's global config directory (e.g., `~/.claude/commands/security-review.md`)
3. Before the ACP session starts, vigolium symlinks the command file into the session CWD's `.claude/commands/` directory
4. `SettingSources` is adjusted so Claude Code loads the commands
5. The agent sees `/security-review` as a native slash command
6. After the swarm run, symlinks and created directories are cleaned up

**Setting up slash commands:**

Create markdown files in your Claude Code commands directory:

```bash
mkdir -p ~/.claude/commands
cat > ~/.claude/commands/security-review.md << 'EOF'
Review the source code for security vulnerabilities. Focus on:
- SQL injection, XSS, SSRF, and path traversal
- Authentication and authorization flaws
- Hardcoded secrets and insecure defaults

Output findings in the standard vigolium findings JSON format.
EOF
```

Then use them in swarm:

```bash
vigolium agent swarm -t https://example.com --custom-slash-command /security-review
```

**Config file:** Default slash commands can be set in `vigolium-configs.yaml`:

```yaml
agent:
  swarm_terminal:
    slash_commands:
      - /security-review
      - /api-audit
```

### Custom Agents

Custom agents (`@agent`) allow the ACP agent to invoke other agent backends (defined in `agent.backends`) via the terminal during a swarm session. The agent runs them as `vigolium agent query --agent=<name> --prompt "..."`.

```yaml
# Define a custom agent backend in vigolium-configs.yaml
agent:
  backends:
    my-sqli-specialist:
      command: claude
      args: ["--dangerously-skip-permissions", "-p"]
      description: "SQL injection specialist agent"

  swarm_terminal:
    custom_agents:
      - "@my-sqli-specialist"
```

Then invoke:

```bash
vigolium agent swarm -t https://example.com --custom-agent '@my-sqli-specialist'
```

The `@` prefix is stripped when resolving the agent backend name. The agent receives prompt context about available custom agents and can invoke them via terminal during the plan and triage phases.

### Terminal Capability

When either `--custom-slash-command` or `--custom-agent` is specified, swarm enables terminal capability in ACP sessions:

- The `CreateTerminal` ACP method becomes active (normally stubbed in swarm mode)
- `vigolium` is always in the terminal allowlist (so custom agents can be invoked via `vigolium agent query`)
- A `--max-commands` limit (default: 50) prevents runaway terminal usage
- Terminal is enabled for all AI phases (plan, triage, source analysis, code audit, SAST review)

## Phase Overview

Phases prefixed with `native-` are executed by native Go code without AI agent involvement.

```
Phase 1:      native-normalize  — Parse input(s) into HttpRequestResponse objects
Phase 1.5:    source-analysis   — 4 AI calls in 2 waves: explore → format-routes + format-session + extensions (if --source)
Phase 1.55:   code-audit        — AI security code audit: business logic, data flow, auth gaps (on by default with --source)
Phase 1.6:    native-sast       — Native ast-grep + secret detection (if --source)
Phase 1.6.1:  sast-review       — AI sub-agent reviews SAST + code-audit findings, validates routes (if --source)
Phase 1.7:    native-discover   — Native crawling + spidering (if --discover)
Phase 2:      plan              — Master agent analyzes request, selects modules, generates extensions
Phase 3:      native-extension  — Merge + write all JS extensions to session directory
Phase 4:      native-scan       — Audit with selected modules + extensions
Phase 5:      triage            — Agent reviews all findings (extension + built-in + code-audit)
Phase 6:      native-rescan     — Targeted rescan based on triage follow-ups (loop)
```

Phases 1.5–1.7 are conditional. Code-audit is enabled by default when `--source` is provided (disable with `--code-audit=false`). The triage→rescan loop (phases 5-6) repeats until the agent sets verdict to `"done"`, there are no follow-ups, or `--max-iterations` is reached.

## Step-by-Step Flow

### Phase 1: native-normalize

Input strings are converted to `HttpRequestResponse` objects using deterministic format detection (no AI needed):

- **URL** → `httpmsg.GetRawRequestFromURL()` generates a GET request
- **Curl** → Parsed using the existing `curl.ParseSingleCommand()` parser (handles `-X`, `-H`, `-d`, `-F`, `-b`, `-u`, `--url`)
- **Raw HTTP** → Parsed directly via `httpmsg.ParseRawRequest()`
- **Burp XML** → Streaming XML decoder extracts `<item>` elements with base64-encoded request/response
- **Record UUID** → Fetched from the `http_records` database table

Normalized records are saved to the database with source `"agent-swarm"`.

### Phase 1.5: Source Analysis (AI — Consolidated 4-Call)

When `--source` is provided, source analysis runs in **4 LLM calls** across 2 waves:

| Wave | Call | Template | Output | Runs |
|------|------|----------|--------|------|
| 1 | Explore | `swarm-source-explore` | Plain-text notes (routes + auth + sinks) | Sequential (first) |
| 2 | Format Routes | `swarm-source-format-routes` | `http_records[]` (JSONL) | Parallel |
| 2 | Format Session | `swarm-source-format-session` | `session_config` (JSON) | Parallel |
| 2 | Extensions | `swarm-source-extensions` | `extensions[]` (JS code blocks) | Parallel |

**Execution flow:**

1. **Wave 1 — Explore:** A single agent reads the entire codebase once and documents all HTTP routes, authentication flows, and vulnerability sinks as plain-text notes with labeled sections (routes + auth/session).
2. **Wave 2 — Format + Extensions (3 calls in parallel):**
   - **Format Routes** converts the route notes into structured JSONL http_records. It reuses the warm ACP session from explore (retains codebase context).
   - **Format Session** converts the auth/session notes into a session_config JSON with login flows and token extraction rules.
   - **Extensions** generates targeted JS scanner extensions from the explore notes. It receives the notes via prompt append (no source code access needed — the explore notes contain all the sink details).

This consolidation reduces LLM calls and eliminates redundant source code reads while maintaining the explore/format separation for structured output quality.

**Without warm sessions:** Explore output is appended to downstream prompts (truncated to 64KB).

Results are merged with mutex protection.

**Session config processing:** The `SourceAnalysisCallback` converts the agent's session config into an `auth-config.yaml` file in the session directory. This auth config is then used by subsequent phases (SAST, discovery, scan) for authenticated analysis.

**Extension handling:** Source-analysis extensions are held and later merged with plan extensions (Phase 2) via `mergeExtensionsTracked()`. On filename collision: identical code is dropped as a duplicate; different code triggers a rename with `-2`, `-3` suffix. The merge result includes a renames map tracking original→new filenames.

### Phase 1.55: code-audit (AI — On by Default with --source)

When `--source` is provided, the code audit phase is enabled by default (disable with `--code-audit=false`). An AI agent performs a deep security code review focusing on vulnerabilities that static analysis tools miss:

- **Business logic flaws** — IDOR, race conditions, privilege escalation, workflow bypasses, mass assignment
- **Authentication/authorization gaps** — missing auth middleware, JWT weaknesses, OAuth misconfigurations
- **Data flow vulnerabilities** — second-order injection, SSTI, unsafe deserialization, path traversal
- **Framework misconfigurations** — CORS, CSRF, debug endpoints, verbose error messages
- **Cryptographic misuse** — weak algorithms, hardcoded keys, timing-unsafe comparisons

The agent receives source analysis explore notes as context to avoid redundant codebase reads. When warm sessions are available, it can reuse the explore session context directly. If source analysis produced no output, the agent reads the source code directly via `--source`.

Findings are saved directly to the database with `module_type="agent"` and `module_id="agent-swarm-code-audit"`. These findings are:
1. Included in the SAST review phase for validation alongside SAST findings
2. Included in the triage phase for final verification
3. Visible in the findings table alongside all other scan findings

Prompt template: `swarm-code-audit.md`

### Phase 1.6: native-sast (Native — No AI)

When `--source` is provided, the native SAST phase runs automatically:

- **ast-grep** — Extracts routes from source code using AST patterns, ingests them into the database with parameterized path resolution and concurrent probing
- **Kingfisher** — Detects hardcoded secrets, API keys, and credentials
- **Third-party tools** — semgrep, osv-scanner, CodeQL (when available on the system)

Findings are saved to the database with `module_type="sast"`. Auth config from source analysis is applied for authenticated SAST analysis.

### Phase 1.6.1: SAST Review (AI Sub-Agent)

After SAST completes, a review sub-agent (`swarm-sast-review` template) evaluates both SAST findings and code-audit findings (if `--code-audit` was enabled):

1. **Validate routes** — Cross-references SAST findings with discovered routes, adds new/corrected routes
2. **Assess quality** — Classifies each finding as high/medium/low confidence
3. **Generate extensions** — Creates targeted JS extensions (prefixed `agent-sast-*`, tagged `sast-verified`) to dynamically verify high/medium confidence SAST findings

The agent receives up to 200 SAST findings and all discovered routes for the target hostname. Output is parsed as `SourceAnalysisResult` — validated routes merge into input records, extensions merge with source-analysis extensions.

### Phase 1.7: native-discover (Native — No AI)

When `--discover` is enabled, native discovery + spidering runs before the master agent:

- Deparos crawling (link extraction, form discovery)
- JavaScript analysis (jsscan)
- Spidering (dynamic page exploration)

Auth config from source analysis is applied for authenticated crawling. Discovered records are queried from the database by target hostname and deduplicated with existing records.

### Phase 2: Plan (AI Checkpoint — Master Agent)

The plan phase consists of two sequential AI calls orchestrated by `runMasterAgent()`:

1. **Plan agent** (`agent-swarm-plan` template) — analyzes HTTP records and generates a `SwarmPlan` with module selections, focus areas, and determines if custom extensions are needed
2. **Extension agent** (`agent-swarm-extensions` template) — if the plan indicates `needs_extensions: true`, generates custom JS scanner extensions based on the plan

The plan agent receives the `agent-swarm-plan` prompt template with:

| Variable | Content |
|----------|---------|
| `TargetURL` | Extracted from the first normalized record |
| `Hostname` | Derived from target URL |
| `ModuleList` | JSON of all available active/passive scanner modules |
| `Extra.RequestContext` | Full HTTP request/response pairs (responses truncated at 4KB) |
| `Extra.VulnType` | User-specified vulnerability focus (if any) |
| `Extra.Focus` | User-specified focus area hint (if any) |

The plan agent analyzes the request surface and returns a **SwarmPlan** JSON:

```json
{
  "module_tags": ["sqli", "injection"],
  "module_ids": ["sqli-error-based"],
  "needs_extensions": true,
  "needs_extensions_reason": "JSON body with user_id parameter susceptible to SQL injection via type juggling",
  "focus_areas": ["SQL injection in JSON body parameters"],
  "notes": "Target uses JSON API with direct DB queries visible in error responses"
}
```

If `needs_extensions` is `true`, the extension agent is called next to generate custom JS extensions, quick checks, and snippets:

```json
{
  "extensions": [
    {
      "filename": "custom-json-sqli.js",
      "code": "var module = { id: 'custom-json-sqli', ... }; function scan_per_request(ctx) { ... }",
      "reason": "Type juggling via JSON body parameters"
    }
  ],
  "quick_checks": [
    {
      "id": "qc-auth-bypass",
      "payloads": ["admin'--"],
      "match_patterns": ["Welcome admin"]
    }
  ],
  "snippets": [
    {
      "id": "snip-idor-check",
      "function_body": "var id = ctx.param('id'); ..."
    }
  ]
}
```

- `module_tags` (required) — scanner module tags to activate (e.g., `sqli`, `xss`, `ssrf`)
- `module_ids` — specific module IDs to include
- `needs_extensions` — whether the extension agent should generate custom extensions
- `needs_extensions_reason` — rationale for why custom extensions are needed
- `extensions` — custom JavaScript scanner extensions for payloads the built-in modules won't cover
- `quick_checks` — declarative payload-and-match checks (auto-converted to full JS extensions)
- `snippets` — shorthand extensions (scan function body only; runner wraps in scaffold)
- `focus_areas` — human-readable description of attack focus
- `notes` — strategy summary

Module tags are resolved against the registry. User-specified `--modules` are merged with agent selections. The plan agent retries up to `--max-master-retries` (default 3) on JSON parse failure, with error feedback appended to the retry prompt.

### Phase 3: native-extension (Write Generated Code)

Extensions from all sources (source analysis, SAST review, plan agent) are merged and written to the session extensions directory. Quick checks and snippets are first converted to full JS modules:

- `QuickChecks` → `GenerateQuickCheckExtensions()` → full ActiveModule scaffold
- `Snippets` → `GenerateSnippetExtensions()` → full ActiveModule scaffold
- Extensions → validated with `ValidateExtensionSyntax()`, invalid ones repaired via `RepairExtensionsWithLLM()`

```
~/.vigolium/agent-sessions/agt-abc123/extensions/
├── custom-json-sqli.js
├── custom-auth-bypass.js
├── qc-auth-bypass.js        (generated from quick_check)
├── snip-idor-check.js       (generated from snippet)
└── agent-sqli-users.js      (from source analysis)
```

The directory path is passed to the scan phase.

### Phase 4: native-scan (Native — No AI)

The audit phase runs with:

- **All built-in modules** enabled by default (`opts.Modules = ["all"]`, `opts.PassiveModules = ["all"]`)
- **Plus the generated extensions** loaded from the session extensions directory
- **Plus any user-specified modules** from `--modules`
- Heuristics check disabled (`"none"`) during swarm scans

Module tags and IDs from the plan are informational — the scan runs all modules regardless. This is pure Go execution — no AI cost.

### Phase 5: Triage (AI Checkpoint)

The triage agent reviews **all findings** — both extension-generated and built-in module findings. Extension findings receive the most scrutiny since they were generated by custom AI-written scanners, but built-in module findings are also reviewed for false positives.

The agent returns a **TriageResult** with confirmed findings, false positives, and optional follow-up scan recommendations.

### Phase 6: native-rescan (Conditional Loop)

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
  "focus": "API injection and auth bypass",
  "instruction": "Focus on JSON deserialization. Generate extensions that test type juggling.",
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
| `http_request_base64` | string | No | Base64-encoded raw HTTP request. Ingested into DB and its UUID is used as input |
| `http_response_base64` | string | No | Base64-encoded raw HTTP response. Attached to the request above |
| `url` | string | No | URL hint for parsing the base64 request (used when the raw request lacks a full URL) |
| `vuln_type` | string | No | Vulnerability type focus (e.g., `sqli`, `xss`) |
| `focus` | string | No | Focus area hint for the agent (e.g., `API injection`, `auth bypass`). Broader than `vuln_type` |
| `instruction` | string | No | Custom instruction appended to all agent prompts |
| `module_names` | string[] | No | Explicit module IDs to include |
| `scanning_phase` | string | No | Scan phase to run (default `audit`) |
| `max_iterations` | int | No | Max triage-rescan rounds (default 3) |
| `agent` | string | No | Agent backend name |
| `project_uuid` | string | No | Project UUID for data scoping |
| `scan_uuid` | string | No | Scan UUID to attach findings to |
| `stream` | bool | No | Enable SSE streaming |
| `timeout` | string | No | Go duration string (default `15m`) |
| `dry_run` | bool | No | Render prompts without executing |
| `code_audit` | bool | No | Enable AI security code audit phase |

\* At least one of `input`, `inputs`, or `http_request_base64` must be provided.

**Response modes:**

- **Streaming (SSE):** Real-time events with phase transitions, agent output chunks, and final result
- **Async (202):** Returns `run_id` for status polling via `GET /api/agent/status/:id`

**SSE event types:**

| Event | Description |
|-------|-------------|
| `phase` | Phase transition (`{"type":"phase","phase":"native-normalize"}`) |
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

# Swarm with base64-encoded HTTP request (e.g. from proxy intercept)
curl -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <api-key>" \
  -d '{
    "http_request_base64": "UE9TVCAvYXBpL2xvZ2luIEhUVFAvMS4xDQpIb3N0OiBleGFtcGxlLmNvbQ0KQ29udGVudC1UeXBlOiBhcHBsaWNhdGlvbi9qc29uDQoNCnsiZW1haWwiOiJ0ZXN0QGV4YW1wbGUuY29tIiwicGFzc3dvcmQiOiJzZWNyZXQifQ==",
    "vuln_type": "auth"
  }'

# Base64 request with a response attached (skips live fetch)
curl -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <api-key>" \
  -d '{
    "http_request_base64": "R0VUIC9hcGkvdXNlcnMvMSBIVFRQLzEuMQ0KSG9zdDogZXhhbXBsZS5jb20NCg0K",
    "http_response_base64": "SFRUUC8xLjEgMjAwIE9LDQpDb250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL2pzb24NCg0KeyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoic3VwZXJhZG1pbiJ9",
    "vuln_type": "idor"
  }'

# Base64 request with a URL hint (when raw request has a relative path)
curl -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <api-key>" \
  -d '{
    "http_request_base64": "R0VUIC9hcGkvb3JkZXJzIEhUVFAvMS4xDQpIb3N0OiBsb2NhbGhvc3QNCg0K",
    "url": "https://staging.example.com/api/orders"
  }'

# Multiple inputs for auth flow testing (login + protected endpoint)
curl -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <api-key>" \
  -d '{
    "inputs": [
      "curl -X POST https://example.com/api/auth/login -H \"Content-Type: application/json\" -d \"{\\\"user\\\":\\\"admin\\\",\\\"pass\\\":\\\"test\\\"}\"",
      "curl -X GET https://example.com/api/admin/users -H \"Authorization: Bearer eyJhbGciOi...\""
    ],
    "vuln_type": "auth"
  }'

# Swarm with record UUID from database
curl -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <api-key>" \
  -d '{"input": "550e8400-e29b-41d4-a716-446655440000"}'

# Swarm with focus area hint
curl -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <api-key>" \
  -d '{
    "input": "https://example.com/api/users?id=1",
    "focus": "API injection and privilege escalation"
  }'

# Dry run — render prompts without executing agent calls
curl -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <api-key>" \
  -d '{
    "input": "https://example.com/api/users?id=1",
    "vuln_type": "sqli",
    "dry_run": true
  }'

# Scoped to a project
curl -X POST http://localhost:9002/api/agent/run/swarm \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <api-key>" \
  -H "X-Project-UUID: proj-abc123" \
  -d '{
    "input": "https://example.com/api/users",
    "project_uuid": "proj-abc123"
  }'

# Check swarm status
curl http://localhost:9002/api/agent/status/<run-id> \
  -H "Authorization: Bearer <api-key>"
```

## Extension Generation Detail

The swarm plan can include three types of agent-generated scanning logic. All three are converted to full JavaScript extensions before the scan phase:

```
  SwarmPlan output from Master Agent
  |
  +-- extensions[]     Full JS modules (written as-is)
  |     { filename: "custom-sqli.js", code: "module.exports = {...}", reason: "..." }
  |
  +-- quick_checks[]   Declarative payload-and-match checks
  |     { id: "qc-auth-bypass", payloads: ["admin'--"], match: "Welcome admin" }
  |     |
  |     +--> GenerateQuickCheckExtensions()
  |          Wraps each into a full ActiveModule JS scaffold:
  |            scan_per_insertion_point(ctx) {
  |              for payload in payloads:
  |                resp = ctx.sendPayload(payload)
  |                if resp.body.includes(match): ctx.addFinding(...)
  |            }
  |
  +-- snippets[]       JS function bodies (scan logic without boilerplate)
        { id: "snip-idor", body: "var id = ctx.param('id'); ..." }
        |
        +--> GenerateSnippetExtensions()
             Wraps the body into a full ActiveModule JS scaffold:
               scan_per_request(ctx) {
                 <snippet body>
               }
```

### Extension Lifecycle

Extensions can originate from three sources. They are merged by filename (plan wins on collision) before writing to disk:

```
  Phase 1.5               Phase 1.6.1             Phase 2 (Plan)
  (Source Analysis)        (SAST Review)           (Master Agent)
  +-----------------+      +-----------------+     +-----------------+
  | 3 sub-agents    |      | SAST review     |     | Master Agent    |
  | generate exts   |      | generates       |     | generates:      |
  | for vuln sinks  |      | agent-sast-*    |     | - extensions    |
  +-----------------+      | verification    |     | - quick_checks  |
          |                | extensions      |     | - snippets      |
          |                +-----------------+     +-----------------+
          |                        |                       |
          +------------+-----------+-----------+-----------+
                       |
                       v
               mergeExtensionsTracked()
               (identical code dropped, different code renamed with -2, -3 suffix)
                       |
                       v
               Phase 3 (Extension)             Phase 4 (Scan)
               +-----------------+           +-----------------+
               | Write to Disk   |           | Scanner Executor|
               |                 |           |                 |
               | session_dir/    |---------->| Load *.js from  |
               |   extensions/   |           | extensionDir    |
               |   *.js          |           |                 |
               +-----------------+           | Register as     |
                                             | ActiveModules   |
                                             |                 |
                                             | Execute via     |
                                             | worker pool     |
                                             +-----------------+
                                                    |
                                                    v
                                             findings saved
                                             to DB with
                                             source: "extension"
                                                    |
                                                    v
                                             Phase 5 (Triage)
                                             reviews ALL findings
```

## Output Schemas

### SwarmPlan (Phase 2)

```go
type SwarmPlan struct {
    ModuleTags            []string             // required, >= 1 tag
    ModuleIDs             []string             // specific module IDs
    Extensions            []GeneratedExtension // custom JS scanner extensions
    QuickChecks           []QuickCheck         // declarative payload-and-match checks
    Snippets              []Snippet            // shorthand extensions (function body only)
    FocusAreas            []string             // human-readable attack focus
    Notes                 string               // strategy summary
    NeedsExtensions       bool                 // whether extension agent should run
    NeedsExtensionsReason string               // rationale for custom extensions
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
    SwarmPlan       *SwarmPlan               // master agent's plan
    TriageResults   []*TriageResult          // all triage rounds
    TotalFindings   int                      // findings from DB
    TotalRecords    int                      // total HTTP records scanned
    SeverityCounts  map[string]int           // critical, high, medium, low, info
    Confirmed       int                      // confirmed by triage
    FalsePositives  int                      // rejected by triage
    Iterations      int                      // triage rounds completed
    Duration        time.Duration
    AgentRunUUID    string                   // DB tracking UUID
    SessionID       string                   // last ACP session ID (single/last batch)
    SessionIDs      []string                 // all ACP session IDs when batched (>5 records)
    SessionDir      string                   // path to session artifacts
    PhaseTimings    map[string]time.Duration // per-phase execution times
    TokenUsage      TokenUsage               // total input/output tokens consumed
    BatchProvenance *BatchProvenance         // only set when merged from multiple batches
}

type TokenUsage struct {
    InputTokens  int
    OutputTokens int
}

type BatchProvenance struct {
    ModuleTags map[string]int // tag -> batch number (1-indexed)
    ModuleIDs  map[string]int // id -> batch number
    Extensions map[string]int // filename -> batch number
    FocusAreas map[string]int // focus area -> batch number
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

## Comparison: Swarm vs Autopilot

| Aspect | Swarm | Autopilot |
|--------|-------|-----------|
| **Scope** | Single request/endpoint, or full target with `--discover` | Entire target |
| **Input** | URL, curl, raw HTTP, Burp XML, DB record | Target URL |
| **AI involvement** | 3-12+ calls (source analysis 4 + code-audit + SAST review + plan + extensions + triage), warm sessions auto-enabled | Many calls (agent-driven) |
| **Custom payloads** | Yes — from source analysis, SAST review, and master agent | No |
| **Discovery** | Optional (`--discover`) — crawling + spidering | Yes — agent decides |
| **SAST** | Automatic when `--source` provided + AI review sub-agent | No |
| **Triage scope** | All findings (extension + built-in) | Agent decides |
| **Default timeout** | 12 hours | 30 minutes |
| **Best for** | Deep targeted testing or full-scope structured scanning | Exploratory research |

**Use `agent swarm`** when you want structured, repeatable scanning — whether targeting a single endpoint for deep analysis or running full-scope scans with `--discover`.

**Use `agent autopilot`** when you want the AI to explore freely and decide its own approach.

## Session Artifacts

Every swarm run creates a session directory (configurable via `agent.sessions_dir`, defaults to `~/.vigolium/agent-sessions/<run-id>/`). The session directory stores all artifacts from the run for debugging and auditability:

```
~/.vigolium/agent-sessions/agt-abc123/
├── inputs.json                    # Normalized input records (JSON array)
├── source-analysis-prompt.md      # Rendered source analysis explore prompts (if --source)
├── source-analysis-output.md      # Raw source analysis output (explore + format phases)
├── code-audit-prompt.md           # Rendered code audit prompt (if --code-audit)
├── code-audit-output.md           # Raw code audit agent output
├── sast-review-prompt.md          # Rendered SAST review prompt (if --source)
├── sast-review-output.md          # Raw SAST review agent output
├── master-prompt.md               # Rendered master agent planning prompt
├── master-output.md               # Raw master agent output
├── auth-config.yaml               # Generated auth config (from source analysis)
├── session-config.json            # Session configuration (from source analysis)
├── swarm-plan.json                # SwarmPlan from the master agent
└── extensions/
    ├── agent-sqli-users-error.js  # Source analysis extension
    ├── agent-sast-sqli-verify.js  # SAST review extension
    └── custom-json-sqli.js        # Master agent extension
```

The session directory path is included in the `SwarmResult` (`session_dir` field) and printed to stderr in CLI mode.

## Key Files

| File | Purpose |
|------|---------|
| `pkg/agent/swarm.go` | Swarm orchestrator (multi-phase pipeline) |
| `pkg/agent/engine.go` | Agent engine (`RunSourceAnalysisParallel`, `Run`, `RunWithExtra`) |
| `pkg/agent/input_normalizer.go` | Input type detection and normalization |
| `pkg/agent/input_parsers.go` | Curl and Burp XML parsers |
| `pkg/agent/pipeline_types.go` | Data structures (SwarmPlan, SwarmResult, shared helpers) |
| `pkg/cli/agent_swarm.go` | CLI command definition and callback wiring |
| `pkg/server/handlers_agent.go` | REST API handlers |
| `pkg/database/models.go` | AgentRun model for DB tracking |
| `public/presets/prompts/swarm/agent-swarm-plan.md` | Plan agent prompt template |
| `public/presets/prompts/swarm/agent-swarm-extensions.md` | Extension agent prompt template |
| `public/presets/prompts/swarm/swarm-source-explore.md` | Source analysis: explore routes, auth, and sinks |
| `public/presets/prompts/swarm/swarm-source-format-routes.md` | Source analysis: format route notes to JSONL http_records |
| `public/presets/prompts/swarm/swarm-source-format-session.md` | Source analysis: format auth notes to session_config JSON |
| `public/presets/prompts/swarm/swarm-source-extensions.md` | Source analysis: generate JS scanner extensions from notes |
| `public/presets/prompts/swarm/swarm-code-audit.md` | Security code audit agent |
| `public/presets/prompts/swarm/swarm-sast-review.md` | SAST review sub-agent |
| `public/presets/prompts/swarm/agent-swarm-triage.md` | Triage agent prompt template |
