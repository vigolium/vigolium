# Anatomy of a Scan

This document traces the complete lifecycle of an HTTP request through a Vigolium scan — from `vigolium scan -t https://example.com` on the command line to a vulnerability finding written to the terminal. It is an architecture deep-dive intended for contributors who want to understand the scanning pipeline end-to-end.

## High-Level Pipeline

```
CLI invocation
  │
  ▼
┌─────────────────────┐
│  CLI Entry & Config  │  cmd/vigolium/main.go → pkg/cli/scan.go
│  Flag parsing, config│  Config loading, strategy/profile, DB init
│  loading, DB init    │
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│   Input Parsing      │  pkg/input/source/
│   URL/file/stdin →   │  InputSource.Next() → WorkItem
│   WorkItem stream    │
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  Runner Orchestration│  internal/runner/runner.go
│  7-phase pipeline:   │  Heuristics → Harvest → Spider →
│  build infra, run    │  SAST → Discovery → SPA →
│  phases in order     │  Audit
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│     Executor         │  pkg/core/executor.go
│  Worker pool feeds   │  feedItems() → worker() → processItem()
│  items to modules    │
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  Module Dispatch     │  pkg/modules/
│  Passive (sequential)│  ScanPerHost → ScanPerRequest
│  Active (parallel)   │  ScanPerHost/Request/InsertionPoint
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│   Result Emission    │  pkg/output/output.go
│  Post-hooks → DB     │  assignModuleInfo → emitResult →
│  save → output write │  SaveFinding → OnResult → Notify
└─────────────────────┘
```

## Stage 1: CLI Entry and Configuration

### Entry Point

`cmd/vigolium/main.go` prints the banner (unless `--json` or certain subcommands suppress it), then calls `cli.Execute()` which invokes the Cobra root command.

### Root Command — `pkg/cli/root.go`

`rootCmd.PersistentPreRunE` fires before every subcommand and:

1. Initializes the global `zap.Logger` via `initLogger()`.
2. Falls back to the `VIGOLIUM_PROXY` environment variable if `--proxy` is empty.
3. Runs first-time setup via `ensureInitialized()` — creates `~/.vigolium/` and writes the default config, profiles, SAST rules, and prompt templates if they don't exist.
4. Handles early-exit flags: `--list-modules`, `--list-input-mode`, `--full-example`.

### Scan Command — `pkg/cli/scan.go`

`runScanCmd()` is the heart of the scan flow. It performs these steps in order:

1. **Copy global flags** into `scanOpts` (`*types.Options`): targets, concurrency, timeout, modules, proxy, format, phases, etc.
2. **Reconcile `--json` and `--format`**: if `--json` is set and format is still the default `"console"`, switch to `"jsonl"`.
3. **Load config**: `config.LoadSettings(configPath)` reads `~/.vigolium/vigolium-configs.yaml`. CLI overrides are applied for origin mode, OAST URL, and database settings. Validates database, extensions, and strategy configs.
4. **Resolve scanning profile**: precedence is `--scanning-profile` flag > `settings.ScanningStrategy.ScanningProfile`. Profiles are loaded from `~/.vigolium/profiles/` or embedded presets, and applied via `config.ApplyProfile()`.
5. **Resolve scanning strategy**: precedence is `--strategy` flag > `settings.ScanningStrategy.DefaultStrategy`. Strategy determines which phases are enabled (discovery, spidering, SPA, etc.).
6. **Resolve heuristics check level**: `--skip-heuristics` > `--heuristics-check` > config > default `"basic"`.
7. **Phase isolation**: `--only` and `--skip` are mutually exclusive. `--only <phase>` enables a single phase and disables all others. `--skip <phase>` disables specific phases. Phase aliases are normalized: `deparos`/`discover` → `discovery`, `spitolas` → `spidering`. The `dynamic-assessment` alias is accepted as a backward-compatible alias for `audit`.
8. **Validate HTML output**: `--format html` requires `--output` and is only allowed with `--only discovery` or `--only spidering`.
9. **Apply scanning pace**: concurrency and max-per-host from config are applied unless explicitly set on CLI.
10. **Initialize database**: `database.NewDB()` → `CreateSchema()` → `database.NewRepository()`.
11. **Handle `--source`**: clone git URLs or resolve local paths, link source repos to targets in DB.
12. **Branch into one of three execution paths**:

```
Has --input file?  ──yes──▶  runScanWithIngest()    Parse file, create InputSource, run
       │ no
       ▼
Has targets?       ──no───▶  runDBScan()            Scan existing DB records (empty source)
       │ yes
       ▼
runner.New(scanOpts)         ──────────────────▶    Target-based: build source from CLI targets
  .SetSettings(settings)
  .SetRepository(repo)
  .RunEnumeration()
  .Close()
```

## Stage 2: Input Parsing

### The InputSource Interface — `pkg/input/source/source.go`

Input sources provide a pull-based stream of work items:

```go
type InputSource interface {
    Next(ctx context.Context) (*work.WorkItem, error)
    Close() error
}
```

Return conventions: `(*WorkItem, nil)` = next item, `(nil, io.EOF)` = source exhausted, `(nil, context.Canceled)` = cancelled.

The optional `Countable` interface adds `Count() int64` for progress tracking.

### InputSource Implementations

| Type | File | Description | Countable |
|------|------|-------------|-----------|
| `TargetSource` | `source.go` | Iterates CLI `-t` targets, builds GET requests via `GetRawRequestFromURL()` | Yes |
| `FileSource` | `file.go` | Parses input files (OpenAPI, Burp, HAR, cURL, etc.) via format-specific parsers | Yes |
| `StdinSource` | `stdin.go` | Reads URLs line-by-line from stdin | No |
| `SingleSource` | `single_source.go` | Returns a single item, then EOF. Used by `scan-url`/`scan-request` | Yes (1) |
| `MultiSource` | `multi.go` | Drains sub-sources sequentially in order | Yes (sum) |
| `ConcurrentMultiSource` | `concurrent.go` | Reads all sub-sources concurrently. Used for queue-based sources | No |
| `ExternalHarvesterInputSource` | `external_harvester_source.go` | Runs external harvesting (Wayback, CommonCrawl, etc.) | No |
| `DeparosDiscoverySource` | `deparos_discovery.go` | Runs content discovery engine per target | No |

`NewInputSource(cfg SourceConfig)` is the factory function. Based on the config fields, it creates `TargetSource`, `FileSource`, and/or `StdinSource`, wrapping multiple sources in a `MultiSource`.

### Supported Input Formats

Resolved by `resolveFormat()` in `file.go`:

| Format names | Parser |
|---|---|
| `urls`, `url`, `list` | Line-delimited URLs |
| `openapi`, `swagger` | OpenAPI/Swagger spec |
| `postman` | Postman collection |
| `curl` | cURL commands |
| `burpraw`, `burp-raw`, `raw` | Burp raw request files |
| `burpxml`, `burp-xml`, `burp` | Burp XML export |
| `nuclei`, `nuclei-output` | Nuclei JSONL output |
| `deparos`, `deparos-output` | Deparos discovery output |
| `crawlerxdir`, `spitolas` | Spitolas spider output (Parquet) |

### The WorkItem — `pkg/work/item.go`

```go
type WorkItem struct {
    Request       *httpmsg.HttpRequestResponse
    EnableModules []string   // per-item module selection (empty = all)
    RecordUUID    string     // pre-existing DB record UUID (skip store)
    onComplete    func()     // queue ack callback (unexported)
}
```

`Complete()` is called after processing to acknowledge queue-based sources.

## Stage 3: HTTP Types

### HttpRequestResponse — `pkg/httpmsg/http_request_response.go`

The central data type flowing through the entire pipeline. It pairs an HTTP request with an optional response:

```go
type HttpRequestResponse struct {
    request  *HttpRequest   // required
    response *HttpResponse  // optional, may be nil
}
```

Key methods: `Request()`, `Response()`, `HasResponse()`, `Service()`, `URL()`, `Target()`, `ID()` (FNV-1a hash of `host:port:method`), `Clone()`, `WithResponse()`, `CreateInsertionPoints()`, `BuildRetryableRequest()`.

Factory functions:
- `GetRawRequestFromURL(url)` — builds a minimal GET request from a URL string (used by `TargetSource` and `StdinSource`)
- `ParseRawRequest(raw)` — parses raw HTTP text
- `FromStdRequest(req)` — converts a stdlib `http.Request`

### HttpRequest — `pkg/httpmsg/http_request.go`

Stores the raw HTTP request bytes as the source of truth, with lazy-parsed accessors:

```go
type HttpRequest struct {
    raw     []byte     // source of truth
    service *Service   // host/port/protocol
    // lazy-parsed cache (populated by ensureParsed())
    method, path string
    headers      []HttpHeader
    bodyOffset   int
    parsed       bool
    mu           sync.RWMutex
}
```

`ensureParsed()` is thread-safe via a double-checked RW mutex. It extracts headers, method, path, and body offset from the raw bytes.

Immutable builder methods (`WithMethod()`, `WithPath()`, `WithHeader()`, `WithBody()`, etc.) return new `*HttpRequest` instances with rebuilt raw bytes. The `RequestOption` / `Apply()` batch builder pattern rebuilds raw bytes only once for multiple changes.

### HttpResponse — `pkg/httpmsg/http_response.go`

Same lazy-parsing pattern as `HttpRequest`:

```go
type HttpResponse struct {
    raw        []byte
    statusCode int
    headers    []HttpHeader
    bodyOffset int
    parsed     bool
    mu         sync.RWMutex
}
```

### Service — `pkg/httpmsg/service.go`

A host/port/protocol triple:

```go
type Service struct {
    host     string   // hostname only (no port)
    port     int
    protocol string   // "http" or "https"
}
```

## Stage 4: Runner Orchestration

### The Runner — `internal/runner/runner.go`

The Runner is the high-level orchestrator. It builds shared infrastructure and executes the multi-phase scan pipeline.

```go
type Runner struct {
    output            output.Writer
    options           *types.Options
    settings          *config.Settings
    inputSource       source.InputSource
    dedupManager      *dedup.Manager
    repository        *database.Repository
    heuristicsResults map[string]*HeuristicsResult
}
```

### buildInfrastructure()

Called once at the top of `RunEnumeration()`. Creates all shared services in the `phaseInfra` container:

```go
type phaseInfra struct {
    svc           *services.Services
    httpRequester *http.Requester
    scopeMatcher  *config.ScopeMatcher
    hostLimiter   *hostlimit.HostRateLimiter
    notifier      *notify.Manager
    hookChain     *jsext.HookChain
    jsEngine      *jsext.Engine
    scanUUID      string
}
```

Built in order:
1. **Notifier** — Telegram and/or Discord backends (from config or env vars).
2. **Services** — wraps Options, Notifier, DedupManager, and HostErrors (circuit breaker for unresponsive hosts).
3. **HostRateLimiter** — per-host concurrency control (default: 2 concurrent per host, 1000 max tracked hosts, 30s idle eviction).
4. **HTTP Requester** — HTTP client with retry, proxy, redirect, and middleware support.
5. **ScopeMatcher** — host/path/status/content-type/body-string filtering from config.
6. **JS Engine** — Grafana Sobek engine for JavaScript extensions, including pre/post hook chains.

### RunEnumeration() — The 7-Phase Pipeline

```
RunEnumeration()
│
├── buildInfrastructure()
│
├─── Phase 0: Heuristics Check     [guard: heuristicsCheck != "none"]
│    Probes target root pages, detects blank/JSON/SPA responses.
│    Flags targets to skip spidering.
│
├─── Phase 1: External Harvest     [guard: ExternalHarvestEnabled]
│    Queries Wayback, CommonCrawl, AlienVault, URLScan, VirusTotal.
│    Ingests discovered URLs into DB (no modules, pure ingestion).
│
├─── Phase 2: Spidering            [guard: SpideringEnabled]
│    Browser-based crawling (Chromium). Applies heuristics filter.
│    Stores discovered pages in DB via repository.
│
├─── Phase 3: SAST                 [guard: SASTEnabled]
│    Static analysis via ast-grep. Extracts routes from source code.
│    Ingests routes as minimal HTTP requests into DB.
│
├─── Phase 4: Discovery            [guard: !SkipIngestion]
│    Content discovery (brute-force dirs/files via deparos engine)
│    + CLI input source. Both wrapped in MultiSource.
│    Ingests into DB (no modules, pure ingestion).
│    Fallback: seedCLITargets() if ingestion skipped but SPA/DA need records.
│
├─── Phase 5: SPA                  [guard: SPAEnabled]
│    Nuclei template scan + Kingfisher secret detection on stored
│    response bodies. Targets enriched with discovered paths
│    (enrich_targets). Filters out secret_detect passive module
│    to avoid duplicates in DA phase.
│    Post-phase: DeduplicateFindings() groups same-module/URL findings.
│
└─── Phase 6: Audit                [guard: !SkipAudit]
     THE CORE SCANNING PHASE. Reads records from DB, dispatches
     active + passive modules. Per-module finding cap suppresses
     noisy modules. Feedback loop (up to 3 rounds) re-scans
     newly discovered URLs.
     Post-phase: DeduplicateFindings() merges redundant findings.
```

Phases 0-5 populate the database with HTTP records. Phase 6 reads those records back and runs the full module pipeline against them.

### Phase 5 Detail: SPA

1. Queries distinct paths from DB via `GetDistinctPaths()`.
2. Builds target URLs — either path-enriched (default, `enrich_targets: true`) or host-level only.
3. Runs Nuclei templates + Kingfisher secret scanning against targets.
4. **Post-phase dedup**: calls `DeduplicateFindings()` to group findings with identical `(module_id, severity, matched_at URL)`.

### Phase 6 Detail: Audit

1. Creates a `database.Scan` record with cursor tracking.
2. Resolves DA concurrency from config (separate from discovery concurrency).
3. Optionally starts the OAST (out-of-band) service.
4. Runs a **feedback loop** (up to `maxFeedbackRounds = 3`):
   - Creates a `OneShotDBInputSource` that reads records after the scan cursor.
   - Builds an Executor with all active + passive modules, `SkipBaseline: true` (responses already in DB).
   - The Executor enforces a per-module finding cap (`MaxFindingsPerModule`, default 15) — once a module emits this many findings, further results from that module are suppressed.
   - After each round, checks for newly created records. Breaks early if none.
5. **Post-phase dedup**: calls `DeduplicateFindings()` to merge findings where the same module fired on the same URL with different payloads.
6. Marks the scan as completed.

## Stage 5: The Executor

### Executor Struct — `pkg/core/executor.go`

The Executor is the central dispatch engine. It receives work items, distributes them to a worker pool, and dispatches modules.

```go
type Executor struct {
    cfg            ExecutorConfig
    source         source.InputSource
    activeModules  []modules.ActiveModule
    passiveModules []modules.PassiveModule
    httpClient     *http.Requester
    scanCtx        *modules.ScanContext
    hooks          HookRunner

    // Pre-grouped by scan scope at init time
    perHostActive     []modules.ActiveModule
    perRequestActive  []modules.ActiveModule
    perIPActive       []modules.ActiveModule
    perHostPassive    []modules.PassiveModule
    perRequestPassive []modules.PassiveModule

    ipCache      *lru.Cache[string, []httpmsg.InsertionPoint]  // 4096-entry LRU
    requestUUIDs *shardedMap   // request hash → DB record UUID
}
```

### Module Pre-Grouping

At construction time, `NewExecutor()` pre-groups all modules by their `ScanScope` bitmask into five slices. A module declaring `ScanScopeInsertionPoint | ScanScopeRequest` appears in both `perIPActive` and `perRequestActive`. This avoids per-item scope-check iteration.

### Execute() — Worker Pool

```go
func (e *Executor) Execute(ctx context.Context) (bool, error)
```

1. Spawns `Workers` goroutines reading from a buffered channel (`cap = Workers * 2`).
2. Calls `feedItems()` on the calling goroutine (producer loop).
3. Closes the channel, waits for all workers to drain.
4. Flushes passive modules (`Flusher` interface) and OAST service.
5. Returns `(foundResults, nil)`.

### feedItems() — The Producer

For each item from `source.Next()`:

1. **Static file filter**: if path matches a static file extension (`.jpg`, `.css`, etc.), skip.
2. **Pre-request scope check**: `ScopeMatcher.InScopeRequest(host, path, "", "")` — host + path only, no HTTP round-trip. Rejects obviously out-of-scope items early.
3. **Host error check**: if `HostErrors.Check(hostID)` returns true (host has been circuit-broken), skip.
4. Send item to the worker channel.

### worker() — The Consumer

Each worker goroutine loops on the channel:

```go
for item := range itemCh {
    e.processItem(item)
    item.Complete()
    e.statsTracker.Increment()
}
```

## Stage 6: Processing an Item

`processItem()` is the per-item hot path. Every item that passes `feedItems()` goes through these steps:

### Step 1: Baseline HTTP Fetch

```
if SkipBaseline && response already attached:
    use existing response (DB-sourced items in audit phase)
else:
    httpClient.Execute(request) → response
    copy response bytes from pool before Close()
    attach response to request via WithResponse()
```

Response bytes are copied from a `sync.Pool` of recycled buffers (32 KiB initial, max 1 MiB for pool return) to reduce GC pressure.

### Step 2: Traffic Callback

If configured, calls `OnTraffic(method, url, statusCode, contentType)` — an observer hook for printing traffic lines to stderr.

### Step 3: Pre-Hooks

```
hooks.RunPreHooks(request)
  → error: log and skip item
  → nil return: hook filtered it out, skip item
  → modified request: continue with transformed request
```

Pre-hooks can inject auth headers, transform requests, or signal to skip entirely.

### Step 4: Body Size Enforcement

If `ScopeMatcher` is set, checks request and response body sizes:
- `BodySizeDrop` → drop item entirely.
- `BodySizeTruncate` → truncate bodies to limits, continue scanning.
- `BodySizeSkipScan` → truncate, save to DB, but skip scanning.

### Step 5: Scope Check + Database Save

```
if ScopeMatcher configured:
    check full scope (host, path, status, content types, body strings)
    if out-of-scope and ScopeOnIngest: drop entirely (no save, no scan)
    save to database
    if out-of-scope: saved but not scanned → return
else:
    save to database and continue
```

`saveToDatabase()` calls `repo.SaveRecord()` and stores the returned UUID in the `requestUUIDs` sharded map (keyed by request SHA-256 hash) for later finding linkage.

### Step 6: Eligibility Pre-Computation

`computeEligibility()` runs once per item (not per module):
1. Request nil check
2. URL parse check
3. Media/JS URL check (`utils.IsMediaAndJSURL`)
4. HTTP method check (skip `OPTIONS`, `CONNECT`, `HEAD`, `TRACE`)

The cached `baseEligible` result lets the executor skip calling `CanProcess()` on modules that embed the standard base checks when the base would reject.

### Step 7: Module Filter

If `item.EnableModules` is non-empty, builds a map-based O(1) filter. Otherwise uses the `allModulesFilter` sentinel.

### Step 8: Passive Module Execution (Sequential)

```
runPassivePerHost(request, filter)      sequential loop over perHostPassive
runPassivePerRequest(request, filter)   sequential loop over perRequestPassive
```

For each module: check filter → check `CanProcess()` → call scan method → process results. No goroutines — passive modules do not perform network I/O.

### Step 9: Active Module Execution (Parallel)

Three categories run in parallel via `conc.WaitGroup`:

```
var g conc.WaitGroup
g.Go(func() { runActivePerHost(request, filter, eligibility) })
g.Go(func() { runActivePerRequest(request, filter, eligibility) })
g.Go(func() { runActivePerInsertionPoint(request, filter, eligibility) })
g.Wait()
```

Within each category, eligible modules also run concurrently (inner `conc.WaitGroup`).

For the insertion-point category specifically, insertion points are iterated **serially** (one at a time), but all eligible modules for a given point run **concurrently**:

```
insertion points = ipCache.GetOrCompute(requestHash)
for each insertionPoint:
    for each eligible module (parallel):
        module.ScanPerInsertionPoint(request, insertionPoint, httpClient, scanCtx)
```

### Concurrency Model Summary

```
Execute()
├── feedItems()                          [calling goroutine, producer]
└── Workers goroutines                   [consumer pool]
    └── processItem()
        ├── Passive modules              [sequential on worker goroutine]
        │   ├── runPassivePerHost
        │   └── runPassivePerRequest
        └── Active modules               [3-way parallel via conc.WaitGroup]
            ├── runActivePerHost          [inner parallel: all modules]
            ├── runActivePerRequest       [inner parallel: all modules]
            └── runActivePerInsertionPoint
                └── for each IP (serial)  [inner parallel: all modules]
```

## Stage 7: Insertion Points

### The InsertionPoint Interface — `pkg/httpmsg/insertion_point.go`

```go
type InsertionPoint interface {
    Name() string                        // parameter name (e.g. "id", "username")
    BaseValue() string                   // original value at this position
    Type() InsertionPointType            // one of INS_* constants
    BuildRequest(payload []byte) []byte  // new request bytes with payload injected
    PayloadOffsets(payload []byte) []int  // [startOffset, endOffset] in built request
}
```

### InsertionPointType Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `INS_PARAM_URL` | 0 | URL query parameter value |
| `INS_PARAM_BODY` | 1 | POST body parameter value |
| `INS_PARAM_COOKIE` | 2 | Cookie value |
| `INS_PARAM_XML` | 3 | XML element value |
| `INS_PARAM_XML_ATTR` | 4 | XML attribute value |
| `INS_PARAM_MULTIPART_ATTR` | 5 | Multipart attribute value |
| `INS_PARAM_JSON` | 6 | JSON value |
| `INS_HEADER` | 32 | HTTP header value |
| `INS_URL_PATH_FOLDER` | 33 | REST URL path folder |
| `INS_PARAM_NAME_URL` | 34 | URL parameter name |
| `INS_PARAM_NAME_BODY` | 35 | Body parameter name |
| `INS_ENTIRE_BODY` | 36 | Entire request body |
| `INS_URL_PATH_FILENAME` | 37 | REST URL path filename |
| `INS_USER_PROVIDED` | 64 | User-defined position |
| `INS_EXTENSION_PROVIDED` | 65 | Extension-provided position |

### InsertionPoint Implementations

| Type | Description |
|------|-------------|
| `ParameterInsertionPoint` | Standard parameter replacement. Uses offset-based splicing with type-aware payload encoding (URL-encode for URL/body/cookie, JSON-aware for JSON params, raw for XML). |
| `HeaderInsertionPoint` | Header value replacement. Uses `AddOrReplaceHeader()` instead of offset splicing. Created for existing injectable headers + synthetic headers (`X-Forwarded-For`, `X-Forwarded-Host`, `Referer`, `True-Client-IP`, `X-Real-IP`). |
| `NestedInsertionPoint` | Multi-level encoding chains (e.g., URL-encoded JSON inside a body parameter). `BuildRequest()` applies inner-to-outer: child builds first, then parent encodes the result. |
| `EncodedInsertionPoint` | Custom encoder chain. Applies `prefix + payload → encoder.Encode() → splice`. Used for complex encoding scenarios. |

### LRU Cache

The Executor maintains a 4096-entry LRU cache (`ipCache`) keyed by request SHA-256 hash. `CreateAllInsertionPoints()` is called once per unique request, and the results are reused for all modules scanning that request.

### Shared Base Request

`CreateAllInsertionPoints()` creates a single `sharedBaseRequest` clone of the raw bytes, shared across all `ParameterInsertionPoint` instances from that call. This is safe because `BuildRequest()` never mutates the shared bytes — it always allocates a new result slice.

## Stage 8: Module Dispatch

### Module Interface Hierarchy — `pkg/modules/`

```
Module (base)
├── ActiveModule
│   ├── ScanPerInsertionPoint(request, insertionPoint, httpClient, scanCtx)
│   ├── ScanPerRequest(request, httpClient, scanCtx)
│   ├── ScanPerHost(request, httpClient, scanCtx)
│   └── AllowedInsertionPointTypes() InsertionPointTypeSet
│
└── PassiveModule
    ├── ScanPerRequest(request, scanCtx)
    ├── ScanPerHost(request, scanCtx)
    ├── Scope() PassiveScanScope
    └── (optional) Flusher: Flush(scanCtx)
```

### ScanScope Bitmask — `pkg/modules/modkit/types.go`

```go
const (
    ScanScopeInsertionPoint ScanScope = 1 << iota  // = 1
    ScanScopeRequest                                // = 2
    ScanScopeHost                                   // = 4
)
```

A module declares one or more scopes by OR-ing constants. The executor uses `ScanScopes().Has(scope)` to pre-group modules at startup.

### InsertionPointTypeSet — `pkg/modules/modkit/types.go`

A `uint32` bitmask where each bit corresponds to an `InsertionPointType`. Checked by the executor before calling `ScanPerInsertionPoint()`:

```go
module.AllowedInsertionPointTypes().Contains(ip.Type())
```

Pre-built presets: `URLParamTypes`, `BodyParamTypes`, `CookieTypes`, `HeaderTypes`, `AllParamTypes`.

### CanProcess Semantics

**Active modules** (via `BaseActiveModule`): reject nil requests, unparseable URLs, media/JS URLs, and non-testable HTTP methods (`OPTIONS`, `CONNECT`, `HEAD`, `TRACE`). The executor pre-computes these checks in `computeEligibility()` and skips calling `CanProcess()` when the base would reject.

**Passive modules** (via `BasePassiveModule`): only check that the required HTTP transaction parts (request and/or response) are present. They process all content types including media — no method filtering.

### Execution Pattern

```
Per item:
  1. Passive per-host   → sequential loop, no goroutines
  2. Passive per-request → sequential loop, no goroutines
  3. Active per-host     → parallel: all eligible modules concurrently
  4. Active per-request  → parallel: all eligible modules concurrently
  5. Active per-IP       → for each insertion point (serial):
                             all eligible modules concurrently
```

Steps 3-5 run as three concurrent goroutine groups via `conc.WaitGroup`.

### ScanContext — `pkg/modules/modkit/context.go`

Shared resources available to all modules during scanning:

```go
type ScanContext struct {
    DedupManager        *dedup.Manager
    RiskScoreUpdater    RiskScoreUpdater
    RequestUUIDResolver RequestUUIDResolver
    OASTProvider        OASTProvider
    MutationGen         MutationGenerator
    baselineCache       sync.Map  // "METHOD:host/path" → *BaselineEntry
}
```

- **DedupManager** — request-level deduplication.
- **OASTProvider** — generates out-of-band callback URLs for blind vulnerability detection.
- **MutationGenerator** — classifies parameter values and generates test mutations.
- **baselineCache** — caches baseline responses for diff-based scanning.

### Flusher Interface

Passive modules that buffer state across many requests (e.g., `anomaly_ranking`) implement `Flusher`:

```go
type Flusher interface {
    Flush(scanCtx *ScanContext)
}
```

Called by the executor after all workers complete, enabling end-of-scan aggregation and final result emission.

### Module Development Defaults — `pkg/modules/modkit/`

Module authors embed `BaseActiveModule` or `BasePassiveModule` to get default implementations of all interface methods. Module IDs must be lowercase kebab-case with prefix `active-` or `passive-` (validated at construction, panics on violation). The `modkit` package also provides `NewBaseModule()`, `NewBaseActiveModule()`, and `NewBasePassiveModule()` constructors.

## Stage 9: Result Emission

### ResultEvent — `pkg/output/output.go`

```go
type ResultEvent struct {
    ModuleID         string                 `json:"template-id"`
    Info             Info                   `json:"info,inline"`
    Type             string                 `json:"type"`
    Host             string                 `json:"host,omitempty"`
    URL              string                 `json:"url,omitempty"`
    Matched          string                 `json:"matched-at,omitempty"`
    ExtractedResults []string               `json:"extracted-results,omitempty"`
    Request          string                 `json:"request,omitempty"`
    Response         string                 `json:"response,omitempty"`
    Metadata         map[string]interface{} `json:"meta,omitempty"`
    Timestamp        time.Time              `json:"timestamp"`
    // ...
}
```

`ResultEvent.ID()` computes a SHA-1 hash over `ModuleID | Description | Severity | Matched` — this becomes `finding_hash` in the database for deduplication.

### processResults() and emitResult()

When a module returns results, the executor processes them:

```
Module returns []*ResultEvent
  │
  ▼
processResults(results, module)
  │
  for each result:
  │
  ├── moduleFindingAllowed(module.ID())
  │     Per-module finding cap check (MaxFindingsPerModule).
  │     When > 0, suppresses results after the limit is reached.
  │     Logs a one-time warning when a module hits its cap.
  │
  ├── assignModuleInfo(result, module)
  │     Set ModuleID, Info.Name, Description, Severity, Confidence
  │     Default Type = "http"
  │     Derive Matched from URL if empty
  │     Derive URL from request bytes if empty
  │     Fill Host from URL
  │
  └── emitResult(result)
        │
        ├── 1. Post-hooks: RunPostHooks(result)
        │      nil return → drop result (hook filtered it out)
        │
        ├── 2. Set results flag: e.results.Store(true)
        │
        ├── 3. Database save:
        │      Build temp HttpRequest from result.Request
        │      Look up requestUUIDs[requestHash] → recordUUID
        │      repo.SaveFinding(result, [recordUUID], scanUUID)
        │      Uses INSERT ON CONFLICT (finding_hash) DO NOTHING
        │
        ├── 4. OnResult callback → output writer
        │
        └── 5. Notifier.Send(result) → Telegram/Discord
```

## Stage 10: Output

### Writer Interface — `pkg/output/output.go`

```go
type Writer interface {
    Close()
    Write(*ResultEvent) error
    WriteFileOnly(*ResultEvent) error
}
```

### StandardWriter

The default `Writer` implementation:

1. Sets `Timestamp = time.Now()`, defaults `Type = "http"`, forces `MatcherStatus = true`.
2. Serializes to JSON via `jsoniter.Marshal()`.
3. Under mutex:
   - **Stdout**: writes JSON (if `--json`) or formatted console output (if not `--silent`).
   - **File**: appends JSON line to output file (JSONL format).

### Console Format — `pkg/output/format_screen.go`

```
[› phase │] [moduleType] [moduleName] [severity] matched-at [extracted-results] [fuzz-param]
```

- Module ID split into type (`active`/`passive`) and name, colored accordingly.
- Severity shown with symbol and ANSI color (Critical=magenta, High=red, Medium=yellow, Low=green).
- Output truncated to terminal width.

### JSON Format — `pkg/output/format_json.go`

Serializes `ResultEvent` via `jsoniter.Marshal()`. Response body is stripped unless `--include-response` is set.

### HTML Format — `pkg/output/format_html.go`

Uses a streaming approach: splits the embedded HTML template at `{{.ResultsJSON}}`, writes the before-portion with simple string replacement (avoids `text/template` because bundled JS contains `{{` sequences), then streams JSON array items one at a time, then writes the after-portion.

### File Output Writer — `pkg/output/file_output_writer.go`

```go
type fileWriter struct {
    file *os.File
    mu   sync.Mutex
}
```

Mutex-locked, appends JSON + newline (JSONL format). Opens with `O_APPEND|O_CREATE|O_WRONLY` for safe resume across invocations.

## Stage 11: Database Persistence

### Data Models — `pkg/database/models.go`

#### HTTPRecord (table: `http_records`)

Fully denormalized — no separate hosts or parameters tables. Key fields:

- **Identity**: `UUID` (primary key), `RequestHash` (SHA-256 of raw request)
- **Host info**: `Scheme`, `Hostname`, `Port`, `IP`
- **Request**: `Method`, `Path`, `URL`, `RequestHeaders` (JSONB), `RawRequest` (bytea), `RequestBody` (bytea)
- **Response**: `StatusCode`, `ResponseHeaders` (JSONB), `RawResponse` (bytea), `ResponseBody` (bytea), `ResponseTitle`, `ResponseWords`
- **Parameters**: `Parameters` (JSONB array of `EmbeddedParam`)
- **Risk**: `RiskScore`, `Remarks` (JSONB array)
- **Metadata**: `Source`, `SentAt`, `ReceivedAt`, `CreatedAt`

#### Finding (table: `findings`)

- **Identity**: `ID` (auto-increment), `FindingHash` (unique constraint for dedup)
- **Module info**: `ModuleID`, `ModuleName`, `Description`, `Severity`, `Confidence`
- **Match data**: `MatchedAt` (JSONB array), `ExtractedResults`, `Request`, `Response`
- **Relations**: `HTTPRecordUUIDs` (JSONB array), `ScanUUID`
- **Grouped evidence**: `AdditionalEvidence` (JSONB array of strings) — request/response pairs from duplicate findings that were merged into this survivor (capped at 10 entries)

The `finding_records` junction table links findings to HTTP records (many-to-many).

### Converters — `pkg/database/converters.go`

- `HTTPRecord.FromHttpRequestResponse()` — converts the in-memory type to the DB model. Generates UUID, parses URL, copies headers/body, computes hashes, extracts HTML title, counts response words.
- `Finding.FromResultEvent()` — maps `ResultEvent` fields to `Finding`. Sets `FindingHash = event.ID()` (the SHA-1 dedup hash).

### Repository — `pkg/database/repository.go`

Key methods:

| Method | Description |
|--------|-------------|
| `SaveRecord()` | Single INSERT, returns UUID |
| `SaveRecordsBatch()` | Bulk INSERT in one transaction |
| `SaveFinding()` | INSERT ON CONFLICT (finding_hash) DO NOTHING + evidence append + junction table |
| `DeduplicateFindings()` | Post-phase grouping: merge findings sharing (module_id, severity, matched_at URL) |
| `CreateScanWithCursor()` | Creates scan record, copies cursor from last completed scan |
| `CountRecordsAfterCursor()` | Counts new records since cursor (used for feedback loop) |
| `GetRecordsWithResponseBody()` | UUID-cursor pagination for batch scanning (Kingfisher) |
| `UpdateRiskScores()` | Batch CASE/WHEN UPDATE, 500 UUIDs per statement |

### RecordWriter — `pkg/database/record_writer.go`

Batched asynchronous persistence for high-throughput ingestion:

```go
type RecordWriter struct {
    repo    *Repository
    cfg     RecordWriterConfig   // BufferSize=4096, BatchSize=128, FlushInterval=50ms
    ch      chan writeRequest     // backpressure via channel capacity
}
```

- `Write()` converts to `HTTPRecord`, sends to buffered channel, blocks until flushed.
- `flushLoop()` runs as a single background goroutine: accumulates batch, flushes on batch-full or ticker-fire via `repo.SaveRecordsBatch()`.
- Each caller gets a `WriteResult{UUID, Err}` back on a per-request result channel.

## Stage 12: Supporting Systems

### Scope Matching — `internal/config/scope_matcher.go`

`ScopeMatcher` evaluates items against configurable rules across multiple dimensions (all AND-ed):

1. **Host**: glob match + origin mode filtering (cached per host)
2. **Path**: `filepath.Match` glob patterns
3. **Static file extension**: configurable extension set
4. **Status code**: exact, wildcard (`2xx`), or range (`400-499`)
5. **Content type**: glob patterns for request and response
6. **Body strings**: case-insensitive substring matching on request/response bodies

**Origin modes** control how CLI targets constrain host scope:

| Mode | Matching Rule |
|------|---------------|
| `all` | No restriction |
| `strict` | Exact hostname match |
| `balanced` | eTLD+1 must match (e.g., `*.example.com`) |
| `relaxed` (default) | Host contains target keyword |

### Rate Limiting — `pkg/core/ratelimit/host_limiter.go`

`HostRateLimiter` provides per-host concurrency control:

- **32 fixed shards** with inline FNV-1a hashing for shard selection.
- Each host gets a **buffered channel semaphore** (capacity = `MaxPerHost`, default 2).
- `Acquire(ctx, host)` blocks until a slot is free; `Release(host)` frees a slot.
- Background eviction goroutine removes idle entries (default: 30s idle, checked every 10s).
- Per-shard capacity cap with oldest-entry eviction when exceeded.

### Host Error Circuit Breaker — `pkg/core/hosterrors/`

`hosterrors.Cache` tracks consecutive errors per host:

- `MarkFailed()` increments the error counter (with regex-based error matching).
- `Check()` returns true when the counter reaches `MaxHostError` (default 30).
- `MarkSuccess()` resets the counter (but not if already at threshold).
- The executor's `feedItems()` pre-checks this to skip items for quarantined hosts.

### JS Extension Hooks — `pkg/jsext/hooks.go`

**Pre-hooks** (`PreHookExecutor`): transform or filter requests before module dispatch. Return `nil` to skip the item.

**Post-hooks** (`PostHookExecutor`): transform or filter results before output. Return `nil` to drop the result.

`HookChain` executes hooks sequentially, passing each hook's output to the next. On error, the hook is skipped (non-fatal). On `nil` return, the chain is aborted immediately.

Each hook uses a `VMPool` (`sync.Pool` of Sobek VMs) — VMs are reused across concurrent invocations with no shared mutable state.

### OAST (Out-of-Band)

Out-of-band callback detection for blind vulnerabilities (SSRF, XXE, etc.). The OAST service generates unique callback URLs per module/parameter/request, and is flushed at the end of the scan with a grace period to catch late callbacks.

### Deduplication and Finding Grouping

Three levels of deduplication prevent noise and redundancy:

1. **Request-level**: `DedupManager` prevents scanning duplicate requests (checked before module dispatch).

2. **Finding-level (inline)**: `finding_hash` unique constraint in the database uses `INSERT ON CONFLICT DO NOTHING`. When a duplicate hash is detected at insert time, `appendRecordsToFinding()` appends the new HTTP record UUIDs and request/response pair (as `AdditionalEvidence`) to the existing finding instead of creating a new row.

3. **Finding-level (post-phase grouping)**: `DeduplicateFindings()` runs after the SPA and audit phases. It groups findings that share the same `(module_id, severity, matched_at[0] URL)` within a project — this catches cases where the same module fires multiple times on the same URL with different payloads (e.g., an injection probe producing dozens of results per endpoint).

   The grouping process:
   - Partitions findings by `module_id || severity || matched_at[0]` and orders by `created_at ASC`
   - Keeps the earliest finding per group as the **survivor**
   - Collects request/response pairs from duplicates into the survivor's `AdditionalEvidence` field (capped at 10 entries to bound storage)
   - Deletes all duplicate findings and their `finding_records` junction rows
   - Returns counts of deleted findings and merged groups for user feedback

```
Phase completes (SPA or audit)
  │
  ▼
DeduplicateFindings(projectUUID)
  │
  ├── GROUP BY (module_id, severity, matched_at[0])
  │     ORDER BY created_at ASC → survivor = row_number 1
  │
  ├── For each group with duplicates:
  │     Merge duplicate request/response → survivor.AdditionalEvidence
  │     Cap at 10 evidence entries
  │
  ├── DELETE duplicate findings + junction rows
  │
  └── Print feedback: "grouped N findings into M"
```

## Putting It All Together

### End-to-End Flow

```
vigolium scan -t https://example.com
         │
         ▼
    ┌────────────┐
    │  CLI Parse  │  pkg/cli/scan.go: runScanCmd()
    │  + Config   │  Load settings, resolve strategy/profile
    │  + DB Init  │  database.NewDB() → CreateSchema()
    └─────┬──────┘
          │
          ▼
    ┌────────────┐
    │   Runner    │  internal/runner/runner.go
    │  Build Infra│  HTTP client, scope matcher, rate limiter, hooks
    └─────┬──────┘
          │
          ▼
    ┌────────────────────────────────────────────────────────┐
    │              RunEnumeration() — 7 Phases                │
    │                                                        │
    │  [Heuristics] → [Harvest] → [Spider] → [SAST]         │
    │       → [Discovery/Ingest] → [SPA] → [Dynamic Assess] │
    │                                                        │
    │  Phases 0-5: populate DB with HTTP records             │
    │  Phase 5-6: DeduplicateFindings() after each          │
    │  Phase 6: scan records with modules                    │
    └───────────────────────┬────────────────────────────────┘
                            │
                            ▼  (Phase 6 detail)
    ┌───────────────────────────────────────────────────┐
    │                    Executor                        │
    │                                                   │
    │  feedItems():                                     │
    │    source.Next() → static filter → scope check    │
    │    → host error check → send to worker channel    │
    │                                                   │
    │  worker() → processItem():                        │
    │    1. Baseline HTTP fetch (or use DB response)    │
    │    2. Traffic callback                            │
    │    3. Pre-hooks (JS transform/filter)             │
    │    4. Body size enforcement                       │
    │    5. Scope check + DB save                       │
    │    6. Eligibility pre-computation                 │
    │    7. Passive modules (sequential)                │
    │    8. Active modules (parallel, 3-way)            │
    │       └── per insertion point: all modules        │
    │                                                   │
    │  Post-processing:                                 │
    │    Flush passive modules (Flusher interface)      │
    │    Flush OAST service (grace period)              │
    └───────────────────────┬───────────────────────────┘
                            │
                            ▼
    ┌───────────────────────────────────────────────────┐
    │              Result Emission                       │
    │                                                   │
    │  Per-module finding cap (suppress after limit)     │
    │  assignModuleInfo() → emitResult():               │
    │    1. Post-hooks (JS transform/filter)            │
    │    2. SaveFinding() to DB (dedup via finding_hash │
    │       + evidence append on conflict)              │
    │    3. OnResult → StandardWriter.Write()           │
    │    4. Notifier.Send() → Telegram/Discord          │
    └───────────────────────┬───────────────────────────┘
                            │
                            ▼
    ┌───────────────────────────────────────────────────┐
    │                   Output                           │
    │                                                   │
    │  Console: colored severity + module + matched URL │
    │  JSON:    JSONL via jsoniter                      │
    │  HTML:    embedded ag-grid template               │
    │  File:    append-only JSONL with mutex            │
    └───────────────────────────────────────────────────┘
```

### Summary Table

| Stage | Key File | Key Function | Data In | Data Out |
|-------|----------|-------------|---------|----------|
| CLI Entry | `cmd/vigolium/main.go` | `main()` → `cli.Execute()` | CLI args | — |
| Config | `pkg/cli/scan.go` | `runScanCmd()` | Flags + YAML | `*types.Options`, `*config.Settings` |
| Input | `pkg/input/source/` | `InputSource.Next()` | URLs/files/stdin | `*work.WorkItem` |
| HTTP Types | `pkg/httpmsg/` | `GetRawRequestFromURL()` | URL string | `*HttpRequestResponse` |
| Runner | `internal/runner/runner.go` | `RunEnumeration()` | Options + Settings | Phase results |
| Executor | `pkg/core/executor.go` | `Execute()` → `processItem()` | `InputSource` + modules | `bool` (found results) |
| Insertion Points | `pkg/httpmsg/insertion_point.go` | `CreateAllInsertionPoints()` | Raw request bytes | `[]InsertionPoint` |
| Module Dispatch | `pkg/modules/` | `ScanPer{Host,Request,InsertionPoint}()` | `*HttpRequestResponse` | `[]*ResultEvent` |
| Result Emission | `pkg/core/executor.go` | `emitResult()` | `*ResultEvent` | DB write + output |
| Output | `pkg/output/output.go` | `StandardWriter.Write()` | `*ResultEvent` | Console/JSON/HTML/file |
| DB Persistence | `pkg/database/` | `SaveRecord()`, `SaveFinding()` | HTTP types / ResultEvent | `HTTPRecord`, `Finding` |
