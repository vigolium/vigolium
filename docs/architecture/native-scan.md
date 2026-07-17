# Native Scan Architecture — Anatomy of a Scan

> _Architecture series: [overview](overview.md) · **native-scan** · [agentic-scan](agentic-scan.md) · [data-and-storage](data-and-storage.md) · [server-and-api](server-and-api.md)_

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
│  Native scan plan:   │  Heuristics/port sweep → Harvest → Spider →
│  build infra, run    │  Discovery → targeted re-spider →
│  phases in order     │  DynamicAssessment → KnownIssueScan
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
│  Passive modules     │  Per-host ordered; per-request bounded parallel
│  Active modules      │  One bounded task pool across all scan scopes
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
3. Runs first-time setup via `ensureInitialized()` — creates `~/.vigolium/` and writes the default config, profiles, and prompt templates if they don't exist.
4. Handles early-exit flags: `--list-modules`, `--list-input-mode`, `--full-example`.

### Scan Command — `pkg/cli/scan.go`

`runScanCmd()` is the heart of the scan flow. It performs these steps in order:

1. **Copy global flags** into `scanOpts` (`*types.Options`): targets, concurrency, timeout, modules, proxy, format, phases, etc.
2. **Reconcile `--json` and `--format`**: if `--json` is set and format is still the default `"console"`, switch to `"jsonl"`.
3. **Load config**: resolve the active project and load global settings plus its optional project overlay. CLI overrides are then applied. Database, extension, and strategy settings are validated.
4. **Resolve scanning profile**: precedence is `--scanning-profile` flag > `settings.ScanningStrategy.ScanningProfile`. Profiles are loaded from `~/.vigolium/profiles/` or embedded presets, and applied via `config.ApplyProfile()`.
5. **Resolve scanning strategy**: precedence is `--strategy` flag > `settings.ScanningStrategy.DefaultStrategy`. Strategy determines which phases are enabled (discovery, spidering, KnownIssueScan, etc.).
6. **Resolve heuristics check level**: `--skip-heuristics` > `--heuristics-check` > config > default `"basic"`.
7. **Phase isolation**: `--only` and `--skip` are mutually exclusive. `--only <phase>` enables a single phase and disables all others. `--skip <phase>` disables specific phases. Phase aliases are normalized: `deparos`/`discover` → `discovery`, `spitolas` → `spidering`, `ext` → `extension`.
8. **Validate output**: report formats require an output path (except per-host naming). When `--only` isolates work, HTML is limited to discovery or spidering; full scans may also render HTML from persisted results.
9. **Apply scanning pace**: concurrency and max-per-host from config are applied unless explicitly set on CLI.
10. **Initialize database**: `database.NewDB()` → `CreateSchema()` → `database.NewRepository()`.
11. **Branch into one of three execution paths**:

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
  .RunNativeScan()
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
| `burpxml`, `burp-xml`, `burp`, `burpstate` | Burp XML/state export |
| `har`, `http-archive` | HTTP Archive (HAR) |
| `nuclei`, `nuclei-output` | Nuclei JSONL output |
| `deparos`, `deparos-output` | Deparos discovery output |


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

Called once at the top of `RunNativeScan()`. Creates all shared services in the `phaseInfra` container:

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
3. **HostRateLimiter** — per-host concurrency control. The standard scanning-pace default is 40 concurrent requests per host; phase settings and CLI flags can override it. The limiter tracks at most 1000 hosts and evicts entries after 30 seconds idle.
4. **HTTP Requester** — HTTP client with retry, proxy, redirect, and middleware support.
5. **ScopeMatcher** — host/path/status/content-type/body-string filtering from config.
6. **JS Engine** — Grafana Sobek engine for JavaScript extensions, including pre/post hook chains.

### RunNativeScan() — The Native Scan Plan

```
RunNativeScan()
│
├── buildInfrastructure()
│
├─── Heuristics Check              [guard: heuristicsCheck != "none"]
│    Probes target root pages, detects blank/JSON/SPA responses.
│    Flags targets to skip spidering.
│
├─── Port Sweep                    [guard: deep intensity or --follow-subdomains]
│    Checks configured alternate HTTP(S) ports on original target hosts.
│
├─── External Harvest              [guard: ExternalHarvestEnabled]
│    Queries Wayback, CommonCrawl, AlienVault, URLScan, VirusTotal.
│    Ingests discovered URLs into DB (no modules, pure ingestion).
│
├─── Spidering                     [guard: SpideringEnabled]
│    Browser-based crawling (Chromium). Applies heuristics filter.
│    Stores discovered pages in DB via repository.
│
├─── Discovery / Input Ingestion   [guard: !SkipIngestion]
│    Content discovery (brute-force dirs/files via deparos engine)
│    + CLI input source. Both wrapped in MultiSource.
│    Ingests into DB (no modules, pure ingestion).
│    Fallback: seedCLITargets() if ingestion skipped but KnownIssueScan/DA need records.
│
├─── Targeted Re-Spider            [guard: spider + discovery + assessment]
│    Revisits rich or SPA routes surfaced by discovery.
│
├─── DynamicAssessment             [guard: !SkipDynamicAssessment]
     THE CORE SCANNING PHASE. Reads records from DB, dispatches
     active, passive, and selected extension modules. Per-module finding cap suppresses
     noisy modules. A configurable feedback loop re-scans
     newly discovered URLs.
     Post-phase: DeduplicateFindings() merges redundant findings.
│
└─── KnownIssueScan                [guard: KnownIssueScanEnabled]
     Runs Nuclei templates and the in-process secret detector over
     in-scope targets and stored textual response bodies.
     Post-phase: finding grouping and deduplication.
```

Reconnaissance and discovery populate the database. Dynamic assessment and
known-issue scan consume those records and can add findings or new traffic.

### KnownIssueScan Detail

1. Queries distinct paths from DB via `GetDistinctPaths()`.
2. Builds target URLs — either path-enriched (default, `enrich_targets: true`) or host-level only.
3. Runs Nuclei templates, then scans stored bodies with `pkg/secretscan`.
4. **Post-phase dedup**: calls `DeduplicateFindings()` to group findings with identical `(module_id, severity, matched_at URL)`.

### DynamicAssessment Detail

1. Creates a `database.Scan` record with cursor tracking.
2. Resolves DA concurrency from config (separate from discovery concurrency).
3. Optionally starts the OAST (out-of-band) service.
4. Runs a **feedback loop**. `dynamic-assessment.max_feedback_rounds` defaults to 1; raise it (for example, to 3) to rescan URLs fed back by modules:
   - Creates a `OneShotDBInputSource` that reads records after the scan cursor.
   - Builds an Executor with all active + passive modules, `SkipBaseline: true` (responses already in DB).
   - The Executor enforces a per-module finding cap (`MaxFindingsPerModule`, default 10) — once a module emits this many findings, further results from that module are suppressed.
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

    ipCache      *lru.Cache[string, []httpmsg.InsertionPoint]  // auto-sized bounded LRU
    requestUUIDs *shardedMap   // request hash → DB record UUID
}
```

### Module Pre-Grouping

At construction time, `NewExecutor()` pre-groups all modules by their `ScanScope` bitmask into five slices. A module declaring `ScanScopeInsertionPoint | ScanScopeRequest` appears in both `perIPActive` and `perRequestActive`. This avoids per-item scope-check iteration.

### Execute() — Worker Pool

```go
func (e *Executor) Execute(ctx context.Context) (bool, error)
```

1. Spawns `Workers` goroutines reading from a buffered channel (`cap = Workers * 2`). Optional adaptive mode can add workers when the queue remains over 75% full, up to the configured ceiling.
2. Calls `feedItems()` on the calling goroutine (producer loop).
3. After source EOF, drains module-fed requests until the executor is idle, then closes the channel and waits for workers with a bounded shutdown grace.
4. Flushes passive side effects (`Flusher`), deferred passive findings (`BatchFlusher`), corroboration observations, and the OAST service.
5. Returns `(foundResults, nil)`.

### feedItems() — The Producer

For each item from `source.Next()`:

1. **Static file filter**: if a path matches a static extension, skip it unless it looks like an object-storage asset. Storage candidates are retained as metadata-only items and fetched with `HEAD` (or a one-byte ranged `GET` fallback), never as full large/binary bodies.
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
    use existing response (DB-sourced items in dynamic-assessment phase)
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

### Step 4: Body Size Classification and Truncation

When a `ScopeMatcher` is configured, the executor classifies oversized request or response bodies and truncates them to the configured limits before any module sees them. The resulting action is applied only after the passive stage:

- `BodySizeTruncate` → persist normally and continue to active scanning.
- `BodySizeDrop` → allow passive inspection of the truncated exchange, then return without persistence or active scanning.
- `BodySizeSkipScan` → allow passive inspection, persist the truncated exchange, then return.
- `BodySizePassiveOnly` → allow passive inspection and normal scope-aware persistence, but skip active scanning.

### Step 5: Module Filter, Record Link, and Full Scope Status

If `item.EnableModules` is non-empty, the executor builds an O(1) module filter; otherwise it reuses the `allModulesFilter` sentinel. DB-sourced items pre-register their existing record UUID so findings link back to that row instead of creating a duplicate. The executor then evaluates full scope using host, path, status, content types, and body rules.

### Step 6: Passive Module Execution

Passive work runs before the body-size and persistence gates:

```
per-host passive modules      ordered on the worker; once per (module, origin)
per-request passive modules   bounded parallel fan-out by default
```

Both groups are pre-filtered by the item module filter, technology/content-class requirements, and `CanProcess()`. On an out-of-scope item, modules implementing `ScopeAwareModule` are skipped; passive modules that are not scope-aware may still inspect the exchange. Per-request parallelism is enabled by the default dynamic-assessment pace and is bounded globally to `max(64, Workers*8)` live tasks. It can be disabled with `scanning_pace.dynamic-assessment.parallel_passive: false`.

### Step 7: Body-Size Gate, Persistence, and Scope Gate

After passive analysis, the body-size action described above is applied. Items that continue use this persistence flow:

```
if out-of-scope and ScopeOnIngest:
    return without saving
save or reuse the HTTP record
if out-of-scope:
    return without active scanning
```

New records go through the batched `RecordWriter` when configured, otherwise `Repository.SaveRecord()`. The returned UUID is cached by request hash for finding linkage. Existing DB records reuse `item.RecordUUID`; request-only stubs can have their fetched baseline response backfilled.

### Step 8: Eligibility Pre-Computation

`computeEligibility()` runs once per item (not per module):
1. Request nil check
2. URL parse check
3. Media/JS URL check (`utils.IsMediaAndJSURL`)
4. HTTP method check (skip `OPTIONS`, `CONNECT`, `HEAD`, `TRACE`)

The cached `baseEligible` result lets the executor skip calling `CanProcess()` on modules that embed the standard base checks when the base would reject.

### Step 9: Active Module Execution

Host-, request-, and insertion-point-scoped tasks all share one `conc.WaitGroup` and one context-aware semaphore. The default task budget is `max(32, Workers*8)`, or `ExecutorConfig.ActiveTaskLimit` when set. There are no outer “three category” goroutines: each scope function submits its eligible module calls directly into the same bounded pool, and `runActiveStage()` waits for all of them.

For insertion-point modules, the loop is module-outer and insertion-point-inner so module-level gates are evaluated once. Every eligible `(module, insertion point)` pair is submitted as its own bounded task:

```
insertionPoints = ipCache.GetOrCompute(requestHash)
for each module:
    apply module filter, technology filter, and CanProcess once
    for each allowed insertion point:
        submit ScanPerInsertionPoint(...) to the shared active task pool
```

Per-host active and passive claims are keyed by `(module, canonical scheme://host:port origin)`, so the same module can run independently on HTTP and HTTPS or on distinct ports.

### Concurrency Model Summary

```
Execute()
├── feedItems()                              producer
└── Workers goroutines                       record-level consumer pool
    └── processItem()
        ├── passive per-host                 ordered, run-once claim
        ├── passive per-request              bounded global task pool (default)
        └── active host/request/IP calls     one bounded global task pool
```

Every module call also has a watchdog: passive calls default to 5 seconds and active calls to 300 seconds, with optional module `TimeoutHint()` overrides. Active whole-request timeouts scale for requests with many insertion points, up to the executor's configured ceiling.

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

The Executor maintains an LRU `ipCache` keyed by request SHA-256 hash. Unknown-size sources default to 4096 entries; countable sources auto-size from `count+100` for small inputs through a 25,000-entry cap for very large inputs. `CreateAllInsertionPoints()` is called once per uncached request, and the results are reused across modules.

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

A `uint64` bitmask where each representable bit corresponds to an `InsertionPointType`. This covers fuzzable types through value 37; user/extension/unknown markers at 64 and above are intentionally not members. The executor checks it before calling `ScanPerInsertionPoint()`:

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
  1. Passive per-host    → ordered loop with per-origin claims
  2. Passive per-request → bounded parallel fan-out by default
  3. Active per-host     ┐
  4. Active per-request  ├→ individual tasks in one bounded pool
  5. Active per-IP       ┘  (one task per module/point pair)
```

The active scope functions share one `conc.WaitGroup`; they submit tasks directly rather than launching three outer scope goroutines.

### ScanContext — `pkg/modules/modkit/context.go`

Selected shared resources available to modules during scanning:

```go
type ScanContext struct {
    DedupManager        *dedup.Manager
    RiskScoreUpdater    RiskScoreUpdater
    RemarksAnnotator    RemarksAnnotator
    RecordRewriter      RecordResponseRewriter
    ArtifactWriter      DerivedArtifactWriter
    RequestUUIDResolver RequestUUIDResolver
    Scope               ScopeChecker
    OASTProvider        OASTProvider
    MutationGen         MutationGenerator
    RequestFeeder       RequestFeeder
    ScopeExpander       ScopeExpander
    InsertionPoints     InsertionPointProvider
    ParamFindings       *ParameterFindingRegistry
    TechStack           *TechRegistry
    WAFStack            *WAFRegistry
    ContentClass        *ContentClassRegistry
    FollowSubdomains    bool
    DeepScan            bool
    // bounded baseline/wildcard caches and singleflight groups are private
}
```

- **DedupManager** — request-level deduplication.
- **OASTProvider** — generates out-of-band callback URLs for blind vulnerability detection.
- **MutationGenerator** — classifies parameter values and generates test mutations.
- **RequestFeeder / ScopeExpander** — feed discovered requests back into the executor and, when allowed, expand exact-host scope.
- **InsertionPoints / ParamFindings** — reuse parsed insertion points and suppress duplicate vulnerability-class work on the same parameter.
- **TechStack / WAFStack / ContentClass** — per-host registries used for conservative module gating and pacing signals.
- Private bounded caches plus `singleflight` coalesce baseline, wildcard, and decoy probes.

### Flusher Interface

Passive modules that need an end-of-scan side effect (for example, `anomaly-ranking`) implement `Flusher`:

```go
type Flusher interface {
    Flush(scanCtx *ScanContext)
}
```

`Flusher` does not return findings. A passive module that buffers deferred findings implements `BatchFlusher` instead:

```go
type BatchFlusher interface {
    FlushFindings(scanCtx *ScanContext) ([]*output.ResultEvent, error)
}
```

The executor calls flushers only after all workers exit. `BatchFlusher` results re-enter the normal post-hook, finding-cap, persistence, callback, and notification pipeline. If a worker cannot be joined within the shutdown grace, flushing is skipped to avoid racing mutable module buffers.

### Module Development Defaults — `pkg/modules/modkit/`

Module authors embed `BaseActiveModule` or `BasePassiveModule` to get default implementations of all interface methods. Module IDs must be unique lowercase kebab-case identifiers with no underscore (for example, `sqli-error-based`); active/passive type is registry metadata, not an ID prefix. Construction and registry contract tests fail fast on invalid or duplicate IDs. The `modkit` package also provides `NewBaseModule()`, `NewBaseActiveModule()`, and `NewBasePassiveModule()` constructors.

## Stage 9: Result Emission

### ResultEvent — `pkg/output/output.go`

```go
type ResultEvent struct {
    ModuleID          string                 `json:"template-id"`
    Info              Info                   `json:"info"`
    RecordKind        RecordKind             `json:"record_kind,omitempty"`
    EvidenceGrade     EvidenceGrade          `json:"evidence_grade,omitempty"`
    Type              string                 `json:"type"`
    Host              string                 `json:"host,omitempty"`
    Scheme            string                 `json:"scheme,omitempty"`
    URL               string                 `json:"url,omitempty"`
    Matched           string                 `json:"matched-at,omitempty"`
    ExtractedResults  []string               `json:"extracted-results,omitempty"`
    Request           string                 `json:"request,omitempty"`
    Response          string                 `json:"response,omitempty"`
    AdditionalEvidence []string              `json:"additional_evidence,omitempty"`
    Metadata          map[string]interface{} `json:"meta,omitempty"`
    Timestamp         time.Time              `json:"timestamp"`
    // Fuzzing fields plus non-serialized routing/dedup fields omitted here.
}
```

`RecordKind` is `finding`, `candidate`, or `observation`; its zero value remains a finding for compatibility. `EvidenceGrade` records confirmation maturity from `E0` (observation) through `E4` (impact demonstrated).

By default, `ResultEvent.ID()` computes a SHA-1 hash over `ModuleID | Description | Severity | Matched`; non-finding kinds are prefixed so they cannot collide with a promoted finding. A module can set the non-serialized `DedupKey` to choose an explicit identity instead. The resulting ID becomes `finding_hash` in the database.

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
  ├── Set ModuleType and FindingSource; assign module metadata/tags
  ├── Backfill baseline request/response when the module omitted them
  ├── Optionally re-confirm body differentials for opted-in modules
  │
  └── emitResult(result)
        │
        ├── 1. Post-hooks: RunPostHooks(result)
        │      nil return → drop result (hook filtered it out)
        ├── 2. Normalize RecordKind
        ├── 3. For findings only: atomically admit the post-hook identity
        │      against MaxFindingsPerModule; duplicates share that decision
        ├── 4. Resolve or persist the evidence HTTP record
        ├── 5. Persist through FindingWriter (batched) or Repository
        │      Duplicate hashes merge record links and new evidence
        └── 6. Route by kind:
               observation → OnObservation only
               candidate   → OnCandidate only
               new finding → OnResult + notifier
               duplicate   → stored merge only
```

Candidates and observations are retained for investigation but do not consume the reportable-finding cap, increment finding totals, trigger cross-module confirmed-result suppression, appear in the normal finding output callback, or send notifications.

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
2. Marshals with `jsoniter` only when JSON stdout or a live output file needs the bytes; console-only runs skip that cost.
3. Under a writer mutex:
   - **Stdout**: writes JSON (if `--json`) or formatted console output (if not `--silent`).
   - **File**: appends JSON line to output file (JSONL format).

### Console Format — `pkg/output/format_screen.go`

```
[› phase │] [moduleType] [moduleName] [severity] matched-at [extracted-results] [fuzz-param]
```

- Module type (`active`, `passive`, known-issue source, and so on) comes from internal `ModuleType` metadata; the lowercase kebab-case module ID is rendered unchanged as the module name.
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

- **Identity and tenancy**: `UUID` (primary key), `ProjectUUID`, `ScanUUID`, `RequestHash`
- **Host info**: `Scheme`, `Hostname`, `Port`, `IP`
- **Request**: `Method`, `Path`, `URL`, HTTP version, content type/length, raw bytes, authorization summary, request hash
- **Response**: status/phrase/version, content type/length, raw bytes, exact and normalized hashes, timing, word count, title, and `HasResponse`
- **Parameters**: `Parameters` (JSONB array of `EmbeddedParam`)
- **Analysis**: technologies, content hash, authentication state, parent record, `RiskScore`, and `Remarks`
- **Metadata**: `Source`, `SentAt`, `ReceivedAt`, `CreatedAt`

#### Finding (table: `findings`)

- **Identity and tenancy**: `ID` (auto-increment), `ProjectUUID`, `FindingHash` (project-scoped unique dedup identity)
- **Run links**: `ScanUUID`, `AgenticScanUUID`, plus denormalized URL and hostname
- **Module/routing info**: `ModuleID`, `ModuleName`, `ModuleType`, `FindingSource`, `RecordKind`, `EvidenceGrade`, tags, description, severity, and confidence
- **Lifecycle/classification**: status, remediation, CWE, CVSS, source file, and repository name
- **Match data**: `MatchedAt` (JSONB array), `ExtractedResults`, `Request`, `Response`
- **Relations**: `HTTPRecordUUIDs` (JSONB array)
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
| `SaveFinding()` | Project-scoped hash dedup; append new record links/evidence on conflict; maintain junction rows |
| `DeduplicateFindings()` | Post-phase grouping: merge findings sharing (module_id, severity, matched_at URL) |
| `CreateScanWithCursor()` | Creates scan record, copies cursor from last completed scan |
| `CountRecordsAfterCursor()` | Counts new records since cursor (used for feedback loop) |
| `GetRecordsWithResponseBody()` | UUID-cursor pagination for the native secret detector and other batch consumers |
| `UpdateRiskScores()` | Batch CASE/WHEN UPDATE, 500 UUIDs per statement |

### RecordWriter — `pkg/database/record_writer.go`

Batched asynchronous persistence for high-throughput ingestion:

```go
type RecordWriter struct {
    repo      *Repository
    cfg       RecordWriterConfig   // BufferSize=4096, BatchSize=128, FlushInterval=50ms
    shards    []*writerShard       // host-hashed queues; backpressure per queue
    dedupCache *lru.Cache[string, string]
}
```

- `Write()` converts to `HTTPRecord`, checks the bounded in-memory dedup cache, sends to the host's buffered shard, and waits for that write's result.
- Each shard accumulates a batch and flushes on batch-full or ticker-fire via `repo.SaveRecordsBatch()`. SQLite defaults to one shard; PostgreSQL defaults to four.
- Each caller gets a `WriteResult{UUID, Err}` back on a per-request result channel.

`FindingWriter` performs the analogous low-volume finding path without blocking the scan worker: it buffers up to 1024 items, batches 64 findings per transaction or every 50 ms, and falls back to a synchronous save if its queue is full or closing. Both writers drain on shutdown with a bounded timeout.

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
- In static mode, each host gets a buffered-channel semaphore capped at `MaxPerHost`. The standalone limiter default is 20; the normal scanner passes the resolved scanning-pace value, whose default is 40.
- `Acquire(ctx, host)` blocks until a slot is free; `Release(host)` frees a slot.
- Background eviction goroutine removes idle entries (default: 30s idle, checked every 10s).
- Per-shard capacity cap with oldest-entry eviction when exceeded.
- Optional AIMD pacing starts at the configured ceiling and backs off on distress. The runner also enables reactive WAF auto-arm: healthy hosts remain at full concurrency until a WAF/CDN block is observed. A detected edge can be pre-armed earlier; `--no-waf-pacing` disables that proactive step, not reactive back-off.

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

Four levels of deduplication prevent noise and redundancy:

1. **Request-level**: `DedupManager` prevents scanning duplicate requests (checked before module dispatch).

2. **Finding-level (inline)**: the project-scoped `finding_hash` constraint atomically rejects a duplicate insert. `appendRecordsToFinding()` then appends new HTTP record UUIDs, the request/response pair (as `AdditionalEvidence`), and the latest scan link to the existing finding instead of creating another row.

3. **Finding-level (post-phase grouping)**: `DeduplicateFindings()` runs after the KnownIssueScan and dynamic-assessment phases. It groups findings that share the same `(module_id, severity, matched_at[0] URL)` within a project — this catches cases where the same module fires multiple times on the same URL with different payloads (e.g., an injection probe producing dozens of results per endpoint).

   The grouping process:
   - Partitions findings by `module_id || severity || matched_at[0]` and orders by `created_at ASC`
   - Keeps the earliest finding per group as the **survivor**
   - Collects request/response pairs from duplicates into the survivor's `AdditionalEvidence` field (capped at 10 entries to bound storage)
   - Deletes all duplicate findings and their `finding_records` junction rows
   - Returns counts of deleted findings and merged groups for user feedback

4. **Finding-level (value grouping)**: `GroupFindingsByValue()` runs as a second post-phase pass (controlled by `known_issue_scan.group_by_value`, on by default). It collapses findings that repeat the *same extracted value* across many URLs — keyed on `(module_id, severity[, hostname], normalized extracted_results)` — so one leaked secret surfaced on dozens of pages becomes a single finding. Modules listed in `by_module` are a stronger case: they collapse on `(module_id, severity[, hostname])` **regardless of** the per-URL value, for modules that fire once per asset where the differing value is noise rather than signal (e.g. `sourcemap-detect`, one `.map` filename per bundle; `unsafe-html-sink` and the source-analysis lead family, one snippet context per JS file; `cookie-security-detect`, one finding per Set-Cookie response). Grouping is per-host by default (`per_host`), so the same value on two hostnames stays two findings, and the survivor's `matched_at` retains every affected URL up to `max_urls`. Secret-bearing modules (`env-secret-exposure`) are kept out of `by_module` so distinct leaked values remain distinct findings.

```
Phase completes (KnownIssueScan or dynamic-assessment)
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
    │                 RunNativeScan() plan                   │
    │                                                        │
    │  [Heuristics/Ports] → [Harvest] → [Spider]            │
    │       → [Discovery/Ingest] → [Re-Spider]              │
    │       → [Dynamic Assess] → [Known-Issue Scan]         │
    │                                                        │
    │  Recon phases populate DB records                      │
    │  Assessment phases scan records and group findings    │
    └───────────────────────┬────────────────────────────────┘
                            │
                            ▼  (executor detail)
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
    │    4. Body classify/truncate + full scope status  │
    │    5. Passive host/request modules                │
    │    6. Body action + persistence/scope gate        │
    │    7. Eligibility pre-computation                 │
    │    8. Active host/request/IP tasks (one pool)     │
    │                                                   │
    │  Post-processing:                                 │
    │    Flush passive side effects + batch findings    │
    │    Flush OAST service (grace period)              │
    └───────────────────────┬───────────────────────────┘
                            │
                            ▼
    ┌───────────────────────────────────────────────────┐
    │              Result Emission                       │
    │                                                   │
    │  assignModuleInfo() → emitResult():               │
    │    1. Post-hooks (JS transform/filter)            │
    │    2. Finding-only cap/admission by final identity│
    │    3. SaveFinding() to DB (dedup via finding_hash │
    │       + evidence append on conflict)              │
    │    4. Route finding/candidate/observation callback│
    │    5. Notify only a newly admitted finding        │
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
| Runner | `internal/runner/runner.go` | `RunNativeScan()` | Options + Settings | Phase results |
| Executor | `pkg/core/executor.go` | `Execute()` → `processItem()` | `InputSource` + modules | `bool` (found results) |
| Insertion Points | `pkg/httpmsg/insertion_point.go` | `CreateAllInsertionPoints()` | Raw request bytes | `[]InsertionPoint` |
| Module Dispatch | `pkg/modules/` | `ScanPer{Host,Request,InsertionPoint}()` | `*HttpRequestResponse` | `[]*ResultEvent` |
| Result Emission | `pkg/core/executor.go` | `emitResult()` | `*ResultEvent` | DB write + output |
| Output | `pkg/output/output.go` | `StandardWriter.Write()` | `*ResultEvent` | Console/JSON/HTML/file |
| DB Persistence | `pkg/database/` | `SaveRecord()`, `SaveFinding()` | HTTP types / ResultEvent | `HTTPRecord`, `Finding` |
