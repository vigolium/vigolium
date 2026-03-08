# Project Structure

This document maps out the Vigolium codebase: directory layout, package responsibilities, and how the pieces fit together.

## Repository Layout

```
vigolium/
├── cmd/vigolium/          # CLI entry point
├── internal/              # Private application code
│   ├── config/            # Configuration management
│   ├── ingestor/          # Standalone ingestion client
│   ├── logger/            # Zap-based structured logging
│   ├── resources/         # Embedded binaries, wordlists, templates
│   └── runner/            # Multi-phase scan orchestrator
├── pkg/                   # Public library packages
│   ├── agent/             # AI agent engine (prompt, context, loop, execution)
│   ├── anomaly/           # Response anomaly detection and ranking
│   ├── cli/               # Cobra CLI commands
│   ├── core/              # Executor, worker pool, rate limiter
│   ├── database/          # Repository pattern ORM (SQLite/PostgreSQL)
│   ├── dedup/             # Request/finding deduplication
│   ├── deparos/           # Content discovery engine
│   ├── harvester/         # External URL harvesting (Wayback, etc.)
│   ├── http/              # HTTP requester with middleware pipeline
│   ├── httpmsg/           # HTTP message models and insertion points
│   ├── input/             # Input format adapters
│   ├── jsext/             # JavaScript extension engine (Sobek)
│   ├── kingfisher/        # Secret/credential scanning
│   ├── metrics/           # Prometheus metrics collector
│   ├── modules/           # Scanner module interfaces and registry
│   ├── notify/            # Notification backends (Discord, Telegram)
│   ├── output/            # Result formatting and file output
│   ├── queue/             # Hybrid in-memory/disk/Redis queue
│   ├── server/            # REST API server (Fiber)
│   ├── sourcetools/       # Third-party SAST tool integration
│   ├── spa/               # Security Posture Assessment (Nuclei)
│   ├── spitolas/          # Browser-based spider (Chromium/CDP)
│   ├── terminal/          # Terminal UI, colors, symbols
│   ├── types/             # Shared types and options
│   ├── utils/             # General utilities
│   └── work/              # Work item abstraction
├── public/                # User-facing presets and examples
│   ├── presets/extensions/ # JavaScript extension examples
│   ├── presets/profiles/  # Scanning profile YAML files
│   └── presets/prompts/   # Agent prompt templates (Markdown)
├── build/                 # Dockerfile for production image
├── test/                  # Integration, E2E, canary, benchmark tests
├── docs/                  # Documentation
├── Makefile               # Build, test, and release targets
├── go.mod                 # Go 1.26+ module definition
└── .goreleaser.yaml       # Multi-platform release automation
```

## Execution Pipeline

```
Input Sources (URLs, OpenAPI, Burp, cURL, ...)
  │
  ▼
Ingestion ──► Database (SQLite/PostgreSQL)
  │
  ▼
┌─────────────────────────────────────────────┐
│  Runner (internal/runner)                   │
│  Phase 1: External Harvesting (opt-in)      │
│  Phase 2: Content Discovery — Deparos       │
│  Phase 3: Browser Spidering — Spitolas      │
│  Phase 4: SPA — Nuclei + Kingfisher         │
│  Phase 5: Dynamic Assessment — Executor     │
└──────────────────┬──────────────────────────┘
                   ▼
┌─────────────────────────────────────────────┐
│  Executor (pkg/core)                        │
│  Worker pool → Module dispatch → Results    │
│  ├── Active modules (send modified requests)│
│  └── Passive modules (analyze traffic)      │
└──────────────────┬──────────────────────────┘
                   ▼
          Output / Notifications
```

## Entry Point

### `cmd/vigolium/`

Single `main.go` — prints the CLI banner, calls `cli.Execute()`, and handles `--json`/`version` flags. All real logic lives in `pkg/cli/` and `internal/runner/`.

## Internal Packages

### `internal/config/`

Configuration management: loads YAML files with environment variable expansion, applies scanning profile overlays, and validates settings.

| File | Purpose |
|------|---------|
| `loader.go` | YAML loading, profile overlay, path normalization |
| `scanning_strategy.go` | Strategy presets (lite, balanced, deep, whitebox) |
| `scanning_pace.go` | Per-phase concurrency, rate limit, max duration |
| `scope.go`, `scope_matcher.go` | Scope rules and pattern matching (host, path, status, content-type) |
| `discovery.go` | Deparos discovery settings (wordlists, recursion, extensions) |
| `spidering.go` | Browser automation settings (depth, states, duration, engine) |
| `dynamic_assessment.go` | Module selection and enabled module lists |
| `extensions.go` | JavaScript extension config (timeout, memory, sandbox) |
| `server.go`, `database.go` | Server and database connection settings |
| `notify.go` | Notification backend configuration |
| `oast.go` | OAST (out-of-band) service config: interactsh server URL, poll interval, grace period, blind XSS |
| `mutation_strategy.go` | Value-aware mutation config: default modes, field type defaults, per-intent limits, enum/synonym mappings |
| `flatconfig.go` | Flat dot-notation display with sensitive key masking |

### `internal/runner/`

High-level orchestrator for the 5-phase scanning pipeline. `runner.go` coordinates input sources, infrastructure setup (HTTP requester, scope matcher, rate limiter, notifier, JS engine), scan execution, result output, statistics, and panic recovery.

### `internal/ingestor/`

Standalone HTTP ingestion client. Parses input (URLs, Nuclei JSON, OpenAPI specs), submits to a remote Vigolium server via concurrent workers with rate limiting.

### `internal/logger/`

Zap logger factory with four log levels (Debug, Info, Error, Silent). Console encoder uses ANSI colors; optional file output writes plain JSON to timestamped logs.

### `internal/resources/`

Embedded runtime resources compiled into the binary:

| Subdirectory | Contents |
|---|---|
| `deparos/` | Default discovery config, jsscan binaries (per-platform), wordlists (`dir-short.txt`, `dir-long.txt`, `file-short.txt`, `file-long.txt`, `fuzz.txt`), HTML report template |
| `spitolas/` | Chromium browser archives (per-platform), version metadata, extraction and caching logic |
| `scripts/` | Shell scripts for Chrome download/update, dependency verification |

## Public Library Packages (`pkg/`)

### Core Execution

#### `pkg/core/`

Central executor that receives `HttpRequestResponse` items, distributes them to registered modules via a concurrent worker pool, and collects `ResultEvent` findings. Supports pre/post hooks, scope filtering, response buffer pooling (up to 1 MiB), and request-to-UUID tracking.

| Sub-package | Purpose |
|---|---|
| `hosterrors/` | Circuit breaker — LRU-based host error cache (ARC algorithm), skips hosts exceeding error threshold |
| `network/` | FastDialer wrapper for DNS resolution; `MemGuardian` monitors memory every 15s and throttles concurrency under pressure |
| `ratelimit/` | Per-host concurrency limiter using sharded semaphores (32 buckets), auto-evicts idle hosts after 30s |
| `stats/` | Atomic progress tracker, prints items/sec rate every 5s |
| `services/` | Dependency injection container aggregating Options, HostRateLimiter, error cache, notifier, dialer, dedup manager |

#### `pkg/work/`

`WorkItem` struct wrapping `HttpRequestResponse` with module selection, database record UUID, and optional completion callback (used by queue-based sources for acknowledgment).

### Scanner Modules

#### `pkg/modules/`

Pluggable vulnerability scanning framework. All modules implement either `ActiveModule` (sends modified requests) or `PassiveModule` (analyzes existing traffic). Thread-safe, registered in a central `Registry`.

| File | Purpose |
|------|---------|
| `module.go` | Base `Module` interface — ID, Name, Severity, Confidence, ScanScopes, Tags, CanProcess |
| `active.go` | `ActiveModule` interface — `ScanPerInsertionPoint`, `ScanPerRequest`, `ScanPerHost` |
| `passive.go` | `PassiveModule` interface — analysis methods, optional `Flusher` for end-of-scan finalization |
| `registry.go` | Thread-safe module registration and lookup |
| `default_registry.go` | Pre-built registry with 127 active and 83 passive built-in modules |

| Sub-package | Purpose |
|---|---|
| `modkit/` | Module development toolkit: type definitions (`ScanScope`, `InsertionPointTypeSet`, `PassiveScanScope`), `BaseActiveModule`/`BasePassiveModule` default implementations, `ScanContext` (with OAST and mutation providers), baseline caching |
| `active/` | 127 active scanner implementations organized by vulnerability type (XSS, SQLi, SSTI, LFI, SSRF, XXE, CRLF, CSRF, IDOR, NoSQLi, GraphQL, file upload, default credentials, OAST probing, race conditions) and framework-specific probes (Spring, Rails, Django, Flask, Laravel, Express, ASP.NET, Next.js, Firebase, WordPress, Drupal, Joomla, etc.) |
| `passive/` | 83 passive analyzers (DOM XSS, auth headers, secrets, security headers, cookie security, CORS, mixed content, IDOR params, error messages, framework fingerprinting, SSR data exposure, cloud storage, API detection, etc.) |
| `infra/` | Block detection (WAF/CDN: Cloudflare, Akamai, CloudFront, Incapsula), request filtering, HTTP method swapping |
| `shared/authzutil/` | Authorization testing utilities — parameter classification for object IDs, neighbor ID generation, authorization enforcement detection, response comparison for differential analysis |
| `shared/diffscan/` | Differential response analysis engine — probes, attacks, response snapshots, quantitative measurements, fingerprint comparison |

See [developing-modules.md](developing-modules.md) for the module authoring guide.

### Discovery and Spidering

#### `pkg/deparos/`

Adaptive content discovery engine: directory/file enumeration with fingerprint-based soft-404 detection, dynamic wordlist growth, and multi-source link extraction.

| Sub-package | Purpose |
|---|---|
| `discovery/` | Core discovery orchestrator — task coordination, payload generation (`payload/`), module-based filtering (`module/`), task queue (`queue/`), error tracking, redirect handling |
| `fingerprint/` | Soft-404 detection — 3-baseline signature learning, 38+ response attributes, anomaly scoring, frequency analysis |
| `spider/` | Static link extraction from HTML (attributes, forms, comments, meta refresh, event handlers), JavaScript string literals, HTTP headers, `robots.txt` |
| `jsscan/` | JavaScript analysis — deobfuscation, string concatenation resolution, `fetch()`/`XHR`/`$.ajax` call site extraction; Aho-Corasick pattern matching via `linkfinder/` |
| `wordlist/` | Runtime wordlist extraction from response bodies — content-type-aware tokenizer with HTML, JSON, JS, CSS, and plaintext preprocessors |
| `storage/` | Thread-safe result storage — SQLite/PostgreSQL via repository pattern, sitemap management, FNV-1a-64 deduplication |
| `http/` | HTTP client infrastructure — connection pooling, retry/rate-limit middleware, fluent request builder, response analyzer |
| `config/` | Discovery configuration structures, builder pattern, validation, file loading |
| `scope/` | URL scope validation — any, subdomain (eTLD+1), or exact host matching |
| `waf/` | WAF detection and tracking |
| `tag/` | Semantic endpoint classification (API key, JWT, error page, modern app, JSON data) |
| `responsechain/` | Response chain management, normalization, cookie jar |
| `casesense/` | Filesystem case sensitivity detection |
| `reqcache/` | Hash map-based request result caching |

See [../scan-layers/deparos.md](../scan-layers/deparos.md) and [../scan-layers/deparos-configs-guide.md](../scan-layers/deparos-configs-guide.md).

#### `pkg/spitolas/`

Browser-based state-machine crawler driving headless Chromium via CDP. Discovers application states through user-like interactions (clicking, form filling, iframe traversal). All HTTP traffic is captured and fed into the scanning pipeline.

| Sub-package | Purpose |
|---|---|
| `internal/crawler/` | Core crawl engine — browser pool, form handler, state machine, backtracking |
| `internal/network/` | CDP-based HTTP traffic capture, conversion to `HttpRequestResponse`, database writer |
| `internal/browser/` | Browser lifecycle management and pooling |
| `internal/state/` | State machine, state graph, near-duplicate clustering, crawl path tracking |
| `internal/form/` | Form detection, field-aware filling, training |
| `internal/action/` | Clickable element detection and interaction |
| `internal/fragment/` | DOM fragment management |
| `internal/mab/` | Multi-armed bandit (Exp3.1) strategy for adaptive exploration |
| `internal/condition/` | Crawl termination and wait conditions |
| `internal/metrics/` | Crawl metrics: code coverage, link coverage, CSV output |
| `internal/auth/` | Authentication bootstrap for crawling authenticated apps |
| `rod/` | Local fork of go-rod — browser control, page manipulation, element interaction, request hijacking, JS evaluation |
| `extension/` | Chrome extensions for traffic filtering; includes uBlock Origin integration |

See [../scan-layers/spitolas.md](../scan-layers/spitolas.md) and [../scan-layers/spa.md](../scan-layers/spa.md).

#### `pkg/spa/`

Security Posture Assessment integration. Runs Nuclei templates and Kingfisher secret detection against in-scope hosts. Supports template tag/severity filtering, custom templates directory, rate limiting, and proxy support.

#### `pkg/harvester/`

Aggregates URLs from external intelligence sources with timeout and deduplication:

- Wayback Machine
- Common Crawl
- AlienVault OTX
- URLScan.io (API key required)
- VirusTotal (API key required)

### HTTP and Messaging

#### `pkg/httpmsg/`

HTTP request/response modeling following Burp Suite Montoya API design patterns. Includes parameter parsing, insertion point discovery, and encoding utilities.

| File | Purpose |
|------|---------|
| `http_request_response.go` | Core `HttpRequestResponse` struct coupling request and response |
| `insertion_point.go`, `insertion_point_impl.go` | Insertion point abstraction for parameter injection |
| `insertion_point_header.go` | Header-based insertion points: existing header fuzzing + synthetic header injection (X-Forwarded-For, X-Forwarded-Host, Referer, True-Client-IP, X-Real-IP) |
| `param.go`, `param_type.go` | Parameter modeling and type system |
| `request_builder*.go` | Fluent request construction (headers, cookies, params, body) |
| `request_analyzer.go`, `response_analyzer.go` | Request/response analysis |
| Format-specific parsers | `query_parser`, `path_parser`, `header_parser`, `json_parser`, `xml_parser`, `multipart_parser`, `urlencoded_parser` |

#### `pkg/http/`

Low-level HTTP requester wrapping `retryablehttp` and `rawhttp` clients with cookie jar, TLS config, custom headers, and middleware pipeline.

### Input and Output

#### `pkg/input/`

Converts various security tool output formats into normalized HTTP request streams.

| Sub-package | Purpose |
|---|---|
| `formats/` | Format parsers: `openapi/`, `burpxml/`, `burpraw/`, `postman/`, `curl/`, `nuclei/`, `crawlerxdir/`, `urls/`, `apivoyagerlist/` |
| `source/` | Request stream providers: file, stdin, concurrent wrapper, multi-source aggregation, deparos/harvester integration |

#### `pkg/output/`

Result formatting compatible with Nuclei JSONL format. Supports JSON/JSONL, terminal tables with colors, and file output with atomic writes. `ResultEvent` carries module ID, severity, confidence, matched URL, extracted results, and raw request/response data.

#### `pkg/cli/`

Cobra-based CLI commands covering all scanner operations:

| Command group | Key files |
|---|---|
| Scanning | `scan.go`, `run.go`, `scan_url.go`, `scan_request.go` |
| Ingestion | `ingest.go` |
| Server | `server.go` |
| Agent | `agent.go`, `agent_loop.go` |
| Database | `db.go`, `db_clean.go`, `db_export.go`, `db_list.go`, `db_seed.go`, `db_stats.go` |
| Configuration | `config.go`, `config_clean.go`, `config_ls.go`, `config_set.go` |
| Modules | `module.go`, `module_enable.go` |
| Extensions | `extensions.go`, `extensions_eval.go` |
| Scope/Traffic/Strategy | `scope*.go`, `traffic*.go`, `strategy.go` |
| Source repos | `source.go`, `source_add.go`, `source_scan.go` |
| Projects | `project.go` — multi-tenant project management (create, list, use, config) |
| Setup | `init.go`, `root.go` |

### Data and Storage

#### `pkg/database/`

Repository pattern ORM over SQLite (default) or PostgreSQL using Bun ORM. Manages HTTP records, findings, scan sessions, source repos, and scope data. Includes write-coalescing record writer, schema initialization, and statistics queries. All data tables include a `project_uuid` column for multi-tenant isolation (see [projects.md](../projects.md)).

#### `pkg/queue/`

Hybrid task queue for async scan work:

| File | Purpose |
|------|---------|
| `queue.go` | Queue interface (Enqueue, Dequeue, Ack, Close, Metrics) |
| `hybrid.go` | In-memory + disk spillover |
| `disk.go` | LevelDB-based persistent backend |
| `redis.go` | Redis-based backend |
| `source.go` | Queue-as-InputSource adapter |
| `task.go` | `ScanTask` struct |

### AI Agent Integration

#### `pkg/agent/`

AI agent engine for running coding agents (Claude, OpenCode, Gemini, or custom CLI tools) to perform security analysis. Handles the full pipeline: prompt resolution → context gathering → context enrichment → agent execution → output parsing → database ingestion.

| File | Purpose |
|------|---------|
| `engine.go` | Core orchestrator — `Run()` pipeline, prompt building, context gathering, agent dispatch |
| `context.go` | Context enrichment — populates template variables from database (findings, HTTP records, stats) and module registry |
| `loop.go` | Iterative loop engine — `RunLoop()` for analyze→scan→repeat cycles with convergence detection |
| `prompt.go` | Template loading (embedded, user, config), rendering with `missingkey=zero`, caching |
| `types.go` | `Options`, `TemplateData`, `Result`, `LoopResult`, `AgentFinding`, `AgentHTTPRecord` structs |
| `exec.go` | Agent process execution (pipe protocol), stdin/stdout handling |
| `exec_acp.go` | ACP protocol execution for agent backends |
| `parse.go` | JSON output parsing for `findings` and `http_records` schemas |
| `ingest.go` | Database ingestion of parsed findings and HTTP records |

See [../agent-mode.md](../agent-mode.md) for the full agent mode documentation.

### OAST and Mutation

#### `pkg/oast/`

Out-of-Band Application Security Testing service. Wraps an interactsh client to detect blind vulnerabilities via callback URLs. Generates unique payload URLs with nonce-based tracking, polls for interactions, correlates callbacks with injected payloads, and emits findings asynchronously. Supports fixed URL mode (user-supplied callback) or interactsh server mode, with optional blind XSS script injection.

#### `pkg/mutation/`

Value-aware mutation generation engine. Classifies insertion point values into semantic types (integer, UUID, email, JWT, base64, path, etc.) and generates intelligent mutations per intent (neighbor, boundary, escalation, format, empty). Integrates with OpenAPI schema hints for type-informed fuzzing. Used by modules via the `MutationGenerator` interface on `ScanContext`.

### Extensions and Integrations

#### `pkg/jsext/`

Grafana Sobek-based JavaScript execution engine (ES5.1+, pure Go — no Node.js). Exposes `vigolium.http`, `vigolium.scan`, `vigolium.ingest`, `vigolium.source`, `vigolium.log` APIs. Manages script loading, VM pooling, module/hook registration, and active/passive module interface adapters. TypeScript definitions in `vigolium.d.ts`.

See [writing-extensions.md](writing-extensions.md).

#### `pkg/kingfisher/`

Secret and credential scanning. Integrates with the Kingfisher binary analysis tool — manages binary download, version management, and result parsing.

#### `pkg/sourcetools/`

Orchestrates running third-party SAST tools against source code repositories. Handles tool execution, output parsing, and finding format conversion.

#### `pkg/notify/`

Async notification queue dispatching findings to backends with severity filtering:

- `discord/` — Discord webhook integration with embed formatting
- `telegram/` — Telegram bot integration with message formatting

### Supporting Packages

| Package | Purpose |
|---|---|
| `pkg/anomaly/` | Response anomaly detection — fingerprinting, frequency tracking, scoring, HTML/HTTP attribute extraction |
| `pkg/dedup/` | Request/finding deduplication using disk-backed sets and hash management |
| `pkg/metrics/` | Prometheus collector exposing uptime, queue depth, DB stats, scan state, memory usage |
| `pkg/terminal/` | Terminal width detection, ANSI colors, status symbols, table formatting, CI/NO_COLOR support |
| `pkg/types/` | Shared `Options` struct; `severity/` and `stringslice/` sub-packages |
| `pkg/utils/` | Hashing, random generation, string manipulation, TLS handling, JSON utilities |

## Build and Test Infrastructure

### Top-Level Files

| File | Purpose |
|------|---------|
| `Makefile` | Build, test, deps, Docker, release, vulnerable app management |
| `go.mod` | Module `github.com/vigolium/vigolium`, Go 1.26+ |
| `.goreleaser.yaml` | Multi-platform release (Linux/macOS/Windows, amd64/arm64) |
| `build/Dockerfile` | Full production image (Debian bookworm-slim, Chromium, Python, SAST tools) |
| `build/Dockerfile.minimal` | Minimal Alpine image (ca-certificates only, non-root, ~30 MB) |

### `public/`

| Directory | Contents |
|---|---|
| `presets/profiles/` | Scanning profile YAML files (e.g., `standard.yaml`) embedded via `go:embed` |
| `presets/extensions/` | 8 JavaScript extension examples embedded via `go:embed` |
| `presets/prompts/` | Agent prompt templates (Markdown with YAML frontmatter) embedded via `go:embed` — includes `security-code-review`, `interactive-scan`, `targeted-retest`, `attack-surface-mapper`, and more |
| `vigolium-configs.example.yaml` | Complete reference configuration with all settings documented |

### `test/`

| Directory | Tag | Requirements | Purpose |
|---|---|---|---|
| `test/e2e/` | `e2e` | Docker | 16 test suites against DVWA, VAmPI, Juice Shop; server tests, pipeline tests, parser tests |
| `test/benchmark/blackbox/` | `integration` | Internet | Active/passive module benchmarks against external sites (Acunetix, GinAndJuice, Testfire) |
| `test/benchmark/whitebox/` | `canary` | Docker | Active/passive/crAPI tests against Docker-based vulnerable apps |
| `test/benchmark/xbow/` | `integration` | Internet | XBOW vulnerability benchmark suite (13 test cases: CMDi, LFI, SQLi, SSRF, SSTI, XSS, XXE) |
| `test/benchmark/coverage/` | — | — | Module coverage matrix report generation |
| `test/benchmark/harness/` | — | — | Shared test infrastructure: Docker Compose orchestration, container management, passive helpers, report generation |
| `test/benchmark/definitions/` | — | — | YAML benchmark definitions for vulnerable apps and XBOW test cases |
| `test/deparos/` | — | — | Spider, scope filtering, PostgreSQL persistence tests + mock spider-app fixture |
| `test/spitolas/` | — | — | Browser crawl tests + multi-depth HTML maze fixture |
| `test/testdata/sample-inputs/` | — | — | Burp exports, OpenAPI specs, Postman collections, cURL examples |
| `test/testdata/extensions/` | — | — | Test JavaScript extensions |
| `test/testdata/vulnerable-apps/` | — | Docker | Docker Compose configs for crAPI, VAmPI, Juice Shop |
| `test/pkg-testdata/` | — | — | Package-level test fixtures (anomaly baselines) |

See [building.md](building.md) for build commands and test tiers.
