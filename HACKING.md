# Hacking on Vigolium

This guide gives developers a high-level understanding of Vigolium's architecture, tech stack, and codebase conventions. If you want to contribute a feature, fix a bug, or write a new scanner module, start here.

## What is Vigolium?

Vigolium is a high-fidelity web vulnerability scanner written in Go. It can run as:

1. **CLI scanner** — scan targets directly from the command line
2. **REST API server** — receive traffic via HTTP endpoints or a transparent proxy, scan on demand
3. **Standalone ingestor** — submit traffic to a remote Vigolium server

It scans for reflected XSS, SQL injection, SSTI, LFI, CRLF injection, open redirects, command injection, path traversal, XXE, race conditions, and more through a pluggable module system.

## Architecture Overview

```
                        ┌──────────────────────────────────┐
                        │         Input Sources            │
                        │  URLs, OpenAPI, Burp, cURL,      │
                        │  Postman, Nuclei, stdin, proxy    │
                        └──────────────┬───────────────────┘
                                       ▼
                        ┌──────────────────────────────────┐
                        │     Ingestion & Database         │
                        │  Parse → HttpRequestResponse     │
                        │  Store in SQLite / PostgreSQL    │
                        └──────────────┬───────────────────┘
                                       ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    Runner (5-phase pipeline)                        │
│                                                                      │
│  Phase 1: External Harvesting ─── Wayback, CommonCrawl, OTX, etc.  │
│  Phase 2: Content Discovery ───── Deparos (dir/file brute-force)   │
│  Phase 3: Browser Spidering ───── Spitolas (Chromium + CDP)        │
│  Phase 4: SPA ─────────────────── Nuclei templates + Kingfisher    │
│  Phase 5: Audit ───────────────── Executor + scanner modules       │
│                                                                      │
└──────────────────────────────────┬───────────────────────────────────┘
                                   ▼
┌──────────────────────────────────────────────────────────────────────┐
│                     Executor (pkg/core)                             │
│                                                                      │
│  Worker pool → Scope filter → Baseline fetch → Module dispatch     │
│                                                                      │
│  ┌─────────────────────┐     ┌─────────────────────────────────┐   │
│  │   Active Modules     │     │   Passive Modules               │   │
│  │   Send modified      │     │   Analyze existing traffic      │   │
│  │   requests with      │     │   without new requests          │   │
│  │   injected payloads  │     │                                 │   │
│  └──────────┬──────────┘     └──────────────┬──────────────────┘   │
│             └──────────────┬────────────────┘                      │
│                            ▼                                        │
│                     ResultEvent findings                            │
└──────────────────────────────┬──────────────────────────────────────┘
                               ▼
              ┌────────────────────────────────┐
              │  Output / Storage / Notify     │
              │  Terminal, JSON, file, DB,     │
              │  Discord, Telegram             │
              └────────────────────────────────┘
```

Each phase is optional. **Scanning strategies** (`lite`, `balanced`, `deep`, `whitebox`) control which phases run. **Scanning profiles** bundle strategy + pace + scope + module config into a single YAML.

## Tech Stack

| Area | Technology | Package |
|------|-----------|---------|
| Language | Go 1.26+ | `CGO_ENABLED=0`, pure Go (including SQLite) |
| CLI framework | Cobra | `github.com/spf13/cobra` |
| REST API server | Fiber v3 | `github.com/gofiber/fiber/v3` |
| Database ORM | Bun | `github.com/uptrace/bun` (SQLite + PostgreSQL) |
| Browser automation | rod (local fork) | `pkg/spitolas/rod/` — Chromium via CDP |
| JS extension engine | Sobek (Grafana) | `github.com/grafana/sobek` — ES5.1+, pure Go |
| Template scanning | Nuclei v3 | `github.com/projectdiscovery/nuclei/v3` |
| HTTP client | retryablehttp + rawhttp | `github.com/projectdiscovery/retryablehttp-go` |
| Queue (disk) | LevelDB | `github.com/syndtr/goleveldb` |
| Queue (remote) | Redis | `github.com/redis/go-redis/v9` |
| Metrics | Prometheus | `github.com/prometheus/client_golang` |
| Logging | Zap | `go.uber.org/zap` |
| Testing | testify + gotestsum + testcontainers | `github.com/stretchr/testify` |
| Release | GoReleaser | `.goreleaser.yaml` |

## Project Structure (Summary)

```
cmd/vigolium/           Single main.go entry point
internal/
  config/               YAML config loading, strategy/pace/scope definitions
  runner/               5-phase scan orchestrator
  ingestor/             Standalone ingestion client
  logger/               Zap logger setup
  resources/            Embedded binaries (jsscan, Chromium), wordlists, templates
pkg/
  cli/                  All Cobra commands (scan, server, ingest, db, config, ...)
  core/                 Executor, worker pool, rate limiter, services DI container
  modules/              Module interfaces, registry, 24 active + 13 passive scanners
    modkit/             Base types, default implementations (BaseActiveModule, etc.)
    active/             Active scanner implementations (XSS, SQLi, SSTI, LFI, ...)
    passive/            Passive analyzers (DOM XSS, secrets, headers, cookies, ...)
    shared/diffscan/    Differential response analysis engine
    infra/              WAF/block detection, request filtering
  agent/                AI agent engine — SDK/ACP/Codex/OpenCode runners, terminal sandbox, swarm runner, warm session pooling, prompt templates
  deparos/              Content discovery engine (Deparos)
  spitolas/             Browser spider (Spitolas) — Chromium, state machine, forms
  spa/                  Nuclei + Kingfisher integration
  httpmsg/              HTTP message models, insertion points, parameter parsers
  http/                 HTTP requester with middleware
  input/                Input format adapters (OpenAPI, Burp, Postman, cURL, ...)
  database/             Repository pattern ORM (SQLite/PostgreSQL)
  queue/                Hybrid in-memory/disk/Redis queue
  server/               REST API server, Swagger UI, proxy
  jsext/                JavaScript extension engine and vigolium.* APIs
  output/               Result formatting (JSON, terminal, file)
  harvester/            External URL harvesting (Wayback, CommonCrawl, OTX, ...)
  anomaly/              Response anomaly detection and scoring
  dedup/                Request/finding deduplication
  kingfisher/           Secret/credential scanning
  notify/               Notification backends (Discord, Telegram)
  metrics/              Prometheus metrics collector
  sourcetools/          Third-party SAST tool integration
  terminal/             Terminal UI, ANSI colors, table formatting
  types/                Shared Options struct, severity/confidence enums
  utils/                Hashing, random gen, TLS, JSON utilities
  work/                 WorkItem abstraction for executor pipeline
public/
  presets/profiles/     Scanning profile YAML files (embedded)
  presets/extensions/   JavaScript extension examples (embedded)
build/                  Dockerfile
test/                   E2E, canary, benchmark, deparos, spitolas tests
```

For the full package-level breakdown with file descriptions, see [docs/development/project-structure.md](docs/development/project-structure.md).

## Key Abstractions

### HttpRequestResponse

The universal data type flowing through the entire pipeline. Defined in `pkg/httpmsg/http_request_response.go`, it couples an HTTP request with its response and service metadata. Every input adapter produces these, every module consumes them.

### Insertion Points

Active modules inject payloads at specific locations in a request. `pkg/httpmsg/insertion_point.go` defines the abstraction — URL params, body params, cookies, headers, JSON values, XML values, path components, parameter names, and entire body. Each provides `BuildRequest(payload)` to construct the modified request.

### Module Interface

All scanner modules implement `Module` (base) plus either `ActiveModule` or `PassiveModule`:

```go
// Base — all modules
type Module interface {
    ID() string                              // "active-xss-reflected"
    Name() string                            // "Reflected XSS Scanner"
    Severity() severity.Severity             // High, Medium, Low, Info
    Confidence() severity.Confidence         // Certain, Firm, Tentative
    ScanScopes() ScanScope           // PerInsertionPoint | PerRequest | PerHost
    CanProcess(ctx *HttpRequestResponse) bool
    // ... Description, ShortDescription, ConfirmationCriteria
}

// Active — sends modified requests
type ActiveModule interface {
    Module
    AllowedInsertionPointTypes() InsertionPointTypeSet
    ScanPerInsertionPoint(ctx, ip, httpClient, scanCtx) ([]*ResultEvent, error)
    ScanPerRequest(ctx, httpClient, scanCtx) ([]*ResultEvent, error)
    ScanPerHost(ctx, httpClient, scanCtx) ([]*ResultEvent, error)
}

// Passive — analyzes existing traffic
type PassiveModule interface {
    Module
    Scope() PassiveScanScope
    ScanPerRequest(ctx, scanCtx) ([]*ResultEvent, error)
    ScanPerHost(ctx, scanCtx) ([]*ResultEvent, error)
}
```

Modules must be **thread-safe** — scan methods are called concurrently from the worker pool.

### ResultEvent

The output type for findings. Defined in `pkg/output/output.go`. Carries module ID, severity, confidence, matched URL, extracted data, and raw request/response. Compatible with Nuclei JSONL format.

### Executor

`pkg/core/executor.go` is the central orchestrator. It pulls `WorkItem`s from input sources, fetches baseline responses, extracts insertion points, dispatches to matching modules, and collects results. It manages per-host rate limiting, scope filtering, response buffer pooling, and pre/post hooks.

## Getting Started

### Prerequisites

- **Go 1.26+** (the project compiles with `CGO_ENABLED=0`)
- **git** and **make**
- **Docker** (only for E2E/canary tests)
- **golangci-lint** (only for linting)

No system-level C libraries required. See [docs/development/building.md](docs/development/building.md) for full details.

### Build and Run

```bash
git clone https://github.com/vigolium/vigolium.git
cd vigolium
make deps           # download Go modules + jsscan binaries
make deps-chrome    # download Chromium archives (needed for spider)
make build          # build and install to $GOPATH/bin
vigolium version    # verify
```

### Run Tests

```bash
make test-unit      # fast unit tests, no external deps
make test           # all tests
make test-race      # all tests with race detector
make lint           # golangci-lint
make fmt            # format code
```

Run a single test:

```bash
go test -v -run TestFunctionName ./pkg/path/to/package/...
```

See [docs/development/building.md](docs/development/building.md) for the complete test tier reference (unit, E2E, canary, benchmark, integration).

## Common Development Tasks

### Adding a Scanner Module (Go)

This is the most common contribution type. Modules live in `pkg/modules/active/` or `pkg/modules/passive/`.

1. Create a directory: `pkg/modules/active/my_check/`
2. Implement the `ActiveModule` or `PassiveModule` interface
3. Embed `modkit.BaseActiveModule` or `modkit.BasePassiveModule` for defaults
4. Register in `pkg/modules/default_registry.go`
5. Write tests alongside your module

Module IDs must be kebab-case with prefix: `active-my-check` or `passive-my-check`.

See [docs/development/developing-modules.md](docs/development/developing-modules.md) for the complete walkthrough with examples.

### Writing a JavaScript Extension

Extensions let users add scan logic without recompiling. They run on the embedded Sobek engine (ES5.1+, no Node.js).

- Place `.js` files in `~/.vigolium/extensions/`
- Use the `vigolium.http`, `vigolium.scan`, `vigolium.source` APIs
- TypeScript definitions: `pkg/jsext/vigolium.d.ts`
- Example extensions: `public/presets/extensions/`

See [docs/customization/writing-extensions.md](docs/customization/writing-extensions.md) for the full guide.

### Agent Mode Architecture

The agent system (`pkg/agent/`) integrates with coding agent CLIs via protocol-specific backends:

- **SDK protocol** (`claudesdk/`, `sdk_runner.go`): Claude Agent SDK — JSON-lines communication with full CLI tool access (Read, Grep, Glob, Bash, Edit, Write). Default and recommended.
- **ACP protocol** (`acp_runner.go`, `acp_terminal.go`): Agent Communication Protocol — bidirectional structured communication. Supports sandboxed terminal execution (autopilot mode) with command allowlisting.
- **Codex-SDK** (`codex_runner.go`): OpenAI Codex native JSON-RPC v2 protocol.
- **OpenCode-SDK** (`opencode_runner.go`): OpenCode native REST + SSE streaming protocol.
- **Pipe** (`runner.go`): Legacy stdin/stdout fallback for any CLI tool.

Operational modes:
- **Query mode** (`engine.go`): Single-shot prompt execution via any protocol. Renders a template, sends to agent, parses structured JSON output.
- **Autopilot mode** (`sdk_runner.go`, `acp_runner.go`): Autonomous scanning. SDK mode gives full coding agent tools; ACP mode uses a sandboxed terminal (`acp_terminal.go`) restricted to `vigolium` commands.
- **Swarm mode** (`swarm.go`): Multi-phase pipeline (normalize → source analysis → code audit → SAST → discover → plan → extension → scan → triage → rescan). Native Go handles scanning; AI agents intervene at strategic checkpoints. Use `swarm --discover` for full-scope scanning.

Warm session pooling (`session_pool.go`, `sdk_pool.go`, `acp_pool.go`, `codex_pool.go`, `opencode_pool.go`) reuses agent subprocesses across multiple AI calls within a single run.

Prompt templates are Markdown with YAML frontmatter in `public/presets/prompts/`. Output schemas: `findings`, `http_records`, `attack_plan`, `triage_result`, `source_analysis`. See [docs/agentic-scan/agent-mode.md](docs/agentic-scan/agent-mode.md) for the full guide.

### Adding an Input Format

Input format adapters live in `pkg/input/formats/`. Each is a sub-package implementing the format interface. Look at `pkg/input/formats/openapi/` or `pkg/input/formats/curl/` for examples. Register new formats in the `pkg/input/` factory.

### Adding a CLI Command

CLI commands use Cobra and live in `pkg/cli/`. Each command is a separate file (e.g., `scan.go`, `server.go`). Follow the existing pattern: define a `cobra.Command`, wire it up in `root.go`.

### Adding an API Endpoint

The REST API server is Fiber-based in `pkg/server/`. Add handlers in `handlers_*.go`, register routes in `routes.go`, and update the Swagger spec (`docs/development/api-swagger.json` -> `make swagger` to sync).

### Adding a Notification Backend

Notification backends live in `pkg/notify/`. Implement the backend interface and register in the manager. See `pkg/notify/discord/` and `pkg/notify/telegram/` for examples.

## Codebase Conventions

### Package Layout

- `cmd/` — Binary entry points only, no business logic
- `internal/` — Private packages not importable by external code
- `pkg/` — Public library packages; designed for potential reuse
- `public/` — User-facing presets and examples, embedded via `go:embed`
- `test/` — Integration and E2E tests (unit tests live alongside source files)

### Go Conventions

- **Thread safety**: modules, executor, queue, and database components are all designed for concurrent use. Document thread-safety guarantees in interface comments.
- **Error handling**: return errors up the call stack. Use `pkg/errors` for wrapping. Log at the appropriate level; don't log and return the same error.
- **Interfaces**: define interfaces in the consumer package, not the implementation package (e.g., `Module` interface in `pkg/modules/`, not in each scanner).
- **Configuration**: all config structs live in `internal/config/`. Use YAML tags. Support environment variable expansion via the loader.
- **Embedding**: static resources (wordlists, browser binaries, configs, presets) use `go:embed` with platform-specific build tags where needed.

### Naming

- Module IDs: `active-<name>` or `passive-<name>`, kebab-case
- Package directories: lowercase, no underscores for Go packages; underscores allowed for module subdirectories (`xss_light_scanner/`)
- Test files: `*_test.go` alongside source, or in `test/` for integration/E2E

### Testing Patterns

- **Unit tests** (`-short` flag): test individual functions, no network/Docker. Co-located with source files.
- **E2E tests** (`-tags=e2e`): full pipeline tests in `test/e2e/`. Use testcontainers for Docker-based vulnerable apps.
- **Canary tests** (`-tags=canary`): scan DVWA, VAmPI, Juice Shop and assert expected findings.
- **Table-driven tests**: preferred for testing multiple inputs/outputs.
- **`testify/assert`**: used for assertions throughout.

### Commit and PR Guidelines

- Keep commits focused on a single change
- Run `make lint` and `make test-unit` before submitting
- Write tests for new modules (at minimum, a unit test that exercises the scan method)
- Update relevant docs in `docs/` if your change affects user-facing behavior

## Documentation Map

| Topic | Document |
|-------|----------|
| Full project structure | [docs/development/project-structure.md](docs/development/project-structure.md) |
| Building from source | [docs/development/building.md](docs/development/building.md) |
| Writing scanner modules (Go) | [docs/development/developing-modules.md](docs/development/developing-modules.md) |
| Writing JS extensions | [docs/customization/writing-extensions.md](docs/customization/writing-extensions.md) |
| Scanning overview | [docs/overview.md](docs/overview.md) |
| Getting started | [docs/getting-started.md](docs/getting-started.md) |
| Native scan strategies | [docs/native-scan/strategies.md](docs/native-scan/strategies.md) |
| Server mode and ingestion | [docs/server-and-ingestion.md](docs/server-and-ingestion.md) |
| REST API reference | [docs/api-overview.md](docs/api-overview.md) |
| Content discovery (Deparos) | [docs/native-scan/phases/discovery.md](docs/native-scan/phases/discovery.md) |
| Browser spider (Spitolas) | [docs/native-scan/phases/spidering.md](docs/native-scan/phases/spidering.md) |
| SPA scanning | [docs/native-scan/phases/spa.md](docs/native-scan/phases/spa.md) |
| Audit | [docs/native-scan/phases/audit.md](docs/native-scan/phases/audit.md) |
| Agent mode | [docs/agentic-scan/agent-mode.md](docs/agentic-scan/agent-mode.md) |
| Configuration | [docs/configuration.md](docs/configuration.md) |
| Example config | [public/vigolium-configs.example.yaml](public/vigolium-configs.example.yaml) |
