# Hacking on Vigolium

This guide gives developers a high-level understanding of Vigolium's architecture, tech stack, and codebase conventions. If you want to contribute a feature, fix a bug, or write a new scanner module, start here.

## What is Vigolium?

Vigolium is a high-fidelity web vulnerability scanner written in Go. It can run as:

1. **CLI scanner** — scan targets directly from the command line
2. **REST API server** — receive traffic via HTTP endpoints or a transparent proxy, scan on demand
3. **Ingestor client** (`vigolium ingest`) — submit traffic to a remote Vigolium server

It scans for reflected XSS, SQL injection, SSTI, LFI, CRLF injection, open redirects, command injection, path traversal, XXE, race conditions, and more through a pluggable module system.

## Architecture Overview

```
                        ┌──────────────────────────────────┐
                        │         Input Sources            │
                        │  URLs, OpenAPI, Swagger, Burp,   │
                        │  cURL, Postman, Nuclei, HAR,     │
                        │  stdin, transparent proxy        │
                        └──────────────┬───────────────────┘
                                       ▼
                        ┌──────────────────────────────────┐
                        │     Ingestion & Database         │
                        │  Parse → HttpRequestResponse     │
                        │  Store in SQLite / PostgreSQL    │
                        └──────────────┬───────────────────┘
                                       ▼
┌──────────────────────────────────────────────────────────────────────┐
│                  Runner (multi-phase pipeline)                       │
│                                                                      │
│  ingestion          ─── Continuous input ingestion                  │
│  external-harvest   ─── Wayback, CommonCrawl, OTX, …                │
│  discovery          ─── Deparos (adaptive content discovery)        │
│  spidering          ─── Spitolas (Chromium via CDP, SPA aware)      │
│  dynamic-assessment ─── Executor + active/passive scanner modules   │
│  known-issue-scan   ─── Nuclei templates + Kingfisher secrets       │
│  extension          ─── User JavaScript modules (Sobek)             │
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
              │  console, jsonl, html, DB,     │
              │  Discord, Telegram             │
              └────────────────────────────────┘
```

Phases accept aliases: `deparos`/`discover` → `discovery`, `spitolas` → `spidering`, `ext` → `extension`, `audit`/`dast`/`assessment` → `dynamic-assessment`. Each phase is optional and gated by the **scanning strategy** (`lite`, `balanced`, `deep`, `whitebox`). **Scanning profiles** bundle strategy + pace + scope + module config into a single YAML — built-in profiles live in `public/presets/profiles/` (`quick.yaml`, `standard.yaml`, `full.yaml`).

## Tech Stack

| Area | Technology | Package |
|------|-----------|---------|
| Language | Go 1.26+ | `CGO_ENABLED=0`, pure Go (SQLite via `modernc.org/sqlite`) |
| CLI framework | Cobra | `github.com/spf13/cobra` |
| REST API server | Fiber v3 | `github.com/gofiber/fiber/v3` |
| Database ORM | Bun | `github.com/uptrace/bun` (SQLite + PostgreSQL dialects) |
| Browser automation | rod | `github.com/go-rod/rod` — Chromium via CDP, used by Spitolas |
| JS extension engine | Sobek (Grafana) | `github.com/grafana/sobek` — ES5.1+, pure Go |
| Template scanning | Nuclei v3 | `github.com/projectdiscovery/nuclei/v3` |
| HTTP client | retryablehttp + rawhttp | `github.com/projectdiscovery/retryablehttp-go`, `github.com/projectdiscovery/rawhttp` |
| Queue (disk) | LevelDB | `github.com/syndtr/goleveldb` |
| Queue (remote) | Redis | `github.com/redis/go-redis/v9` |
| Metrics | Prometheus | `github.com/prometheus/client_golang` |
| Logging | Zap | `go.uber.org/zap` |
| Agent runtime | olium (in-process) | `pkg/olium/` — turn-based engine, pluggable provider drivers |
| Agent TUI | Bubble Tea | `github.com/charmbracelet/bubbletea` (in `pkg/olium/tui/`) |
| Testing | testify + gotestsum + testcontainers | `github.com/stretchr/testify` |
| Release | GoReleaser | `.goreleaser.yaml` |

## Project Structure (Summary)

```
cmd/vigolium/           Single main.go entry point
internal/
  config/               YAML config loading, strategy/pace/scope definitions, agent.olium config
  runner/               Multi-phase scan orchestrator (route probing, batch ingestion)
  ingestor/             `vigolium ingest` traffic-forwarding client internals
  logger/               Zap logger setup
  resources/            Embedded binaries (jstangle, Chromium), wordlists, templates
pkg/
  cli/                  All Cobra commands (scan, server, ingest, db, agent_*, project, ...)
  core/                 Executor, worker pool, rate limiter, services DI container
  modules/              Module interfaces, registry, 201 active + 116 passive scanners (317 total)
    modkit/             Base types, default implementations (BaseActiveModule, etc.)
    active/             Active scanner implementations (XSS, SQLi, SSTI, LFI, framework, CMS, cloud, ...)
    passive/            Passive analyzers (DOM XSS, secrets, headers, cookies, ...)
    shared/diffscan/    Differential response analysis engine
    infra/              WAF/block detection, request filtering, response transfer
  agent/                Agent orchestration — engine, swarm runner, autopilot pipeline, prompt templates,
                        output parsing, DB ingestion. Dispatches to olium via olium_adapter.go
  olium/                In-process Go agent runtime
    provider/           Provider drivers: openai-codex-oauth, anthropic-api-key, anthropic-oauth, openai-api-key, anthropic-cli
    engine/             Turn-based engine (Run, Fork for prompt-cache reuse)
    tool/               Tool registry + builtins (bash, read_file, write_file, edit_file, ls, grep, glob, web_fetch)
    skill/              SKILL.md parsing and registry, system-prompt injection
    autopilot/          Autonomous agentic loop entry point
    vigtool/            Vigolium-integration tools (run_scan, run_extension, sessions, auth_session)
    tui/                Bubble Tea interactive TUI
    stream/             SSE / event streaming
    headless.go         Headless one-shot helper
  audit/               Audit harness (claudecost, claudestream, codexcost, parser, transform, preflight)
  piolium/              Pi-native audit harness (picost, pistream, preflight) — drives the user's pi extension
  deparos/              Content discovery engine (Deparos)
  spitolas/             Browser spider (Spitolas) — Chromium, state machine, forms
  spa/                  Nuclei + Kingfisher integration
  httpmsg/              HTTP message models, insertion points, parameter parsers
  http/                 HTTP requester with middleware
  input/                Input format adapters (OpenAPI, Swagger, Burp, Postman, cURL, HAR, Nuclei)
  database/             Repository pattern ORM (SQLite/PostgreSQL via Bun); SaveRecordBatch + DeduplicateRecordsBySource
  queue/                Hybrid in-memory/disk/Redis queue
  server/               REST API server (Fiber v3), Swagger UI, ingest proxy, agent run/session/SSE handlers
  jsext/                JavaScript extension engine and vigolium.* APIs (http, scan, source, ingest, agent, oast, db)
  output/               Result formatting (console, jsonl, html, markdown, pdf)
  harvester/            External URL harvesting (Wayback, CommonCrawl, OTX, ...)
  anomaly/              Response anomaly detection and scoring
  dedup/                Request/finding deduplication
  kingfisher/           Secret/credential scanning
  notify/               Notification backends (Discord, Telegram)
  metrics/              Prometheus metrics collector
  terminal/             Terminal UI, ANSI colors, table formatting
  types/                Shared Options struct, severity/confidence enums
  utils/                Hashing, random gen, TLS, JSON utilities
  work/                 WorkItem abstraction for executor pipeline
public/
  presets/profiles/     Scanning profile YAMLs: quick.yaml, standard.yaml, full.yaml
  presets/sessions/     Auth session presets (bearer, login flow, IDOR test)
  presets/extensions/   JavaScript extension examples (embedded)
  presets/prompts/      Agent prompt templates (Markdown + YAML frontmatter)
  static-reports/       HTML report ag-grid template
build/                  Dockerfile
test/                   E2E, canary, benchmark, deparos, spitolas, sast tests
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
make deps           # download Go modules + jstangle binaries
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

**`make test-unit` is the canonical unit-test command.** It runs `ensure-jstangle`
first, which builds the embedded jstangle binaries that several packages pull in
via `//go:embed`. A plain `go test ./...` on a fresh checkout fails with
`pattern jstangle/jstangle-<os>-<arch>: no matching files found` because those
binaries are generated (and git-ignored), not committed.

If you want to run Go tooling directly without building the ~100 MB jstangle
binaries (e.g. quick `go test`/`go vet` in an editor), use the `jstangle_stub`
build tag, which swaps the embed for an empty stub:

```bash
go test -tags=jstangle_stub -short ./...
go vet  -tags=jstangle_stub ./...
```

Code paths that launch jstangle treat the stub as "jstangle unavailable" — the same
fallback used on platforms without a prebuilt binary — so unit tests that don't
exercise the spider's JS analysis run unchanged.

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

The agent system has two cooperating layers, plus three foreground source-audit drivers (`audit`, `piolium`, and the unified `audit` dispatcher):

- **`pkg/agent/`** — orchestration: prompt templates, context enrichment (`autopilot_context.go`), swarm pipeline (`swarm.go`), autopilot pipeline runner (`autopilot_pipeline.go`), audit-driver dispatch (`audit_drivers.go`, `audit_agent.go`), prompt-safety guardrail (`guardrail.go`), output parsing (`parsing/`), DB ingestion. The dispatch shim is `olium_adapter.go` — every AI call ultimately goes through olium.
- **`pkg/olium/`** — the in-process Go agent runtime:
  - `provider/` — provider drivers (`anthropic.go`, `codex.go`, `openai.go`, `claudecode.go`, `vertex.go` for `google-vertex` with Anthropic-on-Vertex + Gemini-native routing)
  - `engine/` — turn-based loop (`Engine.Run`, `Engine.Fork` for prompt-cache reuse)
  - `tool/` — tool registry and built-ins (`bash`, `read_file`, `write_file`, `edit_file`, `ls`, `grep`, `glob`, `web_fetch`)
  - `vigtool/` — vigolium-specific tools (`run_scan`, `run_extension`, session management, auth sessions)
  - `skill/` — SKILL.md parsing, registry, system-prompt injection (project-agent / project-claude / user-vigolium / embedded scopes)
  - `autopilot/` — autonomous agentic loop (`Run`, halt conditions, `report_finding` tool, system prompt builder)
  - `tui/` — Bubble Tea interactive TUI; `headless.go` for one-shot non-TUI execution
  - `stream/` — text/toolCall/result/error events; SSE streaming
  - `auth/` — Codex OAuth credential loader (`~/.codex/auth.json`) and Vertex SA-credential resolver (`vertex.go` — env/YAML/file fallbacks for project, location, credentials)
- **`pkg/audit/`** — vigolium-audit harness: `setup.go`, `parser.go`, `transform.go`, `preflight.go` (roundtrips `claude -p` before audit; codex skips via `ErrPreflightUnsupported`), plus per-platform cost/stream support (`claudecost/`, `claudestream/`, `codexcost/`). Runs the `claude` / `codex` CLIs directly — does **not** use olium.
- **`pkg/piolium/`** — Pi-native audit harness: `piolium.go` (driver + availability detection via `pi -h` + `Diagnose()`), `picost/`, `pistream/`, `preflight.go`. Drives the user's installed piolium Pi extension via `pi --mode json -p /piolium-<mode>`. Same finding schema as audit; tagged separately in the DB.

There are no subprocess SDK backends — `claudesdk/` and `codexsdk/` were removed when the runtime moved in-process. Provider selection lives in `agent.olium.provider` (`openai-codex-oauth` (default), `anthropic-api-key`, `anthropic-oauth`, `openai-api-key`, `anthropic-cli`, `google-vertex`).

Operational modes (CLI entry → backend):

| Mode | CLI | CLI file | Backend |
|------|-----|----------|---------|
| Query | `vigolium agent query` | `pkg/cli/agent_query.go` (in `agent.go`) | `pkg/agent/engine.go` `Engine.Run` — render template, call olium, parse structured JSON |
| Autopilot | `vigolium agent autopilot` | `pkg/cli/agent_autopilot.go`, `agent_autopilot_olium.go` | CLI calls `pkg/olium/autopilot.Run` directly. Server (`pkg/agent/autopilot_pipeline.go` `RunAutonomous`) layers vigolium-audit prep, auth preparation, and a frozen context bundle, then delegates to `olium/autopilot.Run` with the assembled brief on `Options.InitialPrompt` |
| Swarm | `vigolium agent swarm` | `pkg/cli/agent_swarm.go` | `pkg/agent/swarm.go` — multi-phase pipeline (normalize → source analysis → code audit → SAST → discover → plan → extension → scan → triage → rescan). Native Go handles scanning; AI checkpoints go through `Engine.Run` |
| Olium | `vigolium agent olium` (alias `vigolium olium` / `vigolium ol`) | `pkg/cli/agent_olium.go` | Direct olium TUI (or `-p` one-shot non-interactive) — useful for ad-hoc prompts and provider debugging |
| Audit | `vigolium agent audit` | `pkg/cli/agent_audit.go` | Separate harness in `pkg/audit/` — spawns `claude` / `codex` CLI directly. Optional `claude -p` preflight (`--no-preflight` / `--preflight-timeout`) |
| Piolium | `vigolium agent audit --driver=piolium` | `pkg/cli/agent_piolium.go` | Separate harness in `pkg/piolium/` — drives the user's piolium Pi extension via `pi --mode json -p /piolium-<mode>` |
| Audit | `vigolium agent audit` | `pkg/cli/agent_audit.go` | Unified driver dispatcher in `pkg/agent/audit_drivers.go` + `audit_agent.go`: runs audit and/or piolium back-to-back under one parent AgenticScan with per-driver child rows, `--driver={both,audit,piolium}` (default `both`), `--fallback` for audit-on-piolium-failure, post-pass project-wide findings dedup once both drivers exit |
| Session | `vigolium agent session` | `pkg/cli/agent_session.go`, `agent_session_tui.go` | Browse / replay session artifacts under `agent.sessions_dir` |

REST API exposes the same modes:
- `POST /api/agent/run/query`, `POST /api/agent/run/autopilot`, `POST /api/agent/run/swarm`, `POST /api/agent/run/audit`, `POST /api/agent/run/audit` (handlers under `pkg/server/handlers_agent_audit*.go`; takes `driver: "piolium"|"audit"|"both"`, default `"both"`, with multiplexed SSE `driver` field when `stream: true`)
- `GET /api/agent/status/list`, `GET /api/agent/status/:id`
- `GET /api/agent/sessions`, `GET /api/agent/sessions/:id`, `…/logs`, `…/artifacts`, `…/artifacts/:filename`
- `POST /api/agent/chat/completions` — OpenAI-compatible endpoint

Prompt templates are Markdown with YAML frontmatter in `public/presets/prompts/` (overridable via `~/.vigolium/prompts/`). Output schemas: `findings`, `http_records`, `attack_plan`, `triage_result`, `source_analysis`. Session artifacts (per run) live under `agent.sessions_dir` (default `~/.vigolium/agent-sessions/`): `runtime.log`, `extensions/`, `session-config.json`, `swarm-plan.json`, per-phase `*-output.md`, `audit-stream.jsonl` (audit / piolium), `checkpoint.json` (swarm resume). Combined audit runs use per-driver subdirs (`{session}/audit/`, `{session}/piolium/`).

See [docs/agentic-scan/agent-mode.md](docs/agentic-scan/agent-mode.md) for the full guide.

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
| Architecture overview | [docs/architecture/overview.md](docs/architecture/overview.md) |
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
