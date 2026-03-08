# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Vigolium is a high-fidelity web vulnerability scanner written in Go. It operates as a CLI scanner, REST API server with traffic ingestion, or standalone ingestor client. Module: `github.com/vigolium/vigolium`, requires Go 1.26+.

## Build & Test Commands

```bash
make build              # Build main binary → bin/vigolium, installs to $GOPATH/bin
make build-ingestor     # Build ingestor binary → bin/vigolium-ingestor
make test               # Run all tests (auto-installs gotestsum)
make test-unit          # Fast unit tests (-short flag, no external deps)
make test-race          # All tests with race detector
make test-e2e           # E2E tests (requires Docker, -tags=e2e)
make test-canary        # Canary tests against DVWA/VAmPI/JuiceShop (Docker, -tags=canary)
make lint               # golangci-lint run
make fmt                # Format code
make tidy               # go mod tidy
```

Run a single test:
```bash
go test -v -run TestFunctionName ./pkg/path/to/package/...
```

Run a single test file with build tags:
```bash
go test -v -tags=e2e -run TestName ./test/e2e/...
```

## Architecture

### Execution Pipeline

Request ingestion → Scope filtering → Executor (worker pool) → Module dispatch → Result output/storage

The **Executor** (`pkg/core/executor.go`) is the central orchestrator. It receives `HttpRequestResponse` items, distributes them to registered modules via a concurrent worker pool, and collects `ResultEvent` findings. It supports pre/post hooks (`HookRunner`), scope matching, and per-host rate limiting.

### Module System

All scanner logic lives in **modules** registered in the **Registry** (`pkg/modules/registry.go`). Two types:

- **ActiveModule** (`pkg/modules/active.go`): Sends modified requests to detect vulnerabilities. Methods: `ScanPerInsertionPoint`, `ScanPerRequest`, `ScanPerHost`. Each module declares which `ScanScope` and `InsertionPointType` it handles.
- **PassiveModule** (`pkg/modules/passive.go`): Analyzes existing request/response pairs without sending new traffic. Optional `Flusher` interface for end-of-scan finalization.

Both share the base `Module` interface (ID, Name, Severity, Confidence, Tags, CanProcess, ScanScopes). Modules are tagged with classification labels (e.g., `spring`, `xss`, `light`) and can be filtered with `--module-tag` CLI flag or `?tag=` API parameter.

Module helper code lives in `pkg/modules/modkit/` (shared constants, default implementations) and `pkg/modules/infra/` (block detection, request filtering, response transfer).

### Ignored Directories

- **`platform/`** — Contains external tooling only. Do not read or modify files in this directory.

### Key Packages

- **`pkg/core/`** — Executor, worker pool, rate limiter, network utilities, scan statistics
- **`pkg/modules/`** — Module interfaces, registry, all active/passive scanner modules
- **`pkg/deparos/`** — Spider & discovery engine: crawling (`discovery/`), JS analysis (`jsscan/`), fingerprinting (`fingerprint/`), Wayback integration (`wayback/`), scope enforcement (`scope/`), WAF detection (`waf/`), storage (`storage/`)
- **`pkg/agent/`** — AI agent integration engine: prompt templates, context enrichment (`context.go`), agent execution via ACP (Agent Communication Protocol) with bidirectional streaming, terminal sandbox for autopilot mode (`acp_terminal.go`), multi-phase pipeline runner (`pipeline.go`), output parsing (findings/HTTP records/attack plans/triage results), and database ingestion. Supports Claude, OpenCode, Gemini, and custom CLI backends
- **`pkg/jsext/`** — JavaScript extension engine (Grafana Sobek). Exposes `vigolium.http`, `vigolium.scan`, `vigolium.ingest`, `vigolium.source` APIs. TypeScript definitions in `vigolium.d.ts`
- **`pkg/httpmsg/`** — HTTP request/response model, insertion points, serialization
- **`pkg/http/`** — HTTP requester with middleware pipeline
- **`pkg/input/`** — Input source adapters (OpenAPI, Swagger, Postman, Burp, cURL, Nuclei, HAR)
- **`pkg/server/`** — REST API server (Fiber), Swagger UI, ingestion handlers, agent run API (`handlers_agent.go`)
- **`pkg/database/`** — Repository pattern over SQLite (default) or PostgreSQL via Bun ORM
- **`pkg/queue/`** — Hybrid queue (in-memory + disk/Redis spillover)
- **`pkg/output/`** — Result formatting, output handlers, and HTML report generation (`format_html.go`)
- **`internal/config/`** — Configuration management, scope matcher, agent config (`agent.go`)
- **`internal/runner/`** — High-level scan runner orchestration
- **`internal/logger/`** — Zap-based structured logging

### Multi-Tenancy (Projects)

All scan data is scoped to a **project** via `project_uuid` on all data tables (scans, http_records, findings, scopes, source_repos, oast_interactions). The CLI `project` subcommand manages projects (`create`, `list`, `use`, `config`). The `--project` flag and `VIGOLIUM_PROJECT` env var scope CLI operations; the `X-Project-UUID` header scopes server API operations. Config merges: global → project → scanning profile → CLI flags. See `docs/projects.md`.

### Entry Points

- `cmd/vigolium/` — Main CLI (Cobra-based, commands in `pkg/cli/`)

### Testing Tiers

1. **Unit tests** (`make test-unit`): Fast, no external dependencies, use `-short` flag
2. **E2E tests** (`make test-e2e`): Docker-based, tagged `e2e`, in `test/e2e/`
3. **Canary tests** (`make test-canary`): Run against vulnerable apps (DVWA, VAmPI, Juice Shop), tagged `canary`
4. **Integration tests** (`make test-integration`): XSS benchmark tests, tagged `integration`, in `test/benchmark/`
5. **SAST benchmarks** (`make test-sast`): Whitebox SAST pipeline tests (route extraction, SARIF parsing, handoff), tagged `sast`, in `test/benchmark/sast/`
6. **SAST E2E benchmarks** (`make test-sast-e2e`): Full source-to-scan pipeline, tagged `sast_e2e`, requires ast-grep binary

Vulnerable apps are managed via Docker Compose in `test/testdata/vulnerable-apps/`. Use `make apps-up` / `make apps-down`.

### JavaScript Extensions

Custom scanning logic can be written in JavaScript using the embedded Sobek engine. Extensions implement active or passive module interfaces via the `vigolium.*` API. See `docs/writing-extensions.md` and `pkg/jsext/vigolium.d.ts` for the full API surface. Preset examples in `public/presets/`. Built-in scanning profiles in `public/presets/profiles/`.

### Agent Mode

The `vigolium agent` command runs AI agents for security analysis. Three operational modes:

- **Run** (`vigolium agent` / `vigolium agent query`): Single-shot prompt execution with template-based prompts. Agent receives prompt via stdin, returns structured output (findings or HTTP records). Good for code review, endpoint discovery, secret detection.
- **Autopilot** (`vigolium agent autopilot`): Interactive ACP (Agent Communication Protocol) session where the agent can execute scanner commands autonomously via a sandboxed terminal. The terminal manager (`acp_terminal.go`) enforces command allowlisting (only `vigolium` subcommands) and shell injection prevention. Supports warm session pooling for subprocess reuse.
- **Pipeline** (`vigolium agent pipeline`): Fixed multi-phase scanning pipeline (discover → plan → scan → triage → rescan → report) where native Go code handles heavy lifting and AI agents only intervene at checkpoints (phases 2 and 4). The pipeline runner (`pipeline.go`) uses callback functions for native scan phases, keeping `pkg/agent/` decoupled from `internal/runner/`.

Prompt templates are Markdown files with YAML frontmatter stored in `~/.vigolium/prompts/` or embedded in the binary (`public/presets/prompts/`). Output schemas: `findings`, `http_records`, `attack_plan`, `triage_result`. Agent backends are configured in the `agent` section of `vigolium-configs.yaml`. REST API endpoints: `POST /api/agent/run/query`, `POST /api/agent/run/autopilot`, `POST /api/agent/run/pipeline`, `GET /api/agent/status/list`, `GET /api/agent/status/:id`. See `docs/agent-mode.md` for the full guide.

### Phase Aliases

Scan phases accept aliases: `deparos` = `discovery`, `discover` = `discovery`, `spitolas` = `spidering`, `audit` = `dynamic-assessment`. These work with `--only` and `--skip` flags.

### Output Formats

The `--format` flag selects output format: `console` (default), `jsonl`, or `html`. HTML reports use an embedded ag-grid template (`public/static-reports/`) and require `-o/--output`. HTML format is supported for discovery and spidering phases.

### Module Development

New scanner modules implement `ActiveModule` or `PassiveModule`, register in the registry, and use `modkit` defaults for common behavior. See `docs/developing-modules.md` for the full guide.
