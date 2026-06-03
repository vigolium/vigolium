# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Vigolium is a high-fidelity web vulnerability scanner written in Go. It operates as a CLI scanner, REST API server with traffic ingestion, or traffic-forwarding ingestor client (`vigolium ingest`). Module: `github.com/vigolium/vigolium`, requires Go 1.26+.

## Build & Test Commands

**IMPORTANT:** Never build the binary directly with `go build` to `./vigolium` or any ad-hoc path. Always use `make build` (outputs to `bin/vigolium`) or `make install` (installs to `$GOPATH/bin`). Direct `go build` bypasses version injection and may leave stale binaries in the working directory.

```bash
make build              # Build main binary → bin/vigolium, installs to $GOPATH/bin
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

### Execution Pipeline (Native Scan)

Request ingestion → Scope filtering → Executor (worker pool) → Module dispatch → Result output/storage

This is the **native scan** pipeline — deterministic, Go-based scanning with no AI involvement. The **Executor** (`pkg/core/executor.go`) is the central orchestrator. It receives `HttpRequestResponse` items, distributes them to registered modules via a concurrent worker pool, and collects `ResultEvent` findings. It supports pre/post hooks (`HookRunner`), scope matching, and per-host rate limiting.

### Module System

All scanner logic lives in **modules** registered in the **Registry** (`pkg/modules/registry.go`); the wiring is in `pkg/modules/default_registry_active.go` / `default_registry_passive.go` (currently 164 active + 96 passive registrations = 260 modules). Two types:

- **ActiveModule** (`pkg/modules/active.go`): Sends modified requests to detect vulnerabilities. Methods: `ScanPerInsertionPoint`, `ScanPerRequest`, `ScanPerHost`. Each module declares which `ScanScope` and `InsertionPointType` it handles.
- **PassiveModule** (`pkg/modules/passive.go`): Analyzes existing request/response pairs without sending new traffic. Optional `Flusher` interface for end-of-scan finalization.

Both share the base `Module` interface (ID, Name, Severity, Confidence, Tags, CanProcess, ScanScopes). Modules are tagged with classification labels (e.g., `spring`, `xss`, `light`) and can be filtered with `--module-tag` CLI flag or `?tag=` API parameter.

Module helper code lives in `pkg/modules/modkit/` (shared constants, default implementations) and `pkg/modules/infra/` (block detection, request filtering, response transfer).

### Ignored Directories

- **`platform/`** — Contains external tooling only. Do not read or modify files in this directory, except for `platform/vigolium-workbench/` which is the Next.js UI frontend — only go into it when making changes to the UI.

### Key Packages

- **`pkg/core/`** — Executor, worker pool, rate limiter, network utilities, scan statistics
- **`pkg/modules/`** — Module interfaces, registry, all active/passive scanner modules
- **`pkg/deparos/`** — Spider & discovery engine: crawling (`discovery/`), JS analysis (`jsscan/`), fingerprinting (`fingerprint/`), Wayback integration (`wayback/`), scope enforcement (`scope/`), WAF detection (`waf/`), storage (`storage/`)
- **`pkg/agent/`** — Agentic scan engine: prompt templates, context enrichment (`autopilot_context.go`), the autopilot pipeline runner (`autopilot_pipeline.go`) and swarm runner (`swarm.go`), output parsing (findings/HTTP records/attack plans/triage results/source analysis), and database ingestion. All AI dispatch goes through the in-process olium engine via `olium_adapter.go` — there are no subprocess SDK backends. Powers the agentic scan modes (autopilot, swarm) and the query mode.
- **`pkg/olium/`** — In-process Go agent runtime: provider drivers (`provider/` for openai-codex-oauth, anthropic-api-key, anthropic-oauth, openai-api-key, anthropic-cli), turn-based engine (`engine/`), tool registry and built-ins (`tool/`), skills support (`skill/`), the autopilot agentic loop (`autopilot/`), TUI (`tui/`), and headless one-shot helper (`headless.go`). Used by every agent mode and exposed directly via `vigolium agent olium` (alias `vigolium olium` / `ol`).
- **`pkg/audit/`** — Vigolium Audit harness driver: parser for the audit's on-disk output (`pkg/audit/parser.go`, `constants.go`), embedded binary management (`pkg/audit/bin/`), per-platform cost/stream support (`claudecost/`, `codexcost/`, `stream/`). Drives the `vigolium agent audit` foreground mode.
- **`pkg/jsext/`** — JavaScript extension engine (Grafana Sobek). Exposes `vigolium.http`, `vigolium.scan`, `vigolium.ingest`, `vigolium.source` APIs. TypeScript definitions in `vigolium.d.ts`
- **`pkg/httpmsg/`** — HTTP request/response model, insertion points, serialization
- **`pkg/http/`** — HTTP requester with middleware pipeline
- **`pkg/input/`** — Input source adapters (OpenAPI, Swagger, Postman, Burp, cURL, Nuclei, HAR)
- **`pkg/server/`** — REST API server (Fiber), Swagger UI, ingestion handlers, agent run API (`handlers_agent.go`)
- **`pkg/database/`** — Repository pattern over SQLite (default) or PostgreSQL via Bun ORM. Supports `SaveRecordBatch` for bulk HTTP record ingestion and `DeduplicateRecordsBySource` for per-source deduplication
- **`pkg/queue/`** — Hybrid queue (in-memory + disk/Redis spillover)
- **`pkg/output/`** — Result formatting, output handlers, and HTML report generation (`format_html.go`)
- **`internal/config/`** — Configuration management, scope matcher, agent config (`agent.go`)
- **`internal/runner/`** — High-level scan runner orchestration
- **`internal/logger/`** — Zap-based structured logging

### Multi-Tenancy (Projects)

All scan data is scoped to a **project** via `project_uuid` on all data tables (scans, http_records, findings, scopes, oast_interactions). The CLI `project` subcommand manages projects (`create`, `list`, `use`, `config`). The `--project` flag and `VIGOLIUM_PROJECT` env var scope CLI operations; the `X-Project-UUID` header scopes server API operations. Config merges: global → project → scanning profile → CLI flags. See `docs/projects.md`.

### Entry Points

- `cmd/vigolium/` — Main CLI (Cobra-based, commands in `pkg/cli/`)

Top-level commands registered in `pkg/cli/root.go`: `scan`, `scan-url`, `scan-request`, `run`, `replay`, `agent`, `olium` / `ol` (alias for `agent olium`), `server`, `ingest`, `db`, `storage`, `project`, `scope`, `traffic`, `finding`, `strategy`, `auth`, `module`, `import`, `export`, `js`, `extensions` (alias `ext`), `init`, `config`, `version`, `update`, `doctor`, `log`. The `auth` command (`auth list`/`load`/`lint`/`totp`) manages authentication sessions; its source files are named `pkg/cli/session_*.go` for historical reasons. Agent subcommands (registered in `pkg/cli/agent_*.go`): `query`, `autopilot`, `swarm`, `olium`, `audit`, `session`.

### Testing Tiers

1. **Unit tests** (`make test-unit`): Fast, no external dependencies, use `-short` flag
2. **E2E tests** (`make test-e2e`): Docker-based, tagged `e2e`, in `test/e2e/`
3. **Canary tests** (`make test-canary`): Run against vulnerable apps (DVWA, VAmPI, Juice Shop), tagged `canary`
4. **Integration tests** (`make test-integration`): XSS benchmark tests, tagged `integration`, in `test/benchmark/`

Vulnerable apps are managed via Docker Compose in `test/testdata/vulnerable-apps/`. Use `make apps-up` / `make apps-down`.

### JavaScript Extensions

Custom scanning logic can be written in JavaScript using the embedded Sobek engine. Extensions implement active or passive module interfaces via the `vigolium.*` API. See `docs/customization/writing-extensions.md` and `pkg/jsext/vigolium.d.ts` for the full API surface. Preset examples in `public/presets/`. Built-in scanning profiles in `public/presets/profiles/`.

### Agent Mode

The `vigolium agent` command runs AI agents for security analysis. The parent command only supports `--list-templates` and `--list-agents` flags — all execution requires a subcommand. All AI dispatch is routed through the in-process olium engine (`pkg/olium/`); there are no subprocess SDK backends.

- **Query** (`vigolium agent query`): Single-shot prompt execution with template-based or inline prompts. Supports `--source` for code path, `--source-label` for ingestion label. Returns structured output (findings or HTTP records). Good for code review, endpoint discovery, secret detection. Not an agentic scan — no network scanning or multi-phase orchestration.
- **Autopilot** (`vigolium agent autopilot`): Agentic scan mode — autonomous scanning. The CLI delegates to `pkg/olium/autopilot.Run`; the server's HTTP handler runs the same loop wrapped by `agent.AutopilotPipelineRunner` so it can layer vigolium-audit prep, auth preparation, and a frozen context bundle in front of the operator agent. Accepts `--input` (curl, raw HTTP, Burp XML, base64, URL) with auto-detection and stdin piping. When `--source` is provided, the agent operates with filesystem read/write access to the source tree.
- **Swarm** (`vigolium agent swarm`): Agentic scan mode — AI-guided vulnerability scanning, supporting both targeted single-request and full-scope scanning (with `--discover`). The master agent analyzes inputs, selects scanner modules, generates custom JS extensions, executes scans, and optionally triages results (with `--triage`). Phases: normalize → source analysis (AI, conditional) → code audit (AI, conditional) → discover (native, conditional) → plan (AI) → extension → native scan → triage (AI, conditional) → rescan (loop). Supports `--source` for AI-driven source code analysis and `--code-audit` for deep AI security code audit. When inputs exceed 5 records, master agent calls are batched (max 5 per batch) with plan merging. `--target` is required when `--source` is used.
- **Olium** (`vigolium agent olium` or top-level `vigolium olium` / `ol`): Direct interactive (TUI) access to the olium agent. Pass `-p "..."` (or `--prompt`) to run a single prompt non-interactively and stream to stdout — useful for ad-hoc prompts and debugging providers.
- **Audit** (`vigolium agent audit`): Foreground vigolium-audit driver (separate harness — does not use olium). Drives the embedded vigolium-audit harness against a source tree using the `claude` or `codex` CLI. Agent selection: `--provider <olium-provider>` resolves the agent **and** forwards that provider's BYOK auth (`anthropic-*` → claude, `openai-*` → codex; empty inherits `agent.olium.provider`); `--agent {claude|codex}` is a pure agent selector layered on top — it overrides the provider-implied agent while keeping the resolved auth (`agent.ForceAuditAgent`, invalid values rejected up front). Same flags exist on `vigolium agent audit` (audit leg only).
- **Piolium** (Pi-native audit driver): Drives the user's installed piolium Pi extension via `pi --mode json -p /piolium-<mode>`. Same finding schema as audit, tagged separately in the DB. There is no standalone `vigolium agent piolium` subcommand — piolium runs only through `vigolium agent audit` (`--driver=piolium` for piolium alone). The shared driver helpers live in `pkg/cli/agent_piolium.go`.
- **Audit** (`vigolium agent audit`): Unified driver dispatcher — runs audit and/or piolium against the same source tree under one parent AgenticScan, with per-driver child rows. Default `--driver=auto` runs audit first and only falls back to piolium if audit fails (a clean audit run finishes the audit; piolium is never consulted and a missing piolium runtime is not reported). `--driver=both` runs audit then piolium unconditionally and sequentially. Both run a post-pass project-wide findings dedup; `--driver=piolium|audit` forces a single driver. Audit-leg agent selection uses `--provider`/`--agent {claude|codex}` (see the Audit entry above; `--agent` warns rather than errors under `--driver=piolium`). `--modes a,b,c` (or REST `modes: [...]`) chains modes back-to-back, stopping on the first non-complete mode: audit runs the chain natively via its own `--modes` (one subprocess, one row, aggregate cost — `auditstream` sums the per-mode `result` events); piolium chains via sequential `pi` runs in the same source tree collapsed into one aggregated child row (`pkg/agent/audit_chain.go` `PioliumChainScanner`). For `--driver=auto|both`, modes a driver can't run are skipped on that driver's leg (per-driver `ValidateAuditDriverModes`); a mode unknown to both drivers is a hard error. `--intensity deep` resolves to the chain `deep,confirm` (quick→`lite`, balanced→`balanced` stay single-mode) across `vigolium agent audit`, `vigolium agent audit`, and the `POST /api/agent/run/{audit,audit}` endpoints. `vigolium agent audit --list-modes` / `vigolium agent audit --list-modes` print the embedded audit binary's `list` (mode graph: phases, time estimate, descriptions) and exit.

Source code context is provided via the `--source` flag across all agent subcommands. The `Options.SourcePath` field carries this through the agent engine. The `TemplateData.SourcePath` variable is available in prompt templates. The legacy `--repo` flag has been removed entirely.

All agent modes create a session directory under `sessions_dir` (configurable via `agent.sessions_dir` in `vigolium-configs.yaml`, defaults to `~/.vigolium/agent-sessions/`). Session dirs store agent artifacts: `runtime.log`, `extensions/`, `session-config.json`, `swarm-plan.json` (swarm), `master-output.md` / `source-analysis-output.md` / `code-audit-output.md` (per-phase outputs), `audit-stream.jsonl` (audit), `checkpoint.json` (swarm resume). The `EnsureSessionDir(baseDir, runID)` helper in `pkg/agent/pipeline_types.go` creates the directory structure.

Prompt templates are Markdown files with YAML frontmatter stored in `~/.vigolium/prompts/` or embedded in the binary (`public/presets/prompts/`). Output schemas: `findings`, `http_records`, `attack_plan`, `triage_result`, `source_analysis`. The olium engine is configured under `agent.olium` in `vigolium-configs.yaml` — see `OliumConfig` in `internal/config/agent.go`. Key fields: `provider`, `model`, `oauth_cred_path`, `oauth_token`, `llm_api_key`, `reasoning_effort`, `max_turns` (default 32), `max_concurrent` (default 4), `call_timeout_sec` (default 600), `cache_size` (default 1024). Providers: `openai-compatible` (default, default model `gemma4:latest`), `openai-codex-oauth`, `anthropic-api-key`, `anthropic-oauth`, `openai-api-key`, `anthropic-cli`. REST API endpoints: `POST /api/agent/run/{query,autopilot,swarm,audit,audit}`, `GET /api/agent/status/list`, `GET /api/agent/status/:id`, `GET /api/agent/sessions[/:id[/logs|/artifacts[/:filename]]]`, `POST /api/agent/chat/completions` (OpenAI-compatible). The audit endpoint takes `driver: "auto"|"both"|"audit"|"piolium"` (default `"auto"`); `auto` runs audit and only falls back to piolium if audit fails, `both` runs both unconditionally, and both multi-driver modes dispatch sequentially, multiplexing SSE chunks with a `driver` field when `stream: true`. The agent request types use `EffectiveSourcePath()` methods for backward-compatible `source`/`repo_path` JSON field handling. See `docs/agentic-scan/agent-mode.md` for the full guide.

### Phase Aliases

Scan phases accept aliases: `deparos` = `discovery`, `discover` = `discovery`, `spitolas` = `spidering`, `ext` = `extension`, `audit`/`dast`/`assessment` = `dynamic-assessment`, `cve`/`kis`/`known-issues` = `known-issue-scan`. The canonical name for the module-based vulnerability scanning phase is `dynamic-assessment` (formerly `audit`). These work with `--only` and `--skip` flags (and as the `vigolium run <phase>` arg, e.g. `vigolium run cve`).

### Output Formats

The `--format` flag selects output format: `console` (default), `jsonl`, or `html`. Multiple formats can be combined (`--format jsonl,html`). HTML reports use an embedded ag-grid template (`public/static-reports/`) and require `-o/--output`. HTML format is supported for discovery and spidering phases.

### Module Development

New scanner modules implement `ActiveModule` or `PassiveModule`, register in the registry, and use `modkit` defaults for common behavior. See `docs/development/developing-modules.md` for the full guide.
