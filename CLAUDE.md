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

All scanner logic lives in **modules** registered in the **Registry** (`pkg/modules/registry.go`); the wiring is in `pkg/modules/default_registry_active.go` / `default_registry_passive.go` (currently 201 active + 116 passive registrations = 317 modules). Two types:

- **ActiveModule** (`pkg/modules/active.go`): Sends modified requests to detect vulnerabilities. Methods: `ScanPerInsertionPoint`, `ScanPerRequest`, `ScanPerHost`. Each module declares which `ScanScope` and `InsertionPointType` it handles.
- **PassiveModule** (`pkg/modules/passive.go`): Analyzes existing request/response pairs without sending new traffic. Optional `Flusher` interface for end-of-scan finalization.

Both share the base `Module` interface (ID, Name, Severity, Confidence, Tags, CanProcess, ScanScopes). Modules are tagged with classification labels (e.g., `spring`, `xss`, `light`) and can be filtered with `--module-tag` CLI flag or `?tag=` API parameter.

Module helper code lives in `pkg/modules/modkit/` (shared constants, default implementations) and `pkg/modules/infra/` (block detection, request filtering, response transfer).

### Ignored Directories

- **`platform/`** — Contains external tooling only. Do not read or modify files in this directory, except for `platform/vigolium-workbench/` which is the Next.js UI frontend — only go into it when making changes to the UI.

### Key Packages

- **`pkg/core/`** — Executor, worker pool, rate limiter, network utilities, scan statistics
- **`pkg/modules/`** — Module interfaces, registry, all active/passive scanner modules
- **`pkg/deparos/`** — Spider & discovery engine: crawling (`discovery/`), JS analysis (`jstangle/`), fingerprinting (`fingerprint/`), Wayback integration (`wayback/`), scope enforcement (`scope/`), WAF detection (`waf/`), storage (`storage/`)
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

Top-level commands registered in `pkg/cli/root.go`: `scan`, `scan-url`, `scan-request`, `run`, `replay`, `agent`, `olium` / `ol` (alias for `agent olium`), `audit` (alias for `agent audit`), `server`, `ingest`, `db`, `storage`, `project`, `scope`, `traffic`, `finding`, `strategy`, `auth`, `module`, `import`, `export`, `js`, `extensions` (alias `ext`), `init`, `config`, `version`, `update`, `doctor`, `log`. The `auth` command (`auth list`/`load`/`lint`/`totp`) manages authentication sessions; its source files are named `pkg/cli/session_*.go` for historical reasons. Agent subcommands (registered in `pkg/cli/agent_*.go`): `query`, `autopilot`, `swarm`, `olium`, `audit`, `session`.

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
- **Audit** (`vigolium agent audit`): Unified driver dispatcher — runs audit and/or piolium against the same source tree under one parent AgenticScan, with per-driver child rows. Default `--driver=auto` runs audit first and only falls back to piolium if audit fails (a clean audit run finishes the audit; piolium is never consulted and a missing piolium runtime is not reported). `--driver=both` runs audit then piolium unconditionally and sequentially. Both run a post-pass project-wide findings dedup; `--driver=piolium|audit` forces a single driver. Audit-leg agent selection uses `--provider`/`--agent {claude|codex}` (see the Audit entry above; `--agent` warns rather than errors under `--driver=piolium`). `--modes a,b,c` (or REST `modes: [...]`) chains modes back-to-back, stopping on the first non-complete mode: audit runs the chain natively via its own `--modes` (one subprocess, one row, aggregate cost — `auditstream` sums the per-mode `result` events); piolium chains via sequential `pi` runs in the same source tree collapsed into one aggregated child row (`pkg/agent/audit_chain.go` `PioliumChainScanner`). For `--driver=auto|both`, modes a driver can't run are skipped on that driver's leg (per-driver `ValidateAuditDriverModes`); a mode unknown to both drivers is a hard error. `--intensity deep` resolves to the chain `deep,confirm` (quick→`lite`, balanced→`balanced` stay single-mode) across `vigolium agent audit`, `vigolium agent audit`, and the `POST /api/agent/run/{audit,audit}` endpoints. `vigolium agent audit --list-modes` / `vigolium agent audit --list-modes` print the embedded audit binary's `list` (mode graph: phases, time estimate, descriptions) and exit. `vigolium audit` is a top-level alias for `vigolium agent audit` (same flags, via `registerAuditFlags`). `--keep-raw` is **on by default** for the CLI (the REST `keep_raw` default is unchanged): it forwards audit's `--keep-raw` AND retains the `<source>/vigolium-results/` source-tree copy (`KeepSourceOutputDir`); `--clean-raw` removes that source copy after the run (the session copy is always kept; `--keep-raw`+`--clean-raw` is a hard error). `-S`/`--stateless` runs the whole audit into a throwaway temp DB (main DB untouched, mirrors `vigolium scan -S`) and, after completion, auto-renders a self-contained HTML report from the run's findings via the `vigolium import --format html` generator to `vigolium-result/vigolium-audit-report.html` (override with `-o`/`--output`, which supports `gs://` and `{ts}`); `-S` is rejected with `--interactive`. `--output-dir <dir>` (stateless-only) bundles the HTML report (as `<dir>/vigolium-audit-report.html`) **and** a copy of each ran driver's raw `vigolium-results/` tree into one folder — one driver lands flat at `<dir>/vigolium-results/`, multiple are namespaced under `<dir>/<driver>/vigolium-results/`; the source-tree copy is left in place (per `--keep-raw`); a relative `-o` nests under `<dir>` while an absolute path or `gs://` URL escapes it, and `{ts}`/`{project-uuid}` in `<dir>` are expanded once so report + raw copy share the same directory. `-S` without `--output-dir` warns that raw output stays under `<source>/vigolium-results/`; `--output-dir` without `-S` warns and is ignored (mirrors `-o`). Audit-leg report/bundle helpers: `pkg/cli/agent_audit_report.go` `emitAuditStatelessReport` / `resolveAuditReportDest` / `bundleAuditRawResults`.

Source code context is provided via the `--source` flag across all agent subcommands. The `Options.SourcePath` field carries this through the agent engine. The `TemplateData.SourcePath` variable is available in prompt templates. The legacy `--repo` flag has been removed entirely.

All agent modes create a session directory under `sessions_dir` (configurable via `agent.sessions_dir` in `vigolium-configs.yaml`, defaults to `~/.vigolium/agent-sessions/`). Session dirs store agent artifacts: `runtime.log`, `transcript.jsonl` (Pi-compatible olium conversation transcript), `extensions/`, `session-config.json`, `swarm-plan.json` (swarm), `master-output.md` / `source-analysis-output.md` / `code-audit-output.md` (per-phase outputs), `audit-stream.jsonl` (audit), `checkpoint.json` (swarm resume). The `EnsureSessionDir(baseDir, runID)` helper in `pkg/agent/pipeline_types.go` creates the directory structure.

The `transcript.jsonl` is a machine-readable, append-only conversation log of an olium engine run, written by `pkg/olium/sessionlog` and shaped to match the Pi coding agent's session-log schema (a parentId-chained event tree: `session` header → `model_change` → `thinking_level_change` → `message` lines for roles user / assistant / toolResult, with full tool arguments and untruncated tool results). It is produced via a single tee at `engine.Engine.Run` (`engine.Config.Recorder`, the `engine.EventRecorder` interface), so the olium TUI (`olium`/`ol`), headless (`-p`), and autopilot all emit one without touching their drain loops; closed via `Engine.CloseRecorder()`. Forks do not inherit the recorder (concurrent sub-runs would interleave one file). Distinct from `runtime.log` (human-readable tool-card log) and `audit-stream.jsonl` (the separate vigolium-audit harness, not olium). Swarm/query phases also emit transcripts now: the `pkg/agent` runtime attaches a recorder in `buildOliumEngineWithSpec` driven by `SessionSpec.Record` (an `agent.RecordSpec`), writing **per-phase** files `transcript-<template>.jsonl` under the session dir (concurrent same-template calls — swarm plan batches — get `-2`/`-3` suffixes via `uniqueTranscriptName` so they never corrupt one file). The fresh-per-call path (`RunPrompt`) flushes via `defer eng.CloseRecorder()`; the reused-session path (source-analysis explore) flushes via `AgentSession.Close()` (forks carry no recorder). Live model reasoning is rendered to a muted `⋈ thinking` stderr lane under `-v/--verbose` in autopilot and swarm/query, centralized in `pkg/olium/toollog` (`HandleThinking`/`FlushThinking`, sharing `CompactThinking` with the TUI). Fidelity caveat: structurally Pi-compatible and readable, but provider-opaque resume fields (message signatures, the per-component cost split, `responseId`) are omitted — the log is for debugging, not for replaying back into Pi.

Prompt templates are Markdown files with YAML frontmatter stored in `~/.vigolium/prompts/` or embedded in the binary (`public/presets/prompts/`). Output schemas: `findings`, `http_records`, `attack_plan`, `triage_result`, `source_analysis`. The olium engine is configured under `agent.olium` in `vigolium-configs.yaml` — see `OliumConfig` in `internal/config/agent.go`. Key fields: `provider`, `model`, `oauth_cred_path`, `oauth_token`, `llm_api_key`, `reasoning_effort`, `max_turns` (default 32), `max_concurrent` (default 4), `call_timeout_sec` (default 600), `cache_size` (default 1024). Providers: `openai-compatible` (default, default model `gemma4:latest`), `openai-codex-oauth`, `anthropic-api-key`, `anthropic-oauth`, `openai-api-key`, `openai-responses` (public OpenAI Responses API `/v1/responses`, API-key auth), `anthropic-cli`, `anthropic-compatible` (Anthropic Messages `/v1/messages` at a custom `custom_provider.base_url`). The Responses wire format (request `input`/`tools` + `response.*` SSE state machine) is shared by `openai-codex-oauth` and `openai-responses` via `pkg/olium/provider/responses_stream.go`. REST API endpoints: `POST /api/agent/run/{query,autopilot,swarm,audit,audit}`, `GET /api/agent/status/list`, `GET /api/agent/status/:id`, `GET /api/agent/sessions[/:id[/logs|/artifacts[/:filename]]]`, `POST /api/agent/chat/completions` (OpenAI-compatible). The audit endpoint takes `driver: "auto"|"both"|"audit"|"piolium"` (default `"auto"`); `auto` runs audit and only falls back to piolium if audit fails, `both` runs both unconditionally, and both multi-driver modes dispatch sequentially, multiplexing SSE chunks with a `driver` field when `stream: true`. The agent request types use `EffectiveSourcePath()` methods for backward-compatible `source`/`repo_path` JSON field handling. See `docs/agentic-scan/agent-mode.md` for the full guide.

### Phase Aliases

Scan phases accept aliases: `deparos` = `discovery`, `discover` = `discovery`, `spitolas` = `spidering`, `ext` = `extension`, `audit`/`dast`/`assessment` = `dynamic-assessment`, `cve`/`kis`/`known-issues` = `known-issue-scan`. The canonical name for the module-based vulnerability scanning phase is `dynamic-assessment` (formerly `audit`). These work with `--only` and `--skip` flags (and as the `vigolium run <phase>` arg, e.g. `vigolium run cve`).

### Output Formats

The `--format` flag selects output format: `console` (default), `jsonl`, `html`, `sqlite` (aliases `sqlite3`, `db`), or `fs`. Multiple formats can be combined (`--format jsonl,html`). HTML reports use an embedded ag-grid template (`public/static-reports/`) and require `-o/--output`. HTML format is supported for discovery and spidering phases. The `sqlite` format dumps the run's standalone database to `<output>.sqlite` via `VACUUM INTO` and requires `-S/--stateless` (the per-run temp DB) plus `-o/--output`; under `--split-by-host` each per-host file is named `<base>-<host>.sqlite`. The exported file reopens directly with `vigolium finding/traffic -S --db <file>.sqlite`.

The `fs` format (`pkg/cli/fsexport.go`) writes a flat, browsable filesystem tree so a coding agent (or anyone with `ls`/`grep`/`jq`) can investigate a scan with no DB. It writes two sibling directories off the `-o` base — defaulting to `vigolium` in the cwd when no `-o` is given, so `-o run` yields `run-traffic/` + `run-findings/`. Each `<host>/` holds per-host zero-padded ids (assigned in `sent_at` order, so re-exports are reproducible): `<id>.req` (a leading `@target <scheme>://<authority>` line then the raw request verbatim — directly replayable by stripping line 1), `<id>.resp.headers` (status line + headers), and `<id>.resp.body` (gzip-decoded so it greps clean). `<host>/<id>.md` under `-findings/` renders each finding cross-linked to its `.req` file (falling back to the finding's inline request/response when the linked record was filtered out). Each sibling dir carries an `index.json` (flat array, jq-friendly) mapping ids → method/url/status/content-type and, for traffic, the top severity of any finding touching that record. Available on `vigolium export`, `vigolium db export` (honoring its filters), and `scan`/`scan-url`/`scan-request`/`run` (works with or without `-S`; `--split-by-host` is a no-op since `fs` already splits by host). Honors `--omit-response` (drops the `.resp.*` files). The shared layout/rendering lives in `pkg/fsexport`.

The same tree can be produced **live** by the ingestion server: `vigolium server --mirror-fs <dir>` (config `server.mirror_fs_path`) mirrors every saved HTTP record and finding to `<dir>/traffic/` + `<dir>/findings/` as they're persisted — in addition to the database — so an external agent can read ingested Burp/proxy traffic as files in real time. It's wired via optional `Repository.OnRecordSaved`/`OnFindingSaved` callbacks (`pkg/database/repository.go`) the server sets only when the flag is on (CLI scans are unaffected), feeding `fsexport.Mirror` — a background-goroutine writer that never blocks the DB save path, uses append-only `index.jsonl` (vs the one-shot export's `index.json` array), and resumes per-host id numbering from the existing tree across restarts.

### Driving Vigolium from a coding agent

Vigolium is built to be shelled out to by an LLM/coding agent. Key contracts (full guide: `docs/coding-agent.md`):

- **Two JSON contracts:** `-j/--json` on read/query commands (`finding`, `traffic`, `db`) emits a single structured object with **compact, token-aware** request/response bodies (header-kept, body-preview-capped with `body_size`/`body_sha256`/`body_truncated`, binary/static bodies stubbed as `body_omitted:"binary"`, findings get a windowed `response_evidence` snippet). The bulk `{"type":...,"data":{...}}` stream stays on `--format jsonl` / `export`. The shared serializer is `pkg/cli/agentview.go`.
- **Output shaping flags** on `finding`/`traffic`/`db ls`: `--compact` (metadata only), `--fields a,b,c` (project JSON keys), `--full-body` (complete bodies), plus `finding --with-records` (embed linked HTTP records → self-contained triage bundle), `--min-severity`, and `--agentic-scan <uuid>` (findings from an agent run; expands to the whole run tree via `resolveAgenticScanTree`).
- **Exit-code gating:** `scan`/`scan-url`/`scan-request`/`run` take `--fail-on <severity>` — exit non-zero when a finding at/above that severity is present (output still written first; `--soft-fail` overrides; per-child under `-P`). Logic in `pkg/cli/scan_fail_on.go` + `severity_gate.go`.
- **Agentic scans** (`agent autopilot|swarm|audit`) under `--json` route the live stream to stderr and print a single summary object to stdout (`{agentic_scan_uuid, status, counts_by_severity, session_dir, top_findings, query}`) via `emitAgentScanJSONSummary` (`pkg/cli/agent_scan_summary.go`), so an agent gets a handle + ready follow-up query without chasing session-dir files.

### Module Development

New scanner modules implement `ActiveModule` or `PassiveModule`, register in the registry, and use `modkit` defaults for common behavior. See `docs/development/developing-modules.md` for the full guide.
