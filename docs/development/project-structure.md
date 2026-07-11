# Project Structure

A map of the repository for contributors. The high-level execution model is in
[../architecture/overview.md](../architecture/overview.md); this doc is about
*where code lives*.

## Top level

```
cmd/vigolium/        Main CLI entry point (Cobra)
pkg/                 Public packages (the bulk of the codebase)
internal/            Private packages (config, runner, logger, embedded resources, ingestor)
docs/                Documentation (this tree)
public/              Embedded presets: scanning profiles, JS extensions, prompt templates
static/              Embedded static report assets (HTML/ag-grid)
test/                e2e, canary, integration & benchmark suites (build-tagged)
platform/            External tooling — do NOT read/modify (except platform/vigolium-workbench, the Next.js UI)
build/               Packaging / docker assets
Makefile             Build & test workflows (always build via make — see building.md)
```

## Entry point & orchestration

| Path | Responsibility |
|------|----------------|
| `cmd/vigolium/` | `main()` — thin; delegates to `pkg/cli` |
| `pkg/cli/` | All Cobra commands (`scan`, `server`, `agent_*`, `ingest`, `db`, `project`, …); commands are registered in `root.go` |
| `internal/runner/` | High-level scan orchestration — sequences the phases of a native scan |
| `internal/config/` | Configuration model, loader, scope matcher, agent config |
| `internal/logger/` | Zap-based structured logging |
| `internal/resources/` | Generated/embedded assets (e.g. the bun-compiled jstangle binary) |
| `internal/ingestor/` | `vigolium ingest` traffic-forwarding client internals |

## Native-scan core

| Path | Responsibility |
|------|----------------|
| `pkg/core/` | The **Executor** — worker pool, module dispatch, rate limiter, scan stats, response buffer pooling |
| `pkg/modules/` | Module interfaces, the **Registry**, and all active/passive scanner modules. `modkit/` = shared base types; `infra/` = block detection & request filtering; `modtest/` = unit-test helper |
| `pkg/httpmsg/` | HTTP request/response model, insertion points, parsing/serialization |
| `pkg/http/` | HTTP requester with a middleware pipeline |
| `pkg/dedup/` | Disk-backed dedup sets and per-scan dedup manager |
| `pkg/input/` | Input source adapters (OpenAPI, Swagger, Postman, Burp, cURL, Nuclei, HAR) |
| `pkg/work/` | Work-item types flowing through the executor |
| `pkg/queue/` | Hybrid queue (in-memory + disk/Redis spillover) |
| `pkg/output/` | Result formatting, output handlers, HTML report generation |
| `pkg/oast/` | Out-of-band (OAST) interaction service for blind-vuln detection |
| `pkg/anomaly/`, `pkg/mutation/` | Anomaly ranking and payload-mutation strategies |

## Discovery & crawling

| Path | Responsibility |
|------|----------------|
| `pkg/deparos/` | Spider & discovery engine: crawling, JS analysis (`jstangle/`), fingerprinting, Wayback, scope, WAF detection, storage |
| `pkg/spitolas/` | Chromium/CDP browser-driven crawler (vendored `rod` lives under `pkg/spitolas/rod`, excluded from lint/test) |
| `pkg/harvester/` | Endpoint/secret harvesting helpers |
| `pkg/jsext/` | JavaScript extension engine (Sobek) exposing the `vigolium.*` API; TS defs in `vigolium.d.ts` |

## Agentic scan & AI runtime

| Path | Responsibility |
|------|----------------|
| `pkg/agent/` | Agentic scan engine: prompts, context enrichment, autopilot/swarm runners, output parsing, DB ingestion. AI dispatch is funneled through `olium_adapter.go` |
| `pkg/olium/` | In-process Go agent runtime: provider drivers, turn-based engine, tool registry, skills, autopilot loop, TUI |
| `pkg/audit/` | Embedded vigolium-audit harness driver (separate from olium) |
| `pkg/piolium/` | Pi-native foreground audit driver |
| `pkg/authentication/`, `pkg/replay/` | Auth session prep and request replay used by agent modes |

## Storage, server & supporting

| Path | Responsibility |
|------|----------------|
| `pkg/database/` | Repository pattern over SQLite (default) / PostgreSQL via Bun ORM; batch record ingestion & per-source dedup |
| `pkg/dbimport/`, `pkg/storage/` | DB import helpers and storage abstractions |
| `pkg/server/` | REST API server (Fiber), Swagger UI, ingestion handlers, agent run API |
| `pkg/notify/` | Outbound notifications |
| `pkg/types/` | Shared types (incl. `severity`) used across packages |
| `pkg/utils/`, `pkg/procutil/`, `pkg/gitutil/`, `pkg/toolexec/`, `pkg/terminal/`, `pkg/yamlext/`, `pkg/metrics/`, `pkg/diagnostics/`, `pkg/cftbrowser/`, `pkg/knownissuescan/` | Cross-cutting utilities |

## Dependency direction

The intended layering (lower depends on nothing above it):

```
types / httpmsg / output     ← foundational, depend on little
        ↑
http / dedup / modkit         ← shared infrastructure
        ↑
modules (active/passive)      ← detection logic
        ↑
core (executor)               ← orchestration
        ↑
internal/runner, pkg/server, pkg/cli   ← top-level wiring
```

`pkg/deparos` is intentionally self-contained — it has no dependency on `core`,
`modules`, or `agent`, so the discovery engine can be embedded independently.

## Multi-tenancy

All scan data is scoped to a **project** via `project_uuid` on every data table.
The `--project` flag / `VIGOLIUM_PROJECT` env var scope CLI operations; the
`X-Project-UUID` header scopes server API operations. See
[../projects.md](../projects.md).

See also: [building.md](building.md) and
[developing-modules.md](developing-modules.md).
