# Architecture Overview

> **You are here:** the entry point to Vigolium's architecture documentation. This page covers the system at a glance — operating modes, the two scanning paradigms, and how the pieces fit together. The sibling documents drill into each subsystem:
>
> - [native-scan.md](native-scan.md) — the deterministic Go scan pipeline, end to end
> - [agentic-scan.md](agentic-scan.md) — the AI agent engine, orchestrators, and olium runtime
> - [data-and-storage.md](data-and-storage.md) — multi-tenancy, the database model, and cloud storage
> - [server-and-api.md](server-and-api.md) — the REST server, traffic ingestion, and the API surface

Vigolium is a high-fidelity web vulnerability scanner written in Go. It combines deterministic, module-based scanning with AI-driven agentic analysis to provide broad and deep coverage of web application security issues. The scanner ships 245 modules (152 active, 93 passive) covering injection flaws, misconfigurations, information disclosure, authentication issues, and more.

Vigolium can operate as a CLI tool for one-off scans, as a persistent REST API server that ingests live traffic, or as a standalone ingestor client that forwards traffic to a running server. All scan data is project-scoped for multi-tenancy support. Module: `github.com/vigolium/vigolium`, requires Go 1.26+.

## Operating Modes

| Mode | Binary | Description |
|------|--------|-------------|
| **CLI Scanner** | `vigolium scan` | Run scans directly from the command line against targets, input files (OpenAPI, Postman, Burp, cURL, HAR), or source code paths. |
| **Server Mode** | `vigolium server` | Launch a REST API server with Swagger UI. Ingest traffic, trigger scans, query findings, and run agent sessions over HTTP. |
| **Ingestor Client** | `vigolium-ingestor` | Lightweight client that captures and forwards HTTP traffic to a running Vigolium server for analysis. |

## Scanning Paradigms

### Native Scan

The native scan pipeline is fully deterministic -- pure Go, no AI involvement. Requests flow through a fixed sequence of phases, each handling a distinct stage of reconnaissance or testing.

**Phases (in order):**

```
Heuristics -> External Harvesting -> Spidering -> Discovery -> DynamicAssessment -> KnownIssueScan -> Extension
```

| Phase | Purpose |
|-------|---------|
| Heuristics | Lightweight fingerprinting and technology detection |
| External Harvesting | Wayback Machine and other passive source enumeration |
| Spidering | Active crawling, JS analysis, link and form extraction |
| Discovery | Endpoint and content discovery via wordlists |
| DynamicAssessment | Core vulnerability testing -- injection, XSS, SSRF, etc. (CLI aliases: `audit`, `dast`, `assessment`) |
| KnownIssueScan | Checks for known CVEs and common misconfigurations |
| Extension | User-supplied JavaScript scanning extensions |

**Strategies** control which phases run and how aggressively:

| Strategy | Behavior |
|----------|----------|
| Lite | Fast surface-level scan; skips heavy crawling and discovery |
| Balanced | Default. Runs all phases with sensible limits |
| Deep | Exhaustive scanning with higher limits, broader wordlists, and external harvesting |

### Agentic Scan

Agentic scanning uses AI agents to drive or augment the scanning process. Invoked via `vigolium agent <mode>`. All AI dispatch runs through the in-process **olium** engine (`pkg/olium/`); providers include `openai-codex-oauth`, `anthropic-api-key`, `anthropic-oauth`, `openai-api-key`, and `anthropic-cli`.

| Mode | Command | Description |
|------|---------|-------------|
| **Query** | `vigolium agent query` | Single-shot prompt execution. Good for code review, endpoint discovery, secret detection. No network scanning. |
| **Autopilot** | `vigolium agent autopilot` | One long-running LLM session with full bash/file/web tools plus `report_finding` and `halt_scan`. The agent decides what to scan, runs scans, inspects results, and iterates until it halts. |
| **Swarm** | `vigolium agent swarm` | Multi-phase pipeline where native Go handles heavy lifting and AI intervenes at checkpoints -- planning attacks, triaging results, and generating custom JS scanner extensions. |
| **Audit** | `vigolium agent audit` | Foreground multi-phase AI source-code audit. Drives a separate Claude Code / Codex harness against a source tree. |
| **Olium** | `vigolium agent olium` (or `vigolium ol`) | Direct interactive TUI access to the olium engine. Use `-p` for a non-interactive one-shot prompt. |

All agent modes support `--source` for source-aware analysis and store session artifacts (plans, extensions, output) in a configurable sessions directory.

## Architecture at a Glance

```
                          +------------------+
                          |   Input Sources   |
                          | curl/OpenAPI/Burp |
                          |  HAR/Postman/URL  |
                          +--------+---------+
                                   |
                    +--------------+--------------+
                    |                             |
              vigolium scan                 vigolium server
                    |                             |
                    v                             v
            +---------------+           +-----------------+
            |  Scope Filter |           | REST API (Fiber)|
            +-------+-------+           +--------+--------+
                    |                             |
                    +-------------+---------------+
                                  |
                    +-------------+-------------+
                    |                           |
              Native Scan                 Agentic Scan
                    |                           |
         +----------+----------+      +---------+---------+
         |  Executor (Workers) |      |   Agent Engine    |
         |  Rate Limiter       |      |   Prompt Templates|
         +----------+----------+      |                   |
                    |                 +---------+---------+
         +----------+----------+                |
         |  Module Registry    |      +---------+---------+
         | 152 Active Modules  |      | Olium Providers   |
         |  93 Passive Modules |      | openai-codex-oauth /     |
         +----------+----------+      | anthropic-api-key |
                    |                 | anthropic-oauth /    |
                    |                 | openai-api-key /  |
                    |                 | anthropic-cli   |
                    |                 +---------+---------+
                    +-------------+---------------+
                                  |
                    +-------------+-------------+
                    |       Results Store       |
                    |  SQLite / PostgreSQL      |
                    |  HTML / JSONL / Console   |
                    +---------------------------+
```

## Architecture Documents

Deep-dives into each subsystem live alongside this page:

| Subsystem | Document | Covers |
|-----------|----------|--------|
| Native scan pipeline | [native-scan.md](native-scan.md) | CLI entry → input parsing → executor → modules → results → DB, all 12 stages |
| Agentic scan engine | [agentic-scan.md](agentic-scan.md) | Subcommands, orchestrators, the engine seam, olium runtime, providers |
| Data & persistence | [data-and-storage.md](data-and-storage.md) | `project_uuid` multi-tenancy, repository pattern, data models, cloud storage |
| Server & API | [server-and-api.md](server-and-api.md) | Fiber server, traffic ingestion, REST surface, agent run API |

## Where to Go Next (task docs)

| I want to... | Go to |
|--------------|-------|
| Get up and running quickly | [../getting-started.md](../getting-started.md) |
| Choose a scanning strategy | [../native-scan/strategies.md](../native-scan/strategies.md) |
| Learn about individual scan phases | [../native-scan/phases/](../native-scan/phases/) (discovery, spidering, dynamic-assessment, extension, known-issue-scan) |
| Explore agentic scanning | [../agentic-scan/agent-mode.md](../agentic-scan/agent-mode.md) |
| Use Autopilot / Swarm mode | [../agentic-scan/autopilot.md](../agentic-scan/autopilot.md) · [../agentic-scan/swarm.md](../agentic-scan/swarm.md) |
| Use the olium engine directly (TUI / headless) | [../agentic-scan/olium-agent.md](../agentic-scan/olium-agent.md) |
| Run Vigolium as a server | [../server-mode/](../server-mode/) |
| Configure scans and settings | [../configuration.md](../configuration.md) |
| Format and export results | [../output-and-reporting.md](../output-and-reporting.md) |
| Write custom JS extensions | [../customization/writing-extensions.md](../customization/writing-extensions.md) |
| Browse the REST API | [../api-references/](../api-references/) |
| Manage projects (multi-tenancy) | [../projects.md](../projects.md) |
| Use cloud storage (gs:// URLs, bundles, uploads) | [../storage.md](../storage.md) |
| Debug issues | [../troubleshooting.md](../troubleshooting.md) |
