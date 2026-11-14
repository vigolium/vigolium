# Architecture Overview

> **You are here:** the entry point to Vigolium's architecture documentation. This page covers the system at a glance — operating modes, the two scanning paradigms, and how the pieces fit together. The sibling documents drill into each subsystem:
>
> - [native-scan.md](native-scan.md) — the deterministic Go scan pipeline, end to end
> - [agentic-scan.md](agentic-scan.md) — the AI agent engine, orchestrators, and olium runtime
> - [data-and-storage.md](data-and-storage.md) — multi-tenancy, the database model, and cloud storage
> - [server-and-api.md](server-and-api.md) — the REST server, traffic ingestion, and the API surface

Vigolium is a high-fidelity web vulnerability scanner written in Go. It combines deterministic, module-based scanning with AI-driven agentic analysis to provide broad and deep coverage of web application security issues. The scanner ships 337 modules (218 active, 119 passive) covering injection flaws, misconfigurations, information disclosure, authentication issues, and more.

Vigolium can operate as a CLI tool for one-off scans, as a persistent REST API server that ingests live traffic, or as a traffic-forwarding ingestor client (`vigolium ingest`) that pushes traffic to a running server. All scan data is project-scoped for multi-tenancy support. Module: `github.com/vigolium/vigolium`, requires Go 1.27+.

## Operating Modes

| Mode | Binary | Description |
|------|--------|-------------|
| **CLI Scanner** | `vigolium scan` | Run scans directly against targets or input files (OpenAPI, Postman, Burp, cURL, HAR). Source-code analysis belongs to the agent commands. |
| **Server Mode** | `vigolium server` | Launch a REST API server with Swagger UI. Ingest traffic, trigger scans, query findings, and run agent sessions over HTTP. |
| **Ingestor Client** | `vigolium ingest` | Lightweight client that captures and forwards HTTP traffic to a running Vigolium server for analysis. |

## Scanning Paradigms

### Native Scan

The native scan pipeline is fully deterministic -- pure Go, no AI involvement. Requests flow through a fixed sequence of phases, each handling a distinct stage of reconnaissance or testing.

**Phases (in order):**

```
Heuristics -> optional Port Sweep -> External Harvesting -> Spidering
-> optional Probe -> Discovery / Input Ingestion -> targeted Re-spider
-> Seed -> DynamicAssessment -> KnownIssueScan
```

Only the enabled phases run; the order and each phase's gate live in
`BuildNativeScanPlan` (`internal/runner/native_plan.go`).

| Phase | Purpose |
|-------|---------|
| Heuristics | Fetches each target's root page and classifies it (blank vs content, JSON/XML API, SPA) to decide whether spidering it is worthwhile; not technology fingerprinting |
| Port Sweep | Optional alternate-port HTTP(S) discovery for deep/subdomain-following runs |
| External Harvesting | Wayback Machine and other passive source enumeration |
| Spidering | Active crawling, JS analysis, link and form extraction |
| Probe | Opt-in host sweep (`--only probe`): one request per target, passive modules only, no content discovery |
| Discovery | Endpoint and content discovery via wordlists |
| Targeted Re-spider | Re-crawls rich/SPA routes that discovery surfaced after the first browser crawl (needs spidering, discovery and dynamic assessment enabled) |
| Seed | When ingestion/discovery is skipped (e.g. `--only dynamic-assessment`), stores the CLI targets as records so assessment has input |
| DynamicAssessment | Core vulnerability testing -- injection, XSS, SSRF, etc. (CLI aliases: `audit`, `dast`, `assessment`) |
| KnownIssueScan | Checks for known CVEs and common misconfigurations |

JavaScript extensions are selected and dispatched as part of dynamic
assessment; `extension` remains a selector for extension-only work, not a
trailing stage after known-issue scanning.

**Browser capture is accounted, not assumed.** The browser phases (Spidering,
targeted Re-spider) and the agent's browser tools persist what Chromium
observed through a writer that returns a *capture receipt* once it has drained:
records accepted, persisted, refused, failed, and whether the final drain
completed. Phase summaries and tool results report from the receipt — never
from the fact that capture was configured — and a phase whose receipts show
loss says `run incomplete`, meaning the stored traffic is a lower bound on what
the browser saw. What a browser crawl may change, and which browser security
exceptions it runs with, is one reported policy; see
[Browser policy](../guides/browser-policy.md).

**Strategies** control which phases run and how aggressively:

| Strategy | Behavior |
|----------|----------|
| Lite | Fast surface-level scan: dynamic assessment only (no spidering, discovery, external harvest, or known-issue scan), under a pace ceiling |
| Balanced | Default. Spidering, discovery, dynamic assessment and known-issue scan; no external harvest, and discovery's `/FUZZ` brute-force is off |
| Deep | Everything in balanced plus external harvesting. The `--intensity deep` preset (which selects this strategy through a scanning profile) also turns on the alternate-port sweep, subdomain following, discovery fuzzing, and the large wordlist tier |

### Agentic Scan

Agentic scanning uses AI agents to drive or augment the scanning process.
Query, Autopilot, Swarm, Triage, and Olium use the in-process **olium** engine
(`pkg/olium/`). Audit is the deliberate exception: it drives the separate audit
and/or piolium harnesses. Olium supports Codex/OpenAI, Anthropic, Vertex, local,
and custom OpenAI/Anthropic-compatible providers.

| Mode | Command | Description |
|------|---------|-------------|
| **Query** | `vigolium agent query` | Single-shot prompt execution. Good for code review, endpoint discovery, secret detection. No network scanning. |
| **Autopilot** | `vigolium agent autopilot` | One long-running LLM session with full bash/file/web tools plus `report_finding` and `halt_scan`. The agent decides what to scan, runs scans, inspects results, and iterates until it halts. |
| **Swarm** | `vigolium agent swarm` | Multi-phase pipeline where native Go handles heavy lifting and AI intervenes at checkpoints -- planning attacks, triaging results, and generating custom JS scanner extensions. |
| **Audit** | `vigolium agent audit` | Unified source audit: audit, piolium, automatic fallback, or both drivers. |
| **Triage** | `vigolium agent triage` | Confirm one stored finding and downgrade false positives. |
| **Olium** | `vigolium agent olium` (or `vigolium ol`) | Direct interactive TUI access to the olium engine. Use `-p` for a non-interactive one-shot prompt. |

`query`, `autopilot`, `swarm`, and `audit` accept source-code context. Agent
runs store their relevant transcripts, plans, extensions, and outputs in the
configured sessions directory.

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
         | 201 Active Modules  |      | Olium Providers   |
         | 117 Passive Modules |      | OpenAI/Anthropic |
         +----------+----------+      | Vertex/local/    |
                    |                 | compatible APIs  |
                    |                 | + CLI/SDK bridge |
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
| Native scan pipeline | [native-scan.md](native-scan.md) | CLI entry → input parsing → orchestration → executor → modules → results → DB |
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
| Use the olium engine directly (TUI / one-shot) | [../agentic-scan/olium-agent.md](../agentic-scan/olium-agent.md) |
| Run Vigolium as a server | [../server-mode/](../server-mode/) |
| Configure scans and settings | [../configuration.md](../configuration.md) |
| Format and export results | [../output-and-reporting.md](../output-and-reporting.md) |
| Write custom JS extensions | [../customization/writing-extensions.md](../customization/writing-extensions.md) |
| Browse the REST API | [../api-references/](../api-references/) |
| Manage projects (multi-tenancy) | [../projects.md](../projects.md) |
| Use cloud storage (gs:// URLs, bundles, uploads) | [../storage.md](../storage.md) |
| Debug issues | [../troubleshooting.md](../troubleshooting.md) |
