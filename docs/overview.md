# Vigolium Overview

Vigolium is a high-fidelity web vulnerability scanner written in Go. It combines deterministic, module-based scanning with AI-driven agentic analysis to provide broad and deep coverage of web application security issues. The scanner ships 210 modules (127 active, 83 passive) covering injection flaws, misconfigurations, information disclosure, authentication issues, and more.

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
Heuristics -> External Harvesting -> Spidering -> SAST -> Discovery -> KnownIssueScan -> DynamicAssessment -> Extension
```

| Phase | Purpose |
|-------|---------|
| Heuristics | Lightweight fingerprinting and technology detection |
| External Harvesting | Wayback Machine and other passive source enumeration |
| Spidering | Active crawling, JS analysis, link and form extraction |
| SAST | Static analysis of source code (when `--source` is provided) |
| Discovery | Endpoint and content discovery via wordlists |
| KnownIssueScan | Checks for known CVEs and common misconfigurations |
| DynamicAssessment | Core vulnerability testing -- injection, XSS, SSRF, etc. (CLI aliases: `audit`, `dast`, `assessment`) |
| Extension | User-supplied JavaScript scanning extensions |

**Strategies** control which phases run and how aggressively:

| Strategy | Behavior |
|----------|----------|
| Lite | Fast surface-level scan; skips heavy crawling and discovery |
| Balanced | Default. Runs all phases with sensible limits |
| Deep | Exhaustive scanning with higher limits and broader wordlists |
| Whitebox | Source-aware scanning with route extraction and SAST integration |

### Agentic Scan

Agentic scanning uses AI agents to drive or augment the scanning process. Invoked via `vigolium agent <mode>`. Supports Claude, Codex, and OpenCode backends.

| Mode | Command | Description |
|------|---------|-------------|
| **Query** | `vigolium agent query` | Single-shot prompt execution. Good for code review, endpoint discovery, secret detection. No network scanning. |
| **Autopilot** | `vigolium agent autopilot` | The AI agent drives the CLI autonomously. With SDK protocol (default), the agent gets full coding agent tools. It can run scans, inspect results, and iterate. |
| **Swarm** | `vigolium agent swarm` | Multi-phase pipeline where native Go handles heavy lifting and AI intervenes at checkpoints -- planning attacks, triaging results, and generating custom JS scanner extensions. |

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
         |  127 Active Modules |      | AI Backend        |
         |   83 Passive Modules|      | Claude/Codex/     |
         +----------+----------+      | OpenCode          |
                    |                 +---------+---------+
                    +-------------+---------------+
                                  |
                    +-------------+-------------+
                    |       Results Store       |
                    |  SQLite / PostgreSQL      |
                    |  HTML / JSONL / Console   |
                    +---------------------------+
```

## Reading Guide

| I want to... | Go to |
|--------------|-------|
| Get up and running quickly | [getting-started.md](getting-started.md) |
| Understand the native scan pipeline | [native-scan/how-it-works.md](native-scan/how-it-works.md) |
| Choose a scanning strategy | [native-scan/strategies.md](native-scan/strategies.md) |
| Learn about individual scan phases | [native-scan/phases/](native-scan/phases/) (discovery, spidering, dynamic-assessment, extension, spa) |
| Explore agentic scanning | [agentic-scan/agent-mode.md](agentic-scan/agent-mode.md) |
| Use Autopilot mode | [agentic-scan/autopilot.md](agentic-scan/autopilot.md) |
| Use Swarm mode | [agentic-scan/swarm.md](agentic-scan/swarm.md) |
| Use Query mode | [agentic-scan/query.md](agentic-scan/query.md) |
| Run Vigolium as a server | [server-mode/](server-mode/) |
| Configure scans and settings | [configuration.md](configuration.md) |
| Format and export results | [output-and-reporting.md](output-and-reporting.md) |
| Write custom JS extensions | [customization/writing-extensions.md](customization/writing-extensions.md) |
| Build from source | [development/building.md](development/building.md) |
| Develop new scanner modules | [development/developing-modules.md](development/developing-modules.md) |
| Browse the REST API | [api-references/](api-references/) |
| Manage projects (multi-tenancy) | [projects.md](projects.md) |
| Debug issues | [troubleshooting.md](troubleshooting.md) |
