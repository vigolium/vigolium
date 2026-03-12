<p align="center">
  <a href="https://www.osmedeus.org"><img alt="Osmedeus" src="static/vigolium-logo.png" height="140" /></a>
  <br />
  <strong>Vigolium - High-fidelity web vulnerability scanner that combines speed, modularity, precision, and AI-powered analysis.</strong>
</p>

***

Vigolium scans web applications for reflected XSS, SQL injection, LFI, SSTI, CRLF injection, CSRF, IDOR, NoSQL injection, open redirects, command injection, path traversal, SAML/XXE, GraphQL issues, file upload flaws, default credentials, CMS vulnerabilities (WordPress, Drupal, Joomla), Firebase misconfigurations, cloud storage security, PHP/ASP.NET framework issues, JS framework security (Next.js, Nuxt, Remix), and more — including blind vulnerabilities via out-of-band (OAST) callbacks.

It operates as a CLI scanner, an API server with traffic ingestion, or a standalone ingestor client. Vigolium also integrates with AI coding agents (Claude, Gemini, OpenCode) for automated security code review, endpoint discovery, and secret detection.


| CLI Scan | Traffic & Finding List |
|:---:|:---:|
| ![CLI Scan 1](static/vigolium-cli-scan-1.png) | ![CLI Scan 2](static/vigolium-traffic-list.png) |
| ![Finding List](static/vigolium-cli-scan-2.png) | ![Traffic List](static/vigolium-finding-list.png) |

| UI Dashboard | More Dashboard |
|:---:|:---:|
| ![Dashboard 1](static/vigolium-ui-dashboard-1.png) | ![Dashboard 2](static/vigolium-ui-dashboard-2.png) |
| ![Dashboard 3](static/vigolium-ui-dashboard-3.png) | ![Dashboard 4](static/vigolium-ui-dashboard-4.png) |

| Static Reports | Static Reports |
|:---:|:---:|
| ![Static Report 1](static/vigolium-static-report-1.png) | ![Static Report 2](static/vigolium-static-report-2.png) |

## Key Features

- **149 scanner modules** — 89 active (fuzzing) and 60 passive (pattern matching) modules covering OWASP Top 10 and beyond
- **Out-of-band testing (OAST)** — detect blind vulnerabilities (blind XSS, SSRF, command injection) via interactsh callback URLs with automatic payload correlation
- **Value-aware mutation** — classify parameter values by semantic type (integer, UUID, JWT, email, etc.) and generate intelligent mutations per intent (neighbor, boundary, escalation)
- **Multi-phase pipeline** — external harvesting, content discovery, SPA crawling, and dynamic assessment controlled by strategy presets
- **Scanning profiles** — bundle strategy, pace, scope, and module config into a single YAML file (`--scanning-profile`)
- **Multiple input formats** — URLs, OpenAPI/Swagger, Postman, Burp Suite, cURL, Nuclei JSONL, CrawlerX
- **API server mode** — REST API with Swagger UI, multi-format ingestion, transparent HTTP proxy, OpenAI-compatible agent endpoint
- **Browser-based spider** — Chromium-driven crawler (Spitolas) with SPA support, form filling, and JS analysis
- **Content discovery** — adaptive directory/file enumeration engine (Deparos) with soft-404 detection
- **Header injection** — automatic fuzzing of existing and synthetic headers (X-Forwarded-For, X-Forwarded-Host, True-Client-IP, Referer)
- **JavaScript extensions** — custom modules and hooks via embedded JS engine (`vigolium.http`, `vigolium.scan`, `vigolium.source`)
- **Source code awareness** — link repos to hostnames for source-aware scanning with `vigolium.source.*` API
- **Concurrent architecture** — configurable worker pool with per-host rate limiting and hybrid in-memory/disk/Redis queue
- **AI agent integration** — run Claude, Gemini, OpenCode, or custom AI agents for security code review, endpoint discovery, and secret detection via CLI or REST API (with SSE streaming). Includes autopilot mode (autonomous sandboxed scanning) and pipeline mode (multi-phase AI-guided vulnerability assessment)
- **HTML reports** — generate self-contained HTML reports with sortable/filterable ag-grid tables (`--format html`)

## Installation

```bash
git clone https://github.com/vigolium/vigolium.git
cd vigolium
make deps          # download Go modules + jsscan binaries
make build         # build and install to $GOPATH/bin
```

Requires **Go 1.26+**. See [docs/development/building.md](docs/development/building.md) for prerequisites, cross-compilation, embedded Chromium builds, and Docker.

## Quick Start

```bash
# Scan a single target (default: balanced strategy)
vigolium scan -t https://example.com

# Scan with a strategy preset
vigolium scan -t https://example.com --strategy deep

# Scan specific modules only
vigolium scan -t https://example.com -m xss-reflected,sqli-error

# Scan from an OpenAPI spec
vigolium scan -T openapi.yaml -I openapi

# Pipe URLs from stdin
cat urls.txt | vigolium scan

# Run only content discovery (alias: deparos)
vigolium scan -t https://example.com --only discovery

# Generate an HTML report
vigolium scan -t https://example.com --only discovery --format html -o report.html
```

See [docs/scanning-guide.md](docs/scanning-guide.md) for the full guide on scan phases, strategies, profiles, pace configuration, and source-aware scanning.

## Server Mode

```bash
# Start API server with authentication
vigolium server -k my-secret-key

# Enable transparent HTTP proxy for traffic recording
vigolium server -k my-key --ingest-proxy-port 9003

# Auto-scan ingested traffic
vigolium server -k my-key --scan-on-receive
```

```bash
# Ingest traffic to a running server
cat urls.txt | vigolium ingest -s http://localhost:9002

# Ingest an OpenAPI spec
vigolium ingest -s http://localhost:9002 -i api.yaml -I openapi
```

See [docs/server-and-ingestion.md](docs/server-and-ingestion.md) for ingestion workflows and [docs/api-overview.md](docs/api-overview.md) for the full REST API reference.

## Agent Mode

Run AI agents for automated security analysis — code review, endpoint discovery, autonomous scanning, and more:

```bash
# Security code review of a repository
vigolium agent --prompt-template security-code-review --repo ./myapp

# Run with specific files
vigolium agent --prompt-template injection-sinks --repo ./myapp --files auth.go,db.go

# Send a freeform prompt to the default agent
vigolium agent query --prompt "Explain the OWASP Top 10 in one sentence each"

# Dry run — render prompt without executing
vigolium agent --prompt-template endpoint-discovery --repo ./myapp --dry-run

# Autopilot: agent autonomously runs scanner commands in a sandboxed terminal
vigolium agent autopilot -t https://example.com

# Pipeline: multi-phase AI-guided scanning (discover → plan → scan → triage → report)
vigolium agent pipeline -t https://example.com
vigolium agent pipeline -t https://example.com --focus 'API injection'
vigolium agent pipeline -t https://example.com --repo ./src --max-rescan-rounds 3
vigolium agent pipeline -t https://example.com --skip-phase discover --start-from plan

# List available agents and templates
vigolium agent --list-agents
vigolium agent --list-templates
```

Three operational modes:
- **Run** — single-shot template-based prompts for code review, endpoint discovery, secret detection
- **Autopilot** — interactive ACP session where the agent autonomously executes scanner commands via a sandboxed terminal with command allowlisting
- **Pipeline** — fixed multi-phase scanning pipeline where native Go code handles discovery and scanning, while AI agents plan attack strategy (phase 2) and triage findings (phase 4)

Configure agent backends in `~/.vigolium/vigolium-configs.yaml`. Custom prompt templates go in `~/.vigolium/prompts/`. See [docs/agent-mode.md](docs/agent-mode.md) for the full guide.

## Scan Layers

Vigolium's scanning pipeline is composed of modular layers, each documented separately:

| Layer | Description | Docs |
|-------|-------------|------|
| **Content Discovery (Deparos)** | Adaptive directory/file enumeration with fingerprint-based soft-404 detection | [docs/scan-layers/deparos.md](docs/scan-layers/deparos.md) |
| **Browser Spider (Spitolas)** | Chromium-driven state-machine crawler with CDP traffic capture | [docs/scan-layers/spitolas.md](docs/scan-layers/spitolas.md) |
| **SPA Scanning** | Single Page Application handling with DOM mutation tracking and async API capture | [docs/scan-layers/spa.md](docs/scan-layers/spa.md) |
| **Dynamic Assessment** | Active/passive vulnerability scanning with insertion point extraction and DiffScan framework | [docs/scan-layers/dynamic-assessment.md](docs/scan-layers/dynamic-assessment.md) |
| **Scanner Modules** | 89 active and 60 passive modules covering OWASP Top 10 and beyond | [docs/scan-layers/scanner-modules.md](docs/scan-layers/scanner-modules.md) |

Discovery configuration: [docs/scan-layers/deparos-configs-guide.md](docs/scan-layers/deparos-configs-guide.md)

## Documentation

| Topic | Link |
|-------|------|
| Scanning Guide | [docs/scanning-guide.md](docs/scanning-guide.md) |
| Scanning Modes Overview | [docs/running-scan/scanning-modes-overview.md](docs/running-scan/scanning-modes-overview.md) |
| Blackbox Scanning | [docs/running-scan/blackbox-scan.md](docs/running-scan/blackbox-scan.md) |
| Whitebox Scanning (SAST) | [docs/running-scan/whitebox-scan.md](docs/running-scan/whitebox-scan.md) |
| Whitebox Agent Scanning | [docs/running-scan/whitebox-agent-scan.md](docs/running-scan/whitebox-agent-scan.md) |
| Full Scan Pipeline | [docs/running-scan/full-scan.md](docs/running-scan/full-scan.md) |
| Server & Ingestion | [docs/server-and-ingestion.md](docs/server-and-ingestion.md) |
| REST API Reference | [docs/api-overview.md](docs/api-overview.md) |
| Agent Mode | [docs/agent-mode.md](docs/agent-mode.md) |
| Content Discovery (Deparos) | [docs/scan-layers/discovery-with-deparos.md](docs/scan-layers/discovery-with-deparos.md) |
| Deparos Configuration | [docs/scan-layers/deparos-configs-guide.md](docs/scan-layers/deparos-configs-guide.md) |
| Browser Spider (Spitolas) | [docs/scan-layers/spidering-with-spitolas.md](docs/scan-layers/spidering-with-spitolas.md) |
| SPA Scanning | [docs/scan-layers/spa.md](docs/scan-layers/spa.md) |
| Dynamic Assessment | [docs/scan-layers/dynamic-assessment.md](docs/scan-layers/dynamic-assessment.md) |
| Scan Scope & Module Dispatch | [docs/scan-layers/scan-scope.md](docs/scan-layers/scan-scope.md) |
| Scanner Modules Reference | [docs/scan-layers/scanner-modules.md](docs/scan-layers/scanner-modules.md) |
| Writing Extensions | [docs/development/writing-extensions.md](docs/development/writing-extensions.md) |
| Developing Modules | [docs/development/developing-modules.md](docs/development/developing-modules.md) |
| Building from Source | [docs/development/building.md](docs/development/building.md) |
| Project Structure | [docs/development/project-structure.md](docs/development/project-structure.md) |
| Benchmark Testing | [docs/development/benchmark-testing.md](docs/development/benchmark-testing.md) |

## Extensions

Write custom scan modules and hooks in JavaScript without recompiling:

```bash
vigolium ext ls                # list loaded extensions
vigolium ext docs --example    # browse API with code examples
vigolium ext preset            # install starter scripts
```

See [docs/development/writing-extensions.md](docs/development/writing-extensions.md) for the extension authoring guide.

## CLI Reference

```
Scanning:
  -t, --target           Target URL
  -T, --target-file      File containing target URLs
  -i, --input            Input file path (- for stdin)
  -I, --input-mode       Input format: urls, openapi, nuclei, burpxml, curl, postman
  -m, --modules          Modules to run (comma-separated or 'all')
      --strategy         Strategy preset: lite, balanced, deep, whitebox
      --scanning-profile Scanning profile name or YAML path
      --only             Single phase: ingestion, discover (deparos), spidering (spitolas),
                         external-harvest, spa, sast, dynamic-assessment (audit)

Performance:
  -c, --concurrency      Concurrent workers (default: 50)
  -r, --rate-limit       Max requests/sec (default: 0 = unlimited)
      --max-per-host     Per-host concurrency cap (default: 2)
      --proxy            HTTP/SOCKS5 proxy URL
      --timeout          HTTP request timeout (default: 15s)

Output:
  -j, --json             JSON output
      --format           Output format: console, jsonl, html
  -o, --output           Output file path
      --silent           Suppress all output except findings
  -v, --verbose          Verbose logging
```

## Repository Layout

The `platform/` directory contains external tooling, UI Dashboard and is not part of the core scanner. No changes should be made to it.

## Benchmarks

Vigolium is continuously benchmarked against intentionally vulnerable applications and also heavily tested against real-world targets through bug bounty and responsible disclosure programs.

- **Self-hosted (Docker):** [DVWA](https://github.com/digininja/DVWA), [OWASP Juice Shop](https://github.com/juice-shop/juice-shop), [VAmPI](https://github.com/erev0s/VAmPI), [crAPI](https://github.com/OWASP/crAPI), [Vulnerable Java App](https://github.com/DataDog/vulnerable-java-application), [Vulnerable Nginx](https://github.com/detectify/vulnerable-nginx), [OopsSec Store](https://github.com/kOaDT/oss-oopssec-store) (custom Next.js app)
- **External (hosted):** [Acunetix TestPHP](http://testphp.vulnweb.com), [Gin & Juice Shop](https://ginandjuice.shop), [Testfire](http://demo.testfire.net)
- **XSS & multi-vuln:** [BruteLogic XSS](test/benchmark/xss_scanner/), [XBOW](test/benchmark/definitions/xbow/) (XSS, SQLi, SSTI, LFI, SSRF, XXE, command injection)

Run benchmarks with `make test-canary` (Docker apps) or `make test-integration` (XSS). See [docs/development/benchmark-testing.md](docs/development/benchmark-testing.md) for details.

## Development

```bash
make build          # build and install
make test           # run all tests (auto-installs gotestsum)
make test-unit      # fast unit tests (-short, no external deps)
make test-e2e       # E2E tests (requires Docker)
make lint           # run linter
make fmt            # format code
```

See [docs/development/building.md](docs/development/building.md) for the full build guide, [docs/development/project-structure.md](docs/development/project-structure.md) for the codebase map, and [docs/development/developing-modules.md](docs/development/developing-modules.md) for the module development guide.

## License

Vigolium is made with ♥ by [@j3ssie](https://twitter.com/j3ssie) & [@theblackturtle](https://github.com/theblackturtle).
