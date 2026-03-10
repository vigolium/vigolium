# Running a Scan

This guide has been reorganized into the `running-scan/` folder for better navigation.

## Guides

- **[Scanning Modes Overview](running-scan/scanning-modes-overview.md)** — Strategies, phase pipeline, `--only`/`--skip`, scanning profiles
- **[Blackbox Scanning](running-scan/blackbox-scan.md)** — Dynamic scanning without source code: input formats, phases, performance tuning, OAST, mutation strategy, output formats, lightweight commands (`scan-url`, `scan-request`)
- **[Whitebox Scanning](running-scan/whitebox-scan.md)** — SAST with source code: framework detection, ast-grep rules, `--source`, `--repo`, third-party tools
- **[Whitebox + Agent Scanning](running-scan/whitebox-agent-scan.md)** — AI-enhanced analysis: prompt templates, autopilot, pipeline, context enrichment
- **[Full Combined Scan](running-scan/full-scan.md)** — SAST + agent + dynamic for maximum coverage, CI/CD integration

## Related Docs

- [Server Mode & Ingestion](server-and-ingestion.md) — REST API server, data ingestion, transparent proxy
- [Agent Mode (REST API)](agent-mode.md) — Agent REST API endpoints, streaming, OpenAI-compatible interface
