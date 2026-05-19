# Quick Start

This page gets you from a fresh install to your first findings in a few
minutes. If you haven't installed Vigolium yet, see
[Installation](installation.md).

## 0. Verify your setup

```bash
vigolium version
vigolium doctor
```

`doctor` reports any missing optional dependencies (e.g. a browser for SPA
spidering) and confirms your config is valid.

## 1. Scan a single URL

The fastest way to check one endpoint. No database, no setup — just direct
active + passive module execution:

```bash
vigolium scan-url https://example.com
```

Target a specific parameter:

```bash
vigolium scan-url "https://example.com/search?q=test"
```

## 2. Run a full scan

`vigolium scan` runs the full multi-phase pipeline (discovery → spidering →
dynamic-assessment) using the **balanced** strategy by default:

```bash
vigolium scan -t https://example.com
```

Tune the depth/speed trade-off with a strategy preset:

```bash
vigolium scan -t https://example.com --strategy lite   # fast, dynamic-assessment only
vigolium scan -t https://example.com --strategy balanced
vigolium scan -t https://example.com --strategy deep   # thorough, more modules
```

`--intensity quick|balanced|deep` is a higher-level alias that also tunes the
scanning profile.

## 3. Choose what to scan

```bash
# A file of targets, one URL per line
vigolium scan -T targets.txt

# From an OpenAPI / Swagger spec
vigolium scan -i api.yaml -I openapi -t https://api.example.com

# Pipe URLs from stdin
cat urls.txt | vigolium scan

# A raw HTTP request or curl command (auto-detected)
echo "curl -X POST -d 'user=admin' https://example.com/login" | vigolium scan-request
```

Supported input modes (`-I`): `urls`, `openapi`, `swagger`, `postman`,
`curl`, `burpxml`, `nuclei`, `har`.

## 4. Pick specific modules (optional)

```bash
# Only run XSS and SQLi modules (fuzzy match on module ID/name)
vigolium scan -t https://example.com -m xss -m sqli

# Filter by tag instead
vigolium scan -t https://example.com --module-tag injection

# List everything available
vigolium -M
```

## 5. Get results out

By default findings stream to the console. For files or machine-readable
output, use `--format` with `-o`:

```bash
# JSONL for scripting / CI
vigolium scan -t https://example.com --format jsonl -o results

# Self-contained HTML report
vigolium scan -t https://example.com --format html -o report

# Several formats at once
vigolium scan -t https://example.com --format jsonl,html -o scan
```

| Flag | Effect |
|------|--------|
| `--format console` | Human-readable terminal output (default) |
| `--format jsonl` / `-j` | One JSON object per line |
| `--format html` | Interactive ag-grid report (requires `-o`) |
| `-o, --output` | Output file path (base name; extension added per format) |
| `--ci-output-format` | JSONL only, no banners or color — ideal for CI |
| `--silent` | Suppress everything except findings |

## 6. Run a single phase

Use `run <phase>` (an alias for `scan --only <phase>`) when you only want one
stage of the pipeline:

```bash
vigolium run discovery -t https://example.com    # content discovery only
vigolium run spidering -t https://example.com    # browser crawl only
vigolium run dynamic-assessment -t https://example.com
```

Phases: `ingestion`, `discovery`, `external-harvest`, `spidering`,
`known-issue-scan`, `dynamic-assessment`, `extension`.

## A note on persistence

`vigolium scan` writes results to a persistent SQLite database at
`~/.vigolium/database-vgnm.sqlite`, so you can browse them afterward:

```bash
vigolium traffic list      # ingested HTTP records
vigolium finding list      # discovered vulnerabilities
```

For one-shot runs that leave nothing behind (CI, ad-hoc checks), add
`--stateless` and export with `-o`. See
[Native Scan & Stateless Scanning](native-scan.md) for the full set of recipes.

## Next steps

- [Native Scan & Stateless Scanning](native-scan.md) — CLI scan recipes.
- [Scanning Strategies](../native-scan/strategies.md) — strategies, profiles, pace.
- [Scanning Modes Overview](../native-scan/scanning-modes-overview.md) — compare all modes.
- [Authenticated Scanning](../native-scan/authentication.md) — sessions and login flows.
- [Setting Up the Agent](setup-agent.md) — AI-driven autopilot and swarm scans.
- [Configuration Reference](../configuration.md) — full configuration options.
