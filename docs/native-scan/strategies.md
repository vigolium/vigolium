# Blackbox Scanning

Blackbox scanning tests a web application from the outside without access to source code. Vigolium sends crafted HTTP requests and analyzes responses to find vulnerabilities.

## Quick Start

```bash
# Scan a single URL
vigolium scan -t https://example.com

# Scan multiple targets
vigolium scan -t https://api.example.com -t https://admin.example.com

# Scan targets from a file
vigolium scan -T targets.txt
```

## Strategies

Use `--strategy` to control how much reconnaissance Vigolium performs before dynamic testing.

### Lite — Fast, Minimal Discovery

Runs only the dynamic-assessment phase against the provided targets. No crawling, no content discovery.

```bash
vigolium scan -t https://example.com --strategy lite
```

Best for: quick checks, CI pipelines, known endpoints.

### Balanced — Default

Runs content discovery, browser spidering, known-issue-scan analysis, and dynamic-assessment.

```bash
vigolium scan -t https://example.com
# Equivalent to:
vigolium scan -t https://example.com --strategy balanced
```

Best for: general-purpose scanning with good coverage.

### Deep — Maximum Recon

Adds external intelligence harvesting (Wayback Machine, CommonCrawl, etc.) on top of balanced.

```bash
vigolium scan -t https://example.com --strategy deep
```

Best for: thorough assessments where you want to discover forgotten endpoints and historical paths.

## Phase-by-Phase Walkthrough

### Input Formats

Vigolium accepts targets in multiple formats via `-I` / `--input-mode`:

| Format | Flag | Example |
|--------|------|---------|
| URL list (default) | `-I urls` | `vigolium scan -T urls.txt` |
| OpenAPI / Swagger | `-I openapi` | `vigolium scan -i api-spec.yaml -I openapi` |
| Postman Collection | `-I postman` | `vigolium scan -i collection.json -I postman` |
| Burp XML export | `-I burpxml` | `vigolium scan -i burp-export.xml -I burpxml` |
| Raw HTTP request | `-I burpraw` | `vigolium scan -i request.txt -I burpraw` |
| cURL commands | `-I curl` | `vigolium scan -i curls.sh -I curl` |
| HAR file | `-I har` | `vigolium scan -i traffic.har -I har` |
| Nuclei output | `-I nuclei` | `vigolium scan -i nuclei.json -I nuclei` |

```bash
# Scan an OpenAPI spec (auto-uses server URLs from the spec)
vigolium scan -i openapi.yaml -I openapi

# Scan an OpenAPI spec against a specific target
vigolium scan -i openapi.yaml -I openapi -t https://staging.example.com

# Scan a Burp Suite export
vigolium scan -i burp-session.xml -I burpxml

# Pipe curl commands
cat curls.sh | vigolium scan -I curl

# OpenAPI with custom headers and parameter values
vigolium scan -i api.yaml -I openapi \
  --spec-header "Authorization: Bearer token123" \
  --spec-var "user_id=42"
```

### External Harvesting

Queries external data sources for historical URLs and endpoints. Enabled by `--strategy deep` or `--external-harvest`.

```bash
# Enable explicitly
vigolium scan -t https://example.com --external-harvest

# Or via deep strategy
vigolium scan -t https://example.com --strategy deep
```

Sources: Wayback Machine, CommonCrawl, AlienVault OTX, URLScan, VirusTotal. API keys for URLScan and VirusTotal can be configured in `vigolium-configs.yaml` under `external_harvester.sources`.

### Content Discovery

Brute-force directory and file discovery using the deparos engine. Enabled by `--strategy balanced`/`deep` or `--discover`.

```bash
# Run discovery with a time limit
vigolium scan -t https://example.com --discover --discover-max-time 30m

# Run only discovery phase
vigolium scan -t https://example.com --only discovery
```

The discovery engine uses recursive brute-forcing (default depth 5), observed filename variants, JS analysis, and case-sensitivity auto-detection.

### Browser Spidering

Chromium-based crawling that handles SPAs, JavaScript rendering, and form interactions. Enabled by `--strategy balanced`/`deep` or `--spider`.

```bash
# Spider with time limit
vigolium scan -t https://example.com --spider --spider-max-time 15m

# Multiple browser instances for faster crawling
vigolium scan -t https://example.com --spider -b 3

# Non-headless (visible browser)
vigolium scan -t https://example.com --spider --headless=false

# Disable form filling
vigolium scan -t https://example.com --spider --no-forms
```

Spider flags:
- `-b` / `--browsers` — number of browser instances (default: 1)
- `-E` / `--browser-engine` — `chromium`, `ungoogled`, or `fingerprint` (default: `chromium`)
- `--headless` — headless mode (default: true)
- `--no-cdp` — disable CDP event listener detection
- `--no-forms` — disable automatic form filling
- `--spider-max-time` — max duration (default: 30m)

### Known Issue Scan

Runs Nuclei templates and Kingfisher secret scanning against discovered hosts and response bodies. Enabled by `--strategy balanced`/`deep` or by the strategy.

By default, known-issue-scan enriches its target list with path prefixes discovered in previous phases (discovery, spidering). This increases coverage — Nuclei templates run against individual path prefixes (e.g., `https://example.com/api/v1/`) rather than just the host root. Disable this for faster but less granular scans:

```yaml
# vigolium-configs.yaml
known_issue_scan:
  enrich_targets: true    # default: true (use discovered paths as targets)
                          # false: use host-level URLs only (faster)
```

```bash
# Filter Nuclei templates by tag
vigolium scan -t https://example.com --known-issue-scan-tags cve,misconfig

# Filter by severity
vigolium scan -t https://example.com --known-issue-scan-severities critical,high

# Custom templates directory
vigolium scan -t https://example.com --known-issue-scan-templates-dir ~/nuclei-templates/
```

### DynamicAssessment

The core scanning phase. Runs active and passive modules against all discovered HTTP records. Enabled in all strategies. CLI aliases: `audit`, `dast`, `assessment`.

Uses a feedback loop (up to 3 rounds): after each round, checks for newly discovered records and rescans if found.

OAST (Out-of-band Application Security Testing) injects blind callback payloads when configured:

```bash
# With a fixed OAST URL
vigolium scan -t https://example.com --oast-url https://your-oast.example.com/callback
```

## Performance Tuning

### CLI Speed Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-c` / `--concurrency` | 50 | Number of concurrent scan workers |
| `--max-per-host` | 2 | Max concurrent requests per host |
| `-r` / `--rate-limit` | 100 | Max request submissions per second |
| `--max-host-error` | 30 | Skip host after N consecutive errors |
| `--max-findings-per-module` | 15 | Suppress findings after this many per module (0 = unlimited) |
| `--timeout` | 15s | Per-request HTTP timeout |
| `--retries` | 1 | Retry count for failed requests |
| `--scanning-max-duration` | unset | Override global max scan duration |
| `--discover-max-time` | 1h | Max duration for content discovery |
| `--spider-max-time` | 30m | Max duration for spidering |

```bash
# Fast scan with high concurrency
vigolium scan -t https://example.com -c 100 -r 200 --max-per-host 5

# Gentle scan with low rate
vigolium scan -t https://example.com -c 10 -r 20 --max-per-host 1

# Time-boxed deep scan
vigolium scan -t https://example.com --strategy deep \
  --scanning-max-duration 1h \
  --discover-max-time 20m \
  --spider-max-time 10m
```

### Scanning Pace (Config File)

The `scanning_pace` section in `vigolium-configs.yaml` provides centralized speed control. Common values serve as a baseline inherited by all phases; per-phase subsections override specific values.

```yaml
scanning_pace:
  # Common defaults (inherited by all phases)
  concurrency: 50
  rate_limit: 100
  max_per_host: 10

  # Per-phase overrides (0 = inherit from common)
  discovery:
    concurrency: 30
    max_duration: 1h

  known_issue_scan:
    concurrency: 50
    rate_limit: 100
    max_duration: 30m

  external_harvester:
    max_duration: 5m

  dynamic-assessment:
    concurrency: 50
```

Precedence (highest to lowest): CLI flags > scanning profile > per-phase overrides > common values > built-in defaults.

## Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| Console | `--format console` (default) | Colored human-readable table output |
| JSONL | `--format jsonl` or `--json` / `-j` | One JSON object per finding per line |
| HTML | `--format html -o report.html` | Interactive ag-grid HTML report |

```bash
# JSON output
vigolium scan -t https://example.com --json

# HTML report
vigolium scan -t https://example.com --format html -o scan-report.html

# JSON to file
vigolium scan -t https://example.com -j -o findings.jsonl
```

## Lightweight Scan Commands

For quick, targeted scans of individual URLs or raw requests.

### `scan-url` — Single URL

```bash
# Basic GET scan
vigolium scan-url https://example.com/api/users

# POST with body and headers
vigolium scan-url https://example.com/api/login \
  --method POST \
  --body '{"username":"admin","password":"test"}' \
  -H "Content-Type: application/json"

# Skip passive modules
vigolium scan-url https://example.com/api/data --no-passive

# JSON output
vigolium scan-url https://example.com/api/users --json

# With content discovery
vigolium scan-url https://example.com --discover
```

### `scan-request` — Raw HTTP Request

```bash
# From stdin
echo -e "GET /api/users HTTP/1.1\r\nHost: example.com\r\n" | vigolium scan-request

# From file
vigolium scan-request -i request.txt

# With target override
vigolium scan-request -i request.txt --target https://staging.example.com
```

When phase flags (`--discover`, `--spider`, `--external-harvest`, `--known-issue-scan`) are used with these commands, they delegate to the full Runner pipeline (database required).

## Module Selection

```bash
# List all available modules
vigolium scan -t https://example.com --list-modules
# Or:
vigolium module ls

# Run specific modules only
vigolium scan -t https://example.com -m xss-reflected,sqli-error

# Run a single module
vigolium scan-url https://example.com/search?q=test -m xss-reflected
```

### Filtering by Tag

Modules are tagged with classification labels (e.g., `spring`, `rails`, `django`, `xss`, `injection`, `light`). Use `--module-tag` to run only modules matching specific tags:

```bash
# Run all Spring-related modules
vigolium scan -t https://example.com --module-tag spring

# Run all Rails and Django modules
vigolium scan -t https://example.com --module-tag rails --module-tag django

# Combine with -m (results are merged as a union)
vigolium scan -t https://example.com -m xss-reflected --module-tag spring
```

Tags are matched with OR logic — a module runs if it matches *any* of the specified tags. When both `-m` and `--module-tag` are provided, the results are merged (union).

## Custom Extensions

Load JavaScript or YAML extension modules alongside or instead of built-in modules. See [Extension Scanning](extension-scan.md) for full details.

```bash
# Add extensions on top of built-in modules
vigolium scan -t https://example.com --ext ./my-scanner.js

# Load extensions from a directory
vigolium scan -t https://example.com --ext-dir ~/my-extensions/

# Run ONLY extension modules (skip built-in modules)
vigolium run extension -t https://example.com --ext ./my-scanner.js

# List loaded extensions
vigolium ext ls
```

## Heuristics

Pre-flight checks detect WAFs, redirects, and technology before scanning. Controlled via `--heuristics-check`:

```bash
# Skip heuristics for faster start
vigolium scan -t https://example.com --skip-heuristics

# Advanced heuristics
vigolium scan -t https://example.com --heuristics-check advanced
```

Heuristics are automatically disabled when `--only` is used.

## OAST (Out-of-Band Testing)

OAST detects blind vulnerabilities where the application triggers an out-of-band callback (DNS/HTTP) instead of reflecting payloads in the response. Vigolium uses an [interactsh](https://github.com/projectdiscovery/interactsh) server for callback tracking.

OAST is **enabled by default**. The OAST probe module injects callback URLs into insertion points and monitors for interactions during and after the scan.

```bash
# Use a fixed OAST callback URL (bypasses interactsh auto-generation)
vigolium scan -t https://example.com --oast-url https://your-oast.example.com/callback
```

Configuration in `vigolium-configs.yaml`:

```yaml
oast:
  enabled: true                     # Enable/disable OAST (default: true)
  server_url: "oast.pro"            # Interactsh server URL
  token: ""                         # Auth token for private interactsh servers
  poll_interval: 5                  # Seconds between interaction polls
  grace_period: 10                  # Seconds to wait after scan for late callbacks

  oast_url: ""                      # Fixed callback URL (bypasses interactsh)

  enabled_blind_xss: false          # Enable blind XSS payload injection
  blind_xss_src: ""                 # JavaScript src URL for blind XSS payloads
```

## Mutation Strategy

The mutation strategy controls how Vigolium generates payloads for parameter fuzzing. Value-aware mutation analyzes the original parameter value, classifies it by semantic type, and generates type-appropriate mutations.

```yaml
mutation_strategy:
  default_modes:
    - append                        # How payloads are applied: "append", "replace", "insert"

  value_aware:
    enabled: true                   # Enable value-aware mutation (default: true)
    max_per_intent: 5               # Max mutations per intent per parameter
    default_intents:
      - neighbor                    # Similar values (e.g., id=5 → id=4, id=6)
      - boundary                    # Edge cases (e.g., 0, -1, MAX_INT, empty)
      - escalation                  # Privilege escalation (e.g., role=user → role=admin)

    enum_mappings:                  # Custom enum escalation mappings
      role: ["admin", "superadmin", "root"]
      status: ["active", "approved", "verified"]

    param_synonyms:                 # Custom parameter name synonyms
      user_id: ["uid", "userId", "account_id"]
```

Recognized value types include: integer, UUID, email, JWT, boolean, path, sequential ID, and 15+ others. Each type has specialized neighbor, boundary, and escalation mutations.

## Project Scoping

Use `--project-id` (with a UUID) or `--project-name` (with a name) to scope all scan data to a specific project for multi-tenant isolation:

```bash
# Scan within a project
vigolium scan -t https://example.com --project-id a1b2c3d4-...

# Or set the environment variable for your session
eval $(vigolium project use a1b2c3d4-...)
vigolium scan -t https://example.com
```

See [Projects](../projects.md) for the full multi-tenancy reference.

## Common Scenarios

```bash
# API scan from OpenAPI spec
vigolium scan -i api-spec.yaml -I openapi \
  --spec-header "Authorization: Bearer $TOKEN"

# Full deep scan with HTML report
vigolium scan -t https://example.com --strategy deep \
  --format html -o report.html

# Quick CI check with JSON output
vigolium scan -t https://staging.example.com --strategy lite -j

# Rescan existing database records
vigolium scan

# Scan with proxy (Burp, ZAP)
vigolium scan -t https://example.com --proxy http://127.0.0.1:8080

# Scan with custom scan ID for grouping
vigolium scan -t https://example.com --scan-id "sprint-42"

# Verbose output with traffic dump
vigolium scan -t https://example.com -v --dump-traffic

# Scan only Spring-related modules within a project
vigolium scan -t https://example.com --module-tag spring --project-id a1b2c3d4-...
```
