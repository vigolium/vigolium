# Scanning Commands Reference

Complete flag reference for `scan`, `scan-url`, `scan-request`, and `run` commands.

## Table of Contents

- [scan](#scan)
- [scan-url](#scan-url)
- [scan-request](#scan-request)
- [run](#run)
- [Strategy and Phase Interaction](#strategy-and-phase-interaction)

---

## scan

**Usage:** `vigolium scan [flags]`

Run a full vulnerability scan pipeline. Supports multiple targets, input formats, phase control, and strategy presets.

### Output flags (scan & run)

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--output` | `-o` | string | — | Write findings to specified output file |
| `--stats` | — | bool | `false` | Show live progress stats during scanning |
| `--include-response` | — | bool | `false` | Include full HTTP response body in output |
| `--omit-response` | — | bool | `false` | Omit raw request/response bytes (smaller files; drops the `.resp.*` files under `--format fs`) |
| `--fail-on` | — | string | — | Exit non-zero when a finding at/above this severity is present (`info`,`suspect`,`low`,`medium`,`high`,`critical`); output written first, `--soft-fail` overrides |
| `--split-by-host` | — | bool | `false` | Stateless multi-target (`-S -T file`): write per-host output files (`base-<host>.<ext>`); required for `-P > 1` fan-out; no-op for `--format fs` |
| `--stateless` | — | bool | `false` | Use a temporary database, export results to `--output`, then discard |
| `--upload-results` | — | bool | `false` | Upload scan results to cloud storage after completion (requires storage config) |

Stateless mode is great for ephemeral CI/CD runs — it creates a temp SQLite file, runs the full scan against it, writes the export/report to `--output`, then deletes the DB (including WAL/SHM sidecars). Requires `--output`; mutually exclusive with `--db`. Combine with `--format jsonl`, `--format html`, `--format fs`, or `--format sqlite` for shareable artifacts (`sqlite` requires `-S`).

`--format` accepts `console` (default), `jsonl`, `html`, `sqlite`, and `fs` (comma-separated for multiple):
- **`fs`** — a flat, browsable tree (`<base>-traffic/` + `<base>-findings/`) with per-host `.req` / `.resp.headers` / `.resp.body` / `.md` files and a jq-friendly `index.json`. No `-o` → `vigolium-traffic/` + `vigolium-findings/`. Works with or without `-S`. `--omit-response` drops the `.resp.*` files.
- **`sqlite`** (aliases `sqlite3`, `db`) — dumps the standalone per-run DB to `<output>.sqlite` via `VACUUM INTO`. Requires `-S/--stateless` + `-o`. Reopen with `vigolium finding/traffic -S --db <file>.sqlite`.

### Request flags (scan & run)

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--header` | `-H` | []string | — | Add custom HTTP header (repeatable, e.g. -H 'Auth: Bearer token') |
| `--advanced-options` | `-a` | map | — | Module-specific options as key=value (e.g. -a xss.dom=true) |
| `--retries` | — | int | `1` | Retry attempts for failed requests |
| `--stream` | — | bool | `false` | Process targets as a stream without buffering or deduplication |

### Input Format flags (scan & run)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--required-only` | bool | `false` | Parse only required fields from input format (ignore optional) |
| `--skip-format-validation` | bool | `false` | Skip validation of input file format |

### Other flags (scan & run)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--auth-file` | []string | — | Path to auth file (YAML/JSON, single session or `sessions:` bundle), or bare name resolved against session_dir. Repeatable. |
| `--auth` | []string | — | Inline session in `name:Header:value` format. Repeatable. |
| `--oast-url` | string | — | Fixed out-of-band callback URL (overrides auto-generated interactsh URL) |
| `--pilot` | bool | `false` | Enable AI pilot-driven crawling |

### Content Discovery flags (scan & run)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--discover` | bool | `false` | Enable content discovery phase before scanning |
| `--discover-max-time` | duration | `1h` | Max time for content discovery per target |
| `--fuzz-wordlist` | string | — | Custom fuzz wordlist path (enables fuzzing during discovery) |
| `--no-prefix-breaker` | bool | `false` | Disable per-prefix circuit breaker that stops trap-directory recursion |

### Browser Spidering flags (scan & run)

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--spider` | — | bool | `false` | Enable browser-based spidering phase before scanning |
| `--spider-max-time` | — | duration | `30m` | Max time for spidering per target |
| `--browser-engine` | `-E` | string | `chromium` | Browser engine: chromium, ungoogled, fingerprint |
| `--browsers` | `-b` | int | `1` | Number of parallel browser instances for spidering |
| `--headless` | — | bool | `true` | Run browser in headless mode |
| `--no-cdp` | — | bool | `false` | Disable Chrome DevTools Protocol event listener detection |
| `--no-forms` | — | bool | `false` | Disable automatic form detection and filling during spidering |

### External Harvest flags (scan & run)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--external-harvest` | bool | `false` | Enable external intelligence gathering phase (Wayback, CT logs, etc.) |

### KnownIssueScan flags (scan & run)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--known-issue-scan-tags` | []string | — | Nuclei template tags to include |
| `--known-issue-scan-exclude-tags` | []string | — | Nuclei template tags to exclude |
| `--known-issue-scan-severities` | []string | — | Filter Nuclei templates by severity (critical,high,medium,low,info) |
| `--known-issue-scan-templates-dir` | string | — | Custom Nuclei templates directory |

### SAST flags (scan & run)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--rule` | string | — | Filter SAST rules by fuzzy name match |
| `--sast-adhoc` | string | — | Ad-hoc SAST scan: local path or git URL (auto-detected, results not saved to database) |

### Examples

```bash
# Basic scan
vigolium scan -t https://example.com

# Multiple targets
vigolium scan -t https://example.com -t https://api.example.com

# Targets from file
vigolium scan -T targets.txt

# Deep strategy with discovery
vigolium scan -t https://example.com --strategy deep

# Phase isolation
vigolium scan -t https://example.com --only dynamic-assessment
vigolium scan -t https://example.com --only ext --ext ./custom-check.js
vigolium scan -t https://example.com --skip discovery,spidering

# Specific modules
vigolium scan -t https://example.com -m xss-reflected,sqli-error

# Custom scanning profile
vigolium scan -t https://example.com --scanning-profile aggressive

# JSONL output
vigolium scan -t https://example.com --format jsonl -o results.jsonl

# HTML report
vigolium scan -t https://example.com --format html -o report.html

# Filesystem tree (run-traffic/ + run-findings/) — browsable with ls/grep/jq
vigolium scan -t https://example.com --format fs -o run

# Standalone per-run SQLite DB (requires -S)
vigolium scan -t https://example.com -S --format sqlite -o run.sqlite

# Fail the pipeline on any high/critical finding
vigolium scan -t https://example.com --fail-on high

# With proxy
vigolium scan -t https://example.com --proxy http://127.0.0.1:8080

# Speed tuning
vigolium scan -t https://example.com -c 100 --rate-limit 200

# Whitebox scanning
vigolium scan -t https://example.com --source ./src --strategy whitebox

# Whitebox via git clone
vigolium scan -t https://example.com --source https://github.com/org/repo --strategy whitebox

# OpenAPI scan
vigolium scan -I openapi -i openapi.yaml -t https://api.example.com

# Burp import scan
vigolium scan -I burp -i burp-export.xml -t https://example.com

# Pipe from stdin
cat urls.txt | vigolium scan -i -

# Filter modules by tag
vigolium scan -t https://example.com --module-tag spring --module-tag injection

# Run extension during scan
vigolium scan -t https://example.com --ext custom-check.js

# Extensions-only scan
vigolium scan -t https://example.com --only extension --ext custom-check.js
```

---

## scan-url

**Usage:** `vigolium scan-url <url> [flags]`

Scan a single URL for vulnerabilities. Designed for quick, targeted scans and AI agent integration. Returns JSON output with findings.

### scan-url specific flags

**Spidering:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--spider` | bool | `false` | Run browser-based spidering before scanning |

**Discovery:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--discover` | bool | `false` | Run content discovery before scanning |

**Harvest:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--external-harvest` | bool | `false` | Run external intelligence harvesting before scanning |

**Request:**

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--header` | `-H` | []string | — | Custom header (repeatable) |

**Other:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--method` | string | `GET` | HTTP method |
| `--body` | string | — | Request body |
| `--known-issue-scan` | bool | `false` | Run known issue scan (Nuclei/Kingfisher) |
| `--no-passive` | bool | `false` | Skip passive modules |
| `--no-insertion-points` | bool | `false` | Skip insertion point testing |

### Examples

```bash
# Simple GET scan
vigolium scan-url https://example.com/api/users

# POST with body
vigolium scan-url https://example.com/login \
  --method POST --body '{"user":"admin","pass":"test"}' \
  -H "Content-Type: application/json"

# With discovery phase
vigolium scan-url https://example.com --discover

# Specific modules, no passive
vigolium scan-url https://example.com/api -m xss-reflected --no-passive
```

---

## scan-request

**Usage:** `vigolium scan-request [flags]`

Read a raw HTTP request from file or stdin and run scanner modules against it. Designed for pipeline integration and AI agent workflows.

### scan-request specific flags

**Spidering:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--spider` | bool | `false` | Run browser-based spidering before scanning |

**Discovery:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--discover` | bool | `false` | Run content discovery before scanning |

**Harvest:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--external-harvest` | bool | `false` | Run external intelligence harvesting before scanning |

**Other:**

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--input` | `-i` | string | `-` (stdin) | Input file or stdin |
| `--target` | — | string | — | Override target URL (scheme://host) |
| `--known-issue-scan` | — | bool | `false` | Run known issue scan |
| `--no-passive` | — | bool | `false` | Skip passive modules |
| `--no-insertion-points` | — | bool | `false` | Skip insertion point testing |

### Examples

```bash
# From file
vigolium scan-request -i raw-request.txt

# From stdin
echo -e "GET /api/users HTTP/1.1\r\nHost: example.com\r\n" | vigolium scan-request

# With target override
vigolium scan-request -i request.txt --target https://staging.example.com

# With discovery
vigolium scan-request -i request.txt --discover
```

---

## run

**Usage:** `vigolium run <phase> [flags]`

**Aliases:** `r`

Run a single scan phase directly. Equivalent to `vigolium scan --only <phase>`.

### Valid phases

| Phase | Aliases |
|-------|---------|
| `ingestion` | — |
| `discovery` | `deparos`, `discover` |
| `external-harvest` | — |
| `known-issue-scan` | — |
| `spidering` | `spitolas` |
| `sast` | — |
| `dynamic-assessment` | `audit`, `dast`, `assessment` |
| `extension` | `ext` |

The `run` command accepts the same flag groups as `scan`: Spidering, Discovery, Harvest, KnownIssueScan, SAST, Input Format, Request, Output, and Other (--oast-url, --pilot).

### Examples

```bash
vigolium run discover -t https://example.com
vigolium run spidering -t https://example.com
vigolium run audit -t https://example.com
vigolium run audit -t https://example.com --module-tag spring
vigolium run external-harvest -t https://example.com
vigolium run known-issue-scan -t https://example.com
vigolium run known-issue-scan -t https://example.com --known-issue-scan-tags cve --known-issue-scan-severities critical,high
vigolium run sast --sast-adhoc /path/to/app
vigolium run sast --sast-adhoc /path/to/app --rule gin
vigolium run extension -t https://example.com --ext custom-check.js
vigolium run ext -t https://example.com --ext ./my-scanner.js
vigolium run deparos -t https://example.com
vigolium run audit -t https://example.com
```

---

## Strategy and Phase Interaction

### Precedence

1. `--only <phase>` overrides everything — only that phase runs, heuristics disabled
2. `--skip <phase>` disables specific phases while keeping all others
3. `--strategy <name>` sets baseline phase configuration
4. Individual phase flags (`--discover`, `--spider`, etc.) override strategy settings
5. Config file `scanning_strategy.default_strategy` provides the lowest-precedence default

### Heuristics

- Default: `--heuristics-check basic`
- Levels: `none`, `basic`, `advanced`
- `basic` probes target root pages to detect content type (HTML / JSON / blank) and skips spidering for non-HTML targets
- `advanced` adds deep HTML analysis to detect SPA frameworks and optimize phase selection
- `none` runs all enabled phases unconditionally
- `--skip-heuristics` is shorthand for `--heuristics-check=none`
- `--only` automatically disables heuristics
- Precedence: `--skip-heuristics` > `--heuristics-check` > config > `basic`

### Intensity Presets

`--intensity quick|balanced|deep` is a cross-cutting preset that maps to a scanning profile + strategy. It is also honored by `agent autopilot` and `agent swarm` with backend-specific defaults. Explicit flags always override the preset — e.g. `--intensity deep --scanning-profile foo` applies `deep`'s strategy but your custom profile.

### Scanning Pace

Speed settings have a layered precedence:

1. CLI flags (`-c`, `--rate-limit`, `--max-per-host`) — highest
2. `--scanning-max-duration` — overrides `scanning_pace.max_duration`
3. Config `scanning_pace` section — per-phase max_duration and duration_factor
4. Built-in defaults — lowest

### CI Output

- `--ci-output-format` enables CI-friendly output: JSONL findings only, no color, no banners
- Equivalent to combining `--format jsonl --silent`
- Useful for CI/CD pipelines that parse JSON output

### Valid `--only` Phases

The following phases can be used with `--only` and `--skip`:

`ingestion`, `discovery`, `external-harvest`, `known-issue-scan`, `spidering`, `sast`, `audit`, `extension`

### HTML Format Constraints

- `--format html` requires `-o/--output`
- In `scan` mode with `--only`, HTML is only supported for `discovery` and `spidering` phases
- The `export` command supports HTML for all data

### Filesystem & SQLite Format Constraints

- `--format fs` writes two sibling dirs off the `-o` base (`<base>-traffic/` + `<base>-findings/`); with no `-o` it defaults to `vigolium-traffic/` + `vigolium-findings/` in the cwd. Available on `scan` / `scan-url` / `scan-request` / `run`, `export`, and `db export`. `--split-by-host` is a no-op (fs already splits per host). For `scan-url` / `scan-request`, pass `-o`, `-S`, or a phase flag so the request routes through the runner that writes the tree
- `--format sqlite` requires `-S/--stateless` **and** `-o/--output`; aliases `sqlite3` / `db`. Under `--split-by-host` each file is `<base>-<host>.sqlite`. Reopen with `vigolium finding/traffic -S --db <file>.sqlite`

### Exit-Code Gating

- `--fail-on <sev>` (`scan` / `run` / `scan-url` / `scan-request`) makes the command exit non-zero when a finding at/above `<sev>` was produced. Accepted (ascending): `info`, `suspect`, `low`, `medium`, `high`, `critical`
- Output is always written first; the gate fires afterward
- `--soft-fail` (global) forces exit 0 even when the gate (or any other error) trips
- Under `-P` / `--split-by-host` the gate is evaluated per child; the parent batch exits non-zero only when every target fails

### SAST Constraints

- `--sast-adhoc` accepts either a local path or a git URL (auto-detected)
- Git URLs are cloned to a temp directory automatically
