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

### scan-specific flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--output` | `-o` | string | — | Write findings to specified output file |
| `--stats` | — | bool | `false` | Show live progress stats during scanning |
| `--include-response` | — | bool | `false` | Include full HTTP response body in output |
| `--retries` | — | int | `1` | Retry attempts for failed requests |
| `--stream` | — | bool | `false` | Process targets as a stream without buffering or deduplication |
| `--header` | `-H` | []string | — | Add custom HTTP header (repeatable, e.g. -H 'Auth: Bearer token') |
| `--advanced-options` | `-a` | map | — | Module-specific options as key=value (e.g. -a xss.dom=true) |
| `--required-only` | — | bool | `false` | Parse only required fields from input format (ignore optional) |
| `--skip-format-validation` | — | bool | `false` | Skip validation of input file format |
| `--source-url` | — | string | — | Git URL to clone for source-aware scanning |
| `--module-tag` | — | []string | — | Filter modules by tag (OR condition, repeatable) |

### Content Discovery flags (scan & run)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--discover` | bool | `false` | Enable content discovery phase before scanning |
| `--discover-max-time` | duration | `1h` | Max time for content discovery per target |

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

### SPA flags (scan & run)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--spa-tags` | []string | — | Nuclei template tags to include |
| `--spa-exclude-tags` | []string | — | Nuclei template tags to exclude |
| `--spa-severities` | []string | — | Filter by severity (critical,high,medium,low,info) |
| `--spa-templates-dir` | string | — | Custom Nuclei templates directory |

### SAST flags (scan & run)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--rule` | string | — | Filter SAST rules by fuzzy name match |
| `--repo` | string | — | Local repo path for ad-hoc SAST scan (results not saved to database) |

### OAST flags (scan & run)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--oast-url` | string | — | Fixed out-of-band callback URL (overrides auto-generated interactsh URL) |

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

# With proxy
vigolium scan -t https://example.com --proxy http://127.0.0.1:8080

# Speed tuning
vigolium scan -t https://example.com -c 100 --rate-limit 200

# Whitebox scanning
vigolium scan -t https://example.com --source ./src --strategy whitebox

# Whitebox via git clone
vigolium scan -t https://example.com --source-url https://github.com/org/repo --strategy whitebox

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

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--method` | — | string | `GET` | HTTP method |
| `--body` | — | string | — | Request body |
| `--header` | `-H` | []string | — | Custom header (repeatable) |
| `--no-passive` | — | bool | `false` | Skip passive modules |
| `--no-insertion-points` | — | bool | `false` | Skip insertion point testing |

### Phase flags (shared with scan-request)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--discover` | bool | `false` | Run content discovery before scanning |
| `--spider` | bool | `false` | Run browser-based spidering |
| `--external-harvest` | bool | `false` | Run external intelligence harvesting |
| `--spa` | bool | `false` | Run security posture assessment |

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

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--input` | `-i` | string | `-` (stdin) | Input file or stdin |
| `--target` | — | string | — | Override target URL (scheme://host) |
| `--no-passive` | — | bool | `false` | Skip passive modules |
| `--no-insertion-points` | — | bool | `false` | Skip insertion point testing |

Also accepts the same phase flags as scan-url (--discover, --spider, --external-harvest, --spa).

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
| `spidering` | `spitolas` |
| `spa` | — |
| `sast` | — |
| `dynamic-assessment` | `audit` |
| `extension` | `ext` |

The `run` command accepts the same flags as `scan` (output, discovery, spidering, SPA, SAST, OAST flags).

### Examples

```bash
vigolium run discover -t https://example.com
vigolium run spidering -t https://example.com
vigolium run dynamic-assessment -t https://example.com
vigolium run dynamic-assessment -t https://example.com --module-tag spring
vigolium run external-harvest -t https://example.com
vigolium run spa -t https://example.com
vigolium run spa -t https://example.com --spa-tags cve --spa-severities critical,high
vigolium run sast --repo /path/to/app
vigolium run sast --repo /path/to/app --rule gin
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
- `--skip-heuristics` is shorthand for `--heuristics-check=none`
- `--only` automatically disables heuristics
- Precedence: `--skip-heuristics` > `--heuristics-check` > config > `basic`

### Scanning Pace

Speed settings have a layered precedence:

1. CLI flags (`-c`, `--rate-limit`, `--max-per-host`) — highest
2. `--scanning-max-duration` — overrides `scanning_pace.max_duration`
3. Config `scanning_pace` section — per-phase max_duration and duration_factor
4. Built-in defaults — lowest

### HTML Format Constraints

- `--format html` requires `-o/--output`
- In `scan` mode with `--only`, HTML is only supported for `discovery` and `spidering` phases
- The `export` command supports HTML for all data
