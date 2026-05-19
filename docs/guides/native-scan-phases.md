# Native Scan: Running Phases Independently

## Overview

Vigolium's native scan pipeline consists of multiple phases that run sequentially. You can run the full pipeline, isolate a single phase with `--only`, or skip specific phases with `--skip`. This guide walks through each phase and how to run them independently.

## The Full Pipeline

When you run a standard scan, phases execute in this order:

1. **External Harvest** - gather endpoints from external sources (Wayback Machine, CT logs)
2. **Spidering** - browser-based crawling to discover dynamic content
3. **Discovery** - content discovery via wordlists and fuzzing
4. **Known Issue Scan** - template-based scanning with Nuclei/Kingfisher
5. **DynamicAssessment** - active and passive vulnerability scanning modules

A full scan with all phases enabled:

```bash
vigolium scan -t https://example.com --discover --spider --external-harvest --known-issue-scan
```

## Running a Single Phase

Use `vigolium run <phase>` or `vigolium scan --only <phase>` to execute one phase in isolation.

### Discovery

Discovers new endpoints through wordlist-based fuzzing and content probing:

```bash
vigolium run discovery -t https://example.com
```

Equivalent to:

```bash
vigolium scan -t https://example.com --only discovery
```

Tune discovery with additional flags:

```bash
vigolium run discovery -t https://example.com \
  --discover-max-time 30m \
  -c 100 \
  --rate-limit 200
```

### Spidering

Crawls the target using a headless browser to discover pages, forms, and JavaScript-rendered content:

```bash
vigolium run spidering -t https://example.com
```

Control the browser engine and parallelism:

```bash
vigolium run spidering -t https://example.com \
  -E chromium \
  -b 3 \
  --spider-max-time 20m \
  --no-forms
```

The alias `spitolas` also works:

```bash
vigolium run spitolas -t https://example.com
```

### External Harvest

Pulls endpoints from external intelligence sources (Wayback Machine, certificate transparency logs):

```bash
vigolium run external-harvest -t https://example.com
```

### Known Issue Scan

Runs template-based scanning (Nuclei templates) against ingested endpoints:

```bash
vigolium run known-issue-scan -t https://example.com
```

Filter templates by severity or tags:

```bash
vigolium run known-issue-scan -t https://example.com \
  --known-issue-scan-severities critical,high \
  --known-issue-scan-tags cve,rce
```

### DynamicAssessment

Runs active and passive vulnerability scanning modules. This is the core scanning phase. CLI aliases: `audit`, `dast`, `assessment`.

```bash
vigolium run dynamic-assessment -t https://example.com
```

Select specific modules or tags:

```bash
vigolium run dynamic-assessment -t https://example.com -m xss -m sqli
vigolium run dast -t https://example.com --module-tag injection
```

### Extension

Runs only custom JavaScript or YAML extensions:

```bash
vigolium run extension -t https://example.com --ext ./my-checks.js
```

## Skipping Phases

Use `--skip` to disable specific phases while keeping the rest of the pipeline:

```bash
# Run everything except spidering
vigolium scan -t https://example.com --discover --skip spidering

# Skip both spidering and known-issue-scan
vigolium scan -t https://example.com --discover --skip spidering --skip known-issue-scan
```

Note: `--only` and `--skip` cannot be used together.

## Phase Aliases

Several phases accept shorthand aliases:

| Alias | Phase |
|-------|-------|
| `deparos`, `discover` | `discovery` |
| `spitolas` | `spidering` |
| `ext` | `extension` |
| `audit`, `dast`, `assessment` | `dynamic-assessment` |

## Chaining Phases Manually

You can chain independent phase runs to build a custom pipeline. Each phase stores its results in the database, so subsequent phases pick up where the previous one left off:

```bash
# Step 1: Discover endpoints
vigolium run discovery -t https://example.com

# Step 2: Dynamic-assessment against the discovered endpoints
vigolium run dynamic-assessment -t https://example.com

# Step 3: Run custom extensions against results
vigolium run extension -t https://example.com --ext ./custom-check.js
```

## Tuning Per-Phase Performance

Override concurrency and rate limits for individual phases using the config file (`vigolium-configs.yaml`):

```yaml
scanning_pace:
  concurrency: 50
  rate_limit: 100

  discovery:
    concurrency: 100
    duration_factor: 1.0

  spidering:
    max_duration: 20m

  dynamic-assessment:
    parallel_passive: true
```

CLI flags (`-c`, `--rate-limit`) always take precedence over config values.

## Controlling Scope

Scope filtering applies across all phases. Use `--scope-origin` to control host matching:

```bash
# Strict: exact host match only
vigolium run discovery -t https://api.example.com --scope-origin strict

# Balanced: same eTLD+1 (*.example.com)
vigolium run discovery -t https://api.example.com --scope-origin balanced

# Relaxed (default): host contains target keyword
vigolium run discovery -t https://api.example.com --scope-origin relaxed
```

## Adding Authentication

All phases respect authentication headers. Pass them with `-H`:

```bash
vigolium run dynamic-assessment -t https://api.example.com \
  -H 'Authorization: Bearer eyJhbGciOi...' \
  -H 'Cookie: session=abc123'
```

For multi-session testing (e.g., IDOR detection), use session configs:

```bash
vigolium run dynamic-assessment -t https://api.example.com \
  --auth-file sessions.yaml
```
