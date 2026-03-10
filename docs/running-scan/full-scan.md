# Full Combined Scan

A full combined scan uses every capability together: static analysis (SAST), AI agent code review, and dynamic blackbox scanning. This provides maximum vulnerability coverage by combining static and dynamic techniques.

## Overview

The comprehensive approach runs in stages:

```
1. SAST route extraction     → Routes from source code saved to DB
2. Third-party SAST tools    → Semgrep + Trivy findings (SARIF)
3. AI agent code review      → Security findings + new endpoints to DB
4. Dynamic blackbox scan     → Active + passive modules against all endpoints
5. Extension modules         → Custom JS/YAML extensions for specialized checks
```

Each stage feeds the next: SAST-discovered routes become dynamic scan targets, agent-discovered endpoints expand the attack surface, and custom extensions add specialized checks.

## Quick Start

```bash
# Step 1: Whitebox scan (SAST + dynamic)
# Use --source for a local path, or --source-url for a git repo
vigolium scan -t https://api.example.com --source ./my-app --strategy whitebox

# Step 2: Agent code review
vigolium agent --prompt-template security-code-review --repo ./my-app
```

## Step-by-Step Workflow

### Step 1: SAST Route Extraction

Extract routes from source code and save them to the database. Routes become targets for dynamic scanning.

```bash
# SAST-only pass first (fast, no network traffic)
vigolium scan -t https://api.example.com --source ./my-app --only sast
```

This detects the framework automatically, runs ast-grep rules, and saves extracted routes as HTTP records. Check what was found:

```bash
# View extracted routes
vigolium db list --source ast-grep
```

### Step 2: AI Agent Code Review

Run an AI agent to find vulnerabilities that static rules miss: business logic flaws, auth issues, complex injection chains.

```bash
# Security code review
vigolium agent --prompt-template security-code-review --repo ./my-app

# Also discover endpoints the SAST rules didn't catch
vigolium agent --prompt-template endpoint-discovery --repo ./my-app

# Check for injection sinks
vigolium agent --prompt-template injection-sinks --repo ./my-app

# Review authentication
vigolium agent --prompt-template auth-bypass --repo ./my-app
```

Agent findings are ingested into the database. HTTP records from `endpoint-discovery` become additional scan targets.

### Step 3: Dynamic Blackbox Scan

Run the full dynamic scan. This uses all endpoints in the database: SAST-extracted routes, agent-discovered endpoints, and any previously crawled/discovered URLs.

```bash
# Full whitebox strategy scan
vigolium scan -t https://api.example.com --source ./my-app --strategy whitebox

# Or deep strategy for maximum coverage (adds external harvesting)
vigolium scan -t https://api.example.com --source ./my-app --strategy deep
```

The database already contains routes from Steps 1-2, so the dynamic scan benefits from the expanded attack surface.

### Step 4: Custom Extension Modules (Optional)

Run custom JS/YAML extensions for specialized checks not covered by built-in modules or AI analysis.

```bash
# Run extensions alongside the dynamic scan
vigolium scan -t https://api.example.com --strategy whitebox --ext ./custom-auth-check.js

# Or run extensions in isolation
vigolium run extension -t https://api.example.com --ext-dir ~/extensions/
```

See [Extension Scanning](extension-scan.md) for details on writing and managing extensions.

### Step 5: Generate Report

```bash
# HTML report from database
vigolium scan -t https://api.example.com --format html -o full-report.html

# Export findings
vigolium db export --format json -o findings.json
```

## Single-Command Approaches

### Whitebox Strategy (SAST + Dynamic)

The whitebox strategy runs SAST and dynamic scanning in a single command:

```bash
vigolium scan -t https://api.example.com --source ./my-app --strategy whitebox
```

This covers: SAST route extraction → content discovery → SPA → dynamic assessment. It does not include AI agent analysis.

### Combining SAST and Agent Review

For maximum coverage, run SAST first, then agent review, then the dynamic scan:

```bash
# SAST populates routes in DB
vigolium scan -t https://api.example.com --source ./my-app --only sast

# Agent code review discovers additional endpoints and findings
vigolium agent --prompt-template security-code-review --repo ./my-app

# Final dynamic scan with everything
vigolium scan -t https://api.example.com --strategy whitebox
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Security Scan
on:
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Vigolium
        run: go install github.com/vigolium/vigolium/cmd/vigolium@latest

      - name: SAST Analysis
        run: |
          vigolium scan -t ${{ vars.STAGING_URL }} \
            --source . --only sast -j -o sast-findings.jsonl

      - name: Dynamic Scan
        run: |
          vigolium scan -t ${{ vars.STAGING_URL }} \
            --strategy lite -j -o dynamic-findings.jsonl

      - name: Upload Results
        uses: actions/upload-artifact@v4
        with:
          name: security-findings
          path: "*-findings.jsonl"
```

### GitLab CI Example

```yaml
security-scan:
  stage: test
  script:
    # SAST pass
    - vigolium scan -t $STAGING_URL --source . --only sast -j -o sast.jsonl
    # Dynamic pass
    - vigolium scan -t $STAGING_URL --strategy lite -j -o dynamic.jsonl
  artifacts:
    paths:
      - "*.jsonl"
```

### Multi-Stage Pipeline

```yaml
# Stage 1: Fast SAST (runs on every PR)
sast:
  script:
    - vigolium scan -t $TARGET --source . --only sast -j

# Stage 2: Agent review (runs on PRs to main)
agent-review:
  script:
    - vigolium agent --prompt-template security-code-review --repo . -j
  rules:
    - if: $CI_MERGE_REQUEST_TARGET_BRANCH_NAME == "main"

# Stage 3: Full scan (runs on merge to main)
full-scan:
  script:
    - vigolium scan -t $STAGING_URL --source . --strategy whitebox
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
```

## Configuration for Maximum Coverage

Optimize `vigolium-configs.yaml` for comprehensive scanning:

```yaml
scanning_strategy:
  default_strategy: whitebox

source_aware:
  ast_grep:
    enabled: true
    timeout: "10m"           # Increase for large codebases
  third_party_integration:
    enabled: true
    timeout: "15m"
    tools:
      - name: semgrep
        enabled: true
        command: semgrep
        args: ["scan", "--sarif", "--quiet"]
      - name: trivy
        enabled: true
        command: trivy
        args: ["fs", "--format", "sarif", "--quiet"]

agent:
  default_agent: claude
  agents:
    claude:
      command: npx
      args: ["-y", "@zed-industries/claude-code-acp@latest"]
      protocol: acp

scanning_pace:
  concurrency: 50
  rate_limit: 100
  max_per_host: 5
  max_duration: "3h"        # Allow time for all phases
```

## Performance Considerations

### Time Budget

A full combined scan is the most thorough but slowest approach. Typical time breakdown:

| Stage | Typical Duration |
|-------|-----------------|
| SAST (ast-grep) | 30s - 5m |
| Third-party SAST (semgrep, trivy) | 1 - 10m |
| Agent code review | 2 - 10m per template |
| Dynamic scan (balanced) | 10m - 2h |

### Optimization Tips

1. **Run SAST first** — It is fast and populates routes for everything downstream
2. **Use `--only sast` for CI on every PR** — Fast feedback without network traffic
3. **Reserve agent + dynamic for merge-to-main** — More thorough but slower
4. **Time-box dynamic scanning** — Use `--scanning-max-duration` and per-phase max times
5. **Use `--strategy lite` for quick dynamic checks** — Skip discovery/spidering

### Resource Usage

- SAST: CPU-intensive (ast-grep), minimal network
- Agent: API calls to AI provider, depends on model and context size
- Dynamic: Network-intensive, respects `--concurrency` and `--rate-limit`

## Example: Complete Workflow for a Go/Gin API

```bash
# 1. Link source code
vigolium scan -t https://api.example.com --source ./backend --only sast

# 2. Check extracted routes
vigolium db list --source ast-grep

# 3. Run agent security review
vigolium agent --prompt-template security-code-review --repo ./backend

# 4. Generate test inputs from agent
vigolium agent --prompt-template api-input-gen --repo ./backend

# 5. Full dynamic scan with all discovered endpoints + extensions
vigolium scan -t https://api.example.com --strategy whitebox \
  --ext ~/extensions/custom-auth-check.js \
  --scanning-max-duration 2h

# 6. Generate HTML report
vigolium scan -t https://api.example.com --format html -o full-report.html
```

## Example: Complete Workflow for a Next.js App

```bash
# 1. SAST scan for route extraction + Next.js security rules
vigolium scan -t https://app.example.com --source ./frontend --only sast

# 2. Next.js-specific agent audit
vigolium agent --prompt-template nextjs-security-audit --repo ./frontend

# 3. React XSS analysis
vigolium agent --prompt-template react-xss-audit --repo ./frontend

# 4. Attack surface mapping
vigolium agent --prompt-template attack-surface-mapper --repo ./frontend

# 5. Dynamic scan
vigolium scan -t https://app.example.com --strategy whitebox

# 6. Report
vigolium scan -t https://app.example.com --format html -o nextjs-report.html
```
