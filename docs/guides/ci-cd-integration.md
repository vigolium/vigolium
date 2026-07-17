# CI/CD Integration

## Overview

Vigolium can be integrated into CI/CD pipelines to automatically scan applications for vulnerabilities on every deployment or pull request. This guide covers common patterns for running scans in automated environments.

## Basic CI Scan

A minimal CI scan using the `lite` strategy for speed and JSONL output for machine parsing:

```bash
vigolium scan -S -t "$TARGET_URL" --strategy lite \
  --format jsonl -o results.jsonl --fail-on high
```

The `lite` strategy skips browser spidering and heavy discovery, making it suitable for time-constrained CI environments. JSONL output produces one JSON object per line, which is straightforward to parse in scripts.

## Exit Codes

Use `--fail-on info|low|medium|high|critical` to make `scan`, `scan-url`,
`scan-request`, or `run` exit non-zero when this run finds an issue at or above
the threshold. Output is written before the gate is evaluated. Global
`--soft-fail` forces exit zero while retaining the error on stderr.

## JSONL Output for Parsing

Use `jq` to filter findings by severity:

```bash
# Fail the build only on high/critical findings
HIGH_COUNT=$(jq -s '[.[] | select(.type == "finding") | .data |
  select(.severity == "high" or .severity == "critical")] | length' results.jsonl)

if [ "$HIGH_COUNT" -gt 0 ]; then
  echo "Found $HIGH_COUNT high/critical severity findings"
  jq 'select(.type == "finding") | .data |
      select(.severity == "high" or .severity == "critical")' results.jsonl
  exit 1
fi
```

Extract a summary of findings:

```bash
jq 'select(.type == "finding") | .data |
    {name: .name, severity: .severity, url: .url}' results.jsonl
```

## With Source Code (Agent Modes)

When the source code is available in the CI workspace, agent modes can use it for richer analysis. Both `swarm` and `autopilot` accept `--source .` and will route source-derived endpoints into the dynamic scanner. For pure code review without dynamic scanning, use `agent query` or `agent audit`:

```bash
# Swarm: AI plans modules, optionally runs source analysis + native scan
vigolium agent swarm -t "$TARGET_URL" --source . --json > agent-summary.json

# Multi-phase AI source-code audit (no live target needed)
vigolium agent audit --source . --json > audit-summary.json
```

See [Agent mode](../agentic-scan/agent-mode.md) for full coverage of each mode.

## Agent Mode in CI

### Code Review

Run an AI-powered security code review on the current source tree:

```bash
vigolium agent query --prompt-template security-code-review --source . --json
```

This produces structured JSON output with findings that can be parsed and posted as PR comments.

### Swarm with Discovery

For a more thorough AI-driven scan with automatic endpoint discovery:

```bash
vigolium agent swarm -t "$TARGET_URL" --discover --max-duration 20m --json \
  > swarm-summary.json
```

`--max-duration` bounds the whole Swarm run. Under `--json`, live progress is
sent to stderr and stdout contains one machine-readable run summary.

## Docker

Build the Vigolium Docker image:

```bash
make docker
```

Run a scan in a container:

```bash
docker run --rm vigolium scan -S -t "$TARGET_URL" \
  --strategy lite --format jsonl
```

For scans that require source code access, mount the workspace:

```bash
docker run --rm -v "$(pwd):/workspace" vigolium agent swarm \
  -t "$TARGET_URL" --source /workspace --json
```

## Tips

- **Keep scans fast**: Use `--strategy lite` and `--skip spidering` in CI to avoid long-running browser-based crawling. Save deep scans for staging or nightly runs.
- **Bound work**: use native phase limits such as `--timeout`,
  `--discover-max-time`, and `--spider-max-time`; use `--max-duration` for
  Swarm or Autopilot.
- **Cache the binary**: Download and cache the Vigolium binary in your CI cache (e.g., GitHub Actions cache, GitLab CI cache) to avoid re-downloading on every run.
- **Use projects**: Create a dedicated project for CI scans with `vigolium project create ci-scans` to keep findings organized and track trends across builds.
- **Incremental scanning**: When scanning the same target repeatedly, previous scan data in the project can help Vigolium avoid redundant checks.
- **Secrets management**: Pass API keys and authentication tokens via environment variables rather than hardcoding them in CI config files. Use `--header "Authorization: Bearer $API_TOKEN"` at runtime.
