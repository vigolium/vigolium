# CI/CD Integration

## Overview

Vigolium can be integrated into CI/CD pipelines to automatically scan applications for vulnerabilities on every deployment or pull request. This guide covers common patterns for running scans in automated environments.

## Basic CI Scan

A minimal CI scan using the `lite` strategy for speed and JSONL output for machine parsing:

```bash
vigolium scan -t $TARGET_URL --strategy lite --format jsonl -o results.jsonl
```

The `lite` strategy skips browser spidering and heavy discovery, making it suitable for time-constrained CI environments. JSONL output produces one JSON object per line, which is straightforward to parse in scripts.

## Exit Codes

Check Vigolium's exit code to determine whether findings were reported. A non-zero exit code can be used to fail a CI pipeline gate when vulnerabilities are detected. Consult `vigolium scan --help` for the exact exit code semantics in your version.

## JSONL Output for Parsing

Use `jq` to filter findings by severity:

```bash
# Fail the build only on high/critical findings
HIGH_COUNT=$(jq -s '[.[] | select(.severity == "high" or .severity == "critical")] | length' results.jsonl)

if [ "$HIGH_COUNT" -gt 0 ]; then
  echo "Found $HIGH_COUNT high/critical severity findings"
  jq 'select(.severity == "high" or .severity == "critical")' results.jsonl
  exit 1
fi
```

Extract a summary of findings:

```bash
jq '{name: .name, severity: .severity, url: .url}' results.jsonl
```

## With Source Code (Whitebox)

When the source code is available in the CI workspace, enable whitebox scanning for deeper coverage. This runs SAST route extraction via ast-grep and feeds discovered routes into the dynamic scanner:

```bash
vigolium scan -t $TARGET_URL --source . --strategy whitebox --format jsonl -o results.jsonl
```

This is particularly effective in CI because the source code is always present in the checkout directory. See the [Whitebox Scanning guide](whitebox-scanning.md) for more details.

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
vigolium agent swarm -t $TARGET_URL --discover --timeout 20m
```

The `--timeout` flag ensures the scan does not run indefinitely in CI. The swarm mode coordinates multiple scan phases with AI-guided triage.

## Docker

Build the Vigolium Docker image:

```bash
make docker
```

Run a scan in a container:

```bash
docker run --rm vigolium scan -t $TARGET_URL --strategy lite --format jsonl
```

For scans that require source code access, mount the workspace:

```bash
docker run --rm -v $(pwd):/workspace vigolium scan -t $TARGET_URL --source /workspace --format jsonl
```

## Tips

- **Keep scans fast**: Use `--strategy lite` and `--skip spidering` in CI to avoid long-running browser-based crawling. Save deep scans for staging or nightly runs.
- **Set timeouts**: Always use `--timeout` in CI to prevent scans from blocking the pipeline indefinitely.
- **Cache the binary**: Download and cache the Vigolium binary in your CI cache (e.g., GitHub Actions cache, GitLab CI cache) to avoid re-downloading on every run.
- **Use projects**: Create a dedicated project for CI scans with `vigolium project create ci-scans` to keep findings organized and track trends across builds.
- **Incremental scanning**: When scanning the same target repeatedly, previous scan data in the project can help Vigolium avoid redundant checks.
- **Secrets management**: Pass API keys and authentication tokens via environment variables rather than hardcoding them in CI config files. Use `--header "Authorization: Bearer $API_TOKEN"` at runtime.
