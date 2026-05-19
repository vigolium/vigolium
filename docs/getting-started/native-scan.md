# Native Scan & Stateless Scanning

The **native scan** is Vigolium's deterministic, Go-based scanning pipeline —
fast, modular, and AI-free. This page is a hands-on tour of running native
scans from the CLI, with a focus on **stateless** scanning: getting results in
a single command without managing a persistent database.

Use it for CI/CD pipelines, scripting, AI-agent integration, and quick ad-hoc
checks. For the conceptual deep-dive see
[Scanning Modes Overview](../native-scan/scanning-modes-overview.md); for the
extended recipe book see [Stateless Scanning](../guides/stateless-scan.md).

## Stateless at a glance

| Command | Persists to DB? | Phases | Use it for |
|---------|-----------------|--------|------------|
| `scan-url` | No | none — direct module run | One URL, fast |
| `scan-request` | No | none — direct module run | A raw HTTP request / curl |
| `scan --stateless` | No (temp DB, discarded) | full pipeline | One-shot full scan |
| `scan` | Yes (`~/.vigolium/...sqlite`) | full pipeline | Persistent projects |

`scan-url` and `scan-request` never touch a database. `scan --stateless`
creates a temporary SQLite database, runs every requested phase, exports
results, and deletes the database on exit.

> Pass `-o/--output` (with `--format`) when using `--stateless` — otherwise
> results are discarded along with the temporary database. Vigolium prints a
> warning if you forget. `--stateless` and `--db` are mutually exclusive.

## Scan a single URL — `scan-url`

```bash
# Simplest possible scan
vigolium scan-url https://example.com/api/users?id=1

# JSON output for scripting
vigolium scan-url -j https://example.com/api/users?id=1
```

POST with a body and headers:

```bash
vigolium scan-url \
  --method POST \
  --body '{"user":"admin","pass":"secret"}' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer tok123' \
  https://example.com/api/login
```

Scope the modules and skip work you don't need:

```bash
# Only injection-class modules (fuzzy match on ID/name)
vigolium scan-url -m sqli -m xss "https://example.com/search?q=test"

# Filter by tag
vigolium scan-url --module-tag injection https://example.com/api/data

# Skip passive analysis and insertion-point fuzzing for the fastest result
vigolium scan-url --no-passive --no-insertion-points https://example.com/api/data
```

Run a discovery/spider phase *before* the scan (these promote `scan-url` to the
full pipeline and require a database — pass `--db`):

```bash
vigolium scan-url --discover --db /tmp/scan.sqlite https://example.com
```

## Scan a raw HTTP request — `scan-request`

```bash
# From a file containing a raw HTTP request
vigolium scan-request -i request.txt

# From stdin
printf 'GET /api/users?id=1 HTTP/1.1\r\nHost: example.com\r\n\r\n' \
  | vigolium scan-request

# From a curl command (auto-detected)
echo "curl -X POST -d 'user=admin' https://example.com/login" \
  | vigolium scan-request
```

Override the host when the request file has only a path:

```bash
vigolium scan-request -i request.txt --target https://staging.example.com
```

## Piping from stdin

Both `scan-url` and `scan-request` auto-detect the stdin format — plain URL,
curl command, or raw HTTP request:

```bash
# Plain URL
echo 'https://example.com/search?q=test' | vigolium scan-url

# Curl command
echo "curl -H 'Content-Type: application/json' -d '{\"id\":1}' https://example.com/api" \
  | vigolium scan-url

# Raw HTTP request
printf 'POST /api/login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=admin&pass=secret' \
  | vigolium scan-request

# Scan whatever is on your clipboard (macOS)
pbpaste | vigolium scan-url -j
```

## Full stateless pipeline — `scan --stateless`

Run discovery, spidering, and dynamic-assessment with no persistent state.
`--stateless` works on both `scan` and `run`:

```bash
# Full pipeline, JSONL out, nothing left behind
vigolium scan --stateless -t https://example.com --format jsonl -o results

# Add content discovery, write both JSONL and HTML
vigolium scan --stateless -t https://example.com \
  --discover --format jsonl,html -o scan-output

# A single phase, statelessly
vigolium run dynamic-assessment --stateless -t https://example.com \
  --format jsonl -o results
```

Multiple targets from a file — each target gets an isolated temporary database,
and the output filename is suffixed per host so results don't overwrite:

```bash
vigolium scan --stateless -T targets.txt --format jsonl -o results
# -> results-example.com.jsonl, results-test.example.com.jsonl, ...
```

## Stateless scans from other input sources

```bash
# OpenAPI / Swagger spec
vigolium scan --stateless -i api.yaml -I openapi \
  -t https://api.example.com --format jsonl -o results

# Postman collection
vigolium scan --stateless -i collection.json -I postman \
  -t https://api.example.com --format jsonl -o results

# Burp Suite XML export
vigolium scan --stateless -i export.xml -I burpxml --format jsonl -o results

# HAR capture
vigolium scan --stateless -i traffic.har -I har --format jsonl -o results

# Nuclei JSONL
vigolium scan --stateless -i nuclei.jsonl -I nuclei --format jsonl -o results
```

## Tuning a scan

```bash
# Speed knobs — defaults: -c 50, -r 100 req/s, --max-per-host 30, --timeout 15s
vigolium scan --stateless -t https://example.com \
  -c 100 -r 200 --max-per-host 10 --timeout 30s \
  --format jsonl -o results

# Strategy presets trade depth for speed
vigolium scan --stateless -t https://example.com --strategy lite -o r --format jsonl
vigolium scan --stateless -t https://example.com --strategy deep -o r --format jsonl

# Route everything through a proxy
vigolium scan --stateless -t https://example.com --proxy http://127.0.0.1:8080 \
  --format jsonl -o results

# Constrain how broadly scope is interpreted
vigolium scan --stateless -t https://example.com --scope-origin strict \
  --format jsonl -o results

# Include the full HTTP response body in findings (scan / run only)
vigolium scan --stateless -t https://example.com --include-response \
  --format jsonl -o results
```

## Authenticated stateless scans

Pass an inline session or a session file — both work in stateless mode:

```bash
# Inline session: name:Header:value
vigolium scan --stateless -t https://example.com \
  --auth "admin:Cookie:session_id=abc123" \
  --format jsonl -o results

# Session / auth-config file (YAML or JSON)
vigolium scan --stateless -t https://example.com \
  --auth-file ./admin-session.yaml \
  --format jsonl -o results

# A static header is often enough for token auth
vigolium scan-url -H 'Authorization: Bearer token123' \
  https://example.com/api/me
```

See [Authenticated Scanning](../native-scan/authentication.md) for login flows,
token extraction, and multi-session IDOR/BOLA testing.

## CI/CD integration

`--ci-output-format` forces clean JSONL with no banners or color codes, ideal
for parsing in a pipeline:

```bash
vigolium scan --stateless -t https://example.com \
  --ci-output-format -o findings
```

A minimal gate that fails the build when any finding is reported:

```bash
vigolium scan --stateless -t "$TARGET" --ci-output-format -o findings
test ! -s findings.jsonl || { echo "Vulnerabilities found"; exit 1; }
```

See [CI/CD Integration](../guides/ci-cd-integration.md) for full pipeline
examples.

## Output formats recap

| `--format` | Output | Notes |
|------------|--------|-------|
| `console` | Terminal (default) | Colored, human-readable |
| `jsonl` | `<o>.jsonl` | One JSON object per line; `-j` is shorthand |
| `html` | `<o>.html` | Interactive ag-grid report; requires `-o` |
| `console,jsonl,html` | All of the above | Comma-separate to combine |

For stateless runs, `-o` is the **base** path — Vigolium appends the correct
extension per format and materializes every requested format from the
temporary database before tearing it down.

## Cheat sheet

```bash
# Quick check on one endpoint
vigolium scan-url https://example.com/api/users?id=1

# One-shot full scan, JSON output, no persistence
vigolium scan --stateless -t https://example.com --discover --format jsonl -o findings

# Scan a clipboard curl command
pbpaste | vigolium scan-url -j

# API spec → HTML report, nothing left behind
vigolium scan --stateless -i openapi.yaml -I openapi \
  -t https://api.example.com --format html -o report

# CI gate
vigolium scan --stateless -t "$TARGET" --ci-output-format -o findings
```

## Next steps

- [Stateless Scanning](../guides/stateless-scan.md) — the extended recipe book.
- [Scanning Strategies](../native-scan/strategies.md) — strategies, profiles, pace.
- [Native Scan: How It Works](../architecture/native-scan.md) — the pipeline internals.
- [Scanner Modules Reference](../native-scan/modules-reference.md) — every module.
- [Output & Reporting](../output-and-reporting.md) — formats and reports in depth.
