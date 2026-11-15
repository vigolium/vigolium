# Stateless Scanning: One-Command Results

## Overview

Vigolium offers several ways to scan a target and get results in a single command without managing a persistent database. This is ideal for CI/CD pipelines, scripting, and quick ad-hoc checks.

## Quick Scan with `scan-url`

The fastest way to scan a single URL: no phases, just direct module execution.

It still opens a database -- every result vigolium produces is written through
one -- so "stateless" is a statement about the database's lifetime, not about
its absence. Without `-S` the run persists into the project database like any
other; with `-S` it runs into a throwaway file that is exported and then
deleted. Dropping `-S` is therefore not a way to make a run cheaper, and a
failed export is a failed run (exit `1`, `error.code: export_failed`) because
under `-S` the artifact is the only copy that survives.

```bash
vigolium scan-url https://example.com/api/users?id=1
```

JSON output for scripting:

```bash
vigolium scan-url -j https://example.com/api/users?id=1
```

With authentication and a POST body:

```bash
vigolium scan-url \
  --method POST \
  --body '{"user":"admin","pass":"secret"}' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer tok123' \
  https://example.com/api/login
```

Run only specific modules:

```bash
vigolium scan-url -m sqli -m xss https://example.com/search?q=test
```

Skip passive analysis for faster results:

```bash
vigolium scan-url --no-passive https://example.com/api/data
```

## Scanning Raw HTTP Requests with `scan-request`

Feed a raw HTTP request from a file or stdin:

```bash
# From a file
vigolium scan-request -i request.txt

# From stdin (raw HTTP)
printf 'GET /api/users?id=1 HTTP/1.1\r\nHost: example.com\r\n\r\n' | vigolium scan-request

# From a curl command (auto-detected)
echo "curl -X POST -d 'user=admin' https://example.com/login" | vigolium scan-request
```

Override the target host when the request file lacks a full URL:

```bash
vigolium scan-request -i request.txt --target https://staging.example.com
```

## Piping Input from stdin

Both `scan-url` and `scan-request` auto-detect the input format from stdin:

**Plain URL:**

```bash
echo 'https://example.com/search?q=test' | vigolium scan-url
```

**Curl command:**

```bash
echo "curl -X POST -H 'Content-Type: application/json' -d '{\"id\":1}' https://example.com/api" | vigolium scan-url
```

**Raw HTTP request:**

```bash
printf 'POST /api/login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=admin&pass=secret' | vigolium scan-request
```

## Full Pipeline with `--stateless`

For a complete multi-phase scan without a persistent database, use the `--stateless` flag on `vigolium scan`. This creates a temporary database, runs all phases, exports results, and cleans up:

```bash
vigolium scan --stateless \
  -t https://example.com \
  --format jsonl \
  -o results
```

This produces `results.jsonl` with all findings. Combine multiple output formats:

```bash
vigolium scan --stateless \
  -t https://example.com \
  --format jsonl,html \
  -o results
```

This produces both `results.jsonl` and `results.html`.

## Output Formats

### Console (default)

Human-readable colored output to the terminal:

```bash
vigolium scan-url https://example.com/search?q=test
```

### Machine output: `-j` and `--format jsonl` are different things

They are two separate contracts and are not interchangeable:

- **`-j`/`--json`** prints **one indented JSON document** for the whole
  invocation — the result object (or, for several targets, one envelope whose
  `items` are the per-target results). This is what you parse for triage.
- **`--format jsonl`** writes the bulk `{"type":…,"data":{…}}` export, one
  object per line, to the `-o` path. This is the archival stream. Without `-o`
  it goes to stdout, which is why it conflicts with `-j` and with
  `--events` — one protocol on stdout at a time.

```bash
vigolium scan-url -j https://example.com/search?q=test               # one document
vigolium scan-url -S --format jsonl -o results https://example.com/  # results.jsonl
```

### HTML

Interactive report with ag-grid table. Requires `-o` to specify the output path:

```bash
vigolium scan --stateless -t https://example.com --format html -o report
```

### Multiple Formats

Comma-separate formats to produce several outputs at once:

```bash
vigolium scan --stateless -t https://example.com --format console,jsonl,html -o scan-output
```

## CI/CD Integration

Use `-j` for one parseable scan document on stdout, or a jsonl file plus a
gate:

```bash
vigolium scan --stateless \
  -t https://example.com \
  --format jsonl -o findings.jsonl \
  --fail-on high
```

`--silent` prints one plain line per finding on stdout and nothing else.

## Scanning from Various Input Sources

### From an OpenAPI Spec

```bash
vigolium scan --stateless \
  --input api-spec.yaml -I openapi \
  -t https://api.example.com \
  --format jsonl -o results
```

### From a Burp Suite Export

```bash
vigolium scan --stateless \
  --input export.xml -I burpxml \
  --format jsonl -o results
```

### From a HAR File

```bash
vigolium scan --stateless \
  --input traffic.har -I har \
  --format jsonl -o results
```

### From a Postman Collection

```bash
vigolium scan --stateless \
  --input collection.json -I postman \
  -t https://api.example.com \
  --format jsonl -o results
```

## Tuning the Scan

Control concurrency and rate limits:

```bash
vigolium scan --stateless \
  -t https://example.com \
  -c 100 \
  --rate-limit 200 \
  --format jsonl -o results
```

Use a scanning strategy preset:

```bash
# Lightweight: fewer modules, faster
vigolium scan --stateless -t https://example.com --strategy lite -o results --format jsonl

# Deep: more modules, thorough
vigolium scan --stateless -t https://example.com --strategy deep -o results --format jsonl
```

Include full HTTP responses in a persisted/stateless scan artifact for
debugging (`scan-url` itself does not expose `--include-response`):

```bash
vigolium scan -S --include-response \
  --format jsonl -o endpoint.jsonl \
  https://example.com/api/users?id=1
```

## Examples

Every example below shows `-S` where the run is meant to leave nothing behind.
Drop it and the same command persists into the project database instead — which
is often what you want, but it is a choice, not the default of this page.

**Quick check on a single endpoint (keep the results):**

```bash
vigolium scan-url https://example.com/api/users?id=1
```

**Same check, leaving no trace:**

```bash
vigolium scan-url -S https://example.com/api/users?id=1
```

**Full scan with a bulk export in one shot:**

```bash
vigolium scan --stateless -t https://example.com --discover --format jsonl -o findings
```

**Scan a curl command from clipboard:**

```bash
pbpaste | vigolium scan-url -S -j
```

**Scan an API spec and export HTML report:**

```bash
vigolium scan --stateless --input openapi.yaml -I openapi -t https://api.example.com --format html -o report
```
