# Stateless Scanning: One-Command Results

## Overview

Vigolium offers several ways to scan a target and get results in a single command without managing a persistent database. This is ideal for CI/CD pipelines, scripting, and quick ad-hoc checks.

## Quick Scan with `scan-url`

The fastest way to scan a single URL. No database, no phases -- just direct module execution:

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

### JSONL

Machine-readable, one JSON object per line. Use `-j` or `--format jsonl`:

```bash
vigolium scan-url -j https://example.com/search?q=test
vigolium scan-url --format jsonl https://example.com/search?q=test
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

Use `--ci-output-format` for clean, parseable output with no banners or color codes:

```bash
vigolium scan --stateless \
  -t https://example.com \
  --ci-output-format \
  -o findings
```

This forces JSONL output and suppresses all decorative output.

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

Include the full HTTP response in findings for debugging:

```bash
vigolium scan-url --include-response -j https://example.com/api/users?id=1
```

## Examples

**Quick check on a single endpoint:**

```bash
vigolium scan-url https://example.com/api/users?id=1
```

**Full scan with JSON output in one shot:**

```bash
vigolium scan --stateless -t https://example.com --discover --format jsonl -o findings
```

**Scan a curl command from clipboard:**

```bash
pbpaste | vigolium scan-url -j
```

**Scan an API spec and export HTML report:**

```bash
vigolium scan --stateless --input openapi.yaml -I openapi -t https://api.example.com --format html -o report
```
