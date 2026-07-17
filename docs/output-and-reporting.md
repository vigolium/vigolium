# Output and Reporting

Vigolium has two related output contracts:

- `--format` controls bulk scan/export artifacts;
- `-j/--json` on read commands such as `finding`, `traffic`, and `db list`
  emits one compact structured object for scripting or an AI agent.

## Scan Formats

Native scans accept these formats:

| Format | Result |
|---|---|
| `console` | Live, colored terminal output (default) |
| `jsonl` | Bulk `{ "type": ..., "data": ... }` records and findings |
| `html` | Self-contained interactive grid report |
| `report` | Self-contained document-style report |
| `pdf` | PDF document rendered through headless Chrome |
| `sqlite` | Standalone database that can be reopened by Vigolium |
| `fs` | Flat, browsable request/response and finding tree |

Comma-separate formats to generate several artifacts from one scan:

```bash
vigolium scan https://example.com \
  --format jsonl,html,pdf \
  -o reports/example
```

File-based report formats require `-o/--output`. For multi-format output,
`-o` is a base path and Vigolium adds the relevant extension.

### Console and JSONL

```bash
vigolium scan https://example.com
vigolium scan https://example.com --format jsonl -o findings.jsonl
vigolium scan-url -j 'https://example.com/search?q=test'
```

JSONL is the bulk stream contract and is suitable for `jq`, a SIEM, or
line-oriented ingestion. Select finding envelopes before reading fields:

```bash
vigolium scan https://example.com --format jsonl \
  | jq 'select(.type == "finding") | .data |
        select(.severity == "high" or .severity == "critical")'
```

`--ci-output-format` is the exception: it emits finding objects only and
suppresses banners/color for a simple CI stream.

Use `--include-response` on `scan`/`run` when the full response body is needed
in scan output, or `--omit-response` to keep persisted exports smaller.

### HTML, Document, and PDF Reports

```bash
vigolium scan https://example.com --format html -o report.html
vigolium scan https://example.com --format report -o report.html
vigolium scan https://example.com --format pdf -o report.pdf
```

Full native scans can produce HTML reports. When `--only` isolates a phase,
HTML is supported for discovery and spidering output.

### Standalone SQLite

SQLite output requires stateless mode so the result is an explicit standalone
database rather than the active project database:

```bash
vigolium scan -S https://example.com --format sqlite -o scan.sqlite
vigolium finding -S --db scan.sqlite --min-severity high
vigolium traffic -S --db scan.sqlite --tree
```

### Filesystem Output

The `fs` format writes two sibling trees, `<base>-traffic/` and
`<base>-findings/`. Requests are replayable `.req` files, responses are split
into headers and decoded bodies, and each tree has a machine-readable index.

```bash
vigolium scan -S https://example.com --format fs -o run
vigolium export --format fs -o project-export
```

## Export Existing Data

`vigolium export` reads the active project database and supports `jsonl`,
`html`, `report`, `pdf`, `markdown`, `bundle`, and `fs`:

```bash
vigolium export --only findings,http --format jsonl -o export.jsonl
vigolium export --format html --severity high,critical -o report.html
vigolium export --format bundle --scan-uuid <agentic-scan-uuid> \
  -o results.tar.gz
```

A bundle contains `export.jsonl`, `report.html`, a manifest, and requested
agent session directories.

## Query Stored Results

Use the noun directly; `finding list` and `traffic list` are not subcommands.

```bash
# Human-readable browsing
vigolium finding
vigolium finding xss --min-severity medium
vigolium traffic --host api.example.com --status 200

# Project scoping
vigolium finding --project-name my-project
vigolium traffic --project-uuid <uuid>

# Generic table access (the table is positional)
vigolium db list findings --severity high,critical
vigolium db list http_records --host api.example.com
```

### Compact JSON for Automation

On query commands, `-j/--json` emits a single structured response rather than
the bulk JSONL stream. Large and binary bodies are previewed or stubbed with
size/hash metadata.

```bash
vigolium finding --min-severity high --json --with-records
vigolium traffic --host api.example.com --json --compact
vigolium finding --json --fields id,severity,url
```

Use `--full-body` only when complete bodies are required. `--compact` omits
bodies, and `--fields` projects selected top-level keys.

## Finding Metadata

Findings include severity (`critical`, `high`, `medium`, `low`, `info`) and
confidence (`certain`, `firm`, `tentative`), plus module identity, affected
location, evidence, request/response links, remediation, and source metadata.

For CI gating, let the scanner set the process status after output is written:

```bash
vigolium scan -S "$TARGET" --format jsonl -o findings.jsonl --fail-on high
```

`--soft-fail` suppresses the non-zero severity gate while retaining results.
