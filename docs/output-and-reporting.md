# Output and Reporting

Vigolium has two related output contracts:

- `--format` controls bulk scan/export artifacts;
- `-j/--json` on read commands such as `finding`, `traffic`, and `db list`
  emits one compact structured object for scripting or an AI agent.

## Scan Formats

Every command that takes `--format` reads one table of formats
(`pkg/output/formats`), so a name or alias means the same thing everywhere,
and `--help` lists exactly what that command accepts. A name the command does
not accept is a usage error (exit 2) that lists the valid ones.

| Format | Result | scan | export | import | REST | db export |
|---|---|---|---|---|---|---|
| `console` | Live, colored terminal output (default) | ✓ | | | | |
| `jsonl` | Bulk `{ "type": ..., "data": ... }` records and findings | ✓ | ✓ | | ✓ | ✓ |
| `html` | Self-contained interactive grid report | ✓ | ✓ | ✓ | ✓ | |
| `report` | Self-contained document-style report | ✓ | ✓ | ✓ | ✓ | |
| `pdf` | PDF document rendered through headless Chrome | ✓ | ✓ | ✓ | ✓ | |
| `markdown` (alias `md`) | One section per finding, with identifiers and follow-ups | ✓ | ✓ | ✓ | ✓ | ✓ |
| `sarif` | SARIF 2.1.0 log for GitHub code scanning, DefectDojo, SARIF viewers | ✓ | ✓ | ✓ | ✓ | |
| `csv` | One row per finding (records on `db export`) | ✓ | ✓ | ✓ | ✓ | ✓ |
| `junit` | JUnit XML for CI test reporters | ✓ | ✓ | ✓ | ✓ | |
| `github` | GitHub Actions annotations (workflow commands) | ✓ | ✓ | ✓ | | |
| `sqlite` (aliases `sqlite3`, `db`) | Standalone database that can be reopened by Vigolium (needs `-S`) | ✓ | | | | |
| `bundle` (alias `gz`) | `.tar.gz` of the export, an HTML report and agent sessions | | ✓ | | | ✓ |
| `fs` (alias `file-system`) | Flat, browsable request/response and finding tree | ✓ | ✓ | | | ✓ |

`db export` also takes `json`, `raw` and `markdown-table` (alias `md-table`)
record dumps. Names are case-insensitive.

Comma-separate formats to generate several artifacts from one scan:

```bash
vigolium scan https://example.com \
  --format jsonl,html,pdf \
  -o reports/example
```

File-based report formats require `-o/--output`. For multi-format output,
`-o` is a base path and Vigolium adds the relevant extension (`.md`, `.csv`,
`.junit.xml`, `.github.txt`, …).

### Console and JSONL

```bash
vigolium scan https://example.com
vigolium scan https://example.com --format jsonl -o findings.jsonl
vigolium scan-url -j 'https://example.com/search?q=test'
```

JSONL is the bulk stream contract and is suitable for `jq`, a SIEM, or
line-oriented ingestion. The post-scan stream from `scan --format jsonl` (and
`scan -j`) is scoped to that scan: its `scan` row, the findings it produced, and
its HTTP records (the exchanges it stored first, `http_records.scan_uuid`, plus
any record its findings cite as evidence). Use `vigolium export --format jsonl`
to dump the whole project. Select finding envelopes before reading fields:

```bash
vigolium scan https://example.com --format jsonl \
  | jq 'select(.type == "finding") | .data |
        select(.severity == "high" or .severity == "critical")'
```

`--ci-output-format` was removed: typing it is exit 2. Use `-j` for one scan
document, `--format jsonl` for the stream, or `--silent` for one plain line per
finding on stdout and nothing else.

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

PDF export runs headless Chrome with a throwaway profile directory, bounded by
a 90-second timeout (`--pdf-timeout 3m`, or `VIGOLIUM_PDF_TIMEOUT`, changes
it). A failed render exits 1 with error code `pdf_failed`. On
timeout the whole Chrome process group is killed, and a failure carries the
last 4 KB of Chrome's stderr. Chrome keeps its sandbox unless it cannot have
one: running as root on Linux, inside a container, or with
`VIGOLIUM_CHROME_NO_SANDBOX=1`.

### Markdown Report

`--format markdown` renders one section per finding. Each section has a
`finding_id` / `finding_hash` / `scan_uuid` / `module_id` / `record_uuids`
table and a follow-up command (`vigolium finding --id N`), pinned to the same
`--db` and project as the run that wrote the report (a stateless scan's temp
database is gone afterwards, so its report carries no follow-ups). The request
and response share one cap, 4 KB each by default (`--max-body-bytes N`; `0`
removes it). The cut never splits a UTF-8 character, and a cut message ends
with a note naming the command that prints it whole:

```text
… [truncated, 4096 of 22000 bytes; full: vigolium traffic body --uuid <record_uuid>]
```

Code fences grow longer than any backtick run in the message. A captured
response that contains three backticks therefore stays inside its block.

### SARIF (interchange with other tools)

`--format sarif` writes a [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html)
log of the run's findings — the format GitHub code scanning, DefectDojo, the
VS Code SARIF Viewer and most SAST/DAST aggregators ingest without a custom
parser.

```bash
vigolium scan https://example.com --format sarif -o scan.sarif
vigolium export --format sarif -o project.sarif
vigolium import ./audit-output --format sarif -o audit.sarif
```

How findings map onto the schema:

| Vigolium | SARIF |
|---|---|
| module id / name | `tool.driver.rules[].id` / `.name` |
| severity | `level` (critical+high → `error`, medium → `warning`, low+info → `note`) |
| severity / CVSS | `properties["security-severity"]` — what GitHub buckets alerts by |
| CWE | rule tag `external/cwe/cwe-079` |
| source file `path:line` | `locations[].physicalLocation` with a `region` |
| URL | `locations[].physicalLocation` when there is no source file |
| request / response | `webRequest` / `webResponse` |
| finding hash | `partialFingerprints` — lets a consumer track one finding across re-scans |

Code findings (from `vigolium agent audit` and the source-aware agent modes)
anchor to a **file and line**, which is what lets GitHub annotate them onto a
pull request diff. Absolute audit paths are made repo-relative when the
repository name identifies a directory in them; when it does not, the absolute
path is kept rather than guessed at, so a result is never pinned to the wrong
file.

Findings from the native module fleet anchor to their **URL** and carry the
proof exchange in the standard `webRequest`/`webResponse` fields. Bodies are
capped (4 KB each) so a large scan stays inside upload limits; a result whose
evidence was cut carries `properties.evidenceTruncated`.

Uploading to GitHub code scanning:

```bash
vigolium scan -S "$TARGET" --format sarif -o results.sarif
gh api /repos/{owner}/{repo}/code-scanning/sarifs \
  -f commit_sha="$(git rev-parse HEAD)" -f ref="refs/heads/main" \
  -f sarif="$(gzip -c results.sarif | base64)"
```

### CSV, JUnit and GitHub annotations (CI)

`--format csv` writes one row per finding with the columns `id`,
`finding_hash`, `severity`, `confidence`, `module_id`, `module_name`, `short`,
`url`, `hostname`, `matched_at`, `scan_uuid`, `http_record_uuids`, `status`,
`cwe_id`, `source_file`, `repo_name` and `found_at` (multi-valued cells are
joined with `; `). Every column is a key of the finding view `vigolium finding
-j` prints and holds the same value, so a column means the same thing in both. Cells are quoted by a standard CSV writer, and a cell that starts with
`=`, `+`, `-`, `@`, TAB or CR gets a leading `'` so a spreadsheet shows it as
text instead of evaluating it. `db export --format csv` (HTTP records) uses the
same writer.

`--format junit` writes JUnit XML: one `<testsuite>` per module, one
`<testcase>` per (module, host), and one `<failure>` per finding at or above the
`--fail-on` severity (`low` when `--fail-on` is not set; `export` and `import`
always use `low`). Findings below the threshold are listed in the testcase's
`system-out`, and a testcase whose findings are all `false_positive` or
`accepted_risk` is `<skipped>`. Every failure names its `finding_hash`, so CI
history tracks a finding across runs; its body lists the finding as
`key: value` lines under the same finding view keys (`id`, `finding_hash`,
`module_id`, `scan_uuid`, `http_record_uuids`, ...).

`--format github` prints one GitHub Actions workflow command per finding:
`::error` for critical/high, `::warning` for medium/low, `::notice` for
info/suspect. Dismissed findings are left out. Code findings carry `file=` and
`line=`; HTTP findings name their URL in the message. Without `-o` the commands
go to stdout, where the Actions runner reads them (live finding lines move to
stderr), so `--format github` cannot be combined with `-j` unless `-o FILE`
sends the commands to a file. When
`GITHUB_STEP_SUMMARY` is set, the Markdown report is appended to the job
summary as well (only its summary when the full report would exceed GitHub's
1 MiB limit).

```bash
# GitHub Actions step
vigolium scan -S "$TARGET" --format github --fail-on high
vigolium scan -S "$TARGET" --format junit,csv -o results/scan --fail-on medium
```

### Standalone SQLite

SQLite output requires stateless mode so the result is an explicit standalone
database rather than the active project database:

```bash
vigolium scan -S https://example.com --format sqlite -o scan.sqlite
vigolium finding -S --db scan.sqlite --min-severity high
vigolium traffic -S --db scan.sqlite --tree
```

### Filesystem Output

The `fs` format (alias `file-system`) writes two sibling trees, `<base>-traffic/` and
`<base>-findings/`. Requests are replayable `.req` files, responses are split
into headers and decoded bodies, and each tree has a machine-readable index.

```bash
vigolium scan -S https://example.com --format fs -o run
vigolium export --format fs -o project-export
```

## Export Existing Data

`vigolium export` reads the active project database and supports `jsonl`,
`html`, `report`, `pdf`, `markdown`, `sarif`, `csv`, `junit`, `github`,
`bundle`, and `fs` (alias `file-system`):

```bash
vigolium export --only findings,http --format jsonl -o export.jsonl
vigolium export --format html --severity high,critical -o report.html
vigolium export --format bundle --scan-uuid <agentic-scan-uuid> \
  -o results.tar.gz
```

A bundle contains `export.jsonl`, `report.html`, a manifest, and requested
agent session directories.

### Several formats in one run

`--format` takes a comma-separated list. The database is read once and every
format renders from that one result set, so three formats cost one query rather
than three:

```bash
vigolium export --format html,markdown,bundle -o agentic-authenticated-scan
# → agentic-authenticated-scan.html
#   agentic-authenticated-scan.md
#   agentic-authenticated-scan.tar.gz
```

With more than one format, `-o/--output` is a shared **base path** and each
format appends its own extension (an extension already on the base is replaced,
not stacked). Because one `-o` cannot name several files, it is required as soon
as you pass a second format. A single format still uses `-o` verbatim:
`--format html -o report` writes exactly `report`.

`{ts}` and `{project-uuid}` are expanded once for the whole run, so every file
carries the same timestamp even when a slow renderer (`pdf`) finishes seconds
after its siblings. If one format fails, the others are still written and the
command exits non-zero naming the format that failed.

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
