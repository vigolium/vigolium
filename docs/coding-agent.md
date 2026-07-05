# Driving Vigolium from a coding agent

A compact, copy-paste reference for running Vigolium **non-interactively** from an
LLM/coding agent and parsing the results. Everything here is additive — the
default human output is unchanged; you opt into machine output with `-j/--json`.

## Mental model

- All data is stored in a project-scoped SQLite/Postgres DB. A scan **writes**
  findings + HTTP records; query commands **read** them back.
- Two JSON contracts:
  - **`-j/--json`** on read/query commands (`finding`, `traffic`, `db`) → a single
    structured object with **compact, token-aware** bodies. This is what you parse.
  - **`--format jsonl`** / `export` → the bulk `{"type":...,"data":{...}}` stream
    (one object per line), full fidelity. Use for archival/bulk, not triage.
- Non-interactive by default: the TUI is opt-in (`--tui`), never auto-launched.
  Destructive commands need `--force`. Add `--no-color` (or `NO_COLOR=1`) for
  clean text; scope with `--project <uuid>` or `VIGOLIUM_PROJECT`.

## Token-aware output (the important part)

Under `--json`, `finding` and `traffic` keep headers + high-signal metadata but
**bound** request/response bodies so you don't blow your context window:

- Bodies are previewed (first ~1–2 KB) with `body_size` + `body_sha256` +
  `body_truncated:true` so you know there's more.
- Binary/static bodies (images, fonts, JS bundles, gzip) are stubbed as
  `{"body_omitted":"binary", ...}`.
- Findings get a `response_evidence` snippet windowed around the match instead of
  the whole page.

Control it:

| Flag | Effect |
|------|--------|
| `--compact` | metadata only, drop bodies (best for surveys / listing endpoints) |
| `--fields a,b,c` | project the JSON to just these top-level keys (cuts tokens hard) |
| `--with-records` | (finding) resolve + embed the linked HTTP records — a self-contained triage bundle |
| `--full-body` | include complete, decoded bodies (use when you need to write an exploit) |
| `--raw` | full raw HTTP request/response, human format (not JSON) |
| `--pick` | (finding) keep only the 1-based position(s) from the result list — `2`, `1,3`, or `2-4`; applied after `--search`/filters + sort |

## Run a scan and gate on results

```bash
# Stateless single-shot, JSON findings to stdout, fail (exit!=0) on high+.
vigolium scan-url https://target.example --json --fail-on high

# Full pipeline into the DB, exit non-zero if a high/critical is found (CI gate).
vigolium scan -t https://target.example --fail-on high

# Scan a raw request from stdin (pipeline-friendly).
printf 'GET /api?q=1 HTTP/1.1\r\nHost: target.example\r\n\r\n' \
  | vigolium scan-request --json
```

- `--fail-on <info|low|medium|high|critical>`: exit non-zero when a finding at or
  above that severity is present. `--soft-fail` forces exit 0 (still prints the
  reason). Output is always written first — the gate only changes the exit code.
- `scan-url`/`scan-request` direct JSON shape:
  `{"target","method","scan_duration_ms","modules_run","findings":[...],"errors":[]}`.

## Query findings

```bash
# Compact triage list of high+ findings, only the fields you need.
vigolium finding --min-severity high --json --compact \
  --fields id,severity,module_id,url,matched_at

# One finding, fully self-contained (finding + linked request/response).
vigolium finding --id 42 --json --with-records

# Narrow a search to the Nth match by list position (1-based), e.g. the 2nd.
vigolium finding --search 'Reverse Proxy' --pick 2 --raw

# Findings from a specific agent run (autopilot/swarm/audit).
vigolium finding --agentic-scan <agentic_scan_uuid> --json --with-records
```

Filters (shared with `traffic` / `db ls`): `--host --path --method --status
--severity --min-severity --from/--to --search --scan-uuid --agentic-scan
--module-type -n/--limit --offset --sort --asc`.

Output shape:
```json
{ "project_uuid": "...", "total": 39, "offset": 0, "limit": 100,
  "findings": [ { "id": 2, "severity": "high", "module_id": "...", "url": "...",
                  "matched_at": ["..."], "extracted_results": ["..."],
                  "response_evidence": "…<match>…" } ] }
```

## Query stored HTTP traffic

```bash
# Survey endpoints (no bodies) — cheap.
vigolium traffic --json --compact --fields uuid,method,url,status_code,response_content_type

# A few records with bounded bodies (default).
vigolium traffic --host target.example --status 200 --json -n 5

# Everything for one record, full bodies.
vigolium traffic search-term --json --full-body -n 1
```

## Read a standalone export (`-S/--stateless`)

`finding` and `traffic` can read a file directly instead of your project DB —
handy for inspecting a `--format jsonl` export or a foreign `.sqlite` lying
around. `-S/--stateless` requires `--db` and turns project scoping **off**, so
every row in the file is shown regardless of the `project_uuid` it carries.
Nothing is written to your project DB (a JSONL source is loaded into a throwaway
in-memory SQLite).

```bash
# Browse a scan's JSONL export with all the normal filters/sorting.
vigolium finding -S --db ./scan-target.jsonl --min-severity medium
vigolium traffic -S --db ./scan-target.jsonl --status 500 -n 20

# A standalone .sqlite works too (auto-detected by extension / header sniff).
vigolium finding -S --db ./run.sqlite --json --with-records
```

A stateless scan can emit that `.sqlite` directly with `--format sqlite` (aliases
`sqlite3`, `db`) — it dumps the per-run DB to `<output>.sqlite` and combines with
other formats. Under `--split-by-host` each per-host file is named
`<base>-<host>.sqlite`:

```bash
vigolium scan -S --format sqlite,html -o scan -t target.example   # → scan.sqlite + scan.html
vigolium scan -S --format sqlite -o run --split-by-host -P 4 -T targets.txt  # → run-<host>.sqlite per target
vigolium finding -S --db ./run-target.example.sqlite --min-severity high
```

## Merge external `.sqlite` scans into one DB (`vigolium import`)

The stateless reads above open a foreign `.sqlite` **in place**. To instead
**fold** those external databases into a single one, `vigolium import` accepts a
vigolium SQLite database as its source and merges it into the destination DB
(the `--db` target, or the configured default when `--db` is omitted). The source
is auto-detected by its SQLite header, so `.sqlite`, `.sqlite3`, `.db`, or a bare
name all work. It's a lossless, **idempotent** merge — HTTP records, findings,
scans, agentic scans, and OAST interactions all flow in, deduped on their natural
keys (records by UUID, findings by `(project_uuid, finding_hash)`), so re-running
the same import adds nothing. Each row keeps its original `project_uuid`.

```bash
# Merge one external scan DB into your default database.
vigolium import other-vigolium-scan.sqlite

# Merge into an explicit destination (--db is the target, not a filter).
vigolium import --db default-db.sqlite other-vigolium-scan.sqlite

# Collapse a directory of per-host/per-run exports into one combined DB.
for f in scans/*.sqlite; do vigolium import --db combined.sqlite "$f"; done
vigolium finding --db combined.sqlite --min-severity high

# -j prints a per-table merge summary for scripting.
vigolium -j import --db combined.sqlite other-vigolium-scan.sqlite
```

This is the natural companion to `vigolium scan -S --format sqlite` above: fan out
scans into standalone per-host `.sqlite` files, then merge them back into one
queryable database. (`import` also still ingests audit folders, JSONL exports,
and `.tar.gz`/`.zip` archives — see `vigolium import -h`.) A Postgres destination
is rejected with a clear error, since the merge is SQLite-to-SQLite.

## Render one finding/record as Markdown (`--markdown`)

`--markdown` prints the selected findings/records as Markdown (evidence +
request/response in fenced `http` blocks) to stdout — pipe it to a file or a
viewer like `glow`. Pair with `--id` / a fuzzy term / `-n 1` to focus one item.

Under `-S/--stateless`, add `--compact` to window the response around the
finding's `matched_at` / `extracted_results` (records cap the body to a preview)
so a long page doesn't flood the console:

```bash
vigolium finding -S --db ./scan-target.jsonl --id 42 --markdown            # full bodies
vigolium finding -S --db ./scan-target.jsonl --id 42 --markdown --compact  # response windowed at the match
vigolium traffic -S --db ./scan-target.jsonl search-term -n 1 --markdown
```

## AI / agentic scans

These run an LLM-driven scan into the DB. With `--json`, the live agent stream
goes to **stderr** and a single JSON summary is printed to **stdout** at the end:

```bash
vigolium agent audit --source . --intensity balanced --json
vigolium agent autopilot -t https://target.example --json
vigolium agent swarm -t https://target.example --json
```

Summary shape (stdout):
```json
{ "agentic_scan_uuid": "...", "status": "completed", "session_dir": "...",
  "total_findings": 7, "counts_by_severity": {"critical":1,"high":3},
  "top_findings": [ ... ],
  "query": "vigolium finding --agentic-scan <uuid> --json --with-records" }
```

Then pull the full results with the `query` line. The `--agentic-scan` filter
expands to the whole run tree (audit driver legs / swarm sub-runs), so one UUID
returns every finding the run produced.

For a one-shot code review without a full scan:
```bash
vigolium agent query --prompt-template security-code-review --source . --json
```

## Counts, export, housekeeping

```bash
vigolium db stats --json                 # counts by severity / per-host
vigolium export --format jsonl -o out.jsonl   # bulk {type,data} stream
vigolium module --json                   # machine-readable module catalog
vigolium doctor --json                   # environment readiness
```

## Export a browsable filesystem tree (`--format fs`)

When you'd rather `ls`/`grep`/`jq` a scan than query a DB, export a flat tree.
Works on `export`, `db export`, and any scan (`scan`/`scan-url`/`scan-request`/`run`).

```bash
vigolium export --format fs -o run            # whole DB → run-traffic/ + run-findings/
vigolium scan-url https://t/ -S --format fs -o run   # straight from a scan
```

Layout (two sibling dirs off the `-o` base; defaults to `vigolium` in the cwd):

```
run-traffic/
  index.json                 # [{id,host,path,method,url,status,content_type,bytes,finding}, …]
  <host>/0001.req            # "@target https://<host>" + the raw request (replayable)
  <host>/0001.resp.headers   # status line + response headers
  <host>/0001.resp.body      # response body, gzip-decoded so it greps clean
run-findings/
  index.json                 # [{id,host,path,severity,confidence,module,title,url,traffic}, …]
  <host>/0001.md             # the finding, cross-linked to ../../run-traffic/<host>/0001.req
```

`index.json` is the entry point — one `jq` over it maps every id to its url/status
and to the file that holds the bytes, so you never guess paths. The `finding` field
on a traffic row is the top severity of any finding touching that request, and each
finding `.md` links straight to the `.req`/`.resp.*` that proves it. `--omit-response`
drops the `.resp.*` files; `--split-by-host` is a no-op (fs already splits by host).

### Live mirror from the ingestion server

To watch traffic land as files while another tool (Burp, a proxy, `vigolium ingest`)
feeds the server, run the server with a mirror dir:

```bash
vigolium server --mirror-fs ./mirror     # also: config server.mirror_fs_path
```

Every ingested record and finding is written to `./mirror/traffic/<host>/…` and
`./mirror/findings/<host>/…` as it's saved to the DB. Same layout as `--format fs`,
except the indexes are append-only **`index.jsonl`** (one object per line — tail/grep
it live) and per-host ids resume across server restarts. Point your agent at `./mirror`
and let it `jq`/`grep` the growing tree.

## Gotchas

- `-S` means `--stateless` on `scan` but `--scan-on-receive` on `ingest`.
- `--json` (compact, single object) ≠ `--format jsonl` (bulk, one line per row).
- With `-P/--parallel`, `--fail-on` is evaluated per child process.
- Agentic scans need a configured LLM provider (`agent.olium` in
  `vigolium-configs.yaml`); run `vigolium doctor --json` to check.
