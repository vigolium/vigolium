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

## Gotchas

- `-S` means `--stateless` on `scan` but `--scan-on-receive` on `ingest`.
- `--json` (compact, single object) ≠ `--format jsonl` (bulk, one line per row).
- With `-P/--parallel`, `--fail-on` is evaluated per child process.
- Agentic scans need a configured LLM provider (`agent.olium` in
  `vigolium-configs.yaml`); run `vigolium doctor --json` to check.
