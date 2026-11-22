# Data & Management Commands Reference

> **Related:** [agent-loop.md](agent-loop.md) for the `-j` triage contracts · [flags.generated.md](flags.generated.md) for any flag

Complete reference for `init`, `import`, `log`, `doctor`, `db`, `finding`, `traffic`, `endpoints`, `params`, `module`, `extensions` (alias `ext`), `js`, `config`, `scope`, `auth`, `project`, `storage`, `strategy`, `export`, `version`, and `update` commands.

## Table of Contents

- [Time filters (shared)](#time-filters)
- [init](#init)
- [import](#import)
- [log](#log)
- [doctor](#doctor)
- [db](#db)
- [db list / ls](#db-list)
- [db stats](#db-stats)
- [db migrate](#db-migrate)
- [db export](#db-export)
- [db clean](#db-clean)
- [db compact](#db-compact)
- [db seed](#db-seed)
- [finding](#finding)
- [finding load](#finding-load)
- [finding mark](#finding-mark)
- [finding verify](#finding-verify)
- [traffic](#traffic)
- [traffic --replay](#traffic---replay)
- [traffic --curl / finding --curl](#traffic---curl--finding---curl)
- [endpoints](#endpoints)
- [params](#params)
- [hosts](#hosts)
- [export (top-level)](#export)
- [module](#module)
- [extensions](#extensions)
- [js](#js)
- [config](#config)
- [config clean](#config-clean)
- [scope](#scope)
- [auth](#auth)
- [project](#project)
- [storage](#storage)
- [storage ls](#storage-ls)
- [storage upload](#storage-upload)
- [storage download](#storage-download)
- [storage results](#storage-results)
- [storage presign](#storage-presign)
- [storage rm](#storage-rm)
- [strategy](#strategy)
- [version](#version)
- [update](#update)

---

## Time filters

`--from`/`--to` (aliases `--since`/`--until`) narrow `finding`, `traffic`,
`db ls`, `db export`, and `replay` to a date window; `db clean --before` takes the
same values. They all share one parser, which accepts more than the tables below
imply:

- **Relative offsets** — `2d`, `12h`, `30m`, `1w`, compound `1h30m`, optional trailing `ago` (`3h ago`)
- **Keywords** — `today`, `yesterday`, `now`
- **Absolute** — `YYYY-MM-DD`, `"YYYY-MM-DD HH:MM[:SS]"`, or full RFC3339

Three contracts worth knowing:

- Bare dates and wall-clock times resolve in your **local** zone, so `--since today` covers the local day (not UTC midnight).
- A bare date on the **upper** bound snaps to end-of-day, so `--from D --to D` is the whole of day D. (`db clean --before D` is the exception — no snap, so day D itself survives the delete.)
- An inverted range (`--from` later than `--to`) is a hard error, not silently-empty output.

```bash
vigolium finding --since 2d --min-severity high      # findings from the last 48h
vigolium traffic --since today --status 500          # today's 5xx responses
vigolium traffic --from 2026-08-01 --to 2026-08-01   # everything on Aug 1 (local)
vigolium db clean --before 30d --force               # prune records older than 30 days
```

---

## init

**Usage:** `vigolium init [--force]`

Create `~/.vigolium/` with a default config file (including a freshly generated API key), database schema, default scanning profiles, prompt templates, and JavaScript extensions. Idempotent: skips components that already exist unless `--force` is passed.

With `--force`, the existing config is rewritten with a new API key and the preset directories (`profiles/`, `extensions/`, `prompts/`) are re-extracted from the embedded assets.

```bash
vigolium init
vigolium init --force   # regenerate API key + re-extract preset data
```

Output (on success):

```
✓ Vigolium initialized successfully!
  ℹ Config:   ~/.vigolium/vigolium-configs.yaml
  ℹ Database: ~/.vigolium/database-vgnm.sqlite
  ℹ Docs:     https://docs.vigolium.com
```

---

## import

**Usage:** `vigolium import <path>`

Import scan data into the current project's database. The input is **auto-detected** from the path (`[path|gs://...] [more-paths...]`), and multiple sources can be imported in one run:

- **Audit output folder** (directory): produced by `vigolium agent audit` (vigolium-audit or piolium leg) — contains `audit-state.json` and `findings-draft/`. Creates a new `agentic_scan` row plus all findings.
- **JSONL export** (file): each line is an envelope like `{"type": "http_record", "data": {...}}` or `{"type": "finding", "data": {...}}` — the output of `vigolium export --format jsonl`. Findings are deduplicated on save.
- **Vigolium SQLite database** (`.sqlite`/`.sqlite3`/`.db`, detected by header): a **lossless, idempotent SQLite→SQLite merge** of the scan-result tables, deduped on natural keys (re-importing the same DB is a no-op). Merged rows keep their **original** `project_uuid`. Requires a SQLite destination. `--host <pattern>` (one per import, `*` wildcards, case-insensitive) merges only that host's records and findings; `--skip-findings` leaves findings out — e.g. `import --db new.sqlite old.sqlite --host acme.test --skip-findings` seeds one host's traffic. Both are refused (exit 2) for any other source.
- **Archive** (`.tar.gz`/`.tgz`/`.zip`) containing any of the above.
- **`gs://<project-uuid>/<key>` URL** to any of the above (downloaded, then imported).

```bash
vigolium import /path/to/vigolium-results/         # audit output folder
vigolium import scan-results.jsonl                 # JSONL export
vigolium import other-vigolium-scan.sqlite         # merge an external scan DB
vigolium import bundle.tar.gz                      # archive (also .tgz, .zip)
vigolium import gs://<project-uuid>/<key>          # cloud-storage object

# Merge several scans into one destination DB (positional, or via --glob-db)
vigolium import --db combined.sqlite scan-a.sqlite scan-b.sqlite
vigolium import --db combined.sqlite --glob-db 'scans/*.sqlite'

# After an interactive audit (`agent audit -i`), turn the on-disk results into a report:
vigolium import ./src/vigolium-results --format html -o audit-report.html
```

> To **read** a colleague's export without merging it into your DB, open it in place with `-S --db <file>.sqlite` or `--glob-db '<glob>'` on `finding` / `traffic` / `export` instead (see those commands).

**Imports are idempotent and loud about loss.** Re-importing the same JSONL or
SQLite skips the duplicates (`records_skipped_duplicate`) rather than failing on
a UNIQUE constraint. An import that could not read everything — a truncated
JSONL, a corrupt member of a glob — prints its full summary and then **exits 1**
with `error.code: "ingest_incomplete"`, so a zero exit means the whole source
landed. A glob read reports `glob_sources` naming every file it skipped and why;
`--glob-strict` turns the first such skip into a hard failure instead.

`import -j` is a mutation envelope: `changed` (did anything land), `action:
"import"` (`"noop"` when a bridge import matched nothing), `items: []`, and the
import counters at the top level under their usual names (`findings_total`,
`findings_saved`, `findings_failed`, `records_imported`, the `*_merged` set for
a SQLite merge, `report_path`, `uploaded_to`).

### import flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--format` | — | string | — | Also write a report after import: `html`, `report`, `pdf`, or `markdown` (`md`). Same generators as `vigolium export --format`, but one value only (no comma list) |
| `--output` | `-o` | string | — | Report output path or `gs://<project>/<key>` URL (required when `--format` is set; supports `{ts}`) |
| `--glob-db` | — | string | — | Glob of local files to import alongside any positional paths (one format per run) |
| `--glob-strict` | — | bool | `false` | Fail on the first `--glob-db` source that cannot be imported, instead of skipping it with a warning |
| `--burp-bridge-url` | `-B` | string | `$VIGOLIUM_BURP_BRIDGE_URL` | Import live Burp/Caido Proxy history from this loopback bridge URL. **Requires a filter or `--all-hosts`** — see below |
| `--host` / `--path` / `--method` / `--status` / `--search` / `--exclude-search` / `--from` / `--to` / `-n` | — | — | — | With `-B`: narrow which live records are imported (same spellings as `traffic -B`) |
| `--all-hosts` | — | bool | `false` | With `-B`: import the **entire** proxy history, unfiltered. Required when no filter is given |
| `--yes` | — | bool | `false` | With `-B`: skip the pre-flight confirmation |
| `--upload` / `--upload-key` | — | bool / string | — | Upload the import source to cloud storage after import (optional explicit key) |
| `--severity` / `--search` | — | string | — | Filter the emitted report's findings |
| `--report-title` / `--report-target` / `--report-duration` / `--report-generated-at` / `--report-url` | — | string | — | HTML report metadata |

**`import -B` refuses an unfiltered pull.** Without a narrowing filter it errors
(exit 2) instead of copying every host the operator has ever browsed — with those
hosts' cookies and tokens — into your database. Pass `--host`/`--path`/etc., or
`--all-hosts` to opt in deliberately. A pre-flight prints how many records are
about to cross **before** anything is written; `--yes` (or a non-TTY) skips the
confirmation, but never the refusal.

```bash
vigolium import -B http://127.0.0.1:9009 --host acme.test    # correct
vigolium import -B http://127.0.0.1:9009                     # refused, exit 2
vigolium import -B http://127.0.0.1:9009 --all-hosts --yes   # deliberate
```

Notes:
- Imported findings inherit the current project's UUID and default `finding_source = "import"` when the field is empty.
- Unknown envelope types are counted and reported at the end (e.g. for forward-compatibility).
- Use `--project-uuid` / `--project-name` (or `VIGOLIUM_PROJECT_UUID` / `VIGOLIUM_PROJECT_NAME`) to target a specific project.

---

## log

**Usage:** `vigolium log [uuid] [flags]`

View raw `runtime.log` for a native scan or agentic scan session. When called without a UUID, behaves like `log ls` and lists all sessions.

### Log resolution order

1. Agentic session file: `~/.vigolium/agent-sessions/<uuid>/runtime.log`
2. Native session file: `~/.vigolium/native-sessions/<uuid>/runtime.log`
3. DB fallback: `scan_logs` table (used when `scanning_strategy.scan_logs.persist_logs` is disabled)

The legacy `run.log` filename is also resolved for older sessions. Agent audit child runs whose UUID does not match a session directory fall back to their parent's `SessionDir` column.

### log flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--tail` | `-n` | int | `200` | Show the last N lines (0 = none, -1 = all) |
| `--full` | — | bool | `false` | Show the full log (shortcut for `--tail -1`) |
| `--follow` | `-f` | bool | `false` | Follow log output as it is written (tail -f). Auto-enabled only when the session is still running **and** stdout is a TTY **and** the row is not stale — see below |
| `--stateless` | `-S` | bool | `false` | Read the session list/log from `--db` (a standalone `.sqlite`) with project scoping off |
| `--strip-ansi` | — | bool | `false` | Strip ANSI color codes from output |
| `--raw` | — | bool | `false` | For agentic sessions, print the raw transcript JSONL verbatim instead of the rendered replay |
| `--tui` / `--no-tui` | — | bool | — | Enable / force-disable interactive picker (affects `log ls` behaviour) |

### `--follow` will not hang on a dead scan

A scan reaped by a deadline or SIGKILL leaves its row saying `running`
**forever**, so auto-follow is gated:

- a **non-TTY stdout** (a pipe — i.e. a program, which wants the log and an exit)
  never auto-follows,
- a row whose log has not been written to for ~2 minutes is treated as stale,
- an explicitly typed `--follow` / `--follow=false` still wins either way.

So `vigolium log <uuid> | cat` terminates promptly. For live progress from a
program, prefer `--events ndjson` on the scan itself (see
[loop-watch.md](loop-watch.md)) — it is a structured stream rather than a
rendered log.

### `--full` is not needed to see WAF notices

WAF notices fire **early** (the edge is fingerprinted on the first clean
response), so the default 200-line tail is structurally the wrong end of the log
for the most important thing in it. Any `[waf-block-detected]` /
`[waf-pacing-armed]` line above the tail window is reprinted above it under a
"N earlier notice(s)" header.

### `log` respects `$VIGOLIUM_DB_PATH`

`log` reads through the same path `finding`/`traffic` do, so a shell pinned with
`$VIGOLIUM_DB_PATH` (or `-S --db <file>`) reaches that session's database with
project scoping off.

### log ls

`vigolium log ls` prints a merged table of native + agentic sessions (kind, UUID, status, target, log availability, size, creation time). Status is color-coded. A tip at the bottom shows how to tail a specific UUID.

### Examples

```bash
# Table of sessions
vigolium log ls
vigolium log                               # same as `log ls`

# Interactive picker
vigolium log --tui

# Stream a session's log, auto-following if it's still running
vigolium log 550e8400-e29b-41d4-a716-446655440000

# Tail the last 500 lines
vigolium log <uuid> --tail 500

# Full log, no follow, strip ANSI for grep
vigolium log <uuid> --full --strip-ansi | grep -i sqli

# Force follow
vigolium log <uuid> -f

# One JSON document: the --tail window as items {text, time?, level?, phase?} (--follow has no -j form)
vigolium log <uuid> --tail 100 -j
```

---

## doctor

**Usage:** `vigolium doctor`

Run a health check on the installation: verifies the config and database paths, external binaries (`claude`, `codex`, `nuclei`, `kingfisher`), directory permissions, and extracted preset data. Use this after `vigolium init` or when an `agent` backend refuses to launch.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--fix` | bool | `false` | Auto-install / repair every failing check instead of only reporting it |
| `--only` | []string | — | Restrict to specific components: `nuclei`, `chrome`, `bun`, `claude`, `agent-browser`, `pi`, `piolium`. With `--fix`, fixes only those - and the output narrows to just those checks |
| `--strict` | bool | `false` | Exit 1 when the verdict is `degraded`, not only when it is `not_ready` |

Exit status follows the verdict, after the report is written: `not_ready`
(no usable database) exits 1 with `error.code: not_ready`; `degraded` exits 0
unless `--strict`. Gate on the exit code, or read `.status` from `doctor -j`
(a read envelope: `items[0]` is the full report and `status` is copied to the
top level; under `--fix` it is the re-checked verdict, with `fixes` and
`updated` beside it).
The report also carries a `scope` check (the `config validate` scope rules;
an error degrades the verdict) and an `oast` check (DNS + TLS reachability of
the interactsh server; never affects the verdict).

```bash
vigolium doctor                          # report only
vigolium doctor --json                   # the machine-readable form an agent should gate on
vigolium doctor --fix                    # install/repair everything that failed
vigolium doctor --fix --only nuclei,chrome
```

`--fix` **downloads and installs software** (a browser, nuclei templates, an
agent CLI). That is the right move on a fresh box and the wrong one on a
locked-down runner, so scope it with `--only` rather than firing it blind at a
single missing check.

---

## db

**Usage:** `vigolium db <subcommand> [flags]`

Manage database records. Parent command for `clean`, `export`, `list` (`ls`), `seed`, and `stats`.

### Shared db flags (persistent)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--table` | string | — | Database table: http_records, findings, scans. **Deprecated for `db list`** — prefer the positional table name (`db ls findings`); still used by `db clean --table` |
| `--search` | string | — | Quick search across record fields |

---

## db list

**Usage:** `vigolium db list [table] [flags]` (aliases: `ls`)

List database records with filtering, sorting, and display options. The target table is a **positional** argument (`db ls findings`), defaulting to `http_records`; the `--table` flag is a deprecated alias.

### Display flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--tree` | bool | `false` | Hierarchical tree format |
| `--raw` | bool | `false` | Full raw HTTP request and response |
| `--list-tables` | bool | `false` | List all database table names |
| `--list-columns` | bool | `false` | List column names for the current table |

### Pagination flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--limit` | `-n` | int | `100` | Max records to display |
| `--offset` | — | int | `0` | Records to skip |

### Column selection flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--columns` | []string | — | Columns to include (`db ls` has no `--exclude-columns`) |

### Filter flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--uuid` | []string | — | Select exact stored record(s) by UUID (repeatable/comma-separated), applied before pagination |
| `--url` | []string | — | Select records whose URL matches **exactly** (repeatable; OR-ed). No normalization — use `--path`/`--search` for substring matching |
| `--host` | string | — | Filter by hostname pattern (wildcard supported) |
| `--method` | []string | — | Filter by HTTP method |
| `--status` | []int | — | Filter by HTTP status code |
| `--path` | string | — | Filter by URL path pattern |
| `--scan-uuid` | string | — | Filter by scan session ID |
| `--severity` | string | — | Filter findings by severity |
| `--min-risk` | int | `0` | Show only records with risk score at or above this value |
| `--min-surface` | int | `0` | Show only records with **attack-surface** score at or above this value (0-100, percent of the attack-surface signals present) |
| `--remark` | string | — | Filter records containing this text in remarks |
| `--module-type` | string | — | Filter findings by module type (active, passive, nuclei, agent, source-tools, oast, extension) |
| `--finding-source` | string | — | Filter findings by source (dynamic-assessment, spa, agent, oast, source-tools, extension) |
| `--record-kind` | string | `finding` | Filter findings table by record kind (finding, candidate, observation; comma-separated) |
| `--from` | string | — | Records after date (YYYY-MM-DD or RFC3339) |
| `--to` | string | — | Records before date (YYYY-MM-DD or RFC3339) |
| `--header` | string | — | Search **only the header block** of the request/response — not bodies. Use `--search` to span the whole exchange |
| `--body` | string | — | Search **only the request/response body** — not headers. Use `--search` to span the whole exchange |

### Sorting flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--sort` | string | `created_at` | Sort field: uuid, created_at, sent_at, method, status_code, response_time, risk_score, surface_score |
| `--asc` | bool | `false` | Sort ascending |

### Agent JSON output flags

With `-j`/`--json`, `db ls` emits the same compact, token-aware object as `finding`/`traffic` and accepts the shared shaping flags: `--compact` (metadata only), `--fields a,b,c` (project top-level keys), `--full-body` (complete bodies), `--max-output-bytes N` (cap the whole document at N bytes, dropping whole trailing items). `--with-records` is finding-only. Most `-j` commands (including `db stats`) use the **same envelope** — `{schema_version, command, kind, ok, project_uuid, project_scoped, db_path, total, offset, limit, items, query, query_argv, generated_at, generated_at_ms}`, with `items` canonical and always an array. The old row key (`records`/`findings`/`scans`/`rows`) is no longer emitted by default — it shipped a **second full copy of the array** on the wire; `--json-legacy-keys` (or `VIGOLIUM_JSON_LEGACY_KEYS=1`) restores it at that cost. See [invariants.md → The `-j` envelope](invariants.md#the--j-envelope).

Notes on this command:

- `--list-tables` / `--list-columns` honor `-j` and emit the envelope (plain ANSI text without it).
- `--fields` applies on every table including `scans`, and an unknown name is a usage error (exit 2) listing the valid set.
- `--uuid <uuid>` selects exact record(s), applied before pagination.
- `-S`/`--stateless` turns project scoping off here as it does on `finding`/`traffic`, so a standalone export whose rows carry another `project_uuid` is readable.
- The envelope's `project_scoped` says whether a project filter was actually applied; `project_uuid` is absent when it was not.

**`--min-surface` vs `--min-risk` - two scores, two different questions.** They
are deliberately separate columns, so filtering on the wrong one quietly gives
you the wrong shortlist:

| | `--min-surface` (`surface_score`) | `--min-risk` (`risk_score`) |
|---|---|---|
| Asks | "is this record *worth attacking*?" | "is this record *unusual*?" |
| Computed from | the record itself - the percentage of the surface signals present: input carried or advertised, method, uploads, the host's tech stack, legacy handlers, a session, a login boundary, a non-standard port, response shape, and origin posture (dynamic, permissive CORS, leaked internals, API) | rank-within-batch percentile against whichever records were flushed alongside it |
| Reproducible | **yes** - same record, same score, every scan | no - depends on the batch |
| Reads back as | percent of surface signals present | a relative percentile |

So `--min-surface 50` means "at least half the signals fired" - a stable
shortlist for picking fuzz targets out of a big crawl. Treat the number as a
percentage, not a signal count: the signal set grows between releases and the
scale rescales with it, so a threshold ports across versions but "N of M
signals" does not.

A bare host sweep (`run probe`) only ever observes a GET with no session, so the
signals that need a request *you* shaped - input carried, a mutating method, an
upload, a session in hand - cannot fire there. Probe scores therefore top out
well under 100; compare them against each other, not against scores from a full
scan. Pair it with the matching sort:

```bash
vigolium db ls --min-surface 50 --sort surface_score -n 20
```

### Examples

```bash
vigolium db ls
vigolium db ls findings
vigolium db ls scans
vigolium db ls findings --severity critical,high
vigolium db ls --host example.com --method POST --status 200
vigolium db ls --list-tables
vigolium db ls --list-columns --table findings
vigolium db ls --tree
vigolium db ls --raw --limit 5
```

---

## db stats

**Usage:** `vigolium db stats [flags]`

Show database statistics including record counts, finding breakdowns, and host summaries.

Under `-j/--json` it emits the **standard envelope** like every other read command: the stats report is the one element of `items` (`items[0]`, `total: 1`), and `--json-legacy-keys` adds it back bare as `stats`.

`items[0].database` names the source: `path` is the file actually opened and `size` is its bytes **including the `-wal`/`-shm` siblings** — on a WAL store the main file alone can be a fraction of what the store occupies. The human view carries the same as a `Source:` line under `Driver:`.

### stats-specific flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--detailed` | bool | `false` | Show per-host and per-module breakdown |
| `--scan-uuid` | string | — | Stats for a specific scan session |
| `--host` | string | — | Stats for a specific hostname |

### Examples

```bash
vigolium db stats
vigolium db stats --detailed
vigolium db stats --host example.com
vigolium db stats --watch 10s
```

---

## db migrate

**Usage:** `vigolium db migrate [-j]`

Upgrade the store to this vigolium's schema and report the steps applied. Read commands open a query-only pool and never take the write lock; when one meets a store written by an older vigolium it migrates it first through a short-lived writer while `database.auto_migrate_on_read: true` (the default for this release). With that set to `false` the read fails with `error.code: "schema_outdated"` and points here.

A store a newer vigolium already migrated is refused with `error.code: "schema_too_new"` (reads still work when its `min_reader_version` allows; writes do not). `-j` emits a mutation document: `changed`, `action` (`migrate` or `noop`), and `items[0]` = `{from_version, to_version, min_reader_version, written_by, applied[], already_current}`. A `--db` path that does not exist is `source_missing`, never a new empty store.

```bash
vigolium db migrate
vigolium db migrate --db ./engagement.sqlite -j
```

A read that keeps hitting another process's write lock past its retry budget fails with `error.code: "database_locked"`; retry once the writer finishes.

---

## db export

**Usage:** `vigolium db export [flags]`

Export database records in various formats.

### export-specific flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--format` | `-f` | string | `jsonl` | Export format: jsonl, json, raw, csv, markdown, markdown-table, `bundle`, `fs` (flat traffic/finding tree, honors these filters) |
| `--report-url` | — | string | — | URL for the "Raw Report URL" button in HTML reports |
| `--output` | `-o` | string | stdout | Output file path |
| `--host` | — | string | — | Filter by hostname pattern |
| `--method` | — | []string | — | Filter by HTTP method |
| `--status` | — | []int | — | Filter by status code |
| `--path` | — | string | — | Filter by URL path pattern |
| `--scan-uuid` | — | string | — | Filter by scan session ID |
| `--severity` | — | string | — | Filter by severity level |
| `--from` | — | string | — | Export records created after this date (YYYY-MM-DD) |
| `--to` | — | string | — | Export records created before this date (YYYY-MM-DD) |
| `--limit` | — | int | `0` (unlimited) | Max records to export |
| `--offset` | — | int | `0` | Records to skip |
| `--uuid` | — | string | — | Export exactly one record by UUID. Works on every format including `fs`, resolved in SQL before paging |
| `--request-only` | — | bool | `false` | Export only HTTP requests, omitting responses (raw format only) |

Under `-j`, `db export` needs `-o` (exit 2 otherwise: the export would share stdout with the document) and prints a receipt: `items` = the files written `[{format, path, detail?}]`, `counts.records`.

### Notes

- Flags are validated **before** the destination is opened, so a bad `--format`
  or date range leaves an existing `-o` file intact.
- `--uuid` works on every format including `fs`, and is resolved in SQL before
  paging, so a record outside the current page is found rather than reported
  missing. It narrows **both halves** of an `fs` tree: the selected record's
  `.req`/`.resp.headers`/`.resp.body`, and the findings *linked to it* — not
  every finding in the store beside one request.
- `--search` binds to the same plain search term on every format.
- `--format fs` is the **only** export path that decodes a gzip body past 1 MiB.
  Use it, not `-j`, whenever you need a large body whole — a `-j` body carrying
  `decoder_capped: true` is a prefix (see
  [agent-loop.md → Token discipline](agent-loop.md#token-discipline)).

### Examples

```bash
vigolium db export -f jsonl -o records.jsonl
vigolium db export -f csv -o records.csv --host example.com
vigolium db export -f markdown -o report.md
vigolium db export -f raw --request-only -o requests.txt
vigolium db export --format fs -o run --host example.com
vigolium db export --uuid abc12345
```

---

## db clean

**Usage:** `vigolium db clean [flags]`

Delete database records with filtering. Destructive operations require `--force`.

### clean-specific flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--all` | bool | `false` | Delete all records (requires `--force`) |
| `--host` | string | — | Delete records matching hostname |
| `--scan-uuid` | string | — | Delete records by scan session |
| `--before` | string | — | Delete records before date (YYYY-MM-DD) |
| `--status` | []int | — | Delete by HTTP status code |
| `--severity` | string | — | Delete findings by severity |
| `--dry-run` | bool | `false` | Show what would be deleted without deleting |
| `--orphans` | bool | `false` | Delete findings with no matching HTTP record |
| `--findings-only` | bool | `false` | Delete findings only, keep HTTP records |
| `--table` | string | — | Delete all rows from a specific table |

### Special behavior

- VACUUM runs automatically after every delete to reclaim disk space (SQLite).
- `db clean` with **no selector** is rejected (it never implicitly wipes the DB). Use `--all --force` to delete every row, or `db reset --force` to delete and recreate the database file.
- `--all` without `--force`: error (`--all --dry-run` needs no `--force`).
- `--severity` with no mode flag deletes findings only; HTTP records stay.
- Without `--force`: interactive confirmation prompt.
- `-j`: one mutation document, `items:[{table, rows}]` with one row per table touched (the mode's own table first), plus `rows_matched`/`rows_deleted` (totals over every table), `mode`, `scope`; `--dry-run` runs the delete and rolls it back, so its counts are exact, and gives `dry_run:true, changed:false`.

### Examples

```bash
vigolium db clean --scan-uuid my-scan
vigolium db clean --host old-target.com --force
vigolium db clean --before 2024-01-01 --dry-run
vigolium db clean --all --force        # delete every row (auto-VACUUM)
vigolium db clean --orphans
vigolium db clean --findings-only --severity info
vigolium db reset --force              # delete + recreate the database file
```

---

## db compact

**Usage:** `vigolium db compact [flags]`

Shrink every stored request or response body larger than `--body-over` to its first `--keep-head` bytes. Records are never deleted: URL, method, status, headers, content type, `response_content_length`, hashes and timing are untouched, and the stored message keeps its whole header block. SQLite only.

### compact-specific flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--body-over` | size | `64k` | Compact a body larger than this |
| `--keep-head` | size | `4k` | Bytes of each compacted body kept (must be smaller than `--body-over`) |
| `--skip-content-type` | globs | — | Never compact a record whose response media type matches (e.g. `'*javascript*'`) |
| `--only-content-type` | globs | — | Compact only records whose media type matches (OR'ed with `--only-path`) |
| `--skip-path` | globs | — | Never compact a record whose URL path matches (e.g. `'*.js'`) |
| `--only-path` | globs | — | Compact only records whose URL path matches |
| `--older-than` | time | — | Only records sent strictly before this (`30d`, `12h`, a date, RFC3339 — same syntax as `db clean --before`) |
| `--max-db-size` | size | — | Budget: compact the oldest records first (by `sent_at`) until the file would be at most this size after VACUUM |
| `--all-projects` | bool | `false` | Compact every project in the file instead of the active one |
| `--dry-run` | bool | `false` | Report what would be compacted; change nothing |
| `--no-vacuum` | bool | `false` | Skip the closing VACUUM + WAL checkpoint |

Sizes are a byte count or a number with a `k`/`m`/`g` suffix, binary (`64k` = 65536). Globs use `*` (any run, `/` included) and `?`, case-insensitive; content types are matched without parameters, paths without the query string. A skip glob always wins over an only glob.

### What a compacted record carries

`http_records.body_compaction` (also the `body_compaction` key of `traffic -j`) is NULL for a record stored as captured, and otherwise:

```json
{"version":1,"compacted_at":"2026-10-09T00:00:00Z","keep_head":4096,
 "response":{"original_length":312004,"sha256":"<hex of the original body>","kept_length":4096},
 "request":{"original_length":...,"sha256":"...","kept_length":...}}
```

Only the compacted parts appear. A compacted part is never compacted again, so repeating a pass is a no-op.

### Special behavior

- A real pass asks for confirmation on a terminal and needs `--force` otherwise; `--dry-run` never asks.
- With `--max-db-size` the command exits 0 whether or not the budget was reached; `budget_met: false` means everything selected was compacted and the file is still over budget, and `remaining` counts selected records a met budget left whole.
- VACUUM runs after a pass that compacted something, or when the file is over `--max-db-size` and has free pages to return; an idle pass skips it.
- `-j` emits one mutation envelope (`command: "db compact"`, `kind: "mutation"`, `action: "compact"`, `changed`, plus `dry_run: true` on a dry run) whose `items[0]` is the summary: `dry_run`, `records_compacted`, `response_bodies_compacted`, `request_bodies_compacted`, `body_bytes_before`, `body_bytes_after`, `db_bytes_before`, `db_bytes_after` (file + WAL; estimated on a dry run), `max_db_size`, `budget_met`, `remaining`, `vacuumed`.
- A build without this command answers `vigolium db compact --help` with the `db` help and exit 0, so probe for the flag (`--max-db-size` in the help text), not the exit code.

### Examples

```bash
vigolium db compact --db traffic.sqlite --dry-run
vigolium db compact --db traffic.sqlite --older-than 30d --force
vigolium db compact --db traffic.sqlite --all-projects --max-db-size 2g \
  --skip-content-type '*javascript*,*ecmascript*' --skip-path '*.js,*.mjs' --force -j
```

---

## db seed

**Usage:** `vigolium db seed [flags]`

Populate database with sample data for development and testing.

### Examples

```bash
vigolium db seed
```

---

## finding

**Usage:** `vigolium finding [search-term] [flags]` (aliases: `findings`)

Browse vulnerability findings with fuzzy search, filtering, raw display, and column selection.

### Finding-specific filter flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--severity` | — | string | — | Filter by severity: `critical,high,medium,low,suspect,info` (comma-separated; shorthands OK, e.g. `h,c`). Alias: `--sev` |
| `--confidence` | — | string | — | Filter by confidence: `certain,firm,tentative` (comma-separated) |
| `--record-kind` | — | string | `finding` | Filter by record kind: `finding`, `candidate`, `observation` (comma-separated) |
| `--scan-uuid` | — | string | — | Filter by scan session ID |
| `--module-type` | — | string | — | Filter by module type (active, passive, nuclei, agent, source-tools, oast, extension) |
| `--finding-source` | — | string | — | Filter by finding source (dynamic-assessment, spa, agent, oast, source-tools, extension) |
| `--id` | — | int | — | Filter by finding ID — the **integer** from the ID column. A UUID is rejected with the flag that reads that namespace instead (`traffic --uuid` for a record, `--agentic-scan`/`--scan-uuid` for a run); it is never coerced |
| `--min-severity` | — | string | — | Show findings at/above this severity (`info`,`suspect`,`low`,`medium`,`high`,`critical`); ignored when `--severity` is set |
| `--agentic-scan` | — | string | — | Findings from an agent run; one root UUID expands to the whole run tree (audit driver legs / swarm sub-runs) |
| `--verdict` | — | string | — | Filter by lifecycle status: `draft,triaged,confirmed,false_positive,accepted_risk,fixed` (comma-separated; set with [`finding mark`](#finding-mark)). Not `--status`, which is the HTTP status code |
| `--new-since` | — | string | — | Only findings new since a scan — a UUID, an 8+ char prefix, `latest` or `previous`: first observed by a later scan and **not** observed by it — or since a time (`24h`, `2d`, a date: stored after it). Leaves out `false_positive`/`accepted_risk` unless `--include-dismissed` or `--verdict`. An unknown scan is an error (`scan_not_found`), never an empty list |
| `--include-dismissed` | — | bool | `false` | With `--new-since`: keep findings marked `false_positive`/`accepted_risk` |

### Display flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--raw` | bool | `false` | Show full raw HTTP request and response for each finding |
| `--burp` | bool | `false` | Display in Burp Suite-style format (colored request/response) |
| `--tree` | bool | `false` | Display as a host/path hierarchy tree (repeated titles collapse into one node) |
| `--markdown` | bool | `false` | Render the matched findings as Markdown (evidence + request/response in fenced blocks) to stdout |
| `--pick` | string | — | Select finding(s) by 1-based position after filters + sort (e.g. `2`, `1,3`, `2-4`) |
| `--curl` | bool | `false` | Render each finding's proving request (its stored evidence, else its first linked record) as a curl command (see [finding --curl](#traffic---curl--finding---curl)) |
| `--curl-all` | bool | `false` | Like `--curl`, but one command per linked HTTP record |
| `--redact-auth` | bool | `false` | With `--curl`/`--curl-all`: mask Authorization/Cookie/API-key header values as `<redacted>` |
| `--columns` | []string | — | Columns to show (comma-separated, e.g. ID,SEVERITY,MODULE) |
| `--exclude-columns` | []string | — | Columns to hide (comma-separated) |
| `--stateless` / `-S` + `--glob-db` | bool / string | — | Read from a `.jsonl`/`.sqlite` export (or a glob merged into one temp DB) with project scoping off |

### Pagination and sorting flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--limit` | `-n` | int | `100` | Maximum findings to display |
| `--offset` | — | int | `0` | Number of findings to skip (for pagination) |
| `--sort` | — | string | `found_at` | Sort by: found_at, created_at, severity, module, confidence |
| `--asc` | — | bool | `false` | Sort in ascending order |

### Additional filter flags

Also accepts: `--host`, `--method`, `--status`, `--path`, `--from`, `--to`, `--source`, plus `--search` (repeatable, AND-combined; searches module metadata, matched location, and the linked request/response), `--header`, `--body`, and their inverses `--exclude-search` (repeatable), `--exclude-header`, `--exclude-body`.

Every search term is matched **literally**: `%` and `_` are ordinary characters, not SQL wildcards, so `--body 'api_key'` does not also match `api-key` and `--body '100%'` does not match everything. `--host`/`--path` remain patterns where `*` is the wildcard.

### Finding → Burp push flags (triage handoff)

Hand each selected finding's evidence request (and response, where available) to Burp for manual confirmation. This is an action, not a display: it returns before any table/JSON render and never runs the scanner. Only `finding` has these (traffic/`db ls` do not).

`--push-to-burp` (Organizer) and `--to-repeater` are **independent destinations that compose**, exactly as they do on `vigolium replay` — one invocation can file a finding *and* open it. `--to-repeater` alone still means Repeater only.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--push-to-burp` | — | bool | `false` | Push the selected finding(s)' evidence request+response to Burp's Organizer for manual confirmation; requires `--burp-bridge-url` |
| `--to-repeater` | — | bool | `false` | Also stage the finding(s) in a Burp Repeater tab (respects Burp's 30-tabs/min cap; warns above 20 findings). Composes with `--push-to-burp` |
| `--send-via-burp` | — | bool | `false` | With `--push-to-burp`/`--to-repeater`: re-issue the request through Burp's engine and store the fresh response |
| `--burp-bridge-url` | `-B` | string | `$VIGOLIUM_BURP_BRIDGE_URL` | Loopback Burp bridge URL used by `--push-to-burp` / `--to-repeater` |
| `--http-mode` | — | string | — | With `--send-via-burp`: wire protocol — `auto`\|`http1`\|`http2`\|`http2_ignore_alpn` (default `auto`) |

### Agent JSON output flags

With `-j`/`--json`, `finding` emits **one compact, token-aware object** (bodies preview-capped at ~2 KiB, binary/static stubbed, each finding gets a ±240-char `response_evidence` snippet) instead of a table:

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--json` | `-j` | bool | `false` | Emit the compact agent object (global flag) |
| `--compact` | — | bool | `false` | Metadata only — drop bodies and evidence snippets |
| `--fields` | — | []string | — | Project only these top-level JSON keys (comma-separated) |
| `--full-body` | — | bool | `false` | Complete bodies — no preview caps, no binary/static stubbing |
| `--with-records` | — | bool | `false` | Embed each finding's linked HTTP records as a `records:[…]` triage bundle |
| `--record-limit` | — | int | `20` | With `--with-records`: max records embedded per finding (`0` = no cap). Over the cap the finding also carries `records_total` and `records_truncated: true` |
| `--record-fields` | — | []string | — | With `--with-records`: project the **nested** record rows, independently of `--fields` |

`--compact`, `--fields`, and `--full-body` are shared with `traffic` and `db ls`; `--with-records`, `--record-limit`, `--record-fields`, `--min-severity`, and `--agentic-scan` are finding-only. See [agent-loop.md → Token discipline](agent-loop.md#token-discipline).

Two behaviours to rely on:

- An unknown `--fields` / `--record-fields` name is a **usage error (exit 2)** listing the valid set for that view — it is never dropped silently. `--fields '?'` is a quick way to print the vocabulary.
- `--fields` never removes the `records` array: it was requested by `--with-records`, so the projection narrows the finding's own keys only.
- If the linked records cannot be read, the finding carries `records_error` plus `records_total` rather than looking like a finding with no evidence.

### Available columns

ID, SEVERITY, CONFIDENCE, MODULE, MODULE_ID, SHORT_DESC, DESCRIPTION, TYPE, SOURCE, MATCHED_AT, FOUND_AT, SCAN_UUID, TAGS

Default columns: ID, SEVERITY, MODULE, SHORT_DESC, TYPE, SOURCE, MATCHED_AT

### Examples

```bash
vigolium finding
vigolium finding --severity high,critical
vigolium finding --search "sql injection"
vigolium finding --module-type active
vigolium finding --finding-source dynamic-assessment
vigolium finding --id 42
vigolium finding --burp
vigolium finding --raw
vigolium finding --columns ID,SEVERITY,MODULE,MATCHED_AT,TAGS
vigolium finding --sort severity --asc
vigolium db ls findings --watch 5s   # --watch is on the db command, not finding
vigolium finding -j --min-severity high --with-records
vigolium finding -j --agentic-scan 550e8400-e29b-41d4-a716-446655440000
vigolium finding -j --new-since previous --min-severity high   # what the latest scans added
vigolium finding --verdict confirmed,triaged                    # the still-open, believed-real set
```

The `-j` item carries the lifecycle verdict as `status`, plus `status_note` and
`status_actor` when one was recorded (`--fields status,status_note` selects them).

---

## finding load

**Usage:** `vigolium finding load [file] [flags]`

Import findings from a file or stdin. Formats are **auto-detected**: agent output
(`{"findings":[…]}`, markdown-wrapped variants included), a single finding
object, Nuclei-compatible ResultEvent JSONL, or raw database `Finding` JSON - so
you can pipe another tool's output straight in without converting it first.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--finding-file` | string | — | Path to the findings file. Same thing as the positional argument, for callers that would rather name it |
| `--scan-uuid` | string | — | Associate the imported findings with an existing scan UUID, so they join that run instead of floating unattached |

**Input precedence:** positional argument → `--finding-file` → stdin. They do not
merge - the first one present wins, so passing both a positional path and
`--finding-file` silently ignores the flag.

### Examples

```bash
vigolium finding load findings.jsonl
vigolium finding load --finding-file findings.json --scan-uuid <uuid>
cat findings.jsonl | vigolium finding load
vigolium finding load findings.json -j
```

`-j` is a mutation envelope: `items` = the ids of the findings stored (so
`total` counts them), `changed`, `action: "import"`, and top-level `format`,
`parsed`, `saved`, `skipped`. The pre-envelope `total` (the parsed count) is
now `parsed`.

---

## finding mark

**Usage:** `vigolium finding mark <id|hash>... --as <verdict> [--note "…"] [--by <actor>]`

Record a lifecycle verdict on one or more findings. Name each finding by its
numeric id or its `finding_hash` (full, or a prefix of at least 12 characters —
the hash is stable across merges and exports, the id is not). A prefix matching
more than one finding is refused (exit 2) with the candidates listed; nothing is
written.

| `--as` | Meaning |
|--------|---------|
| `false_positive` | not a bug (noise, not exploitable) — **dismissed** |
| `accepted_risk` | real, the owner keeps it — **dismissed** |
| `confirmed` | reproduced (by a human or a re-verification) |
| `triaged` | looks real, not yet reproduced |
| `fixed` | resolved |

Lifecycle: `draft → triaged → confirmed → fixed`, with `false_positive` /
`accepted_risk` as exits. Dismissed findings are left out of the `--fail-on`
gate, `scan diff` and `finding --new-since` by default; reports keep them.

Each change sets the finding's `status_note` / `status_actor` (a new verdict
without `--note` clears the old note) and appends one row to its status history.
A finding already at the verdict is reported `unchanged` and left alone.

`-j` is a mutation envelope: `changed` (bool), `action: "update"`, `items` = the
changes `[{id, finding_hash, from, to}]`, plus `status`, `unchanged`, and
`not_found` (the selectors that matched nothing). **Any `not_found` exits 1**
after the document is written, so a typo is never mistaken for success; ids
from another project are `not_found` too.

Writes to the project DB, or a standalone `.sqlite` with `-S --db <file>`
(project scoping off). Refused (exit 2) under `--glob-db` and for a `.jsonl`
`--db` (both read a temporary copy) and under `--read-only`.

```bash
vigolium finding mark 42 --as false_positive --note "static asset, no user input"
vigolium finding mark 3f9a0c2b71de 43 --as confirmed --by alice -j
```

---

## finding verify

**Usage:** `vigolium finding verify <id|hash>... [--scan-uuid <uuid>] [--mark] [--fail-if <verdicts>] [flags]`

Re-run the module behind each finding against the request it originally
scanned and record whether the finding reproduces. Name findings as for
[`finding mark`](#finding-mark); `--scan-uuid` adds every finding of a scan.

| Verdict | Meaning |
|---------|---------|
| `confirmed` | the module reported the same finding again |
| `not_reproduced` | the module ran against a responding target and did not report it |
| `inconclusive` | no verdict: target unreachable, module timed out or errored, or the baseline could not be rebuilt (`reason` says which) |
| `unsupported` | no deterministic re-run: agent, audit, OAST and known-issue-scan findings, or an `ext-*` module that is not loaded |

**Reconstruction.** The module comes from the finding's `module_id`; an
`ext-*` module is loaded from `--ext` / `--ext-dir` (or the configured
extension directory). The baseline is the finding's `origin_record_uuid` (the
record the module scanned, stored since schema v3); for older findings it is the
linked record when that is a scanned record, otherwise a scanned record on the
same host, method and path that differs from the finding's request in exactly
one insertion point. The insertion point is the stored `insertion_point`
(`{type, name}`), else that single differing point. The module then runs alone
on that point with cross-module dedup and the finding cap off, against a fresh
baseline response. A **passive** finding is re-analyzed on its stored record
and sends nothing; `--refetch` fetches a fresh response first.

**Writes.** The verdict is stored in the finding's `verification`
(`{verdict, at, module_version, scan_uuid, reason}`) and `verified_at`; status
is not changed. `--mark` also moves `not_reproduced` → `false_positive` and
`confirmed` → `confirmed` through the `finding mark` path (status note, actor
`finding-verify`, status history). `--no-write` stores nothing; `--dry-run`
prints the reconstruction (module, baseline request, insertion point) and sends
nothing.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--scan-uuid` | string | — | Also verify every finding of this scan (UUID, 8+ char prefix, `latest`, `previous`; unknown → exit 1 `scan_not_found`) |
| `--mark` | bool | false | Set the status from the verdict (not with `--dry-run` / `--no-write`) |
| `--fail-if` | string | — | Exit 4 when any finding gets one of these verdicts (comma-separated) |
| `--dry-run` | bool | false | Print what would run; send and write nothing |
| `--no-write` | bool | false | Run, but do not store the verdict |
| `--refetch` | bool | false | Passive findings: analyze a fresh response instead of the stored one |
| `--rate-limit` | float | 0 | Max requests/second (0 = unlimited) |
| `--timeout` | duration | 2m | Time limit per finding (one request is capped at 15s) |

`-j` is a mutation envelope: `action: "verify"`, `changed` (a verdict was
stored), `dry_run`, `items` = one object per finding `{id, finding_hash,
module_id, verdict, reason, plan: {baseline, insertion_point,
insertion_point_source, payload, network}, results, matched, requests,
duration_ms, written, status_change}`, plus `verdicts` (count per verdict),
`not_found` and `written`. Any `not_found` exits 1; `--fail-if` exits 4, both
after the document is written. Refused (exit 2) to write under `--glob-db` and
for a `.jsonl` `--db` — use `--no-write` there.

The finding `-j` item carries the replay context and the latest result:
`origin_record_uuid`, `insertion_point`, `payload`, `verification`,
`verified_at`.

```bash
vigolium finding verify 42 -j
vigolium finding verify --scan-uuid 6f1c2a9e --mark --fail-if not_reproduced
vigolium finding verify 3f9a0c2b71de --dry-run
```

---

## traffic

**Usage:** `vigolium traffic [search-term] [flags]`

**Aliases:** `traffics`, `tf`

Browse stored HTTP traffic. Shortcut for `vigolium db ls http_records`. To load
traffic in, see [ingest.md](ingest.md) / [server.md](server.md); to re-send it,
see [loop-confirm.md](loop-confirm.md#bulk-replay).

**Host facts are output-only, not stored.** A `run probe` sweep reports `a`,
`aaaa`, `cname` and `tls` inline in its own `--json` stream, but the schema keeps
only the single `ip` column — a sweep writes several records per host, so storing
the full answer per row would be many copies of one identical, TTL-stale blob.
Reading the same database back later (here, or with `export`) therefore shows
`ip` and no `a`/`aaaa`/`cname`/`tls`. That is correct, not a gap: re-run the
probe if you need them. `surface_score`, `response_time_ms` and `parent_uuid`
**are** stored and queryable.

**`--source probe`** selects a sweep's records; `--sort surface_score` ranks them
by attackable surface (0-100, percent of the surface signals present). `parent_uuid` chains a followed
redirect: `a.example` (301) → `www.a.example` (302) → the 200 that answered.

### Filter flags (persistent, inherited by replay)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--uuid` | []string | — | Select exact stored record(s) by UUID (repeatable/comma-separated). Applied **before** pagination, so `-n`/`--offset` can never hide a match. A UUID as the *positional* term searches text, not identity — use this flag |
| `--url` | []string | — | Select records whose URL matches **exactly** (repeatable; OR-ed), applied before pagination. No normalization or case folding — use `--path`/`--search` for substring matching |
| `--host` | string | — | Filter by hostname pattern (wildcard supported) |
| `--method` | []string | — | Filter by HTTP method (repeatable, e.g. --method GET --method POST) |
| `--status` | []int | — | Filter by HTTP status code (repeatable, e.g. --status 200 --status 404) |
| `--path` | string | — | Filter by URL path pattern |
| `--from` | string | — | Show records after this date (YYYY-MM-DD or RFC3339) |
| `--to` | string | — | Show records before this date (YYYY-MM-DD or RFC3339) |
| `--search` | string | — | Fuzzy search across URLs, paths, and hostnames |
| `--header` | string | — | Search **only the header block** of the request/response — not bodies. Use `--search` to span the whole exchange |
| `--body` | string | — | Search **only the request/response body** — not headers. Use `--search` to span the whole exchange |
| `--source` | string | — | Filter by record source (e.g. scanner, probe, burp, caido, ingest-cli, ingest-server, ingest-proxy, seed) |
| `--scan-uuid` | string | — | Only records **first stored** by this scan (`http_records.scan_uuid`, stamped on insert). A record deduplicated against an earlier scan keeps that scan's uuid. An empty result for a scan that has no stamped records (it predates stamping) carries `provenance_warning: "scan_uuid_not_stamped"` with a `--from/--to` window to use instead; an unknown uuid gives `scan_not_found` |
| `--sort` | string | `created_at` | Sort field: uuid, created_at, sent_at, method, status, time, risk_score, surface_score |
| `--asc` | bool | `false` | Sort in ascending order (default: descending) |
| `--limit` / `-n` | int | `100` | Maximum records to display |
| `--offset` | int | `0` | Number of records to skip (for pagination) |

### Display flags (traffic only)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--tree` | bool | `false` | Display as host/path hierarchy tree |
| `--raw` | bool | `false` | Full raw HTTP request and response |
| `--burp` | bool | `false` | Burp Suite-style colored format |
| `--markdown` | bool | `false` | Render matched records as Markdown (request/response in fenced http blocks) to stdout |
| `--group-by` | string | — | **Count** the matched records by one field instead of listing them: `host`, `method`, `status_code`, `response_content_type`, `source`, `scan_uuid`, `ip`, `is_authenticated`. An unknown name is a usage error listing the set |
| `--group-limit` | int | `20` | With `--group-by`: maximum buckets, largest first (`0` = every bucket) |
| `--curl` | bool | `false` | Render each matched record as a curl command instead of listing it (see [traffic --curl](#traffic---curl--finding---curl)); at most 20 without `-a` |
| `--redact-auth` | bool | `false` | With `--curl`: mask Authorization/Cookie/API-key header values as `<redacted>` |
| `--columns` | []string | — | Columns to show (comma-separated, e.g. HOST,METHOD,PATH,STATUS) |
| `--exclude-columns` | []string | — | Columns to hide (comma-separated) |
| `--exclude-search` / `--exclude-header` / `--exclude-body` | []string / string | — | Inverse-search filters (drop records where the term appears) |
| `--stateless` / `-S` + `--glob-db` | bool / string | — | Read from a `.jsonl`/`.sqlite` export (or a glob merged into one temp DB) with project scoping off |

With `-j`/`--json`, `traffic` emits **one compact, token-aware object** (headers kept, bodies preview-capped, binary/static stubbed) built for coding-agent consumption. Shape it with `--compact` (metadata only), `--fields a,b,c` (project top-level keys), or `--full-body` (complete bodies) — the same contract as `finding`/`db ls`.

### Available Columns

UUID, HOST, METHOD, PATH, STATUS, TIME, SIZE, WORDS, CONTENT_TYPE, SENT_AT, TITLE, AUTH, STATUS_PHRASE, REQ_HEADERS, RESP_HEADERS, SOURCE, REMARKS

Default columns: HOST, METHOD, PATH, STATUS, CONTENT_TYPE, SIZE, WORDS, TIME, TITLE, SOURCE

### Argument Routing

- `vigolium traffic` — default table view
- `vigolium traffic <term>` — fuzzy search
- `vigolium traffic tree` — tree view
- `vigolium traffic list` or `ls` — default table view
- `vigolium traffic body` — extract one message body (below)
- `vigolium traffic headers` — read one message's headers (below)

### Extracting one message: `traffic body` / `traffic headers`

Both take exactly one record — positionally or with `--uuid`, a full UUID or a
unique 8+ character prefix (`uuid_short`) — and one side: `--response` (the
default) or `--request`. They always open the source read-only. Neither re-sends
anything; that is `vigolium replay`.

```bash
# Save a response body to a file (atomic write, exact bytes)
vigolium traffic body <id> -o response.json
vigolium traffic body --uuid <id> -o response.json
# Pipe it instead
vigolium traffic body --uuid <id> | jq .
# Just the receipt: size, sha256, completeness — no body in the output
vigolium traffic body --uuid <id> -j
# The request side
vigolium traffic body --uuid <id> --request -o request.txt
# Compressed bytes exactly as captured, no decoding
vigolium traffic body --uuid <id> --representation stored -o body.gz

# Headers as an ordered array — duplicates survive, unlike a map
vigolium traffic headers --uuid <id> -j
# Every value of one header, case-insensitively
vigolium traffic headers --uuid <id> --name set-cookie -j
```

`--representation` defaults to `decoded` (supported content encodings removed);
`stored` returns the captured bytes untouched. A body whose decode would be
partial fails with `body_incomplete` rather than writing a prefix — pass
`--allow-incomplete` to write it anyway, and the receipt keeps `complete: false`.

Each state has its own `error.code`:

| Condition | `error.code` |
|---|---|
| No record with that UUID | `record_not_found` |
| A prefix matches several records (they are listed) | `ambiguous_id` |
| Record exists, that side was never captured | `body_unavailable` |
| Announced encoding could not be undone | `body_decode_failed` |
| Only a prefix is available | `body_incomplete` |

A body that was captured and is genuinely zero-length **succeeds**, with
`empty: true` in the receipt — that is not the same as never having been
captured.

### Terse rows: `--format tsv`

One header line, then one line per record, nothing else on stdout. Columns are
`--fields` names (aliases included); the default is
`uuid_short,status_code,method,response_content_length,url`. Tabs, newlines and
backslashes in a value are escaped, so every row is one line with one cell per
column. `--no-header` drops the header. `-j` and `--format tsv` are exclusive.

```bash
vigolium traffic --host api.example.com --format tsv
vigolium traffic --format tsv --fields uuid_short,status,length,title,url --no-header
```

`finding`, `endpoints`, `params`, `hosts` and `dns` take `--format tsv` too.

### Field names and aliases

`--fields` accepts every key a row can carry, plus the shared aliases, and the
row comes back with the names you passed: `status`/`code` → `status_code`,
`length`/`size`/`body_size` → `response_content_length`, `words`, `time`,
`content_type`, `title`, `id` → `uuid`, `headers` → `response_headers`. An unknown
name fails before any query and suggests the nearest one. Three keys appear only
when named:

| Key | Value |
|---|---|
| `uuid_short` | The 8-character prefix every record flag accepts |
| `response_headers` | The response's header block, without its body |
| `matches_not_found` | Whether the response is its origin's not-found page: a 404/410, or a match against the baseline `vigolium fingerprint` stored. Absent when the origin has no baseline |

`--exclude-not-found` drops those records from the returned page and reports
how many under `not_found_excluded`.

### Saving a `-j` result: `-o/--output`

`traffic`, `finding` and `db ls` accept `-o <path>` alongside `-j`: the result
document goes to the file and a small receipt (path, bytes, sha256, whether the
file is one page or the whole result) takes its place on stdout. `-o -` forces
stdout. The file is byte-identical to what the same command prints without `-o`.

```bash
vigolium finding -j -n 500 -o findings.json
vigolium traffic -j --compact -n 1000 -o traffic.json
```

For a rendered report or a bulk dump, `vigolium export -o <path> --format <fmt>`
is still the right command; `-o` here only saves the `-j` document.

### Examples

```bash
# Browse all traffic
vigolium traffic

# Fuzzy search
vigolium traffic login
vigolium traffic api/v2

# Tree view
vigolium traffic --tree

# Burp-style output
vigolium traffic --burp

# Filter by host and method
vigolium traffic --host api.example.com --method POST,PUT

# Filter by status code
vigolium traffic --status 200,301

# Date range
vigolium traffic --from 2024-01-01 --to 2024-06-30

# Only records that came in from the recording proxy
vigolium traffic --source ingest-proxy --tree

# Custom columns
vigolium traffic --columns HOST,METHOD,PATH,STATUS,AUTH

# Count instead of listing — the same filters, a dozen integers back
vigolium traffic --group-by status_code --host api.example.com
vigolium traffic -j --group-by response_content_type --group-limit 5
```

**`--group-by` runs the same filters the listing would**, so the buckets describe
exactly the rows `traffic` would have shown — it is the answer to "how many
records share this value" without paying for the records. Under `-j`, `items` is
the bucket list (`{value, count}`), `total` is the number of buckets, and
`total_records` / `other_groups` / `other_records` state what was counted and
what the limit left out. It cannot be combined with a flag that renders records
(`--raw`, `--burp`, `--markdown`, `--tree`, `--replay`, the `--save-to-*` pair):
one counts, the other prints.

---

## traffic --replay

Re-sending stored traffic — both `traffic --replay` (human comparison table,
`--with-browser`) and the top-level `vigolium replay` (structured JSONL diffs) —
is documented with the rest of the confirm/hand-off workflow in
**[loop-confirm.md](loop-confirm.md#bulk-replay)**.

Burp-bridge **listing** sync flags stay here because they operate on the
`traffic` listing, not on replay:

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--burp-bridge-url` / `-B` | string | `$VIGOLIUM_BURP_BRIDGE_URL` | Merge live traffic from this loopback Burp bridge URL with local DB records |
| `--save-to-vigolium-db` | bool | `false` | Persist the live Burp records selected by the active filters into the database (requires `--burp-bridge-url`; not with `--replay`). The **write** is not bounded by `-n`'s listing default — an untyped `-n` does not truncate the import at 100 records; a typed `-n` is honored and warns when it bit |
| `--save-to-burp` | bool | `false` | Copy the DB records selected by the active filters into Burp's Target site map (requires `--burp-bridge-url`; not with `--replay`) |

The two `--save-to-*` flags are mutually exclusive with `--replay`.

---

## traffic --curl / finding --curl

Render stored requests as curl commands — the hand-off for re-sending one
exchange by hand. Nothing is sent.

```bash
vigolium traffic --uuid <id> --curl
vigolium traffic --host api.example.com --path /login --curl -j
vigolium finding --id 42 --curl
vigolium finding --id 42 --curl-all --redact-auth
```

- The URL comes from the record's stored **scheme, host and port**, never from
  the `Host` header alone. A `Host` that matches the URL is dropped (curl sends
  it); a different one (virtual host) is kept.
- Every argument is POSIX single-quoted, so the command is safe to paste or run
  with `sh -c` — `$`, backticks, quotes and newlines in a body survive.
- A body that is not printable UTF-8 is piped in:
  `printf '%s' <base64> | base64 --decode | curl … --data-binary @-`.
- `--http2` for HTTP/2 records, `--path-as-is` for `..`/`.` segments or `%2f`,
  `--compressed` when the request had `Accept-Encoding`, `-g` when the URL holds
  `[]`/`{}`. `Content-Length` and `Transfer-Encoding` are dropped (curl
  recomputes them).
- `traffic --curl` renders at most **20** commands unless `-a` asks for all.
  `--curl` cannot be combined with `--replay`, `--group-by` or another view.
- Credentials are printed as stored. `--redact-auth` masks them; when stdout is
  not a terminal and commands carry credentials, a note on stderr says so.

`finding --curl` renders the finding's own stored evidence request (the one the
module sent) when present, else its first linked record; `--curl-all` renders
every linked record.

Under `-j` the envelope's `items` are the commands:
`traffic` gives `{uuid, method, url, curl, argv}` and `finding` gives
`{id, finding_hash, record_uuid, method, url, curl, argv}` (`record_uuid` is
empty when the finding's own evidence was used). `argv` is the exec vector;
when `stdin_base64` is set, write its decoded bytes to curl's stdin.

---

## endpoints

**Usage:** `vigolium endpoints [search-term] [flags]` · **Alias:** `endpoint`

The application's endpoint inventory, aggregated from stored traffic: one row
per **origin + path template**, with every method seen on it.

```bash
vigolium endpoints
vigolium endpoints --host api.example.com -j
vigolium endpoints --source jstangle --sort findings     # routes known from JS
vigolium endpoints --remark jstangle:not_found           # JS routes that 404'd
vigolium endpoints --scan-uuid <uuid> --min-records 2
vigolium endpoints --collapse 5 -n 0                     # merge slug siblings
```

- Paths group by structural template (the shared `pathshape` normalizer):
  `/users/42` and `/users/7` are `/users/{int}`; uuids, long hex, dates,
  timestamps, emails, JWTs and base64 blobs collapse too. `/users/me`, `/about`
  and `v1` stay literal.
- `--collapse N` (off by default) also merges N or more sibling literal
  segments with the same child templates into `{var}` (`/blog/a`, `/blog/b`, …
  → `/blog/{var}`). It can merge real routes, so it is opt-in.
- The filters are `traffic`'s (`--host`, `--method`, `--status`, `--path`,
  `--source`, `--remark` (repeatable, AND), `--scan-uuid`, `--from/--to`, the
  positional search term, `-S`, `--db`, `--glob-db`), so the aggregate covers
  exactly the records `traffic` would list. Bodies are never read; the pass
  streams light columns, so it is safe on large corpora.
- `--min-records N`, `--sort records|findings|template|last_seen`, `-n`
  (default 100, `0` = all) and `--offset` page the endpoint list, not the records.

Each `-j` item:

| Field | Meaning |
|---|---|
| `id` | Stable id: sha1(origin + " " + template), 12 hex chars — the same in every DB |
| `origin`, `host`, `template`, `methods` | What the endpoint is |
| `records`, `distinct_paths` (`distinct_paths_capped`), `sample_paths` (≤3) | How often, how many concrete paths |
| `params` | Parameter names by location (`query`, `body`, `json`, `cookie`, `xml`, `multipart`, `path`), ≤50 each; `param_count` totals them |
| `request_content_types`, `response_content_types` | Top 5 media types |
| `status`, `top_status` | Status-code histogram |
| `auth` | `{authenticated, anonymous}` record counts (auth flag or an `Authorization` header) |
| `sources`, `js_outcomes` | Record sources; `jstangle:*` outcomes (`found`, `not_found`, `withheld`, …) of JS-derived records |
| `findings`, `findings_by_severity`, `max_severity` | Live findings whose URL maps here (`false_positive`/`accepted_risk` excluded) |
| `first_seen`, `last_seen` | Record timestamps |

The envelope adds `records_scanned`, `capped`/`unbucketed_records` (a 100,000
distinct-endpoint safety cap; overflow is counted, never dropped silently) and
a `query` follow-up: `vigolium traffic --host <h> --path <template glob> -j`.
`--scan-uuid` provenance warnings are the same as `traffic`'s.

---

## params

**Usage:** `vigolium params [search-term] [flags]` · **Aliases:** `param`, `parameters`

Every parameter of every endpoint, with a value-type histogram — the starting
point for IDOR and param-mining work.

```bash
vigolium params --host api.example.com
vigolium params --type integer,uuid,sequential_id -j    # IDOR candidates
vigolium params --endpoint <endpoint-id> --show-values
vigolium params --location query,json --min-occurrences 3
vigolium params --paths --method POST,PUT -j             # JSON body shapes per operation
```

- One row per (endpoint, location, name); `endpoint_id` is the `endpoints` id.
- Dynamic path segments are parameters too: location `path`, named
  `{kind}@index` (`{int}@1` in `/users/{int}`), with `after` naming the literal
  segment before it.
- `types` is a `mutation.Classify` histogram over at most **200** values per
  parameter (`classified` says how many); `dominant_type` is its mode.
  `distinct_values` stops counting at 1000 (`distinct_capped`).
- `samples` (≤3, ≤64 chars) are **redacted by default** for cookies, headers
  and secret-looking names (token, session, password, key, auth, …) —
  `--show-values` prints them. The envelope says `values_redacted`.
- Filters: everything `endpoints` takes, plus `--endpoint <id|template>`,
  `--location <list>`, `--type <value types>` (dominant type; an unknown name is
  a usage error listing the set) and `--min-occurrences N`.
- `--paths`: JSON body shapes per operation, never values — `method`, `template`, `key_path`
  (`user.name`; arrays share their path), `json_type`/`json_types`, `sample_count` of
  `operation_records` (fewer = optional key); `records_without_paths` counts older rows.

## hosts

**Usage:** `vigolium hosts [host-pattern] [flags]`

Reads stored host facts, one row per host:port (the latest observation; `--history`
for every run's): DNS answers (`vigolium dns`, the probe phase — port 0 for a
DNS-only row), the TLS handshake and certificate (`fingerprint`, `run probe
--tls-probe`), the icon hash (`fingerprint`, `run probe --favicon`), the
fingerprint report and the not-found baseline. Never sends a request.

| Flag | Effect |
|---|---|
| `--host <pattern>` | Hostname or `*` wildcard (same as the positional) |
| `--scan-uuid <uuid>` | Only one run's observations |
| `--has dns\|tls\|favicon\|fingerprint\|not-found` | Only hosts carrying that fact (`favicon`: the probe's `--favicon` read) |
| `--soft-404` | Only origins answering 2xx/3xx to a missing path |
| `--sans` | Distinct certificate DNS names, one per line (wildcards dropped) |
| `--fields`, `--compact`, `--format tsv`, `-n`, `--offset` | Shaping and paging |

Rows lift the survey facts to the top — `title`, `server`, `status_code`,
`technology`, `favicon_mmh3`, `soft_not_found`, `tls_version`, `cert_not_after`,
`sans` — beside `a`/`aaaa`/`cname`/`mx`/`ns`/`txt`/`soa`/`caa`, `favicon`
(`url`, `mmh3`, `md5`, `sha256`, `size`; the probe's read, else the fingerprint
report's) and the nested `tls`, `fingerprint` and `not_found` documents
(`--compact` drops the nested ones).

```bash
vigolium hosts -j --compact
vigolium hosts '*.example.com' --format tsv --fields hostname,port,title,favicon_mmh3
vigolium hosts --has tls --sans
```

## match-not-found

**Usage:** `<producer> | vigolium match-not-found [flags]`

Says whether each response read from stdin is its origin's not-found page, for
responses vigolium did not record. Same decision as `traffic --fields
matches_not_found`: a 404/410 is not-found; any other status is compared with
the baseline `vigolium fingerprint` stored for the URL's host:port. Never sends
a request; `--db`/`-S` select the store as for `hosts`.

Input, one JSON object per line:

```json
{"id": "r1", "url": "https://app.example/x", "status": 200, "headers": {"Content-Type": "text/html", "Set-Cookie": ["a=1", "b=2"]}, "body_b64": "PGh0bWw+..."}
```

- `headers` values are a string or a list of strings.
- Omit `body_b64` (or send `null`) when you have no body; `""` is an empty body.
- A decoded body over 30 MiB is cut to 30 MiB (the transport's own read cap).

`-j` items, one per answered line, in input order:
`{"id", "url", "matches": bool, "known": bool, "reason"}`. `reason` is
`status-404`, `status-410`, `signature` (compared; `matches` is the verdict),
`no-baseline` or `no-body` (`known: false` — no answer, `matches` means
nothing). A line that does not parse is counted in top-level `failed` and listed
in `failures[]` (`line`, `id`, `error`, first 20); the others are still answered.
`--fields` and `--format tsv` shape the rows as on other read commands.

```bash
my-fetcher | vigolium match-not-found -j --fields id,matches,known
vigolium match-not-found -S --db run.sqlite -j < responses.jsonl
vigolium match-not-found --format tsv < responses.jsonl    # id, matches, known, reason, url
```

## export

**Usage:** `vigolium export [flags]`

Top-level export command. Exports database tables and module registry as JSONL, HTML, or a flat filesystem tree (`fs`).

### export flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--format` | — | string | `jsonl` | Format(s), comma-separated: `html`, `report`, `pdf`, `jsonl`, `markdown` (alias `md`), `bundle` (alias `gz`), `fs` (flat request/response + finding tree). Multiple formats read the DB once; `-o` becomes the shared base path and each format appends its own extension |
| `--output` | `-o` | string | — | Output file or `gs://<project>/<key>` URL (required for html); supports `{ts}`/`{project-uuid}` placeholders |
| `--only` | — | []string | all but modules | Export only these tables (repeatable: http, findings, scans, modules, oast, source-repos, scopes; aliases such as `http_record`, `finding`, `scan` accepted). Applies to every format, jsonl included |
| `--exclude` | — | []string | — | Drop these tables (same names and aliases as `--only`; an unknown name is exit 2). The module registry is left out unless `--only` names `modules`, whatever `--exclude` says. `--format csv`/`sarif` with no findings left is exit 2 |
| `--omit-response` | — | bool | `false` | Omit raw HTTP request/response bytes from output (keeps metadata, smaller files) |
| `--search` | — | string | — | Fuzzy search filter across URLs, paths, hostnames, methods, content types, and sources |
| `--severity` | — | string | — | Filter findings by severity (comma-separated) |
| `--scan-uuid` | — | []string | — | Agentic scan UUID(s) whose session dirs to include in `--format bundle` (repeatable) |
| `--report-title` / `--report-target` / `--report-duration` / `--report-generated-at` / `--report-url` | — | string | — | HTML report metadata |
| `--stateless` / `-S` + `--glob-db` | — | bool / string | — | Read from `--db` (a standalone `.sqlite`/`.jsonl` export, or a glob merged into one temp DB) |
| `--limit` | — | int | `0` (unlimited) | Max records per table |

### Examples

```bash
vigolium export --format jsonl -o full-export.jsonl
vigolium export -o full-export.jsonl -j     # receipt: files written + counts (-j needs -o)
vigolium export --format jsonl --only findings
vigolium export --format jsonl --only findings,http
vigolium export --format html -o report.html
vigolium export --format fs -o run
vigolium export --format html,markdown,bundle -o run   # → run.html, run.md, run.tar.gz (one DB read)
vigolium export --only modules
vigolium export --omit-response --only http -o urls.jsonl
vigolium export --search "example.com" -o filtered.jsonl
```

---

## module

**Usage:** `vigolium module [flags]` (aliases: `mo`, `modules`)

Manage scanner modules. Lists active and passive modules with their scan scope, severity, and enabled status.

### Subcommands

| Command | Aliases | Description |
|---------|---------|-------------|
| `module ls [filter]` | `list` | List available modules (optional fuzzy filter) |
| `module enable <search>` | `e` | Enable modules matching search |
| `module disable <search>` | `d` | Disable modules matching search |

### module ls flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--type` | string | `all` | Filter: all, active, passive |
| `--list-enabled` | bool | `false` | Show only enabled modules |
| `--tags` | bool | `false` | Show only unique module tags |
| `--verbose` / `-v` | bool | `false` | Show long description and confirmation criteria |

`module ls -j` (also `module -j` and `-M -j`) is a read envelope: `items` =
modules `{id, name, type, description, short_description, confirmation_criteria,
severity, confidence, scan_scope, tags, enabled}`, with `active_count` and
`passive_count` at the top level.

### module enable/disable flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--id` | bool | `false` | Match exact module ID instead of fuzzy |

`disable` adds to `dynamic-assessment.enabled_modules.disabled_{active,passive}_modules`
(the `[all]` allow-list stays); `enable` removes from it, and adds to an explicit
allow-list. A term matching more than 5 modules needs `--force`.

### Examples

```bash
vigolium module ls
vigolium module ls xss                 # fuzzy filter
vigolium module ls --type active
vigolium module ls --list-enabled
vigolium module ls -v                  # verbose with descriptions
vigolium module enable xss --force     # enable all xss modules (more than 5 match)
vigolium module disable sqli --force   # disable all sqli modules
vigolium module enable active-xss-reflected --id  # exact ID
vigolium scan -M                       # shortcut to list modules
```

---

## extensions

**Usage:** `vigolium extensions [filter]` (aliases: `ext`)

Manage JavaScript extensions for custom scanning logic.

### Subcommands

| Command | Aliases | Description |
|---------|---------|-------------|
| `ext docs [function]` | `doc`, `api` | Show API reference |
| `ext eval [code]` | `run`, `exec` | Evaluate JavaScript code with vigolium.* APIs available |
| `ext example [filter]` | `examples`, `templates`, `tpl` | Print self-contained example extensions in every supported format - the authoring template |
| `ext lint [file]` | — | Validate extension files: syntax, unknown APIs, metadata, missing handlers, load-time effects, YAML schema |
| `ext ls [filter]` | `list` | List loaded extensions |
| `ext preset [name]` | `presets`, `init` | Install example presets |

### ext ls flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--type` | — | string | `all` | Filter: all, active, passive, pre_hook, post_hook |
| `--verbose` | `-v` | bool | `false` | Show long description / details |

### ext docs flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--example` | bool | `false` | Show usage examples for each function |

### ext example flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--list` | `-l` | bool | `false` | Print only the catalog index (keys + titles), no code |
| `--lang` | — | string | — | Restrict to one language: `javascript` (`js`), `yaml`, or `json` |

Every example is emitted inside a fenced code block **with its suggested
filename**, so it can be copied straight into `~/.vigolium/extensions/`. The
catalog covers JavaScript and YAML modules (active, passive, `pre_hook`,
`post_hook`), the lightweight quick-check and snippet JSON forms, and the
auth/session config bundle in both YAML and JSON.

**Start with `-l`.** Bare `ext example` prints *every* example - a large read
when you only need one shape. List first, then fetch by filter:

```bash
vigolium ext example -l                  # catalog index only
vigolium ext example passive             # filter by key, language, type, or title
vigolium ext example --lang yaml         # only the YAML forms
```

Writing against the API those examples use: [extensions.md](extensions.md).

### ext lint flags

`ext lint` takes a **positional** file or directory to validate (e.g. `ext lint custom-check.js`), or reads from stdin. There is no `--ext-file` on lint (that flag is `eval`-only).

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--stdin` | bool | `false` | Read extension source from stdin |
| `--stdin-kind` | string | sniffed | Language of `--stdin` source: `js`, `ts` or `yaml` (default: a top-level `id:`/`type:` YAML map without `module.exports` is yaml) |
| `--strict` | bool | `false` | Treat warnings as errors |

Exits 1 with `error.code: "lint_failed"` when any file has an error. With `-j`: one document, `items` = files (`{path, kind, issues: [{severity, line, col, message, rule}]}`), `summary` = `{files, errors, warnings}`, `ok: false` exactly when there are errors. Rule ids and the load-time semantics are in [extensions.md](extensions.md#lint-and-what-happens-when-an-extension-does-not-load).

### ext eval flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--stdin` | bool | `false` | Read JS code from stdin |
| `--ext-file` | string | — | Path to JS file to evaluate |

### Examples

```bash
vigolium ext ls
vigolium ext ls --type active
vigolium ext docs
vigolium ext docs http             # filter API docs by namespace
vigolium ext docs --example        # with code examples
vigolium ext preset                # install all presets
vigolium ext preset idor           # install the presets whose name contains "idor"
vigolium ext eval 'vigolium.log.info("hello")'
vigolium ext eval --ext-file script.js
echo 'vigolium.utils.md5("hello")' | vigolium ext eval --stdin
```

---

## js

**Usage:** `vigolium js [flags]`

Execute JavaScript code with access to the full `vigolium.*` API surface. Reads from stdin by default, or use `--code` / `--code-file` for inline or file input. TypeScript files (`.ts`) are auto-transpiled.

### Input methods (mutually exclusive, in order of precedence)

1. `--code` — Inline JavaScript code
2. `--code-file` — Path to JavaScript/TypeScript file
3. stdin (default) — Read JS code from piped input

### js flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--code` | string | — | Inline JavaScript code to execute |
| `--code-file` | string | — | Path to JavaScript/TypeScript file (auto-transpiles `.ts`) |
| `--target` | string | — | Set TARGET variable in JS scope (URL string) |
| `--timeout` | duration | `30s` | Execution timeout (e.g., `60s`, `2m`) |
| `--format` | string | `json` | Output format: `json` or `text` |

### Available API

The JS VM provides access to all `vigolium.*` namespaces:

| Namespace | Description |
|-----------|-------------|
| `vigolium.http` | HTTP requests, sessions, batch, replay, sequence, auth testing, GraphQL, caching |
| `vigolium.utils` | Encoding, hashing, diff, similarity, JWT, CSS selectors, multipart, file I/O |
| `vigolium.parse` | URL, HTTP request/response, HTML, headers, cookies, query, JSON, form parsing |
| `vigolium.scan` | Module listing, scope, finding creation, scan control |
| `vigolium.db` | HTTP record and finding queries, annotations, comparison |
| `vigolium.ingest` | URL, curl, raw HTTP, OpenAPI, Postman ingestion |
| `vigolium.agent` | AI-augmented analysis (ask, chat, complete, generatePayloads, analyzeResponse, confirmFinding) |
| `vigolium.mcp` | Model Context Protocol client, SSE parsing, detection, JSON-RPC envelope building |
| `vigolium.oast` | Out-of-band testing (enabled, payload, poll) |
| `vigolium.log` | Logging (info, warn, error, debug) |
| `vigolium.config` | Read-only config variables |
| `vigolium.payloads(type)` | Built-in payload wordlists (xss, sqli, ssti, ssrf, lfi, etc.) |

### Return value

- Returns `undefined`/`null` → no output
- Otherwise → JSON-stringified return value on stdout
- With `--format text` → JSON strings are unquoted

### Examples

```bash
# Inline code
vigolium js --code 'vigolium.http.get("https://example.com/api/health")'

# From a file
vigolium js --code-file scanner-script.js

# TypeScript auto-transpilation
vigolium js --code-file scanner.ts

# From stdin (ideal for agent/pipe workflows)
echo 'vigolium.utils.md5("password123")' | vigolium js

# With target context (accessible as TARGET variable)
vigolium js --target https://example.com --code 'vigolium.http.get(TARGET + "/api/users")'

# Custom timeout and text output
vigolium js --timeout 60s --format text --code 'vigolium.utils.sha256("hello")'

# Query database records
vigolium js --code 'JSON.stringify(vigolium.db.records.query({ hostname: "example.com", limit: 5 }))'

# Ingest and scan
vigolium js --code 'vigolium.ingest.url("https://example.com/api/users"); vigolium.scan.startNewScan({ targets: ["https://example.com"] })'

# Use AI to generate payloads
vigolium js --code 'JSON.stringify(vigolium.agent.generatePayloads({ type: "xss", context: "HTML attribute", count: 5 }))'
```

### Differences from `vigolium ext eval`

| Feature | `vigolium js` | `vigolium ext eval` |
|---------|---------------|---------------------|
| Input methods | `--code`, `--code-file`, stdin | positional arg, `--ext-file`, `--stdin` |
| Target context | `--target` sets `TARGET` variable | Not available |
| Timeout | Configurable via `--timeout` | Not configurable |
| Output format | `--format json\|text` | Direct output |
| Use case | General scripting, automation | Quick extension testing |

---

## config

**Usage:** `vigolium config <subcommand>`

Manage configuration settings.

### Subcommands

| Command | Aliases | Description |
|---------|---------|-------------|
| `config ls [filter]` | `list`, `view` | Display current configuration |
| `config set <key> <value>` | — | Set a configuration value |
| `config validate` | — | Check the effective config; exit 1 (`config_invalid`) on errors, `--strict` on warnings too |
| `config clean` | — | Clean/reset configuration |

### Examples

```bash
vigolium config ls
vigolium config ls scope           # filter by section
vigolium config ls scanning_pace
vigolium config ls server          # view server config
vigolium config ls --show-secrets  # reveal sensitive values (API keys, tokens) unredacted

vigolium config set scanning_strategy.default_strategy deep
vigolium config set scope.cli_origin_mode strict
vigolium config set notify.enabled true
vigolium config set scope.host.include '["*.example.com","example.com"]'   # JSON or YAML flow lists
vigolium config set scope.host.exclude.add admin.example.com               # append (.clear empties)

vigolium config validate                   # same rules config set enforces
vigolium config validate -j --project <uuid> --recent 5 --strict
```

List and map values take JSON/YAML flow syntax checked against the setting's
type; the comma form still works for lists. A value that does not parse, has
the wrong element type, an empty element, or would introduce an error-level
validation issue (e.g. a host pattern with `https://`) exits 2 and writes
nothing. `config validate -j` returns `items[]` of
`{key, severity, code, message, fix}` plus `valid`, `errors`, `warnings`; it exits
1 with `error.code: config_invalid` on any error.

Config file location: `~/.vigolium/vigolium-configs.yaml`

---

## config clean

**Usage:** `vigolium config clean [--force]`

Reset Vigolium to a clean state: remove the entire `~/.vigolium/` directory (config, database, extensions, prompts, session directories) and regenerate fresh defaults by running the same bootstrap as `vigolium init`.

Prompts for `yes` confirmation unless `--force` is passed.

```bash
vigolium config clean
vigolium config clean --force       # skip confirmation
```

Warning shown:

```
✗ Warn: This will remove ~/.vigolium (config, database, and all local data)
Proceed? (type 'yes' to confirm):
```

Use this at the start of a new engagement or when an installation has drifted out of sync with the binary. After cleaning, the default API key is regenerated and all preset data (profiles, prompts, extensions) is re-extracted.

---

## scope

**Usage:** `vigolium scope [flags]` (aliases: `sc`)

Manage scan scope rules for filtering traffic.

### Subcommands

| Command | Aliases | Description |
|---------|---------|-------------|
| `scope view [component]` | `ls`, `list` | Display current scope configuration |
| `scope set <key> <value>` | — | Set a scope configuration value (validated like `config set`; `--project <uuid>` writes the project overlay) |

### Scope Components

host, path, status_code, request_content_type, response_content_type, request_string, response_string

### Examples

```bash
vigolium scope view
vigolium scope view host           # view host scope only
vigolium scope set cli_origin_mode strict
vigolium scope set host.include '["*.example.com"]' --project <uuid>
```

---

## auth

**Usage:** `vigolium auth <subcommand> [flags]`

Manage authentication configurations and utilities.

### Subcommands

| Command | Aliases | Description |
|---------|---------|-------------|
| `auth check` | — | Check a session is really logged in on a protected URL (verdict; exit 0 only when authenticated) |
| `auth lint` | — | Validate auth config files for errors and warnings |
| `auth list` | `ls` | List authentication configs |
| `auth load` | — | Load auth configs from a file or stdin into the database |
| `auth totp` | — | Generate a TOTP code from a base32 secret |

### Examples

```bash
vigolium auth list
vigolium auth lint auth-config.yaml
vigolium auth check auth-config.yaml --url https://example.com/account
vigolium auth load auth-config.yaml
vigolium auth totp --secret JBSWY3DPEHPK3PXP
```

---

## project

**Usage:** `vigolium project <subcommand> [flags]`

Manage projects for multi-tenancy scan data scoping.

### Subcommands

| Command | Aliases | Description |
|---------|---------|-------------|
| `project config` | — | Show the project's config overlay path (`-j`: `items:[{project_uuid, path, exists}]`) |
| `project create <name>` | — | Create a new project (positional name; `--description` optional). `-j`: `items[0].uuid` is the new UUID |
| `project list` | `ls` | List all projects |
| `project use <project>` | — | Write the global `~/.vigolium/active-project` file. Takes a UUID, an exact name or a unique 8+ char UUID prefix. An unknown one exits 1 with `project_not_found` (hint: `project create <name>`) and creates nothing, unless `--create` (then `--name`/`--description` apply). Prints `export VIGOLIUM_PROJECT_UUID=…` only when stdout is not a terminal (for `eval`); never under `-j`. `--print-env` prints the export line and writes no file: it pins one shell |
| `project delete <uuid>` | `rm`, `remove` | Delete a project and its data (`--keep-config` retains `~/.vigolium/projects/<uuid>`). An absent project is `changed:false`, not an error |

### Examples

```bash
vigolium project list
vigolium project create my-project                 # positional name (no --name flag on create)
vigolium project create my-project --description "Q4 engagement"
eval "$(vigolium project use acme --print-env)"   # this shell only; writes no file
vigolium project use <uuid> --create --name acme -j   # create-and-activate; never implicit
vigolium project config
vigolium project delete <project-uuid>             # aliases: rm, remove
```

The active-project file is shared by every shell and agent. Every `-j` document
carries `project_source` (`flag`/`env`/`active_file`/`default`), plus a
`warnings` entry when the project came from that file: pin `--project-uuid` or
`VIGOLIUM_PROJECT_UUID` in automation.

All mutating commands here and in `db clean`/`db reset`, `module enable/disable`,
`config set/clean`, `scope set`, `storage upload/rm/results`, `init` and
`skills install`/`uninstall` print one mutation document under `-j`:
`{"kind":"mutation","changed":bool,"action":"…","items":[…]}` (`dry_run:true`
on any `--dry-run`). `changed:false` with `action:"noop"` means nothing
was written.

---

## storage

**Usage:** `vigolium storage <subcommand>`

Manage cloud-storage objects scoped to the **active project** (selected via `--project-uuid`, `--project-name`, `VIGOLIUM_PROJECT_UUID`, or `VIGOLIUM_PROJECT_NAME`). Mirrors the REST endpoints under `/api/storage/*`.

**Requires** `storage.enabled: true` in `vigolium-configs.yaml` (or `VIGOLIUM_STORAGE_ENABLED=true`) plus `storage.driver`, `storage.bucket`, `storage.access_key`, and `storage.secret_key`. When storage is disabled, every subcommand prints a tip showing how to enable it and exits cleanly (no error).

### Subcommands

| Command | Aliases | Description |
|---------|---------|-------------|
| `storage ls` | `list` | List objects under the project's prefix |
| `storage upload` | — | Upload a single local file |
| `storage download` | `get` | Download an object by key |
| `storage results` | — | Download a scan's `results.tar.gz` bundle by scan UUID |
| `storage presign` | — | Generate a presigned GET or PUT URL |
| `storage rm` | `delete` | Delete one or more objects |

### Source-archive integration

`agent audit` accepts `--source gs://<project>/<key>` for source archives. The archive is downloaded, extracted (`.zip / .tar.gz / .tar.bz2 / .tar.xz`), and cleaned up automatically.

### Result-bundle integration

Pass `--upload-results` to `scan`, `agent autopilot`, `agent swarm`, `agent audit`, or `agent query` to bundle the session/output and push it to storage at the end of the run. Native scan bundles land at `native-scans/<scan-uuid>/results.tar.gz`; agentic bundles land at `agentic-scans/<uuid>/results.tar.gz`. `vigolium storage results <uuid>` checks both prefixes.

---

## storage ls

**Usage:** `vigolium storage ls [flags]` (alias `list`)

List objects under the active project's prefix in the configured bucket.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--prefix` | string | — | Limit results to keys under this prefix (e.g. `ugc/`, `native-scans/`) |
| `--tree` | bool | `false` | Render objects as a directory tree (directories first, then files) |

```bash
vigolium storage ls
vigolium storage ls --prefix ugc/
vigolium storage ls --tree
vigolium storage ls -j
```

`-j` is the global flag (the old local `--json` printed a bare array and
broke `-j`): a read envelope with the objects as `items` and `prefix` at the
top level.

---

## storage upload

**Usage:** `vigolium storage upload <file> [flags]`

Upload a single local file to the active project's storage. Without `--key`, the file is stored under `ugc/<basename>` (matching `POST /api/storage/upload-source`). Pass `--key` to choose an explicit object key. Directories are rejected.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--key` | string | `ugc/<basename>` | Object key |
| `--content-type` | string | — | `Content-Type` to set on the object |

```bash
# Default key (ugc/report.pdf)
vigolium storage upload ./report.pdf

# Explicit key
vigolium storage upload ./report.pdf --key reports/q4.pdf

# Pin a content type
vigolium storage upload ./report.pdf --content-type application/pdf
```

---

## storage download

**Usage:** `vigolium storage download <key> [flags]` (alias `get`)

Download an object from the active project's storage by full key. Streams to stdout by default; use `-o` to write to a file. `-j` requires `-o` (exit 2 otherwise) and prints a receipt `items:[{key, path, size}]`.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--output` | `-o` | string | — | Write to this file instead of stdout |

```bash
# Stream to a file
vigolium storage download ugc/report.pdf -o report.pdf

# Stream to stdout (for pipelines)
vigolium storage download ugc/notes.txt | grep TODO
```

---

## storage results

**Usage:** `vigolium storage results <scan-uuid> [flags]`

Download the `results.tar.gz` bundle for a native or agentic scan run. Tries `native-scans/<uuid>/results.tar.gz` first, then `agentic-scans/<uuid>/results.tar.gz`. Default output filename is `results-<uuid>.tar.gz` in the current directory.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--output` | `-o` | string | `results-<uuid>.tar.gz` | Write to this file |

```bash
vigolium storage results 550e8400-e29b-41d4-a716-446655440000
vigolium storage results 550e8400-e29b-41d4-a716-446655440000 -o results.tgz
```

---

## storage presign

**Usage:** `vigolium storage presign --key <key> [flags]`

Generate a presigned URL for direct GET (download) or PUT (upload) against the active project's storage. Mirrors `POST /api/storage/presign`.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--key` | string | — | Object key (**required**) |
| `--method` | string | `GET` | HTTP method: `GET` or `PUT` |
| `--expiry` | duration | `1h` | URL validity duration (e.g. `30m`, `1h`, `24h`) |

`-j` (global) emits a read envelope with `items:[{url, key, method, expiry_seconds}]`.

```bash
# 1h GET URL
vigolium storage presign --key ugc/foo.tar.gz --method GET --expiry 1h

# 30m PUT URL (machine-readable)
vigolium storage presign --key uploads/new.tar.gz --method PUT --expiry 30m -j
```

---

## storage rm

**Usage:** `vigolium storage rm <key> [<key>...] [flags]` (alias `delete`)

Permanently delete one or more objects from the active project's storage. Prompts for confirmation (typed `yes`) unless `--force` is set.

```bash
# Single delete (prompts for confirmation)
vigolium storage rm ugc/foo.tar.gz

# Bulk delete, skip confirmation
vigolium storage rm ugc/a.pdf ugc/b.pdf --force
```

---

## strategy

**Usage:** `vigolium strategy [flags]` (aliases: `st`, `phase`)

Display scanning strategies and their phase configurations. `strategy` takes **no subcommands** — running it (or its `st` / `phase` aliases) with no args prints the strategy table directly. There is no `strategy ls`.

### Examples

```bash
vigolium strategy
vigolium phase              # alias for strategy
vigolium st                 # alias for strategy
```

---

## version

**Usage:** `vigolium version`

Show version, build time, commit, and author information. Supports `-j` for machine-readable output: a read envelope whose `items[0]` carries `version`, `commit`, `build_time`, `db_schema_version` and `db_min_reader_version` (the envelope's own `schema_version` is the `-j` contract) - check both at startup rather than discovering drift at parse time.

---

## update

**Usage:** `vigolium update [flags]`

Re-run the official install script to fetch the latest release binary, then refresh the local nuclei-templates checkout used by `known-issue-scan`. **Both happen by default.**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--skip-binary` | bool | `false` | Only refresh nuclei templates; do not reinstall the binary |
| `--skip-templates` | bool | `false` | Only reinstall the binary; do not refresh nuclei templates |

```bash
vigolium update                      # binary + templates
vigolium update --skip-binary        # templates only - the usual CI refresh
vigolium update --skip-templates     # binary only
```

The binary half runs the same installer as `curl -fsSL https://vigolium.com/install.sh | bash`, so it **replaces the running executable** - not something to fire mid-engagement or inside a pinned container image. `--skip-binary` is the safe half: stale nuclei templates are the common reason `known-issue-scan` misses a recent CVE, and refreshing them changes nothing about the tool you are driving.
