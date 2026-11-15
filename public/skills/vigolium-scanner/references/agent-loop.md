# The Agent Loop

> **Related:** [scanning.md](scanning.md) · [fuzzing.md](fuzzing.md) · [burp.md](burp.md) · [agent-modes.md](agent-modes.md) · [data.md](data.md) · [flags.generated.md](flags.generated.md)

How to drive vigolium **non-interactively** from a coding agent (Claude Code,
Codex, Cursor, Pi, CI) and parse what comes back. Everything here is additive —
default human output is unchanged; you opt into machine output with `-j/--json`.

The loop:

```
scope → plan → scan → watch → read → confirm → mark → diff → hand off
```

## Where each step lives

| Step | Reference | What is there |
|---|---|---|
| Scope, sweep, plan, scan | [loop-scan.md](loop-scan.md) | `doctor`/`db stats`, host-list sweeps, the `--dry-run` plan document, the scan document and gates |
| Watch | [loop-watch.md](loop-watch.md) | `--events ndjson` types, terminal statuses, coverage fields, `scan status`/`wait`/`stop` |
| Read | [loop-read.md](loop-read.md) | `finding`/`traffic` triage, reading exports and `--format fs` trees |
| Confirm, record, diff | [loop-confirm.md](loop-confirm.md) | `finding verify`, `replay`, `finding mark`, `scan diff`, bulk replay, `fuzz` |
| Hand off | [loop-handoff.md](loop-handoff.md) | Burp/Caido, curl, reports, agent-run documents |
| Contract | [invariants.md](invariants.md) | the `-j` envelope, `error.code`, exit codes |

Fetch one without the skill on disk: `vigolium skills get vigolium-scanner --ref loop-scan`.

## Mental model

The four load-bearing facts — **the database is the state** (scans write,
queries read, commands compose through the DB not pipes), **three machine
contracts** (`-j/--json` = one compact envelope for triage; `--format
jsonl`/`export` = bulk archival stream, URL-deduplicated and confirmed-findings
only unless you pass `--no-url-dedup`; `--events ndjson` =
a live stream while a scan runs), **non-interactive by default** (TUI is
`--tui`, destructive needs `--force`), and **every JSON summary hands you the
next command** (the `query` field) — are stated in full in `SKILL.md`, always in
context. This file assumes them and drills into each step.

Scoping: `--project-uuid <uuid>`, `--project-name <name>`,
`VIGOLIUM_PROJECT_UUID=<uuid>`, or `VIGOLIUM_PROJECT_NAME=<name>`. Every
envelope's `project_source` (`flag`, `env`, `active_file`, `default`) says
which one applied; `active_file` means another shell's `project use` scoped
this command, so pin a project instead. A project that does not exist is
`project_not_found` (exit 1), never an empty result; `--project-uuid` also
takes an exact name or a unique 8+ character UUID prefix. A standalone source
(`-S`, `--glob-db`) has no project registry, so there it is only a filter.

## Token discipline

Under `--json`, `finding` and `traffic` keep headers and high-signal metadata but
**bound** bodies so a scan can't blow your context window:

- Bodies are previewed (request ~1 KiB, response ~2 KiB) with `body_size`,
  `body_sha256`, and `body_truncated:true` so you know more exists.
- Binary/static bodies (images, fonts, JS bundles, gzip) are stubbed as
  `{"body_omitted":"binary", …}`.
- gzip is decoded transparently, but **only the first 1 MiB** — see the trap
  below before you trust a decoded body.
- Findings get a ±240-char `response_evidence` snippet windowed on the match
  instead of the whole page.

**A gzip body over 1 MiB is capped, and says so.** The JSON decoder holds at most
1 MiB, so a larger body comes back as a prefix — but the metadata describes the
*whole* body, which is what lets you act on it:

| Field | Meaning |
|---|---|
| `body_size` | size of the **complete** body, not of the prefix you got |
| `body_truncated` | `true` whenever `body` is shorter than `body_size` (set under `--full-body` too) |
| `body_sha256` | digest of the **complete** body — safe as a dedupe key |
| `decoder_capped` | the 1 MiB decoder limit was hit; `--full-body` cannot lift it |
| `decoder_hint` | names the command that returns the whole body |

So `decoder_capped: true` means **do not conclude a string is absent** from this
body. Pull it whole with `traffic body`, which writes the bytes straight to a
file:

```bash
vigolium traffic body --uuid "$RECORD_UUID" -o resp.body      # decoded, one call
vigolium traffic body --uuid "$RECORD_UUID" --representation stored -o resp.gz
```

Past the decoder ceiling, `decoded` refuses rather than writing a prefix
(`body_incomplete`) — take `--representation stored` for the complete compressed
bytes, or `--allow-incomplete` if a prefix really is enough. `db export --format
fs -o out --uuid "$RECORD_UUID"` still works and writes a whole tree
(`out-traffic/<host>/<id>.resp.body`) when you want the record's other parts too.

Control it:

| Flag | Effect | Commands |
|------|--------|----------|
| `--compact` | metadata only, drop bodies — best for surveys. Also drops `request`/`response` entirely, so there is **no header access** under it (use `traffic headers` for that) | finding, traffic, db ls |
| `--fields a,b,c` | project the JSON to just these top-level keys (cuts tokens hardest). An unknown name is a **usage error listing the valid set**, not a silent drop | finding, traffic, db ls |
| `--full-body` | complete decoded bodies, except past the 1 MiB gzip cap — which is flagged `decoder_capped` | finding, traffic, db ls |
| `--with-records` | embed the linked HTTP records → self-contained triage bundle. Capped at 20 per finding | finding |
| `--record-limit N` | change that cap (`0` = no cap). Over the cap you get `records_total` + `records_truncated: true` | finding |
| `--record-fields a,b` | project the **nested** records independently of `--fields` | finding |
| `--min-severity` | threshold that expands upward (`high` → high + critical) | finding |
| `--agentic-scan <uuid>` | every finding from an agent run (expands to the whole run tree) | finding |
| `--pick N` | keep only the 1-based position(s) from the result list — `2`, `1,3`, `2-4` | finding |
| `--markdown` | render as Markdown (evidence + fenced `http` blocks) instead of JSON | finding, traffic |
| `--raw` | full raw HTTP request/response, human format | finding, traffic |
| `--group-by <field>` | **count** the matched records by one field instead of listing them; `--group-limit N` bounds the buckets (default 20, `0` = all) | traffic |
| `--max-output-bytes N` | with `--json`, cap the whole result document at N bytes by dropping whole trailing items (`0` = unlimited, the default). The document stays valid JSON and gains `output_budget` | finding, traffic, db ls |
| `-o/--output <path>` | with `--json`, write the result document to a file and print a small receipt (path, bytes, sha256, `complete`) instead — the document never enters your context | finding, traffic, db ls |

Rule of thumb: **survey with `--compact --fields`, then drill with `--id` +
`--with-records`.** Never fetch full bodies for more than one record at a time.

**`--max-output-bytes` is the backstop for the budget you actually have.**
`-n/--limit` counts rows, and a row is anywhere from a few hundred bytes to
megabytes, so no row count reliably stays under a context window. Cap the bytes
directly and resume from the reported offset:

```bash
vigolium traffic -j --full-body --max-output-bytes 65536
# → "output_budget": {"max_bytes":65536,"returned":14,"omitted":26,"next_offset":14}
vigolium traffic -j --full-body --max-output-bytes 65536 --offset 14
```

The cut is at a record boundary, `total` still describes the whole result set
(so an `-o` receipt reports `complete: false`), and a budget too small for the
envelope's fixed parts fails with `error.code: "output_too_large"` rather than
handing you an over-budget document. It requires `-j`.

When you want the rows on disk rather than in context, `-o` is the cheapest
option in the surface: the file is byte-identical to what the command would have
printed, and stdout carries only the receipt. `complete: false` in that receipt
means the file holds one page — raise `-n/--limit` (or `-a` on `traffic`) for the
whole set. `-o -` forces the document back to stdout.

```bash
vigolium finding -j -n 500 -o findings.json   # ~65 KB to disk, ~7 lines to you
```

And before either: if the question is a *shape* rather than a row set, count in
SQL. `--group-by` applies the same filters the listing would, so the buckets
describe exactly the rows `traffic` would have shown:

```bash
vigolium traffic -j --group-by status_code --host target.example
# → items: [{value,count}…] plus group_by, total_records, other_groups, other_records
```

`total` is the number of **buckets**; `total_records` is how many records were
counted. The tail past `--group-limit` is reported as `other_groups` /
`other_records` — a capped grouping never looks complete. Groupable fields:
`host`, `method`, `status_code`, `response_content_type`, `source`, `scan_uuid`,
`ip`, `is_authenticated` (an unknown name is a usage error listing the set).

`--fields` composes safely with `--with-records`: the projection narrows the
finding's own keys and never removes the `records` array, because that was
requested by a different flag. `--record-fields` narrows the nested rows.

To discover the selectable names, ask for a bad one — the error lists the whole
supported set for that view:

```bash
vigolium traffic -j --fields '?' 2>&1 | head -3
```

Note that JSON field names are not SQLite column names: the JSON key is `host`,
the storage column is `hostname`. Go by the error's list, not by the schema.

### Worth knowing

- **An unknown `--fields` name is a usage error** (exit 2) listing the valid
  set for that view and the nearest match, so a typo fails loudly instead of
  returning rows with the key quietly missing. `--fields` composes with
  `--with-records`; shape the nested records with `--record-fields` / `--record-limit`.
- **`--fields` takes one vocabulary everywhere.** `status`, `code`, `length`,
  `size`, `words`, `time`, `content_type`, `title`, `id` and `headers` resolve on
  every view that carries the concept (`traffic`, `fuzz`, `replay`, `endpoints`,
  `hosts`, …) and come back under the name you passed, so a parser keyed on its
  own names never misses. A view's real key wins over an alias (`endpoints
  --fields status` is its histogram; `status_code` there is `top_status`).
- **`--fields` and `--compact` are on every `-j` list command**: traffic, finding,
  db ls, endpoints, params, log ls, fuzz, replay, hosts, dns, and the scan
  document. `vigolium schema command <name>` has every document's shape.
- **`--format tsv` is cheaper than `-j`** for a survey: one line per row, columns
  from `--fields`, nothing else on stdout. Use it instead of dropping to sqlite3;
  `vigolium schema storage [table]` maps the store when SQL is the only way.
- **Short ids.** Every record UUID flag takes a unique 8+ character prefix;
  `--fields uuid_short` prints it and `--format tsv` shows it by default.
- **`--usage` on any command** (`vigolium fuzz --usage`) prints its flags one per line (local
  flags described, globals named) — a fraction of `--help`; `--usage -j` is the
  `schema flags` document.
- **A gzip body over 1 MiB comes back as a prefix** flagged `decoder_capped:
  true`, with `body_size`/`body_sha256` describing the whole body. Do not
  conclude a string is absent; pull it whole with `traffic body --uuid <uuid>
  -o resp.body` (above).
- **Read one record by identity with `traffic --uuid <uuid>`**, applied before
  pagination. A UUID as the positional term searches text, not identity. To
  select by URL use `--url` (exact equality, repeatable); the positional term
  is a substring search.
- **`--header` and `--body` search only their own half of the message**, and
  `--search` spans the whole exchange. Every search term is **literal**: `%`
  and `_` are ordinary characters, so `--body 'api_key'` does not also match
  `api-key`. `--host`/`--path` stay patterns where `*` is the wildcard.

## Gotchas

- `-S` means `--stateless` **everywhere**, and is accepted as a harmless no-op on
  commands where it has no meaning. On `server`/`ingest` it is a usage error
  that names `--scan-on-receive`; type that flag long.
- `$VIGOLIUM_DB_PATH` pointing at a path that can never hold a database (a
  directory, an uncreatable parent) is a hard error, not a silent fall-through to
  the shared default. A path that simply does not exist yet is created. Read
  `db_path` off any `-j` envelope to confirm which store you actually got.
- `vigolium log <uuid> | cat` terminates even when the scan row still says
  `running` (a deadline or SIGKILL leaves it that way). Auto-follow is off for a
  non-TTY stdout and for a stale row; pass `--follow` to force it, and use
  `scan status` (`effective_status: abandoned`) to tell a dead scan from a slow one.
- `--json` (one compact object) ≠ `--format jsonl` (bulk, one line per row).
- **Fetch one record by UUID with `traffic --uuid <uuid>`** (also on `db ls`,
  repeatable/comma-separated). It is an exact equality match applied **before**
  pagination, so `-n`/`--offset` can never hide a match. A UUID passed as the
  *positional* term still matches 0 rows — that searches URL/path/body, not
  identity, so use the flag.
- **`-S`/`--stateless` is a scoping mode, not a read-only one.** A command that
  writes opens the database read-write: `mkdir -p` on the parent, a
  `journal_mode` PRAGMA (a header rewrite) and a WAL checkpoint. A pure read
  opens it `query_only` and never *creates* a store at a pinned path that has
  none (see the exit-code table), but it may leave a `-shm` sibling beside
  one that is there. Pass **`--read-only`** when the source is
  evidence — it skips all three, leaves the file's SHA-256 unchanged, leaves no
  `-wal`/`-shm` siblings behind, and reads a `chmod 444` file fine. It is
  accepted on the read commands and refused (exit 2) on anything that writes, and
  it cannot migrate an old store (that fails with a schema error instead).
- `db export --uuid` works on every format including `--format fs`, and is
  applied in SQL before paging, so a record outside the current page is found
  rather than reported missing.
- `--with-browser` produces **no diff** — a navigation has no status code or
  body to compare, so `result` is null and a `browser` object is emitted instead.
- Agentic scans need a configured LLM provider (`agent.olium` in
  `vigolium-configs.yaml`); check with `vigolium doctor --json`.
