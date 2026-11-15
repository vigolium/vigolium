# The Agent Loop

> **Related:** [scanning.md](scanning.md) · [fuzzing.md](fuzzing.md) · [burp.md](burp.md) · [agent-modes.md](agent-modes.md) · [data.md](data.md) · [flags.generated.md](flags.generated.md)

How to drive vigolium **non-interactively** from a coding agent (Claude Code,
Codex, Cursor, Pi, CI) and parse what comes back. Everything here is additive —
default human output is unchanged; you opt into machine output with `-j/--json`.

The loop:

```
scope → plan → scan → watch → read → confirm → mark → diff → hand off
```

## Table of Contents

- [Mental model](#mental-model)
- [Token discipline](#token-discipline)
- [Step 1 — Scope](#step-1--scope)
- [Step 1.5 — Sweep, when the scope is a host list](#step-15--sweep-when-the-scope-is-a-host-list)
- [Step 1.75 — Plan before you scan](#step-175--plan-before-you-scan)
- [Step 2 — Scan and gate](#step-2--scan-and-gate)
- [Watching a scan while it runs](#watching-a-scan-while-it-runs)
- [Step 3 — Read the results](#step-3--read-the-results)
- [Step 4 — Confirm a finding](#step-4--confirm-a-finding)
- [Recording a verdict](#recording-a-verdict)
- [What changed since the last scan](#what-changed-since-the-last-scan)
- [Step 5 — Hand off](#step-5--hand-off)
- [Bulk replay](#bulk-replay)
- [Payload fuzzing](#payload-fuzzing)
- [Reading exports without a database](#reading-exports-without-a-database)
- [Filesystem tree output](#filesystem-tree-output)
- [Agentic scans](#agentic-scans)
- [The `-j` envelope](#the--j-envelope)
- [Exit codes](#exit-codes)
- [Gotchas](#gotchas)

---

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

## Step 1 — Scope

```bash
# What's already in the DB?
vigolium db stats --json

# Is the environment ready (binaries, providers, templates)?
vigolium doctor --json

# What modules exist / match a topic?
vigolium module ls xss
```

## Step 1.5 — Sweep, when the scope is a host list

With more than a handful of targets, probe first and scan what's worth scanning.
`run probe` sends one request per target — no discovery, no fuzzing. With
`--format jsonl` it streams one record per line on stdout (progress goes to
stderr, so `2>/dev/null` or `--silent` gives a clean pipe; `-j` would print the
one scan document instead):

```bash
vigolium run probe -T hosts.txt --format jsonl --no-response -c 50 2>/dev/null > sweep.jsonl

# Alive + interesting, ranked by attack surface:
jq -r 'select(.type=="http_record") | .data
       | select(.status_code < 500)
       | [.surface_score, .status_code, .url, .response_title] | @tsv' sweep.jsonl \
  | sort -rn | head -40
```

Each record carries `status_code`, `response_time_ms`, `response_title`,
`response_words`, `surface_score` (0-100, percent of the surface signals present), `ip`, and the full DNS
answer (`a`/`aaaa`/`cname`). Add `--tls-probe` for the certificate (`tls` object:
version, cipher, subject/SANs, issuer, validity, fingerprints). Field names match
httpx's, so an existing consumer reads them unmodified.

Then scan only the survivors:

```bash
jq -r 'select(.type=="http_record") | .data | select(.surface_score >= 30) | .url' \
  sweep.jsonl > worth-scanning.txt
vigolium scan -T worth-scanning.txt --fail-on high
```

`a`/`aaaa`/`cname`/`tls` are stored per host:port, not per record: `traffic -j`
merges them back onto each row, and `vigolium hosts -j` reads them on their own.

For the survivors, `vigolium fingerprint` answers "what is this origin" in a
bounded number of reads — stack, title, favicon hash, well-known paths, CORS,
OPTIONS, Host-header variants and the not-found baseline — stored for the next
session to read with `vigolium hosts`:

```bash
vigolium fingerprint -T worth-scanning.txt -j --compact
vigolium hosts --format tsv --fields hostname,port,title,technology,soft_not_found
```

## Step 1.75 — Plan before you scan

`--dry-run` on `scan` (and `run <phase>`) resolves the scan exactly as it would
run and prints the plan, sending nothing: no scan UUID, no scan row, no output
file, no wordlist written, no login, no OAST registration; an existing database
is only read.

```bash
vigolium scan -t https://target.example --dry-run -j
vigolium run discovery -t https://target.example --dry-run -j
```

`-j` is a `kind: "scan"` envelope with `dry_run: true`, `items` = the phases and
`plan` = the full plan (the same object `scan.plan` carries and the scan row
stores). What to read in it:

- `phases[]`: every phase in execution order with `enabled`, `disabled_by`
  (`strategy`, `only`, `skip`, `heuristics`, `intensity`, `module_selection`,
  `default` = opt-in, `gate` = a runtime precondition, `flag`, `scope`),
  `sends_target_traffic`, `budget {per_target_ms, phase_ceiling_ms,
  duration_factor, grace_ms, semantics, source}` (`semantics`: `per_target`,
  `per_target_capped`, `phase`, `per_leg`, `per_call`; `source`: `flag`,
  `config`, `factor`, `default`, `floor`), the `pace` fields the phase enforces,
  and `request_cap_enforcement` when `--max-requests` is set.
- `targets {seeded, admitted, rejected, rejected_sample, db_records_in_scope}`:
  scope admission, with the same rule a real scan applies — every seeded target
  refused exits `1` with `error.code: no_targets_in_scope`.
- `modules {active, passive, extensions, tier_ceiling, tier_filtered,
  hygiene_suppressed, risk_gated, payloads_gated[], by_scope}`: what runs and
  what the intensity holds back.
- `auth[]`: session names, roles and kinds only, never a secret.
- `discovery` (wordlist tier and line counts, fuzzing and why, recursion,
  jstangle workers, sitemap caps), `harvest`, `param_mining`, `egress`.
- `estimate {low, high, ceiling_by_pace, clamped_to, hits_max_requests,
  by_phase, basis, confidence: "rough"}`. `ceiling_by_pace` (rate limit × the
  time budget) is the only hard number; the rest is a heuristic, explained in
  each `basis`. A `--max-requests` lower than `high` clamps it and names the
  phases that will hit it.
- `warnings[]`: `{code, message}` — `targets_out_of_scope`,
  `unbounded_discovery` (no `--scanning-max-duration` or `--max-requests`),
  `auth_invalid`, `input_file`.

## Step 2 — Scan and gate

```bash
# Stateless single-shot, JSON findings to stdout, non-zero exit on high+.
vigolium scan-url https://target.example --json --fail-on high

# Full pipeline into the DB, gated for CI.
vigolium scan -t https://target.example --fail-on high

# A raw request from stdin (pipeline-friendly).
printf 'GET /api?q=1 HTTP/1.1\r\nHost: target.example\r\n\r\n' \
  | vigolium scan-request --json
```

`scan`, `run`, `scan-url` and `scan-request` under `--json` print **one scan
document** when the scan ends (`kind: "scan"`, `schema_version: 2`), on every
path — direct, `-S`, `-o`, one target or many, success or failure:
`{"scan_uuid","scan_uuids","persisted","status","completeness","stop_reason","reasons","targets":[{"target","method","scan_uuid","admitted","reached","reason","code","detail","resolved_target","scheme_source","findings","duration_ms"}],"targets_not_scanned","phase_outcomes","modules":{"selected","executed"},"counts_by_severity","candidates","observations","errors":[{"code","message"}],"total","items":[…],"items_truncated","query","query_argv"}`.
`items` are finding rows in the `finding -j` shape (plus `request` /
`response_evidence`), highest severity first, capped at `-n/--limit` (default
200); `total`/`counts_by_severity` are exact and `query` (`finding --scan-uuid
<uuid> -j`) lists the rest. An unpersisted finding (`-S`) has no `id` — use
`finding_hash`. `status` is `completed`, `curtailed`, `failed` or
`interrupted`; a failed scan still prints its document with `errors[]` and the
exit code carries the failure. A target that never answered: `reached: false`,
`reason: "unreachable"`, `code` (`refused`, `dns`, …), `stop_reason:
"no_targets_reachable"`, exit `1` (a batch: only when no input answered).
`modules.executed` counts modules that actually ran (`selected` is the
selection). `scan-request` fills `scheme_source`: with no `-t`, absolute-form
line, `:80`/`:443` or same-origin `Origin`/`Referer`, it probes the target
(connect + TLS handshake) instead of assuming `https://`; `--no-scheme-probe`
keeps the old default. `--fields`, `--compact`, `--full-body` and
`--max-output-bytes` shape `items` as on `finding`. `-j` is not the bulk
stream; use `--format jsonl -o <file>` for that.

**Which command?** Use `scan-url` / `scan-request` only when you're confirming
**one specific request** — full params, a deep path, or custom headers you need
sent verbatim. For a bare host/root URL, `scan -t` expands the surface for you.

A full `scan -t` can run well past 30 min (discovery defaults to 1h, spidering
30m, no total cap) — **launch it in the background** and poll the DB, or bound it:

```bash
vigolium scan -t https://target.example --scanning-max-duration 30m --fail-on high
```

For a quick single-phase pass, run it directly: `vigolium run spidering -t <url>`.

## Watching a scan while it runs

Don't poll the DB and don't invent a patience message. Ask for the stream:

```bash
vigolium scan -t https://target.example --events ndjson 2>/dev/null | jq -c .
```

One JSON object per line on **stdout**, flushed per event; the human console
stays on stderr, so `2>/dev/null` yields clean NDJSON with **zero** non-JSON
lines. Available on `scan`, `run`, `scan-url`, `scan-request`.

**`--events` owns stdout.** Anything else that would write there is refused with
exit `2` rather than interleaved into a stream that is neither contract:
`-j` (the scan document — read it afterwards with `finding --scan-uuid`),
`--format jsonl` without `-o`, `--print-finding`,
`--print-traffic` and `--print-traffic-tree`. `-j` owns stdout the same way:
it refuses those writers too, and a `-P`/`--split-by-host` fan-out. The error names the conflicting flag; give the other
writer an `-o <file>` and both work. `--events` is also refused under a
`-P/--parallel` fan-out, where each child's stdout is captured to its own log.

```jsonc
{"v":1,"ts":"…","scan_uuid":"…","type":"scan.started","target":"https://…","strategy":"lite","phases":["heuristics-check","discovery","dynamic-assessment"],"db_path":"/tmp/…","pace":{"rate_limit":20,"concurrency":10,"max_per_host":10}}
{"v":1,"ts":"…","scan_uuid":"…","type":"scan.plan","plan":{"schema_version":1,"scan_uuid":"…","strategy":"lite","phases":[…],"targets":{"seeded":1,"admitted":1,…},"estimate":{"low":1200,"high":48000,"confidence":"rough",…},…}}
{"v":1,"ts":"…","scan_uuid":"…","type":"phase.started","phase":"discovery"}
{"v":1,"ts":"…","scan_uuid":"…","type":"phase.progress","phase":"discovery","requests_sent":1204,"findings":3}
{"v":1,"ts":"…","scan_uuid":"…","type":"phase.progress","phase":"dynamic-assessment","requests_sent":8812,"findings":5,"done":340,"total":1290,"unit":"records"}
{"v":1,"ts":"…","scan_uuid":"…","type":"waf.block","host":"app.example.com","vendor":"cloudflare","status_code":403,"detail":"edge is filtering scan traffic — results for this host may be incomplete"}
{"v":1,"ts":"…","scan_uuid":"…","type":"waf.pacing","host":"app.example.com","vendor":"akamai","concurrency_from":40,"concurrency_to":8}
{"v":1,"ts":"…","scan_uuid":"…","type":"finding.new","severity":"high","confidence":"firm","module_id":"sqli-error-based","url":"…"}
{"v":1,"ts":"…","scan_uuid":"…","type":"phase.finished","phase":"discovery","status":"completed","duration_ms":184000,"requests_sent":1544,"findings":3}
{"v":1,"ts":"…","scan_uuid":"…","type":"error","phase":"spidering","message":"chromium launch failed"}
{"v":1,"ts":"…","scan_uuid":"…","type":"scan.finished","status":"completed","duration_ms":903000,"findings_by_severity":{"high":3,"medium":11},"records_written":4820}
```

What each type is for:

| Type | Read it for |
|---|---|
| `scan.started` | The canonical `phases[]` the aliases resolved to, the `db_path` to query afterwards, and the `pace` that actually applied (plus `phase_pace` when a phase differs). `targets_admitted`/`targets_rejected` (also on `scan.finished`) when the targets are the input: a `targets_admitted: 0` scan fails next with `stop_reason: no_targets_in_scope`, exit 1, nothing sent. `egress {gated, exempt: [{path, reason}]}` names the outbound paths `--rate-limit`/`max_per_host` do **not** govern for this scan's phases (nuclei, the browser crawl, own-dialer probes): budget for that traffic separately. `budgets {max_requests, max_requests_per_host}` (0 = unlimited) and, when one is set, `request_cap_enforcement {phase: hard\|soft\|partial}`: `hard` = exact, `soft` = the browser crawl is checked every 500ms, `partial` = some traffic (nuclei, own dialers) is not counted. |
| `scan.plan` | Always second, right after `scan.started` and before any request: `plan` is the resolved plan (see [Step 1.75](#step-175--plan-before-you-scan)), with `scan_uuid` set and the loaded extensions' selection. The same object is stored on the scan row. |
| `phase.progress` | Liveness. `requests_sent` every 5s is the real slope — a crawl that is working versus one that is wedged. On `spidering` and `targeted-respider`, `requests_in_scope` is the in-scope share (the browser also fetches third-party URLs). Where the phase has a work-item count, `done`/`total`/`unit` give progress: `records` for `dynamic-assessment` and `seed`, `targets` for `heuristics-check`, `port-sweep`, `spidering` and `probe` (also on `phase.finished`). `total` is a **non-decreasing upper bound**, not a fixed denominator: it can grow (a feedback round adds records) but never shrinks or drops below `done`, and is omitted until a bound is known. |
| `waf.block` | The edge started filtering. Results for that host are **incomplete** — do not read a thin surface as a clean target. |
| `waf.pacing` | Vigolium slowed itself down on purpose. Attribute the slowdown here, not to the target. |
| `host.quarantined` | `host` (`host:port`) hit `--max-host-error` consecutive transport errors; `detail` gives the error class and when it is re-probed. Its pending items are skipped (counted as `skipped_quarantined`, phase reason `targets_unreachable`), so coverage of that host is **incomplete**. |
| `host.recovered` | A re-probe of a quarantined `host` succeeded; requests to it resume. |
| `host.dead` | Every re-probe failed (`host_errors.max_trips`); nothing more is sent to `host` this scan. |
| `finding.new` | Metadata only. Evidence lives in `db_path`; query it with `finding -j --with-records` afterwards. |
| `scan.setup` | A lazy first-run install inside the phase that needs it, before that phase's budget starts: `component` (`chrome` before spidering, `nuclei` before known-issue-scan; the `doctor --fix --only` id), `state` (`started`, then `finished` or `failed`), `phase`, `bytes` (download size, when known), `duration_ms` and `message` (on `failed`) on the terminal line. A pause after `started` is the download, not a hung scan. A `failed` install fails that phase only (message names `vigolium doctor --fix --only chrome\|nuclei`). |
| `oast.unavailable` | OAST registration with the interactsh server failed or did not finish within 3s of `dynamic-assessment` starting. `message` names the server and cause (`oast.pro: dial timeout`). Blind/out-of-band checks did not run; the phase carries the `oast_unavailable` reason and the scan is `partial`. |
| `extension.failed` | An extension failed to load: `module_id` (when its metadata loaded), `path`, `stage` (`read`/`transpile`/`compile`/`metadata`/`schema`/`unknown_type`/`module`), `explicit` (named with `--ext`: the scan then stops, exit 2 `extension_load_failed`, unless `--ext-allow-failures`), `message`. Run failures arrive with `module.error`. |
| `module.error` | A module call failed: `module_id`, `phase`, `url`, `error_kind` (`exception`/`timeout`/`panic`), `message`, and `count`, the module's running total for the scan. Rate-limited per module: the first 3, then every 100th, so the last line's `count` is close to the real total and `scan.finished.module_errors` has the exact one. An `ext-*` module erroring is **your extension's bug** (fix it, then `vigolium ext lint`); a built-in module erroring means that check did not run on that item. |
| `error` | A phase failed and the scan **carried on** — non-fatal by construction. A failure that ends the run rides on `scan.finished{status:"failed"}` instead, so this is never a reason to abandon a run that is still producing findings. |
| `phase.finished` | `status` plus `reasons`/`limits` (below) for that phase. |
| `scan.interrupting` | **Nonterminal.** A shutdown began (SIGINT/SIGTERM). The terminal event still follows — do not treat this as the end of the stream. |
| `scan.finished` | Terminal. `status`, `findings_by_severity`, `records_written`, and `stop_reason`/`reasons` when coverage was lost. `targets_admitted`/`targets_rejected` and, once the preflight ran, `targets_reached`/`targets_unreachable`. `--max-requests` running out ends the scan `curtailed` with `stop_reason: request_budget`; hosts that used their `--max-requests-per-host` are listed in `budget_exhausted_hosts` (their phases carry the `host_request_budget` limit). `extensions_failed` lists the paths of extensions that failed to load; `module_errors` is the error count per module id (exceptions, timeouts and panics; also on the scan row). |
| `auth.session_suspect` | A session's responses (or its proactive probe) look logged out: `session`, `gen` (credential generation), `detail` (`status`/`redirect`/`body`/`interval`). The `check.url` probe confirms before any re-login. |
| `auth.relogin` | A re-login cycle ended: `session`, `gen` (new generation when `ok`), `ok`, `count` (logins tried), `message` on failure. `ok: false` means the session is lost: phases go partial with `auth_lost`. |

### Reserved types and fields

These are in the event vocabulary (`scanevents.Types`, `vigolium schema event`)
but **nothing emits them yet**. Until then the type never appears and the field
is absent; code against them and ignore them while they are missing.

| Type or field | On | Carries |
|---|---|---|
| `records_basis` | `scan.finished` | Absent: `records_written` counts records stamped with this scan. `time_window`: records created since the scan started (approximate on a shared DB). |
| `exports` | `scan.finished` | `[{format, path}]` for every file the scan wrote. |

### Terminal `status` values

| `status` | Means |
|---|---|
| `completed` | Ran to the end and covered its input. |
| `curtailed` | Ran to the end but **did not cover everything** — a budget fired, targets failed, or records could not be stored. **Exit code is still 0.** |
| `interrupted` | SIGINT/SIGTERM. |
| `failed` | The run ended on an error. |

`curtailed` is a downgrade of `completed` only: `failed` and `interrupted` pass
through untouched, because a scan that failed is not a scan that was curtailed.

### Coverage fields

`phase.finished` and `scan.finished` carry three additive fields. On a clean
scan these keys are absent, not empty.

| Field | On | Means |
|---|---|---|
| `reasons[]` | both | Coverage was **lost**: `scan_budget`, `phase_deadline`, `cancelled`, `targets_failed`, `targets_skipped`, `persistence_incomplete`, `auth_unavailable`, `oast_unavailable` (blind/out-of-band checks skipped; a caveat, never the `stop_reason` while another reason exists), `checkpoint_failed`, `input_incomplete`, `targets_out_of_scope` (scope refused some targets, or every item of a phase), `targets_unreachable` (some admitted targets gave no HTTP answer to the preflight GET, or a quarantined host's items were skipped), the stop reason `no_targets_in_scope` (scope refused every target; nothing was sent, exit 1), and the stop reason `no_targets_reachable` (no admitted target answered; no phase ran, exit 1), `auth_lost` (a session expired mid-scan and re-login did not restore it; with `reauth.on_failure: abort` it is also the `stop_reason`), `extensions_all_failed` (every extension that ran failed on every item it ran on — the run's extension coverage is nil, not clean), `phase_error` (a phase failed and the scan carried on without it; the phase is `failed` and an `error` event names it), … `request_budget` (`--max-requests` ran out) is also the `stop_reason` when it fires. |
| `limits[]` | both | A configured bound was **reached** — designed behaviour (`target_budget`, `host_request_budget`, `js_template_persist_cap`, `cdx_max_rows`, `sitemap_cap`, and `responses_while_logged_out` — responses a phase received while a session was logged out, counted in the phase's `counts`; reserved: `js_request_cap`, `js_input_over_hard_limit`). Never downgrades a status; do not read a correctly time-boxed target as degraded. |
| `stop_reason` | `scan.finished` | The scan-level roll-up of why the run stopped launching work. |

The same facts are persisted on the scan row as `completeness`
(`complete`/`partial`; **empty means unknown**), `stop_reason`, and
`phase_outcomes` — readable in the scan document (`vigolium scan wait <uuid>
-j`), and carried by the REST scan object and `--format jsonl`. Reason codes are **add-only**: new ones appear over time, so
match the ones you care about and ignore the rest rather than switching
exhaustively.

Five contracts you can build on:

- **Every line carries `scan_uuid`.** A sweep is several `vigolium scan`
  invocations; this is how you attribute an event to one.
- **`v` is the event-schema version.** Gate on it.
- **`seq` is the stream's own total order**, a 1-based write counter stamped
  under the write lock. Use it to detect a dropped line; `ts` alone cannot.
- **`scan.finished` is always last**, including `status:"interrupted"` on
  SIGINT/SIGTERM and `status:"curtailed"` on lost coverage. `scan.interrupting`
  may precede it and does not end the stream.
- **Its absence means the process was killed outright** (SIGKILL can't be
  caught). Treat a stream that stops without a terminal event as a hard kill,
  not as a completed scan.

This replaces scraping `vigolium log` for `[waf-block-detected]` /
`[waf-pacing-armed]` markers — every notice that reaches the log also reaches the
stream, with no `log` invocation and no session-listing walk.

### Watching a scan you did not start in this shell

Backgrounded the scan, or lost its stream? Pin its UUID and poll it:

```bash
ID=$(uuidgen | tr A-Z a-z)
vigolium scan -t https://target.example --scan-uuid "$ID" >/dev/null 2>&1 &
vigolium scan status "$ID" -j                  # where is it now (one item)
vigolium scan wait "$ID" --timeout 45m -j --fail-on high   # block until it ends
```

- `scan status -j` → `items[0]`: `effective_status`
  (`running|abandoned|completed|failed|cancelled`), `phase`, `phases_done`,
  `requests_sent`, `findings_by_severity`, `progress {done,total,unit}` (null
  without a count), `eta {estimate_ms, upper_bound_ms, basis}`,
  `liveness {last_write_at, stale, sources, process_gone}`, and `plan` (the
  scan's stored plan, verbatim; null when the row has none).
- **Act on `effective_status`, not `status`.** `abandoned` = the row still says
  `running` but nothing has written for 2 minutes, or its PID on this host is
  gone. The process died; do not wait on it.
- **ETA is null when there is no basis** — never read null as "almost done".
  `upper_bound_ms` is the tighter of the remaining `--scanning-max-duration`
  and the stored plan's ceilings for the phases left; `estimate_ms` is the
  current phase's rate (needs a known total) plus the later phases at 0.6 of
  their ceilings. `basis` names the inputs (`phase_rate`, `plan_ceilings`,
  `scan_budget`).
- `scan wait` exits `0` completed, `1` failed/cancelled (`failed`),
  `scan_abandoned` or `wait_timeout` (default `--timeout 30m`), `4` on
  `--fail-on`, `5` on `--fail-on-partial` with a partial scan. When the scan
  ends, `-j` prints the **scan document** — the same envelope `scan -j` prints
  (`kind: "scan"`, findings as `items`, `status`, `completeness`,
  `phase_outcomes`, `plan`), rebuilt from the row — so parse it exactly as you
  would a scan you ran. Progress goes to stderr (or, with `--events ndjson`, as
  `phase.progress` lines on stdout).
- Works for `-S` and `--db-isolate` scans too: the runner's heartbeat file
  (`<sessions_dir>/<uuid>/status.json`) answers when the row is not in the
  store yet.
- `log ls -j` rows carry the same verdict: `effective_status`, `stale`,
  `last_write_at`, `liveness_sources`. Use them to find dead `running` rows;
  `vigolium log ls --reap` finalizes them (`status: failed`,
  `stop_reason: "abandoned"`; `-j` lists them in `reaped`) and prunes
  `status.json` files older than `scan_logs.status_retention_days` (default 30).

## Step 3 — Read the results

```bash
# Compact triage list of high+ findings, only the fields you need.
vigolium finding --min-severity high --json --compact \
  --fields id,severity,module_id,url,matched_at

# One finding, fully self-contained (finding + linked request/response).
vigolium finding --id 42 --json --with-records

# Narrow a search to the Nth match by list position (1-based).
vigolium finding --search 'Reverse Proxy' --pick 2 --raw

# The endpoint inventory: one row per origin + path template (/users/{int}),
# methods, params by location, status mix, auth split, live finding counts.
vigolium endpoints --host api.example.com --json
vigolium endpoints --source jstangle --json        # routes known only from JS

# Parameters with value-type histograms: IDOR candidates in one call.
vigolium params --type integer,uuid,sequential_id --json

# Survey raw records without bodies — cheap.
vigolium traffic --json --compact \
  --fields uuid,method,url,status_code,response_content_type

# Only what one scan stored first (records are stamped on insert).
vigolium traffic --scan-uuid <uuid> --json --compact

# Everything for one record.
vigolium traffic search-term --json --full-body -n 1
```

`endpoints` and `params` aggregate in one streaming pass over light columns
(never bodies), through the same filters as `traffic`, so they are safe on a
large corpus. Their `-j` items and caps are in
[data.md → endpoints](data.md#endpoints) / [params](data.md#params). An empty
`--scan-uuid` read for a scan with no stamped records carries
`provenance_warning: "scan_uuid_not_stamped"` (it predates stamping — use the
`--from/--to` window in `provenance_detail`), not a silent empty list.

Filters shared by `finding` / `traffic` / `db ls`: `--host --path --method
--status --severity --min-severity --from/--to --search --scan-uuid
--agentic-scan --module-type -n/--limit --offset --sort --asc`.

`--search` / `--header` / `--body` span the full request/response corpus (URL,
path, headers, body). Each has an inverse — `--exclude-search` (repeatable,
AND-combined: a row drops if ANY term matches), `--exclude-header`,
`--exclude-body`:

```bash
vigolium traffic --search api --exclude-search /health --exclude-body heartbeat
```

Finding output shape:

```json
{ "schema_version": 2, "command": "finding", "kind": "read", "ok": true,
  "project_uuid": "…", "total": 39, "offset": 0, "limit": 100,
  "items": [ { "id": 2, "finding_hash": "…", "severity": "high", "module_id": "…",
               "url": "…", "status": "draft", "matched_at": ["…"],
               "response_evidence": "…<match>…" } ] }
```

## Step 4 — Confirm a finding

Two tools, for two questions:

- **Does the module still find it?** `vigolium finding verify <id|hash>...`
  re-runs the finding's own module against the request it scanned, on the one
  insertion point it was found on, and records a verdict. Use it first: it
  needs no reasoning about the payload and it writes the answer back.
- **What exactly does the target answer?** `vigolium replay` re-sends one
  request and diffs it against the stored baseline, for manual confirmation.

```bash
vigolium finding verify 42 -j                         # one finding
vigolium finding verify --scan-uuid <uuid> --mark -j  # every finding of a scan, status set
vigolium finding verify 42 --dry-run                  # what would run; sends nothing
```

Verdicts: `confirmed` (the module reported it again), `not_reproduced` (the
module ran against a responding target and did not), `inconclusive` (target
unreachable, module timed out, or no baseline could be rebuilt — the `reason`
says which), `unsupported` (agent, audit, OAST and known-issue-scan findings,
or an `ext-*` module not loaded with `--ext`). The verdict lands in the
finding's `verification` field (`finding -j` shows it with `verified_at`); the
status is untouched unless `--mark` moves `not_reproduced` → `false_positive`
and `confirmed` → `confirmed`, with the same audit trail as `finding mark`.
Passive findings are re-analyzed on the stored record without a request
(`--refetch` fetches a fresh one). `--fail-if not_reproduced` exits 4 when any
finding matches, after the envelope is written. Full reference:
[data.md → finding verify](data.md#finding-verify).

`vigolium replay` re-sends **one** request and diffs it against the stored
baseline. It is the CLI surface of the in-process `replay_request` tool, and it
is the way to inspect a finding's evidence by hand before reporting it.

```bash
# Re-send the request behind a stored record.
vigolium replay --record-uuid <uuid>

# Re-confirm a finding's evidence. When the finding came from an imported
# source (audit, JSONL) with no linked record, this falls back to the
# finding's stored request/response bytes.
vigolium replay --finding-id 42

# Any input shape: curl, raw HTTP, Burp XML, base64, URL, or stdin.
vigolium replay -i "curl -X POST https://target.example/api -d '{\"id\":1}'"

# Send exact bytes verbatim (no reframing).
vigolium replay --raw-request-file ./request.txt
```

Output is a human summary by default. Under `-j` it is one envelope whose
`items[0]` is the result: `result.baseline`, `result.replay`, `result.diff`
(status delta, length delta, content hash, interpretation). A supplied request
(`-i`, `--raw-request`) is sent **once**, with `baseline` and `diff` null; add
`--baseline` to send it a second time as a baseline and diff the two. `--format jsonl`
prints the same object bare, on one line; `-o <file>` writes that line to a file.

**Persist auth across calls.** Multi-step flows (login → CSRF → action) need
cookies between requests:

```bash
vigolium replay --session-id login -i curl-login.sh        # sets cookies
vigolium replay --session-id login --record-uuid <action>  # reuses them
```

The jar lives at `~/.vigolium/replay-jars/<session-id>.json`; `--no-cookies`
opts out.

**Confirm against another environment** — `--target` rewrites the destination
while keeping the baseline request bytes intact:

```bash
vigolium replay --record-uuid <prod-uuid> --target https://staging.example.com
```

**Update the stored baseline** with `--in-replace` (only when the source is a
stored HTTPRecord):

```bash
vigolium replay --record-uuid <uuid> --in-replace
```

## Recording a verdict

Once a finding is confirmed or refuted, write the verdict back so later gates
and diffs stop re-asking:

```bash
vigolium finding mark 42 --as confirmed --note "replayed: 500 + SQL error on id=1'"
vigolium finding mark 3f9a0c2b71de --as false_positive --note "static asset" -j
```

Verdicts: `false_positive`, `accepted_risk` (both **dismissed**), `confirmed`
(reproduced), `triaged` (believed real, not reproduced), `fixed`. Name findings
by id or by `finding_hash` (≥12-char prefix) — the hash survives merges and
exports, the id does not. Dismissed findings drop out of `--fail-on`, `scan diff`
and `finding --new-since`; `finding --verdict <list>` filters on the status and
the `-j` item carries `status`, `status_note`, `status_actor`. An id or hash that
matches nothing **exits 1** (listed in the envelope's `not_found`). Refused under
`--glob-db`, a `.jsonl` `--db`, and `--read-only`. Full reference:
[data.md → finding mark](data.md#finding-mark).

## What changed since the last scan

A re-run overwrites `findings.scan_uuid` with the newest observer, so
`--scan-uuid` cannot answer "what is new". Use the per-scan observation history:

```bash
vigolium scan diff previous latest -j            # keywords, UUIDs or 8+ char prefixes
vigolium scan diff --target https://app.example --last 2 --fail-on-new high
vigolium finding --new-since <base-scan> -j      # composes with every finding filter
vigolium finding --new-since 24h -j              # or a time: stored after it
```

Each `scan diff` item is the finding view plus `change` and `first_seen_scan`:

| `change` | Meaning |
|---|---|
| `new` | head saw it, base did not |
| `unchanged` | both saw it |
| `fixed` | base saw it, a **comparable** head did not |
| `not_reobserved` | base saw it, a head that cannot vouch for its absence did not — **not** evidence of a fix |

The envelope adds `base`/`head` (uuid, status, completeness, target),
`comparable` + `comparability_reasons` (`head_partial`, `head_not_finished`,
`head_targets_not_superset`, `head_phases_not_superset`, `*_unknown`), `counts`,
and `history`: `"partial"` when a scan predates the store's observation history,
so an older re-detection may be missing. Dismissed findings are left out unless
`--include-dismissed`. `--fail-on-new <sev>` exits `4` after the result is written.

`scan <uuid>` is refused (exit 2) — a UUID in the target position is a mistyped
subcommand (`scan staus <uuid>`), and the error points at the `scan` subcommands.

## Step 5 — Hand off

### To Burp, for manual work

All Burp handoffs need the bridge extension's loopback listener via
`-B`/`--burp-bridge-url` or `$VIGOLIUM_BURP_BRIDGE_URL`.

```bash
# A finding's evidence → Burp Organizer (default) or a Repeater tab
vigolium finding --id 42 --push-to-burp -B http://127.0.0.1:9009
vigolium finding --severity high --to-repeater -B http://127.0.0.1:9009

# A replayed request → Repeater / Organizer / Site map
vigolium replay -u <uuid> --to-repeater -B http://127.0.0.1:9009
vigolium replay -u <uuid> --to-organizer --notes "IDOR candidate" -B http://127.0.0.1:9009

# Fuzz matches → the Organizer (Burp re-issues each)
vigolium fuzz -u <uuid> --fuzz params --class sqli --matches-to-organizer -B http://127.0.0.1:9009
```

`--send-via-burp` (on `replay` / `fuzz` / `finding`) routes the actual send
through Burp's engine byte-for-byte. Pair it with `--http-mode http1` for
smuggling/desync work so `auto` doesn't reframe the request.

Reading Burp's live history, Site map sync, limits, and the full flag surface:
**[burp.md](burp.md)**.

### As a curl command

```bash
vigolium finding --id 42 --curl                 # the finding's proving request
vigolium finding --id 42 --curl-all -j          # every linked record, as items
vigolium traffic --uuid <id> --curl --redact-auth
```

The URL comes from the stored scheme/host/port, arguments are POSIX
single-quoted (safe for `sh -c`), and a binary body is piped through
`base64 --decode`. Under `-j` each item carries `curl` (the shell line) and
`argv` (the exec vector). `traffic --curl` renders at most 20 without `-a`.
Nothing is sent. Details: [data.md](data.md#traffic---curl--finding---curl).

### To a report

```bash
vigolium finding --id 42 --markdown                 # Markdown to stdout
vigolium export --format html -o report.html        # interactive ag-grid report
vigolium export --format jsonl -o out.jsonl         # bulk stream
```

Under `-S/--stateless`, add `--compact` to `--markdown` so the response is
windowed at the match instead of dumping a whole page.

## Bulk replay

There is **one** bulk replay implementation: `vigolium replay`.
`vigolium traffic --replay` is a shortcut for it that keeps traffic's flag
spellings, defaults to the human comparison table, and does not follow
redirects. Reach for `replay` directly whenever you need to *change* the
request — the shortcut has no override flags.

Bulk `replay` still streams JSONL (one object per record) by default, with a
stderr notice; the default becomes the per-record tables in the next release.
Say what you want: `--format jsonl` for the stream, `-j` for one envelope.

```bash
# Re-send ALL stored traffic through Burp, 5 at a time.
vigolium replay --all --proxy http://127.0.0.1:8080 -c 5

# Fuzzy-search stored traffic and re-send just the matches.
vigolium replay admin --proxy http://127.0.0.1:8080 -c 5

# Pattern-search like `traffic`: POSTs to an API host, drop logout.
vigolium replay --host api.example.com --method POST --search token \
  --exclude-search logout --proxy http://127.0.0.1:8080 -c 5

# From a standalone export (project scoping off).
vigolium replay -S --db scan.sqlite --all --proxy http://127.0.0.1:8080 -c 5

# Per-record tables instead of the JSONL stream.
vigolium replay login --format console

# One envelope, every replayed record a row in items (failed ones carry error).
vigolium replay login -j
```

Bulk selection mirrors `vigolium traffic`: `--host`, `--method`, `--status`,
`--path`, `--source`, repeatable AND-combined `--search`, `--header-search`,
`--body`, `--exclude-search`/`--exclude-header-search`/`--exclude-body`,
`--from`/`--to`, `--sort`/`--asc`/`--offset`. Throttle with `-c/--concurrency`
(default 10), cap with `-n/--limit` (default 100; `--all` lifts it). Bulk
selection is mutually exclusive with `--record-uuid` / `--finding-id` /
`--input`. With `-B/--burp-bridge-url`, live Burp Proxy history is merged into
the selection just as it is for `traffic`.

### Replaying with different headers / cookies

`--header-search` **filters** which records are selected; `-H/--header`
**rewrites** headers on what gets sent. (They are separate flags because
`traffic`'s `--header` is a search filter.) `-H` replaces the whole header
value, so pass the complete cookie string — it is not additive per-cookie.

```bash
# Same request, another user's session — the diff IS the IDOR/BFLA check.
vigolium replay -u <uuid> -H 'Cookie: session=victim; csrf=xyz'

# Merge a stored auth session, then override one header on top (-H wins).
vigolium replay -u <uuid> --auth-session staging -H 'X-Forwarded-For: 127.0.0.1'

# Re-send everything that carried a header, under a different session.
vigolium replay --header-search 'X-Api-Key' -H 'Cookie: session=other' -c 5
```

### Browser-driven replay

`--with-browser` loads each matched URL in a real browser routed through
`--proxy`, so the proxy sees genuine browser traffic — real TLS fingerprint, JS
execution, subresource loads. It is **navigation-only**: a browser exposes no
status code or response body, so these runs report final URL, title, and fired
JS dialogs and carry **no diff** (`result` is null; a `browser` object is
emitted instead). A navigation is a GET, so a non-GET record's method and body
are not reproduced — the JSON says so in `browser.method_note`.

```bash
vigolium replay --all --with-browser --proxy http://127.0.0.1:8080
vigolium traffic --replay --with-browser --proxy http://127.0.0.1:8080
```

`validateReplayFlags` rejects it alongside every flag downstream of the send
(`--in-replace`, `--raw-request`, and the Burp send/stage targets), and warns
when `--proxy` is absent — a browser run with nothing intercepting it captures
nothing.

## Payload fuzzing

`vigolium fuzz` is a low-level **primitive**, not a scanner. It injects a
caller-supplied payload set into chosen positions of ONE request and streams
per-payload signals (status / size / words / lines / time / reflection /
baseline-delta) with match/filter gating and auto-calibration against the
target's catch-all. It makes **no** vulnerability decision and emits **no**
findings — you bring the intelligence.

For confirmation-backed detection of known classes, use the module scanner
(`scan-request -m …`) instead. `fuzz` fills only the gap modules can't express:
custom payloads, an exact position, wordlist-scale discovery.

```bash
# Start here: let anomaly detection find what's interesting — no matchers needed.
vigolium fuzz -u <record-uuid> --point URL_PARAM:id --class sqli -a

# A literal FUZZ marker anywhere in the request wins over --fuzz/--point.
echo -e "GET /api/FUZZ HTTP/1.1\r\nHost: target.example\r\n" | vigolium fuzz -w dir-short

# Wordlist discovery + matcher gating (keep 200/301, drop the calibrated catch-all).
vigolium fuzz https://target.example/FUZZ -w file-long --match-status-code 200,301

# Build the request curl-style from a positional URL.
vigolium fuzz https://target.example/login -X POST \
  -d 'user=admin&pass=FUZZ' -H 'X-Api-Key: k' -w file-short

# Inline payloads across a specific header, with excludes.
vigolium fuzz -u <uuid> --fuzz-header X-Forwarded-For \
  -p "127.0.0.1" -p "localhost" --exclude-size 0

# Two markers in lockstep (user/pass pairs from two lists).
vigolium fuzz -i login.txt --mode pitchfork -w users.txt -w passwords.txt

# Agent handle: ONE envelope on stdout, exit 3 on match.
vigolium fuzz -u <uuid> --fuzz params --class xss,sqli -a -j --fail-on-match
```

**Source** (one of): a positional URL, `-i/--input` (curl / raw HTTP / Burp XML /
base64 / URL / `-`), `--input-file`, `-u/--record-uuid`, or a piped request on
stdin. `-t/--target` overrides scheme/host/port without touching the bytes.

**Positions** (first match wins): a literal `FUZZ` marker anywhere →
`--point TYPE:name` → `--fuzz-header` →
`--fuzz method|path|params|param-name|headers|cookies|all` (default: all
insertion points).

**Payloads** combine `--class` (`cmdi,crlf,lfi,open_redirect,path_traversal,sqli,
ssrf,ssti,xss,xxe`) + `-w/--wordlist` (builtin `dir-long`, `dir-short`,
`file-long`, `file-short`, `fuzz`, or a file path) + `-p/--payload` (inline,
repeatable).

**Prefer `-a/--anomaly` over hand-written matchers.** A matcher requires knowing
the interesting size or status up front; `-a` instead scores every response
against the baseline *and* the run's own population and keeps what stands out,
with `anomaly_score` + `anomaly_reasons` on each result. It reports where to
look, never a verdict.

**Output** (matched only unless `--all-results`): a human table by default;
`--format jsonl` for the per-payload stream on stdout; `-o` writes that stream to
a file. Under `-j`, ONE envelope goes to stdout — the ranked top results in
`items`, plus `target, sent, matched, calibrated, baseline, anomalies` at the top
level — and `query`/`query_argv` is a ready `scan-request` confirmation command.
`--fail-on-match` exits 3 for CI/agent gating.

Always `--dry-run` a large run first: it resolves positions and payloads and
prints the exact bytes each would send, with **zero** network traffic.

Attack modes, the full signal/weight table, matcher grammar, curl-parity flags,
and operational knobs: **[fuzzing.md](fuzzing.md)**.

## Reading exports without a database

`finding` and `traffic` can read a file directly instead of your project DB.
`-S/--stateless` requires `--db` and turns project scoping **off**, so every row
in the file is shown. Nothing is written to your project DB (a JSONL source is
loaded into a throwaway scratch SQLite **file**, deleted on exit — it was
in-memory once, and a large export did not fit). An explicit `--project-uuid`
(or `$VIGOLIUM_PROJECT_UUID`) still filters a stateless read.

```bash
vigolium finding -S --db ./scan-target.jsonl --min-severity medium
vigolium traffic -S --db ./scan-target.jsonl --status 500 -n 20
vigolium finding -S --db ./run.sqlite --json --with-records
```

**Pin a session DB with `$VIGOLIUM_DB_PATH`** to avoid repeating `--db` on every
command. The open order is `--db` → `$VIGOLIUM_DB` → `$VIGOLIUM_DB_PATH` →
`database.sqlite.path` in config → the built-in default. `$VIGOLIUM_DB` is
exactly `--db` from the environment (project scoping stays on); it is what an
agent run hands the `vigolium` commands its bash tool runs, alongside
`$VIGOLIUM_PROJECT_UUID`, `$VIGOLIUM_CONFIG` (`--config` from the environment)
and `$VIGOLIUM_BIN`. Setting it also makes **read** commands
(`finding`/`traffic`/`fuzz -u`) treat that file as a stateless source — project
scoping off, same as `-S --db` above — while writes still go to it. It never
turns a *scan* stateless (that would collide with `--db`).

```bash
export VIGOLIUM_DB_PATH=~/scans/acme.sqlite
vigolium finding --min-severity high      # reads acme.sqlite, scoping off
vigolium scan -t https://acme.example     # writes into acme.sqlite
```

The scoping-off flip is conditional: it applies once the pinned file **exists and
is a usable vigolium store**. Run that `finding` before the first scan of the
session and the read stays project-scoped against a store it just created — which
is the right behavior (it prints an empty table instead of erroring), but means
`project_scoped` is the field to check, not something to assume. A pin that can
never *become* a database — a directory, or a parent dir that cannot be created —
is a hard error rather than a silent fall-through to the shared default; a path
that merely does not exist yet is fine.

A stateless scan emits that `.sqlite` directly with `--format sqlite` (aliases
`sqlite3`, `db`) — it dumps the per-run DB via `VACUUM INTO`, fully
checkpointed, no WAL/SHM sidecars:

```bash
vigolium scan -S --format sqlite,html -o scan -t target.example
vigolium scan -S --format sqlite -o run --split-by-host -P 4 -T targets.txt
vigolium finding -S --db ./run-target.example.sqlite --min-severity high
```

**Merging** foreign databases is the companion operation — `vigolium import`
folds them into one DB (lossless, idempotent, deduped on natural keys; each row
keeps its original `project_uuid`):

```bash
vigolium import other-vigolium-scan.sqlite
vigolium import --db combined.sqlite --glob-db 'scans/*.sqlite'
vigolium -j import --db combined.sqlite other-scan.sqlite   # per-table merge summary
```

Fan out with `scan -S --format sqlite`, merge back with `import`. A Postgres
destination is rejected — the merge is SQLite-to-SQLite.

## Filesystem tree output

When you'd rather `ls`/`grep`/`jq` a scan than query a DB, export a flat tree.
Available on `scan`/`scan-url`/`scan-request`/`run`, `export`, and `db export`.

```bash
vigolium export --format fs -o run                    # whole DB
vigolium scan-url https://t/ -S --format fs -o run    # straight from a scan
vigolium scan -t https://t/ --format jsonl,fs -o run  # alongside other formats
```

Two sibling dirs off the `-o` base (defaults to `vigolium-traffic/` +
`vigolium-findings/` in the cwd). Ids are zero-padded and assigned in `sent_at`
order, so re-exports are reproducible:

```
run-traffic/
  index.json                 # [{id,host,path,method,url,status,content_type,bytes,finding}, …]
  <host>/0001.req            # "@target https://<host>" line, then the raw request
  <host>/0001.resp.headers   # status line + response headers
  <host>/0001.resp.body      # response body, gzip-decoded so it greps clean
run-findings/
  index.json                 # [{id,host,path,severity,confidence,module,title,url,traffic}, …]
  <host>/0001.md             # the finding, cross-linked to ../../run-traffic/<host>/0001.req
```

`index.json` is the entry point — one `jq` maps every id to its url/status and to
the file holding the bytes, so you never guess paths. The `finding` field on a
traffic row is the top severity of any finding touching that request. A `.req`
file is directly replayable by stripping line 1.

`--omit-response` drops the `.resp.*` files. `--split-by-host` is a no-op here
(fs already splits by host).

### Live mirror from the ingestion server

To watch traffic land as files while another tool (Burp, a proxy,
`vigolium ingest`) feeds the server:

```bash
vigolium server --mirror-fs ./mirror        # config: server.mirror_fs_path
```

Every ingested record and finding is written to `./mirror/traffic/<host>/…` and
`./mirror/findings/<host>/…` as it is saved to the DB. Same layout as
`--format fs`, except the indexes are append-only **`index.jsonl`** (one object
per line — tail/grep it live) and per-host ids resume across restarts. It runs on
a background goroutine that never blocks the DB save, and is
server-ingestion-only — CLI scans are unaffected.

## Agentic scans

These run an LLM-driven scan into the DB. With `--json`, the live agent stream
goes to **stderr** and one run document is printed to **stdout** at the end:

```bash
vigolium agent audit --source . --intensity balanced --json
vigolium agent autopilot -t https://target.example --json
vigolium agent swarm -t https://target.example --json
vigolium agent query --prompt-template security-code-review --source . --json
```

Run document (autopilot / swarm / audit; `kind: "scan"`, the scan document's
spine):

```json
{ "kind": "scan", "ok": true, "agentic_scan_uuid": "…", "mode": "autopilot",
  "session_dir": "…", "status": "completed", "completeness": "complete",
  "persisted": true, "usage": {"input_tokens": 0, "output_tokens": 0, "cost_usd": 0},
  "budget": {"max_commands": 750, "token_budget": 0, "max_cost_usd": 0, "exhausted": false},
  "total": 7, "counts_by_severity": {"critical":1,"high":3, …},
  "items": [ … top 20 finding views … ], "errors": [], "warnings": [],
  "query": "vigolium … finding --agentic-scan <uuid> -j" }
```

Branch on `status`: `completed` / `completed_with_warnings` (exit 0);
`timed_out`, `budget_exhausted`, `completed_with_errors` (exit **5**, the run's
work is still in the DB); `failed` / `cancelled` (exit 1). The database spells
`timed_out` as `timeout`. With no DB the document still prints,
`persisted: false`. `provider_missing` / `preflight_failed` (exit 1, error
envelope) mean nothing ran. Budgets: `--max-commands`, `--token-budget`,
`--max-cost-usd`, `--max-duration`. `agent audit` needs `--source` (`.` for
cwd); `agent autopilot` runs a nested `--audit`/`--piolium` harness only when
asked. `agent triage <id> -j` is a mutation document (`--no-write` to report
only; a `false_positive` keeps its severity). `agent query` / `triage` print
their `agentic_scan_uuid` on stderr.

Run the `query` line to pull full results. `--agentic-scan` expands to the whole
run tree (audit driver legs, swarm sub-runs), so one UUID returns every finding
the run produced.

Full flags, intensities, and providers: `references/agent-modes.md`.

## The `-j` envelope

Every command prints **one envelope document** under `-j/--json`, so one
parser handles them all: reads, mutations (`finding mark`, `project use`,
`module enable`), scans (`scan`, `run`, `scan wait`, the agent runs), `kit *`,
`fuzz`, `doctor` and `version` included. Parse `items`; do not write key
fallbacks. `vigolium schema command <name>` prints the exact JSON Schema of a
command's document; `vigolium schema list` names every covered command.

Two shape notes that are not exceptions to the envelope, just to `items`:

- `items` is **always an array**, never `null` and never an object. A command
  whose answer is one object (`db stats`, `db compact`, `traffic body`/`headers`
  receipts) wraps it as `items: [obj]` with `total: 1`, so `.items[0]` reads it.
- `ingest -j` has an empty `items` (`[]`); its payload is the sibling fields
  `records_ingested`, `records_failed`, `records_skipped`, `input_format`,
  `record_source`, `duration_ms`. `records_ingested` is rows the database
  HOLDS — it equals a `count(*)` on `http_records` for the run — and a non-zero
  `records_failed` exits `1` with `error.code: "ingest_incomplete"`.

**Errors are JSON too.** A failed `-j` command writes a parseable error object to
**stdout** and the human `✖ Error:` line to stderr, so a consumer never has to
scrape prose:

```jsonc
{ "schema_version": 2, "command": "traffic", "ok": false,
  "error": { "code": "source_missing", "message": "…", "exit_code": 1 } }
```

`error.code` is the stable branch point. A successful envelope has no `error`
key. Still check the exit code — a parseable error is still an error.

**Source codes** — three different next moves:

| `error.code` | What the file is | What to do |
|---|---|---|
| `source_missing` | nothing at that path | fix the path |
| `source_unreadable` | not a database, or corrupt | treat it as damaged evidence; do not "recover" it by reading somewhere else |
| `source_incompatible` | **valid SQLite that is not a vigolium store** — it opens and passes an integrity check, but has none of vigolium's tables | you are pointed at the wrong file (a zero-byte stub, another tool's database) |
| *(no error, `total: 0`)* | a real vigolium store with no matching rows | nothing has scanned this yet — go scan it |

Those four are distinct on a read. **A pure read command
(`traffic`, `finding`, `db ls`, `db stats`, `db export`, `export`, `log`,
`traffic body`, `traffic headers`) against an explicitly pinned `--db` or
`$VIGOLIUM_DB_PATH` never creates a store**: a path that is not there fails
`source_missing`, and one that is there but is not a vigolium database fails
`source_incompatible`. Neither needs `--read-only`; that flag is about leaving
the file byte-identical (below).

The built-in default database is still created on first use, because a fresh
install's first `vigolium traffic` legitimately has nothing to read yet. It is
**not** created when `--db` (or `$VIGOLIUM_DB_PATH`) pins a different store.
`version`, `help` and `completion` never create `~/.vigolium`.

**Single-message extraction codes** (`traffic body`, `traffic headers`):

| `error.code` | Meaning |
|---|---|
| `record_not_found` | no record carries that `--uuid` |
| `body_unavailable` | the record exists, but the requested side was never captured |
| `body_decode_failed` | the body announces an encoding that could not be undone (try `--representation stored`) |
| `body_incomplete` | only a prefix is available; pass `--allow-incomplete` to take it anyway |

A body that *was* captured and is genuinely zero-length **succeeds**, with
`empty: true` in the receipt. That is not the same as never having been
captured (`body_unavailable`).

```jsonc
{
  "schema_version": 2,
  "command": "traffic",
  "kind": "read",
  "ok": true,
  "project_uuid": "…",
  "project_scoped": true,
  "project_source": "env",
  "db_path": "/home/me/.vigolium/database-vgnm.sqlite",
  "total": 39,
  "offset": 0,
  "limit": 100,
  "items": [ … ],
  "query": "vigolium traffic --uuid <uuid> --json --full-body",
  "query_argv": ["vigolium", "traffic", "--uuid", "<uuid>", "--json", "--full-body"],
  "generated_at": "2026-09-04T10:11:12.345Z",
  "generated_at_ms": 1788453072345
}
```

| Field | Why it is there |
|---|---|
| `schema_version` | Gate on it. Bumped on any breaking field change; `2` since v0.5.3 (scan document, every `-j` an envelope; `--json-legacy-keys` renders old row names for one release). |
| `ok` | `true` on every result document; the error object carries `"ok": false`, so `.ok` is a valid branch on anything `-j` prints. |
| `kind` | The document's shape: `read` (rows, or one object as `items: [obj]`), `mutation` (adds `changed`, `action`, and `dry_run` on a dry run) or `scan`. `changed` is always present on a mutation and is `false` on a dry run. |
| `finding_hash` | (on finding rows) The finding's stable identity — the dedup key and what SARIF fingerprints use. Selectable with `--fields`. |
| `items` | **The** row array, and the only one — always an array, `[]` when empty. The pre-envelope names (`records`, `findings`, `scans`, `rows`, `stats`) are not emitted by default: they duplicated every row on the wire. `--json-legacy-keys` (or `VIGOLIUM_JSON_LEGACY_KEYS=1`) brings the alias back for a caller still migrating, at that cost; for a one-object result the alias renders the object itself (`stats: {…}`). |
| `db_path` | The database this command actually opened. Assert it; the open order ends at one shared default file, so a fall-through silently mixes engagements. |
| `project_uuid` | The project filter that was **actually applied**, or absent when none was (a `-S` read spanning every project names none). |
| `project_source` | Where the project selection came from: `flag`, `env`, `active_file` (the global file `project use` writes; the envelope then also carries a `warnings[]` entry) or `default`. |
| `project_scoped` | Whether a project filter was applied at all, so "unscoped" is explicit rather than inferred from a missing `project_uuid`. `false` on a plain `-S` read; `true` once you pass `--project-uuid`. |
| `query` | A suggested follow-up. **Read it before running it** — see below. |
| `query_argv` | The same follow-up as an argv vector. Prefer it from code: `query` is shell-quoted for a human, and re-splitting it is where the quoting breaks the parse. The two are always present or absent together — both are absent under `--glob-db`, whose merged source no argument list can reopen. |
| `output_budget` | Present only when `--max-output-bytes` truncated the page: `{max_bytes, returned, omitted, next_offset}`. `total` still describes the whole result set. |
| `generated_at` / `_ms` | RFC3339 with **exactly 3** fractional digits, plus an epoch-millisecond sibling. Both are safe to compare against a JS `toISOString()`. |

### The `query` hint

Every hint is a valid, **read-only** command — running one never puts traffic on
the wire. `traffic`/`db ls` hand back `traffic --uuid <uuid> --json --full-body`
(inspect the record), `finding` hands back `finding --id <int> --json
--with-records` (the evidence bundle), `ingest` hands back a plain recency
listing.

To re-send a request you must ask for it explicitly — `replay -u <uuid>` or
`fuzz -u <uuid>`. Those are never suggested by a read.

Check the contract once at startup:

```bash
vigolium version --json   # envelope: schema_version (the -j contract); items[0] = {version, commit, db_schema_version, db_min_reader_version}
```

## Exit codes

| Code | Meaning |
|-----:|---------|
| `0` | success (or `--soft-fail` forced it) |
| `1` | error — the command failed to do its job |
| `2` | usage error — bad flag, bad value, rejected combination |
| `3` | `fuzz --fail-on-match` matched |
| `4` | `--fail-on <sev>` / `scan diff --fail-on-new <sev>` gate tripped |
| `5` | incomplete — ran but did not finish; `error.code` is `timed_out`, `budget_exhausted` or `partial` (agent runs; native partial scans still exit 0) |

**`4` is not a failure.** The scan ran to completion, wrote its output, and found
something at or above the threshold — the opposite outcome from `1`, where it
never got that far. Branch on them separately; treating every non-zero as
breakage either ignores real outages or reports every finding as one.

**A requested artifact that was not written is exit `1`, code `export_failed`** —
even when the scan itself ran clean, and even when it would otherwise have
tripped the `--fail-on` gate. The gate's whole premise is that the output was
written before the code was chosen; when it wasn't, exit `4` would send you to
read a file that does not exist. Retry the export, not the scan: the findings
reached the database, they just did not reach your `-o`. Formats are attempted
independently, so with `--format jsonl,sqlite` one of them may well be on disk —
the "Exports" summary on stderr lists what actually landed.

On the read commands:

| Read | Exit | `error.code` |
|---|---:|---|
| `--fields bogus` | `2` | `usage_error` (lists the valid names) |
| `--db <not a sqlite file>` | `1` | `source_unreadable` |
| `--db <missing file>` | `1` | `source_missing` — **nothing is created** |
| `--db <sqlite, but not a vigolium store>` | `1` | `source_incompatible` — **no tables are added to it** |
| `finding --id <a UUID>` | `2` | `usage_error` (names the flag that reads that namespace) |
| `traffic --group-by <unknown field>` | `2` | `usage_error` (lists the groupable fields) |
| `traffic body --uuid <no such record>` | `1` | `record_not_found` |
| `finding mark <id/hash that matches nothing>` | `1` | `not_found` — after the mutation envelope, which lists it in `not_found` |
| `finding verify … --fail-if not_reproduced` (a finding did not reproduce) | `4` | `gate_tripped` — after the envelope |
| `scan diff <unknown scan>` / `finding --new-since <unknown scan>` | `1` | `scan_not_found` |
| `traffic body --uuid <request with no response>` | `1` | `body_unavailable` |
| `scan -S -o <unwritable path>` | `1` | `export_failed` — the scan ran; the artifact did not land |
| `--id 999999` (no such finding) | `0` | —, `{"total":0,"items":[]}` |
| `--search zzzznomatch` (genuine zero hits) | `0` | —, `{"total":0,"items":[]}` |

The last two rows are still one answer each way, so to tell "no such finding"
from "`--search` legitimately matched nothing", assert the envelope's `db_path`
and check `total` against a second query you know matches.

`--read-only` is a *different* guarantee: the source file survives the
read **byte-identical**, with no journal-mode flip, no WAL checkpoint, and no
`-wal`/`-shm` siblings left beside it. Use it when the store is evidence or under
chain of custody. It costs nothing on a current store, but it cannot migrate an
old one — a store on an earlier schema fails with a schema error instead of
being upgraded in place, which is the point.

Always check the exit code before parsing — and never `2>&1` into a JSON parser:
the machine object is on stdout, the human line on stderr, and merging them
corrupts the stream.

`--fail-on <info\|suspect\|low\|medium\|high\|critical>` on `scan`/`run`/
`scan-url`/`scan-request` exits `4` when a finding at or above that severity is
present. Findings marked `false_positive` or `accepted_risk` ([`finding mark`](#recording-a-verdict))
do not count. **Output is always written first** — the gate only changes the exit
code. `--soft-fail` (global) forces exit 0 even on error and overrides
`--fail-on`. Under `-P/--parallel` the gate is evaluated **per child**: the
batch exits `4` when any child tripped it, and `1` only when every target
failed.

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
- **`-S`/`--stateless` is a scoping mode, not a read-only one.** By default,
  opening any database writes to it: `mkdir -p` on the parent, a `journal_mode`
  PRAGMA (a header rewrite) and a WAL checkpoint. A pure read never *creates*
  a store at a pinned path that has none (see the exit-code table), but it does
  still touch one that is there. Pass **`--read-only`** when the source is
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
