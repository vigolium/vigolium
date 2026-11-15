# Driving Vigolium from a coding agent

A compact, copy-paste reference for running Vigolium **non-interactively** from an
LLM/coding agent and parsing the results. Everything here is additive — the
default human output is unchanged; you opt into machine output with `-j/--json`.

> **Using an agent skill instead?** The same material — plus the replay/fuzz
> confirm chain and the Burp handoff — ships inside the binary as
> `references/agent-loop.md` in the `vigolium-scanner` skill. Install it with
> `vigolium skills install --agent claude` and your agent gets a version-matched
> copy without reading this page. See
> [`public/skills/README.md`](../public/skills/README.md).

## Mental model

- All data is stored in a project-scoped SQLite/Postgres DB. A scan **writes**
  findings + HTTP records; query commands **read** them back.
- Two JSON contracts:
  - **`-j/--json`** on read/query commands (`finding`, `traffic`, `db`) → a single
    structured object with **compact, token-aware** bodies. This is what you parse.
    On the scan commands (`scan`, `run`, `scan-url`, `scan-request`) `-j` is the
    one [scan document](#the-scan-document), printed when the scan ends.
    It is printed compact (one line); the global `--pretty` (or
    `VIGOLIUM_JSON_PRETTY=1`) indents it for reading.
  - **`--format jsonl`** / `export` → the bulk `{"type":...,"data":{...}}` stream
    (one object per line). Use for archival/bulk, not triage. After a scan the
    stream covers that scan's `scan` row, findings and records (the exchanges
    it stored first plus any its findings cite); `export` is the whole-project
    dump. It is a *view*, not
    a lossless copy of the store: HTTP exchanges sharing a URL collapse to the
    first one (plus any exchange a finding links to), and only confirmed findings
    are emitted. `export --no-url-dedup` turns the collapse off; for the complete
    store use `-S --format sqlite` or copy the database file.
- Non-interactive by default: the TUI is opt-in (`--tui`), never auto-launched.
  Destructive commands need `--force`. Color is automatic: on only when stdout
  and stderr are both terminals, off under `-j` and `--events`; `--color always|never|auto` overrides it (`--no-color`
  = `never`; `NO_COLOR`, `FORCE_COLOR` and `CLICOLOR_FORCE` are honored under
  `auto`). The banner prints only when stderr is a terminal and `--events` is
  off. Scope with `--project-uuid <uuid>`, `--project-name <name>`,
  `VIGOLIUM_PROJECT_UUID`, or `VIGOLIUM_PROJECT_NAME`.

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
| `--max-output-bytes N` | cap the whole result document at N bytes, dropping whole trailing items (`0` = unlimited, the default) |

### Capping the size of a result document (`--max-output-bytes`)

`-n/--limit` counts rows, and rows vary in size by orders of magnitude — twenty
compact findings are a few KB, twenty traffic records under `--full-body` are
tens of MB. If what you actually have is a byte budget (a context window, a log
limit, a response body), cap it directly:

```bash
vigolium traffic -j --full-body --max-output-bytes 65536
```

- Opt-in: `0` (the default) is unlimited, and nothing changes for a caller that
  does not pass it. Available on `finding`, `traffic` and `db ls`.
- The cut is at a **record boundary**, so what you get is still one valid JSON
  document — never a prefix of a broken one.
- A truncated document carries an `output_budget` object and nothing else
  changes:

  ```json
  "output_budget": {"max_bytes": 65536, "returned": 14, "omitted": 26,
                    "next_offset": 14}
  ```

  Resume with `--offset <next_offset>`. `total` still describes the whole result
  set, so a page cut by bytes reports exactly as one cut by `-n` does — including
  `complete: false` in the `-o` receipt.
- A budget too small for the envelope's fixed parts fails with exit `1` and
  `error.code: "output_too_large"` rather than emitting an over-budget document.
- It requires `-j/--json` (exit `2` otherwise): a silently ignored budget is
  indistinguishable from one that did not bind.

## Run a scan and gate on results

```bash
# Single-shot into your project DB, JSON findings to stdout, fail on high+.
vigolium scan-url https://target.example --json --fail-on high

# Same, but throw the database away afterwards (nothing persists).
vigolium scan-url https://target.example -S --json --fail-on high

# Full pipeline into the DB, exit non-zero if a high/critical is found (CI gate).
vigolium scan -t https://target.example --fail-on high

# Scan a raw request from stdin (pipeline-friendly).
printf 'GET /api?q=1 HTTP/1.1\r\nHost: target.example\r\n\r\n' \
  | vigolium scan-request --json
```

- `--fail-on <info|low|medium|high|critical>`: exit non-zero when a finding at or
  above that severity is present. Findings marked `false_positive` or
  `accepted_risk` ([Finding lifecycle](#finding-lifecycle)) do not count.
  `--soft-fail` forces exit 0 (still prints the reason). Output is always
  written first — the gate only changes the exit code.
- **`scan-url` and `scan-request` persist by default.** Their findings and
  traffic go into the project database like any other scan; `-S/--stateless`
  is what makes a run throwaway (pair it with `-o`/`--format` to keep anything).
- **Single-input scans test only their input.** `scan-url`, `scan-request` and
  `run <phase> -t` leave the records already stored for the target's host alone
  (`plan.targets.stored_records: "exclude"`, `db_records_excluded`);
  `--include-stored` tests them too. `scan -t` names an origin and keeps
  including them (`stored_records: "include"`, the banner states the count);
  `scan --input-only` excludes them.
- **`-S` on a scan writes nothing to `$HOME`.** On `scan`, `run`, `scan-url`
  and `scan-request`, `-S` skips the first-run bootstrap (no config, database,
  presets or `initialized` marker is created; the scan runs on embedded
  defaults and built-in profiles), does not write the update-check cache, and
  redirects every state path — native-sessions liveness, materialized
  wordlists, and a jstangle cache it cannot write — to a per-process scratch
  directory under `$TMPDIR` that is removed on exit. It may READ caches: an
  installed browser (`~/.cache/vigolium/chrome-for-testing-*`), jstangle, and
  nuclei templates. A download that would land in `$HOME` fails closed with
  the fix: missing templates fail the known-issue scan (`vigolium doctor --fix
  --only nuclei`, or `--known-issue-scan-templates-dir`), a missing browser
  fails the crawl (`vigolium doctor --fix --only chrome`, `spidering.browser_path`,
  or `--skip spidering`). Pin paths explicitly with `VIGOLIUM_WORDLIST_DIR`,
  `--known-issue-scan-templates-dir` and `spidering.browser_path` to reuse
  prepared copies in a read-only image. **Limitation:** the embedded
  nuclei/uncover libraries create their config directories
  (`~/Library/Application Support/{nuclei,uncover}` on macOS,
  `~/.config/{nuclei,uncover}` on Linux) at package init, before any flag is
  parsed; set `XDG_CONFIG_HOME`/`NUCLEI_CONFIG_DIR` to a writable path (e.g.
  `/tmp`) to keep them out of `$HOME`.
- **Every scan command prints ONE scan document under `-j`** — `scan`, `run`,
  `scan-url` and `scan-request`, on every path (direct, `-S`, `-o`, `--only`,
  `--skip`, one target or many, success or failure). See
  [The scan document](#the-scan-document). `-j` is not `--format jsonl`: the bulk
  stream runs only when `--format jsonl` is given, and goes to the `-o` file.
- **A target that never answered fails the command** (see
  [Reachability](#reachability)). The document is still written:
  `status: "failed"`, `stop_reason: "no_targets_reachable"`, the target's
  `reached: false`, `reason: "unreachable"`, `code` (`dns`, `refused`,
  `timeout`, `tls`, `reset`, `other`) and `detail`, `modules.executed: 0`, and an
  `errors[]` entry with `code: "no_targets_reachable"`. The exit is `1` unless
  another input of the same invocation answered.
- **`scan-request` reports how it chose the scheme** in the target's
  `scheme_source`: `explicit` (`-t`, an absolute-form request line, a curl URL),
  `port` (Host `:80`/`:443`), `origin`/`referer` (a same-origin header), `probe`
  or `default`. With none of the first four, it probes the target — a TCP
  connect, plus a TLS handshake on an explicit non-standard port — and scans over
  the scheme that answered; `resolved_target` is the result. Nothing answered
  keeps `https://` (`default`), and the unreachable error suggests
  `-t http://host:port`. `--no-scheme-probe` skips the probe. `replay -i` and
  `fuzz -i` parse raw request text the same way (`-t` pins the scheme; a
  missing final blank line is repaired, from a file or stdin), and probe only
  an in-scope host. `ingest -I burpraw -t <base>` rebases the captured request
  onto `<base>` instead of storing `<base>` as a record of its own.
- **Both commands enforce the config scope**, with or without `-S` (see
  [Scope admission](#scope-admission)). A refused input is not sent; its target
  entry says `admitted: false`, `reason: "out_of_scope"`, `code: <rule>`, and
  when every input was refused the command exits `1` with
  `stop_reason: "no_targets_in_scope"`. `--ignore-scope` scans it anyway.

### Plan first (`--dry-run`)

`vigolium scan … --dry-run` (and `run <phase> --dry-run`, `scan-url
--dry-run`, `scan-request --dry-run`) resolves the scan and prints its plan
without running it. On scan-url/scan-request the plan carries
`execution_path`: `runner` (the plan as described) or `direct` (one single
pass of the modules over the request, with a `direct_path` warning);
scan-request does not probe the scheme under `--dry-run`. In every case: no scan UUID, no scan row, no output file,
no wordlist materialized, no login, no OAST registration, no request; an
existing database is opened read-only for the record counts. `-j` prints a
`kind: "scan"` envelope with `dry_run: true`, `items` = the plan's phases and
`plan` = the full plan:

```bash
vigolium scan -t https://target.example --dry-run -j | jq '.plan | {phases: [.phases[] | {id, enabled, disabled_by}], targets, estimate}'
```

- Every phase is listed, enabled or not; `disabled_by` says why one is off
  (`strategy`, `only`, `skip`, `heuristics`, `intensity`, `module_selection`,
  `default`, `gate`, `flag`, `scope`). `budget.semantics` says what a phase's
  max-duration bounds (`per_target`, `per_target_capped`, `phase`, `per_leg`,
  `per_call`) and `budget.source` where it came from.
- `targets` carries scope admission. When scope refuses every seeded target the
  dry run exits `1` with `error.code: no_targets_in_scope`, as the scan would.
- `estimate` is a rough request count (`confidence: "rough"`, a `basis` per
  phase). `ceiling_by_pace` — rate limit × the time budget — is the one hard
  number; `--max-requests` clamps the rest (`clamped_to`, `hits_max_requests`).
  `estimate.duration_ms {low, high, basis, confidence: "rough"}` is the
  expected wall-clock range: requests over each phase's rate, bounded by the
  phase budgets and `--max-time`. The banner prints it as `~2m-15m (rough)`.
- `auth` lists session names and kinds, never values.
- `proxy` (present when anything is proxied): `routes[] {scheme, url, source}`
  (`source` is `--proxy`, `VIGOLIUM_PROXY` or the environment variable),
  `no_proxy`/`no_proxy_source`, and `targets{<target>: "<proxy> (from X)" |
  "direct" | "direct (NO_PROXY)"}`. Environment proxies are picked by target
  scheme and honour `NO_PROXY`; loopback is not bypassed on its own. An
  unreachable error names the proxy and its variable.

The same plan is the second event of every `--events` stream (`scan.plan`),
is stored on the scan row (`scans.plan`), and drives the pre-scan banner.

### The scan document

```json
{
  "schema_version": 2, "command": "scan-url", "kind": "scan", "ok": true,
  "scan_uuid": "9551f38a-…", "scan_uuids": ["9551f38a-…"],
  "project_uuid": "00000000-0000-0000-defa-c01001000001", "project_scoped": true,
  "db_path": "/home/you/.vigolium/database-vgnm.sqlite",
  "persisted": true, "stateless": false,
  "status": "completed", "completeness": "complete", "reasons": [],
  "targets": [
    { "target": "https://target.example/login", "method": "GET",
      "scan_uuid": "9551f38a-…", "admitted": true, "reached": true,
      "resolved_target": "https://target.example:443",
      "findings": 2, "duration_ms": 1840 }
  ],
  "targets_not_scanned": [],
  "phase_outcomes": [],
  "modules": { "selected": 325, "executed": 41 },
  "counts_by_severity": { "critical": 0, "high": 1, "medium": 1, "low": 0, "suspect": 0, "info": 0 },
  "candidates": 3, "observations": 7,
  "errors": [],
  "total": 2, "offset": 0, "limit": 200,
  "items": [
    { "id": 12, "finding_hash": "6a803b51…", "severity": "high",
      "module_id": "sqli-error-based", "url": "https://target.example/login",
      "matched_at": ["…"], "scan_uuid": "9551f38a-…" }
  ],
  "items_truncated": false,
  "plan": null,
  "query": "vigolium --db /home/you/.vigolium/database-vgnm.sqlite --project-uuid 00000000-0000-0000-defa-c01001000001 finding --scan-uuid 9551f38a-… -j",
  "query_argv": ["vigolium", "--db", "/home/you/.vigolium/database-vgnm.sqlite",
                 "--project-uuid", "00000000-0000-0000-defa-c01001000001",
                 "finding", "--scan-uuid", "9551f38a-…", "-j"],
  "duration_ms": 1840, "started_at": "2026-10-10T08:14:20.641Z",
  "finished_at": "2026-10-10T08:14:22.481Z",
  "generated_at": "2026-10-10T08:14:22.481Z", "generated_at_ms": 1791620062481
}
```

- **`items` are finding rows in the `finding -j` shape** (`compactFindingView`)
  plus the evidence (`request`, `response_evidence`), highest severity first,
  capped at `-n/--limit` (default 200; `0` = no cap). `total` and
  `counts_by_severity` are exact; `items_truncated` says the cap bit, and
  `query`/`query_argv` list every finding of the scan. `--fields`, `--compact`,
  `--full-body` and `--max-output-bytes` shape `items` as they do on `finding`.
  Candidates and observations are counts only (`finding --scan-uuid <uuid>
  --record-kind candidate`). No nuclei-shaped keys (`template-id`, `matched-at`,
  `info{}`) appear anywhere.
- **`plan`** is the scan's resolved plan as the runner stored it on the row
  (`scans.plan`, the [`--dry-run`](#plan-first---dry-run) object, `vigolium
  schema plan`), embedded verbatim. It is `null` for a direct `scan-url` /
  `scan-request` run (no plan is resolved there), a row written by an older
  binary, and a document spanning several scans.
- **Identity.** A persisted finding has its store `id`; an unpersisted one (`-S`,
  or a direct run with no store) has none — `finding_hash` is its identity.
- **`status`**: `completed`, `curtailed` (finished but partial: see `reasons`),
  `failed` or `interrupted`. A scan that fails still prints its document, with
  `status: "failed"` and `errors: [{code, message, target?}]`; `ok` stays `true`
  (it is a result document) and the exit code carries the failure. Only a
  failure before any scan existed (bad config, an unopenable `--db`) prints the
  error envelope instead.
- **`targets[]`**: `admitted`, `reached` (`null` when reachability was not
  checked), `reason` (`out_of_scope` / `unreachable`) with `code` and `detail`;
  direct-path inputs also carry `resolved_target`, `scheme_source`, `findings`
  and `duration_ms`. `targets_not_scanned` lists inputs an interrupt never
  reached (always an array).
- **Several scans, one document.** `scan-url -t a -t b -j` (one row per input
  unless `--scan-uuid` pins one) has `scan_uuids` with both, no top-level
  `scan_uuid`/`query`, and a `query` on each target entry instead. `status` is
  `failed` only when every input failed; a failed input among answered ones
  makes the run `curtailed` with `targets_out_of_scope`/`targets_unreachable`
  in `reasons`.
- **`persisted: false`** for `-S` (the temp store is gone when the process
  exits, so `db_path` and `query` are omitted) and for a direct run that had no
  store. A `-S` document embeds each finding's evidence record under `records`
  (`records_total`/`records_truncated` when it links more) and omits
  `http_record_uuids`/`origin_record_uuid`, which nothing resolves afterwards;
  they stay when `--format sqlite` wrote the store or the working database was
  kept. `modules.selected` is what the scan was handed, `modules.executed` how
  many ran at least once (scan-url used to report `modules_run`, which counted
  the loaded modules).
- **`-j` owns stdout.** `-j` with `--events`,
  `--format jsonl` without `-o`, `--print-finding`, `--print-traffic` or
  `--print-traffic-tree` is a usage error (exit 2); so is `-j` with a
  per-target fan-out (`-P` over `-T`, `-S -T --split-by-host`). `--format jsonl
  -o run.jsonl -j` writes the stream to the file and the document to stdout.
- **`--ci-output-format`** was removed: using it is exit 2 naming `-j` and
  `--format jsonl`. `--silent` prints one plain line per finding on stdout and
  nothing else (unless `-j`, `--events` or a stdout jsonl/github stream owns
  stdout).

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

`--from`/`--to` (also spelled `--since`/`--until`) take a relative offset as well
as an absolute time, so recent work is reachable without computing a date:

```bash
vigolium finding --since today          # found since local midnight
vigolium finding --since 2d             # the last 48 hours
vigolium traffic --since 90m --until 30m
vigolium finding --since yesterday --until yesterday   # just yesterday
vigolium traffic --from 2026-08-05 --to 2026-08-05     # one whole day
vigolium finding --since '2026-08-05 14:30'            # from a wall-clock time
```

Accepted: `30s`/`15m`/`2h`/`3d`/`1w` and compound Go durations (`1h30m`),
`today`, `yesterday`, `now`, `YYYY-MM-DD`, `YYYY-MM-DD HH:MM[:SS]`, and RFC3339.
Bare dates and wall-clock times are **local**, and a bare date on the upper bound
covers that whole day — `--from D --to D` is the full day D, not an empty range.
An inverted range is rejected rather than silently returning nothing.

`--search`/`--header`/`--body` now span the full request/response corpus (URL,
path, headers, and body). Each has an inverse: `--exclude-search` (repeatable,
AND-combined — a row is dropped if ANY term appears), `--exclude-header`, and
`--exclude-body`. Compose them, e.g. keep API traffic but drop noise:
`vigolium traffic --search api --exclude-search /health --exclude-body heartbeat`.

### Query findings → Output shape

Every `-j` read command emits the same envelope. The row array is **`items`**;
the old per-command names (`findings`, `records`, `scans`, …) are gone unless you
ask for them with `--json-legacy-keys` (or `VIGOLIUM_JSON_LEGACY_KEYS=1`), which
duplicates the rows on the wire and exists only for consumers still migrating.

```json
{
  "schema_version": 2,
  "command": "finding",
  "kind": "read",
  "ok": true,
  "project_uuid": "00000000-0000-0000-defa-c01001000001",
  "project_scoped": true,
  "db_path": "/home/you/.vigolium/database-vgnm.sqlite",
  "total": 39,
  "offset": 0,
  "limit": 100,
  "items": [
    { "id": 2, "severity": "high", "module_id": "…", "url": "…",
      "matched_at": ["…"], "extracted_results": ["…"],
      "response_evidence": "…<match>…" }
  ],
  "query": "vigolium --db /home/you/.vigolium/database-vgnm.sqlite finding --id 2 --json",
  "query_argv": ["vigolium", "--db", "/home/you/.vigolium/database-vgnm.sqlite",
                 "finding", "--id", "2", "--json"],
  "generated_at": "2026-10-03T08:14:22.481Z",
  "generated_at_ms": 1791015262481
}
```

- `schema_version` is the contract version — gate on it. It is bumped on any
  breaking field change; it is `2` since v0.6 (see
  [Schema version 2](#schema-version-2-v1--v2)).
- `ok` is `true` on every result document. The error object carries
  `"ok": false`, so `.ok` is a valid branch on anything `-j` prints.
- `kind` names the document's shape: `read` (a row list, or a one-object answer
  wrapped as `items: [obj]` with `total: 1`, as `db stats` and `doctor` do), `mutation`, or
  `scan`. A `mutation` document adds `changed` (always present; `false` on a dry
  run), `action` (`"compact"`, `"push_to_burp"`, …) and `dry_run: true` on a dry
  run. Commands not yet on the envelope have no `kind`.
- `items` is always an array: `[]` when empty, never `null`, never an object.
- Finding rows carry `finding_hash`, the finding's stable identity (the dedup
  key, and what SARIF fingerprints use); `--fields` accepts it.
- `project_scoped` says whether a project filter was applied at all, so "no
  filter" is explicit rather than inferred from an absent `project_uuid`.
- `project_source` says where the project selection came from: `flag`
  (`--project-uuid`/`--project-name`), `env` (`VIGOLIUM_PROJECT_UUID`/`_NAME`),
  `active_file` (`~/.vigolium/active-project`, written by `project use`) or
  `default`. That file is shared by every shell and agent on the machine, so a
  document whose project was actually resolved from it also carries
  `warnings: ["project resolved from the global active-project file …"]`. Pin
  `--project-uuid` or `VIGOLIUM_PROJECT_UUID` and both go away.
- `db_path` names the store that was actually opened, so a consumer pinning
  `VIGOLIUM_DB_PATH` or `--db` can assert the pin survived.
- `query`/`query_argv` are absent together under `--glob-db`; `db_path` is
  absent for a non-SQLite driver. See [Following a result](#following-a-result).
- Commands attach their own keys alongside these (`glob_sources`,
  `output_budget`, `targets_not_scanned`, …). A key colliding with one of the
  envelope's own is dropped rather than shadowing it.
- Finding rows carry the lifecycle verdict as `status`, with `status_note` and
  `status_actor` when one was recorded.

### Schema version 2 (v1 → v2)

v0.6 moved every `-j` output onto the envelope and bumped `schema_version` to
`2` once. `--json-legacy-keys` (or `VIGOLIUM_JSON_LEGACY_KEYS=1`) renders the
old row names (and flattens a single-object answer) for one release; there is
no v1 emulation mode.

| v1 | v2 |
|---|---|
| `scan-url`/`scan-request -j`, one target: a bare object `{target, method, scan_duration_ms, modules_loaded, modules_run, findings: [nuclei events], errors: [strings]}` | the [scan document](#the-scan-document): `targets[0]`, `modules{selected, executed}`, `items` (finding rows), `errors: [{code, message}]` |
| several targets: an envelope whose `items` were the bare objects above, plus `targets_unreachable` | one scan document; `items` are findings across every target, per-target state in `targets[]` (`reason: "unreachable"`) |
| `scan -j` / `run -j` / the `scan-url -S`/`-o` path: the `--format jsonl` stream on stdout | the scan document; pass `--format jsonl -o <file>` for the stream |
| finding keys `template-id`, `matched-at`, `extracted-results`, `info.{name,severity}`, `type` | `module_id`, `matched_at`, `extracted_results`, `module_name`, `severity`, `module_type` (the `finding -j` row) |
| `modules_run` (counted loaded modules) | `modules.executed` (ran at least once); `modules.selected` |
| `reachable`, `unreachable{}`, `stop_reason`, `targets_rejected[]` on the result | `targets[].reached`, `.reason`, `.code`, `.detail`; top-level `stop_reason` |
| a failed scan: the error envelope (`ok: false`) | the scan document, `status: "failed"`, `errors[]`; still exit 1 |
| `--events` + `-j`: `-j` meant jsonl, a usage error naming jsonl | a usage error naming `-j` (D11: no `scan.result` event) |
| read commands' raw objects/arrays, row arrays named `findings`/`records`/… | the envelope, rows in `items` (tables below) |
| `db stats` / `db compact` `items` was an object | `items: [obj]` |
| no `ok`/`kind` | `ok` on every document, `kind` (`read`, `mutation`, `scan`) |
| `command` was typed by hand: `db list -j` said `traffic`, `db ls --list-tables -j` carried flags, `traffic --group-by` too | the cobra path of the command that ran (`db list`, `traffic`); bare `scope`, `extensions` and `log` name the subcommand they are shorthand for (`scope view`, `extensions ls`, `log ls`) |
| `log <uuid> -j`: the text transcript | an envelope of log lines (below); `--follow -j` is a usage error |
| `export -j` / `db export -j`: `-j` ignored, the export stream on stdout | a receipt envelope (below); `-j` needs `-o` (exit 2 otherwise) |
| `ext example`, `ext preset`, `ext eval`, `db seed -j`: text; `ext types -j`: the d.ts on stdout | envelopes (below) |
| `import --format`, `js --format`: local flags shadowing the global `--format` | the global `--format`, same spelling and values |
| `agent -j` with no list flag: help text on stdout | a usage error (exit 2) |

### Commands that moved onto the envelope

These used to print a bare object or array of their own. They now print the
envelope above; the rule is "wrap, don't reshape": the rows move to `items`,
and every other top-level key stays where it was under the same name. A
single-object answer becomes `items: [obj]` (read `.items[0]`).
`--json-legacy-keys` (or `VIGOLIUM_JSON_LEGACY_KEYS=1`) brings back the old
row name, or flattens a single object back to the top level, for one release.

| Command | `kind` | `items` | Kept at the top level | Legacy alias |
|---|---|---|---|---|
| `module ls` (`module`, `-M`) | read | modules | `active_count`, `passive_count` | `modules` |
| `doctor` | read | `[report]` | `status` (copied up; the re-checked verdict under `--fix`), `fixes`, `updated` | `.` (`report` under `--fix`) |
| `version` | read | `[{version, commit, db_schema_version, …}]` | — | `.` |
| `skills list` | read | skills | `installed`: `[{name, agent, scope, path, version, status}]` per install location (`./.claude/skills`, `~/.claude/skills`, `./.agents/skills`, `~/.agents/skills`), `status` one of `current`, `stale`, `modified`, `missing` | `skills` |
| `skills get` | read | `[{name, description, embed_path, content, references?}]` | — | — (was raw markdown; still is without `-j`) |
| `kit secret-scan` | read | matches | `files_scanned`, `count` | `matches` |
| `kit harvest` | read | urls | `domains`, `sources`, `count`, `stats`, `limits` | `urls` |
| `kit oast new` / `poll` | read | urls / interactions | `server`, `session`, `count` | `urls` / `interactions` |
| `kit wordlist` | read | wordlists, or entries with a name | `name`, `count` | `wordlists` / `entries` |
| `kit payload` | read | payloads (class names with `--list`) | `classes`, `count` | `payloads` / `classes` |
| `kit js-beautify`, `kit jwt-crack` | read | `[result]` | — | `.` |
| `kit tmp-clean` | mutation | `[result]` | — | `.` |
| `js` | read | `[{value}]`, the return value as JSON | — | — (was the raw value; still is without `-j`) |
| `extensions eval <code>` | read | `[{value}]`, as `js` (with `--record-uuid` it prints the `extensions run` document) | — | — |
| `extensions example` | read | `[{key, lang, type, title, filename, save_as, code}]` (no `code` under `--list`) | `filter`, `lang`, `list_only` | `examples` |
| `extensions types` | read | `[{bytes, content}]`, or `[{path, bytes}]` with `-o` | — | `.` |
| `log <uuid>` | read | the `--tail`/`--full` window of lines `{text, time?, level?, phase?}` (`time`/`level`/`phase` for lines read back from the database); an agentic session's transcript lines verbatim in `text` | `uuid`, `session_kind`, `status`, `effective_status`, `stale`, `last_write_at`, `liveness_sources`, `source` (`file`, `transcript`, `database`), `path`, `tail`, `truncated` | — |
| `export`, `db export` | read | the files written `[{format, path, detail?}]` (absolute paths) | `counts` (`export`: by type plus `total`; `db export`: `records`, or per type for `fs`/`bundle`) | — |
| `project list`, `storage ls` | read | projects / objects | `prefix` (storage) | — (was a bare array) |
| `storage presign` | read | `[{url, key, method, expiry_seconds}]` | — | `.` |
| `traffic --glob-db … --burp` | read | `[aggregate]` | `pattern`, `files`, `files_read`, `unreadable`, `duration_ms` | `result` |
| `import` | mutation | `[]` | every import counter, `report_path`, `uploaded_to` | — |
| `finding load` | mutation | stored finding ids | `format`, `parsed`, `saved`, `skipped` (the old `total` is `parsed`) | — |
| `ingest` (local and `-s` remote) | mutation | `[]` | `records_ingested`/… or `records_submitted`, `errors`, `duration_ms` | — |
| `update` | mutation | steps | — | `steps` |
| `agent --list-agents` | read | providers `{name, model, auth, description, is_active}` | `active`, `active_source` (`config` or `auto-detect`), `setup_hint` | `providers` |
| `agent --list-templates` | read | templates | — | `templates` |
| `agent audit --list-modes` | read | audit's modes (its `list --json` lines) | `piolium_modes` | `modes` |
| `agent session` | read | sessions (agentic_scans rows) | — | `sessions` |
| `agent session <uuid>` | read | `[run]` | — | `.` |
| `agent query` | read | `[result]` (`raw_output`, `findings`, `saved_count`, …) | `agentic_scan_uuid`, `session_dir` | `.` |

Mutating commands that used to print only prose now print one mutation
document under `-j` (prose moves to stderr). `changed: false` with
`action: "noop"` means nothing was written; a declined confirmation is a noop
with `aborted: true`.

| Command | `items` | `changed` when | Also at the top level |
|---|---|---|---|
| `project create` | `[{uuid, name, description, config_path}]` | always | `project_uuid` |
| `project use` | `[project]` | created, or the active file now names a different project | `created`, `previous_project`, `activated_scope: "global"`, `active_file`, `env: {VIGOLIUM_PROJECT_UUID}` |
| `project delete` | `[{uuid, name, http_records, findings, scans, …, config_removed, active_project_cleared}]` | the project existed | `found` (an absent project is `changed: false`, exit 0) |
| `project config` (read) | `[{project_uuid, path, exists}]` | — | — |
| `module enable` / `disable` | every matched module `{id, type, changed}` | any module flipped | `modules_changed`, `config_path` |
| `db clean` | `[{table, rows}]` (rows matched) | rows were deleted | `mode`, `scope`, `store_wide`, `rows_matched`, `rows_deleted`; `dry_run: true` under `--dry-run` |
| `db reset` | `[{path, files_removed}]` | always | — |
| `config set` | `[{key, value, sensitive, redacted, config_path}]` | the stored value moved | — |
| `config clean` | `[{path, reinitialized}]` | `~/.vigolium` existed | — |
| `scope set` | `[{key, old, new, layer, config_path}]` | `old` ≠ `new` | — |
| `storage upload` / `results` | `[{key, size, url / path}]` | always | `scan_uuid` (results) |
| `storage rm` | `[{key, deleted, error?}]` | any key deleted | `deleted`, `failed`; a partial failure also sets `ok: false` and `error`, and exits 1 |
| `init` | `[{kind, path}]` written | not already initialized (or `--force`) | `already_initialized` on a noop |
| `skills install` | `[{name, path, installed, status, reason?, previous_version?, backup?, pruned?}]`; `status` is the state found before the run (`missing`, `current`, `stale`, `modified`) | any bundle written | `installed`, `skipped`, `dir` |
| `agent triage <id>` | `[{finding_id, verdict, reasoning, notes?, old_severity, new_severity, old_status, new_status, written, agentic_scan_uuid}]` | the verdict was written (not `--no-write`, not `inconclusive`) | `agentic_scan_uuid`, `session_dir`; `dry_run: true` and `items: [{finding_id, prompt}]` under `--dry-run` |
| `extensions preset` | `[{name, path, status, error?}]`, `status` one of `installed`, `skipped` (already present), `failed`, and for `vigolium.d.ts` `updated` or `current` | a preset was installed or `vigolium.d.ts` rewritten | `extension_dir`, `extensions_enabled`, `installed`, `skipped`, `failed` |
| `db seed` | `[{table, inserted}]` (rows this run added; existing rows are skipped) | any row was inserted | `rows_inserted` |

`storage download -j` needs `-o <file>` (exit 2 otherwise: without it the
object's bytes are stdout) and prints a read receipt `[{key, path, size}]`.
`project use <unknown-uuid>` exits 1 with `error.code: "not_found"` and creates
nothing; pass `--create` to create it.

`project list`, `storage ls` and `storage presign` had a local `--json` flag
that shadowed the global one (so `-j` failed). It is gone: `--json` and `-j`
are now the global flag on every command. Every one of these documents goes
through the shared writer, so `--pretty`, `-o` and `--max-output-bytes` apply.

`import` and `js` likewise lost their local `--format`: `import --format html
-o r.html` and `js --format text` read the global flag, with the same values.
`export -j` and `db export -j` need `-o`: without it the export is written to
stdout, where the document goes, so the run is refused (exit 2) before
anything is read; drop `-j` for the stream itself. `db export -j --watch` is
refused too (a repeated export has no single receipt).

Every command prints exactly one envelope under `-j`; help, completion, the
TUIs, the server and the passthrough shims (`ffuf`, `nuclei`, …) have no `-j`
document.
`test/e2e/machine_contract_e2e_test.go` runs every command this way, plus once
with an unknown flag (one `usage_error` document, exit 2).

## Finding lifecycle

Statuses: `draft → triaged → confirmed → fixed`, with `false_positive` and
`accepted_risk` as **dismissed** exits. Dismissed findings are left out of the
`--fail-on` gate, `scan diff` and `finding --new-since` by default
(`--include-dismissed` keeps them); reports keep them, labelled.

```bash
# Record a verdict. Name findings by id or finding_hash (>= 12-char prefix).
vigolium finding mark 42 3f9a0c2b71de --as false_positive --note "static asset" --by agent -j

# Filter on the verdict (--status is the HTTP status code).
vigolium finding --verdict confirmed,triaged -j

# What did later scans find that this one did not? (UUID, 8+ prefix, latest, previous, or a time)
vigolium finding --new-since <scan-uuid> -j
vigolium finding --new-since 24h -j

# Compare two runs; exit 4 when something new is high or above.
vigolium scan diff previous latest -j --fail-on-new high
vigolium scan diff --target https://app.example --last 2 -j
```

- `finding mark` emits a `mutation` envelope: `changed`, `action: "update"`,
  `items` = `[{id, finding_hash, from, to}]`, plus `status`, `unchanged` and
  `not_found`. Any `not_found` selector exits `1` (code `not_found`) after the
  document is written. An ambiguous hash prefix is a usage error listing the
  candidates; nothing is written. Refused under `--glob-db`, a `.jsonl` `--db`
  and `--read-only`; `-S --db <file.sqlite>` writes that file with project
  scoping off.
- `oast ingest <file|-> --format interactsh-json|collaborator-json|raw-log`
  emits a `mutation` envelope (`action: "import"`): `items` = the findings it
  saved (`nonce`, `project_uuid`, `scan_uuid`, `module_id`, `class`,
  `target_url`, `param`, `protocol`, `severity`, `confidence`,
  `finding_hash`), plus `format`, `callbacks`, `matched`, `unmatched` and
  `duplicates`. It only attributes callbacks for probes planted with a
  `{nonce}` `--oast-url`; same refusals as `finding mark`.
- `scan diff` items are finding rows plus `change` (`new`, `unchanged`, `fixed`,
  `not_reobserved`) and `first_seen_scan`. A base-only finding is `fixed` only
  when the head is `comparable` — completed, completeness `complete`, a superset
  of the base's targets, and every phase that ran in the base completed in the
  head — and `not_reobserved` otherwise; `comparability_reasons` says why.
  `history: "partial"` means a scan predates the store's per-scan observation
  history (schema v3), so an older re-detection may be missing. The envelope
  also carries `base`, `head` and `counts`.
- An unknown scan in `scan diff` or `--new-since` exits `1` with
  `scan_not_found`, never an empty result.
- `scan <uuid>` exits `2`: a UUID in the target position is a mistyped
  subcommand, and the error names the `scan` subcommands.

## Query stored HTTP traffic

```bash
# Survey endpoints (no bodies) — cheap.
vigolium traffic --json --compact --fields uuid,method,url,status_code,response_content_type

# A few records with bounded bodies (default).
vigolium traffic --host target.example --status 200 --json -n 5

# Everything for one record, full bodies.
vigolium traffic search-term --json --full-body -n 1

# Only the records one scan stored first (stamped on insert, never on a dedup hit).
vigolium traffic --scan-uuid <uuid> --json --compact

# A stored request as a curl command (URL from the stored scheme/host/port).
vigolium traffic --uuid <id> --curl
vigolium finding --id 42 --curl -j              # items: {id, finding_hash, record_uuid, curl, argv}
```

`--scan-uuid` on `traffic` (and `db ls`/`db export`/`db clean`, which used to
ignore it for records) selects `http_records.scan_uuid`. When a scan exists but
no record carries its uuid — it predates stamping — the envelope says
`provenance_warning: "scan_uuid_not_stamped"` and `provenance_detail` gives the
`--from/--to` window to use instead; an unknown uuid says `scan_not_found`.

`--curl` renders, never sends: arguments are POSIX single-quoted, a binary body
is piped through `base64 --decode` (`stdin_base64` in `-j`), and
`--redact-auth` masks Authorization/Cookie/API-key values. `traffic --curl`
renders at most 20 commands without `-a`.

### Terse rows and one field vocabulary

`--format tsv` on `traffic`, `finding`, `endpoints`, `params`, `hosts` and `dns`
prints a header line and one line per row — nothing else on stdout. Columns are
the `--fields` names. Tabs, newlines and backslashes in a value are escaped.

`--fields` accepts every key a view can carry plus shared aliases (`status`,
`code`, `length`, `size`, `words`, `time`, `content_type`, `title`, `id`,
`headers`), and the projected row uses the names passed. A view's own key wins
over an alias. `--compact` and `--fields` are on every `-j` list command.

Record references take a unique 8+ character UUID prefix anywhere a UUID is
accepted (`traffic body <prefix>`, `--uuid`, `replay -u`, `fuzz -u`, `db export
--uuid`); an ambiguous prefix fails with `error.code: ambiguous_id` naming the
candidates, scoped to the current project.

## Host facts

`vigolium hosts` reads what runs stored about hosts rather than requests — DNS
(`vigolium dns`), the TLS certificate (`fingerprint`, `run probe --tls-probe`),
the icon hash (`fingerprint`, `run probe --favicon`; `favicon_mmh3`, and
`favicon` with `url`/`mmh3`/`md5`), the fingerprint report and the not-found
baseline. `vigolium schema storage` describes the database's tables and which
`-j` field each column surfaces as.

The fingerprint report says which reads have no answer: `fingerprint.errors[]`
holds `{path, kind, error}` (plus `method`, `host` for a vhost read and
`probe`), `kind` one of `network`, `budget`, `scope`, `blocked`, `cancelled`,
`skipped`; `probe_errors` is their count. A transport failure was already
retried once. Treat a path listed there as unread, not as absent.

`vigolium match-not-found` applies the stored baseline to responses vigolium
did not record. One JSON object per stdin line —
`{"id", "url", "status", "headers": {name: value or [values]}, "body_b64"}` —
and one item per answered line, in order:

```bash
my-fetcher | vigolium match-not-found -j
# {"items":[{"id":"r1","url":"https://app.example/x","matches":true,"known":true,"reason":"signature"}, ...]}
```

`reason` is `status-404`/`status-410` (not-found by status), `signature`
(compared with the origin's baseline; `matches` is the verdict), `no-baseline`
or `no-body` (`known: false`: no answer). It is the decision `traffic --fields
matches_not_found` makes for stored records. Omit `body_b64` when you have no
body (`""` is an empty body); a decoded body over 30 MiB is cut to 30 MiB, as a
recorded response would be. A line that does not parse is counted in `failed`
and listed in `failures[]` (`line`, `id`, `error`); the rest are still answered.
`--db` and `-S` select the store as for `hosts`. Never sends a request.

## Endpoint and parameter inventory

```bash
# One row per origin + path template (/users/{int}), with methods, params by
# location, status mix, auth split, sources, jstangle outcomes, live findings.
vigolium endpoints --host target.example -j
vigolium endpoints --source jstangle -j          # routes known only from JS
vigolium endpoints --collapse 5 -n 0             # opt-in: merge slug siblings into {var}

# One row per (endpoint, location, name) with a mutation.Classify histogram.
vigolium params --type integer,uuid,sequential_id -j
vigolium params --endpoint <endpoint-id> --show-values
```

Both stream light record columns (never bodies) through `traffic`'s filters —
`--host --method --status --path --source --remark --scan-uuid --from/--to`,
`-S`, `--db`, `--glob-db` — so they cover exactly what `traffic` would list.
`-n` pages the inventory (default 100, `0` = all), not the records. Endpoint ids
are stable across databases (sha1 of origin + template). `params` redacts
sample values for cookies, headers and secret-looking names unless
`--show-values`. Field reference:
[data.md → endpoints](../public/skills/vigolium-scanner/references/data.md#endpoints).

## Read a standalone export (`-S/--stateless`)

`finding`, `traffic` and `db ls` can read a file directly instead of your
project DB — handy for inspecting a `--format jsonl` export or a foreign
`.sqlite` lying around. `-S/--stateless` requires `--db` and turns project
scoping **off by default**, so every row in the file is shown regardless of the
`project_uuid` it carries. Nothing is written to your project DB: a JSONL source
is loaded into a throwaway **file-backed** SQLite inside the process scratch
directory, which is deleted on exit. (It was an in-memory database once; a
corpus large enough to matter did not fit, and a `--glob-db` merge of several
sources never did.)

Two things follow from "off by default":

- **An explicit project selection still filters.** `--project-uuid X` (or
  `VIGOLIUM_PROJECT_UUID`) narrows a stateless read to that project; it used to
  be accepted and ignored. When the selection came from the environment rather
  than the command line, one notice line is printed to stderr so an invisible
  filter is not a mystery. `--project-name` needs a project registry to look the
  name up in, which a JSONL export and a `--glob-db` merge do not have — those
  exit `2` and tell you to use `--project-uuid`.
- **Rows keep their own `project_uuid`.** A JSONL load and a `--glob-db` merge
  report the project each row was exported under, not the default project of
  whoever is reading. (`vigolium import` still re-homes rows into the project
  they are imported into — importing means joining.)

`-S` parses on every command so a driver never has to keep a per-command
acceptance table, but on a command that does nothing with it you now get one
stderr line saying it was ignored.

**`--glob-db` accounts for every match.** The merge is still best-effort — a
source that cannot be imported is skipped and the rest are read — but a skipped
source is now *rolled back* rather than left half-merged, and the `-j` envelope
carries a `glob_sources` object on every glob read:

```json
"glob_sources": {"pattern": "scans/*.sqlite", "matched": 40, "loaded": 39,
                 "skipped": [{"file": "scans/partial.sqlite", "error": "..."}]}
```

Assert `matched == loaded` before trusting a merged read to be complete;
`skipped` is `[]` when it is. Pass `--glob-strict` (on `finding`, `traffic`,
`export`) to fail the read on the first bad source instead.

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

**JSONL imports are idempotent too.** A record whose `uuid` is already stored is
skipped rather than aborting the run, so re-importing the same export, or two
exports that overlap, is safe. The `-j` document reports
`records_skipped_duplicate` alongside `records_imported`.

**A lossy import exits 1.** Two counters mean data was in the source and is not
in the database, and either being non-zero is now a non-zero exit:

- `findings_failed` — findings the destination refused. Always present in the
  `-j` document. Distinct from `findings_skipped`, which is the benign "already
  present" case; the two used to be summed, so a lossy import and a repeated one
  printed the same line.
- `parse_errors` — lines the JSONL parser could not read (a truncated transfer,
  a mangled file). Present when non-zero.

The summary still prints in full before the non-zero exit, so you can see what
did land. A completely unreadable source is still a plain exit-1 error with no
summary.

A single JSONL line is capped at 256 MiB. Past that the import fails naming the
line number and how many records had already been committed, instead of reading
a non-JSONL file into memory until the kernel intervenes.

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
goes to **stderr** and **one run document** is printed to **stdout** at the end:

```bash
vigolium agent audit --source . --intensity balanced --json
vigolium agent autopilot -t https://target.example --json
vigolium agent swarm -t https://target.example --json
```

The run document is an envelope of `kind: "scan"` with the scan document's
spine, so an agent run reads like a scan:

```json
{ "schema_version": 2, "command": "agent autopilot", "kind": "scan", "ok": true,
  "agentic_scan_uuid": "…", "mode": "autopilot", "session_dir": "…",
  "status": "timed_out", "completeness": "partial", "stop_reason": "timed_out",
  "persisted": true, "provider": "openai-compatible", "model": "…",
  "usage": {"input_tokens": 81234, "output_tokens": 9120, "cost_usd": 0.38},
  "budget": {"max_commands": 750, "token_budget": 0, "max_cost_usd": 0,
             "max_duration_ms": 21600000, "exhausted": true, "stop": "wall_time"},
  "total": 7, "counts_by_severity": {"critical":1,"high":3,"medium":3,"low":0,"info":0,"suspect":0},
  "items": [ /* the 20 most severe, finding views */ ], "items_truncated": false,
  "errors": [], "warnings": [], "halt_reason": "…",
  "audit_harness": {"mode": "off"},
  "query": "vigolium --db … finding --agentic-scan <uuid> -j" }
```

It is always printed once the run started: with no database it says
`persisted: false` and reports the finding count the run itself kept; a session dir that
could not be created is listed in `errors[]`. A run that failed outright still
gets its document (`status: "failed"`, `errors[]`) and exits `1`. A provider
that cannot be built or does not answer fails *before* the run with the error
envelope instead: `error.code` `provider_missing` or `preflight_failed` (exit 1).

| `status` (document) | `agentic_scans.status` | `completeness` | `stop_reason` | exit |
|---|---|---|---|---|
| `completed` | `completed` | complete | — | 0 |
| `completed_with_warnings` | `completed_with_warnings` | complete | — | 0 |
| `completed_with_errors` (some audit drivers failed) | `completed_with_errors` | partial | `partial` | 5 |
| `timed_out` (`--max-duration`) | `timeout` | partial | `timed_out` | 5 |
| `budget_exhausted` (`--max-commands` / `--token-budget` / `--max-cost-usd`) | `budget_exhausted` | partial | `budget_exhausted` | 5 |
| `cancelled` (Ctrl-C / SIGTERM) | `cancelled` | partial | `interrupted` | 1 |
| `failed` | `failed` | partial | — | 1 |

Exit `5` comes after the document, like the `--fail-on` gate; `--soft-fail`
forces `0`.

Then pull the full results with the `query` line. The `--agentic-scan` filter
expands to the whole run tree (audit driver legs / swarm sub-runs), so one UUID
returns every finding the run produced.

**Budgets** (autopilot and swarm): `--max-commands` (tool calls; autopilot's
default comes from `--intensity`), `--token-budget` (input+output tokens) and
`--max-cost-usd` (estimated spend, priced per turn from the provider's usage).
`0` is no cap. Autopilot checks them after every operator turn; swarm after
every agent call.

**Preflight**: query, triage, swarm and autopilot ping the provider before
working. The deadline is `agent.olium.preflight_timeout` (default `15s`, `60s`
for a loopback Ollama / LM Studio endpoint) or `--preflight-timeout`; skip the
ping with `--no-preflight`. The provider is auto-detected unless
`agent.olium.provider` is set.

**Nested harness**: `agent autopilot --source` and `agent swarm --source` no
longer start an audit harness (a claude/codex CLI, or pi for piolium) on their
own, and swarm no longer auto-picks an installed piolium; pass
`--audit lite|balanced|deep` or `--piolium <mode>` (REST: `audit` /
`piolium`). The run document echoes the choice as
`audit_harness: {mode, piolium, harness, agent_cli}`. `agent audit` needs an
explicit `--source` (`--source .` for the working directory); without one it
exits `2`.

**The agent's own `vigolium` calls.** The operator agent shells out to
`vigolium`. Its bash tool runs `bash -c` (not a login shell) with `PATH`
starting at a directory whose `vigolium` is the running binary (also exported
as `$VIGOLIUM_BIN`), plus the parent's database and project:
`$VIGOLIUM_DB` (`--db` from the environment, project scoping kept) and
`$VIGOLIUM_PROJECT_UUID`, or `$VIGOLIUM_DB_PATH` alone when the parent itself
reads unscoped (`-S`, or a shell pinned with `VIGOLIUM_DB_PATH`); and
`$VIGOLIUM_CONFIG` when `--config` was given.

For a one-shot prompt or a code review without a full scan, `agent query`
records its own run (`mode: query`), prints `agentic_scan_uuid=… session_dir=…`
to stderr, and under `-j` prints a read envelope with the result in `items[0]`:
```bash
vigolium agent query --prompt-template security-code-review --source . --json
```

`agent triage <finding-id>` asks the agent to confirm one finding. The verdict
is `confirmed` (status → `confirmed`), `false_positive` (status →
`false_positive`; the severity is **kept**, the status alone takes it out of
gates and diffs) or `inconclusive` (nothing written). `--no-write`
(`--report-only`) reports without writing, `--no-probe` gives the agent no
HTTP/browser/shell tools, and `--dry-run` only renders the prompt. Under `-j`
it needs the finding id (the picker is a TUI) and prints the mutation document
in the table above.

## Counts, export, housekeeping

```bash
vigolium db stats --json                 # counts by severity / per-host
vigolium export --format jsonl -o out.jsonl   # bulk {type,data} stream
vigolium export --format jsonl --no-url-dedup -o all.jsonl  # every stored exchange
vigolium module --json                   # machine-readable module catalog
vigolium doctor --json                   # environment readiness
```

**Single-file `-o` outputs are published atomically.** `export -o`,
`db export -o` and `db export --format bundle` stage into a sibling temp file and
rename it into place, so a run that fails — a database read error, a full disk,
a Ctrl-C — leaves the *previous* file at that path rather than a half-written one
you cannot tell from the real thing. The one exception is `db export -o` under
`--watch`, which rewrites the same destination on every tick and so has no single
publication point.

**Export reads are strict.** A table the export cannot read fails the run
(exit `1`, with the failing table named in the message) instead of producing a
well-formed file silently missing that table. Under a scan's own `--format
jsonl` the failure is reported as `error.code: "export_failed"` like every other
unwritten artifact. The only thing still reported-but-not-fatal is the
`N endpoint(s) exported without host facts` notice on stderr: those records were
read, they just have no stored DNS/TLS observation.

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

Each export publishes a whole **generation**: the tree is built in a sibling
`.<name>.staging-*` directory and renamed over the final root only once it is
complete. So:

- A re-export **replaces** the tree. Narrowing the filters no longer leaves the
  previous run's files behind for `index.json` to disagree with.
- A re-export that now matches nothing replaces a stale tree with an empty
  index. A *first* export that matches nothing creates nothing at all.
- A base path colliding with an unrelated directory is an **error** (`refusing
  to replace <dir>: not a vigolium fs export (no index.json)`), and that
  directory is left untouched. Only an empty directory or one holding an
  `index.json` is replaceable.
- Traffic publishes before findings. Two sibling renames are not one atomic act,
  so if the findings pass fails the error says the traffic tree was already
  updated.

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

## Process contract

Exit codes:

| Code | Meaning |
|------|---------|
| `0` | success |
| `1` | the work failed; `error.code` says how (`source_missing`, `export_failed`, `no_targets_in_scope`, `no_targets_reachable`, …) |
| `2` | usage error — bad flag, bad value, rejected combination, a search that matched nothing (`module enable`), or a mutation that needed `--force` and had no terminal to ask. `error.code: "usage_error"`, except a scan whose `--ext` extension failed to load before any request: `extension_load_failed` (`--ext-allow-failures` to scan without it), and a send to a host the configured scope refuses: `out_of_scope` (`fuzz`, `dns`, `replay` single and bulk, `traffic --replay`, `kit param-mine`, `finding verify`; nothing is sent, `--ignore-scope` on each overrides it) |
| `3` | `--fail-on-match` / `--fail-on-crack` matched (`fuzz`, `kit secret-scan`, `kit jwt-crack`) |
| `4` | the `--fail-on <severity>` (or `scan diff --fail-on-new <severity>`) gate tripped |
| `5` | incomplete — the work ran but did not finish. `error.code` is `timed_out`, `budget_exhausted` or `partial`. The default for agent runs (`agent autopilot`/`swarm`/`audit`: a `--max-duration` stop, a `--max-commands`/`--token-budget`/`--max-cost-usd` stop, an audit in which some drivers failed; `agent query`/`triage` past `--max-duration`) — see [AI / agentic scans](#ai--agentic-scans); a native scan that is merely partial still exits `0` (see [Partial scans](#partial-scans)), with an opt-in `--fail-on-partial` planned for a later release |

`error.code` is a closed set shared with the REST API (`pkg/apicontract`):
values are added, never re-worded, so branch on the code rather than the message.

`3`, `4` and `5` are *completed results*, not failures: the output was written before
the code was chosen. When it was NOT written — an unwritable `-o`, a query that
failed mid-stream — the run exits `1` with `error.code: "export_failed"`, and
that outranks the gate: a `4` whose artifact is missing would send a CI job to
read a file that is not there. Each `--format` is attempted independently, so
some of them may still have landed; the "Exports" summary on stderr lists the
ones that did. This covers every artifact the run was asked for — reports
(`html`/`report`/`pdf`/`markdown`/`sarif`/`csv`/`junit`/`github`; a failed PDF
render reports the more specific `pdf_failed`), the `fs` tree, the `jsonl` export
and `--upload-results` — on the persisted path as well as under `-S`; a
`--upload-results` that could not reach storage is the run failing to deliver,
while the configured webhook stays best-effort. `--soft-fail` forces the process status to `0` for all of
them while leaving the output intact — under `--json` the error object still
reports the code that would have been used, plus `"soft_fail": true`.

Under `--json` you get **exactly one document per invocation**, whatever happens:

- Flag order does not matter. `traffic --bad --json` and `traffic --json --bad`
  both emit one `usage_error` object.
- A command that already wrote its result does not get an error object appended
  to it — the exit code carries the outcome.
- A command that was *about* to write its result and then failed does get one.
  `-o <path>` that cannot be written exits `1` with `error.code:
  "export_failed"` and a message naming the path; the result document is not
  printed in its place, and stdout is not left empty.
- `import` holds its document until every requested artifact has landed, so a
  failed `--format` report or `--upload` produces the error object alone rather
  than a success summary followed by it. On success the document carries
  `report_path` and `uploaded_to` alongside the import counts.
- `--watch` is the one exception to "one document", and only because its frame
  is NDJSON: a failure appends one more compact line, with `"ok": false`, so a
  stream that stops says why. See Gotchas.
- Nothing else is ever written to stdout. Banners, prompts, progress, and
  warnings all go to stderr.

Confirmation for a destructive command requires a terminal. Without one it
refuses immediately with exit `2` rather than blocking or reading your data
stream as the answer; pass `--force` to authorize it non-interactively. `--json`
is **not** authorization.

Reading stdin is bounded by `--input-read-timeout`, so a producer that never
closes its end cannot hang the process:

- Default `3m`. It applies to every stdin read in the CLI, including commands
  that do not expose the flag.
- **`0` disables the deadline**, as the help text has always said. (It used to
  silently re-arm the default, which is the one value a caller passes precisely
  because their producer is slower than any deadline they can guess.)
- A **negative** value is a usage error (exit `2`).
- `scan-url` and `scan-request` accept it too; they read a request from stdin
  like `scan` does, and had no way to bound it before.
- A single stdin or `-i` read is also capped at 512 MiB, deadline or not.
- **Implicit stdin waits 2s for its first byte.** When stdin is read only
  because nothing else was given (`scan` with no `-t`/`-T`/`-i`, `scan-url`
  with no URL, `scan-request` with the default `-i`, and the stdin fallback of
  `agent autopilot`/`swarm`, `replay` and `fuzz`), a pipe that produces nothing
  within 2s counts as no input: `scan`, `scan-url` and `scan-request` exit `2`,
  and the others report "no source". Once the first byte arrives the
  `--input-read-timeout` deadline applies. A typed `-i -` is an explicit request
  for stdin and waits the full deadline, so use it for a producer that is slow
  to start (`subfinder | vigolium scan -i -`). `scan-request` with a terminal
  stdin and the default `-i` fails at once instead of blocking on the keyboard.

`scan` and `run <phase>` never fall back to the database on their own. With no
`-t`/`-T`/`-i`/stdin they exit `2`, and the message names the database and
project a rescan would touch. Pass `--all-records` to rescan every HTTP record
in the active project; it cannot be combined with `-t`, `-T`, `-i` or `-S`
(exit `2`). On an interactive terminal the bare form still rescans for one
release, with a deprecation warning; under `-j`, `--events`, `--ci-output`, or
when stdout or stderr is not a terminal it is already an error.

### Scope admission

Every scan checks its targets against the configured scope before it sends
anything, with the same matcher the scan then enforces:

- **Every target refused → exit `1`, `error.code: "no_targets_in_scope"`, and
  no request is sent.** The message names each target with the rule that
  refused it (`scope.host.include`, `scope.host.exclude`, `scope.path.include`,
  `scope.path.exclude`, `scope.cli_origin_mode`, `static_file`) and the config
  key to fix. The scan row still exists — `failed`, `completeness: partial`,
  `stop_reason: no_targets_in_scope` — so `log <uuid>` explains it.
- **Some refused → the rest are scanned**, the scan is `partial` with reason
  `targets_out_of_scope`, and the exit code stays `0`.
- The verdict is on the row as the `preflight` phase outcome:
  `targets: {requested, admitted, reached, rejected: [{target, code}]}`.
  `scan.started` and `scan.finished` carry `targets_admitted` and
  `targets_rejected` (zeros are written).
- It applies when the targets are the input (`-t`, positional URLs, `-T`, a
  piped URL list, `scan-url`, `scan-request`). For `-i` specs, `--all-records`
  and scan-on-receive, scope meets the records one by one; a phase whose every
  item it dropped, with nothing answered, is `partial` with
  `targets_out_of_scope`.
- `scan-url`/`scan-request --ignore-scope` scans a target the scope refuses.
  REST `POST /api/scan-url` and `/api/scan-request` answer `422` with
  `details: "no_targets_in_scope"` instead of accepting a scan that would do
  nothing.

### Reachability

After admission, a scan checks that its admitted targets answer, so a dead or
mis-schemed target is an error instead of a clean-looking empty scan:

- **Runner scans** (`scan`, `run`, `scan-url -S`/`-o`) send one GET to each
  admitted target URL before the first phase (bounded concurrency, on the
  egress gate's priority lane). Any HTTP status counts as an answer. The
  heuristics check reuses the root page this fetched, so with heuristics on
  the check costs no extra request for a root target.
- **None answered → exit `1`, `error.code: "no_targets_reachable"`**, and no
  phase runs. The message names each target and why
  (`connection refused`, `DNS lookup failed`, …). The row is `failed`,
  `completeness: partial`, `stop_reason: no_targets_reachable`.
- **Some answered → every target stays in the plan** (a transient blip is not
  a silent drop), and the scan is `partial` with reason `targets_unreachable`;
  the exit code stays `0`.
- The preflight outcome's `targets` adds `reached`, `reachability_checked` and
  `unreachable: [{target, code, detail}]`; `scan.finished` carries
  `targets_reached` and `targets_unreachable` when the check ran.
- `--skip preflight` turns the GET off. It is skipped for `run probe` (the
  sweep has its own reachability accounting), plans that never reach the
  target (`run external-harvest`), scan-on-receive, and input that is not a
  target list (`-i`, `--all-records`).
- **The `scan-url`/`scan-request` direct path** sends nothing extra: the
  baseline request is the check, and the result document carries `reachable`
  (see [Run a scan and gate on results](#run-a-scan-and-gate-on-results)).

### Partial scans

A scan that ran to its end having covered less than it was given is a **partial**
scan, and partial is **not** an error:

- **The exit code does not change.** A partial scan still exits `0`. Nothing
  failed; coverage was simply less than complete, and a CI job that treats that
  as a failure would fail on every correctly time-boxed run. There is no
  `--fail-on-partial` gate today; exit `5` is reserved for it, and a later
  release adds the flag as an opt-in.
- **`scan.finished` reports `"status": "curtailed"`** instead of `"completed"`,
  with `stop_reason` (one code) and `reasons` (the union of every phase's
  reasons). `failed` and `interrupted` are never relabelled — a scan that failed
  is a worse outcome than one that was curtailed, and overwriting the status
  would lose the more serious fact.
- **`phase.finished` reports `"status": "curtailed"`** for a phase that was cut
  short, with `reasons` and `limits`. A phase whose own `max_duration` fired
  inside an otherwise healthy scan is included — that used to report
  `"completed"` with nothing to read.
- **`reasons` are defects; `limits` are configured bounds.** A `target_budget`
  limit means a per-target time box did its job, so it never downgrades a status.
  Act on `reasons`.
- **The scan row is authoritative.** `completeness` is `complete`, `partial`, or
  **empty**; empty means unknown (an older binary, or a caller with no outcome
  data) and must never be read as `complete`. `stop_reason` and `phase_outcomes`
  carry the detail. `vigolium db ls scans` shows `completed (partial)`; the REST
  scan object and `-j` output carry all three fields. See
  [the scan API reference](api-references/scan.md#scan-completeness) for the
  field and code vocabulary.

- **`auth_unavailable` changes how you read the findings.** It means configured
  authentication never reached the scan, so everything behind the login was
  probed anonymously. Treat the run as unauthenticated coverage, not as evidence
  that the application exposes nothing — and do not report the resulting 401s as
  findings. The specific cause rides alongside it (`login_budget`, `cancelled`,
  `scan_budget`). It is recorded whichever subsystem failed to log in — the HTTP
  session manager or the browser.
- **`persistence_incomplete` on a browser phase** (`spidering`, `respider`)
  means the crawl captured traffic that did not reach the database. The phase's
  `persistence` block carries the counts (`accepted` / `committed` / `failed` /
  `unknown`), and `timed_out` means the capture writer was abandoned before it
  drained, so some entries have no recorded outcome either way. A crawl that
  lost records is a partial phase even when every page was visited.

Reason and limit codes are added, never renamed, so matching on a code is safe;
a code you do not recognise is a code added after your version.

**An interrupted scan's row says `status: failed`.** The event stream says
`"status": "interrupted"` for the same run, and the two disagree on purpose:
`status` on the scan row is a released value, and the finalizer has always
written `failed` for a run that did not reach its end. (The vocabulary has a
`cancelled` value; the finalizer does not use it.) Do not read the row's
`status` as "something broke" for an interrupted run — read the coverage fields,
which the row and the stream agree on completely: `completeness: partial`,
`stop_reason: cancelled`, and `input_incomplete` among the reasons. If you need
to distinguish an interrupt from a crash, that triple is the signal.

Record delivery is **at-least-once**. A curtailed phase leaves its durable cursor
*behind* the records it did not finish, so a successor run — `scan-on-receive`,
or `--scan-uuid` against a prior scan — re-serves them rather than skipping them.
The phase outcome's `unprocessed` count says how many that was, and
`checkpoint_failed` means the cursor could not be written at all, in which case
the whole round is re-served. Duplicate work is the deliberate trade: findings
dedup downstream, so the cost is time, where a skipped record is a silent gap.

Still check `completeness` before treating a predecessor as a baseline: a partial
predecessor covered less than its target list, whatever its cursor says about the
records it did reach.

### The event stream (`--events ndjson`)

One NDJSON line per event on **stdout**, from `scan.started` to a single
terminal `scan.finished`. Human output stays on stderr throughout.

- **`--events` owns stdout exclusively.** Combining it with another writer of
  stdout — `-j/--json`, `--format jsonl` without `-o`,
  `--print-finding`, `--print-traffic`, `--print-traffic-tree` — is rejected
  before any work starts, with exit `2` naming the conflict. It used to produce
  a corrupt interleaved stream and exit `0`. Exactly one protocol on stdout,
  always. (First-run setup — the Chrome-for-Testing download a cold machine's
  first spidering phase triggers, and the nuclei-template clone of its first
  known-issue scan — writes its progress to stderr and announces itself on the
  stream as `scan.setup`, so a brand-new machine's very first `--events` run is
  still clean NDJSON.)
- **`seq`** is the stream's own total order: 1-based, stamped under the write
  lock, one per line. Use it rather than `ts` — timestamps are
  millisecond-precision and a busy scan emits several events per millisecond, so
  sorting by `ts` reorders them. A gap in `seq` means a line was lost.
- **`scan.interrupting` is nonterminal.** It is written when SIGINT/SIGTERM
  arrives, carrying the signal name in `message`, and the graceful shutdown then
  runs. The terminal `scan.finished` still follows, with
  `"status": "interrupted"` and the totals. A second signal forces exit `1`
  after a best-effort terminal event that carries no totals.
- **The terminal event is last, and arrives after finalization.** Its totals and
  `reasons` are read from the persisted scan row, and under `--db-isolate` it is
  written after the merge into the real database — so a run whose results never
  landed reports `"status": "failed"` rather than `"completed"`. A consumer that
  stops at the first terminal event is unaffected.
- **A closed consumer does not kill the scan.** `vigolium scan --events ndjson |
  head -5` runs to completion and exits on its own merit; the truncated stream
  is reported on stderr as `event stream delivery failed: …; the scan ran to
  completion`. The exit code is unaffected.
- **SIGTERM shuts a native scan down gracefully**, with or without `--events`,
  including during setup before the first request is sent.

New event types and fields are added, never renamed; an event type you do not
recognise is safe to ignore. `scan.plan` is always the second line, right
after `scan.started` and before any request; its `plan` is the object
[`--dry-run`](#plan-first---dry-run) prints, with `scan_uuid` set. Some types
and fields (`host.*`, `auth.*`,
`targets_reached`, …) are already reserved in the vocabulary before anything
emits them; the skill's `references/agent-loop.md` lists each with the release
expected to start emitting it.

### Watching a scan from another process (`scan status`, `scan wait`)

When the scan was launched elsewhere (in the background, by another tool, on a
`--scan-uuid` you chose), poll it instead of holding its stream:

```bash
vigolium scan status <uuid> -j          # one item: where it is now
vigolium scan wait <uuid> --timeout 45m -j --fail-on high
```

Every native scan keeps a **heartbeat**, whether or not `--events` or
`persist_logs` is set: every 10s and on each phase change it rewrites
`<sessions_dir>/<uuid>/status.json` atomically (phase, requests sent, findings,
`progress {done,total,unit}`, PID, host) and stamps the scan row's
`heartbeat_at`, `current_phase`, `pid`, `runner_host` and `total_requests`.
The file is what answers for a `-S` or `--db-isolate` scan, whose row is not in
the store you are reading until the run ends. `scan-url`/`scan-request` rows
get the same heartbeat while their input runs.

`scan status` item fields: `status` (stored), `effective_status`
(`running|abandoned|completed|failed|cancelled`), `liveness {last_write_at,
stale, sources, process_gone}`, `phase`, `phases_done`, `requests_sent`,
`findings`, `findings_by_severity`, `progress` (null when the phase has no
count), `eta {estimate_ms, upper_bound_ms, basis}`, `plan` (the stored plan,
verbatim; null when the row has none), `completeness`, `stop_reason`,
`started_at`, `duration_ms`, `db_path`. **The ETA is never invented:**

- `upper_bound_ms` is the tighter of the remaining `--scanning-max-duration`
  budget and the stored plan's ceilings for what is left (the current phase's
  ceiling less the time it has run, plus every later enabled phase's ceiling;
  a per-target budget counts as budget × admitted targets).
- `estimate_ms` is the current phase's own rate, `elapsed × (total−done)/done`
  (needs a known total), plus the later phases at 0.6 of their ceilings,
  clamped to the upper bound.
- Either is `null` when something it rests on is unknown (no plan, a later
  phase with no ceiling, no count for the current phase). `basis` joins what
  the figures rest on — `phase_rate`, `plan_ceilings`, `scan_budget` — or says
  `unknown`; a finished scan reports `0`/`0` with `basis: "finished"`.

**Abandoned** means the row says `running` but nothing has written for 2
minutes (heartbeat, `status.json`, `runtime.log`, the newest `scan_logs` line),
or the scan ran on this host and its PID is gone — then immediately. The same
verdict feeds `log ls -j` (`last_write_at`, `stale`, `effective_status`,
`liveness_sources` per row; `status` stays the stored value) and `log <uuid>`'s
auto-follow.

`scan wait` polls through the read-only database pool (it never contends for
the scan's write lock), prints progress lines on stderr, and on a terminal
state prints, under `-j`, the finished scan's [scan document](#the-scan-document)
— the envelope `scan -j` prints (`kind: "scan"`, findings as `items`,
`status`, `completeness`, `phase_outcomes`, `plan`), rebuilt from the scan's
row, with the row's own `started_at`/`finished_at`/`duration_ms`. `-n/--limit`,
`--fields` and `--compact` shape it as on `scan`. A `-S`/`--db-isolate` scan
whose row is not in the store being read gets the same document from its
`status.json` (counts, no `items`, `persisted: false`). Without `-j` it prints
the human status block. Then it exits:

| Exit | When |
|---|---|
| `0` | completed |
| `1` | failed or cancelled (`failed`), abandoned (`scan_abandoned`), `--timeout` elapsed (`wait_timeout`, default 30m; `0` waits forever) |
| `4` | `--fail-on <severity>` matched a finding of that scan |
| `5` | `--fail-on-partial` and the scan completed `partial` (`partial`) |

**Cleaning up dead scans.** `vigolium log ls --reap` finalizes every
`running` row of the project whose liveness says abandoned: `status: failed`,
`completeness: partial`, `stop_reason: "abandoned"`, `finished_at` = its last
write. It also prunes `status.json` files whose last write is older than
`scanning_strategy.scan_logs.status_retention_days` (default 30; `0` keeps
them; `vigolium server` runs the same prune at start). `-j` adds `reaped`
(UUIDs) and `status_files_removed`. `--reap` writes, so `--read-only` and
`-S`/`--glob-db` refuse it (exit 2).

An unknown UUID is tolerated for 30s (the row may not exist yet), then fails
`not_found`. `--events ndjson` streams `phase.progress` lines on stdout instead
and ends with `scan.finished`, or with an `error` line whose `error_kind` is
`wait_timeout` / `scan_abandoned`; it cannot be combined with `-j`.

## Discovering the interface

```bash
vigolium strategy --json    # strategies, phase names + aliases, intensities,
                            # agent modes, installed profiles
vigolium config ls --json   # every setting (credentials redacted)
vigolium scope view --json  # scope rules
vigolium module ls --json   # module catalog
vigolium doctor --json      # environment readiness
```

`strategy --json` is generated from the same registries the flags are validated
against, so `phases[].canonical` and `phases[].aliases` are exactly what `--only`,
`--skip`, and `run <phase>` accept.

### Machine-readable schemas (`vigolium schema`)

The shapes above are published as JSON Schema (draft 2020-12), reflected from the
Go types the commands emit, so a driver can validate what it parses instead of
trusting prose:

```bash
vigolium schema                          # what has a schema: commands, event types, error, documents
vigolium schema command finding          # one command's -j document (envelope + typed items)
vigolium schema command scan status      # multi-word command paths need no quoting
vigolium schema event phase.progress     # one --events line type
vigolium schema event                    # any --events line: oneOf keyed on `type`
vigolium schema error                    # the -j error envelope; error.code is the closed enum
vigolium schema all > vigolium.schema.json
```

- Without `-j` the output is the bare schema, ready for a validator. With `-j` it is
  the usual envelope whose `items` are `{name, kind, envelope_kind, description, schema}`.
- Command schemas pin `schema_version` (2), `command`, `ok: true` and `kind`; a
  mutation's schema requires `changed` and `action`. Objects are closed
  (`additionalProperties: false`), so a key the schema does not name is a contract
  change, not a silent addition. Keys marked optional are omitted when empty;
  `--fields` may drop any item key, and `--json-legacy-keys` documents are outside
  the contract.
- Registered commands: `finding`, `traffic` (both with the `--curl` row variant),
  `endpoints`, `params`, `log ls`, `scan status`, `scan wait`, `scan diff`, the scan
  document (`scan`, `run`, `scan-url`, `scan-request`), and the mutations `finding
  mark`, `oast ingest`, `project create|use|delete`, `module enable|disable`.
  `vigolium schema` lists the current set; a test keeps every other command on an
  explicit pending list with the reason it has no schema yet.
- Each `--events` type is closed over the keys that type can carry (`v`, `ts`,
  `seq`, `scan_uuid`, `type` on every line).
- `schema plan` prints the scan plan document (`scan --dry-run`, the `scan.plan`
  event) once a build registers it; otherwise it fails `not_found`.
- The same files are committed under [`docs/schema/`](schema/) and regenerated with
  `make schema`; a test fails when they drift from the code.

## Credentials

`auth list` and `config ls` redact secrets by default — session tokens, auth
headers, stored login requests, and login bodies. This applies under `--json`
too, because `--json` output is the output most likely to end up in a transcript.
Pass `--show-secrets` to reveal them; it prints a warning to stderr.

Redacted rows keep `has_session_token`, `header_names`, and a
`session_token_fingerprint` (a short stable digest) so you can still tell two
sessions apart or confirm a rotation landed.

## Following a result

Every `-j` read carries a `query` field: a ready-to-run follow-up pinned to the
same store and scope, correctly shell-quoted — and `query_argv`, the same
command as an argv vector.

```bash
q=$(vigolium --db ./run.sqlite -S finding --limit 1 --json | jq -r .query)
eval "$q"    # reaches the same finding in the same database

# or, without a shell in the middle:
readarray -t argv < <(vigolium --db ./run.sqlite -S finding --limit 1 --json \
                        | jq -r '.query_argv[]')
"${argv[@]}"
```

Prefer `query_argv` from code: `query` is shell-quoted for a human to read, and
re-splitting a quoted string is where that quoting becomes the thing that breaks
the parse. The vector goes straight into `exec`. The two are always present (or
absent) together.

Finding IDs are per-database autoincrement integers, so the `--db`/`--stateless`/
`--project-uuid` flags are load-bearing. Three properties make them reproduce the
read rather than merely resemble it:

- `--db` and `--config` are **absolute**, so the follow-up works from any
  directory.
- The project is pinned as a resolved `--project-uuid`, never as a
  `--project-name` the next process would look up again or as an implicit active
  project that `project use` could change in between.
- Under `-S/--stateless` the `--db` names the **source** you gave (a `.jsonl`
  export, a standalone `.sqlite`), not the scratch database it was loaded into.

Both fields are **absent** under `--glob-db`: the merged source is a temporary
database that no argument list can reopen. `--db` alone is absent for a
non-SQLite driver, whose connection details live in the config rather than in a
path.

## Gotchas

- `-S` means `--stateless` on `scan` but `--scan-on-receive` on `ingest`.
- `--json` (compact, single object) ≠ `--format jsonl` (bulk, one line per row).
  On the scan commands `-j` is the scan document and no longer implies
  `--format jsonl`.
- `replay` and `fuzz` print a **human** view by default. `-j` gives one envelope
  (`replay`: the result in `items[0]`, or one row per record in bulk mode;
  `fuzz`: the ranked top results in `items`, the run summary beside them).
  `--format jsonl` is their per-item stream and `-o <file>` writes that stream to
  a file; `-j --format jsonl` without `-o` is a usage error. Bulk `replay` still
  defaults to JSONL for one release (with a stderr notice), so pass `--format
  jsonl` or `-j` explicitly. Their old local `--pretty` ("human instead of
  JSON") is a deprecated no-op; `--pretty` is now the global "indent -j".
- `traffic -j` cannot be combined with `--tree`, `--markdown`, `--raw` or
  `--burp` (exit `2`): those are human views. The rows are `traffic -j`; a
  per-host aggregate is `traffic -j --group-by host`.
- `finding`/`traffic` print their "Filtered by:" echo on **stderr**, and drop it
  entirely for `--markdown`/`--raw`/`--burp` when stdout is not a terminal.
- `--json --watch <n>` switches to NDJSON: one compact document per line, no
  clear-screen, no heading. If the read breaks, the last line is a compact error
  object (`"ok": false`) rather than silence. `--watch` is rejected on a command
  that writes.
- `db clean --findings-only`, `--orphans`, `--table`, and `--all` are *modes*,
  not modifiers. The first two are confined to the active project; the last two
  address the whole store and reject a narrowing filter rather than ignoring it.
- With `-P/--parallel`, `--fail-on` is evaluated per child process, and the
  batch exits `4` if any child tripped it. A gated child is a *success* in the
  roll-up — it scanned and wrote its output — and is listed separately from
  failures; `--resume` will not re-scan it.
- `scan-url`/`scan-request` with `--events` route through the full Runner, so
  the stream is real. Several targets under `-j` emit **one** scan document:
  per-target state in `targets[]`, `targets_not_scanned` naming anything an
  interrupt cut off, `persisted` saying whether the findings also reached a
  database, and `status: "interrupted"` when a signal cut the run short.
- `traffic body`/`traffic headers --uuid` are project-scoped like every other
  read: a record in a project the invocation did not select reports
  `record_not_found`, the same code as a UUID that does not exist. That is
  deliberate — a distinct "wrong project" error would confirm the record exists.
  The receipt carries `project_uuid` and `project_scoped`.
- `vigolium export` defaults to the **whole database**, not your active project.
  Pass `--project-uuid`/`--project-name` to narrow it; the stderr summary and a
  bundle's `manifest.json` both state which scope the contents have.
- A failed `-S` scan deletes its throwaway database, losing whatever it had
  learned before it broke. `--keep-db-on-error` moves it to
  `~/.vigolium/recovered/` instead and names the path in the error, so you can
  read the partial results with `vigolium finding -S --db <that path>`. Nothing
  sweeps that directory — it is yours to delete. The flag requires `-S` (exit
  `2` otherwise) and is inherited by `-P` children.
- A `--db-isolate` run whose merge fails now moves its working database to
  `~/.vigolium/recovered/` and prints the `vigolium import` command that
  completes the merge. The path it used to name was inside process scratch,
  which is deleted at exit.
- **`vigolium version`, `help` and `completion` no longer create `~/.vigolium`.**
  Nothing that only answers a question — including the hidden `__complete` RPC
  a shell runs on every tab press — writes a config or a database any more.
  Everything else still bootstraps on first run, and a first run that pins
  `--db` (or `$VIGOLIUM_DB_PATH`) now skips the *default* store, which it used
  to create, seed and never open. A `--read-only` read with no `--db` still
  creates the default file, because that file is the store it is about to read.
- **A raw request's body bytes are preserved.** `scan-request` used to
  `TrimSpace` its whole input, which rewrote the body of any request ending in
  whitespace while `Content-Length` still declared the original length. Trailing
  whitespace is now stripped only when the headers declare no body (no
  `Content-Length`, no `Transfer-Encoding`); leading whitespace always is.
- **A raw request's body is exactly what its `Content-Length` declares.** Write
  `Content-Length: 3` with the body `a=1` and three bytes go out, even though
  your editor put a newline after it — the trailing byte used to go out too,
  making the body one longer than the request said. `Content-Length` is the
  authority on where the body ends; a body that is *short* of the declaration
  has the header corrected down instead, because nobody can send bytes that are
  not there. A body that genuinely ends in whitespace is unaffected: its
  `Content-Length` counts that whitespace, so write `Content-Length: 7` for
  `a=1 \r\n\n` and all seven bytes are sent. Requests carrying
  `Transfer-Encoding`, or two `Content-Length` headers, are left exactly as
  written — that disagreement is the point of a desync probe.
- **`ingest`'s count is rows, not attempts.** `records_ingested` equals a
  `count(*)` on `http_records` for the run. Records that were read and could not
  be stored are `records_failed` and exit `1` with
  `error.code: "ingest_incomplete"`; records a filter dropped are
  `records_skipped` and are not a failure. A batch (`-i a.har -i b.har`,
  `--dir`) emits **one** envelope covering every source, not one per source.
  Ingesting a capture never re-fetches a record that already carries its
  response, so the origins in a HAR do not have to still resolve.
- **`-I`/`--input-mode` canonical names**: `urls`, `nuclei`, `openapi`, `wsdl`,
  `postman`, `curl`, `burpraw`, `burpxml`, `burpscope`, `har`, `deparos`.
  Aliases are accepted (`nuclei-output`, `swagger`, `burp`, …) but the canonical
  name is what `--list-input-mode` and the `-I` help text now show — the listing
  used to advertise `nuclei-output` as canonical, which is the reverse of what
  the parser resolves.
- Agentic scans need a configured LLM provider (`agent.olium` in
  `vigolium-configs.yaml`); run `vigolium doctor --json` to check.
- **A broken `--config` is now an error (exit 1), not a fallback to defaults.**
  If you pass `--config` and the file is missing or unparseable, the command
  fails naming the file. It used to run against the *default* database with the
  *default* settings and exit 0. A config found by discovery still degrades to
  defaults with one stderr warning. `vigolium doctor` reports it as a failed
  `config` check instead of failing, and `db clean --reset` refuses on any config
  error at all. See [Configuration](configuration.md#when-a-config-file-cannot-be-read).
- A SQLite path containing `#`, `%`, a space or non-ASCII characters now reaches
  the file it names; a `#` used to truncate it at the driver's URI parser and
  open a different, empty database. A path containing a literal `?` is rejected
  with an error — the driver cannot address one in any spelling.
