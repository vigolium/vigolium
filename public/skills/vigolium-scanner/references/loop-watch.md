# The agent loop: Watch a scan

> **Related:** [agent-loop.md](agent-loop.md) (start here) · [invariants.md](invariants.md) (the `-j` envelope, exit codes) · [flags.generated.md](flags.generated.md)

The events a running scan writes, the coverage fields, and following a scan you did not start.

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
| `scan.plan` | Always second, right after `scan.started` and before any request: `plan` is the resolved plan (see [Step 1.75](loop-scan.md#step-175--plan-before-you-scan)), with `scan_uuid` set and the loaded extensions' selection. The same object is stored on the scan row. |
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
| `scan.finished` | Terminal. `status`, `findings_by_severity`, `records_written`, and `stop_reason`/`reasons` when coverage was lost. `targets_admitted`/`targets_rejected` and, once the preflight ran, `targets_reached`/`targets_unreachable`. `--max-requests` running out ends the scan `curtailed` with `stop_reason: request_budget`; hosts that used their `--max-requests-per-host` are listed in `budget_exhausted_hosts` (their phases carry the `host_request_budget` limit). `extensions_failed` lists the paths of extensions that failed to load; `module_errors` is the error count per module id (exceptions, timeouts and panics; also on the scan row). `exit_code` is the status the invocation exits with (gates included, `--soft-fail` not applied) and `error_code` its stable code when not 0, so the stream alone tells a gate trip from a failure. `scope_dropped` counts records refused per scope rule class (intent, not lost coverage). `oast_sessions_kept[{id, server}]` are the interactsh sessions left open for late callbacks: collect them with `vigolium oast poll --scan <uuid> --close -j`, then re-read findings. `skipped_controls {count, sample[{label, selector, url, reason, match}]}` is what the browser crawl refused to click (`reason`: `deny_click`, `deny_click_extra`, `logout`; at most 20 named): a skipped "Delete" is an operation you may authorise deliberately on a throwaway object, never a gap to close by loosening the guard. `caveats[{code, phase, hosts, modules, count, message, done?, total?, unit?}]` is the coverage statement; a phase cut short (`phase_deadline`, `scan_budget`, `request_budget`, `cancelled`, `input_incomplete`) adds how far it got (`done` of `total` `unit`). |
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

### Harness timeouts

A coding-agent harness usually kills a foreground command after a few minutes;
a full `scan` outlasts that, and a killed scan leaves only what it flushed.
Compare `plan.estimate.duration_ms.high` (from `--dry-run -j`) with your
command timeout. When it is longer, start the scan in the background under a
UUID you chose and block on `scan wait` in calls that each fit the limit:

```bash
ID=$(uuidgen | tr A-Z a-z)
nohup vigolium scan -t https://target.example --scan-uuid "$ID" >/dev/null 2>&1 &
vigolium scan wait "$ID" --timeout 100s -j    # exit 1 wait_timeout: still running, call again
```

`wait_timeout` (exit 1, the scan untouched) means "not yet"; loop on it, or
read progress in between with `vigolium scan status "$ID" -j`. Do not kill the
background process to get control back: stop it (below).

### Stopping a scan

```bash
vigolium scan ls -j --fields uuid,status,effective_status,target   # what is running
vigolium scan stop <scan-uuid-or-8-char-prefix> --wait -j          # ask it to stop, wait for it
vigolium agent cancel <agentic-scan-uuid> --wait -j                # the same for an agent run
```

- `scan stop` writes a stop request the scan's heartbeat picks up within about
  10 s, wherever it runs (this shell, another one, the server, a `-S` scan via
  its session directory). The scan flushes what it found, stores
  `status: cancelled` with `stop_reason: user_stopped`, and its own process
  exits `5` with `error.code: "interrupted"`; its document is still printed.
- `--wait` (default `--timeout 60s`) returns when the scan has stopped; not
  acknowledged in time is exit 1 `wait_timeout`, whose hint names `kill -INT
  <pid>` when the scan runs on this host. A scan that already finished is exit
  0, `changed: false`, `action: already_finished`.
- `kill -INT <pid>` (or Ctrl-C) is the same graceful stop for a process you
  own; a second signal, or SIGKILL, loses the unflushed tail and the terminal
  event.
