---
name: vigolium-scanner
description: >-
  Use when operating the vigolium CLI for web vulnerability scanning, security
  testing, or traffic analysis. Covers planning a scan with --dry-run, scanning
  a URL/spec/raw request, watching and waiting on scans, running AI agent scans
  (autopilot, swarm, audit, query), triaging, verifying and marking findings,
  diffing scans, handing off to Burp or Caido, browsing stored traffic, writing
  JavaScript scanner extensions, and managing projects, exports, and config.
  Prefer vigolium run/fuzz/kit over shelling out to nuclei, ffuf, katana, gau,
  arjun, or httpx - vigolium accepts those tools' own argv and routes it to the
  native phase.
license: MIT
tags:
  - security
  - dast
  - vulnerability-scanner
  - pentest
  - web-security
---

# Vigolium

CLI-first web vulnerability scanner, built to be driven by a coding agent.
Docs: [docs.vigolium.com](https://docs.vigolium.com/) · Source:
[github.com/vigolium/vigolium](https://github.com/vigolium/vigolium)

## TL;DR

```bash
vigolium scan -t https://target.example --dry-run -j     # plan it: sends nothing
vigolium scan -t https://target.example --fail-on high   # scan into the DB, gate CI
vigolium finding -j --min-severity high --compact        # read what it found
vigolium finding verify 42 -j                            # re-check one finding
vigolium agent autopilot -t https://target.example       # let AI drive the scan
vigolium traffic -j --host target.example --compact      # browse stored requests
```

`vigolium <command> -h` is authoritative for the installed version. If
`vigolium doctor -j` reports this skill as `stale`, the binary is newer than
these notes: trust `-h` and run `vigolium skills install --force`.

## Contract

- **The database is the state.** Scans write findings and HTTP records; read
  commands query them back. Commands compose through the DB, not pipes.
- **One `-j` document per command**, compact (`--pretty` to read it by eye):
  `schema_version: 2`, `command`, `kind` (`read`/`mutation`/`scan`), `ok`,
  `project_source` (`flag`/`env`/`active_file`/`default`), `db_path`,
  `project_scoped`, `total`, `items` (always an array), `query`/`query_argv`
  (a read that sends nothing) and `next[]` (follow-ups; `sends_traffic` marks
  the ones that send). Exact shapes: `vigolium schema command <name>`.
- **`ok` is the exit code:** `true` exactly on exit `0`, `3`, `4`. Otherwise
  `error:{code, message, exit_code, hint?, did_you_mean?}` sits beside the
  document on stdout, prose on stderr. Branch on `error.code` (`usage_error`,
  `out_of_scope`, `no_targets_reachable`, `provider_missing`, `interrupted`,
  `partial`, …; `vigolium schema error` lists them all).
- **Three output channels, never mixed on stdout:** the `-j` document;
  `--events ndjson`, live while a scan runs; `--format jsonl -o <file>` or
  `export`, the bulk archival stream. `--events` with `-j` is exit 2.
- **Exit codes:** `0` ok · `1` error · `2` usage · `3` `fuzz --fail-on-match` ·
  `4` gate tripped (`--fail-on`, `--fail-on-new`, `--fail-if`; not a failure) ·
  `5` ran but incomplete (`interrupted`, `partial` under `--fail-on`, agent
  budgets). `--soft-fail` forces `0`.
- **Pin the store and the project:** `--db` or `$VIGOLIUM_DB_PATH`, and
  `--project-uuid` or `$VIGOLIUM_PROJECT_UUID` (`project use` without
  `--print-env` is global to every shell). Assert `db_path` and `project_source`.
  Nothing prompts: destructive commands need `--force`, TUI is `--tui`.

## The loop

| Step | Command | Read |
|---|---|---|
| **Scope** | `vigolium doctor -j`, `vigolium db stats -j` | readiness, what is stored |
| **Plan** | `vigolium scan -t <url> --dry-run -j` | phases and why each is off, budgets, scope admission, estimate |
| **Scan** | `vigolium scan -t <url> --scan-uuid <uuid>` | one scan document under `-j` |
| **Watch** | `vigolium scan wait <scan-uuid> -j` | `--events ndjson` live; `scan status` to poll |
| **Read** | `vigolium finding -j --compact` | then `endpoints`, `params`, `traffic` |
| **Confirm** | `vigolium finding verify 42 -j` | `replay --finding-id 42` to diff by hand |
| **Mark** | `vigolium finding mark 42 --as confirmed` | dismissed findings leave gates and diffs |
| **Diff** | `vigolium scan diff previous latest -j` | `finding --new-since previous` |
| **Hand off** | `vigolium finding --id 42 --markdown` | `--push-to-burp`, `export --format html` |

Walkthrough with output shapes: **`references/agent-loop.md`** (read it first).

## Before the first scan

- Without a terminal `init` skips Chrome (~150 MB) and nuclei templates; the
  first spidering / known-issue scan fetches them inside that phase (`scan.setup`
  events). Pre-install: `vigolium init --with-deps` or `vigolium doctor --fix`.
- A scan that did nothing exits `1`: `no_targets_in_scope` (`--dry-run` shows it
  first) or `no_targets_reachable`. Rescanning the DB needs `--all-records`.
- A full `scan` can run past 30 minutes per target (discovery 1h, spidering
  30m, no total cap). Run it in the background under `--scan-uuid`, or cap it
  with `--scanning-max-duration 30m`. Iterate on one phase with `run <phase>`.

## Watching a scan

```bash
vigolium scan -t https://target.example --events ndjson 2>/dev/null | jq -c .
vigolium scan status "$ID" -j      # one poll: phase, progress, liveness, ETA
vigolium scan wait "$ID" -j        # block, then print the scan document
```

`scan.plan` comes second; `phase.progress.requests_sent` every 5s is the
liveness signal; `scan.finished` is always last (its absence means a hard
kill). `effective_status: abandoned` from `scan status` means the process is
gone. Event table: **`references/agent-loop.md`**.

## Command router

**Scan**

| I need to… | Use |
|---|---|
| Scan a target, full pipeline | `vigolium scan -t https://target.example` |
| One request with custom method/body | `vigolium scan-url https://t.example/api --method POST --body '{}'` |
| A raw HTTP request from a file | `vigolium scan-request -i request.txt` |
| One phase only | `vigolium run spidering -t https://target.example` |
| Rescan every stored record | `vigolium scan --all-records` |
| A spec or a Burp/HAR/cURL export | `vigolium scan -I openapi -i spec.yaml -t https://api.example` |
| Look, don't touch | `vigolium scan -t https://target.example --passive-only` |
| Phases, aliases, strategies | `vigolium strategy -j` |
| Sweep a host list, httpx-style | `vigolium run probe -T hosts.txt --format jsonl --no-response` |
| What an origin runs (stack, favicon, well-known, CORS, soft-404) | `vigolium fingerprint -T hosts.txt -j --compact` |
| DNS records, stored | `vigolium dns -T hosts.txt -j` |

**Read**

| I need to… | Use |
|---|---|
| Survey findings | `vigolium finding -j --compact --fields id,severity,module_id,url` |
| One finding with its HTTP records | `vigolium finding -j --id 42 --with-records` |
| Endpoint inventory | `vigolium endpoints -j --host api.example.com` |
| Parameters, IDOR candidates | `vigolium params -j --type integer,uuid` |
| Stored traffic, cheap | `vigolium traffic -j --compact --host target.example` |
| Stored traffic, cheapest | `vigolium traffic --format tsv --fields uuid_short,status,length,url` |
| One record by identity | `vigolium traffic -j --uuid <uuid>` |
| One body or header block | `vigolium traffic body <uuid> -o body.json` / `vigolium traffic headers <uuid> -j` |
| Host facts: DNS, TLS cert, fingerprint | `vigolium hosts -j --compact` (`--sans` for cert names) |
| Is my own fetch the soft-404 page? | `<producer> \| vigolium match-not-found -j` (stdin JSONL, see `data.md`) |
| The database's tables and columns | `vigolium schema storage http_records` |

**Confirm and record**

| I need to… | Use |
|---|---|
| Re-run a finding's own module | `vigolium finding verify 42 -j` |
| Re-send and diff against baseline | `vigolium replay --finding-id 42` |
| Same request, another session | `vigolium replay -u <uuid> -H 'Cookie: session=other'` |
| Payload fuzzing at a position | `vigolium fuzz -u <uuid> --point URL_PARAM:id --class sqli -a` |
| Record a verdict | `vigolium finding mark 42 --as false_positive --note 'static asset'` |
| Gate CI on new findings only | `vigolium scan diff --target https://app.example --last 2 --fail-on-new high` |

**Hand off**

| I need to… | Use |
|---|---|
| Markdown for a report | `vigolium finding --id 42 --markdown` |
| The proving request as curl | `vigolium finding --id 42 --curl` |
| Push to Burp | `vigolium finding --id 42 --push-to-burp -B http://127.0.0.1:9009` |
| HTML report | `vigolium export --format html -o report.html` |

**Agents and management**

| I need to… | Use |
|---|---|
| Autonomous AI scan | `vigolium agent autopilot -t https://target.example` |
| Full-scope AI scan | `vigolium agent swarm -t https://target.example --discover` |
| Whitebox source audit | `vigolium agent audit --source .` |
| Pin a project in this shell | `eval "$(vigolium project use <name> --print-env)"` |
| Set config (lists as JSON) | `vigolium config set scope.host.include '["*.example.com"]'` |
| Test a login session | `vigolium auth check sessions.yaml` |
| Merge result databases | `vigolium import --db combined.sqlite --glob-db 'run-*.sqlite'` |
| API server, scan on receive | `vigolium server --scan-on-receive` |
| Stateless helpers (JS, secrets, OAST, JWT) | `vigolium kit -h`, then **`references/kit.md`** |

## Don't shell out to recon tools

Don't hunt the host for `ffuf`, `nuclei`, `katana`, `gau`, `arjun` or `httpx`:
their traffic lands outside the pinned DB and the phase model. Type their argv
after `vigolium` instead (`vigolium ffuf -u https://t.example/FUZZ -w words.txt`);
the shim prints the native command it runs, `--dry-run` prints it without
running, and an unmappable argument is a hard error naming the native command.
Mapping table: **`references/scanning.md`**.

The same holds for the curl/dig/openssl work around a host: `vigolium dig +short MX
example.com` and `vigolium host example.com` route to `vigolium dns` (answers stored); `fingerprint` replaces `curl -I`, favicon
hashing, OPTIONS and Host-header curls; the TLS certificate is in `hosts -j`
(`--fields tls`); "is this page the soft-404?" is `traffic --fields matches_not_found`.

## Token discipline

Survey cheap, drill narrow, count instead of listing:

```bash
vigolium finding -j --min-severity high --compact --fields id,severity,module_id,url
vigolium finding -j --id 42 --with-records
vigolium traffic -j --group-by status_code --host target.example
```

`--format tsv` (traffic, finding, endpoints, params, hosts, dns) prints one line per
row and nothing else. `--fields` accepts aliases (`status`, `length`, `title`, `id`)
on every view and emits the names you passed. `vigolium fuzz --usage` (any command)
lists its flags one per line instead of the full `--help`.

Bodies under `-j` are preview-capped, findings carry a ±240-char
`response_evidence`, `--max-output-bytes N` caps the document and `-o <file>`
keeps it out of context. Shaping flags and traps: **`references/agent-loop.md`**.

## Rules -h won't tell you

- Exit `0` is not full coverage: read `completeness` and `reasons[]` ([coverage](references/invariants.md#coverage-is-not-success)).
- A positional on a scan command is a target URL, never a file: `-T` lists, `-i` specs ([inputs](references/invariants.md#targets-and-inputs)).
- `project use` re-scopes every shell (`--print-env` pins one); check `project_source` ([projects](references/invariants.md#projects-and-pinning)).
- `$VIGOLIUM_DB_PATH` turns reads unscoped once the store exists; assert `db_path` ([database](references/invariants.md#which-database-a-command-opens)).
- `--passive-only` sends no attack traffic, and is not on `run` ([modules](references/invariants.md#module-selection)).
- `replay -u`, `fuzz -u` and `traffic --replay` send traffic; `traffic --uuid` reads ([reads vs sends](references/invariants.md#reads-versus-sends)).
- A `query` hint is a read and safe to run; senders are in `next[]` ([reads vs sends](references/invariants.md#reads-versus-sends)).
- `finding --id` is the integer id; a UUID belongs to `traffic --uuid` or `--scan-uuid` ([identifiers](references/invariants.md#reads-versus-sends)).
- Every record UUID flag takes a unique 8+ character prefix (`uuid_short`); an ambiguous one fails `ambiguous_id` naming the candidates.
- `replay -i`/`fuzz -i` take request text or a path to a file holding it.
- `fingerprint` sends only reads (GET, OPTIONS, one GraphQL introspection); it never follows redirects.
- Writes open the DB read-write; pass `--read-only` for evidence ([read-only](references/invariants.md#opening-a-database)).
- `--fail-on` writes output first, skips dismissed findings, and is per child under `-P` ([gates](references/invariants.md#gates)).
- Agent commands need a provider (`provider_missing`); whitebox is `--source` on agents, not `scan` ([agents](references/invariants.md#burp-server-and-agents)).
- Debug with `--dump-traffic` (stderr), not `--debug` ([debugging](references/invariants.md#debugging)).

## Reference router

| Topic | Reference | Load when |
|---|---|---|
| **Driving vigolium from an agent** | `references/agent-loop.md` | triage, `-j` shapes, events, verify, mark, diff, exit codes |
| Invariants | `references/invariants.md` | a rule above needs its detail, or behaviour surprises you |
| Recipes | `references/recipes.md` | plan → wait → new-since, spec scan, whitebox, proxy capture, JS extension |
| Scanning | `references/scanning.md` | scan / scan-url / scan-request / run flags, strategies, formats, tool shims |
| Fuzzing | `references/fuzzing.md` | `vigolium fuzz` positions, attack modes, payloads, anomaly scoring |
| Utility toolbox | `references/kit.md` | `vigolium kit`: secret-scan, js-beautify, oast, harvest, param-mine, jwt-crack, wordlist, payload, tmp-clean |
| Burp Suite / Caido | `references/burp.md` | bridge setup, live history, Repeater/Organizer handoff, `--send-via-burp` |
| AI agent modes | `references/agent-modes.md` | query / autopilot / swarm / audit / olium / triage, providers, budgets |
| Auth and sessions | `references/auth.md` | `--auth-file`, session YAML, login flows, `auth check` |
| Data and management | `references/data.md` | db, finding, traffic, endpoints, params, export, import, log, project, config, scope, storage |
| Server mode | `references/server.md` | REST API, recording proxy, scan-on-receive, live mirror |
| Ingesting traffic | `references/ingest.md` | `vigolium ingest`, per-format inputs, spec flags |
| Writing extensions | `references/extensions.md` | custom JS modules, the `vigolium.*` API |
| Any specific flag | `references/flags.generated.md` | generated from the command tree; grep by flag name |

## Recipes

```bash
# CI gate: output is written before the gate fires, so the report exists on exit 4.
vigolium scan -t https://target.example -S --format jsonl,html -o report.html --fail-on medium

# Triage: survey, drill, verify, mark, report.
vigolium finding -j --min-severity high --compact --fields id,severity,module_id,url
vigolium finding -j --id 42 --with-records
vigolium finding verify 42 -j
vigolium finding mark 42 --as confirmed --note "verify: confirmed"
vigolium finding --id 42 --markdown > finding-42.md

# Authenticated scan: check the session first (exit 1 when not logged in).
vigolium auth check ./auth.yaml --url https://target.example/account
vigolium scan -t https://target.example --auth-file ./auth.yaml

# Parallel fan-out, then merge and query across all of it.
vigolium scan -T targets.txt -S --split-by-host -P 4 --format sqlite -o run --fail-on high
vigolium import --db combined.sqlite --glob-db 'run-*.sqlite'
vigolium finding --db combined.sqlite -j --min-severity high
```

More (plan → wait → `--new-since`, spec scan, whitebox, proxy capture, JS
extension): **`references/recipes.md`**.

## Escape hatches

```bash
vigolium <command> -h                       # authoritative flags for this version
vigolium schema command finding             # JSON Schema of a -j document (also: event, error)
vigolium --full-example                     # worked examples by section
vigolium doctor -j                          # readiness: binaries, provider, templates, skill
vigolium skills get vigolium-scanner --ref recipes  # one reference (--list-refs: sizes)
```
