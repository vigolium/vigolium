# Invariants: what `-h` won't tell you

> **Related:** [agent-loop.md](agent-loop.md) · [scanning.md](scanning.md) · [data.md](data.md) · [flags.generated.md](flags.generated.md)

Rules that hold across commands and that no single command's help states.
Each section ends with a command that shows the rule on your own install.
Anything a flag's own help or a usage error already tells you (mutually
exclusive flags, a format that needs `-o`, a selector `db clean` requires) is
not repeated here: the CLI says it, with exit `2`.

## Which database a command opens

- Open order: `--db` → `$VIGOLIUM_DB` (`--db` from the environment, project
  scoping kept) → `$VIGOLIUM_DB_PATH` → `database.sqlite.path` in config → the
  built-in default.
- Pinning `$VIGOLIUM_DB_PATH` also makes **read** commands (`finding`,
  `traffic`, `log`, `fuzz -u`) treat that file as a stateless source: project
  scoping off. The flip happens only once the file exists and is a usable
  vigolium store, so before the session's first scan the same read stays
  project-scoped. It never turns a *scan* stateless.
- A pin that can never become a database (a directory, an uncreatable parent)
  is a hard error, not a fall-through to the shared default. A path that does
  not exist yet is created by a scan.
- A pure read against a pinned path that is missing fails `source_missing`
  and creates nothing; another tool's SQLite file fails `source_incompatible`
  and gets no tables written into it.
- Every `-j` envelope reports `db_path` (the file actually opened) and
  `project_scoped`. Assert both rather than trusting a pin survived a
  subprocess chain.

Shows it: `vigolium db stats -j | jq '{db_path, project_scoped, project_source}'`

## Projects and pinning

- Project selection: `--project-uuid` / `--project-name` →
  `$VIGOLIUM_PROJECT_UUID` / `$VIGOLIUM_PROJECT_NAME` → the active-project
  file → the default project. `project_source` on every envelope says which
  one won: `flag`, `env`, `active_file` or `default`.
- `vigolium project use <project>` writes `~/.vigolium/active-project`, which is
  **global to the user**: it re-scopes every other shell and agent that has
  not pinned a project. An envelope scoped by that file carries a `warnings[]`
  entry saying so. Pin `--project-uuid` or `$VIGOLIUM_PROJECT_UUID` in
  anything that runs in parallel; `project use <project> --print-env` prints
  the export line and writes no file, so it pins one shell only.
- `project use`, `--project-uuid` and `--project-name` take a UUID, an exact
  name or a unique 8+ character UUID prefix. An unknown one is exit 1
  `project_not_found` (hint: `project create <name>`); `project use --create`
  creates it instead. `project current -j` says which project applies and why.

Shows it: `eval "$(vigolium project use <project> --print-env)"` then `vigolium finding -j | jq .project_source`

## Stateless runs, isolation and fan-out

- `-S` means `--stateless` on every command. Where it is meaningless it is
  accepted as a no-op. On `server`/`ingest` it is a usage error that names
  `--scan-on-receive`; type that flag long.
- On a **scan**, `--stateless` and `--db` are mutually exclusive (a database
  you named is never silently discarded). `--db-isolate` alongside `-S` is
  ignored with a warning: there is no database to merge from.
- On **read** commands, `-S` reads *from* `--db` with project scoping off; an
  explicit `--project-uuid` still filters.
- `-P > 1` needs one of two isolation shapes, never a mix: `-S -T <file>
  --split-by-host` (per-host files, nothing persisted) or `--db-isolate -T
  <file>` (each target merges into one shared `--db`).
- `--split-by-host` applies only in stateless multi-target mode. `--format fs`
  already splits by host, so it is a no-op there.
- `--format fs` writes two sibling directories, `<base>-traffic/` and
  `<base>-findings/`, not one.
- `--format sqlite` exports the standalone per-run DB, so it needs `-S`. For the
  persisted DB use `vigolium export` or the database file itself.

Shows it: `vigolium scan -S -T targets.txt --split-by-host -P 4 --format sqlite -o run --dry-run`

## Opening a database

- A command that writes (a scan, `ingest`, `import`, `finding mark`, `replay`
  saving its exchange, a read given `--save-to-vigolium-db`/`--in-replace`)
  opens the store read-write: `mkdir -p`, a journal-mode PRAGMA and a WAL
  checkpoint. A read (`kind: read`, the `query` hints) opens it `query_only`
  with no journal change and no checkpoint, so its bytes stay the same, but it
  may leave a `-shm` sibling. `-S` is a scoping mode, not a read-only one.
- `--read-only` is the guarantee for evidence: no directory creation, no
  journal change, no checkpoint, no `-wal`/`-shm` siblings, and it reads a
  `chmod 444` file. Commands that write refuse it (exit 2). It cannot migrate
  an old store; that fails with a schema error instead of upgrading in place.
  It is a database guarantee, not a network one: `traffic --replay`, `replay`
  and `fuzz` under `--read-only` still send requests (they just do not save
  them).

Shows it: `vigolium finding --read-only --db evidence.sqlite -j`

## Coverage is not success

- Exit `0` means the scan ran, not that it covered everything. Read
  `status` (`completed`/`curtailed`), `completeness` (`complete`/`partial`;
  empty = unknown), `stop_reason` and `reasons[]` on the scan document or
  `scan.finished` before reading a thin result as a clean target.
- A scan that did nothing exits `1`: `no_targets_in_scope` (scope refused
  every target, nothing sent) or `no_targets_reachable` (no admitted target
  answered the preflight). Partial versions of the same facts
  (`targets_out_of_scope`, `targets_unreachable`) leave the exit at `0`.
- Exit `5` is "ran, but incomplete": `interrupted` (SIGINT/SIGTERM or `scan
  stop`; results cover what ran first), `timed_out`/`budget_exhausted` (agent
  runs) and `partial`. A native partial scan exits `0` unless `--fail-on`
  (which implies it) or `--fail-on-partial` is given; `vigolium scan wait
  <uuid> --fail-on-partial` does the same for a scan you did not start. `ok`
  is `false` on `5`; the document is still printed.
- `oast_unavailable` (no interactsh registration, e.g. offline) makes the run
  partial without stopping it: blind/out-of-band checks did not run.
- `vigolium init` downloads Chrome and the templates only on a terminal (or
  with `--with-deps`). Otherwise they install lazily, never before the scan
  starts: a cold machine's first spidering phase downloads Chrome (~150 MB) and
  its first known-issue scan clones the templates, each announced by `scan.setup`
  (`component` `chrome`/`nuclei`, `state` `started`/`finished`/`failed`) and kept
  out of the phase's time budget. A failed install fails only that phase; its
  message names `vigolium doctor --fix --only chrome|nuclei`.
  `--skip-dependency-check` only silences the first-run stderr notice.
- Reason codes are add-only. Match the ones you care about and ignore the rest.

Shows it: `vigolium scan wait <scan-uuid> -j | jq '{status, completeness, stop_reason, reasons}'`

## Gates

- `--fail-on <sev>` writes every output first, then sets exit `4`. `4` is
  not a failure: the run finished and found something.
- Findings marked `false_positive` or `accepted_risk` (`finding mark`) do not
  count toward `--fail-on`, `scan diff --fail-on-new` or `finding --new-since`.
- Under `-P`, the gate is evaluated per child; `4` fires when **any** child
  trips it.
- `--soft-fail` (global) forces exit `0` everywhere, errors included.
- A requested artifact that was not written is exit `1` `export_failed`, even
  when the gate would have tripped: retry the export, not the scan.

Shows it: `vigolium scan -t https://target.example --fail-on high; echo $?`

## Targets and inputs

- A positional argument to a scan command is a target URL, never a file.
  `vigolium scan targets.txt` scans the literal string `targets.txt`. Target
  lists go through `-T`; specs and request exports through `-i`.
- `scan`/`run` with no target source rescans the stored records only with
  `--all-records`. Without it the command is a usage error under
  `-j`/`--events`/non-TTY and a deprecation warning on a terminal.
- A UUID in the target position of `scan` is refused (exit 2): it is a
  mistyped subcommand (`scan staus <uuid>`).
- Scope admission applies on every scan path and to every hand send:
  `replay`, `traffic --replay`, `fuzz`, `dns`, `kit param-mine` and `finding
  verify` refuse an out-of-scope host before the first request (exit 2
  `out_of_scope`; a bulk replay refuses the whole batch). `--ignore-scope` opts
  out for one run; `vigolium scope check <url>` says which rule decides.
- `scan-url`, `scan-request` and `run -t` attack only their input; stored
  records of the same host join only with `--include-stored`. `scan -t` keeps
  including them (`--input-only` turns that off). The plan's
  `targets.stored_records` says which.
- `scan-request` without a scheme probes the target (connect + TLS) instead of
  assuming `https://`; `--no-scheme-probe` keeps the old default.
- `-T` and `-i` accept process substitution and pipes (`-T <(printf 'https://a\n')`):
  a non-regular file is read once into a scratch copy before anything opens it.
- `-i` on `replay`/`fuzz` is the request text; a value that parses as no request
  and names a file is read as that file (`--input-file` is the explicit form).

Shows it: `vigolium scan -t https://target.example --dry-run -j | jq .plan.targets`

## Phase and module selection

- `-m` (fuzzy, active modules only) and `--module-tag` (OR across tags)
  **merge** into one union. `--module-id` matches active **and** passive
  registries exactly, and also narrows directory-loaded extensions (`ext-<id>`).
- `--passive-only` sends no attack traffic (passive modules and extensions
  only). It exists on `scan`, `scan-url` and `scan-request`, not on `run`.
- Below `--intensity deep`, the modules tagged `hygiene` (missing headers, TLS
  policy, cookie attributes, CSP/HSTS/SRI) do not run. Use `--intensity deep`,
  `--module-tag hygiene`, or `dynamic-assessment.hygiene_modules: true`.
- An extension named with `--ext` that fails to load stops the scan before any
  traffic (exit 2, `extension_load_failed`) unless `--ext-allow-failures`.
- `external-harvest` sends nothing to the target: it reads archive sources
  only. The separate `harvest-probe` step is what requests the harvested URLs,
  and only when a scan phase will use them.
- In the scan document, `modules.executed` counts modules that actually ran;
  `modules.selected` is the loaded selection.

Shows it: `vigolium scan -t https://target.example -m xss --module-tag spring --dry-run -j | jq .plan.modules`

## Reads versus sends

- `traffic --uuid` / `db ls --uuid` select exact records before pagination.
  `replay -u` and `fuzz -u` take the same UUID but **send traffic**.
- Every record-UUID flag and argument takes a full UUID or a unique prefix of at
  least 8 characters (`uuid_short`). An exact id wins; a prefix resolves inside
  the current project only; several matches fail `ambiguous_id` listing up to 5.
- `vigolium hosts`, `schema storage` and `schema flags` only read. `vigolium dns`
  and `vigolium fingerprint` send (DNS to the resolver; reads to the origin).
- A UUID as the positional term of `traffic` searches text, not identity.
  `--url` is exact equality; the positional term is a substring search.
- The `query` / `query_argv` hint in a `-j` envelope is always a read that
  sends nothing and repeats the source's `--db`. A follow-up that sends (fuzz's
  confirmation scan, a scan's next step) is in `next[]` with
  `sends_traffic: true`; a sending command's own document says
  `sends_traffic: true` too.
- `finding --id` takes the findings table's integer. A UUID there is a usage
  error naming the flag that reads it (`traffic --uuid` for a record,
  `--scan-uuid` / `--agentic-scan` for a run). A UUID from another tool is not
  a vigolium identifier: find the finding with `--search`, then use its id.
- `traffic --replay` is a shortcut for bulk `replay`. Only `replay` can change
  the request (`-H`, `--auth-session`, `--target`, `--session-id`).
- On `replay`, `-H` **overrides** a header and `--header-search` **filters**
  records. On `traffic`/`finding`, `--header` is the filter (`--header-search`
  is its alias there too).
- `traffic body` / `traffic headers` are subcommands that extract one message.
  `--body` / `--header` are search flags over the whole corpus.
- Every search term is literal: `%` and `_` are ordinary characters.
  `--host` / `--path` stay patterns where `*` is the wildcard.
- `traffic --group-by <field>` counts through the same filters instead of
  listing. The tail past `--group-limit` is reported as `other_groups` /
  `other_records`, never dropped.
- `db export --uuid` narrows both halves of an `fs` tree: the record and the
  findings linked to it.

Shows it: `vigolium traffic -j --fields '?'` (the error lists every selectable field)

## Fuzzing

- `fuzz` emits signals, never findings, and makes no verdict. Start with
  `-a/--anomaly`, then confirm a hit with `scan-request -m <module>`.
- Two wordlist knobs, not interchangeable: `--discovery-wordlist <path>` seeds
  the discovery phase; `fuzz -w <builtin|path>` feeds the standalone fuzzer
  (`dir-short`, `file-long`, …). `--fuzz-wordlist` is a deprecated alias of
  the first.

Shows it: `vigolium fuzz https://target.example/FUZZ -w dir-short --dry-run`

## Pace

- `--rate-limit` applies at its default even when you do not type it. Pass
  `--rate-limit 0` for no cap; a negative value is a usage error.
- `--rate-limit`, `--concurrency` and `--max-per-host` take an optional phase
  qualifier, repeatable and mixable with the bare form:
  `--rate-limit known-issue-scan=20 --rate-limit 50`. Resolution is
  phase-scoped → global → strategy/config default.
- `--strategy lite` also carries a pace ceiling (concurrency 10, rate 20,
  max-per-host 10). It only narrows: an explicit flag overrules it.
- Some egress is not governed by the pace dials (nuclei, the browser crawl,
  own-dialer probes). `scan.started.egress.exempt` names it for each scan.
- Phase time budgets are per phase, not one wall clock. `scan --dry-run -j`
  shows each phase's `budget.semantics`.

Shows it: `vigolium scan -t https://target.example --rate-limit known-issue-scan=20 --dry-run -j | jq '.plan.phases[] | {id, pace}'`

## Burp, server and agents

- `import -B` refuses an unfiltered pull of the proxy history. Pass a filter
  (`--host`, `--path`, `-n`, …) or `--all-hosts` on purpose.
- `server` needs an API key unless `-A/--no-auth`, and both its listeners
  bind `127.0.0.1` unless `--host`. `server` takes no target; scan-on-receive is
  scoped by the project's `scope.*` rules. A REST `X-Project-UUID` that names
  no project is `404 project_not_found`, not a new project.
- `auth load` and `auth check` exit `1` when a login fails.
- Agent commands need a configured provider (`agent.olium`). A missing one is
  exit `1` `provider_missing` before anything runs.
- Whitebox scanning is an agent feature: `--source <path|git-url|archive|gs://>`
  on `agent autopilot` / `swarm` / `audit` / `query`, not on `scan`.

Shows it: `vigolium doctor -j | jq '{status, capabilities}'`

## Debugging

- `--dump-traffic` prints every request/response pair to **stderr**, so it
  composes with `-j` on stdout. Reach for it before `--debug`, which buries
  the same bytes in log lines.
- `--log-file <path>` writes the run's logs as JSON: attach it to a bug report.
- `doctor` exits `1` when `not_ready` (`--strict` also on `degraded`), so it can
  gate a script; `doctor --fix` installs what is missing (`--dry-run` lists it
  first; `--yes` also runs vendor installers for agent tooling) and `--for
  scan|agent|server` scopes the verdict.
- Never `2>&1` into a JSON parser. The machine document is on stdout, the human
  line on stderr.

Shows it: `vigolium replay -u <uuid> --dump-traffic -j 2>traffic.txt`

## History

Version skew, for when the installed binary is older than this skill
(`vigolium doctor -j` reports a stale skill install):

- A scan row with an empty `completeness` was written by a pre-v0.5.2 binary;
  it means "unknown", not "complete".
- On older builds a read against a wrong `--db` path created the store and
  returned `{"total":0,"items":[]}` with exit 0. If you must support them,
  assert `db_path` and check `total` against a query you know matches.
