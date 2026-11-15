# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

The CLI as a coding agent drives it: outcomes that match the exit code, verbs to stop and inspect runs, sends that stay in scope and say where they go, and a skill that describes all of it.

### Security

- Config writers (`config set`/`unset`, `module enable`/`disable`, `scope set`/`add`/`rm`, project overlays, the server's config and scope handlers) edit the raw YAML in place: `${VAR}` placeholders and comments survive, and no expanded secret (`VIGOLIUM_DB_PASSWORD`, storage keys, OAST token) is written to disk any more. Booleans and integers are parsed strictly (exit 2 otherwise) and the value read back is echoed.
- Under `-j` with a coding-agent variable set (`CLAUDECODE`, `CLAUDE_CODE_ENTRYPOINT`, `CODEX_SANDBOX`, `CURSOR_AGENT`, `GEMINI_CLI`, `VIGOLIUM_AGENT`; CI variables do not count), raw request/response views mask credential header values, cookie values and sensitive query parameters, and every envelope says `redacted`. `--redact` / `--no-redact` override. Bodies, the database and exports stay raw.
- `server --no-auth` on a non-loopback `--host` (including `$VIGOLIUM_SERVER_HOST=0.0.0.0`) is refused unless `--allow-unauthenticated-bind`.
- `auth load` prints sensitive header values and tokens as `<redacted>` and refuses a session file with lint errors (`lint_failed`; `--force` overrides).

### Added

- Verbs: `vigolium status`, `scan ls`, `scan stop <uuid|prefix> [--wait]` (a stop request the heartbeat picks up, also for `-S` scans and server-run scans), `agent cancel`, `finding show`, `config get`, `config unset`, `config env`, `config ls --effective`, `scope add`/`rm`/`check`, `project current`/`rename`, `auth show`/`rm`, `module show`, `server status`/`stop`, `skills uninstall`, `skills get --ref <file>` / `--list-refs`.
- `--dry-run` on `db reset`, `project delete`, `module enable`/`disable`, `finding load`, `finding mark`, `import`, `ingest`, `skills install`/`uninstall`, `scope set`, `auth load`, `config set`, `replay`, `scan-url`, `scan-request` and `agent audit`; `agent autopilot`/`swarm --dry-run` call no provider and send nothing.
- `replay --once` (one send, response inline), `--save`/`--no-save` (a single replay stores its exchange as source `replay`), `--baseline`, `--all-matches`, `--keep-host`, `--excerpt-bytes`; `fuzz --save[=all]` (source `fuzz`), `-n`, `--all-results`, `sent_total`; `scan --record-uuid`; `--include-stored` / `--input-only`; `--no-auth`; `--ignore-scope` on every sender; `init --with-deps`.
- `server -j` / `--events ndjson` print one `server.ready` line once both listeners are bound; a pidfile under `~/.vigolium/server/`; `/health` reports `pid`.
- Envelope fields: `error {code, message, exit_code, hint?, did_you_mean?, usage_argv?}` beside any document that ends non-zero, `next[] {argv, why, sends_traffic}`, `sends_traffic`, `redacted`. Plan fields: `proxy`, `estimate.duration_ms`, `execution_path`, `targets.stored_records`, `scope.rules`; scan documents count `scope_dropped` per rule class.
- Error codes `out_of_scope`, `interrupted`, `provider_unreachable`, `storage_disabled`, `finding_not_found` / `scan_not_found` / `project_not_found` on the CLI paths that used generic ones.
- `doctor -j` lists flat `checks` with `status` and `capabilities {scan, spidering, known_issue_scan, out_of_band, agent, audit}`; `--for scan|agent|server`, `--only` without `--fix`, `--fix --dry-run`, a proxy row naming its source.
- Generic shaping (`--fields`, `--compact`, `--max-output-bytes`, `-n/--offset`) on every read that has rows; `module ls` rows carry `tier` and `risk_high`.
- Shared spellings as aliases: `--header-search`/`--body-search` on reads, `-u/--record-uuid` for a stored record, `--data` on `scan-url`, `--method` on `fuzz`, `--max-time` on the agent runs, `js-beautify` and `scan wait`, `-o/--output` on `server ca print` and `skills gen-flags`.
- The skill: `agent-loop.md` is split into one `loop-*.md` file per step, `invariants.md` holds the `-j` envelope, an `error.code` → next-command table and the exit codes, and the references cover untrusted target content, a one-off `-S` scan, harness timeouts, stopping a scan, local dev servers and proxied sandboxes. The e2e suite runs every documented read-only example against a seeded store and evaluates its `jq` paths.

### Changed

- `ok` is true exactly when the exit code is 0, 3 or 4. A command that produced its document and then failed prints it once with `ok: false` and `error`; there is no second document.
- A `query` / `query_argv` hint is always a read that sends nothing and repeats the source's `--db`; a follow-up that sends (fuzz's confirmation scan) moves to `next[]`.
- A gracefully interrupted scan (SIGINT/SIGTERM, `scan stop`) exits 5 with `error.code: "interrupted"` and is stored `cancelled`. `--fail-on` implies `--fail-on-partial`.
- `scan-url`, `scan-request` and `run -t` attack only their input; `--include-stored` adds the stored records of the host. `scan -t` keeps including them and states the count (`--input-only` turns it off).
- Environment proxies are picked by target scheme (`HTTPS_PROXY` for https, `HTTP_PROXY` for http, `ALL_PROXY` for both) and honour `NO_PROXY`; loopback is not bypassed on its own. The plan, the banner, `status`, `doctor` and the unreachable error name the proxy and the variable it came from. `--proxy` still proxies everything.
- Every sender (`replay`, `traffic --replay`, `fuzz`, `dns`, `kit param-mine`, `finding verify`) checks scope before the first request: exit 2 `out_of_scope`.
- `fuzz` needs an explicit position (a marker, or `--fuzz`/`--point`/`--fuzz-header`, not both), defaults to `--rate-limit 100` and `--max-requests 10000` (a bigger plan is exit 2), and skips headers the request does not carry unless `--fuzz headers:synthetic`.
- `replay -i` sends a supplied request once (`--baseline` for the diff); URL-shaped positionals are refused (exit 2 naming `-i`); a bulk replay matching several records needs `--all-matches`.
- Unknown subcommands, flags, enum values and near-miss verbs (`scan stauts`, `scan ps`) are exit 2 with `did_you_mean`; group commands reject unknown words; argument-count errors are usage errors.
- `--compact` also trims the envelope (`query`, `generated_at`, `db_path`) and empties a scan document's `plan`; the output budget empties bulky context before cutting findings.
- A single loopback or private-address target is paced from its first request, and three connection resets in a row arm adaptive back-off on any host.
- `module disable` writes a deny-list; a broad term needs `--force`.
- Agent commands fail at once with `provider_unreachable` when the provider refuses the connection; a TUI or picker without a terminal is a usage error naming the non-interactive form.
- `skills install -j` items carry `status_after`, and `--agent`/`--scope` are validated even with `--dir`. `init` names the built-in AI agent's skills apart from the coding-agent skill.
- `vigolium export` now exports the active project by default, like `traffic`, `finding` and `db export`; pass `--all-projects` for the whole store. Report metadata (target, duration) is scoped the same way.
- `vigolium import` of a JSONL export now stores its `scan` and `oast_interaction` rows (re-homed into the active project, deduplicated); `scope` rows load only with `--include-scopes` or into a `-S`/`--glob-db` scratch database. `import -j` reports `imported_by_type`, `duplicates_by_type` and `skipped_types`.
- `db export --format jsonl` (the default) writes the `{"type","data"}` lines `vigolium export` writes and `import` reads: the selected records, then their linked findings. The previous nuclei-style output is `--format nuclei`. `--table http_records|findings` picks the line types; other tables are a usage error.
- `finding load` reads `export`/`db export` JSONL and `finding -j` documents, keeps `url`, `hostname` and `matched_at`, rejects an unknown severity (`input_unparsed`, nothing stored), and counts agent findings that differ only by URL as separate findings.
- A multi-source `import` (several paths or `--glob-db`) continues past a source that fails, lists each source with its status in `-j` `sources[]`, and exits 1 naming the failures; `--glob-strict` stops at the first. A SQLite file that is not a vigolium store is refused (`source_incompatible`) instead of merging as zeros.
- `ingest` reports the format it detected (`input_format: har`, not `urls`), labels the records it fetches `ingest-cli` like the ones it saves directly, keeps a HAR entry's `time` as `response_time_ms`, and sets `changed` from the rows it actually wrote (new `records_written`); re-ingesting the same input is `changed: false`.
- `traffic -j` rows carry `sent_at` (RFC 3339, UTC). `hosts`, `log ls`, `db stats` and `export` accept `--from/--to` (`--since/--until`). Time-filter help states that a time without a zone is local and results print in UTC.
- `--host` on `traffic`, `finding`, `db list|export|stats|clean`, `inventory`, `hosts` and bulk `replay` accepts a bare host, `host:port`, an origin (`https://host[:port]`, as `traffic -j` prints it) or a bracketed IPv6 address.
- `--glob-db` reads and multi-source `import` no longer leave `-wal`/`-shm` files beside their sources (a source with no live WAL is read immutable; one with a live WAL is read in place and the created sidecars removed, or through a scratch copy in a read-only directory), and a glob never matches a sidecar as a source.
- `db ls`, `log ls`, `scan diff` and `db stats` honour `--format tsv` (with `--no-header`) and refuse other formats; `log <prefix>` resolves an 8+ character session UUID prefix; `db reset --dry-run` lists the files it would delete; `db stats` reads like `traffic` (standalone sources whole, `project_uuid` in `-j`); `--db` naming a non-SQLite file (a JSONL export) fails with a hint to pass `-S`.
- `config ls` shows the settings of the active project (global config plus its overlay), lists every settable key including ones set to `false` or empty, and `-j` values are typed (`value`; the old text is `display`) with `default`, `type` and `source` (`default`, `file`, `env:NAME`, `project`, `flag`). Redaction applies to string credentials only (any key under `api_keys`, tokens, passwords), not to booleans like `disable_secret_scan`. `config ls --effective` lists only the keys a layer set. New `vigolium config env` lists every `VIGOLIUM_*` variable the binary reads.
- `scope view` reads the active project's overlay and labels each value with its source; `scope set` honours the global `--project-uuid`/`--project-name` like `--project`.
- `project use` accepts a name or a unique 8+ character UUID prefix; an unknown one is `project_not_found` (was `not_found`) with a `project create <name>` hint. New `project use --print-env` prints the export line and writes no `active-project` file, pinning one shell.
- `vigolium init` help states its downloads (Chrome for Testing ~150 MB, nuclei-templates ~100 MB); without a terminal it skips them and prints the command that fetches them (`--with-deps` downloads anyway).
- `doctor` prints the verdict first with what still works (scan, spidering, known-issue scan, out-of-band, agent, audit), then one line per check; detail lines need `-v`. `doctor -j` lists the checks flat in `items` (`id`, `group`, `status`, `message`, `affects`, `fix_argv`, and on a failing check `source`: the setting it tested and where it came from) with `status` and `capabilities` at the top level; `--json-legacy-keys` keeps the nested report. A proxy row names the proxy, the flag or variable that set it, and that loopback targets go through it. `--only` works without `--fix`. `--fix` prints the re-checked report once, and `--fix --dry-run` lists each install with its method, destination and approximate size. An agent provider behind an endpoint (`openai-compatible`, `anthropic-compatible`) is `unverified` instead of ok; `--for agent` probes the endpoint.

### Removed

- `--ci-output-format`: hidden, and using it is exit 2 naming `-j` (the scan document) and `--format jsonl` (the findings stream).

### Fixed

- `scan-url` and `scan-request` apply `--rate-limit` (they printed it and ignored it).
- `server` binds both listeners before announcing them; a bind failure exits 1.
- `ingest` from stdin honours `-I` and file-format detection.
- `db clean --severity` deletes findings only, and every dry run reports per-table counts.
- A scan with no target (`--all-records`) no longer panics on a nil admission.
- Skill, help and docs examples that had rotted: `jq '.records[]'` (rows are in `.items[]`), a non-existent `jwt-none` preset, `ext lint` suggested for an auth file (`auth lint`), and statements the changes above made false.

## [v0.5.7] - 2026-11-14

### Added

- `kit oast new` falls back to `$VIGOLIUM_OAST_TOKEN` when `--token` is empty.

### Security

- `GET /api/config?show_sensitive=true` unmasks secrets for admin tokens only; rotate keys if viewer tokens were shared.
- `agent audit --source` extracts archives inside `os.Root`, skipping escaping symlinks and capping modes at `0755`.

### Fixed

- `vigolium init` on an existing config still installs missing core deps (chromium, nuclei-templates).
- REST background scans and agent runs no longer drift to another project via a reused `X-Project-UUID` buffer.
- A failed Nuclei or secret-scan leg marks `known-issue-scan` as `failed`.
- `ingest --server` stops on malformed nuclei JSON, fails on unreadable inputs, and treats `--rate-limit 0` as unlimited.
- A cancelled agent tool batch no longer breaks later requests in the same session.

## [v0.5.6] - 2026-10-25

### New Vulnerability Checks

- `node2shell` active module probes the Brotli decoder's version (CVE-2026-111497) with a 22 MiB stream only an unpatched decoder accepts, behind the same cheap decode gate; filed as a Suspect/Tentative lead, never the crash trigger. Probe stream from [assetnote/node2shell-scanner](https://github.com/assetnote/node2shell-scanner).

### Added

- `vigolium match-not-found` classifies stdin JSON-lines responses against stored not-found baselines.
- `run probe --favicon` stores each origin's favicon hashes as a host fact; `hosts --has favicon`.
- `fingerprint` reports unanswered reads in `errors[]` with a `kind`.
- `--only discovery,spidering,targeted-respider` runs the SPA re-spider without dynamic assessment.
- `pkg/modules/infra/node2shell` shares the Brotli decode gate, differential and streams between both Brotli modules.
- `modkit.ElideRequestBody` keeps multi-MiB probe bodies out of stored evidence; the shared-helper contract test now forbids private `elideBody` copies.
- `pkg/modules/modtest` helpers for content-encoding fixtures and module test servers.

### Fixed

- `fingerprint` retries a transport-failed read once instead of reporting it as not found.
- `fingerprint` and `hosts` schemas drop the never-filled `method_matrix`.
- Scanner transport sets `ExpectContinueTimeout`, so `Expect: 100-continue` senders let an edge refuse a huge body before it is uploaded.

### Changed

- Schema v5: `host_observations` gains a `favicon` column.
- `brotli-request-decoding-exposure` reuses the shared gate instead of its own copy (−388 lines).
- `php2shell` uses `modkit.ElideRequestBody` in place of its private elider.

## [v0.5.5] - 2026-10-24

### New Vulnerability Checks

- `php2shell` active module (CVE-2026-109618 / CVE-2026-109619) on PHP-fingerprinted hosts; detection inspired by [assetnote/php2shell-scanner](https://github.com/assetnote/php2shell-scanner).
- `php2shell-version` passive module flags vulnerable PHP 8.2–8.5 banners.
- `brotli-request-decoding-exposure` active module flags servers that decode Brotli request bodies (CVE-2026-111497, the http2shell surface). Not just Node: the out-of-bounds write sits in the Brotli decoder itself, so Bun, Envoy/Istio decompressors and anything linking libbrotli are exposed too. Stack-agnostic and never sends the crash trigger. See [patchtheplanet.org/brotli](https://patchtheplanet.org/brotli).

### Added

- `fuzz` multiplexes over HTTP/3 → HTTP/2 → HTTP/1.1 (`--http-version`, `--http3`, `--http3-only`), reported as `pace.protocol`.
- Discovery pins each origin's protocol (`discovery.engine.protocol`) with a dedicated brute-force pool (`brute_force_concurrency`).
- `vigolium fingerprint` stores per-origin host facts (`--depth light|standard|full`).
- Favicon mmh3 hashes (Shodan/FOFA) alongside MD5 and SHA-256.
- `vigolium hosts` reads stored host facts; `--sans` and `--soft-404`.
- `vigolium dns` resolves and stores records; `dig` and `host` shims route to it.
- `traffic --fields matches_not_found` and `--exclude-not-found`.
- `--format tsv` on `traffic`, `finding`, `endpoints`, `params`, `hosts`, `dns`.
- Shared `--fields` aliases with nearest-name suggestions; new `uuid_short` and `response_headers` fields.
- `--fields`, `--compact`, `--max-output-bytes` on `fuzz`, `replay`, `endpoints`, `params`, `log ls`, `hosts`, `dns`.
- JSON schemas for `fuzz`, `replay`, `ingest`, `traffic body/headers`, `hosts`, `dns`, `fingerprint`, `schema storage/flags`.
- `vigolium schema storage [table]` describes tables, columns and row counts.
- `--usage` on any command and `vigolium schema flags <command> -j`.
- Record UUID flags accept a unique 8+ char prefix (`ambiguous_id` on collision).
- `ingest -j` lists stored `items` and failure reasons; `--keep-blocked` stores WAF block pages.

### Fixed

- Proxied scans no longer drop pooled connections every 100 requests.
- TLS sessions resume across connections instead of full handshakes.
- Discovery backs off on 429/5xx/WAF responses and honors `Retry-After`.
- Discovery classifies 404/400/414/421/431 by status before soft-404 fingerprinting.
- `fuzz --send-via-burp` pools bridge connections.
- Process-substitution and pipe inputs (`-T <(…)`) no longer read as empty.
- `ingest --dir` works, including a single matching file.
- `replay --raw-request-file` / `--raw-request` alone is a valid source.
- `replay -i` and `fuzz -i` read a file path instead of parsing it as a request.
- Unparsed-input error is `input_unparsed` and names `--input-file`.
- `fuzz -w builtin|default` selects the default list; `builtin:<name>` picks one.
- `ingest` reports the dominant WAF-block reason instead of "no response to store".

### Changed

- Probe markers say `vigolium` instead of `vgl`/`vgn`/`vgm`/`vgo`/`vig-`.
- `traffic body` and `traffic headers` accept the record positionally.
- `--tls-probe` help explains certificates are readable via `vigolium hosts`.
- Schema v4: `host_observations` gains DNS, `fingerprint` and `not_found` columns (additive).
- Go 1.27.3 and upgraded Go/JS dependencies (Bun v1.3).

## [v0.5.4] - 2026-10-18

### Added

- `oast.fallback_to_default` (default true) re-registers against `oast.pro` when the configured `server_url` does not answer, without carrying the token.

### Fixed

- Preflight no longer follows redirects, so a target redirecting to a dead host is no longer reported unreachable (`no_targets_reachable`).
- The heuristics check no longer classifies a redirecting root from the destination's page, nor requests that destination twice.
- `confirmBlank`'s secondary probes leaked two pooled buffers per blank-rooted target.
- Through an `http://` proxy, `replay` and `fuzz` dropped a non-default port from the request line, so the proxy forwarded to port 80.
- Through an `http://` proxy, a scan, discovery or login request with a `Host` header differing from its URL was forwarded to that `Host` instead of the target.
- Raw request-target probes (routing SSRF) stripped the port from the `Host` header.
- `fuzz` omitted a non-default port from its `fuzzing …` line and the `-j` summary's `target`.
- The ingest proxy dropped a non-default port from the upstream `Host` for an intercepted HTTPS request that carried none.

### Changed

- `--scope-origin` help now says it bounds stored records, not egress — a followed redirect is `--redirect-mode`'s job.
- `replay` and `fuzz` send the request's own `Host` instead of the target hostname, matching `--send-via-burp`; a request without one gets `host:port`.

## [v0.5.3] - 2026-10-10

### Added

- `vigolium schema` — JSON Schema for every `-j` document, event and error envelope, committed under `docs/schema/`.
- `module.error` events and `scans.module_errors` totals — module errors, timeouts and panics are reported instead of logged away.
- `ext run` / `ext eval --record-uuid` runs one extension offline against a stored record; `ext test` runs fixture cases.
- OAuth2 client-credentials and refresh-token logins in session files, auto-refreshed before expiry.
- `login.headers` and `{{env:}}` / `{{totp:}}` / `{{totp_secret_file:}}` templates in login flows.
- `--auth-file` on `agent swarm` and `agent autopilot`.
- Discovery recovers webpack/Vite lazy chunks named only at runtime.
- Agent run budgets: `--max-commands`, `--token-budget`, `--max-cost-usd` (exit 5 when exhausted).
- `--preflight-timeout` / `--no-preflight` for agent provider pings.
- `agent triage --no-write` / `--no-probe` and an `inconclusive` verdict.
- `agent query` and `agent triage` record their own agentic_scans row.
- `VIGOLIUM_DB` and `VIGOLIUM_CONFIG` environment variables.
- The agent bash tool inherits the running binary, database, project and config.
- `scan --dry-run` / `run <phase> --dry-run` prints the resolved scan plan without sending anything.
- `scan.plan` event, also stored on the scan row.
- Client routes found in JavaScript seed the browser crawl (`spidering.route_seeds`).
- Multi-tab browser crawling via `spidering.tabs`.
- The browser crawl clicks elements inside shadow DOM and web components.
- `fuzz -r/--rate-limit` global request cap.
- `fuzz --fuzz new-param`, `--suffix` and a builtin `params` wordlist.
- `--discovery-extensions` and `--discovery-max-depth`.
- `--known-issue-scan-templates` to run specific nuclei templates.
- Shims accept vigolium globals and `--dry-run`, and print approximation notes.
- `--format csv`, `junit` and `github` report formats for CI.
- `--max-body-bytes` and `--pdf-timeout` for reports.
- `-tags audit_external` builds download the pinned vigolium-audit helper on demand.
- `vigolium db compact` shrinks stored bodies without deleting records.
- Global `--color auto|always|never` and `--pretty`.
- `auth totp --secret-env` / `--secret-file` / `--secret -`.
- `auth load --force` / `--timeout` with per-session login results under `-j`.
- `auth lint` takes multiple files, reports unknown fields with line/column, and supports `-j`.
- `vigolium auth check` verifies a session actually authenticates against a URL.
- Session-file `check` and `reauth` blocks.
- In-scan re-login when a session is detected as logged out.
- `vigolium server ca print|path|install|uninstall` for the ingest-proxy CA.
- Ingest proxy access control via `--proxy-token` and `--proxy-allow`.
- `server --discard-queued`.
- `vigolium config validate`.
- `doctor` `scope` and `oast` checks, and `doctor --strict`.
- `scope set --project`.
- `discovery.wordlists.tier` with a new embedded `large` tier.
- Repeatable `--discovery-wordlist` with `.gz` support.
- Hidden-parameter mining phase (`param-mining`) and `kit param-mine`.
- `finding mark` records verdicts (false positive, confirmed, accepted risk, fixed, triaged).
- `finding verify` re-runs a finding's module to confirm it.
- Findings store replay context: origin record, insertion point and payload.
- Differential re-confirmation for modules mixing in-band and OAST/timing checks.
- `vigolium scan diff` compares findings between two scans.
- `finding --new-since` and `--verdict` filters.
- Scope admission check before a scan sends anything.
- Per-target reachability preflight (`--skip preflight` to disable).
- `scan-url` / `scan-request` report per-target reachability and scheme source.
- `scan-request --no-scheme-probe`.
- `vigolium endpoints` lists endpoints from stored traffic.
- `vigolium params` lists parameters per endpoint.
- `traffic --scan-uuid`.
- `traffic --curl` and `finding --curl` render requests as curl commands.
- `vigolium scan status` with liveness and ETA.
- `vigolium scan wait` blocks until a scan finishes.
- Liveness heartbeat for every native scan; dead runs are reported `abandoned`.
- Liveness fields in `log ls -j` and `log ls --reap`.
- `scanning_strategy.scan_logs.status_retention_days`.
- `vigolium update --check`, `--dry-run` and `--install-dir`.
- Signed releases (minisign) and `VIGOLIUM_UPDATE_BASE_URL`.
- `--max-requests` and `--max-requests-per-host` request budgets.
- `ext lint` loads files in a side-effect-free VM; adds `--strict` and `--stdin-kind`.
- YAML extension lint flags unknown keys with suggestions; `extensions.yaml_strict`.
- `extension.failed` events.
- `skills install` manifests with stale/modified detection, plus a `doctor` `skill` check.
- Opt-in REST API v2 responses via header or `?api_version=2`.
- `POST /api/findings/:id/verify`.
- `POST /api/scan-request` settles schemeless requests like the CLI.
- `{nonce}` templates in `--oast-url` and `vigolium oast ingest`.
- `scan-url` / `scan-request` accept `--auth`, `--intensity`, `--scanning-max-duration`, `--oast-url` and `--scope-origin`.
- The `scan-url` / `scan-request` direct path now runs OAST checks.

### Changed

- First-run dependencies (Chrome, nuclei-templates) install lazily when their phase needs them.
- A failing phase no longer ends a native scan; only infrastructure errors do.
- Every command's `-j` output is now one envelope.
- **BREAKING** `schema_version` is 2; scan commands print one scan document under `-j`.
- **BREAKING** `-j` on a scan no longer implies `--format jsonl`.
- **BREAKING** A `-j` document's `command` is always the cobra path.
- **BREAKING** `import` and `js` use the global `--format`.
- **BREAKING** Remaining read commands print the `-j` envelope; `--json-legacy-keys` restores old keys.
- **BREAKING** `-j` output is compact by default; use `--pretty` to indent.
- **BREAKING** Color is automatic instead of always on.
- **BREAKING** `replay` and `fuzz` print a human view by default; `-j` is one envelope.
- **BREAKING** `traffic -j` with tree/markdown/raw/burp output exits 2.
- `-j` documents carry `project_source`.
- Mutating commands print a mutation document under `-j`.
- `--ci-output-format` finding lines are deprecated.
- "Filtered by:" moves to stderr; the banner prints only on a terminal without `--events`.
- Runtime machine-contract e2e test covers every command.
- `vigolium-scanner` skill rewritten as a short router with reference files.
- `agent autopilot` / `swarm` / `audit` print one run document under `-j`.
- Agent runs that stop short exit 5.
- `agent triage` marks false positives by status instead of downgrading severity.
- **BREAKING** `agent audit` requires `--source`.
- The nested audit harness is off by default on `agent autopilot`, `agent swarm` and REST autopilot.
- `agent session`, `--list-agents`, `--list-templates` and `--list-modes` print read envelopes under `-j`.
- `agent query -j` prints one envelope; streamed output goes to stderr.
- The olium bash tool runs `bash -c` instead of a login shell.
- The scan webhook fires on every exit (`scan.failed`, `scan.cancelled`) and is drained before exit.
- `scanning_strategy.session.*` settings act as session `check` defaults.
- **BREAKING** An `--ext` extension that fails to load stops the scan; `--ext-allow-failures` restores the old behavior.
- **BREAKING** `ext lint` errors on missing handlers and exports.
- Extension top-level code is limited to 10s at load.
- **BREAKING** Extension header objects are case-insensitive, with `get`/`getAll`/`has`/`entries`/`raw`.
- Module selection now applies to JS/YAML extensions, on the CLI and REST.
- Embedded helpers are zstd-compressed (binary 310 MB → 220 MB); run `make build` once after pulling.
- **BREAKING** `project use` no longer auto-creates; pass `--create`.
- One egress gate paces every scan request; retries and redirects take their own tokens.
- Discovery streams fuzz results during the crawl (`discovery.stream_fuzz`).
- `--intensity deep` uses the large wordlists.
- A missing `--discovery-wordlist` file exits 2.
- `scans.total_requests` is now populated.
- `log <uuid>` uses the shared liveness check.
- `kit harvest -j` reports stats and limits; missing arguments exit 2.
- **BREAKING** `auth load` exits 1 on a failed login and runs the full scan login flow.
- **BREAKING** `auth totp` prints the bare code; JSON is behind `-j`.
- `auth load`, `auth lint` and `--auth-file` share one session-file parser.
- **BREAKING** `--fail-on`, `scan diff` and `--new-since` ignore dismissed findings.
- **BREAKING** `scan <uuid>` exits 2 as a mistyped subcommand.
- **BREAKING** `server` binds to `127.0.0.1` by default; a non-loopback ingest proxy needs a token or allow-list.
- **BREAKING** `-S` on `server` and `ingest` is a usage error.
- The scan-on-receive spill queue moved to `~/.vigolium/server-queue/` and resumes on restart.
- Dead-host quarantine is a recovering circuit breaker keyed on `host:port`.
- `--mirror-fs` writes owner-only files atomically.
- **BREAKING** `scan` / `run` with no target need `--all-records` to rescan the database.
- Implicit stdin gives up after 2s with no input.
- jstangle workers and memory budget scale with CPU and RAM.
- `engine.jstangle_concurrency` is deprecated in favor of `jstangle.worker_count`.
- `--max-per-host` defaults to 40 everywhere.
- REST scans resolve options the same way as `vigolium scan`.
- The agent's `run_native_scan` honors the strategy's pace and phases.
- **BREAKING** `doctor` exits 1 when `not_ready`.
- `config set` parses JSON/YAML list and map values and validates before writing.
- `config set` and `scope set` write atomically.
- **BREAKING** A scan whose every target is out of scope exits 1 (`no_targets_in_scope`).
- **BREAKING** `scan-url` / `scan-request` enforce scope without `-S`; REST answers 422.
- **BREAKING** A scan with no reachable targets exits 1 (`no_targets_reachable`).
- **BREAKING** `modules_run` counts modules that executed; `modules_loaded` holds the old number.
- `scan-request` probes the scheme when the raw request gives no hint.
- **BREAKING** `vigolium update` updates in process with signature verification.
- **BREAKING** `VIGOLIUM_AUTO_UPDATE` only acts at an interactive terminal.
- Installers fail closed on missing checksums or signatures.
- Derived spidering budgets are at least 60s, and crawls drain before the deadline.
- `vigolium ffuf` routes to `fuzz` when FUZZ isn't the last path segment; more flags mapped.
- `vigolium arjun` routes to `fuzz --fuzz new-param`.
- `vigolium nuclei` requires `-u`/`-l`; `-t` maps to `--known-issue-scan-templates`.
- More `katana` and `gau` flag mappings.
- All `--format` values resolve through one table; `scan --format md` works.
- **BREAKING** `db export --format csv` uses standard quoting and neutralizes formula injection.
- REST v1 errors gain `error_code`; unknown routes return JSON.
- **BREAKING** An unknown `X-Project-UUID` returns 404 instead of creating a project.
- The ingest proxy applies the target project's scope overlay.
- Postman collections accept `-t` as base URL and `--spec-var`; an explicit `-I` disables content detection.
- Module browser confirmations honor `spidering.stealth` and `--proxy`.

### Fixed

- `finding --sort severity` returned an unsorted list.
- `config set` / `scope set` split JSON lists on commas, producing scope patterns that matched nothing.
- `auth load` validated only part of multi-step flows, ignored `expect` and `--proxy`, and saved failed sessions.
- `POST /api/scan-all-records` silently ignored an unloadable profile or intensity.
- Large source maps (>512 sources or 8 MiB) produced no finding.
- `db clean --scan-uuid` deleted every HTTP record in the project; `export`/`ls`/`stats` ignored the filter too.
- Several REST handlers kept running after writing an error response.
- PostgreSQL stores failed on integer-typed bool columns; `db migrate` converts them.
- `--session` / `--session-file` aliases were unknown flags on `scan` and `run`.

## [v0.5.2] - 2026-10-03

### Added

- Scan completeness: `completeness`, `stop_reason` and `phase_outcomes` on the scan row, in the REST object and in `--format jsonl`.
- `reasons` / `limits` on `phase.finished` and `scan.finished`, plus `stop_reason` on the scan line.
- `--require-auth` / `spidering.require_auth` — a failed login is fatal for that target.
- `--keep-db-on-error` — a failed `-S` run's database is kept under `~/.vigolium/recovered/`.
- `--glob-strict` for `--glob-db` reads, with `glob_sources` accounting naming every skipped file.
- `--max-output-bytes` (opt-in) on `finding`, `traffic` and `db ls`.
- `--json-legacy-keys` — restores the per-command row arrays replaced by `items`.
- `make test-browser-conformance` — browser conformance suite with a launch precheck.
- `spidering.interaction.*`, `spidering.identity_email_domain`, `spidering.graph_include_values`, `spidering.max_capture_body_bytes`.

### Changed

- **BREAKING** The browser crawler no longer creates accounts, uploads or downloads files, and now cancels `confirm()` dialogs; `spidering.interaction.*` restores each.
- **BREAKING** Crawl graphs are now `crawl-graph-<host>-<scan>-<seq>.json`, redacted and owner-only; widen any glob on the old name.
- **BREAKING** `-j` emits one document per invocation with `items` as the only row array; `--json-legacy-keys` restores the old names.
- Cookies are evaluated per request, so fewer are sent — host-only, path-scoped, `Secure` and expired cookies are no longer sent everywhere.
- SIGTERM now cancels a scan like Ctrl-C.
- `--events ndjson` owns stdout exclusively; events carry `seq` and a terminal event written after finalization.
- A requested output that cannot be written exits 1 with `error.code: "export_failed"` instead of warning.
- Single-file `-o` outputs publish atomically; a failure leaves the previous file intact.
- `--format fs` re-exports replace the tree instead of merging into it.
- A broken `--config` exits 1 instead of silently falling back to defaults.
- `spidering.max_duration: 0s` now means the 30m default; negative durations exit 2.
- All login flows together are bounded by a 2-minute budget.
- Record delivery is at-least-once: a curtailed phase leaves its cursor behind unfinished records.
- The browser sandbox is on by default; `--browser-insecure` restores the old posture.
- Generated identities use `example.com`.
- `FormsSubmitted` is a real count rather than structurally 0.
- Stored `duration_ms` for browser-captured responses excludes the CDP body fetch, so values shrink.
- `-I` and `--list-input-mode` are generated from the parser registry; all old aliases still work.
- `version`, `help` and `completion` no longer create `~/.vigolium`.
- First-run setup and `doctor --fix` write to stderr, so a cold-`$HOME` NDJSON run stays clean.
- Agent tool contracts: `web_fetch`/`browser_probe` capture fields and `browser_auth` cookie fields renamed; `agent-browser` pinned to `>=0.26.0 <1.0.0`.

### Fixed

- `vigolium ingest` reported records it never persisted, and discarded the captured response on every HAR/Burp/Postman entry to re-fetch it live.
- A stored login flow could never be reloaded — double-encoded `ExtractRules` failed validation and killed session init for the whole scan.
- `session.use_in_discovery: false` made the entire scan anonymous, including DynamicAssessment and KnownIssueScan.
- Compare-session requesters carried the primary session's credentials, so authorization-differential checks read "same as primary".
- A cancelled scan acked unprocessed work, advancing the DB cursor past records a later run then skipped permanently.
- `scope.host.exclude` / `scope.path.exclude` were not enforced before a discovery request left.
- `requests_sent` for Discovery was effectively 0 rather than the real count.
- A browser crawl that lost its corpus recorded `completed`; capture loss and browser auth failure now reach the scan row.
- Login flows ignored `--proxy` and rejected the target's certificate, unlike every other request.
- `-P --fail-on` exited 0 unless every child tripped the gate; it now exits 4 when any does.
- A raw request's declared `Content-Length` disagreed with its body when the source file ended in a newline.
- A SQLite path containing `#`, `%`, a space or non-ASCII did not reach the file it named.
- `--stateless=false` dropped a `VIGOLIUM_DB_PATH` pin, and `--project-uuid` did not filter a stateless read.
- JSONL and SQLite re-imports failed on a UNIQUE constraint; a lossy import now exits 1.
- `scan-url --events ndjson` emitted nothing, and `| head` killed the scan with SIGPIPE.
- A `--format fs` re-export with a narrower filter left the previous run's files behind.
- `--input-read-timeout 0` did not disable the deadline; a negative value now exits 2.
- A dynamic-assessment round that errored printed "all rounds completed" and carried on.
- A phase stopped by its own `max_duration` reported `completed`.
- Discovery cleanup deleted records that findings referenced, and grouped by hostname rather than origin.
- `scanning_pace.discovery.rate_limit` was accepted and ignored.
- The per-module finding cap restarted every feedback round instead of spanning the phase.
- Writer shutdown was unbounded and could take 3× `flush_timeout`.
- A failed browser launch stranded a Chromium profile directory, and an abandoned crawl left its browser running.
- `module ls` printed the default config path while `module enable/disable` wrote the resolved one.

## [v0.5.1] - 2026-09-24

### Added

- Claude 5 family pricing (Fable 5.1/5, Opus 5.5/5, Sonnet 5) in audit cost estimates.
- `reasoning_effort: max` for Anthropic; the effort level now reaches every provider that supports it.
- Adaptive thinking enabled for Claude 4.6+ models.
- Conversation-tail prompt caching on Anthropic, cutting input cost on long agent loops.
- Skill `allowed-tools` now surfaced to the model, with warnings for tools the run does not expose.

### Fixed

- Parallel tool calls no longer cross-wire their arguments or drop a call (OpenAI chat-completions, id-less gateways).
- Gemini parallel calls: unique synthesized call ids and tool results folded into one turn.
- Responses API turns with multiple text blocks no longer lose all but the last.
- A truncated provider stream is retried instead of committed as a finished turn.
- Orphaned `tool_use` blocks are auto-answered, avoiding a hard 400 on every re-send path.
- 429/529 and 5xx provider errors are retried with longer backoff instead of ending the run.
- Hitting `--max-commands` or context overflow now finalizes the run (summary, triage, transcript) instead of exiting early.
- Scan tools honor their own duration budget and read back results even after the deadline, no more all-zero summaries.
- Timeout marker placed at the head of tool output so spilling large results no longer hides it.
- `bash` tool timeout clamped to the engine deadline; `web_fetch` rejects unknown modes.
- Tool args accept a bare string/number where a list is expected.
- Repeated identical tool failures escalate their error text to break retry loops.
- Autopilot coverage probe scans are time-capped and fail loudly on snapshot errors.
- Prompt-cache key now uses the run UUID, not the shared session directory.
- openai-compatible: tool-call-only assistant turns always send `content`, fixing a 400 (`messages.N.content Field required`) from Open WebUI and other strict gateways; nil tool args send `{}`; id-less tool calls get a synthesized id.
- A model stuck repeating itself (text or `reasoning_content`/`reasoning`) is cut off instead of streaming until the server's output ceiling; reasoning from vLLM/Ollama/OpenRouter now shows as thinking.
- Autopilot runs where the model stopped calling tools report `stalled` with a warning (and a "never called a tool" diagnosis) instead of "natural stop"; the server marks them degraded.
- Workbench agent log: no longer yanks to the bottom while you read, reconnects replay only the last 512 KB, finished runs are capped the same way, and split UTF-8/ANSI sequences no longer garble chunks.
- openai-compatible servers: a 200 JSON body (proxy ignoring `stream:true`, or an error sent with 200), events separated by single newlines, `content` as an array of parts, a final `message` chunk, and tool arguments sent as an object or double-encoded are all read instead of ending as "stream incomplete" or an empty turn; in-stream `{"error":...}` frames surface as errors.
- openai-compatible `/v1` probe: when the alternate spelling answers with an error (401/429/5xx), it is remembered instead of pinning the dead URL; 405 triggers the probe like 404. Servers that reject `stream_options` get one retry without it.
- Tool calls whose arguments do not parse (truncated at the output limit, malformed) are no longer run with `{}`; the model gets the parse error and its raw arguments back (all drivers).
- Engine history: no two user messages in a row after a failed run, no empty assistant message, and a tool call whose name changed after it started is no longer dropped - each broke alternation-strict chat templates (Mistral, Gemma) or strict gateways.
- Workbench: the scan-detail LOGS panel works again (it could not read the plain-text runtime.log tail), runs ending `completed_with_errors`/`completed_with_warnings` stop polling, degraded runs show amber with their warnings, the live log reconnects past the follower's 2 h cap, and abandoned log followers exit on a heartbeat.
- Run status is decided in one place (`database.CompletedAgenticScanStatus` / `MultiDriverAgenticScanStatus`): CLI autopilot runs now record `completed_with_warnings` like the server, a CLI multi-driver audit where every driver failed is `failed`, and report metadata and `agent session` listings include degraded runs. Single-newline SSE framing is handled for every provider (Anthropic, Responses, Gemini), and id-less Responses tool calls get a stable id.

### Changed

- Default models bumped: `claude-sonnet-5` for LLM helpers; provider defaults centralized.
- `agent.olium.max_tokens` defaults to `0` (provider default, 64000 on Anthropic); oversized values are ignored.
- `temperature` is accepted but ignored, as current Claude models reject sampling params.
- Docs and prompts now reference the real tool name `run_native_scan`; olium system prompt trimmed.

## [v0.5.0] - 2026-09-22

A **trustworthy-output** release: two finding families that were entirely false positives now need evidence the transport can actually produce, the hardening advisories move off the default intensity, a run that fails to write a requested artifact exits non-zero, and scans stop leaking temp scratch.

### Added

- `vigolium kit tmp-clean` - collect vigolium scratch left in the system temp directory by interrupted runs. `--max-age` (default 6h) governs what counts as abandoned.
- `hygiene` module tag, selectable with `--module-tag hygiene` / `--module-id <id>`.
- `dynamic-assessment.hygiene_modules` - force the hardening advisories on at any intensity, or off even at deep.
- `scans.scope_origin_mode` - the resolved host-scope mode, carried through `--format jsonl`, `vigolium export` and the REST scan object.
- `config.ResolveCLIOriginMode`, the one fallback chain the matcher, banner, summary, snapshot and scan row all read.
- A `Host scope` reference section documenting how `--scope-origin` also selects *stored* records.

### Fixed

- **All 12 request-smuggling findings in an engagement were false positives.** `net/http` dropped `Transfer-Encoding` and rewrote `Content-Length`, so every probe reached the wire as a well-formed POST identical to its control. Probes now go out as verbatim bytes (`http.Options.RawBytes`), the gate is probe-vs-control (3x **and** a 2s margin **and** a 5s floor) against the median of three controls re-measured after each probe, and hosts are skipped when an edge/auth gate answers, traffic is not HTTP/1.1, or the server sends `Connection: close`.
- **`ssi-injection` filed ~113 high-severity false positives.** The oracle proved evaluation by the *absence* of directive markup, so a WAF, an SSO gate or a denial page read as a hit. It now brackets `<!--#echo var="DATE_GMT"-->` between two fresh tags and requires a server-owned value, rules out a comment-stripping sanitizer with a control round, and skips blocked/redirect/404 responses. A quadratic needle scan (8.5s on a 900 KB page) is bounded to 64 bytes.
- **`-t`/`-T` no longer wait on stdin.** An inherited pipe (CI runner, agent harness, `| tee`) makes `HasStdin()` true, so scans blocked for the full `--input-read-timeout` - and `ingest -t` hung indefinitely - before using targets already on the command line. A typed `-i -` still wins.
- **A requested artifact that was never written now fails the run.** An export failure exited `0`, reported `scan.finished status=completed` and left no file. `scan`/`run`/`scan-url`/`scan-request` and an agentic `-S` run now exit `1` with `error.code: "export_failed"`; formats are still attempted independently.
- **A failed SQLite export no longer destroys the previous one.** `VACUUM INTO` refuses to overwrite, so the destination was deleted first; the copy is now staged beside it and renamed into place.
- **Scans clean up after themselves.** Every temporary store - dedup LevelDBs, deparos' caches, ephemeral sitemaps, jstangle jobs, stateless SQLite, the spidering Chromium profile - lives under one per-process directory teardown removes whole, and scratch abandoned by a killed run is collected on a later scan.
- **The spidering browser stranded its Chromium profile on every launch**: `Browser.Close` never called go-rod's `launcher.Cleanup()`. One workstation held 3,384 profiles totalling 104 GB.
- Reading a `.jsonl` artifact re-read all of `os.TempDir()` (55-170 ms on every `traffic`/`finding`/`export` and every `--glob-db` merge), and fastdialer's write-only dial history swept the whole temp directory at startup (~180 ms per invocation); both are gone.
- The config snapshot logged `scope_origin_mode: ""` for any run that took the default.

### Changed

- **The 14 `hygiene`-tagged hardening advisories no longer run at the default intensity** - each fires on nearly every response and buried exploitable findings under one near-identical row per URL. They now need `--intensity deep`, the tag, or the config key. `express-session-audit` joins them; Info-tier fingerprints, endpoint/param observers, `surface-scoring` and `clickjacking-detect` are unaffected.
- `ssi-injection` in-band findings are Medium, not High - the echo oracle proves directive evaluation, not the file read or RCE.
- **Startup is about 20 ms faster** (`go-runewidth` v0.0.27 -> v0.0.30, whose `init` no longer builds a 2.2 MB width table rune by rune).
- **A single-phase stateless scan is several times faster** (`run probe -t <host> -S`: ~0.78 s -> ~0.12 s). Dedup sets keep a bounded in-memory tier and allocate a LevelDB only past it, so a one-host probe opens none where it opened seventeen; the executor's post-EOF drain backs off instead of ticking; stderr-capture teardown waits for its reader rather than sleeping 50 ms.
- **Phases that never contact the target no longer build infrastructure for traffic they will not send** - `run external-harvest --auth-file` used to authenticate against a host it was only going to query archives about.
- `--scope-origin` help text states the default and what `balanced` admits, on `scan`, `run` and `ingest`; `-S/--stateless` is documented as the isolation lever, not just a CI one.

## [v0.4.9] - 2026-09-20

A **source-map recovery and redirect-lineage** release: exposed `.map` files are parsed, secret-scanned and fed back into the scan, redirected records finally name the server the bytes came from, and every phase stops at a login/SSO wall. Registry moves to 208 active + 117 passive.

### Added

- `sourcemap-ingest` active module - fetches an exposed source map, secret-scans the recovered originals and ingests their routes.
- Shared `jstangle/sourcemap` package: one definition of a map reference, a sibling candidate and a parsed map.
- Source-map detection now covers CSS, `eval` strings, `SourceMap`/`X-SourceMap` headers and unreferenced `<bundle>.map` siblings.
- `http_records.target`, `root_uuid` and `chain_truncated` - the submitted target, the chain root in O(1), and whether the chain stopped short.
- Redirects stop at a login/SSO wall under every `--redirect-mode`; each phase reports the walls it hit with an example target.
- A schemeless probe target resolves its scheme by TCP connect (plus a TLS handshake on a non-standard port) before the sweep requests it.
- `kit js-beautify` gains `-o`, `--modules`, `--profile`, `--unpack-modules`, `--max-ast-nodes`, `--max-input-mb`, `--deadline`; `-j` adds status, diagnostics and per-endpoint provenance.

### Fixed

- **The source-map pipeline was dead code** - the prefix breaker dropped referenced `.map` URLs and link extraction won the request cache, so the only parsing branch was always deduped away.
- **Nothing called `discovery.SetLogger`**, so every discovery, jstangle, asset-graph and source-map log line went to a no-op logger.
- **A redirected record paired the original request with the final response** - the destination's body, technology and findings were filed under the target's own URL, and out-of-scope destinations were scanned under an in-scope name.
- A source map served as `application/octet-stream` (the static-host default for `.map`) failed the text-MIME test and was skipped by every secret-scan caller.
- **A large bundle returned zero endpoints**: the AST node budget ended the run before `bundleModuleScan`, the stage written for that case, could run (jstangle 0.2.0).
- The regex fallback replaced the whole engine result instead of merging into it, discarding a beautified document and artifacts that were real.
- `make update-ui` deleted the report template before a build that could not produce it, and the workbench build's `rm -rf dist/__next.*` killed the home page's segment-cache prefetch (root `/__next._tree.txt` 404).
- Recovered `.scss`/`.less` sources had no record to anchor to and were dropped; they now anchor to their origin's record.
- The fallback extractor stamped `GET` on every unresolved request, making a guess indistinguishable from a resolved verb to the replay gate.
- `response_time_ms` reported `0` for rows that were never timed (redirect hops, records rebuilt from stored bytes) instead of omitting the field.
- The probe summary's "attempted" count omitted targets the prefetch stage found closed on every port.

### Changed

- `pkg/spitolas/loginsig` moved to `pkg/authsig` - the transport, runner phases and three modules now share the crawler's login signatures.
- `IsRedirectStatus` has one definition in `pkg/httpmsg`; four packages carried four spellings of it.
- Recorded chains collapse canonical hops (scheme upgrade, trailing slash, `www.`, default port) into their destination row and cap at 4 rows, ends kept.
- `--record-redirect-chain` no longer gates the request/response re-pairing, only the hop rows.
- jstangle `maxBundleModules` default is 512 (was 64), modules are ordered by endpoint likelihood before the cap, and each sub-scan gets its own node budget.
- New `max_unpack_input_mb` (16 MiB) bounds the source-level unpack pass independently of the AST ceiling.
- `nextjs_chunk_audit` fetches through the shared `modkit.FetchAssetBytes`, so the catch-all/echo-server guards live in one place.
- npm publish verification polls every 30s: 30m for `version`, 10m for `dist-tag`.
- `make update-ui` runs `bun install` and refuses to replace `public/ui/` when the workbench build produced no `index.html`.
- Workbench deps bumped (next 16.3.5, react 19.3, vitest 5, ag-grid 36.2); `jsdom` and `@vitest/ui` dropped.

## [v0.4.8] - 2026-09-18

A **target-and-banner correctness** release: schemeless targets reach every phase, the banner prints the budget the phase will actually use, and composed flags stop failing a run over nothing.

### Fixed

- **A schemeless target silently skipped spidering** — `-t example.com` or a bare-hostname `-T` file scanned fine under probe/discovery but net/url rejected the crawl seed, so `--only spidering --soft-fail` exited 0 with 0 records; every entry point now normalizes to an explicit scheme.
- The banner advertised the `scanning_pace` slice instead of the real budget: `--spider-max-time 5m` printed `6m0s` while the phase crawled for 5m; `--discover-max-time` had the same gap.
- `--db-isolate` alongside `-S/--stateless` aborted the run; it is now ignored with a warning, since `-S` keeps no database to merge from.
- npm publish verification timed out at 300s on ~133 MB platform tarballs that landed minutes later, so a release needed several `make npm-publish` re-runs.

### Changed

- **Relicensed under MIT** — `LICENSE`, `THIRD_PARTY_NOTICES.md`, the npm package metadata and the server's license header all updated.
- Phase-budget rendering moved to one shared `runner.PhaseLabel`/`SpideringBudget` pair, so the pre-scan banner and the phase itself can no longer disagree.
- `npm-verify-publish.sh version` polls for 15 minutes (90 x 10s); `dist-tag` keeps the short 300s budget.
- The `gau` shim reuses the shared scheme helper (still defaulting to https, unlike scan targets' http).
- Skills and flag docs updated for the new `-S` / `--db-isolate` precedence, plus the previously undocumented `autopilot -S`, `-o` and `--prompt-file`.

## [v0.4.7] - 2026-09-18

A **read-surface correctness** release: search filters that mean what they say, a source pin that refuses a typo, and single-message extraction.

### Added

- `vigolium traffic body` and `traffic headers` — extract one side of one stored exchange to stdout or a file, with no re-send.
- `-o/--output` on `traffic -j`, `finding -j` and `db ls -j` — writes the result document to a file and prints a receipt instead.
- `--url` on `traffic` and `db ls` — exact URL selection, repeatable and OR-ed, applied before pagination.
- `db stats` now reports the source path and on-disk size (`path`/`size` were declared and never filled).

### Fixed

- **LIKE metacharacters in a search term were interpreted, not matched** — `--body '%'` returned every record and `api_key` also matched `api-key`; every substring filter now escapes the term and carries an `ESCAPE` clause.
- **`--header` and `--body` searched the whole message**, so `--header password` matched response bodies; each now scans only its own region, in SQL, so `total` and pagination agree with the rows.
- **A read command pointed at a missing `--db`/`$VIGOLIUM_DB_PATH` created the database** and reported `total: 0`, exit 0 — now `source_missing`, and a foreign SQLite file is `source_incompatible` instead of gaining vigolium's tables.
- `--read-only` left `-wal`/`-shm` sidecars beside the file it promised not to touch, and still ran `PRAGMA optimize` on close.
- The flag suggester answered `--url` with "did you mean `--all`?" — short names now need to be within one edit, and a name with no near-miss points at the command's help.
- An openai-compatible `base_url` written as a bare host POSTed to the root and 404'd; `/v1` is now resolved, the other spelling is tried once, and the winner is latched per process.
- `vigolium ol` printed two banners, and scripting `config set` printed one per key.
- The `-j` error envelope was written into the `-o` file the caller expected results in.
- `finding --path` was interpolated into SQL with hand-doubled quotes instead of bound as a parameter.
- `atomicfile.Write` renamed without an `fsync`, so "atomic" covered the rename but not the bytes.

### Changed

- **Default concurrency is 25**, from one shared `types.DefaultConcurrency` — the CLI, pace config, REST API and discovery source had drifted to 50/40/50/50, so the same scan ran at different speeds depending on which one started it.
- `--search` stays the whole-exchange search and is now documented as the flag to use when the location does not matter.
- A capped body's `decoder_hint` names `traffic body -o <file>` instead of the whole-tree `db export --format fs`.
- `humanBytes` moved to `terminal.HumanBytes`, shared by the storage listing and `db stats`.

## [v0.4.6] - 2026-09-13

A **CLI ergonomics** release, built to be driven from another agent - best used in other coding agents. A new `vigolium run probe` host sweep, redirects that are actually followed, `-T/--target-file` seeding the scan at last, and a deterministic attack-surface score on every record. Registry moves to 207 active + 117 passive.

### Added

- **`vigolium run probe`** — a host sweep: one request per target, passive fingerprinting only, no content discovery and no fuzzing, so `-T hosts.txt -c 20` reaches thousands of hosts instead of spending the budget on the first handful the way `run discover` does. Aliases: `probing`, `httpx`, `alive`, `sweep`.
- Probe rows are labelled `probe` (`traffic --source probe`), so a sweep is separable from a real scan in the same project.
- `--tls-probe` completes a TLS handshake per HTTPS endpoint and reports the negotiated version/cipher plus the leaf certificate — subject/CN, SANs, issuer, validity window, serial, MD5/SHA-1/SHA-256 fingerprints — under an httpx-shaped `tls` key. Validation is deliberately off: an expired or self-signed certificate *is* the result.
- The probe phase resolves the whole target list's DNS before the first request, so `a`/`aaaa`/`cname` are reported inline in `-j`/JSONL output and the agent view. Only `ip` is stored — the rest is cheap to re-resolve and TTL-stale the moment it is written.
- `--redirect-mode off|same-host|same-apex|any` (default `any`) replaces the `FollowRedirects`/`FollowHostRedirects` bool pair, which had no spelling for what a host sweep needs. `same-apex` follows `www.example.com → example.com` but not `example.com → tracker.example.net`, and fails closed to exact-host equality when either side has no registrable domain.
- `--record-redirect-chain` stores each followed hop as its own `http_records` row, chained through the existing `parent_uuid` column (no schema change). On by default under `run probe`.
- **`http_records.response_location`** stores a 3xx's `Location` header verbatim. `traffic --tree` reads the destination off the row (`↪ https://…`) instead of hydrating an 8 KiB response prefix — or, under `--glob-db`, reopening every source file the redirects came from. Older records fall back to parsing their stored bytes.
- `--no-response` as an alias for `--omit-response`, which on a sweep is the bulk of every row.
- **`http_records.surface_score`**: a deterministic attack-surface score - the percentage of a 17-signal set present - written by the new `surface-scoring` passive module. Absolute and reproducible, unlike `risk_score`'s per-batch rank. Every signal is readable from a single unauthenticated GET, which is what a host sweep has to rank on: an advertised authentication boundary, a non-standard port, a dynamic origin, permissive CORS, leaked internals (source maps, directory listings, dev-server banners, debug headers), API surface, and input surface the response advertises.
- **`http_records.technology` is now written by a scan.** The `*_fingerprint` passive modules publish per host into the tech registry, and `surface-scoring`'s flush - the one point that knows both which records belong to a host and what all 26 fingerprint modules concluded - writes that stack onto every record of the host. Previously only a test seeder ever populated it.
- `db ls --min-surface`, `surface_score` as a `db ls --sort` key and a `SURFACE` column in its listing, `min_surface`/`min_surface_score` on the records APIs, and the field in `-j` output, the CSV export and the agent's `inspect_record`.
- `--export-only` on `scan`/`run` limits the `--format jsonl` envelope to chosen record types, reusing the `export --only` vocabulary. The scope is passed explicitly to the shared export stream, so narrowing the jsonl envelope cannot reach the html, report, pdf, sarif, bundle or console exports behind the same gate.
- `spa` joins the known tech tags, so a module can gate on "this host client-side-routes".
- `traffic --group-by <field>` counts matched records by `host`/`method`/`status_code`/`response_content_type`/`source`/`scan_uuid`/`ip`/`is_authenticated`, bounded by `--group-limit` with the tail reported as `other_groups`/`other_records`.
- `error.code: "source_incompatible"` for a valid SQLite file that is not a vigolium store, instead of the generic `failed`.

### Fixed

- **Redirects were never actually followed.** `doRequest` walked the response chain back to its *oldest* hop, so every caller of `Execute` received the first 3xx instead of the page behind it — a target that redirects to its real application was recorded as a bodyless 3xx and no module ever saw the application. The transport had been following the redirect the whole time.
- **`response_time_ms` was always 0** — the requester truncated the duration to whole seconds, every caller discarded it, and the response model had nowhere to put it, so `db stats`' p50/p95/p99 were computed over a column of zeros. A measured duration is now floored at 1ms, leaving 0 to mean unambiguously "not measured".
- **Browsing a `--glob-db` source file modified it.** A read-write SQLite open is itself a write: the DSN sets `journal_mode=WAL` (changing an archive's hash), the open checkpoints main and sidecar, a background checkpointer truncates the WAL every five minutes, and `Close` writes `sqlite_stat1`. Sources are now opened and attached `mode=ro`.
- **The SQLite driver parses every `ATTACH` filename as a URI**, not only ones beginning with `file:`, so a `--glob-db` path containing `?` attached a different, empty database and the merge reported success having copied nothing. Sources are now attached through a percent-encoded read-only URI; a path containing `?`, which no spelling can address, is an explicit error.
- **Full-text search availability depended on how the database was opened.** `HasFTS` was set only by `SeedDefaults`, so `vigolium server` took the indexed path and every read command took the LIKE fallback on the same file — and the two did not return the same rows, FTS5 `MATCH` being token/prefix based where `LIKE` is substring. The capability is now discovered from the database, and the indexed path keeps the metadata `LIKE` predicates alongside `MATCH`.
- **Migrating the legacy body-indexed FTS table left every existing record unsearchable.** The external-content replacement is created empty and filled by triggers, so only records written *after* the upgrade were indexed and search reported no error. The migration now rebuilds the index once, and restores the `AFTER UPDATE` trigger dropped years ago.
- A `--fuzzy` term containing FTS5 expression syntax (`"`, `AND`, `NEAR`, `:`, `-`) was passed to `MATCH` unescaped, so it could mean something other than the term — or fail the whole listing with a syntax error.
- **Deleting one of several records a finding cites deleted the finding**, leaving the junction rows for the survivors dangling. A finding is now removed only once nothing it links to survives, and findings with no HTTP record at all (audit and source-scan) are left alone.
- **`surface-scoring` silently stopped scoring past 1000 distinct hosts.** The buffer was bounded on host count, the wrong dimension for a sweep that buffers one record per host: a 1041-host list left the rest at 0, indistinguishable from "no surface". The bound is now on total buffered entries (200k, roughly 20 MB).
- Two scoring signals were near-constant or dead on exactly the corpus that needs ranking: `SignalAuthBearing` counted any `Set-Cookie` as identity (a CDN's `__cf_bm`, `_ga`, `AWSALB`) and now requires an `Authorization` header or a recognised session cookie; the input signal read only the request, so a bare-GET sweep could never fire it, and response-advertised input surface now earns its own signal.
- `AppendRemarks` read a record's current remarks outside the transaction that wrote them back merged, so two concurrent analysis passes each overwrote the other's addition. The read now happens inside the write transaction, with row locking on PostgreSQL.
- `clicommon.GetDB` leaked the connection pool (and, on a writable handle, a checkpointer goroutine) when it rejected an outdated schema.
- Read commands (`traffic`, `finding`, `db ls`, `export`) migrate the schema on open instead of failing an old database's first read with a bare `no such column: r.surface_score`. A read-only handle cannot migrate, so it names the missing columns and how to proceed.
- `-T/--target-file` now seeds `Options.Targets`, so `run spidering -T hosts.txt` crawls instead of finishing in 0s with a false "Targets: N" banner. Piped URL lists (including explicit `-I urls`) promote the same way, and `TargetSource` skips an unparseable line instead of aborting the scan on the first junk URL in a recon export.
- `verbose_error_stacktrace` never matched a real Java, Node.js or .NET stack trace — every repeated-frame pattern required unindented frames, and all three runtimes indent theirs.
- `db export --uuid --format fs` narrowed only the traffic half of the tree, writing the one selected `.req` beside every finding in the store; the identity selector now narrows both.

### Changed

- A probe-only run gets its own defaults — redirect hops recorded, `--redirect-mode same-apex`, the `sweep` transport profile, and **proactive WAF-edge pacing off** (a sweep sends one request per host, so there is no burst to pre-empt, while the pre-arm would switch adaptive feedback on for the whole run and print a pacing notice per host). Reactive back-off after an actual block is untouched. Its JSONL envelope also narrows to `http_record` objects, since every finding a sweep produces is a "Technology Detected" one now carried by the record's own `technology` field; `--export-only http,findings` restores them.
- `surface_score` is a percentage of the signal set rather than ten points per signal across ten: no whole number of points divides 100 at the new signal count, and a clamped 10-point scheme would flatten the top band that ranking exists to separate. The count is derived from the signal block, so adding a signal cannot leave the scale behind. **Scores from earlier scans are not comparable to new ones.**
- **A `--glob-db` merge no longer copies findings for a read that shows none.** `traffic` renders and filters by no finding, yet every source's findings, junction rows and OAST interactions were read into memory in full — inline request, response and evidence included — because those three tables need id remapping and so cannot be copied set-based.
- **Record→source attribution is resolved for the page being printed, not the whole merged corpus.** The merge used to hold every inserted uuid in a `map[string]string` for the life of the command — hundreds of megabytes to answer a question about the few hundred rows that survive the `WHERE`. It now uses the per-file rowid ranges the merge already records.
- The `--glob-db` scratch store defers the thirteen `http_records` read indexes until after the merge, so a bulk load maintains only the primary key, then builds them once over the finished table and refreshes planner statistics.
- `traffic --tree`'s redirect lookup batched 400 uuids per query against SQLite's pre-3.32 999-parameter limit. Neither applies — bun renders list values as SQL literals — so the batch is 20x larger, and the unbounded `IN ()` lists in the record and finding delete/lookup paths are chunked for the same reason.
- Stack-trace signatures move to `pkg/modules/infra/stacktrace` so `verbose_error_stacktrace` and `surface_scoring` read one table instead of two copies.
- The `-j` envelope no longer duplicates its rows into the legacy `records`/`findings`/`scans`/`rows`/`stats` key, roughly halving every payload; `--json-legacy-keys` (or `VIGOLIUM_JSON_LEGACY_KEYS=1`) restores the alias for callers still migrating.
- `finding --id` rejects a UUID with the flag that reads that namespace (`traffic --uuid`, `--agentic-scan`/`--scan-uuid`) instead of a bare `strconv` error.

New columns are added by the existing self-healing DDL path, so an existing database gains them on the next open with its rows untouched. `currentSchemaVersion` is deliberately **not** bumped — that would re-run the O(rows) backfills on every database in the field for columns that need no backfill.

## [v0.4.5] - 2026-09-04

A **machine-interface** release: vigolium is now readable by a program while it runs, its safety dials do what their names say, and the shapes a driver parses stopped drifting per command. Sourced from a downstream driver's workaround list — every item below replaces code someone wrote to recover a fact vigolium already knew. No module changes (registry stays at 207 active + 116 passive).

### Added

- `--events ndjson` on `scan`/`run`/`scan-url`/`scan-request`: a live event stream on stdout (`scan.started`, `phase.started|progress|finished`, `waf.block`, `waf.pacing`, `finding.new`, `error`, `scan.finished`) while the human console keeps stderr unchanged.
- The three pace dials take a repeatable phase qualifier — `--rate-limit known-issue-scan=20` caps nuclei without capping the native modules that pace themselves.
- Tool shims: `vigolium ffuf|nuclei|katana|gau|arjun` take each tool's own argv, print the translation, and run the native phase into the pinned database.
- Batch ingest: `-i` is repeatable and `--dir`/`--dir-glob` walk a directory, so N specs cost one process instead of N.
- `vigolium version --json` reports `schema_version` and `db_schema_version`, so a consumer fails on contract drift at startup instead of at parse time.
- `import -B` accepts the filter set `traffic -B` already had (`--host`, `--path`, `--method`, `--status`, `--search`, `--from`/`--to`, `-n`), plus `--all-hosts` and `--yes`.

### Fixed

- **`import -B` no longer copies the operator's entire proxy history** — every host they have browsed, with those hosts' cookies and tokens — into the destination database; an unfiltered pull is refused unless `--all-hosts` is passed, after a pre-flight count.
- `traffic -B --save-to-vigolium-db` silently truncated an import at 100 records, because `-n`'s listing default also bounded the write.
- `--rate-limit` was applied only when explicitly typed, so silence meant *unlimited* while the help text advertised 100; negative values now fail instead of reading as no cap.
- `--strategy lite` opened a crawl exactly as hard as `balanced` — same concurrency, same per-host ceiling — and now carries a real pace ceiling.
- `known-issue-scan` ran nuclei outside the shared requester with no back-off and no block notice, so a filtered edge returned a thin surface indistinguishable from a clean target.
- `vigolium log` rejected `-S` outright ("unknown shorthand flag"), and auto-followed forever on a `running` row left behind by a killed scan.
- WAF notices fire early in a scan, so the default 200-line log tail was the wrong end of the file to look for them.
- `$VIGOLIUM_DB_PATH` pointing at an unusable path silently fell through to the shared default database.
- Bumped `bytedance/sonic` v1.15.0 → v1.15.3 (and its loader), which was falling back to `encoding/json` with a warning on Go 1.27.

### Changed

- **Exit codes are a table:** `0` success, `1` error, `2` usage error, `3` `fuzz --fail-on-match`, `4` `--fail-on` gate tripped. `1` used to mean both "the scan crashed" and "the scan worked and found something".
- **One `-j` envelope for every command** — `{schema_version, command, project_uuid, db_path, total, offset, limit, items, query}`, with each command's old row key kept as a deprecated alias. `db stats -j` is no longer an exception.
- Machine-output timestamps carry exactly three fractional digits plus an epoch-millisecond sibling; microsecond precision broke lexical comparison against a millisecond clock.
- `-S` means `--stateless` everywhere and is accepted as a no-op where meaningless; on `server`/`ingest` it is a deprecated alias for `--scan-on-receive` that warns.
- `--fuzz-wordlist` is now `--discovery-wordlist` (old spelling kept as a deprecated alias) — it collided in name with `vigolium fuzz -w`, which is a different knob.
- `finding --push-to-burp` and `--to-repeater` compose instead of being mutually exclusive, matching `replay`.
- An over-long `--notes` is truncated with an ellipsis and warned about rather than failing the whole push.
- The first-run `nuclei-templates` clone announces itself instead of looking like a hung scan; `--templates-dir` pins it per run.
- Every `-j` envelope and `scan.started` names the database it opened, so a driver can assert the store rather than trust a pin.

## [v0.4.4] - 2026-08-30

A **large-result-set** release: reading a `--glob-db` glob of hundreds of scan databases (854 files / 16 GB / 290k records) no longer collapses into swap, plus the Go 1.27 toolchain bump. No module changes (registry stays at 207 active + 116 passive).

### Performance

- The `--glob-db` merge builds in a temp **file** instead of `:memory:`, so its working set pages against the OS cache instead of competing with the process heap (18.7 GB RSS, 149s of kernel paging, never finished).
- `finding` no longer copies every matched file's record corpus to hydrate the findings on screen (20.4 GB); `--raw/--burp/--markdown/--with-records/--push-to-burp/--to-repeater` fetch evidence afterwards by uuid.
- `traffic --save-to-burp --glob-db` streams file-by-file instead of merging, bounding peak memory by the largest single file (16 GB → 417 MB).
- A single-format `export` streams envelopes instead of materializing the whole set (6.1 GB); the summary tally is accumulated on the way past.
- Scratch databases stranded by a killed run are reaped (age-based) on the next open.

### Fixed

- `--glob-db` findings filters resolving through `finding_records` (`--host`, `--path`, `--method`, `--status`, `--source`) silently returned nothing — or everything, for the negated forms — when the merge omitted the record table.
- `make github-release` published no Windows artifact (the upload glob was `*.tar.gz`-only); the upload set is now cross-checked against `checksums.txt` and a gap is a hard error.
- OpenAPI 3.1 spells `exclusiveMinimum` as a number rather than a boolean modifier, so generated examples ignored it and the target rejected the body built to probe it.
- The fuzz anomaly detector's population snapshot handed out the live status/body-hash maps, racing a scoring goroutine against another worker's `observe`.
- A Burp Site map save split across batches could report the 10-error cap once per batch; the cap now applies to the running total.

### Changed

- Go 1.27 toolchain across `go.mod`, both Dockerfiles, the e2e images and the docs; the CI golangci-lint pin moves v2.9.0 → v2.13.2.
- `platform/` is excluded from linting — it holds external tooling and vendored node deps, including a stray Go package under `node_modules`.
- `traffic --glob-db --save-to-burp` prints per-file progress, and carries dedup, `--offset` and the `-n` budget across files instead of over one merged table.

## [v0.4.3] - 2026-08-19

A **Windows support** release: vigolium now ships a windows/amd64 build, and every path that quietly assumed POSIX (shell, browser discovery, installers, line endings) is platform-aware. No module changes (registry stays at 207 active + 116 passive).

### Added

- Windows (amd64) builds across goreleaser, `make public-release`, and the npm package, shipped as a `.zip`.
- The embedded `vigolium-audit` and `jstangle` helpers are built and staged for Windows.
- `procutil.ShellArgv` resolves the host shell: POSIX `bash`/`sh` elsewhere, an installed Git Bash/MSYS2 bash or PowerShell on Windows (WSL's `System32\bash.exe` is rejected).
- CI cross-compiles and vets the tree for windows/amd64, then smoke-tests that artifact on a Windows runner.
- `make sync-skills` mirrors `public/skills/` to the standalone skills repo; `make build-jstangle-target` stages one target triple.

### Fixed

- Chrome was never found on Windows: the candidate list was two bare PATH names, so every crawl silently downloaded Chrome for Testing instead.
- `chrome.exe --version` prints nothing on Windows (GUI subsystem), so validation rejected every real install; it now stats the file.
- `vigolium update` on Windows failed with a bare `bash: file not found` instead of naming the zip download path.
- `doctor --fix` ran `curl … | bash` for bun and claude on Windows; it now uses each vendor's PowerShell installer.
- `findBun` returned the extensionless candidate path, which fails to exec against `bun.exe`.
- Two processes extracting the embedded audit binary raced on a shared `.tmp` name; extraction is now per-process and adopts an identical binary a peer already installed.
- The audit blob platform guard read every PE image as "windows, unknown arch"; it now decodes the COFF machine field.
- `vigolium.readFile()` kept the `\r` of a CRLF file on every line, which extensions then injected verbatim.
- `build/npm/bin/vigolium.js` was swallowed by a `bin` ignore rule and never committed, so `make npm-build` failed on a fresh clone.

### Changed

- **Breaking:** the legacy `VIGOLIUM_PROJECT` env var is gone — use `VIGOLIUM_PROJECT_UUID` or the new `VIGOLIUM_PROJECT_NAME`; an explicit `--project-uuid`/`--project-name` still wins.
- windows/arm64 is not shipped (Bun has no `bun-windows-arm64` target); the npm x64 package claims `arm64` so ARM hosts install and emulate.
- The `vigolium-scanner` skill maps standalone recon tools (nuclei, ffuf, katana, gau, httpx) onto vigolium phases and `kit`, and documents scan-vs-scan-url choice, scan duration, the strategy matrix, and the Caido bridge.
- The duplicated skill tree under `platform/vigolium-audit/` was removed; `public/skills/` is the single source.

## [v0.4.2] - 2026-08-15

A **hardening and performance** release for the REST API server and the scan hot paths: bounded memory everywhere a caller could previously make the server allocate without limit, plus a cross-project record-scoping fix. No module changes (registry stays at 207 active + 116 passive).

### Fixed

- `POST /api/scan-records` validated record UUIDs unscoped — a leaked UUID could pull another project's traffic into a scan.
- A failed agentic-scan registration leaked its concurrency slot, shrinking the agent pool on every repeat.
- CORS preflight omitted `PATCH`, so a browser client could never mark a finding triaged.
- `completed_with_errors` wasn't a terminal status: its log stream ran to the 2-hour cap and its row survived every retention sweep.
- Storage downloads answered a missing object with a truncated stream instead of a JSON 404.
- Storage read endpoints were unreachable in view-only mode.
- The `Server:` header rendered as `Vigolium vv0.4.1`.
- A chunked body could grow the heap to the 512 MB framework ceiling on a 4 MB route; now capped at `limit+1` and drained before the 413.
- `--debug` logging drained streamed uploads into memory on the large-upload routes.
- Crawl-path repair rescanned every edge in the graph on each duplicate transition.

### Performance

- Nested insertion points share one base-request buffer: a 98 KB request with 2,000 nested children retains ~0.9 MiB, was ~188 MiB.
- The insertion-point cache is bounded by retained bytes (128 MiB) and per-entry size, not entry count alone.
- The Content-Length rewrite layout is computed once per request instead of once per insertion point.
- Scan and agent log endpoints return the last 2 MiB of `runtime.log` (`?max_bytes=` up to 64 MiB) instead of the whole file per poll.
- Storage downloads stream to the client instead of buffering the whole object in memory.
- Agent list endpoints read blob-free summaries; the SSE log follower polls the status column alone.
- YAML extension matcher regexes are compiled once and cached, failures included.
- DOM-XSS taint matching dropped its per-identifier regex compile (~50 µs → ~0.9 µs per statement, zero allocations).
- `POST /api/scan-records` caps `record_uuids` at 10,000 and checks scan admission before enumerating.

### Added

- `X-Author` response header, the companion to the `Server:` banner.

### Changed

- Workbench moved to an ESLint flat config (`eslint .` replaces `next lint`); TypeScript stays on 6.x and ESLint on 9.x, since either bump breaks the lint run outright.
- Workbench dependency bumps: Next 16.3, React 19.2.8, ag-grid 36.
- Workbench header account links use `next/link`; the dead `ScanDetailPanel` was removed.

## [v0.4.1] - 2026-08-12

A **standalone utilities** release: a new `vigolium kit` command exposes the scanner's internal primitives as one-shot tools for coding agents and shell pipelines. No module changes (registry stays at 207 active + 116 passive).

### Added

- **`vigolium kit`** — standalone security utilities that reuse the scanner's own engines, usable outside a full scan.
- `kit secret-scan` — scan files, dirs, or stdin for leaked credentials via the built-in secret catalog.
- `kit js-beautify` — unminify and unpack a JavaScript bundle (file/url/stdin) into readable source.
- `kit oast new`/`poll` — mint OOB/OAST callback URLs and drain their received interactions.
- `kit harvest` — collect known URLs for a domain from public archives and indexes.
- `kit jwt-crack` — recover a JWT's HMAC signing secret from a wordlist.
- `kit wordlist` — list the built-in wordlists or print one to stdout.
- `kit payload` — emit built-in payload sets by vulnerability class.

### Changed

- Extracted `jwtutil.CrackHMAC` from the `jwt_weak_secret` module so the passive scanner and `kit jwt-crack` share one crack loop.
- Extracted `harvester.BuildSources` so `kit harvest` and the `external-harvest` runner phase share one source set.

## [v0.4.0] - 2026-08-11

A **multi-tenancy fix** release: scans, ingestion, and the project subcommands now honor the active project end-to-end, so non-default projects stop silently losing their findings and records. No module changes (registry stays at 207 active + 116 passive).

### Fixed

- Findings and records from `scan`/`scan-url`/`scan-request`/`ingest`/`server` landed in the default project on any non-default project — `ExecutorConfig.ProjectUUID` was consumed but never set by any caller.
- Every executor caller now resolves and passes the active project (CLI scan/ingest paths, server URL/request/records handlers, and the discovery/harvest/dynamic-assessment runner phases).
- A failed project resolution on `scan-url`/`scan-request` is now fatal, not a warning — continuing would silently misfile the whole scan into the default project.
- `project create` (and `list`/`use`/`delete`) failed with "no such table: projects" on a fresh `--db` file — the subcommands never created the schema before touching it.
- `project` subcommands now bootstrap schema and seed defaults via `openProjectRepo`, so a brand-new database is usable without cloning a populated one.

### Added

- `TestExecutorConfigAlwaysSetsProjectUUID` and a project-scoping E2E test guard the wiring against regression.

## [v0.3.12] - 2026-08-10

A **SARIF output** release: emit SARIF 2.1.0 so runs feed GitHub code scanning, DefectDojo, and the VS Code SARIF Viewer. Also teaches the bridge to say which proxy it is, so Caido traffic stops showing up labelled `burp`. No module changes (registry stays at 207 active + 116 passive).

Upgrading with Caido: rebuild the [Caido plugin](https://github.com/vigolium/caido-vigolium) alongside this release. Vendor detection is wire-only with no fallback probe, so a listener predating it is read as Burp — silently. Rows imported from Caido before this release stay labelled `burp` and cannot be reclassified after the fact.

### Added

- **`sarif` output format** — writes a SARIF 2.1.0 log on `scan`/`scan-url`/`scan-request`/`run`, `vigolium export`, and `vigolium import --format`.
- File-anchored findings map to the source file (URL kept as a related location); DAST evidence rides in `webRequest`/`webResponse`.
- `security-severity`, zero-padded CWE tags, and `FindingHash` fingerprints so consumers bucket and track findings across re-scans.
- **`--caido-bridge-url`** alias for `--burp-bridge-url` (`-B`) — the Caido plugin ([vigolium/caido-vigolium](https://github.com/vigolium/caido-vigolium)) exposes the same bridge listener.
- **Bridge traffic is labelled by vendor** — listeners report an `implementation` identity on every `/health`, `/search` and `/inspect` reply, mapped through a closed allowlist to `http_records.source`, so the `traffic` Source column, `--source caido`, and persisted imports all name the proxy that actually served the traffic. Echoed per reply rather than probed from `/health`, because the read path never calls it and a single-record inspect has no preceding search to learn the vendor from.
- **`X-Vigolium-Source` on `POST /api/ingest-http`** — a client pushing traffic can declare itself (`burp`, `caido`) instead of landing under the generic `ingest-server` label every HTTP client shares. The Caido plugin sets it, so one `--source caido` covers traffic that arrived either by pull or by push. Allowlisted rather than passthrough: `source` decides which rows scan-on-receive feeds back into a scan, so a client able to claim `scanner` could silently exclude its own traffic from the scan it just asked for.
- `X-Vigolium-Bridge-Source` response header on `/api/http-records`, naming the vendor that answered.

### Changed

- `--format` extension/output-path machinery now recognizes `.sarif` on both scan and export sides.
- Exported `severity.ToSeverity` helper that maps a severity name to its comparable enum rank.
- `--source` on a bridge-enabled `traffic`/`replay` query admits any bridge vendor up front — which one is listening is not knowable until it replies — and drops the live set afterwards when the vendor does not match, zeroing its total alongside it so paging is not inflated by records it cannot show.
- Send-preflight warnings and the bridge import summary name the answering vendor instead of assuming Burp.
- Record UUIDs keep the `burp:` prefix for both vendors: it is a routing token meaning "this record lives behind the bridge, not in the database", not a provenance label. Vendor lives in `source`.

### Fixed

- Bridge-sourced rows were excluded from scan-on-receive — silently, since they land in the database and the poller simply never selected them. `burp` and `caido` now join `database.IngestRecordSources`.

## [v0.3.11] - 2026-08-09

An **external-harvest** release: `wayback`/`commoncrawl` now mine archived response bodies (not just their indexes), plus a new keyless `arquivo` source and urlscan paging fixes. No module changes (registry stays at 207 active + 116 passive).

### Added

- **`arquivo` source** — keyless web-archive index, added to the default source set.
- **`wayback` body mining** — replays captures via `/web/<ts>id_/` and walks each host's robots.txt history to recover paths no index holds.
- **`commoncrawl` body mining** — range-fetches each index row's WARC record (one small gzip member) and extracts in-scope URLs from the body.
- **`urlscan` `task.url`** — also collects the originally-submitted URL, not only the final loaded one.

### Changed

- Mined URLs are scope-checked, junk-extension filtered, and stripped of archive hostnames; index rows are still emitted verbatim (provenance via `Result.Mined`).
- Mining is gated on the index carrying timestamps and capped by fixed per-domain budgets, not flags.
- Config validation's valid-source list and key-required checks now derive from one table, so they can't drift.

### Fixed

- **urlscan `search_after` cursor** — `sort` is kept as raw JSON so a millisecond timestamp isn't reformatted into a 400 (or a panic on a string value).
- **urlscan page size lowered to 1000** — an over-large size is rejected outright rather than clamped.
- **JS regex-literal false positives in the relative-URL extractor** — `(` is no longer treated as a URL delimiter and shapes like `/x/gi` are rejected.

## [v0.3.10] - 2026-08-08

A **WSDL / SOAP input-format** release: scan a SOAP service the way you scan an OpenAPI spec. No module changes (registry stays at 207 active + 116 passive).

### Added

- **`-I wsdl` (aliases `soap`/`svc`)** — parses a WSDL 1.1 / SOAP description into one SOAP POST per bound operation.
- **SOAP 1.1 and 1.2 envelopes** — `SOAPAction` + `text/xml` for 1.1, `action=` in `application/soap+xml` for 1.2; document/literal and rpc styles.
- **XSD-synthesized request bodies** — fuzzable by the active modules through the existing XML insertion points.
- **Content-sniff auto-detection** — a `.wsdl` file is recognized without an explicit `-I`.
- **`.svc`/`.asmx` URL support** — a live endpoint auto-fetches its WSDL (`?singleWsdl` / `?WSDL`).
- **`-t` host-override + spec flags** — `-t` overrides only the endpoint host (WSDL path preserved); `--spec-header`/`--spec-var` apply to WSDL.
- **Response-time auto-ingest** — a WSDL discovered mid-crawl is expanded into scan traffic, like a discovered OpenAPI spec.

### Fixed

- **`-t` combined with `-i` silently dropped the spec endpoint/base-URL override** — the MultiSource is now unwrapped; also fixes the same gap for OpenAPI.

### Docs

- Documented WSDL/SOAP scanning across the API guide, getting-started pages, and the `vigolium-scanner` skill.

## [v0.3.9] - 2026-08-07

An **output and agent-ergonomics** release: multi-format exports, throwaway autopilot runs, and a profile-overlay fix that had been silently disabling discovery.

### Added

- **`export --format` takes a comma-separated list** (`html,markdown,bundle`) — the database is read once, `-o` becomes a shared base path, and a failing format no longer discards its siblings.
- **`agent autopilot -S/--stateless`** runs the whole autopilot into a throwaway database and materializes `--format` outputs from it, mirroring `vigolium scan -S`.
- **`--prompt-file`** on `agent autopilot`/`swarm` — task guidance from a file, same channel as `--prompt`, so a long prompt needn't be shell-escaped.
- **`VIGOLIUM_DB_PATH`** — env-var default for `--db` that pins a shell to one session database; reads additionally treat it as a stateless source, writes do not.
- **Agent setup-guide pointer** — surfaced in `agent`/`olium` help, under `--list-agents`, and on any agent command failure, including credential errors raised inside the olium TUI.

### Changed

- **`scan -S` and `agent autopilot -S` share one `--format` list**, so a format accepted by either is accepted by both.
- **The `vigolium-scanner` skill splits its server/ingest reference** into `server.md` and `ingest.md`, with an expanded data/query reference.

### Fixed

- **A scanning profile zeroed every config key it did not set** — `--intensity quick|balanced|deep` wiped `discovery.jstangle.memory_budget_mb` and no-op'd the entire discovery phase; profile overlays are now key-preserving.
- **An invalid jstangle memory budget** is now a clear config error at scan start rather than a silently aborted discovery phase.

## [v0.3.8] - 2026-08-06

A **coverage** release: six new active modules (registry now 207 active + 116 passive), unified `--from`/`--to` date filtering across the read commands, and richer browser-crawl seeding.

### Added

- **`ssi-injection`** — Server-Side Includes injection detection.
- **`server-side-js-injection`** — server-side JavaScript (Node) injection detection.
- **`smtp-header-injection`** — SMTP header injection via email-bearing parameters.
- **`react-rsc-rce`** — React Server Components RCE probe.
- **`dependent-response`** — responses that change based on a spoofable request header.
- **`path-relative-stylesheet`** — path-relative stylesheet import (RPO) exposure.
- **`--from`/`--to`** (aliases `--since`/`--until`) time filtering on `finding`/`traffic`/`db ls`/`db export`/`replay`, plus `db clean --before` and swarm `--records-from`, sharing one parser (relative offsets like `2d`/`today` or absolute dates).
- **`burpscope` input mode** — parses a Burp Suite scope export and expands its include rules into seed URLs; content-sniffed so it works through `-T` and `-i` alike.
- **Frontier seeding from `robots.txt` and `sitemap.xml`** reaches crawl routes that nothing links to (default on).
- **Speculative link scraping** pulls same-origin URLs out of inline scripts and HTML comments a rendered SPA never serves in static HTML (default on).
- **Spidering knobs** — `max_depth`/`max_states` bounds (default 6/1500), `self_register`, and `graph_output_dir`.

### Changed

- **`code-exec`** now ships language-specific interpreter payloads across several string-breakout contexts, not just generic OS-shell payloads.
- **`ssti-blind`** confirms JVM template stacks with a pure-JVM DNS/URL callback, needing no shell on the target.
- **`cors-misconfiguration`** adds a single-mutation trusted-origin probe gated on a negative control, so a blanket reflector isn't re-reported.
- **`file-upload-scan`** confirms PHP web shells by an arithmetic execution marker that proves evaluation, not mere storage.
- **`graphql-scan`** walks endpoint names over parent-path prefixes and nested `api`/version permutations.
- **`ldap-injection`** adds a negation boolean oracle (match-all vs match-none divergence).
- **`open-redirect`** matches a wider set of leading separators to catch blocklist-bypass redirect targets.
- **`cache-deception`** adds delimiter-confusion variants alongside the static-extension append.
- **`web-cache-poisoning`** probes `X-Host`/`X-Forwarded-Server`/`X-Original-Host`/`X-Forwarded-Prefix` as cached-authority vectors.
- **`secret-detect`/`env-secret-exposure`** treat Pusher/Salesforce client-side keys as public identifiers and keep Stripe restricted live keys graded as secrets.
- **Input-mode help** clarifies `-i/--input` vs `-T/--target-file` so a spec isn't mistaken for a target list.

## [v0.3.7] - 2026-08-04

A **scan throughput** release. Dynamic assessment is ~99.7% idle wait, so a static concurrency cap sets the phase wall clock outright — four changes attack that. Also ships the `vigolium fuzz` curl-parity + anomaly-scoring overhaul and bulk/browser replay. Registry stays at 201 active + 116 passive.

### Added

- **`fuzz` curl parity** — accepts curl's long-form flags, with body assembly shared with the curl parser so `--data-urlencode`/`--form` behave identically as a flag or inside a pasted command.
- **`fuzz -a/--anomaly`** scores each response against the baseline *and* the run's own population, so a status change every payload triggers reads as normal behaviour rather than a signal.
- **`fuzz` attack modes** — `sniper`/`batteringram`/`pitchfork`/`clusterbomb` over numbered `FUZZ` markers, plus a comparison-predicate matcher grammar (`N-M`, `>N`, `!N`).
- **`replay` bulk pattern search** reuses `traffic`'s own filters verbatim, and `--with-browser` emits a `browser` object instead of a hollow diff a navigation can't produce.
- **Adaptive per-host concurrency ramps above `MaxPerHost`** (2× headroom) so a scan can discover a host tolerates more; WAF auto-arm stays pinned, since a block is not licence to raise concurrency.

### Fixed

- **`curl -e https://referer/ https://target/` silently retargeted the request at the referer** — the parser is now table-driven and strict, and an unknown flag is a hard error rather than a skip.
- **A per-module timeout never stopped the module** — 725+ abandoned modules kept hammering the target for discarded findings; `WithAbandonSignal` now refuses to start new requests.
- **`ReuseRatio` read healthy during heavy churn** — a 17.6× undercount from httptrace misattribution, now derived from dials counted in the transport's own dialers.
- **Discovery pre-warm ran 10 sequential waves before any fuzzing** — 66% of a host's discovery time at ~0.01 CPU cores; now sized to configured concurrency, capped at 16.
- **`input-behavior-probe` re-learned one number per insertion point** — 40 round trips where 2 suffice; now memoized per endpoint, with identical detection behaviour.

### Changed

- **The four costliest probes are tagged `heavy`, not `moderate`** — affects `--intensity quick` only; the default scan still runs all 201 active modules, and every deferred module is logged.

### Internal

- **`modkit.ScanContext.EndpointMeasurement`** replaces the fifth hand-rolled per-endpoint memo; per-scan lifetime drops the copied TTL and stops calibration leaking across server-mode runs.
- **The abandon signal is an `atomic.Bool`**, not a per-dispatch context child that took the phase context's lock twice to carry one bit.
- **The transport reads `HostRateLimiter.CeilingPerHost()`** instead of the runner re-deriving it, removing two hand-synced writers and fixing four sites that never published at all.
- **Observability** — module metrics Debug → Info, the SQL hook now needs `VIGOLIUM_SQL_TRACE=1`, and `make build-prof` emits an unstripped binary with real profiler frames.
- **Skills restructure** — `agent-browser` dropped, `vigolium-scanner` references renamed to shorter stems, and `flags-reference.md` replaced by a generated `flags.generated.md`.

## [v0.3.6] - 2026-08-03

A **false-positive and severity-calibration** release. Three families of live High
findings are retired: `bfla-detection` on endpoints that were never privileged,
`secret-detect` on values the vendor's own flow requires the browser to carry, and
the LFI pair on files a deployment publishes into its own web root. Severities move
to match what the oracles actually prove. Registry stays at 201 active + 116 passive.

### Fixed

- **`bfla-detection` reported four classes of non-privileged endpoint as High authorization bypasses.** Admin-path matching was an unbounded substring test, so Tableau's static `/vizportalclient/internalServerError.var` read as the `/internal` admin tree — patterns are now anchored at a word boundary (`/admin` still matches `/administration`). Health/liveness probes (`/actuator/health`, `/internal/ping`, `/healthz`) are skipped outright: they answer every method with one fixed body by design. Responses published as long-lived, publicly cacheable artifacts (`max-age ≥ 1h` + validator, no session cookie) are skipped — one representation for every caller can't evidence a per-caller authorization decision. And when the original request carried **no** credentials, a method switch returning byte-identical content is dropped: the route just ignores the method.
- **`secret-detect` graded ~50 public-by-design identifier families as leaked credentials.** Values the vendor ships to the browser — OAuth client ids, Stripe/Supabase publishable keys, Mapbox public access tokens, widget app ids, site keys — now report Info/Tentative, recognised by rule name (`IsPublicIdentifierRule`), with a guard so a paired-secret rule name (`secret`/`private`/`password`) keeps full severity. Salesforce Connected App consumer keys (`3MVG9…`) get the same treatment by value shape, alongside the existing Google client ID carve-out.
- **`secret-detect` matched links, resource ids, and non-tokens as secrets.** A hyphenated word slug sitting in the *path* of an absolute URL is now dropped — the NYT proximity rule fired on an ordinary press-mention `href`, capturing the article slug as a 32-char API key. A `<random>.<camelCaseWord>` value is recognised as a namespaced resource id rather than a two-part `id.secret` credential (covers all ~90 dot-composite rules). A Discord bot token whose leading segment doesn't base64-decode to a snowflake id is rejected as not a token at all.
- **Netlify's bot-challenge interstitial read as a leaked High-severity JWT on every challenged host.** The proof-of-work challenge token (`pow` + `ch`/`dif` claims) is now recognised as a pre-auth token, and an identity claim whose value is a bare IP literal — the edge binding the token to the visitor's own address — no longer counts as an authenticated subject. The interstitial itself is added to the shared challenge-page markers so block detection sees it.
- **The LFI pair reported published files as file-read vulnerabilities.** When a payload naming a docroot-publishable target (`.env`, `.git/HEAD`, `.htaccess`, `.htpasswd`, `WEB-INF/web.xml`, `web.config`) is injected into a **URL path segment**, the traversal prefix normalizes away and the request is an ordinary GET — a fetch, not an inclusion. `lfi-generic` and `lfi-path-traversal` now report these informationally, anchored at the file's own URL. OS-filesystem targets (`/etc/passwd`, `win.ini`, `/proc/self/environ`) are unaffected: no web root serves them, so a 200 carrying their content is a genuine escape.

### Changed

- **`tls-protocol-cipher-audit` is now Low across the board** (was Medium). Every weak-setting probe — TLS 1.0, TLS 1.1, RC4, 3DES, static-RSA — reports Low, so the aggregate host finding caps at Low. A legacy protocol or cipher still being *offered* is a hardening/compliance gap, not a directly exploitable flaw: attacking it needs a privileged network position plus a client willing to negotiate down. This lines the module up with the rest of the TLS/transport family (`hsts-preload-audit`, `mixed-content-detect` — Low; `tls-cert-recon` — Info).
- **`lfi-generic` is High, not Critical.** The oracle proves a file was read, not that the read reaches code execution — that depends on a sink the module never establishes. Critical also left no headroom above the weaker docroot-relative results. Sibling `lfi-path-traversal` already reported High.

### Internal

- **`infra.CacheMaxAge`** is the one `Cache-Control: max-age` parser, anchored so it can't match the tail of `s-maxage`. `bfla-detection` reads it to recognise a shipped static artifact, `web-cache-poisoning` to decide cacheability — the latter's hand-rolled loop is gone.
- **`modkit` docroot-fetch helpers** (`IsURLPathInsertionPoint`, `DocrootPublishableTarget`, `DocrootFetchNotInclusion`, `DocrootFetchInfo`) are the shared primitive for any file-read module that can be pointed at a URL path segment. The target allowlist is positive, so an unrecognised payload keeps the module's own severity.
- **`modtest.InsertionPointByType`** selects the positional URL path points that `InsertionPoint` can't address readably — path folders and filenames are named by ordinal, so name-based selection breaks whenever a test URL's depth changes.

## [v0.3.5] - 2026-07-28

A **false-positive hardening** release. Hosts behind a load balancer that
round-robins between mismatched backends answer the *same* request with two
different pages, which breaks every body-differential oracle in the scanner; a new
shared gate proves an endpoint is a function of the request before any diff-based
finding is reported. Also ships the **`replay` refocus**: bulk-selection filters now
track `vigolium traffic`, and payload fuzzing is consolidated into `vigolium fuzz`.
Registry stays at 201 active + 116 passive.

### Fixed

- **False positives on round-robin backend pools, across 10 modules.** Parked hosts serving one of two Apache default pages at random produced High findings with no application behind them — blind SQLi, path normalization, IDOR, header-trust size shifts, and several diff-based Info leads. New `modkit.EndpointVolatile` re-samples the unmodified request and drops the finding when the endpoint isn't deterministic.
- **`dashboard-exposure` reported any JSON `/version` endpoint as vLLM at High.** The signature matched on the mere presence of `"version"` — a near-universal health-endpoint convention — and flagged unrelated services. It now requires vLLM's exact response shape and confirms via the vLLM-specific `/v1/models`.
- **`wp-misconfig` awarded Critical for the word "installation".** The installer probe accepted that bare token, so an Apache default page mentioning an installation read as an exposed WordPress installer. Replaced with installer-specific markers.

### Added

- **`vigolium replay` bulk mode gains full `traffic`-style pattern search.** A positional `vigolium replay <term>` now does a broad fuzzy match (URL/path/host/method/content-type/source + raw request/response), mirroring `vigolium traffic <term>`, and switches replay into "iterate the matching stored records" mode. New selectors bring the surface to parity with `traffic`: repeatable AND-combined `--search`, `--exclude-search`/`--exclude-body` negative filters, `--from`/`--to` date range, and `--sort`/`--asc`/`--offset` ordering + pagination (on top of the existing `--host`/`--method`/`--status`/`--path`/`--source`/`--body`/`--all`). Each matched record is re-sent verbatim through the diff engine and streams as JSONL; combine with `--proxy`, `--save-to-burp`, or `-S --db <export>` as before.

### Removed

- **`vigolium replay --mutate`/`-m` removed.** Payload / insertion-point fuzzing now lives entirely in `vigolium fuzz` (wordlists, `--class`, matchers, auto-calibration) — `replay` is for re-sending and confirming. Send exact bytes verbatim with `--raw-request`/`--raw-request-file`. The `pkg/replay` library (exported `ParseMutationFlag`, `Options.Mutations`) and the agent's in-process `replay_request` tool are unchanged and still apply mutations.

### Internal

- **`modkit.EndpointVolatile` is the shared determinism primitive** any future differential oracle should gate on. It is memoized per record and runs only when a module is about to report, so wiring it into ten modules costs about the same as one.
- **`modtest.RoundRobinHandler`** gives module tests a one-line mismatched-backend pool, replacing five per-package copies of the same fixture.

## [v0.3.4] - 2026-07-20

A **Burp bridge send** release: `replay`, `fuzz`, and `finding` can now push requests through the Vigolium Burp extension's loopback listener — sending exact bytes on the wire via **Burp's own HTTP engine** (malformed/smuggling requests preserved, HTTP/1 vs HTTP/2 selectable) and staging traffic into Burp's Repeater and Organizer for manual work. Without the new flags, every command's send path is byte-for-byte unchanged. No module changes (registry stays at 201 active + 116 passive).

### Added

- **`replay --send-via-burp`** routes the (mutated) request through Burp's HTTP stack instead of Go's client, so deliberate `Content-Length`, request smuggling, and unusual methods reach the wire unnormalised — pair with `--http-mode http1` for classic desync. `--to-repeater` (stage a Repeater tab) and `--to-organizer --notes/--highlight` (store the request+response pair) hand the exchange off for manual testing.
- **`fuzz --send-via-burp`** sends every payload variant through Burp byte-for-byte (with `--http-mode` control); `--matches-to-organizer` pushes each matched anomaly into Burp's Organizer (Burp re-issues it) for triage.
- **`finding --push-to-burp`** hands a finding's evidence request+response to Burp's Organizer (severity-coloured, one item per finding) for manual confirmation; `--to-repeater` opens it in a Repeater tab and `--send-via-burp` re-issues it through Burp's engine to capture a fresh response.
- New `pkg/burpbridge` client methods (`Send`, `SendToRepeater`, `SendToOrganizer`, `Health`) wrap the extension's new `/api/burp-bridge/{send,repeater,organizer}` endpoints. All send flags require `--burp-bridge-url` (loopback-only) and preflight the listener, so an unavailable bridge is a clear up-front error rather than one failure per request. A scope-blocked target (Burp's "in-scope only" setting) surfaces as a clean error; a target-side failure is reported per-request without aborting a fuzzing loop.

### Internal

- A single pluggable `Sender` seam on `pkg/replay` (`replay.Options.Sender`) and `pkg/fuzz` (`fuzz.Job.Sender`) backs all three commands; when unset (the default) the native `net/http` send path is used exactly as before. `burpbridge.SummaryFromSend` adapts a Burp `/send` reply into the same `*replay.Summary` a native send produces, so diff/signal logic stays transport-agnostic.

## [v0.3.3] - 2026-07-17

A **read-path performance** release: `finding` and `traffic` no longer materialize HTTP request/response bodies they don't render, which turns large `--glob-db` reads from swap-thrashing multi-minute runs into seconds and trims memory across ordinary reads and the REST API too. No module changes (registry stays at 201 active + 116 passive).

### Performance

- **`finding --glob-db` skips the `http_records` table entirely.** Merging a glob of result files copied every request/response blob into an in-memory database before the first filter ran; findings carry their own evidence inline, so the record table is never needed. A 169-database `finding --severity high --tree` drops from ~5m20s / 10.8 GB RSS to ~1.2s / 379 MB, byte-identical output.
- **`traffic --glob-db` column-projects the raw bodies out of the merge.** Every record row still lands with its metadata (so counts and `--status`/`--host`/`--method` are unaffected), but the `raw_request`/`raw_response` columns — ~96% of the bytes — are dropped unless an output mode or filter needs them. A 169-database `traffic --status 200` drops from ~6m / 20 GB RSS to ~24s / 2 GB. `--search`, `--raw`, `--burp`, `--markdown`, `--json`, and `--columns REQ_HEADERS/RESP_HEADERS` keep the full bodies.
- **Ordinary single-database reads stop hydrating unused bodies.** The `traffic` table/tree views and agent context enrichment (autopilot/swarm) no longer fetch raw request/response blobs they never read; `traffic --tree -a` on a 453 MB database drops from ~1.1 GB to ~470 MB RSS.
- **REST API over-fetching removed.** `POST /api/scan-records` validates a caller-supplied UUID list with a projected existence check instead of loading whole records; the record/finding delete and finding status-update handlers read only the project scope rather than the full row; `GET /api/findings` collapses its page + count into a single round-trip.

### Fixed

- **`traffic`'s `includeRaw` control had no effect.** The shared traffic query path accepted a "does this view need bodies" flag but never applied it, so every read hydrated the blobs. It now drives a body-column projection, with `--json` and `--columns REQ_HEADERS/RESP_HEADERS` correctly counted as needing them.

## [v0.3.2] - 2026-07-14

A focused **REST API scan-path hardening** release: a server database-init correctness fix plus a batch of tests that drive both native and agentic scans end-to-end through the REST API. The fix closes a gap where a half-initialized results database (connection opens but schema creation fails — a locked, read-only, disk-full, or schema-incompatible file) left the server running with a live DB handle paired with a nil repository, which repo-backed handlers dereferenced into nil-pointer panics (HTTP 500). No module changes (registry stays at 201 active + 116 passive).

### Fixed

- **Server no longer 500-panics on a half-initialized database** — schema-creation failure now collapses into the same no-persistence mode as an open failure, so the server is consistently DB-less and repo-backed endpoints (`/api/scans`, `/api/projects`, …) return a clean **503** instead of a nil-pointer panic. Enforced in two places: a new `initServerDatabase` helper in the CLI `server` path closes the connection and returns no repo on schema failure, and `NewHandlers` — the single constructor every server is built through — normalizes the invariant by dropping to no-DB mode if it ever sees a non-nil db with a nil repo. The reverse pairing (repo-backed agent endpoints with no traffic DB) is a legitimate, tested config and is left untouched.

### Internal

- **REST scan-trigger E2E tests** (`make test-e2e-rest-scan`, `TestAPI_REST_*`) — boot the API server in-process and drive a native scan **and** an agentic (autopilot/swarm) scan entirely through the REST API against a hermetic `127.0.0.1` target. No Docker or LLM provider required — the agentic legs assert the launch/track/cancel wiring. A regression guard against server mis-wiring that turns scan-triggering endpoints into 500s/panics.
- **REST coverage scorecard canary** (`TestCoverageScorecard_RESTNativeScan_DVWA`) — the same DVWA ground-truth coverage scan, driven through the REST API instead of the CLI, folded into `make test-e2e-scorecard`.
- **REST autopilot smoke test** (`make test-smoke-autopilot-rest`, `TRANSPORT=rest`) — the real, paid access-lab autopilot smoke run driven through the server (`POST /api/agent/run/autopilot` + poll `/api/agent/status/:id`) instead of the CLI, exercising the operator/workbench path end-to-end.
- Added no-persistence handler tests (`handlers_norepo_test.go`) and DB-init tests (`server_db_init_test.go`) covering the degraded paths above.

## [v0.3.1] - 2026-07-13

The headline is a **redesigned `agent autopilot`** — an opt-in (`agent.olium.autopilot_mode`) **durable, bounded-section operator** that rotates context instead of accumulating unbounded conversation history, paired with a **verify-before-promote** path where a fresh-context skeptic verifier grades each candidate against per-class evidence gates before it becomes a finding. Around it: **durable state + `--resume`**, an operator **`--knowledge-base`** (read-on-demand app docs), **`--prior-context`** (mine the traffic and findings already in the project DB), **`--plan-file`** seeding, and shared `--headed` / `--browser-auth` / `--session-dir` / `--transcript` debugging controls across autopilot and swarm. Underneath the features is a broad **reliability sweep** across the scan pipeline plus a batch of code-review fixes for regressions the v0.3.0 refactors introduced — scan lifecycle correctness (recovered panics/cancellations no longer report as successful scans, single-owner finalization, project-scoping enforced on every scan-control endpoint), several fixed data races and resource leaks, and restored CSRF / passive-module scoping and gating that had regressed. No module changes (registry stays at 201 active + 116 passive).

### Added

- **Redesigned `agent autopilot` — durable, bounded-section operator with verify-before-promote (opt-in via `agent.olium.autopilot_mode`)** — `legacy` (default) is byte-for-byte unchanged; `shadow` and `enforced` opt into the redesign. The operator now runs in **bounded sections with context rotation**: instead of accumulating unbounded conversation history until it hits a context ceiling, it resets the engine and reconstructs a compact brief (durable scratchpad + previous-section closing note + candidate ledger + recent actions), rotating on a turn cap / token soft-cap / stall — removing the long-run context ceiling. In `enforced` mode a `propose_candidate` tool replaces `report_finding`, and a **fresh-context skeptic verifier** (its own engine and transcript file, detached from the operator's `--max-duration` deadline) grades each candidate against per-class evidence gates — IDOR owner/non-owner, XSS browser-execution, SQLi paired controls, SSRF/RCE OAST — promoting only the confirmed ones; `shadow` mirrors reported findings into candidates for FP-rate comparison without changing behavior. State is durable in new `agent_sections` / `agent_finding_candidates` tables (cascade-delete), and additive `section_start` / `section_end` / `section_interrupted` events are recorded to the transcript.
- **`--resume <agentic-scan-uuid>` for autopilot** — resume a durable-mode run from its persisted state: reuses the run's session dir, project, target, and durable scratchpad / candidate ledger, and skips pre-scan and audit re-prep. Requires `agent.olium.autopilot_mode != legacy`.
- **`--knowledge-base <file|dir>` / `--knowledge-base-raw` for autopilot** — front-load operator-supplied reference docs describing the app (auth model, login flows, roles / privilege tiers, business logic) into the operator's opening brief. The design is **read-on-demand**, mirroring `--source`: an LLM distills the docs into a compact briefing plus an authoritative document index that are inlined, while the full documents stay on disk for the agent to `read_file` / `grep` on demand — so a directory of many markdown files adds a few hundred tokens, not the whole tree. Works blackbox and whitebox (it matters most blackbox). The distilled brief is cached to `<session-dir>/knowledge-base-brief.md` so a `--resume` reuses it instead of re-paying the LLM call, and distillation is best-effort — any failure degrades to the deterministic index, the run never fails over the KB. `--knowledge-base-raw` skips distillation and inlines the deterministic index only, for offline / reproducible runs.
- **`--prior-context` (`auto` | `summary` | `off`) for autopilot** — front-load a bounded summary of the traffic and findings **already in the project DB** (Burp imports, prior scans, prior findings) so the operator mines them instead of re-deriving from scratch. `auto` (default) renders a bounded table — totals, up to 20 endpoints, up to 10 findings, each capped with an "N more — use the tool" pointer — when prior data exists; `summary` is a one-line pointer; `off` disables it. The brief is built before this run's pre-scan (so it reflects genuinely prior data) and its token cost is roughly fixed regardless of DB size.
- **`--burp-bridge-url` on autopilot** — pull live Burp Proxy history into the project DB before the run (default from `$VIGOLIUM_BURP_BRIDGE_URL`), so the pre-scan and operator can mine it alongside prior traffic.
- **`--plan-file` on autopilot and swarm** — a plan file mixing free-text guidance and raw HTTP request block(s); the file owns the instruction and every request block becomes a seed input. Cannot be combined with `--input` or a prompt (`--prompt` / positional).
- **`--prompt` on autopilot and swarm** — an explicit flag for the free-text task guidance that was previously positional-only (same effect as the positional `[prompt]`; use `--plan-file` for a whole plan with seed requests).
- **`--headed` on autopilot and swarm** — show the browser window during the run (native pre-scan / `--discover` spidering, in-process probes, and agent-browser subprocesses); sets `VIGOLIUM_BROWSER_HEADED=1` for the run. A debugging aid.
- **`--browser-auth` on swarm** — run the browser-based auth phase before discovery.
- **`--session-dir` / `--transcript` on autopilot** — pin the run's debug artifacts (`transcript.jsonl`, `runtime.log`, scratchpad, tool-results) to an explicit directory, and/or copy `transcript.jsonl` out to a chosen path after the run (the in-session copy is always kept). Both are conveniences for debugging throwaway / stateless-DB runs; the run UUID stays a real UUID for DB linkage.

### Changed

- **Prompt-embedded credentials are honored on explicit-flag runs** — auth / browser signals carried in a free-text prompt (e.g. "log in as admin/admin123, focus on /admin") are now extracted and applied even when the target / source come from explicit `-t` / `--source` flags, instead of being silently dropped. The explicit flags still own the target / source; only the auth / browser signals are lifted from the prompt.
- **Multi-app autopilot runs are scheduled sequentially** — when a prompt yields multiple apps, autopilot now runs them one at a time (swarm keeps its parallel fan-out), because autopilot overrides shared package-level flags per app and concurrent runs would cross-contaminate targets / sources.
- **`agent.olium.max_concurrent` negative value = unbounded** — a negative `max_concurrent` now disables the provider-call concurrency cap entirely (0 / unset still resolves to the default of 4; 0 does *not* mean unbounded).

### Fixed

- **Scan lifecycle correctness** — a recovered panic or cancellation in a native scan is no longer reported as a successful scan; scan finalization now has a single owner (detached-context `CompleteScan` + a `Finalized()` safety net) so the server can't overwrite a terminal status back to `completed`. Rejected/dry-run requests are admitted before heavyweight allocation, leaving no leaked runner or pending scan row, and shutdown cancels and awaits in-flight scans instead of starting queued ones.
- **CSRF regressions from v0.3.0** — `csrf_verify` now models a real cross-site forgery (foreign `Origin`/`Referer` on the probe) and keys dedup on request identity after the token-applicability check; `csrf_detect` requires a likely-session cookie, resolves `SameSite` from the request's own session cookie, and bounds its token regex (`\btoken\b`) so `accessToken` / `siteToken` no longer suppress a real missing-token finding.
- **Host-scoped passive regressions from v0.3.0** — reverted `cors_misconfiguration` and `clickjacking_detect` to per-route scope; restored the HTML/scheme `CanProcess` gates on `security_headers_missing`, `csp_weakness_audit`, `hsts_preload_audit`, `permissions_policy_detect`, and `cross_origin_isolation_audit` (HSTS gated to HTTPS); `cookie_security_detect` now parses `Set-Cookie` attributes instead of substring-matching and grades material session-cookie issues (missing `Secure`/`HttpOnly`) as Low/Tentative candidates.
- **Data races & resource leaks** — `responseObserver.sink` moved to `atomic.Pointer`; process-global `os.Stderr` capture is now single-owner (no cross-scan descriptor corruption); `Runner.Close` guarded by `sync.Once`; fixed the `PauseController` pause/resume race, an OAST request-resolver race, a spider writer leak, and a `RecordWriter.Close` that could hang shutdown on a wedged DB.
- **HTTP/executor robustness** — transmit an explicit `Host` override via `req.Host`; floor `ResponseHeaderTimeout` at `max(timeout, 30s)` so a 6s time-blind SQLi probe isn't aborted at the transport layer; per-scan requester isolation (`CloneForScan`); the cluster key now includes `DisableCompression`; batch-flush no longer double-counts the per-module cap.
- **Database & input hardening** — finding host filter rewritten as `EXISTS` (no duplicate rows) with a risk-ranked severity sort; `total_findings` resettable to 0; fixed a risk-keyset coverage hole (retry the page rather than silently skip); fixed nuclei/deparos JSON decoder infinite-loops on malformed lines and persisted disk-queue sealed-segment state across restarts.
- **Agent / audit / JS-extension resilience** — a canceled audit finalizes on a detached context (no more stuck `running`); JS extensions are interruptible via a watchdog with poisoned VMs discarded; process cleanup no longer kills live or PID-reused processes; the JSTangle pool self-heals on worker-replacement failure.
- **Scanner-module correctness** — gRPC missing-auth confirmation compares response content (hash) not just length; padding-oracle reconfirms the byte that actually controls final CBC padding; boolean-blind SQLi dedups claims per insertion point and honors the per-module deadline between payloads; IPv6 `ServiceBaseURL` bracketing.
- **httpmsg / WAF pacing** — lowercase absolute-form scheme before parsing (`HTTP://` was dropped) and make `OriginRefererScheme` port-aware so a cross-port `Origin`/`Referer` no longer flips the inferred scheme; a per-entry `preArmed` flag distinct from `armed` fixes birth-armed adaptive `PreArm`, and a limiter evict-notifier clears the edge-pacing dedup so a re-created entry re-arms after eviction.

### Internal

- Marked `modernc.org/sqlite` as a direct dependency (`go mod tidy`).
- Added `.github/secret_scanning.yml` `paths-ignore` so the synthetic secret-detection test corpus isn't flagged by scanning / push protection.
- Consolidated the spider DESTRUCTIVE-endpoint guard into a single Go-side `filterDestructiveURLs`; extracted a `decodeResponseBody` network/capture helper; surfaced `--no-waf-pacing` under Speed Control in CLI usage.
- **Durable-autopilot plumbing** — a durable-state repository (`agent_sections` / `agent_finding_candidates` CRUD, indexes, cascade-delete); `SaveFindingReported` so the autopilot `report_finding` counter tallies only distinct, non-deduped findings; and `CountFindingsByModule` / `CountFindingsByURL` for run-scoped coverage.
- `RegisterReadOnlyBuiltins` consolidates the read-only olium builtin set (`read_file`, `ls`, `grep`, `glob`, `web_fetch`, `browser_probe`) in one place; the `/diagnostics` embedded-binary + piolium probes now run concurrently (wall time bounded by the slowest single probe rather than their sum).
- Multi-target autopilot smoke runner (`test/smoke-test/smoke-autopilot.sh`, `PROFILE=access-lab|ginandjuice|crapi|juiceshop`) with a hermetic `access-lab` vulnerable app; agent-transcript test fixtures + generator (`test/testdata/agent-transcripts/`); `sanity-check.sh` de-staled (`archon`→`audit` driver rename). Refreshed the bundled `vigolium-scanner` skill and the agentic-scan docs for the new flags.

## [v0.3.0] - 2026-07-12

Two-way **Burp Suite integration** through a new loopback **live bridge** (paired with the [`burp-vigolium`](https://github.com/vigolium/burp-vigolium) extension **v0.2.0**) headlines this release, alongside two engine-level upgrades. First, the embedded JavaScript analyzer is **rebuilt and renamed `jsscan` → [`jstangle`](https://github.com/vigolium/jstangle)** — turning a `js-beautify` + regex sweep into a deobfuscating, **AST-based JavaScript intelligence engine** that resolves real request facts (endpoints, GraphQL operations, WebSocket/SSE, client routes, browser security flows) out of minified, obfuscated bundles. Second, **secret detection drops the external `kingfisher` binary** for a pure-Go, in-process scanner (`pkg/secretscan`) built on **[`wasilibs/go-re2`](https://github.com/wasilibs/go-re2)**. They join a broad **CLI agent-ergonomics overhaul**, a batch of **autopilot / olium agent-tooling** safety, provenance, and attribution fixes, and **per-origin scan-identity** / **strict input-format** correctness contracts. The module registry grows to **201 active + 116 passive**. See the [Burp Suite guide](https://docs.vigolium.com/getting-started/burp-suite) for bridge setup and usage.

### Added

- **Burp Suite live bridge (bidirectional traffic sync)** — Vigolium can now read live traffic straight out of a running Burp Suite and write traffic back into Burp's **Target → Site map**, over an opt-in, loopback-only listener that the extension exposes (default `http://127.0.0.1:9009`, loopback-bind only, no credentials). Point Vigolium at it with the new `--burp-bridge-url` flag (or the `VIGOLIUM_BURP_BRIDGE_URL` env var). Live Burp rows are merged into the ordinary traffic views labelled `source: burp`, and the usual filters, sorting, pagination, JSON output, and record-detail workflow keep working. Imports are idempotent — new requests are inserted, changed responses refresh the existing row, and unchanged traffic is skipped. Implemented in `pkg/burpbridge` (client), `pkg/olium/vigtool/burp_bridge.go` (agent tool), and `pkg/server/handlers_burp_bridge.go` (server-side merge).
- **New CLI flags for fetching Burp traffic directly** — bring Burp's Proxy history and Site map into Vigolium (and push traffic back) without leaving the CLI:
  - `vigolium traffic --burp-bridge-url <url>` — merge live Burp Proxy history with the local database in the `traffic` view.
  - `vigolium traffic --save-to-vigolium-db [--all]` — persist bridge-visible Burp history into Vigolium's database (the current page, or every matching record with `--all`).
  - `vigolium traffic --save-to-burp` — copy selected Vigolium database traffic into Burp's Target Site map.
  - `vigolium replay --record-uuid <uuid> --save-to-burp` — save a mutated replay and its fresh response back into Burp's Site map.
  - `vigolium import --burp-bridge-url <url>` — persist all bridge-visible Proxy history into the database in one shot.
  - `vigolium server --burp-bridge-url <url>` — merge live Burp rows into `GET /api/http-records` for the UI and API.
- **Companion extension — [`burp-vigolium`](https://github.com/vigolium/burp-vigolium) v0.2.0** — ships the loopback live-bridge listener and on-demand / interval **Target Site map snapshots** (idempotent, incrementally chunked upload; `Ctrl+Alt+S`), a dedicated **Bridge** tab/panel, and direct context-menu dispatch from Proxy History, Site map, and Repeater. Site-map snapshots are ingested by Vigolium's `POST /api/burp/sitemap/snapshot` endpoint.
- **Positional targets and prompts across the CLI** — `scan` (and `scan-url` / `scan-request` / `run`) now accept target URLs as bare positional arguments, deduplicated against `-t/--target`; `agent autopilot` / `agent swarm` preserve a positional prompt as extra instruction context even when flags are also set; and `db list` takes a positional table selector (`findings` / `scans` / `scopes`), conflict-checked against `--table`.
- **`db reset --force` and `config ls --show-secrets`** — a dedicated `db reset --force` replaces the ambiguous overloaded `--force`, and `config ls --show-secrets` is now the explicit, self-documenting way to reveal masked secret values (VACUUM stays automatic on reset).
- **`swarm --provider` / `--model`** — the swarm agent gains provider/model overrides via the shared `oliumOverrides` helper, matching autopilot; `--list-agents` and every `--provider` help string are now driven by a single `olium.ProviderNames` registry so they can't drift.
- **`report_finding` links its proof; `replay_request` persists** — the autopilot `report_finding` tool now accepts `record_uuids` and populates `HTTPRecordUUIDs`, so agent findings link the `http_records` that prove them; `replay_request` persists the sent request and received response as an `olium-replay` http_record, returned as `replay_record_uuid`.
- **`--input-mode` advertises every supported parser** — `SupportedFormats()` now derives from a single format registry and lists all accepted formats (adds `postman`, `curl`, `burpraw`, `burpxml`, `har`).
- **"Did you mean" suggestions for mistyped flags** — a near-miss long flag (e.g. `--module` for `--modules`) no longer dead-ends at a bare `unknown flag`; the error now points at the closest registered flag on the command that failed to parse (`… Did you mean --modules? (run 'vigolium scan --help' for all flags)`). The match is Levenshtein-based with a length-scaled threshold so short flags don't over-suggest, and only long flags qualify — an unknown shorthand is left untouched. Installed once on the root command so every subcommand inherits it, mirroring cobra's built-in near-miss *subcommand* suggestions. Implemented in `pkg/cli/flag_suggest.go`.
- **Proactive WAF/CDN pacing (`--no-waf-pacing` to disable)** — an aggressive active phase can burst a CDN/WAF edge into arming a rate-based block (e.g. AWS WAF starts `403`-ing every probe seconds in), which hides real findings behind the edge. The per-host limiter now pre-throttles a host *before* the active phase bursts: the first time any earlier phase's traffic fingerprints a host behind a CDN/WAF edge — CloudFront, Cloudflare, Akamai, Imperva/Incapsula, Sucuri, or Azure Front Door, from headers present on ordinary `200`s — the host's concurrency is dropped (to `MaxPerHost/4`) and ramps back up on healthy responses. A one-time-per-host `[waf-pacing-armed]` notice prints the drop (e.g. `40→10`) to stderr and the session log so the slower pace is visible. It complements — and does not replace — the existing reactive WAF-block back-off; pass `--no-waf-pacing` to keep full opening concurrency (the reactive back-off still applies after a confirmed block). The fingerprint hangs off the shared HTTP requester and the notice off the shared host limiter, so it fires exactly once per host across every phase and requester. Implemented in `pkg/deparos/waf` (edge fingerprint) and `pkg/core/ratelimit` (`PreArm`).

### Changed

- **`jsscan` → [`jstangle`](https://github.com/vigolium/jstangle): a rebuilt JavaScript intelligence engine, not just a rename** — the embedded Bun/webcrack helper and its Go wrapper are renamed end-to-end (`platform/jstangle`, `pkg/deparos/jstangle`, the per-platform `internal/resources/deparos/embed_jstangle_*` binaries, discovery `engine_jstangle.go`, config key `jsscan:` → `jstangle:`, plus build targets, Dockerfiles, and docs), **and the engine itself is substantially upgraded** rather than left behavior-identical. A plain string/regex sweep over bundled JS is nearly blind — it can't follow how a URL is assembled or whether a match is live code. jstangle instead **deobfuscates and normalizes** the source (webcrack-backed, loaded lazily), walks the **AST**, and resolves request facts with real evidence. Output is a **typed, provenance-tracked analysis envelope** spanning record families `httpRequest`, `domFlow`, `assetReference`, `graphqlOperation`, `websocket`, `eventSource`, `clientRoute`, and `browserSecurityFlow` — each with per-record confidence and a source span — while large transformed/beautified documents spill to contained, session-scoped artifacts. Callers pick **analysis profiles** (`endpoints`, `dom-security`, `beautify`, `discovery`, `discovery-lite`, `full`, `inspect`) so each runs only the stages it consumes, and **rewrite levels** (`strict` | `standard` (default) | `aggressive`) trade unminification depth against cost. Replay is safety-gated: only high-confidence facts are eligible for exact replay (observed method/query/body/safe static headers), and auth, cookies, API keys, CSRF tokens, and browser-controlled headers are never copied into replay traffic. The Go scanner drives it over a persistent length-framed `--worker` transport behind a machine-readable `--capabilities` contract, and jstangle is now a standalone, MIT-licensed, publishable CLI (`npm install -g @vigolium/jstangle`).
- **Native, in-process secret detection — the external `kingfisher` binary is dropped** — passive secret scanning no longer shells out to (or downloads) the MongoDB kingfisher binary; the entire `pkg/toolexec` subprocess/download tree is removed and replaced by a new in-process `pkg/secretscan` detector. It runs a **[`coregx/ahocorasick`](https://github.com/coregx/ahocorasick) keyword prefilter → regex → gate** pipeline over **[`wasilibs/go-re2`](https://github.com/wasilibs/go-re2)** — real Google RE2 compiled to WebAssembly via wazero, so it needs no cgo, works on `arm64`, runs ~10× faster than the `regexp` stdlib, and is concurrency-safe. The rule set is a single embedded catalog of **1,264 rules** (`pkg/secretscan/catalog.json`) merged from **kingfisher v1.106.0** (Apache-2.0 patterns normalized from Rust-regex to RE2, live-validation blocks stripped) and **betterleaks v1.6.1** (MIT, the gitleaks successor), regenerated byte-reproducibly via `make update-secret-rules`. kingfisher's detection semantics are preserved faithfully (entropy gate, character-class requirements, capture-group selection, safelist), and — matching the previous `-n` invocation — live credential **verification stays off**. All three consumers (the passive `secret_detect` module, the known-issue-scan batch, and the discovery engine) now detect inline with no temp files. Config renamed to match: `disable_kingfisher` → `disable_secret_scan` (the `DisableKingfisher` field and `kingfisher_findings` storage column follow suit — no backward-compatible alias); original rule IDs, `kingfisher` provenance, and attribution are retained.
- **Repeatable opaque flags use a stable `StringArray`** — `-H/--header`, `--auth`, `--auth-file`, `--target`, `--spec-header`, and `--cookie` now use a `StringArray` value type that preserves each entry verbatim (no comma-splitting), so header/cookie values containing commas survive intact.
- **Every active module declares an intensity tier** — 19 previously untagged active modules were assigned explicit intensity tiers, and a registry contract test now requires every active module to declare one (`xss-stored` / `xss-dom-confirm` are waived as deliberate always-on modules).
- **Safer autopilot default tooling** — the `attack_kit` Redis gopher PoC is now a harmless `PING` probe instead of a destructive `FLUSHALL`, so an autonomous agent can't wipe a target's data by default; `web_fetch` is reclassified as non-read-only whenever capture is enabled (it writes an `http_record` on every fetch, so it must not join the engine's read-only parallel fan-out).

### Fixed

- **Per-origin scan identity (`scheme://host:port`)** — per-host module claims and the tech / content-class read key are now keyed by canonical origin rather than a bare hostname, so a `ScanPerHost` module is no longer suppressed on `:8443` / `:8080` after `:443` claims the `(module, host)` pair, and per-port tech-gating no longer leaks or drops non-default-port detections.
- **Strict `--input-mode` — no silent fallback** — an unknown `--input-mode` value is now rejected up front instead of silently falling through to the Nuclei parser (a typo previously yielded zero or partial records with no error).
- **`cwe_id` populated on the native path** — findings' `Metadata["cwe"]` now fills the existing `cwe_id` column (previously dropped for native-scan findings; no schema change).
- **`web_fetch` truncation off-by-one** — a response body landing exactly on the size cap is no longer mislabeled as truncated.
- **`get_session` cross-project guard** — a cross-project UUID can no longer read another project's session record.
- **`storage` requested-but-disabled returns a config error** — asking for storage output when storage is disabled now exits nonzero with a clear config error instead of silently succeeding (exit 0).
- **`db clean` refuses no-selector wipes** — a `db clean` with no selector no longer wipes everything; an explicit selector (or `db reset --force`) is required.
- General reliability, correctness, and false-positive hardening across the server, config handling, WAF/CDN detection, and scanner internals.

### Internal

- **Child-scan attribution** — `run_native_scan` / `run_module` / `run_extension` now attribute the child scan and its findings back to the parent agentic scan (`ScanContext.attributeChildScan`).
- **Single-source provider registry** — `olium.ProviderNames` backs `--list-agents` and all `--provider` help text; the swarm/autopilot override paths share one `oliumOverrides` helper.
- **Registry contract test** — a new test asserts every active module declares an intensity tier.
- **Secret-catalog codegen** — `internal/cmd/secretgen` merges the pinned kingfisher + betterleaks rule sets into `pkg/secretscan/catalog.json` (regenerated by `make update-secret-rules`, `KINGFISHER_VERSION` / `BETTERLEAKS_VERSION` pins); `go.mod` gains `wasilibs/go-re2` and `coregx/ahocorasick` and loses the kingfisher-download deps; `THIRD_PARTY_NOTICES.md` is updated to attribute go-re2, ahocorasick, kingfisher (rules), and betterleaks (rules). Coverage: `pkg/secretscan/{engine,detector,bundle}_test.go` and `pkg/modules/passive/secret_detect/{bundle,jstangle_beautify}_test.go` (real minified-bundle detection, RE2↔stdlib parity, `-race` concurrency, and beautify→scan compose).
- Removed the dead SDK-mode guardrails config block; refreshed stale bundled skills, the autopilot prompt, and built-in examples; added `Args` validators on `scan` / `server` / `ingest` / `strategy` / `doctor` / `version` / `scope view` / `db list` / `config ls`.

## [v0.2.4] - 2026-07-09

Catch-all / echo-server false-positive hardening across the endpoint-exposure module families. No new modules (registry stays at 198 active + 115 passive) — 31 existing active modules gain a shared confirmation guard against hosts that answer every path with the same 200 body. The release also hardens browser-launch reliability (a crash-on-startup system Chromium now falls through to a working browser, and `doctor` smoke-launches the browser instead of trusting its `--version` banner), makes hand-picked module runs skip the broad `known-issue-scan` pass by default, fixes a jstangle large-output truncation, and closes an npm-publish staleness bug that shipped v0.2.2 binaries as 0.2.3.

### Added

- **WAF/CDN block warning** — when scan traffic to a host first comes back as a WAF/CDN block (a captcha, bot-detection, or challenge page), the scanner now prints a one-time-per-host `[waf-block-detected]` warning to stderr (and the session log) noting the edge is filtering traffic and results for that host may be incomplete. Detection runs on the shared HTTP requester, so it fires across every phase (discovery, spidering, dynamic-assessment); the dedup means at most one line per host regardless of how many requests are blocked. Suppressed under `--silent`.
- **Expanded WAF/CDN + bot-management fingerprints** — the block detector (`pkg/deparos/waf`) gains 12 vendors on top of the existing Cloudflare/Akamai/AWS/F5/Imperva/Sucuri/ModSecurity set: **WAF/CDN** — Azure (Application Gateway / Front Door), Fortinet FortiWeb, Barracuda, Citrix NetScaler, Wallarm, Radware, Reblaze, Wordfence; **bot management / anti-automation** — DataDome, PerimeterX (HUMAN), Kasada, Queue-it. Header matching now inspects every `Set-Cookie` value (not just the first) so cookie-name signatures like `datadome=`, `rbzid=`, and `_pxhd` are caught reliably. The status-code gate still applies, so a bot-manager tracking cookie on an ordinary 200 is never mistaken for a block.
- **Browser launch smoke-test in `doctor` / first-run init** — `vigolium doctor` (and the first-scan dependency check) now *actually launches* the resolved Chromium headless instead of trusting its `--version` banner. A binary that prints a version but SIGTRAPs on real headless startup (seen with Debian's Chromium on a KVM guest) or is missing a runtime shared library is downgraded from green to a warning carrying a specific remedy — run `vigolium doctor --fix --only chrome` to download a working Chrome for Testing, or point `spidering.browser_path` at a working browser — instead of being reported healthy and then failing every spider. The probe (new `pkg/browserprobe`) performs the same DevTools remote-debugging handshake the spider relies on, in an isolated self-cleaning user-data dir, bounded to 30s. Only the one-shot CLI paths (doctor, first-run init) enable it; the server `/diagnostics` endpoint leaves it off to stay a cheap, poll-safe readout.

### Changed

- **Hand-picked module selection auto-skips `known-issue-scan`** — narrowing a scan to specific modules (`--module-id`, or `-m`/`--modules`) now auto-appends `--skip known-issue-scan`, since selecting a handful of modules signals a targeted, low-noise scan and the broad Nuclei/Kingfisher known-issue pass would flood it. A one-line console note explains the auto-skip; pass `--only known-issue-scan` to force the pass. It's a no-op when `--only` is set, when no module narrowing is active, or when the phase is already off or explicitly skipped, and is silent under `--silent`.
- **WAF/CDN block warning now fires on the direct single-request path too** — the `scan-url` / `scan-request` path builds its own HTTP requester and previously missed the one-time-per-host `[waf-block-detected]` warning; it now installs the same notifier so an edge filtering scan traffic is surfaced regardless of scan entry point. The shared `FormatBlockNoticeLine` keeps the message identical to the Runner-backed path.
- **`finding` tree leaves show the producing module type** — each collapsed leaf now renders a `(confidence, active|passive)` tag so it's clear both how sure a finding is and whether an active or passive module produced it; the `active` label is now colored green (matching the passive/active convention in `traffic` / `db ls`).
- **HTML-report body-trim note points at the full-fidelity formats** — the "trimmed N bodies to stay within browser limits" stderr note now directs the reader to the `sqlite`, `jsonl`, and `fs` export formats for the full raw data (previously it named only the JSONL export).

### Fixed

- **Universal-catch-all false positives** — a reflecting/echo server, SPA fallback, or blanket rewrite that serves the same 200 body for `/<dir>/<anything>` could survive a weak marker (`pool:`, `pong`, a brand string in a truncated tail) and be reported as a genuine exposure. Affected modules now issue **catch-all decoy disproof** rounds: a random same-directory/same-extension sibling is fetched through the *same* marker predicate, and any candidate whose decoy also matches is dropped. A genuinely exposed file/panel/endpoint has no such sibling (the decoy 404s), so this costs no true positives, and running the decoy through the same predicate makes it robust to the body-truncation quirk that a body-similarity compare would miss.
- **Plaintext-only probes gated by content-type** — probes whose genuine hit is only ever served as plaintext (PHP-FPM status/`/ping`, and similar) now reject a `text/html` response outright as a catch-all/echo shell, while probes whose real content is legitimately HTML (phpinfo, admin/login UIs) skip the content-type gate and lean on the decoy disproof instead.
- **Discovery no longer brute-forces SPA build directories** — spidering a Next.js/Nuxt/Vite/webpack/CRA app harvested chunk names from the JS bundles and replayed them under the immutable, content-hashed build-output directory (e.g. `/_next/static/chunks/<name>/`, `/_next/static/chunks/<name>`), producing hundreds of pointless requests that can never surface a real route. Discovery now detects content-hash fingerprinted bundles by filename (`main-5cf96b0d57f7f579.js`, `938-50137dfb3187f5b2.js`, CRA `main.073c9bfa.chunk.js` — a `-`/`.`/`_`-delimited token of ≥8 hex chars containing at least one `a-f` letter, so version numbers and timestamps don't match) and skips recursive wordlist/observed brute-forcing into any directory that holds them, plus backup/numeric derivations off the files themselves. This is framework-agnostic — no hardcoded directory list — with a cheap path fast-path for the well-known roots (`/_next/static/`, `/_nuxt/`, `/_app/immutable/`). A generic `/static/` with hand-authored assets stays fully discoverable. The bundles the spider actually found are still fetched and scanned; genuine endpoints like `/api/...` are unaffected.
- **Browser launch falls through a broken system Chromium instead of aborting the scan** — spidering resolved a single browser binary and failed the whole scan if it crashed on real launch. Launch now tries each candidate in priority order — configured `browser_path` → embedded engine binary → system Google Chrome → system Chromium → Chrome for Testing (cached, then downloaded) → rod auto-download — and falls through to the next whenever one fails the launch/DevTools handshake, so a crash-on-startup distro Chromium auto-recovers to a working browser (in practice Chrome for Testing) rather than aborting. All resolvable system binaries are enumerated (real Chrome preferred over Chromium), and only when *every* candidate fails does launch return an aggregated error (with an `sudo apt-get install -y chromium` hint on linux/arm64, where neither rod nor Chrome for Testing publish a build to auto-download).
- **jstangle large-output truncation** — jstangle's `code` / `beautified` JSONL records for a big bundle exceed 64KB, and the Bun/Node runtime could exit before the tail of a large write drained through the ~64KB kernel pipe buffer, silently truncating those records so the JSON failed to parse and the beautified document was lost. jstangle's stdout is now captured to a temp file (always write-ready, no pipe-buffer cap) instead of a `bytes.Buffer` pipe, so the full output survives regardless of line size.
- **Request-cluster cache no longer double-decodes bodies** — a cached response snapshot kept the original `Content-Encoding` / `Content-Length` / `Transfer-Encoding` headers even though its body was already decoded at capture, so reconstructing the response (`ToResponseChain`) could re-decode a plaintext body and misreport its size as 0. The snapshot now strips those content-coding / framing headers at the single point where the decoded body and headers are paired, and sets `ContentLength` to the decoded length, keeping the cached entry self-consistent.
- **npm publish shipped stale binaries under a newer version** — the `NPM_NEEDS_BUILD` staleness guard grepped the built binary for the target version string, which false-matched because a binary embeds newer version strings in its content (a v0.2.2 build literally contains "v0.2.3"), so `make npm-*` repackaged stale v0.2.2 binaries under the 0.2.3 npm version. Staleness is now judged by the goreleaser archive name (`vigolium_<version>_<os>_<arch>.tar.gz`, authoritative since `--clean` wipes `build/dist` each run), and `build/npm/build.mjs` gained a `verifyReleaseVersion` backstop that refuses to pack when `build/dist` holds binaries built for a version other than the one being published.

### Modules hardened

`aem_content_discovery`, `aspnet_blazor_exposure`, `aspnet_identity_probe`, `aspnet_misconfig`, `aspnet_sensitive_files`, `aspnet_service_exposure`, `cloud_storage_listing`, `cms_installer_exposure`, `dashboard_exposure`, `django_browsable_api_exposure`, `django_debug_exposure`, `fastify_hono_probe`, `firebase_misconfig`, `flask_werkzeug_debugger`, `js_devserver_exposure`, `laravel_devtool_exposure`, `laravel_ignition_rce`, `laravel_misconfig`, `laravel_sensitive_files`, `nextjs_chunk_audit`, `oauth_misconfiguration`, `php_composer_exposure`, `php_debug_exposure`, `php_framework_debug`, `php_path_info_misconfig`, `php_source_disclosure`, `rails_admin_dashboard`, `rails_sensitive_files`, `unauth_service_exposure`, `wp_ajax_exposure`, `wp_xmlrpc`.

### Internal

- 30 new/expanded `scan_detect_test.go` suites covering the catch-all decoy and content-type gates.
- New tests for the reliability work: `browserprobe_test.go`, `diagnostics/chromium_probe_test.go`, `spitolas/.../candidates_test.go` (candidate ordering / fall-through), `http/block_notifier_test.go`, `http/clustering_test.go`, `cftbrowser_test.go`, plus jstangle, WAF-detector, and immutable-asset-dir suites.

## [v0.2.3] - 2026-07-07

False-positive hardening for the injection modules plus search-flag ergonomics. No new modules (registry stays at 198 active + 115 passive).

### Added

- **`--exclude-search` / `--exclude-header` / `--exclude-body` on `finding`, `traffic`, `db ls`** — inverse of the search flags; drop any row where the term appears. `--exclude-search` is repeatable (AND-combined).

### Changed

- **`--search` / `--header` / `--body` now span the full request/response corpus** (URL, path, headers, body — and linked records for `finding`), not just URL/path.
- **XPath boolean oracle hardened** — three operand pairs (was two) plus symmetric OR-false/AND-true inert controls; `sqli-boolean-blind` confirmation raised to three rounds.

### Fixed

- **Time-based injection FPs** — new `infra.ScaledDelayConfirmed` requires the delay to scale with the injected sleep over a no-sleep control, across `sqli-time-blind`, `command-injection-timing`, and `nosqli-operator-injection`.
- **CDN/challenge FPs** — `infra.LooksOpaqueBody` (entropy) and `infra.IsCDNInfraPath` (`/cdn-cgi/`) make the differential and injection modules fail closed on opaque, non-deterministic edge responses; `xpath-injection` also skips standard request headers, and `ldap-injection` rejects block pages served with a 200.

## [v0.2.2] - 2026-07-07

A false-positive-hardening and read-command ergonomics release on top of v0.2.1 — no new modules (registry stays at 198 active + 115 passive). It fixes two shared root causes behind a class of differential/blind false positives — confirmation legs that "reproduced" against a cached response, and non-deterministic endpoints whose status flips were misread as injection — and tightens signature-stripping, OAST callback fan-out, and hygiene-finding noise.

### Added

- **`--severity` / `--sev` filter on `finding` and `db list`** — comma-separated severity list accepting single-letter shorthands (`h,c`) and any unambiguous prefix (`me,info`, `crit`).
- **"Filtered by:" summary line on `finding` and `traffic`** — text-mode listings echo the active filter conditions (severity, confidence, search, host, …) so it's clear how the result set was narrowed; suppressed for JSON output.
- **Per-source attribution for `--glob-db` merged reads** — `finding`/`traffic` trees built from multiple merged databases show one db-path root per source file, attributing each finding and record back to where it came from.
- **`--limit` cap notice** — a stderr hint reports how many rows were shown of the total and how to raise the cap.

### Changed

- **Finding grouping widened for noisy per-URL / per-page findings** — `sensitive-header-leak`, `sensitive-url-params`, `clickjacking-detect`, `reverse-tabnabbing-detect`, `nginx-path-escape`, `cache-auth-misconfiguration`, `crlf-injection`, and `api-key-url-exposure` now collapse to one per-host finding (affected routes/params/values unioned onto the survivor) instead of one row per crawled URL.
- **OAST findings coalesce per emission key** — a payload's callback fan-out (DNS A/AAAA, recursive resolvers, then the HTTP-fetch leg) collapses to one finding at the strongest protocol rank, and low-signal Info interactions also coalesce across the many URLs that plant the same injection point on a host.
- **SAML signature-stripping scoped to where the attack applies** — the leg now requires a SAML `<Assertion>` (so a `SAMLRequest`/`AuthnRequest` to an IdP SSO endpoint no longer false-positives), requires an accepted baseline status (2xx/3xx), and treats a 5xx control as a crash rather than a bypass.

### Fixed

- **Confirmation legs poisoned by the request-cluster cache** — the 500 ms cache keyed on raw request bytes returned the first response verbatim, so an identical re-send always "reproduced" (and timing re-sends came back ~0 ms). Confirm/baseline/timing round-trips now pass `NoClustering: true` across `code-exec`, `default-credentials`, `http-request-smuggling`, `race-interference`, `reverse-proxy-path-confusion`, `sqli-boolean-blind`, `sqli-time-blind`, `ssti-blind`, `unauth-service-exposure`, and `ssrf-detection`.
- **Non-deterministic / status-flip differentials misread as injection** — endpoints that flap between a 200 page and a 302 redirect independent of the payload could mimic a proxied fetch or boolean oracle. The differential legs now require a determinism re-fetch, agreeing controls, and 2xx status discipline (via shared `infra.Is2xx`) across `ssrf-detection`, `xpath-injection`, `ldap-injection`, `nosqli-operator-injection`, and `idor-guid` (which also requires a *substantial* body difference so per-request tokens don't read as a different object).
- **Standard request headers wrongly treated as URL-fetch / injection sinks** — `Referer`, `Origin`, `Upgrade-Insecure-Requests`, `Via`, and `From` are fixed browser/protocol headers, not application parameters. A shared `infra.IsStandardRequestHeader` now excludes them across the SSRF/OAST family (`ssrf-blind`, `oast-probe`), and `input-behavior-probe` drops them from its probe set.
- **GraphQL boolean-injection keyword differentials** — the `graphql_scan` boolean leg now confirms against an inert-`OR` control, so an endpoint reacting to the mere presence of the token is no longer misread as injection.
- **Base64 findings collapse rotating-token JSON blobs** — `base64-data-detect` keys findings on the decoded JSON shape (per host+source), collapsing a rotating token embedded on every page to one finding while opaque/non-JSON blobs keep their per-value identity.

### Internal

- New shared helpers in `pkg/modules/infra/filter.go` (`Is2xx`, `IsStandardRequestHeader`) plus `pkg/cli/{filter_summary,severity_gate}.go`.
- New/expanded tests: `severity_gate_test.go`, `oast/service_test.go`, `signature_bypass_test.go`, `base64_data_detect/scanner_test.go`, scanner tests for the new gates (`ssrf_detection`, `xpath_injection`, `ldap_injection`), and `known_issue_scan_test.go`.

## [v0.2.1] - 2026-07-05

A detection-breadth and agent-provider release on top of the v0.2.0 stable line. Eleven new modules land (5 active + 6 passive), several existing detectors grow out-of-band and bypass legs, the olium agent runtime gains three new provider backends (the public OpenAI Responses API, a Claude Code Agent-SDK bridge, and a generic Anthropic Messages proxy), and a path-normalization/FUZZ baselining bug that was suppressing cache-key and content-discovery findings is fixed. A batch of read-command ergonomics also lands — a grouped `finding` tree view, `--pick` position selection, repeatable AND-combined `--search`, compact-by-default (and syntax-highlighted) Markdown, and post-scan traffic printing — alongside a subcommand-help reorganization and two scoping/merge correctness fixes. The registry now stands at 198 active + 115 passive registrations.

### Added

- **New active modules (5):**
  - `xpath-injection` (High) — XPath injection detection.
  - `sqli-out-of-band` (Critical) — out-of-band SQL injection confirmed via OAST callbacks (an unforgeable hit on a per-payload subdomain).
  - `unauth-service-exposure` (Critical) — unauthenticated infrastructure-service exposure (a backend admin/data service reachable without credentials).
  - `tls-protocol-cipher-audit` (Medium) — weak TLS protocol / cipher-suite configuration audit.
  - `session-fixation` (Medium) — permissive session management (server accepts an attacker-fixed session identifier).
- **New passive modules (6):**
  - `llm-endpoint-fingerprint` (Info) — detects LLM / AI API endpoints, backed by a new `infra/llmsig` signature catalog.
  - `payment-integration-audit` (Info) — flags payment-gateway integration risk surfaces (Stripe, PayPal, Braintree, Square, Adyen, Razorpay, Checkout.com).
  - `css-injection-detect` (Info) — input reflected into a CSS context.
  - `dom-clobbering` (Info) — DOM-clobbering gadget: a JavaScript sink fed from a named global.
  - `cross-origin-isolation-audit` (Info) — missing cross-origin isolation headers (COOP / COEP / CORP).
  - `reverse-tabnabbing-detect` (Low) — `target=_blank` links without `rel=noopener`.
- **`vigolium skills` command** — `list`, inspect (`get`), and `install` the bundled coding-agent skills into a coding agent's skills directory. Frontmatter parsing is lenient, so bundles using a looser SKILL.md schema still surface their name/description.
- **olium provider: `openai-responses`** — the public OpenAI Responses API (`POST https://api.openai.com/v1/responses`) with API-key auth. Same key resolution as `openai-api-key` (`agent.olium.llm_api_key` → `$OPENAI_API_KEY`), differing only in the wire format (Responses instead of Chat Completions). Default model `gpt-5.5`.
- **olium provider: `anthropic-claude-sdk-bridge`** — drives Claude Code (or Codex) through the Agent SDK via a new `vigolium-audit bridge` sidecar, using your logged-in Claude Code subscription; no key required (an explicit `llm_api_key`/`oauth_token` is forwarded). The bridge binary is resolved from `agent.olium.bridge_binary` / `--bridge-bin`, else the embedded vigolium-audit blob, else `vigolium-audit` on `PATH`.
- **olium provider: `anthropic-compatible`** — any Anthropic Messages (`/v1/messages`)-compatible endpoint at a custom `agent.olium.custom_provider.base_url` (a self-hosted Claude gateway or a Messages-format proxy); `extra_headers` can switch the auth scheme.
- **`scan --print-traffic` / `--print-traffic-tree`** — after a scan, dump the run's HTTP traffic to stdout: `--print-traffic` prints raw request/response pairs (like `traffic --raw`), `--print-traffic-tree` prints a host/path hierarchy tree (like `traffic --tree`). Mirrors the existing `--print-finding`, pairs with `-S`/`--silent` for a quick throwaway single-target scan, and is available on `scan` / `scan-url` / `scan-request` / `run`.
- **`finding --tree`** (also `vigolium finding tree`) — a host/path hierarchy view that collapses recurring findings by title (module name + short description) and severity into one node with a `×N` recurrence count, listing each affected `#id (confidence) → url` beneath it. The positional argument now routes like `traffic`: `tree` activates the tree, `ls`/`list` select the default table, anything else is a fuzzy search term.
- **`finding --pick`** — narrow the result page to specific 1-based positions after filters and sort (`--pick 2`, `--pick 1,3`, `--pick 2-4`); composes with `--raw` / `--burp` / `--markdown` / `--json` / `--tui`. Out-of-range positions warn on stderr and are skipped; a spec that selects nothing from a non-empty list errors with the valid range.
- **Repeatable `--search` on `finding` and `traffic`** — `--search` is now repeatable and AND-combined, so each added term further narrows the match (`--search sqli --search login`). `finding` search also widened to cover the module name and short description (in addition to the description, module id, and matched-at).
- **olium `--bridge-bin` flag / `agent.olium.bridge_binary` config** — point the `anthropic-claude-sdk-bridge` provider at a specific `vigolium-audit` binary hosting the SDK bridge (default: embedded blob, then `PATH`). `anthropic-claude-cli` is accepted as an alias for `anthropic-cli`.

### Changed

- **JWT vulnerability scanner** gains two forgery legs: `jku`/`x5u` header-claim injection pointing at unique OAST URLs (a callback proves the server fetched an attacker-controlled verification key), and a `kid` path-traversal token that forces `alg=HS256` and signs with the empty contents of `/dev/null` (accepted only by a server that resolves `kid` to a file and uses it as the HMAC secret).
- **XXE scanner** gains blind / out-of-band detection: per-payload external-entity and parameter-entity DTD templates that reference a unique OAST URL, so a callback on the unguessable subdomain is unforgeable proof the XML parser resolved the external reference.
- **XML / SAML security** adds signature-bypass detection — stripping the `<Signature>` element from a SAML assertion/response and confirming the target still accepts the unsigned document.
- **Sensitive-file discovery** adds high-confidence signatures for a fully walkable `.git` tree (index `DIRC` magic, reflog, packed-refs → whole source reconstructable with git-dumper, not merely a leaked config), Terraform state (`*.tfstate`), and docker-compose files, each with HTML anti-markers so catch-all pages don't trigger it.
- **CSP weakness audit** now understands `nonce-`/`sha*-` source expressions and `strict-dynamic`, so it no longer flags `unsafe-inline` when a nonce/hash or `strict-dynamic` makes modern browsers ignore it.
- **OAST service** classifies the new JWT (`jku`/`x5u`) and XXE out-of-band callbacks so their in-band-silent legs correlate correctly.
- **Codex provider refactor** — the shared OpenAI Responses request shaping and `response.*` SSE state machine are extracted into `pkg/olium/provider/responses_stream.go` and reused by both `openai-codex-oauth` and the new `openai-responses` provider.
- **`finding --markdown` / `traffic --markdown` compact response bodies by default** — a response body now renders as a window around the finding's `matched_at`/evidence (or a leading preview with a truncation note) instead of dumping a whole page, and this no longer depends on `-S`/`--compact`; pass `--full-body` to render bodies whole. The request is always shown whole (it carries the payload/injection point). The rendered Markdown is also syntax-highlighted on an interactive terminal (headings, rules, ` ``` ` fences, **bold**, `inline code`) while piped/redirected output stays plain, greppable Markdown.
- **Subcommand help reorganized** — the inherited *Global Flags* block is regrouped (Output / Network / Extensions / Project / Info / Configuration) and collapses to a single-line pointer when stdout is piped or redirected, so an agent or `cmd | less` no longer sees the full block repeated on every subcommand (the full list stays reachable via `vigolium --help`); the native-scan (`scan` / `run` / `scan-url` / `scan-request`) local-flag help is regrouped into Target & Input / Scanning / Discovery / Spidering / Module Selection / … sections.
- **Traffic / `db … tree` rows** — dropped the per-row `[Nh]` request-header-count tag and now render the path in white and the response content-type in orange for readability.
- **Provider override flags list the new backends** — the `--provider` help across the agent subcommands now lists `openai-responses`, `anthropic-compatible`, and `anthropic-claude-sdk-bridge`; `vigolium agent --list-agents` shows the bridge agent and the `anthropic-claude-cli` alias, and the active-provider marker is matched against the canonical provider name.

### Fixed

- **Path-normalization / FUZZ baseline false negatives** — the discovery fingerprinter no longer runs bypass paths through `path.Clean`; a new `SetWirePath` preserves bypass sequences (`%23`, `..`, `//`, `..;/`) byte-for-byte on the wire, `engine_init` keys the baseline via `ExtractCacheKey` (instead of a `path.Dir` that collapsed the bypass to `/`), and `httpmsg` emits the raw `RequestURI` rather than a decoded relative path. Cache-key and content-discovery findings that depended on an un-normalized path are detected again.
- **Scope keyword over-matching** — origin-scope keyword matching now compares the keyword against the host's registrable-domain leading label (its eTLD+1 label) instead of a bare full-hostname substring. Same-org hosts on other TLDs / brand domains stay in scope (keyword `acme` still matches `acme.io`, `acmegroup.com`) while an unrelated third party whose subdomain merely *contains* the keyword — e.g. `acmegroup.cloudflareaccess.com`, a Cloudflare SSO wall whose registrable label is `cloudflareaccess` — is now correctly excluded.
- **`--db-isolate` merge race on a fresh shared `--db`** — the destination-database critical section (open → schema-create → default-seed → merge) now runs entirely inside one cross-process merge lock. Previously the WAL-mode switch and `CREATE … IF NOT EXISTS` DDL ran outside the lock and could surface `SQLITE_BUSY` under a `-P` fan-out of finishers targeting one brand-new shared database.

### Internal

- New shared infra: `infra/llmsig` (LLM-endpoint signatures) and `infra/cookiesig` (cookie signal catalog) backing the new passives; `provider/responses_stream.go` shared by the Responses-format providers.
- **vigolium-audit bridge sidecar** (`platform/vigolium-audit`) — a headless Agent-SDK entrypoint (`bridge` one-shot + `bridge serve` daemon) that resolves a task preset (triage / exploit / plan), assembles an ephemeral plugin that always loads the `vigolium-scanner` skill, runs one agent loop, and returns a normalized event stream. Backs the `anthropic-claude-sdk-bridge` provider.
- New CLI display helpers: `pkg/cli/finding_tree.go` (grouped finding tree), the `--pick` position selector and repeatable-`--search` wiring in `finding.go`/`traffic.go`, `markdown_highlight.go` (interactive-only Markdown ANSI tinting), and `scan_print_traffic.go` (`--print-traffic{,-tree}`). The query layer gains an AND-combined `SearchTerms []string` on `QueryFilters` (`pkg/database/query.go`), and `pkg/cli/usage.go` was refactored so global and native-scan flags render from declarative group tables (with a piped-output terse mode).
- New tests: `resolve_provider_test.go`, `openai_responses_test.go`, `claudesdkbridge_test.go`, `anthropic_compatible_test.go`, `bypass_regression_test.go`, `fuzz_probe_resolve_test.go`, `url_request_target_test.go`, `signature_bypass_test.go`, `finding_pick_test.go`, `finding_tree_test.go`, `usage_test.go`, expanded `scope_matcher_test.go` keyword-scope cases, plus scanner tests for the JWT/XXE/CSP legs and for the new `skills`/`usage` CLI.

## [v0.2.0] - 2026-07-05

The first stable (non-beta) release, and a major expansion of detection coverage. Six new module families land — GraphQL security testing, Adobe Experience Manager (AEM), SaaS data-exposure (Salesforce / ServiceNow / Power Pages), Internet Information Services (IIS), an enlarged Model Context Protocol (MCP) suite, plus standalone dependency-confusion and JavaScript-beautification passives. Together they add 29 registered modules (22 active + 7 passive), bringing the registry to 193 active + 109 passive. Every new active family is tech-gated, fail-closed, and multi-round-confirmed to keep the false-positive floor low.

### Added

- **GraphQL security scanning (OWASP WSTG)** — the `graphql_scan` module gains a full phase suite backed by a new `pkg/graphqlx` library: operation-name expansion, introspection/console exposure, query batching, field-level authorization (IDOR), reflected-XSS-in-errors, boolean-based SQL injection, and denial-of-service (deeply-nested / aliased / circular queries). Every phase runs only against an endpoint confirmed to speak GraphQL (a `{ __typename }` probe returning a spec-shaped envelope, not merely the word "graphql") and confirms findings across multiple rounds.
- **Adobe Experience Manager (AEM) module family** — 11 active + 1 passive `aem_*` modules over a shared, fail-closed `infra/aem` gate (`ConfirmAEM`): dispatcher-bypass (differential), sensitive-servlet and console exposure, QueryBuilder content discovery (surfacing `rep:password` as Critical), default credentials, CloudSettings injection, reflected XSS (headless-confirmed), SSRF, out-of-band injection, XXE (CVE-2019-8086 entity-expansion proof), and RCE, alongside a passive `aem-fingerprint`. Detection-only; every active probe is gated to a genuine AEM instance.
- **SaaS data-exposure family (Salesforce / ServiceNow / Power Pages)** — 7 active + 3 passive modules over a shared `infra/saasprobe` gate: Salesforce Aura object/record exposure (`getConfigData` / `getItems`), Salesforce Aura guest **Apex execution** (`ApexActionController.execute` reachability, confirmed with a benign read-only managed-package method — the pivot for guest-driven SSRF/DML/exfiltration), Salesforce **Lightning debug-mode** exposure (a site served in `PRODDEBUG`/`DEV`/`JSTESTDEBUG` that leaks backend stacktraces to unauthenticated clients), ServiceNow widget and KB-article data exposure (`g_ck` + cookie, treating a `401` as *not* a finding), and Power Pages Dataverse `/_api` exposure, each paired with a per-vendor passive fingerprint. Every active probe gates on a live Aura gateway (fail-closed presence check), pairs a catch-all negative control with the positive, and confirms across multiple independent rounds.
- **IIS module family** — `iis-shortname-discovery` gains true 8.3 short-name resolution (a Go port of the gen8dot3/checksum technique that feeds deparos content-discovery with embedded wordlists), joined by two new active modules: `iis-cookieless-source-disclosure` and `iis-extension-confusion-bypass` (`::$DATA` / trailing-dot). All IIS/ASPX-gated and multi-round-confirmed.
- **MCP suite expansion** — two new active modules (`mcp-tool-definition-drift`, `mcp-dos-amplification`) and a new passive `mcp-dangerous-tool-exposure` extend the Model Context Protocol family audited against OWASP.
- **`dependency-confusion` passive module** — extracts scoped npm import specifiers from first-party JS responses *only* and flags any package left unclaimed (404) on `registry.npmjs.org`. Suspect/Tentative severity, batched registry lookup via a flusher, with over-query guards (public-scope skiplist + statement-boundary regex) and fail-closed handling of any indeterminate lookup.
- **`js-beautify` passive module** — unminifies and unpacks minified or bundled first-party scripts (React/Next/Vue SPA output) into readable source, driven by the embedded **jstangle** tool over `webcrack` (a static unpacker — no `eval`-based deobfuscation). jstangle runs as a bounded `bun` subprocess (capped at `GOMAXPROCS-2`, max 4, so a wide passive fan-out over many JS records never spawns a process per record) and returns a beautified document plus, for webpack/browserify bundles, a per-module split with recovered source paths — the jstangle `webpackExtractor` was extended in this release to reconstruct those module paths. For JavaScript responses the stored record body is rewritten in place with the beautified document (dropping `Content-Encoding`) and tagged `js-beautified` / `js-format:<format>`, so linkfinder, observed-word harvesting, and manual review all read clean source; inline `<script>` code in HTML pages is beautified into finding evidence only (`js-inline-beautified`), never rewriting the page body. A cheap Go-side pre-gate (min 500 bytes, webpack/Next/SystemJS markers or a minified average line length) avoids spawning a subprocess for tiny or already-readable scripts, results are deduped per host+path, and known third-party assets — CDN libraries and analytics/captcha/chat/payment/bot-management SDKs, matched by `jsvendor` on host, path, and content signature — are skipped unless the scan is actually targeting that vendor. Informational severity; the module cleanly no-ops when the embedded binary is unavailable.

### Changed

- **Version dropped its `-beta` prerelease label and jumped to a minor release** — v0.2.0 is the first stable release, reflecting the size of this coverage expansion.
- **MCP false-positive hardening** across the existing family — method-enum negative control, batch singleton baseline, session-fixation gate, origin locality, server-probe `isError`/skip handling, and resource-fuzz OAST/metadata checks — plus expanded `mcp-description-injection` coverage.

### Internal

- New shared libraries: `pkg/graphqlx` (GraphQL detection, introspection, schema, and operation building) and the `infra/aem` / `infra/saasprobe` gate packages backing the AEM and SaaS families.
- Tech-fingerprint tags added for the new gating (`aem`/`adobe`, `salesforce`/`lightning`/`aura`, `servicenow`, `powerpages`/`dataverse`) in `tech_tags.go`, published by the respective `*_fingerprint` passives.
- The jstangle `webpackExtractor` (`platform/jstangle`) was extended to recover per-module source paths for `js-beautify`; supporting tweaks landed across the spider (`pkg/spitolas`), discovery (`pkg/deparos`), and the core executor/rate-limiter.

## [v0.1.47-beta] - 2026-07-04

A discovery-depth and data-portability release. The spider now fills forms with values derived from the target and the page itself (so register→login flows carry consistent identities), and — at balanced/deep intensity — sprays a short list of common credentials against *confirmed* local login forms to crawl authenticated. Separately, `vigolium import` learns to merge one vigolium `.sqlite` result database into another, `agent audit -S` can bundle its report with the raw scanner output, and `vigolium server` gains a passive-only scan-on-receive mode.

### Added

- **Spider response-aware form filling** — the crawler (`pkg/spitolas`) now derives form values from the target and the response instead of always using fixed placeholders: it recalls a value entered earlier in the same crawl (so a registered identity is reused at login), falls back to target-derived values (`vigolium-crawl@<domain>`, `<label>_crawl`), then to an on-page example (a field's `defaultValue` or a `datalist` option), and only then to the existing smart/fixed defaults. Passwords are never taken from the page (a strong fixed password is kept). Default-on and non-destructive — with no fill context the original behavior is preserved.
- **Common-credential login spray on confirmed login forms** — at `balanced` intensity the spider tries a minimal list (`admin:admin`, `admin:123456`) and at `deep` the full documented short list (never a wordlist) against a login form, but *only* after confirming the form is a genuine local login (exactly one visible password + submit + in-scope action, not an external IdP) and that a bogus control pair is rejected first. On success the session cookies persist and the crawl continues authenticated. Off at `quick`/`lite` (lockout/authorization risk). Reported via `LoginCredsTried`/`LoginCredsSucceeded` on the spider result.
- **`vigolium import` merges vigolium SQLite databases** — `import` now accepts another vigolium result database as its source (auto-detected by its SQLite magic header, so `.sqlite`/`.sqlite3`/`.db` or a bare name all work) and folds it into the destination `--db` (or the configured default). A lossless, idempotent SQLite→SQLite merge of HTTP records, findings, scans, agentic scans, and OAST interactions, deduped on natural keys — re-importing the same database is a no-op, and each row keeps its original `project_uuid`. The natural companion to `scan -S --format sqlite`: fan out per-host `.sqlite` files, then merge them back into one queryable DB. `-j` prints a per-table merge summary.
- **`agent audit --output-dir <dir>`** (stateless-only) — bundles a `-S` run's HTML report (as `<dir>/vigolium-audit-report.html`) *and* a copy of each driver's raw `vigolium-results/` tree into one folder — one driver lands flat, several are namespaced under `<dir>/<driver>/`. A relative `-o` nests under the bundle; an absolute path or `gs://` URL escapes it; `{ts}`/`{project-uuid}` are expanded once so the report and raw copy share a directory. `-S` without `--output-dir` now nudges the operator that raw output stays under `<source>/vigolium-results/`.
- **`vigolium server --passive-only`** — with `-S/--scan-on-receive`, restricts scanning to passive modules only (no active scan traffic; secret detection still runs) on every ingested request. Warns when combined with `--full-native-scan-on-receive`, which still crawls.

### Changed

- **Example blocks refreshed** — `replay`, `update`, `agent triage`, and `extensions example` now carry inline `--help` examples; the `import` examples document the new SQLite-merge source.

### Internal

- New `form.FillContext` (`pkg/spitolas/internal/form/fillcontext.go`, per-crawl identity memory) threads response-aware values through `getValueForInput`; `DetectedInput` gains `DefaultValue`/`DatalistOptions` harvested by the DOM-detection JS. The login spray lives in `crawler/login_creds.go` (single-flight per host, negative-control gated), driven by new `SpiderConfig.LoginCredentialAttempts`/`LoginCredentialFullList` fields that the runner sets via `loginCredsPolicy(intensity)` for the discovery and re-spider phases.
- SQLite file detection is centralized in the new `pkg/database/detect.go` (`IsSQLiteFile`/`HasSQLiteHeader`, magic-header based); `dbimport.ImportPath` dispatches to a new `ImportSQLite` (over the existing `database.MergeSQLiteFile`) and surfaces a `MergeStats` on the import `Result`. `runner_modules.go` documents the module-slice sentinel convention (nil/empty → zero modules, `["all"]` → every module) that `--passive-only` and `--no-passive` rely on.
- Test coverage added: `form/fillcontext_test.go`, `crawler/login_creds_test.go` (+ an `integration`-tagged end-to-end), `database/detect_test.go`, `dbimport/importer_test.go`, `agent_audit_stateless_test.go`, and a `--passive-only` server-options guard.

## [v0.1.46-beta] - 2026-07-03

A replay-ergonomics release. `vigolium replay` gains a bulk mode that re-sends every matching stored record through the mutation/diff engine — so an operator (or a coding agent driving vigolium) can fuzz one parameter across a whole host, or funnel all stored traffic through Burp, in a single command with streaming JSONL output.

### Added

- **`vigolium replay` bulk mode** — passing `--all` (or any of `--host`/`--method`/`--status`/`--path`/`--source`/`--search`/`--body`) replays *every* matching stored record instead of a single source, mirroring the `traffic --replay` filters but running each record through the full replay engine. Any `--mutate` is applied to each record that has that insertion point; without one, records are re-sent verbatim. Results stream as JSONL (one stable `replayOutput` per record) so a bad record surfaces an inline `error` without aborting the batch. Throttle with `-c/--concurrency` (default 10) and cap with `-n/--limit` (default 100; `--all` lifts it).
- **`replay -S/--stateless --db <file>`** — replay can now read baselines from a standalone `.sqlite` or `.jsonl` export with project scoping off, matching the read semantics of `traffic`/`finding`. Every DB touchpoint in the command (record/finding lookup, `--auth-session` merge, bulk query) routes through the shared `openReadDB`/`effectiveProjectUUID` helpers.

### Changed

- **`replay` no longer prints the banner** — added to the banner-suppression list alongside `scan`/`run`/`traffic`, keeping JSONL output clean for piping.
- **`traffic --replay` examples refreshed** — document stateless-export replay, method/host filtering, and `--all --with-browser`.

### Internal

- The single-source and bulk paths share one call shape via a new `replayRun` struct and its `one()` method; the HTTP client construction (cookie jar + `--proxy` routing), cookie-jar save, header-overlay parsing, and output-writer setup were extracted into reusable helpers (`newReplayClient`, `saveReplayJar`, `parseReplayHeaderFlags`, `openReplayOutputWriter`, `sourceFromDBRecord`). Bulk selection maps directly onto `database.QueryFilters` via `buildReplayBulkFilters`. New coverage in `replay_bulk_test.go`.

## [v0.1.45-beta] - 2026-07-02

A false-positive-hardening and severity-calibration release. A broad sweep stops markup-reflection, error-signature, IDOR, and differential detectors from self-triggering on echoed input, framework build artifacts, and ambiguous numeric parameters; a batch of low-signal passive detectors drops from Medium to Low/Info; and secret findings now carry a short credential-family label.

### Added

- **Secret findings are labelled by credential family** — `secret-detect` tags each finding with a short classification (`JWT`, `Google API key`, `reCAPTCHA site key`, `Google OAuth client ID`, or the Kingfisher rule name verbatim), rendered as a leading `[JWT]` bracket on the console line and carried in the jsonl/DB `meta.pattern` field. The console renderer picks up any module's `Metadata["pattern"]`, so it's a generic opt-in.

### Fixed

- **Markup-reflection oracles ignore JSON/XML-echoed payloads** — a new `modkit.IsNonHTMLReflectionContext` treats an HTML/template marker echoed inside a non-HTML response (the canonical FastAPI/Pydantic `422 application/json` validation-error echo) as a data value, not rendered markup. Applied to the reflection paths of `csti-detection`, `pdf-generation-injection`, and `ws-injection`; evaluated-result oracles (SSTI/OGNL/SQL errors) are left alone.
- **Error-signature detectors bound their match span** — a loosely-anchored `X.*?Y` pattern could bridge two coincidental words across a large body (`Oracle.*?Driver` spanning 60 KB of a Salesforce Aura shell). The shared `modkit.MatchWithinSpan` / `MaxErrorSignatureSpan` (512 B) gate requires a compact span while still firing on a genuine short signature elsewhere. Applied to `sqli-error-based`, `insecure-deserialization`, and siblings.
- **IDOR detectors no longer flag bare sequential integers** — `authzutil.ClassifyParam` drops the value signal for a plain sequential integer lacking both an identifier-shaped name and a resource-noun path context, so telemetry/pagination/status params (`page_number=5`, `responseStatus=200`) stop being misreported. Wired into `idor-guid` and `idor-params-detect`.
- **Passive server-side detectors skip client build bundles** — `jsframework.IsClientBuildArtifact` skips immutable framework output (`/_next/static/`, `/_nuxt/`), where server-only constructs are compiled out, so a shared vendor chunk no longer yields one false positive per host. Applied across the Next.js/Nuxt/server-action detectors and `cache-data-leak`.
- **Differential detectors confirm against non-determinism** — `http-method-tampering` and `race-interference` add determinism controls so a per-request token/nonce or SSR variance between legs isn't mistaken for a method-override or race divergence.
- **Discovery extension-fuzz gating** — deparos trusts a start URL's `.aspx`/`.php`/`.jsp` suffix as a stack signal only when the URL was actually *served* as that extension (2xx/401/403, not a 3xx/404/5xx recon seed), plus a per-extension catch-all guard (two random `<nonce>.<ext>` probes) so an SPA/CDN that 200s any path isn't fingerprinted into a wrong-stack wordlist fuzz.
- **Lower-signal passive findings recalibrated** — `oauth-facebook-detect` and `graphql-introspection-detect` → Info; `serialized-object-detect`, `jackson-deserialize-detect`, `sensitive-api-fields-detect`, `api-pagination-leak`, `auth-headers-detect` → Low; `jwt-claims-detect` now grades per-issue (hygiene → Low, `alg=none` → High); `postmessage-handler-detect`, `javascript-uri-sink`, `openredirect-params`, `input-reflection-detect`, and `unsafe-html-sink` gained value-shape/context gates.

### Internal

- New shared helpers `modkit.IsNonHTMLReflectionContext`, `modkit.MatchWithinSpan` + `modkit.MaxErrorSignatureSpan`, `jsframework.IsClientBuildArtifact`, the `authzutil.ClassifyParam` sequential-int gate, and `secret_detect.PatternLabel`; `format_screen.go` renders any finding's `Metadata["pattern"]` as a leading bracket. Regression tests added alongside each hardened module.

## [v0.1.44-beta] - 2026-07-01

A false-positive-hardening release. Path-probe exposure modules no longer confirm on their own last path segment reflected into a content route, several injection detectors no longer self-trigger on an endpoint that merely echoes the rejected payload back, and secret-detect treats copy-paste sample credentials on documentation pages as low-value.

### Fixed

- **Path-probe exposure modules ignore their own reflected slug** — a marker that is just the probe's last path segment (`filament` for `/filament`, `redoc` for `/<dir>/redoc`, `healthchecks-ui` for `/healthchecks-ui`) self-matched when a content/SEO route echoes the requested slug into the page (a `/topic/filament` route rendering "Filament Lenses" in the title/JSON-LD/canonical link). A new slug-reflection control probes a nonexistent sibling carrying a distinctive canary and drops the finding only when the route reflects that canary into a 200 response. Applied to **`laravel-admin-exposure`** (bare `filament`/`Filament` tokens dropped in favor of structural anchors like `filament-panels`, `/filament/assets/`, `fi-sidebar`), **`swagger-exposure`**, and **`aspnet-health-exposure`**.
- **`struts-ognl-injection` confirms the addHeader variant via a real response header** — the `struts2-ct-ognl` payload sets `X-Struts-Test` via OGNL, but a gateway that rejects the request (415/400) commonly echoes the injected `Content-Type` verbatim into the error body and into other header values (e.g. gRPC's `Grpc-Message`), forging both `X-Struts-Test` and the baked marker with no OGNL ever running. Detection now keys on `X-Struts-Test` being a genuinely parsed **response header**, and confirmation re-injects a fresh random marker and requires it back as a real header each round.
- **Injection detectors strip the reflected payload before matching** — a new `modkit.StripReflected` removes the injected payload from the response before signature matching, so an endpoint that merely rejects and quotes the input back (a 400 "invalid input: `<payload>`") can't self-trigger. Fixes **`insecure-deserialization`** (PHP's `O:8:"stdClass":0:{}` wire form matched the `O:\d+:"..."` error pattern) and **`xxe-generic`** (the internal-entity probe carried its own success marker as the entity value); **`nosqli-error-based`** now uses the shared helper, and the `struts-ognl-injection` arithmetic variant strips the payload as defense in depth.
- **`secret-detect` downgrades documentation-page demo credentials** — a secret-shaped string served as rendered page content from a docs/reference/manual/CLI/tutorial route (Supabase's `supabase-demo` anon/service_role JWTs, local-dev `postgresql://postgres:postgres@…` URLs, placeholder connection strings) is almost always an illustrative sample, so it drops to **Low/Tentative**. Gated on both the route and an HTML/RSC (`text/x-component`) content type, so a JWT in a `/docs/_next/static/...` bundle or a live token in a docs-path JSON API still keeps full severity. A validated live secret always outranks this to Critical. Wired into both the passive flush and the known-issue-scan path.

### Internal

- New shared path-decomposition and slug-reflection helpers in `modkit/pathprobe.go`: `splitProbePath`, `PathSegmentReflected`, `SlugReflectionFP`, and a slug-reflection control folded into `MatchAndConfirmSibling` (grouped callers pass only the anchor; flat-marker callers pass every matched marker). `modkit.StripReflected` is the request-body analogue of `StripReflectedProbePath`. `secret-detect` gains `IsDocDemoSecretContext` (plus the `docRouteSegments` set and content-type gate) and threads the response `Content-Type` through its batch entries.

## [v0.1.43-beta] - 2026-06-30

A scope-isolation fix release. The known-issue-scan phase, dynamic-assessment, and the scan-completion summary now restrict themselves to the exact origins (scheme + host + port) actually being scanned, so records left in a shared project by prior scans of other origins no longer leak into a run's targets or counts.

### Fixed

- **`known-issue-scan` no longer scans origins outside the current scope** — the Nuclei and Kingfisher secret-scan legs previously pulled *every* record in the project DB, so targets/response bodies from earlier scans of unrelated origins (e.g. leftover `localhost` records in the default project) were silently scanned alongside the current target. Both legs are now restricted to the same in-scope origins `dynamic-assessment` uses; with no CLI targets/scope it falls back to a project-wide pass, matching `dynamic-assessment` semantics.
- **Record scoping now matches scheme + host + port, not just hostname** — `dynamic-assessment`, `known-issue-scan`, spidering, discovery, and the targeted re-spider select DB records by the CLI target's full origin, so a different port on the same host left by a *prior* scan (e.g. `localhost:8080` while targeting `localhost:3000`) is no longer pulled in. Default ports are normalized (https→443, http→80) so `https://example.com` matches its stored records.
- **In-scan discoveries are always scanned, regardless of port** — a host found during the *current* scan (a subdomain on the target's scheme/port, or a different-port service from the `--intensity deep` port sweep or a followed cross-port link) is scanned even when its origin differs from the CLI target's. Provenance is keyed on the scan's start time (records carry no `scan_uuid`), so this scan's discoveries are kept while prior scans' leftovers stay out.
- **The "Native scan completed" summary counts only the scanned origins** — record and finding totals were previously a raw count of the *entire* database (no project filter, no host filter), inflating the summary with leftovers from prior runs. The record count is now scoped to the current project and in-scope origins; the finding count is scoped to the project and in-scope hostnames (the findings table carries no scheme/port column).

### Internal

- New `Repository.InScopeHosts` resolves the in-scope origins from CLI targets + scope config + DB state (single source of truth for the runner phases and the summary): an origin is in scope when its hostname passes the scope matcher AND either its (scheme, port) matches a target OR it was discovered during the current scan (records created at/after the scan start). The DB input sources gain `WithHostScopes`, and `GetDistinctPaths`/`GetRecordsWithResponseBody`/`GetReSpiderCandidates`/`CountRecordsAfterCursor` take an optional variadic `HostTarget` origin filter that is a no-op when empty.

## [v0.1.42-beta] - 2026-06-28

A performance and false-positive-hardening release. The CLI gains an opt-in update check, the evaluated-math and reflected-value detectors now confirm a match tracks fresh inputs instead of a fixed substring, and a broad hot-path sweep cuts allocations and blocking work across deduplication, the database, discovery, and HTML analysis.

### Added

- **Startup update check (`vigolium update`)** — Vigolium now checks the npm registry at most once every 24 hours (cached in `~/.vigolium/update-check.json`, 1.5s timeout, fetched in the background) and prints a one-line upgrade notice after the run when a newer `@vigolium/vigolium` is available. The notice is suppressed for `--json`, CI, non-TTY/piped output, and the `version`/`update`/`init` commands. Set `VIGOLIUM_AUTO_UPDATE=1` to silently install the new version and re-exec the original command; set `VIGOLIUM_DISABLE_UPDATE_CHECK=1` to turn the whole thing off.

### Fixed

- **`reflected-ssti` and `struts-ognl-injection` confirm the evaluated result tracks fresh operands** — both detectors previously matched a single hard-coded product (`1970×2024` for SSTI; a fixed constant for OGNL) appearing anywhere in the body, which collides with incidental numbers (product ids, file sizes, timestamps). Each now re-injects the winning payload with two rounds of fresh random operands and requires the newly *computed* product to appear each time. This also repairs `struts-ognl-injection`, whose hard-coded result string (`1614244871`) didn't equal the operands it claimed (`41273×39127 = 1614888671`), so genuine detections were being silently dropped — the marker is now computed, not hardcoded.
- **`web-cache-poisoning` confirms generic header values actually reflect** — short, common probe values such as `X-Forwarded-Port: 1337` or a scheme override matched on a single coincidental substring (an asset hash, a story id). The detector now re-injects two fresh, distinct values (a random high port, a canarized scheme token) and requires each to reflect the same way before flagging.

### Performance

- **Lower-contention deduplication** — `DiskSet` lookups take a read lock and escalate to a write lock only for genuinely new keys, and request hashing no longer materializes per-insertion-point body copies when body hashing is off (the default), unblocking the 60+ modules that share one dedup set.
- **Off-hot-path database writes** — DNS resolution for saved records moved to a bounded background pool (no more ~5s blocking timeouts on the write path; IP is now best-effort metadata), record dedup collapsed from a per-record `SELECT` on each worker to one batched lookup in the flush goroutine, and a new covering index makes the scan-status severity aggregation index-only.
- **Cheaper per-request and per-module work** — `IsMediaPath`/media-class results are memoized on the request, `GetMethod`/`GetPath` scan only the request line, the tech registry serves read queries via lock-free `Peek`, the discovery enabled-module set is memoized, and the anomaly HTML extractor shares one lazily-built DOM index across its ~18 attribute checksums instead of re-walking the tree each time. Hot-path regexes and string formatting were hoisted/precompiled throughout.

## [v0.1.41-beta] - 2026-06-27

A finding-deduplication and false-positive-hardening release. Out-of-band (OAST) callbacks now collapse to one finding per planted payload, the secret detector ignores build-tool content-hash maps and folds repeats of a single rule, and the path-traversal / forbidden-bypass family confirms the target isn't already reachable by a plain request.

### Fixed

- **OAST callbacks collapse to one finding per planted payload** — a single out-of-band payload normally triggers a burst of callbacks (DNS `A` + `AAAA`, several recursive resolvers hitting the authoritative server, then the HTTP-fetch leg), and each previously became its own finding sharing one callback host. Findings are now keyed by the callback nonce and coalesced by protocol strength: duplicate or weaker callbacks fold into the existing finding, while a strictly stronger callback (the HTTP fetch confirming an earlier DNS lead) upgrades it in place. The command-injection modules also mint a **unique OAST host per breakout variant** instead of sharing one host across all payloads, so a callback pinpoints the exact shell payload that fired.
- **`command-injection-oast` and blind-SSRF downgrade proxy-reflected host headers** — a unique OAST host placed in `X-Forwarded-Host`, `X-Forwarded-Server`, `X-Host`, `X-Original-Host`, `X-Original-URL`, or `X-Rewrite-URL` is routinely reflected by a reverse proxy into a redirect `Location` / upstream URL that the proxy (or a redirect-following client) then fetches — an outbound request with no shell or server-side SSRF involved. A shared `isProxyReflectedHostHeader` set now downgrades both the DNS and HTTP callbacks on these headers to informational, replacing the single hard-coded `X-Forwarded-Host` check; genuine parameter-based SSRF and client-IP headers (`X-Forwarded-For`, `Referer`, `Origin`, …) stay high.
- **`secret-detect` ignores build-tool content-hash manifests** — a new structural `IsChunkHashManifestMatch` guard recognises when a fixed-width / high-entropy rule clipped its "secret" out of a webpack/Vite/rspack chunk-hash map (a minified bundle ships dozens to hundreds of identical-shape lowercase-hex hashes). A response that genuinely leaks one short hex credential carries at most a handful of unrelated hashes, never a map of them, so the match is dropped. Wired into both the passive flush and the known-issue-scan path via the shared `IsNonSecretMatch` chain.
- **`secret-detect` folds repeats of one rule while keeping distinct secrets apart** — a new **by-rule** grouping mode collapses findings on `(module, rule_name, severity[, host])`, so one Kingfisher rule (e.g. "Looker Client ID") matching every hash in a bundle's content-hash map becomes a single finding (all values unioned on), while a genuinely different secret — an AWS key, a Slack token — keeps its own row. Distinct from the by-module mode, which would wrongly merge unrelated secrets under one finding.
- **Path-traversal and forbidden-bypass detectors confirm the target isn't reachable cleanly** — a "clean-canonical control" now verifies that the file/route a bypass appears to reach isn't already served by a plain, un-mangled request (a public file at the web root, an app catch-all shell, or a resource that simply became public since the crawl-time `401`/`403` baseline). Added to **`path-normalization`** static traversal, **`nginx-off-by-slash`**, **`php-path-info-misconfig`**, **`cdn-object-traversal-listing`**, **`forbidden-bypass`**, and **`nextjs-middleware-bypass`**.

## [v0.1.40-beta] - 2026-06-26

A false-positive-hardening release. Several detectors that fired on a name or substring match now require structural proof, and the secret detector gains per-URL deduplication, two new reflection/source-code guards, and an inline matched value in the finding body.

### Fixed

- **`secret-detect` no longer reports public OAuth client IDs as leaked secrets** — a Google OAuth client ID (`NNNN-xxxx.apps.googleusercontent.com`) is the public half of an OAuth client, embedded in every sign-in button by design, so it now drops to **Info/Tentative**. The paired client *secret* is a separate match and keeps full severity.
- **`secret-detect` drops JavaScript source artifacts matched out of unicode escapes** — a new structural `IsJSEscapeArtifactMatch` guard recognises when a fixed-length / high-entropy token rule clipped its match out of a `\uXXXX` / `\xXX` escape in a minified bundle (e.g. Angular's `ɵ`-prefixed exports), which is source code, not a credential. The check is body-located and conservative, so a genuine secret in the same bundle is still reported.
- **`secret-detect` downgrades values reflected from the request** — a matched value that appears verbatim in the request URL or raw bytes (the dominant case: a Cloudflare Access application id in a `/cdn-cgi/access/verify-code/<app-id>` SSO URL echoed into the login page) is client-supplied input the server merely echoed, not a newly leaked server-held secret, so it drops to **Low/Tentative**.
- **`secret-detect` collapses the same secret re-observed on one URL** — the same `(host, url, rule, snippet)` leak is now emitted once across the discovery / spidering / re-spider / dynamic-assessment passes (and across records in the known-issue-scan batch), so near-identical request/response copies no longer pile up as redundant Additional Evidence. Distinct secrets on a single URL (e.g. a `client_id`, `client_secret`, and `access_token` in one response) are no longer merged by the URL-keyed finding dedup — secret-detect is excluded from that pass and deduped by value instead. Every secret finding's description now ends with the matched value inline.
- **`csrf-verify` only fires on a cross-site-forgeable request** — token enforcement is now checked only when the request is actually CSRF-able: a simple/form content type, no header-based auth (`Authorization`), and an ambient `Cookie`. A `*token*`-named field in a JSON/XML body (a CORS non-simple request that can't be auto-submitted cross-origin) is application data, not an anti-CSRF token — closing the false positive on a Cloudflare RUM beacon's JSON `siteToken`. The token-name pattern is also anchored (`\btoken\b`) so camelCase app fields like `accessToken`/`deviceToken` no longer match.
- **`wp-user-enum` requires a per-author leak, not a generic redirect** — adds a baseline control (an author id far beyond any real account), an edge-block guard (`IsBlockedResponse` for WAF/SSO/maintenance pages), a uniformity guard (multiple `?author=N` ids collapsing to one slug is a catch-all, not enumeration), and rejection of author-id echoes (`/author/1` → `/author/1.html`), WordPress' own routes, and error/status-shaped slugs.
- **`drupal-user-enum` rejects self-canonicalised UID echoes** — a redirect whose captured segment is just the requested id echoed back, bare or with an appended extension/selectors (e.g. AEM canonicalising `/user/1` → `/user/1.html`), is no longer mined as a leaked username.
- **`cors-headers-detect` only flags credentialed CORS on true cross-origin reflection** — credentials enabled alongside a specific origin is now reported only when the response echoes the request's `Origin` *and* that origin is cross-origin to the target host. A fixed allow-list entry or a site reflecting its own origin (e.g. a Cloudflare RUM telemetry beacon) is the normal, safe pattern and is no longer flagged.

## [v0.1.39-beta] - 2026-06-24

Adds a no-database `fs` export format and a live filesystem mirror for the ingestion server, so a coding agent can investigate a scan or watch ingested traffic with `ls`/`grep`/`jq`. Also tightens the spider's `max-duration` so it can no longer run past its deadline.

### Added

- **`--format fs` — a flat, browsable filesystem export** — writes `<base>-traffic/` + `<base>-findings/` trees (per-host raw `.req`/`.resp.*` files, finding `.md` files cross-linked to their request, and a jq-friendly `index.json`) so a scan can be triaged with no DB. Available on `export`, `db export`, and the `scan`/`scan-url`/`scan-request`/`run` family; honors `--omit-response`.
- **`vigolium server --mirror-fs <dir>`** (config `server.mirror_fs_path`) — mirrors every saved HTTP record and finding to a live `<dir>/traffic` + `<dir>/findings` filesystem tree as they are persisted, in addition to the database, so an external agent can read ingested Burp/proxy traffic as files in real time. Wired through new optional `Repository.OnRecordSaved`/`OnFindingSaved` callbacks that never block the DB save path; per-host id numbering resumes across restarts.

### Fixed

- **The spider now honors `max-duration` during in-flight browser operations** — the crawl deadline is bound onto rod's per-operation CDP timeouts (navigation, `WaitStable`, clicks, element lookups, form fills) rather than only being polled between actions, so an individual blocking browser op can no longer push the crawl far past its budget. Browser-level teardown is also bounded so a wedged browser can't hang shutdown.
- **Spidering gains an overall phase budget ceiling** — each target still gets its full `max-duration`, but the whole phase is capped at `max-duration × min(targets, 8)`, so a large merged target list (CLI targets plus many in-scope DB hosts) can no longer stretch spidering out to `len(targets) × max-duration`.
- **Further false-positive hardening** in the `path-normalization` traversal detector and the `cdn-object-traversal-listing`, `auth-headers-detect`, and `server-action-auth` modules.

## [v0.1.38-beta] - 2026-06-22

A false-positive-hardening release for the host-injection, blind-OAST, file-read, and header-leak detectors, plus a scan-resume convenience. Detectors that fired on a substring match now require structural proof, and a DNS-only command-injection callback on a forwarding header is no longer reported as a confirmed shell.

### Added

- **Bare `vigolium scan --resume`** — run with no other flags to auto-discover the `*.progress.json` manifest in the working directory, rebuild the original `-S -T --split-by-host -P` command from it, and relaunch — no need to re-type the full flag set. Pass `-o <prefix>` to disambiguate when several manifests exist.

### Fixed

- **Host-injection detectors require authority position, not a substring** — a new shared `modkit.HostReflectedAsAuthority` gate confirms the client-supplied host actually becomes the *authority* of a generated URL, rather than appearing as an incidental substring. This closes a CDN/OAuth false positive where `X-Forwarded-Host`/`Host` is reflected into a `redirect_uri=`/`continue=` query parameter of a 3xx whose authority stays the trusted IdP (nothing to poison), which a bare `strings.Contains` flagged High/Firm. Wired into **`proxy-header-trust`**, **`host-header-injection`**, **`express-trust-proxy-misconfig`**, **`web-cache-poisoning`**, and **`oauth-misconfiguration`**.
- **`command-injection-oast` grades confidence by callback proof** — a DNS-only callback proves a value was *resolved*, not that a shell ran. An HTTP-fetch callback (curl/wget) stays **Critical/Certain**; a DNS-only callback on a genuine parameter is **High/Firm**; a DNS-only callback on a client-IP / forwarding header (`X-Forwarded-For`, `X-Real-IP`, `True-Client-IP`) is downgraded to **Low/Tentative**, since edge infrastructure resolves those header values for geo-IP/logging with no shell running. Findings also reconstruct the real planting request (the actual `;nslookup <host>` payload) via a new OAST `RecordPayload` hook.
- **LFI / file-read modules confirm by file shape, not bare words** — a new shared `pkg/modules/shared/filesig` package requires the leaked file's real structural shape (a genuine `passwd` line, a bracketed `win.ini` section, an anchored nginx directive) with baseline subtraction, replacing bare-word markers (`server`, `location`, `root:`) that also appear in English, CSP directives, and JSON. Closes a Cloudflare 403 block-page reported as LFI. Wired into **`lfi-path-traversal`** (with a block/status gate), **`mcp-resource-fuzz`**, and **`mcp-tool-fuzz`**.
- **`sensitive-header-leak` downgrades redirect / auth-challenge artifacts** — a token-shaped value in a `Location`/`Www-Authenticate`/`Refresh`/`Proxy-Authenticate` header, or any sensitive value on a 3xx response, is now **Info/Tentative** rather than Medium/Firm — these are login-flow navigation artifacts, not deliberate secret leaks. A hit in a genuine custom header (e.g. `X-Api-Key`) keeps full severity.

## [v0.1.37-beta] - 2026-06-19

Adds resumable parallel scans: a stateless `-S -T --split-by-host -P` fan-out stopped with Ctrl-C can now be picked up where it left off.

### Added

- **`--resume` for the stateless parallel fan-out** — `vigolium scan -S -T <file> --split-by-host -P <n>` now writes a tiny line-cursor progress manifest (`<output>.progress.json`) tracking how far the contiguous run of cleanly-completed targets reached. Re-running the same command with `--resume` skips that prefix and scans only the remainder, while the final roll-up still reflects the whole batch (previously-completed hosts are folded in from the manifest). On Ctrl-C — or a failure — the summary prints a copy-pasteable resume command. The manifest stores only a cursor plus aggregate counts, never the target list, so it stays small for huge target files; out-of-order completions under `-P` are buffered so at most a handful of in-flight targets are ever re-scanned. The progress file is also surfaced on the scan banner's `Output:` line. Scoped to the stateless fan-out — the `--db-isolate` parallel path and the single-target/sequential split path are unaffected (the latter warns that `--resume` is fan-out-only).

## [v0.1.36-beta] - 2026-06-18

A hotfix release for a schema-migration ordering bug that could break an upgraded database.

### Fixed

- **`CreateSchema` no longer aborts on a pre-existing database missing a migration-added column** — v0.1.35 added `http_records.response_norm_hash` together with an index on it (`idx_records_norm_hash`), but on a database created by an older binary the index-creation loop ran *before* the column-add migration. `CREATE INDEX` then referenced a column that did not exist yet, errored, and aborted schema init entirely — leaving the server's repository `nil` and breaking a swathe of endpoints. The index loop now runs after all `addColumnIfNotExists` migrations, so an upgraded database heals itself (adding both the column and its index) instead of failing to open. Added `schema_migration_test.go` covering the legacy-DB heal path and `CreateSchema` idempotency.

## [v0.1.35-beta] - 2026-06-17

A performance and false-positive-hardening release. The native-scan hot path and ingest write path shed redundant allocations and DB work, and the discovery engine's server-side extension-confirmation gate gains two catch-all guards so an SPA/catch-all gateway that bounces or echoes every guessed path can no longer confirm (and then wordlist-fuzz) a phantom stack. The workbench HTTP-records page gains a source filter and a curl export.

### Added

- **Workbench: source filter + curl export on the HTTP records page** — a source dropdown filter and an always-visible clear-filters button let you scope the records list by ingestion source, and a new curl export helper copies any record as a ready-to-run `curl` command. Detail-panel updates and regenerated static UI assets ship alongside.

### Performance

- **Fewer allocations and less DB work across the scan pipeline** — the executor now uses struct-keyed per-host claim LRUs and reuses the baseline-request hash for finding↔record links, the request builder gains a single-allocation body + `Content-Length` fast path, `modkit` reconfirm gets an allocation-free tokenizer, host rate-limit acquisition is context-aware, and many active scanners wrap the raw request directly instead of re-parsing it. On the database side, ingest writes are slimmed (metadata-only FTS index, a covering dedup index, projected scan-record column reads, batched remarks updates) and a new `DB.Optimize` refreshes query-planner stats on checkpoint/close.

### Fixed

- **Extension confirmation no longer trusts a path-preserving redirect** — a redirect that merely bounces a request back to the same path it asked for (`/x.php` → `/x.php` for an HTTP→HTTPS upgrade, an auth/cookie round-trip, or host/trailing-slash normalization) fires at the gateway before any handler runs, so it is no proof the server executes that extension. Because each such `Location` is per-path-distinct it also slips past the wildcard soft-404 filter, which on a catch-all/SPA gateway would otherwise let every guessed stack extension confirm — and get wordlist-fuzzed — at once. The new `redirectPreservesPath` guard withholds the extension confirmation in that case; names and paths are still harvested.
- **Extension confirmation refuses a second, incompatible server stack** — a single application serves exactly one server-side stack family (PHP xor classic/modern ASP.NET xor Java/JSP/Struts xor ColdFusion xor CGI). The confirmation gate (`reserveExtension` + `serverStackFamily`) now checks the family under one lock: once one family is confirmed, a second incompatible one is a signal the host is answering for extensions it does not run — a catch-all/SPA gateway echoing every guessed path — so it is refused rather than fuzzed. The first family confirmed still fuzzes normally.

## [v0.1.34-beta] - 2026-06-16

A false-positive-hardening release for the differential and behavioral injection detectors. A new shared surface gate keeps the boolean-oracle modules off cache/CDN-fronted and large dynamic-HTML pages, every boolean-blind SQLi probe is now WAF/CDN-block aware, and curated payloads are re-confirmed with randomized operands to defeat the classic WAF `1=1`-tautology false positive. NoSQLi and default-credentials gain control/reproduction gates of their own. Also adds a repeatable `-T/--target-file` flag and a `finding --confidence` filter.

### Added

- **`-T/--target-file` is now repeatable** — pass it multiple times (`-T hosts-a.txt -T hosts-b.txt`) to merge several URL-list files into one run; lines from all files are read in order and concatenated. Plumbed through `scan`, `ingest`, the ingestor client, the high-level runner, and the shared input-source builder, so an ingest from preloaded stdin/`-i` still folds in any `-T` files instead of dropping them, and an `-T`-only run no longer blocks waiting on a TTY. (Internally `Options.TargetsFilePath string` → `TargetsFilePaths []string`.)
- **`finding --confidence <certain,firm,tentative>`** — filter findings by confidence label (comma-separated), mirroring `--severity`. The `CONFIDENCE` column now also shows by default in the `finding` table and is colorized (certain→purple, firm→yellow, tentative→gray) in line with the other summary lines.

### Changed

- **`client-prototype-pollution` recalibrated to Medium/Tentative and gated on a reachable URL source** — the module is a static-analysis heuristic (it only verifies the URL is reachable, never that a prototype was polluted at runtime), so its blanket High/Firm verdict was overstated. Severity now tracks the evidence: a bare source pattern is **Medium**, an actual high-impact gadget (innerHTML/eval/document.write reading attacker-controllable keys) raises realistic impact to **High**, and confidence stays **Tentative** throughout. Generic "sink-only" shapes (deep-merge / recursive bracket-assignment) that a safe object clone shares with a vulnerable URL-param parser are now reported only when an attacker-controllable URL source (`location.search`/`hash`/`href`, `URLSearchParams`, …) sits within proximity of the sink, dropping benign library code (analytics serializers, script loaders, framework helpers) that merely shares the shape. Patterns that embed their own URL source still fire on the pattern alone (FN-safe).

### Fixed

- **Differential-oracle modules now skip unreliable surfaces** — a new shared `modkit.DifferentialSurfaceUnreliable` gate (header/size only, sends no traffic) flags a response as an untrustworthy boolean-differential surface when a cache/CDN layer fronts the origin (an `X-Cache`/`Age` cache state — a HIT can answer one probe while an origin renders the next) or when the body is a large (≥100 KiB) rendered `text/html` content page whose per-request dynamic content (ads, recommendations, rotating blocks) dwarfs any real true/false difference. The size gate is `text/html`-scoped, so JSON / auth endpoints — the real injection-oracle surface — are never affected, and a missing baseline fails open. Wired into **`sqli-boolean-blind`**, **`ldap-injection`** (the boolean pass only; the error-token pass still runs), **`ssti-detection`**, **`smart-behavior-detection`** (also a meaningful speedup — it is the slowest active module), and **`nosqli-operator-injection`**.
- **`sqli-boolean-blind` no longer fires on WAF/CDN tautology signatures** — two long-standing false-positive classes are closed. (1) Every probe is now WAF/CDN-block aware: a blocked TRUE or FALSE branch is the *edge* reacting to a payload signature (the literal `1=1`, the `/**/`-comment evasion form), not the application's SQL logic, and it kills the pair (or the whole insertion point on a blocked baseline) — the single most common boolean-blind false positive. (2) Curated / bypass / WAF-evasion payload pairs are re-confirmed with **randomized operands** (`confirmRandomized`): the matched comparison is rebuilt with fresh random numbers while the surrounding boundary, token separator, comment terminator, URL-encoding, and evasion mutation are preserved, so a differential bound to boolean truth reproduces while one bound to the literal `1=1` token vanishes and is rejected. This defeats the textbook `Accept-Language: '/**/OR/**/1=1--` finding where a WAF's standalone `1=1`-tautology signature blocks the TRUE branch and passes the FALSE one. Header insertion points are held to the higher bar (rejected outright when operands can't be re-derived, never falling back to repeat-only confirmation), and content-negotiation request headers (`Accept`, `Accept-Language`, `Accept-Encoding`, `Accept-Charset`) — whose response legitimately varies and almost never reaches a SQL backend — are excluded from testing.
- **`nosqli-operator-injection` boolean path hardened against scheduling and inert-surface noise** — three additions cut phantom differentials: (1) a benign, operator-free **control** value is sampled on the same interleaved cadence as the true/false probes, and if it isn't self-consistent the endpoint's per-request variance is correlated with the request schedule (round-robin upstreams, alternating cache HIT/MISS), so any true/false divergence is a scheduling artifact rather than a query boolean; (2) a surviving differential must **reproduce with a second set of always-true/always-false constants** (`9==9`/`9==8`, `4==4`/`4==5`) before it is reported, so a one-off transient (a cache miss, a momentary content variant) can't satisfy it; and (3) URL-path-segment and header insertion points are **inert-prechecked** — a benign value that returns the same page as the baseline marks a cosmetic catch-all segment or a header the app never consumes, where a boolean differential is noise. Plus the shared surface gate above.
- **`default-credentials` confirms a login before reporting it** — the failed-login baseline is now drawn from **two** independent invalid-credential probes that must agree, proving the login surface is stable enough to trust a differential (a page with a rotating CSRF token or dynamic chrome no longer manufactures a phantom success, and a single anomalous baseline can't poison every comparison). A candidate success must then **reproduce on re-send and be materially distinct from a fresh random-invalid negative control**, so plain login-page variance isn't mistaken for authentication. WAF/CDN blocks are recognized and skipped (neither a success nor a lockout), and a success indicator that *also* appears in the failed-login body (e.g. "dashboard" on `dashboard.example.com`) is treated as page chrome rather than evidence of a login.
- **`import` reads JSONL lines of any size** — the importer switched from `bufio.Scanner` to a growing `bufio.Reader`, so an exported `http_record` carrying a multi-megabyte request/response body on a single line no longer overflows the scanner's fixed token cap ("token too long") and aborts the import.
- **Parallel per-target stats render under `--format sqlite`** — the `-S -T --split-by-host` parallel rollup recovered each child's record/finding counts only from a JSONL export; it now falls back to the child's standalone `.sqlite` export (opened read-only, query-only, no WAL sidecar next to the operator's artifact), so the per-target stats segment and the final Totals line still show when the operator requested `--format sqlite,html` without `jsonl`.

## [v0.1.33-beta] - 2026-06-16

A performance and memory-footprint release: unbounded caches across the long-lived server become bounded LRUs, SQLite WALs are kept compact, and the native-scan hot path sheds redundant allocations. Adds a standalone `--format sqlite` export, stateless reads of `.jsonl`/`.sqlite` files, and Markdown rendering for findings and traffic.

### Added

- **`--format sqlite`** — dumps the run's standalone DB to `<output>.sqlite` via `VACUUM INTO`; requires `-S/--stateless` + `-o`, combines with other formats, and names per-host files under `--split-by-host`. Aliases: `sqlite3`, `db`.
- **`finding`/`traffic -S/--stateless`** — read a `--db` source (a `--format jsonl` export or standalone `.sqlite`) directly with project scoping off; nothing is written to your project DB.
- **`finding`/`traffic -m/--markdown`** — render matched findings/records as Markdown (request/response in fenced `http` blocks) to stdout; under `-S`, `--compact` windows the response around the match.

### Performance

- **Unbounded maps → bounded LRUs across the long-lived server** — the per-host run-once claims, storage-host set, OAST nonce tracker, per-host Tech/WAF/ContentClass registries, the ParameterFinding dedup registry, and the transcript-sequence counter were all process-lifetime leaks in a scan-on-receive server. Each is now a capped LRU; eviction only forgets a cached hint or run-once claim, so at worst a stale entry is re-derived/re-fired once.
- **SQLite WAL kept compact** — a background TRUNCATE checkpointer (every 5m) plus per-connection `wal_autocheckpoint`/`mmap_size`/`temp_store` tuning and an on-open checkpoint stop the ingest DB's WAL ballooning over a multi-day run; reader pool raised 4 → 8.
- **Disk-backed dedup set bounded** — `DiskSet` caps its keyspace (default 1M keys, batched eviction) so a process-lifetime dedup manager can't grow LevelDB without limit. FN-safe: an evicted fingerprint is re-processed once and re-deduped at the DB layer.
- **Native-scan hot path allocations cut** — single-allocation insertion-point splice (was N reallocs/fuzz), baseline response composed into one pooled buffer, body hashed only when stubbed/truncated, and `--with-records` batch-loads linked records in one query (no N+1).
- **Bounded memory on big scans/audits** — the re-spider phase pages candidates body-free instead of holding 5000 bodies at once; the coverage probe and code-audit query metadata-only (skip `raw_request`/`raw_response` BLOBs) when they need only method/URL.
- **Fewer doomed goroutines/writes** — module dispatch fast-exits an already-cancelled context; `DBInputSource` coalesces a run of acks into one cursor UPDATE; the disk-queue Ack deletes the record instead of rewriting it; the server sheds the heavy `Result`/`SwarmResult` blobs from the status map once persisted.

### Fixed

- **`rails-info-exposure` / `rails-sensitive-files` blank-body catch-all FPs** — a blank `200` on `/up` or `/tmp/local_secret.txt` (a catch-all/CDN placeholder) slipped past the soft-404 fingerprint and was reported as a health check / leaked secret. The markerless paths now reject an empty body, and the local-secret case requires an anchored hex token.
- **Host rate-limiter no longer evicts an in-flight host** — forced-cap eviction could pick a host with acquired-but-not-released slots, orphaning its semaphore accounting; it now evicts the least-recently-used *idle* entry (or briefly exceeds the soft cap if all are busy).
- **Disk-queue segment data race** — `tryDequeue`/`Ack` ranged over `q.segments[:]`, aliasing the backing array mutated concurrently by segment create/cleanup; they now copy the slice under the lock.
- **Combined audit keeps running after client disconnect** — a dropped SSE stream during a `driver=auto/both` run left the multi-hour subprocess running against nobody; the SSE pump now cancels the run on first write error.

## [v0.1.32-beta] - 2026-06-15

### Changed

- **`balanced` intensity now runs the `intrusive` tier** — `balanced` resolves to the `intrusive` ceiling instead of `heavy`, so the default scan runs the full module battery (including `internal-header-probe`). The aggressiveness-tier gate now only trims modules on a `quick`/`lite` pass; `balanced` and `deep` share the same tier ceiling (`deep` still differs via its other deep-only behaviors). `internal/runner/module_tiers.go`.

## [v0.1.31-beta] - 2026-06-13

A reachability-and-recon release: an alternate-port sweep that finds web services running off the standard ports, TLS-certificate recon that mines self-signed and private-CA certs for subdomains and internal names, and default-credential checks that try documented vendor defaults against confirmed third-party consoles. It also makes the native scan intensity-aware — modules now run up to an aggressiveness tier set by `--intensity`, passive analyzers skip responses of the wrong body shape, and value-only-different GET URLs collapse to a few representative samples.

### Added

- **Discovery mines the JS that earlier phases already collected** — the discovery crawl previously only ran jstangle/linkfinder on JavaScript it fetched itself, so a framework bundle the browser spider captured (e.g. a Salesforce Aura/Lightning app bundle) sat in storage unparsed and its embedded routes were never requested. Discovery now, at init, walks the stored responses and feeds every captured JS body through the same jstangle + linkfinder extraction (reusing the already-stored body — nothing is re-fetched), so endpoints that appear only as strings inside a bundle become observed paths and extracted requests. This recovers routes that only ever exist in JS — notably a Salesforce captcha iframe (`/apex/APP_Login_NewCaptcha?source=…`) whose iframe mounts only after the login form is interacted with, but whose route is a literal `src` string in the Aura bundle the spider already grabbed; the query param is preserved so the endpoint is fetched with its reflected parameter. New `extractRoutesFromStoredJS` in `pkg/deparos/discovery`.
- **Alternate-port sweep** — a new `port-sweep` native phase (backed by `pkg/portsweep`) probes each original CLI target host for web services running off the standard ports. For every target host it TCP-connects a curated list of common alternate HTTP(S) ports (`3000`, `5000`, `8000`, `8008`, `8080`–`8083`, `8088`, `8888`, `9000`, `8443`, `9443`) concurrently, HTTP-confirms the open ones, and appends any confirmed web service to the target set *before* the ingestion/scan phases consume it, so a console on `:8443` or a dev server on `:3000` flows through the normal pipeline instead of being missed. A honeypot guard discards a host whose ports are nearly all open with near-identical responses (an all-ports-open tarpit; open/probed ratio ≥ `0.7`). Bounded by a 512-host cap (excess hosts announced, never silently dropped) and per-host/outer-host concurrency limits. Off by default and auto-enabled at `--intensity deep` or under `--follow-subdomains`; the port list is overridable per-run with `--port-sweep-ports` and configurable under `scanning_strategy.port_sweep` (`ports`, `concurrency`, `dial_timeout_ms`, `http_timeout_ms`, `honeypot_ratio`).
- **TLS certificate recon (`tls-cert-recon`)** — a new active per-host module completes a single TLS handshake per host and reads the leaf certificate for recon value without sending any application traffic. Certificates from recognized public CAs and CDNs (Let's Encrypt, DigiCert, Cloudflare, …) are ordinary and skipped; what remains — self-signed certificates and ones from a private or internal CA — is flagged (INFO/Certain) as a likely forgotten staging/admin/appliance host. From those certs it harvests Subject Alternative Names: sibling subdomains under the target's registrable domain (widening the surface) and internal-only names such as RFC1918/loopback IPs and `.local`/`.internal`/`.corp` hostnames (leaking internal naming and network layout).
- **Default-credential checks on confirmed dashboards** — once `dashboard-exposure` actively confirms a third-party console is present, it now submits that product's vendor-documented default credentials against the confirmed context path and escalates a working pair to a **Critical/Certain** default-credentials finding. Only documented default pairs are tried (never a brute-force wordlist, so it can't trigger account lockout), and every attempt is **negative-control gated** — a random credential pair must be rejected by the success matcher first, so a login form that "succeeds" on anything can't produce a false positive. The check runs once per `(host, product)`, draws from the shared per-host probe budget, and is driven by a new nuclei-template-derived `dashboardsig.LoginProbe` (per-product login path, request body, credential pairs, and success matcher). Shipped for 8 products: Grafana, GitLab, SonarQube, RabbitMQ, MinIO, Open WebUI, Apache Superset, and Node-RED. The module gains a `default-login` tag.

### Changed

- **`vigolium update` no longer prompts for confirmation** — the interactive "type 'yes' to confirm" gate (and its `-F/--force` bypass) was removed, so `update` proceeds directly to fetching the binary and nuclei templates.
- **Per-asset findings collapse to one finding per host** — the default finding-grouping `by_module` set (formerly just `sourcemap-detect`) now covers the source-analysis and per-response hygiene modules that fire once per JS bundle or page, so a single domain reports one finding apiece instead of one per asset. Added: `unsafe-html-sink`, `dom-xss-taint`, `dom-xss-detect`, `javascript-uri-sink`, `insecure-token-storage`, `cookie-security-detect`, and the framework/build/SSR audit family (`build-misconfig-detect`, `client-auth-guard`, `cache-data-leak`, `nextjs-config-audit`, `nextjs-dynamic-param-audit`, `nuxt-config-audit`, `nextauth-config-audit`, `server-action-{auth,bind-audit,input-audit}`, `server-only-boundary-audit`, `ssr-data-exposure`, `ssr-hydration-xss`, `remix-loader-exposure`). Grouping stays **per-host** (a finding on `a.example.com` never merges with one on `b.example.com`) and **per-severity**, and the merged survivor keeps every affected URL under `matched_at` (capped by `max_urls`, default 50). Secret-bearing modules such as `env-secret-exposure` are deliberately excluded — each distinct leaked value is signal, so they remain value-grouped (identical secrets collapse, different ones stay separate). Applies to both the stored/reported findings and the live console rollup; override via `known_issue_scan.group_by_value.by_module`.
- **`--intensity` now gates modules by an aggressiveness tier** — a module can declare a single tier tag in its `Tags()` advertising how expensive/aggressive it is (`light` recon/fingerprinting, `moderate` standard active testing, `heavy` blind/timing probes, `intrusive` rare high-side-effect checks), and the resolved intensity sets a ceiling on what runs: `quick` runs up to **moderate** (drops the heavy blind/timing probes and the intrusive checks for a fast pass), `balanced` runs up to **heavy** (the default — the full active battery minus intrusive, matching legacy coverage), and `deep` runs **everything**. A module with no tier tag (`TierAlwaysOn`) is ranked strictly below every tier and so is never excluded — core detectors like stored / DOM-confirm XSS run at every intensity. The gate is applied symmetrically to active and passive modules, and the deferred module IDs are logged (never silently dropped). New `pkg/modules/tier_tags.go` (`ModuleTierRank`) plus the runner-side ceiling in `internal/runner/module_tiers.go`.
- **Passive content-class gating** — a passive module that structurally requires a particular response body shape is now skipped on a record whose response is a confirmed *different* structured class, so an analyzer that could produce nothing on that body isn't run against it. Currently only the UI-redress modules opt in (`clickjacking` / `ui-redress` require an HTML document), via a tiny conservative tag→class map plus an explicit `ContentClassAware` interface. The gate **fails open** on unknown/`text` bodies, on content-agnostic modules, and when the tech filter is disabled (`--no-tech-filter`, or `deep`); the per-host root-page classification from heuristics seeds the registry and is consulted only when a record's own `Content-Type` is indeterminate. Passive-only by design — skipping a passive analyzer that can't parse the shape it was given can't hide a finding, whereas active modules often probe a host independently of the triggering record's body and so are intentionally left ungated. New `pkg/modules/content_class_tags.go`.
- **Param-shape GET coalescing in dynamic assessment** — the risk-prioritized dynamic-assessment input source now collapses redundant fan-out over URLs that differ only in query values (e.g. `/search?q=1..N`): GET records sharing a `(host, path, query-param-name-set)` shape are reduced to at most a few value-distinct representatives (default **3**, `dynamic_assessment.max_param_shape_samples`). It walks the already-risk-prioritized snapshot so the highest-value records claim the per-shape sample slots first. Only query-param-bearing GETs coalesce — other methods, body-bearing requests, and param-less GETs are always kept, so a request whose full shape isn't visible from the URL alone (e.g. a POST body) is never dropped. Records stay in the database; only this scan's iteration list is pruned, and the scan cursor still advances past coalesced-away records so they aren't re-scanned in a later feedback round. `0`/unset uses the built-in default of 3; a negative value disables coalescing. New `pkg/database/param_shape.go`.

### Fixed

- **Spidering now drives the login flow it used to abandon on SPA portals** — an unauthenticated visit to a heavy enterprise SPA (Salesforce Lightning, Angular portals, …) routinely bounces to a landing page whose "Log on" button kicks off an OAuth/SAML/SSO navigation chain (`… /oauth2/authorize → /idp/login → SAML → vendor login`). The browser crawler captured a half-rendered shell and never entered the flow, so its entire URL set — the OAuth authorize hop, the SAML redirect, the vendor login page and its own data XHRs — was missed. Three additive priming steps fix it, mirroring the existing service-worker / iframe priming: (1) **SPA bootstrap settle** waits for the landing's sequential bootstrap XHRs (config → region → i18n → feature-flags → content) to go network-idle *before* the state is snapshotted and clickables are extracted (bounded by `SPASettleTimeout`, default 12s), so the real UI — including the login CTA and the deep data calls — has actually rendered; (2) **consent-overlay dismissal** clicks cookie-consent "accept" controls (OneTrust et al., piercing shadow DOM) so the overlay neither blocks the render nor masks the CTA; (2b) **auto-scroll** drives the landing through its full height (window + the largest scrollable container, dispatching scroll events with a pause per step) so content and assets that load only as sections enter the viewport — IntersectionObserver-gated sections, infinite-scroll data fetches, deferred hero/bundled-media images — are actually requested and captured (`AutoScroll`, default on); (3) **login-CTA priming** finds the best login call-to-action and drives it once per crawl. Detection is shadow-DOM-piercing and tag-agnostic — it scores not just `<a>`/`<button>` but any genuinely clickable element (web-component apps render the real "Log on" as a `<div>`/custom element with a JS click handler), by visible label / auth-endpoint href / login-ish attributes, excluding logout controls and **non-interactive `aria-hidden`/disabled loading-skeleton placeholders** (a SPA shows one before the real button hydrates). It clicks the top candidates in turn — a real CDP click for true buttons, a synthetic (bubbling) click for web-component divs — until one actually changes the URL (it waits for the navigation rather than racing ahead and cancelling it), then lets the destination login page run its own XHRs (Aura `/aura`, `/c/*.app`, the captcha iframe) and returns to the landing so the normal crawl resumes. Bounded so a landing whose button never becomes interactive can't drain the crawl budget. All steps are on by default (`DismissConsent`, `LoginCTAPriming`, `SPASettleTimeout`, `AutoScroll`). The runner surfaces a `drove login CTA into the auth flow` line only when a click actually enters the flow. Two further pieces make this hold up on real enterprise portals: (4) **the spider now presents as a normal browser** — it strips `HeadlessChrome` from the User-Agent (keeping the real Chrome version) and pins `Accept-Language: en-US` (+ `--lang=en-US`); many SPAs gate their locale routing and content loading on a real UA + language and otherwise render only a blank shell that never routes to its localized landing (e.g. `/us/en-us/about`), so the content and login button never appear; and (5) **the login-CTA drive runs before form-filling**, because a cookie-consent preference form (OneTrust et al.) can carry dozens of controls that the form filler spends the per-element timeout on apiece, which would otherwise exhaust the spider budget before the login flow is ever driven. Detection also waits specifically while a login control is still hydrating (so a slow SSO-bounce landing is given time) but returns immediately on pages with no login affordance. With these, a start URL that bounces through an SSO portal to a localized content landing and back into a Salesforce-Lightning login now captures the whole chain end-to-end (portal data XHRs, `oauth2/authorize`, `idp/login`, the SAML `idp/endpoint/HttpRedirect`, `aura`, `c/*.app`). (Remaining gap: a captcha iframe that a vendor login mounts only after the form is interacted with isn't harvested by passive crawling.)
- **Redirect hops are now captured, not overwritten** — the browser network capture reused a single in-flight entry per CDP request id, so each `3xx` hop in a redirect chain was silently replaced by its target and lost. The intermediate URLs an SSO chain is *made of* — an OAuth `/oauth2/authorize`, a SAML `/idp/endpoint/HttpRedirect?SAMLRequest=…` that only ever appears as a redirect — therefore never reached the records table even when the browser requested them. `onRequestWillBeSent` now finalizes and emits the previous hop (with its redirect-response status/headers) before recording the redirect target, so every step of a redirect/auth chain is captured.
- **NoSQLi false positives cut hard; both modules normalized to High/Tentative** — `nosqli-error-based` flagged a minified pdf.js worker (served `application/javascript`) as a Critical MongoDB injection: a generic operator/expression token baked into the bundle matched a Mongo pattern, and an empty captured baseline disabled the present-without-payload guard. Several confirmation layers were added: (1) static assets / code bundles are skipped outright — by both captured content-type and URL path (`IsStaticAssetContentType`/`IsStaticAssetPath`, the latter extended with `.mjs`/`.cjs`), re-checked on the live fuzzed response; (2) the generic English/JS-ish patterns (`$expr`, `unrecognized expression`, `unknown operator`, `FailedToParse`) are now "weak" and believed only when an independent database/error-context marker sits **near** the match (windowed corroboration), while strong driver/class signatures still fire on their own; (3) a response-shape gate requires the body to actually look like an emitted error — a 5xx status, a JSON error envelope, or a stack trace — so a driver name in a normal 200 page is dropped; and the injected payload is stripped from the body before matching so a reflected operator can't self-satisfy a pattern. The sibling `nosqli-operator-injection` gained the same static-asset gate. Confidence is dialed down across the board to reflect that NoSQLi detections are behavioral/heuristic inferences: `nosqli-error-based` drops from Critical/Certain to **High/Tentative**, and the operator-injection auth-bypass and boolean-diff paths drop from High/Firm to **High/Tentative** (its weaker size-change and time-based paths remain Suspect/Tentative). Every finding now reads as a high-impact lead to verify rather than a definitive injection.
- **By-module finding grouping query** — the `GroupFindingsByValue` dedup pass built its `module_id IN (…)` clause with `bun.In` (which double-wraps the placeholder list into `IN ((?, ?))`) instead of `bun.List`, so the by-module grouping mode (e.g. `sourcemap-detect` collapse) could fail to match. Corrected to `bun.List`.
- **Laravel admin-exposure false positives on catch-all login shells** — `laravel-admin-exposure` flagged a Salesforce/Visualforce login page (served identically for every probed path, with a per-request ViewState token defeating the soft-404 hash/length fingerprint) as exposed Nova/Filament panels, because each probe matched on a single weak generic token (`login`, `email`, `admin`, `data`) inside an OR-list. The module now confirms structurally with `modkit.MatchAllGroups`: every probe requires a framework/endpoint-specific **anchor** (e.g. `laravel-nova`, `filament-panels`, `swagger-ui`, `"openapi"`+`"paths"`, `__schema`+`queryType`) plus corroboration, so a bare generic word can no longer fire. Bare-word `/admin` and `/backoffice` detection now requires a named admin package (Backpack/Voyager) rather than the word "admin"/"dashboard". The sub-directory catch-all guard re-checks the same marker groups against a nonexistent sibling path.
- **Same hardening applied across the path-probe exposure family** — auditing the sibling modules for the identical weak-single-OR-token pattern, the grouped-marker (`MatchAllGroups`) + group-aware catch-all guard was applied to: **fastapi-docs-exposure** (`/openapi.json` now requires the `"openapi"`/`"swagger"` version key, not a bare `"info"`/`"paths"`), **php-composer-exposure** and the Composer probes in **joomla-misconfig** (anchor on Composer-specific keys like `"_readme"`/`"content-hash"`/`"require"` instead of bare `"name"`/`"version"`), **joomla-misconfig** `com_ajax` (requires the full `{success,message,data}` envelope, configuration.php backups anchor on `JConfig`/`$secret`, manifests on `files_joomla`), **firebase-misconfig** (every config-file probe anchors on a Firebase-specific token — `.runtimeconfig.json` no longer matches a bare `{`, service-account files require `private_key` + a second key field), **java-appserver-console** (drops the generic `Oracle`/`Management Console`/`Web Console`/`Administration Console` words, anchoring on the product name), **tomcat-manager-exposure** (drops bare `Deploy`/`JVM`/`HTTP`, anchoring on the manager title + a corroborating action), and **sensitive-file-discovery** (`.vscode/settings.json` requires a VS Code setting-key prefix, not `{`/`}`). Directory-listing markers (`Index of`/`Parent Directory`) and already-framework-specific modules (django-admin, php-debug, symfony profiler) were left unchanged — `Index of` genuinely indicates a real listing, and those markers don't fire on catch-all shells.
- **`additional_evidence` capped at 5** — the per-finding evidence ceiling (request/response pairs folded in from duplicate findings, and pairs a module collects itself) dropped from 10 to 5, and the cap is now also enforced at the result-event→finding converter, so a noisy module that fires across many sibling paths of one host no longer balloons the stored payload (or the `http_records` rows it pulls in).

## [v0.1.30-beta] - 2026-06-12

A finding-fidelity and coverage release: context-path-aware exposure probing, secret findings that carry their evidence, probe-finding collapse to keep the traffic table clean, recovery of JS bundles and service-worker-precached assets that no link points at, passive recon harvesting with opt-in subdomain follow, third-party-dashboard detection, and targeted false-positive fixes.

### Added

- **Context-path-aware exposure probing** — new `modkit` path helpers (`CandidateBasePaths` / `CandidateBasePathsIncludingStatic`, `UnclaimedBasePaths`, `BasePathClaimKey`, plus `DecoyFileBaseline` / `FetchPath` / `SiblingServesAnyMarker`) walk the web root *plus* each observed path prefix, so a known endpoint mounted under a context path (`/api/actuator/env`, `/myapp/...`) is probed, not just the root. Adopted across ~26 exposure modules (Spring family, Swagger, FastAPI, GraphQL, Firebase, Tomcat, WordPress, Drupal/Joomla/Magento/Symfony, ASP.NET, Django/Laravel/Rails, …), replacing each module's hand-rolled checksum/path-walk loop; fan-out is capped (`MaxBasePathDepth`) and per-`(host, base)` dedup keeps traffic bounded.
- **Secret findings carry their evidence** — passive secret detection and the known-issue-scan Kingfisher pass now attach the originating request and the matched response (head + windowed body around the leak) to each finding, via shared `secret_detect` helpers, backed by a new `HttpResponse.Head()`.
- **Probe-finding collapse** — new `modkit.CollapseFindings` folds many findings that confirm one issue into a single finding (one `http_records` row), the rest riding along as capped inline `AdditionalEvidence`. `input-behavior-probe` now collapses its per-endpoint header/path/char/debug probes this way (ranking a `403→200` bypass above a tag-only change) instead of writing one row per probe.
- **SPA-gated JS-bundle name sweep** — on monolith / server-rendered apps, discovery now probes a curated list of common, never-content-hashed base names (`main`, `app`, `config`, `settings`, `admin`, `api`, `auth`, …), each tried as both `.js` (bundles) and `.json` (sibling config/data), across the web root, the start directory, and the app's observed JS directories. These files frequently aren't linked from the HTML, so they were never harvested; confirmed hits — validated against the soft-404 baseline with a per-directory wildcard/catch-all guard — flow into the JS-fetch pipeline (jstangle + link extraction, recorded as `http_records`) so their endpoints and secrets reach later phases. The sweep is skipped when the start page fingerprints as a JS-shell SPA (Next.js/React/Angular/Vue/Svelte): those bundles are content-hashed (`main.a1b2c3.js`) and so unguessable, and the real ones are already linked and harvested. Bounded by hard request caps and default-on, configurable under `discovery.extensions.js_bundle_sweep` / `js_bundle_names`.
- **SPA / PWA asset-manifest recovery** — modern frameworks code-split the app into hashed JS chunks (`100.<hash>.js`) whose names are assembled at runtime from a webpack chunk-id→hash map and appear nowhere as literal strings, so neither link extraction nor a short headless visit finds them — a real browser only fetches them because the framework, or a service worker pre-caching the build, reads a manifest the page never links. Both ends of the pipeline now close that gap. In **discovery**, the engine derives the well-known service-worker and manifest URLs (`/ngsw.json`, `/ngsw-worker.js`, `/sw.js`, `/manifest.webmanifest`, …), fetches them through the JS-fetch pipeline, and parses each framework's asset manifest so every cached chunk is fetched, recorded, and scanned — Angular `ngsw.json`, React CRA `asset-manifest.json`, Nuxt build manifests, and the generic Workbox precache list embedded in a PWA service worker (mirroring the existing Next.js route-manifest harvest, but for *asset* manifests). In the **browser spider**, a bounded in-page priming step does what the worker would — locates the registered worker and manifest, reads the full asset list, and fetches each same-origin asset so the browser's network capture records them as spidering traffic. Both sides are same-origin-only and capped (the crawler at `ServiceWorkerMaxAssets`, default 600); priming is on by default (`ServiceWorkerPriming`).
- **Passive recon harvesting (subdomains + third-party backends)** — two new INFO-severity passive modules, backed by a shared `pkg/reconsig` signature package, read HTML/JS/JSON response bodies for recon value without sending traffic. `subdomain-harvest` collects every hostname sharing the page's registrable domain (eTLD+1) — sibling origins, API hosts, and environment URLs that SPAs and minified bundles routinely embed — and flags ones whose name suggests a non-production environment (`dev`, `staging`, `test`, `qa`). `baas-endpoint-fingerprint` matches a 22-provider catalog of backend-as-a-service / identity / serverless / managed-data backends (Okta, Auth0, Cognito, Supabase, Convex, Lambda function URLs, Cloud Run, Hasura, Algolia, Contentful, Sentry, …), recording the provider, category, and tenant/instance identifier; Firebase and object-storage references are deliberately left to their dedicated modules.
- **`--follow-subdomains` scope expansion** — opt-in flag that lets `subdomain-harvest` feed the in-scope subdomains it discovers back into the running scan, so a sibling host referenced only in a JS bundle gets crawled and scanned instead of being noted and dropped. It adds **exact discovered hosts** to a new runtime allow-set (`ScopeMatcher.AllowHost`, surfaced to modules via `modkit.ScopeExpander`) rather than wildcarding the apex, so the scope stays tight — `app.example.com` referencing `staging.example.com` pulls in that one host, not all of `*.example.com`. Off by default and automatically enabled at `--intensity deep`.
- **Third-party dashboard / console detection** — a new module pair, backed by a shared `infra/dashboardsig` catalog of ~60 off-the-shelf products across 10 categories (observability, data, CI/CD, orchestration, automation, messaging, collaboration, infra, analytics, AI — Grafana, Kibana, Elasticsearch, Airflow, GitLab, Jenkins, HashiCorp Vault, OpenAI-compatible LLM APIs, database consoles, …), inventories and probes self-hosted admin surfaces. Passive `dashboard-fingerprint` (INFO) recognises a product from a catalogued response signature — a unique header, body markers, or a distinctive cookie plus a name reference — recording which off-the-shelf software is reachable so product-specific checks and CVE matching can follow. Active `dashboard-exposure` confirms the product against its own health/version/config endpoints and grades the result in tiers: a reachable console is reported as attack surface (Medium), while an endpoint that discloses internal data — version, full config, model list, cluster status — *without authentication* escalates to a High info leak (the leaked value, e.g. the version, captured as evidence). Probing is intensity-scaled: at normal intensity only each product's single best (`Primary`) endpoint is probed, and `--intensity deep` (plus passive tech hints) unlocks the full per-product confirmer set.

### Changed

- **Quieter stateless headers** — `-S`/`--stateless` scans no longer print the Scan ID or Project UUID; both live in a throwaway database and can't be queried later, so they were just noise.
- **`--skip` accepts phase aliases** — e.g. `--skip discovery,spidering,kis`; usage examples updated to show it.
- **`--only discovery` syncs the discovery toggle** — keeps `DiscoverEnabled` in step with the skip (mirroring the `--only` path) so the config panel and downstream gates don't still report discovery as active.
- **Tighter extension-confirmation source gating** — the "observed" confirmation that gates server-side extension fuzzing now counts only URLs the application genuinely references (start URL, links from HTML attributes / meta-refresh / HTTP headers / robots.txt, sitemap entries, files actually fetched and confirmed). Path-like strings scavenged from JS/HTML body text no longer count — they aren't proof the server serves that extension — and on a JS-shell SPA the observed source is suppressed entirely, since the index shell answers every path. Cuts spurious extension sweeps triggered by body-text noise.
- **Per-module finding grouping (sourcemap noise collapse)** — finding grouping gained a `by_module` mode: for the modules it lists, findings collapse to a single finding per `(module, severity[, host])` regardless of the per-URL extracted value, folding every URL into `MatchedAt`. This handles modules that fire once per asset where the value is noise rather than a shared identity — `sourcemap-detect`, which reports a distinct `.map` filename for every JS/CSS bundle, so a site with dozens of bundles previously produced dozens of near-identical findings. Default-on for `sourcemap-detect` (per-host); severity stays in the key so a Low "sourcemap advertised" never merges with a High "full source exposed". Applies both to the stored findings (the `GroupFindingsByValue` dedup pass) and the live console output, configurable under `known_issue_scan.group_by_value.by_module`.
- **Proxy path-normalization bypass probing on exposure modules** — a shared `modkit` path-bypass helper appends `/..;/`-family prefixes (the Servlet matrix-parameter `..;/`, encoded `..%3b/` / `..%2f` / double-encoded `..%252f`, chained up to `MaxPathBypassClimb` deep) ahead of a blocked endpoint so a request a fronting proxy refuses by literal prefix is forwarded and re-reaches the endpoint once the Java/Servlet backend strips the path parameter and collapses the climb. Wired into several path-gated modules (`spring-actuator-misconfig`, `tomcat-manager-exposure`, `forbidden-bypass`, `xss-light`) and gated on a proxy-block status (401/403/405) so it only runs where there's actually a block to bypass.
- **Header-less Rails recognition for the Active Storage / Action Mailbox probes** — a new `infra/railssig` body-signal set (CSRF/Turbo/Action Cable meta tags, the default Rails 404/500/exception pages, `ActionController::` references) lets these probes confirm a Ruby on Rails app even when it strips `X-Runtime`/`Server` headers, with the probe path echo-stripped first so a reflected `ActiveStorage`/`ActionMailbox` target can't self-match.
- **Decoded preview on base64 findings** — `base64-data-detect` now decodes each matched blob (handling both standard and URL-safe alphabets, so JWTs decode cleanly) and, when it decodes to displayable text, attaches a truncated `(decoded)` preview line to the finding evidence and description, so the leak is readable without a manual round-trip.
- **Seed-parent directory fuzzing** — the standard discovery profile now fuzzes each ancestor directory of the seed URL (`/api/v1/auth/x` → `/`, `/api/`, `/api/v1/`, `/api/v1/auth/`) with the short file+dir lists and observed words (`discovery.expand_seed_parents`), while `enrich_targets: false` keeps scope to the seed's own path structure plus live crawl breadcrumbs instead of re-seeding from paths earlier phases wrote to the database.
- Rebuilt the static HTML report bundle.

### Fixed

- **`input-behavior-probe` empty-body / redirect false positives** — a tag-structure delta now counts only when both the baseline and fuzzed responses serve 2xx content *and* the fuzz body carries real HTML (≥3 tags), so a 404/302 empty-body or non-HTML response no longer registers a bogus maximal tag distance; the reproduce round applies the same guard.
- **Reflected/redirect secrets downgraded** — a secret that appears only on a 3xx redirect or reflected into a response header value (e.g. an OAuth identifier echoed into a `Location` URL on the way to SSO) now drops to Low instead of High/Critical.
- **`sensitive-file-discovery` decoy baseline + unified confirmation** — adds a per-candidate decoy-file baseline (same directory and extension) to catch extension-scoped catch-alls, probes sensitive files under every candidate base path including static/CDN directories where a misconfigured front serves an exposed `.env`/`.git`/backup, and routes all confirmation rounds through one `confirms` predicate (`.env` gated on a real `KEY=VALUE` line so prose mentioning "SECRET" can't forge a Critical).
- **IDOR/BOLA neighbor-id false positives on public content** — `idor-detection` and `idor-guid` now require the *original* request to carry a credential (Authorization, Cookie, a well-known API-token header, or a credential query parameter) before a "neighbor id returns different-but-valid content" differential is reported as a High/Firm authorization bypass, via a new shared `authzutil` helper. With no credential there is no per-user boundary to cross, so the same differential on public, navigable content — `GET /blog/3/` vs `/blog/4/`, a docs site, a product catalog — is downgraded to a Medium/Tentative lead rather than dropped; a baseline page that itself links the neighbor id is treated as public and likewise discounted.
- **`nextjs-image-ssrf` confirmation hardening** — the Next.js image-optimizer SSRF check now confirms a reached internal target through the shared `infra` SSRF internal-target set and the stricter `FreshMetadataMarkers`/`ConfirmFreshMetadata` defenses, so a generic token the app itself echoes (e.g. `compute`) can no longer confirm on its own — only a self-evidencing metadata marker that's present in the optimizer response and absent from the baseline does.

## [v0.1.29-beta] - 2026-06-12

A coverage-expansion and finding-quality release: a targeted re-spider phase that browser-crawls the SPA routes discovery finds after spidering already ran, Next.js route-manifest harvesting (Pages Router, SSG, and App Router route recovery), a ground-up rewrite of every module's finding description plus classification tags on native findings, and a consolidated `traffic --replay` that can drive a real browser through Burp.

### Added

- **Targeted re-spider of discovery-found SPA routes** — a new `targeted-respider` native phase (after discovery dedup, before dynamic assessment) closes a structural gap in the pipeline: the one-shot browser spider runs *before* discovery, so a rich route that discovery surfaces later — `/ui/`, `/console/`, an admin panel found in a JS bundle — never got its client-rendered pages crawled, and its XHR/fetch API calls never entered the scan. The phase re-reads discovery's already-stored response bodies straight from the database (zero extra HTTP for candidate selection), keeps only pages that look client-rendered/SPA or meaningfully interactive, screens out login/SSO walls so the browser budget isn't burned on auth bounces, and dedups candidates per (host, app-shell) so one crawl covers an entire SPA router instead of re-crawling the same shell per route. Survivors get short, budgeted browser crawls whose records land in `http_records` under a distinct `targeted-respider` source tag and flow into dynamic assessment like any other traffic. Default on with deliberately tight caps, all configurable under `discovery.respider.*`: max 3 seeds per host / 10 total, 45s + 25 states + depth 3 per seed, and a 5-minute wall-clock cap on the whole step; the phase only rides along when spidering, ingestion, and an assessment phase are all enabled, so headless/stateless modes are unaffected.
- **Next.js route-manifest harvesting** — discovery now recognizes Next.js pages, derives the `buildId` (from a referenced manifest URL in the markup, falling back to the `__NEXT_DATA__` JSON blob), and fetches two manifests that enumerate the app's routes but are typically absent from the rendered HTML: `_buildManifest.js` — the full Pages Router route table, including dynamic routes like `/blog/[slug]` — and `_ssgManifest.js` — the concrete pre-rendered paths, which the client router loads at runtime and which fill in real values for those dynamic segments. Every harvested route flows through link extraction into observed paths (with trusted-source priority) and `http_records`, so dynamic assessment scans pages no link on the site points at. App Router routes, which appear in *neither* manifest, are recovered separately by decoding page/route-handler chunk paths (`app/<segments>/page-<hash>.js`) back into their addressable routes.
- **Shared login/SSO URL signatures (`pkg/spitolas/loginsig`)** — the spider's login-detection tables (auth-fronting host prefixes like `sso.`/`adfs.`, known IdP hosts like Okta/Auth0/`login.microsoftonline.com`, and OAuth/SAML path markers) moved out of the crawler internals into a reusable package, so the re-spider candidate screen and any future phase share one source of truth instead of growing divergent copies.

### Changed

- **Finding descriptions and tags overhauled across all 263 modules** — every module's description was rewritten from internal implementation notes (detection-logic walkthroughs, CLI flag requirements, reference-link lists) into a concise, operator-facing **What it means / How it's exploited / Fix** block: what the finding actually establishes, how an attacker leverages it, and the concrete remediation. Net effect on the tree: ~4,100 lines of boilerplate replaced by ~2,300 lines of substance. The executor now *composes* the stored description instead of letting one source overwrite the other — the module's per-finding context line (the specific header/param/endpoint it flagged) leads, followed by the static explanation block — so reports keep both the instance specifics and the explanation. Module classification tags (`xss`, `spring`, `injection`, `light`, …) now also propagate onto every native finding, which previously carried no tags at all (only known-issue-scan findings did); tags are copied, not aliased, so editing one finding's tags can't corrupt its siblings. This is the new convention for all future modules.
- **`traffic replay` is now `traffic --replay`** — the standalone `vigolium traffic replay` subcommand was removed and folded into the `traffic` command as a `--replay` mode, so the full filter surface (`--host`, `--method`, `--status`, fuzzy search, header/body search, …) applies identically to listing and replaying. New knobs: `-c/--concurrency` (default 10) replays the matched records concurrently — and lets you throttle down to avoid overwhelming an intercepting proxy like Burp; `--with-browser` replays each URL through a real browser routed via `--proxy`, so the proxy captures genuine browser traffic — real TLS fingerprint, JS execution, subresource and XHR loads — with the stored `Authorization`/`Cookie`/`User-Agent` headers forwarded so the navigation runs under the captured session, redirects/page titles/fired JS dialogs reported per record, and Chrome's implicit proxy bypass for loopback targets removed so even `localhost` traffic reaches the proxy (non-GET records are noted as replayed as GET navigations, since that's what a browser can do); and `-a/--all` lifts the `-n/--limit` cap (default 100) so `--replay --all` re-sends every stored record. `--in-replace` and `--timeout` carry over, and concurrent replays buffer their output so each original-vs-replay comparison block prints atomically rather than interleaved.
- **Live finding lines match the console format** — the stderr finding echo used when results are deferred to files (`--format jsonl,html`) previously had its own ad-hoc layout; it now renders the exact `[type] [module] [severity] METHOD URL [value]` shape of the console result writer (including the type/phase de-duplication and the grouped extracted-value suffix), so a finding reads identically whether it streams to the terminal via stdout or the stderr echo.

### Fixed

- **`bfla-detection` no longer flags empty-200 endpoints** — an endpoint whose "privileged" baseline is an empty (or whitespace-only) body carries no privileged content to compare, so every sub-test degenerated into matching nothing against nothing: fronting CDNs, XSRF/login bounces, and JSP `.jspa` action handlers that answer *any* request with an empty 200 were reported as unauthenticated-access or method-switch bypasses. The real-world trigger was an Atlassian `/secure/ConfigureReport.jspa` returning `Content-Length: 0` for both GET and POST — which also defeated the existing random-path method baseline, since the random path 404s while the action handler empty-200s, making the responses look "different enough" to pass the guard. The module now bails up front when the baseline body is empty and skips switched-method candidates whose bodies are empty, on the principle that an empty body is no-signal for both baseline and candidate. Covered by new regression tests alongside the existing positive cases.

## [v0.1.28-beta] - 2026-06-11

A detection-expansion and noise-reduction release: object-storage traversal and cloud-URL harvesting, value-based finding grouping that collapses one leaked secret seen on many URLs into a single finding, tech-fingerprint-gated extension fuzzing, a faster native-scan hot path, and continued module false-positive hardening.

### Added

- **Value-based finding grouping** — a secret that leaks on N different URLs now collapses to a single finding (and a single console line) keyed on the extracted value, instead of one finding per URL. Applied both live (the console `findingGrouper` suppresses repeats to file-only and prints a grouped summary with per-host rollups) and in the database dedup pass (`GroupFindingsByValue`, folded into `deduplicateFindings`, covering known-issue-scan secret templates and passive secret detection). Controlled by a new `known_issue_scan.group_by_value` config (`Enabled`/`PerHost`/`Tags`/`MaxURLs`; per-host grouping on by default), with an identical non-empty value required as the guardrail.
- **Tech-fingerprint-gated extension fuzzing** — discovery now wordlist-fuzzes server-side extensions (`.php`, `.aspx`, `.jsp`, `.action`, `.cgi`, `.jspx`, `.ashx`, `.asmx`, …) only after *confirming* the app actually serves them — via an observed URL, a technology-fingerprint match, or an active soft-404 probe — instead of always sweeping every extension. New `deparos/config` tech-signature table plus an `extension_confirm` pipeline; the previously always-on custom-list sweep is now gated behind a default-on confirmation step (with a console `ext-fuzz` notice when it engages).
- **Object-storage traversal & cloud-URL harvesting** — a new active `cdn-object-traversal-listing` module appends `..;`-family trailing payloads to object-storage fetches to turn a single-object read into a full bucket listing, and a new passive `cloud_storage_url_harvest` module collects S3/GCS/Azure Blob/OSS/TOS storage URLs from response bodies. Both are backed by a new `storagesig` package that fingerprints object-storage backends and listing responses behaviorally (storage response headers, `/obj/<bucket>/<object>` path shape, listing-XML bodies). Object-storage assets are now carved out of the static-file filter across the executor, CLI/JS/server ingest, and proxy paths and recorded metadata-only via HEAD/ranged-GET (new `WorkItem.StaticMeta`) instead of being dropped, so these modules can see them.
- **Concurrent triage batches** — `TriageLoopConfig.BatchConcurrency` runs disjoint triage batches concurrently within a round (default 3, mirroring master-agent batch concurrency), wired through `SwarmRunner.runTriageLoop`.

### Changed

- **Module false-positive hardening** — expanded FP defenses and test coverage across `nosqli-*`, `sqli-time-blind`, `path-normalization`, `xml-saml-security`, `bfla-detection`, `proxy-header-trust`, and other active/passive modules.
- **Trusted identity-header spoofing in `forbidden-bypass`** — the 403-bypass module now also replays the request with spoofed trusted identity/routing headers, catching gateways that authorize on a forwarded identity header an external client can set.
- **Faster native-scan hot path** — three independent optimizations to the deterministic pipeline: `ParameterInsertionPoint` caches the `Content-Length` byte offsets at construction so body/form/XML fuzzing patches the length in place instead of re-parsing every header per payload (~4.4× faster, 15→6 allocs/op); the per-host rate limiter's `Acquire` is now lock-free in steady state (drops the per-`Acquire` shard write-lock + `heap.Fix`), which matters most when a scan hammers a single host; and module workers enqueue findings through a new batched `FindingWriter`/`SaveFindingsBatch` instead of blocking on a synchronous per-finding save (coalesced into one transaction, retried per-finding, flushed on full/close so nothing is dropped — the linked HTTP record is still persisted synchronously first).
- **Autopilot prep overlapped with the background audit** — auth preparation and pre-flight discovery now run concurrently with the background vigolium-audit pass and are joined before the frozen context bundle is assembled, taking their latency off the critical path.
- **Richer report output & audit-platform refactor** — enriched HTML/console report output, plus an internal refactor of the embedded vigolium-audit harness (shared CLI-process adapter, retry/cost engine helpers, content loader).

### Fixed

- **`--external-harvest` now works on demand** — on `vigolium scan` the scanning-strategy baseline unconditionally overwrote the external-harvest phase toggle, so passing `--external-harvest` under the default `balanced` strategy had no effect. The flag is now a true per-phase override: when explicitly set it wins over the strategy (e.g. `--intensity balanced --external-harvest` enables harvesting while keeping balanced depth), and when unset the strategy's value still applies.

## [v0.1.27-beta] - 2026-06-10

A detection-expansion and false-positive-reduction release: two new modules (clickjacking detection and internal-header fuzzing), out-of-band findings that carry the request that triggered them, a stateless audit mode with an auto HTML report, and catch-all/reflection hardening across several modules.

### Added

- **Clickjacking (UI-redress) passive module** — a new `clickjacking-detect` module that flags a page only when it is both framable *and* worth hijacking, instead of every missing `X-Frame-Options`. It computes the framing verdict like a browser (enforced CSP `frame-ancestors` overrides `X-Frame-Options`; report-only, `ALLOW-FROM`, invalid/conflicting headers, and wildcard sources are treated as ineffective), requires sensitive/interactive content (credential form, authenticated session, or state-changing form), and downgrades when a `SameSite=Strict`/`Lax` session cookie would make the cross-site frame unauthenticated.
- **Internal header probe (active module)** — a new `internal-header-probe` module that mines a CORS preflight's `Access-Control-Allow-Headers`/`Access-Control-Expose-Headers` for gateway-injected custom headers (identity, routing, trust, feature-flag), re-sends the request with each set to a battery of probe values, and reports those whose response body reproducibly changes — reflection stripped, measured against a per-endpoint noise floor, with a per-host circuit breaker. Adds an OAST spray per header for blind SSRF. Severity Suspect/Tentative: a body change proves the backend reads the header, not that it is exploitable.
- **Out-of-band findings carry their originating request** — an OAST callback finding now embeds the request/response that planted the payload, the callback URL, the raw collaborator callback as evidence, and trace anchors, so it answers "which request caused this callback?" on its own. A new `GetRecordByRequestHash` lookup recovers the origin even for late callbacks, and the finding is saved even when the record can't be resolved.
- **Stateless audit with auto HTML report** — `-S`/`--stateless` on `vigolium agent audit` runs the whole audit into a throwaway temp DB (main DB untouched, mirroring `vigolium scan -S`) and auto-renders a self-contained HTML report via the `vigolium import --format html` generator. Defaults to `vigolium-result/vigolium-audit-report.html`; `-o`/`--output` overrides it (supports `gs://` and `{ts}`).
- **`vigolium audit` top-level alias** — a shortcut for `vigolium agent audit` with the same flags (mirroring `vigolium olium`).

### Changed

- **Audit `--keep-raw` now on by default (CLI)** — retains the `<source>/vigolium-results/` copy for review/re-import; new `--clean-raw` removes it after the run. Mutually exclusive, audit-leg only.
- **Catch-all false-positive hardening** — `bfla-detection` and `forbidden-bypass` now drop findings when a random unprivileged path returns the same response, catching empty-200 / reflected-shell edge gateways the existing wildcard guards missed.
- **ASP.NET false-positive hardening** — `crossdomain.xml` / `clientaccesspolicy.xml` are flagged only when actually wildcard-permissive (not merely present), and the OIDC discovery document (`/.well-known/openid-configuration`) is no longer double-reported; all downgraded Medium→Low (these are Flash/Silverlight/OIDC standards, not ASP.NET-specific).
- **Severity recalibration** — PDF-generation-injection's plain HTML-marker reflection drops High/Firm→Medium/Tentative (the JS/SSRF/file-read variants stay High/Firm), and `web-cache-poisoning` drops Firm→Tentative.

### Fixed

- **Console output no longer clipped to a file or pipe** — width-based truncation now applies only to an interactive TTY (new `terminal.IsTerminal()`). Redirected output — including the `-P`/`--parallel` per-target `.console.log` — previously clipped URLs and payloads mid-token; file/pipe consumers now get the full, greppable line.

## [v0.1.26-beta] - 2026-06-08

A false-positive-reduction release closing the "404 catch-all / SPA shell" and "reflected-but-not-executed" classes across the error-based injection and reflection modules: a shared error-surface status gate, structural (not bare-token) signatures, and a headless-browser confirmation tier for discovered-parameter XSS.

### Added

- **`infra.IsErrorSurfaceStatus`** — a shared status gate, companion to `IsBlockedResponse`. A genuine server-side leak (DBMS/driver error, reflected file contents, a stack trace) rides a 5xx or a 2xx/4xx that echoes the payload; a `404` means the route never resolved (no handler ran) and a `3xx` carries no handler output, so a signature substring in either body is page noise — a catch-all/SPA 404 shell or a redirect interstitial. Body-matching modules whose finding is not itself a status signal now reject a response failing *either* gate before matching.

### Changed

- **Error-based injection signatures hardened against catch-all 404 shells** — `sqli-error-based`, `nosqli-error-based`, `xxe-generic`, and `ws-injection` no longer match DBMS/driver/error tokens on a `404`/`3xx` body (via the new `IsErrorSurfaceStatus` gate), and their bare tokens are tightened to structural forms: the CockroachDB name is word-boundary-anchored (was firing on `userHasCockroachDBEnabled` in a Salesforce community 404 shell's feature-flag list), the MongoDB/`BSON` patterns now require genuine driver/error contexts instead of the bare 4–6-char token, XXE confirms `/etc/passwd` by the full `root:…:0:0:` line shape (not a `root:` substring that a `--dxp-g-root:` CSS var carries), and `ws-injection` requires a pattern to be absent from the baseline, match the body only (not headers), and — for the `{{7*7}}`/`${7*7}` template probes — proves evaluation by requiring the literal payload to be *gone* from the response.
- **`nosqli-error-based` re-confirmation** — a matched DBMS error must now reproduce when the payload is re-sent (a per-request random token that coincidentally matched won't recur) and be absent from a fresh control fetch of the original value, with `NoClustering` forcing a real origin round-trip so the request-clustering cache can't replay the captured hit. Fails open on transport errors.
- **`lfi-generic` reflection guards and file-shape confirmation** — the `php://filter/convert.base64-encode` read now discards base64 runs that are simply our own `data://` payload being reflected back (Salesforce-Aura-class echo endpoints) or that decode to carry our injection marker, the `/etc/passwd` rule requires the full `root:…:0:0:…` line shape (not the former greedy `root:.*:0:0:`), `win.ini` is confirmed by ≥2 distinct bracketed section headers (was the bare English words `fonts`/`extensions`), and `.env`/`.htaccess` are confirmed by ≥2 distinct file-shaped lines — sensitive `KEY=VALUE` assignments or recognised Apache directives — which both strengthens the evidence and broadens detection beyond the former rigid `DB_PASSWORD`+`APP_KEY`+`APP_SECRET` triple that real Laravel/Symfony files rarely carry.
- **`xss-light` discovered-parameter confirmation** — a reflected character-transform hit is now re-sent as a real, context-shaped executable payload and graded in tiers: dropped when the breakout signature never survives unescaped in the body (the reflection-only false positive this gate exists to suppress), reported Low/Tentative when it survives but no dialog fires (CSP-locked or non-executing context), and only raised to High/Certain once a headless browser actually pops `alert(marker)`. Browser probes are globally rate-limited and injectable so tests never spawn a real browser.

### Fixed

- **Spidering no longer crashes the whole scan on a cross-origin iframe** — go-rod's lazy `getJSCtxID()` dereferences a nil `ContentDocument` for cross-origin/detached frames, and the existing `frameAccessible()` pre-filter could not close the TOCTOU gap where a same-origin iframe navigates cross-origin (or detaches) between frame enumeration and the element query during extraction — common on SPAs. The nil-pointer panic propagated to the top-level `RunNativeScan` recover and aborted the entire scan (later phases skipped, zero findings). The browser wrappers that reach `getJSCtxID` (`Element`/`ElementX`/`Elements`/`ElementsX`/`EvalWithArgs`/`HTML`/`HasElement[X]`, plus the recursive frame-HTML builders) now convert such panics into ordinary errors so the bad frame is skipped, with a per-frame `recover()` backstop in the candidate-element extractor as a second line of defense.

## [v0.1.25-beta] - 2026-06-07

A false-positive-reduction release hardening the endpoint- and file-exposure modules against generic markers and reflected error pages.

### Changed

- **Rails Active Storage / Action Mailbox probe** — confirms OPTIONS endpoints only on a 2xx `Allow: POST` header (no longer body-matching `"Allow"`/`"POST"`, which forged findings from nginx `405 Not Allowed` pages), and rejects blanket-OPTIONS hosts, CORS preflights, and WAF/rate-limit pages.
- **Marker hardening** — `.env` files now require a real `KEY=VALUE` line (was bare `"="`), Magento `deployed_version.txt` a valid version token (was `"."`), and ASP.NET health checks an actual health-state word (was generic JSON keys).

## [v0.1.24-beta] - 2026-06-07

A false-positive-reduction and severity-recalibration release: per-template severity overrides for known-issue scan, decode-confirmed LFI and marker-confirmed WordPress detection, right-sized passive DOM-XSS severities, and a fix for response bodies being dropped from stored known-issue findings.

### Added

- **Known-issue-scan severity overrides** — a new `known_issue_scan.severity_overrides` map remaps a finding's recorded severity by nuclei template ID (case-insensitive), applied after a match but before output/persistence so the stored finding, console output, and severity counts all agree. Lets you right-size noisy or context-dependent templates without forking the upstream template (which reverts on `nuclei -update-templates`). Ships a default `config-json-exposure-fuzz: medium` — an exposed `config.json` often carries only public base URLs / feature flags rather than always-critical secrets; set an entry back to the template's own severity to undo a remap.

### Changed

- **WordPress module false-positive hardening** — `wp-ajax-exposure` now requires plugin/action-specific markers (AND-of-OR groups via `modkit.MatchAllGroups`) in the response body and rejects generic CDN/WAF/SPA error pages, so an unrelated "load-failed … Refresh" page is no longer mislabelled as a critical export vulnerability. `cms-installer-exposure` now requires the CMS-name anchor and installer-specific context to co-occur (instead of any single generic word like "language" or "database") and adds a soft-404 / SPA-shell gate (`ConfirmNotSoft404`) to reject wildcard catch-all hosts.
- **LFI base64-read confirmation** — the `php://filter/convert.base64-encode` read is now confirmed by actually decoding the returned base64 and requiring real PHP source (a PHP open tag, not already present in the baseline), replacing a bare `^[A-Za-z0-9+/=]{50,}` charset regex that fired on incidental base64 (data-URI images/fonts) embedded in ordinary CDN/static 404 pages. LFI matches are additionally gated to 2xx/3xx responses, so a 4xx/5xx error/404 body is never mistaken for leaked file content.
- **Passive DOM-XSS severity recalibration** — `dom-xss-detect`, `dom-xss-taint`, and `unsafe-html-sink` (and each of its per-sink patterns) are lowered from Medium to Low, reflecting that these are static source/sink indicators without runtime confirmation.

### Fixed

- **Known-issue-scan findings lost their response body** — `formatJSON` zeroed `Response` in place on the shared `*ResultEvent` before `SaveFinding`/`SaveRecord` ran, wiping the response body from the stored finding and its HTTP record. It now serializes a shallow copy with `Response` cleared, leaving the persisted finding and record intact.

## [v0.1.23-beta] - 2026-06-06

A combined detection and agentic-scan reliability release: routing-based SSRF detection from PortSwigger's "Cracking the lens" research, OpenRouter provider routing for the olium agent, resilient agent streaming with run cancellation and graceful shutdown, plus continued Spring/false-positive hardening.

### Added

- **Routing-based SSRF detection ("Cracking the lens")** — two new active modules. `routing-ssrf` writes an attacker-chosen host on the request line (absolute-URI `http://internal/`, `@`-userinfo, protocol-relative `//host/`) while still connecting to the victim host, confirming via an out-of-band OAST callback or a self-evidencing internal/metadata marker that reproduces, is absent from a baseline, and is absent for a benign decoy. `upgrade-routing-ssrf` detects internal/metadata endpoints reachable only when a WebSocket-upgrade handshake bypasses a proxy URL filter, confirmed by a with-vs-without differential. Backed by a new `http.Options.RawRequestTarget` request-line primitive (rawhttp, Host/target mismatch preserved) and shared `infra` payload ladders.
- **"Collaborator Everywhere" OAST headers** — `oast-probe` expands its blind-callback header fan-out (`True-Client-IP`, `CF-Connecting-IP`, `Forwarded`, `X-WAP-Profile`, …) with per-header value shaping and a `Cache-Control: no-transform` hint, surfacing SSRF in routing/analytics headers that backends behind a reverse proxy commonly fetch.
- **OpenRouter provider routing** — a typed `agent.olium.custom_provider.provider_routing` knob (provider order, fallbacks, data-collection, quantization, …) plus a generic `extra_body` JSON passthrough merged into every openai-compatible request, for steering OpenRouter and other OpenAI-compatible backends.
- **Agent run cancellation** — `POST /api/agent/scans/:uuid/cancel` aborts an in-flight autopilot/swarm/query/audit run (recorded as `cancelled`), wired to a Stop control in the workbench UI.
- **Agent config hot-reload** — the `agent` config section now reloads at runtime, so `vigolium config set agent.olium.*` (provider/model/credentials) takes effect on the next run without a server restart; the CLI echoes a reload line.
- **Invalid-date mutation payloads** — the mutation engine now emits explicit, labeled invalid-date boundary values (impossible day-of-month, out-of-range month 13) for date parameters to probe lenient date parsers/validators, deterministically and reproducibly.

### Changed

- **Spring module false-positive hardening** — `spring-actuator-misconfig` now confirms each endpoint by its actuator-specific JSON structure (`"status":"UP"` for `/health`, the `propertySources` envelope for `/env`, dotted Micrometer metric ids for `/metrics`, …) instead of a generic word match, and the seven sibling exposure modules (boot-admin, cloud-config, data-rest, debug, gateway, h2-console, jolokia) now require co-occurring marker groups rather than any single weak token. All eight probe a guaranteed-nonexistent sibling under the same directory to reject catch-all handlers (e.g. Keycloak i18n message bundles, SPA fallbacks) that 200 every child path. New shared `modkit` primitives back this: `MatchAllGroups` (AND-of-OR groups) and `SiblingPathCatchAll`, folded into a single `MatchAndConfirmSibling` helper.
- **Parallel-scan interrupts** — Ctrl-C during a `-P`/`--parallel` batch now treats un-started and cut-short targets as "not scanned" rather than failures: a muted per-target line, no `ERROR` log spam, a `Parallel scan interrupted · N not scanned` roll-up, and an exit status that distinguishes an operator stop from a genuine all-failed batch.

### Fixed

- **Streaming agent disconnects** — a streaming (`stream: true`) agent run no longer freezes `runtime.log` or hangs in `running` when the SSE client disconnects (e.g. a connection dropped during a long model "thinking" pause). Writes now drain the agent pipe to EOF so logging and DB finalization always complete, a vanished client cancels the run instead of burning its full budget, and a client disconnect or server shutdown is recorded as `cancelled` rather than `failed`. Concurrent SSE producers (swarm phase callbacks) are serialized through a single sink to stop interleaved/half-written events.
- **Graceful server shutdown** — shutdown now cancels in-flight agent runs first so live SSE streams release their connections, honors the caller's deadline (`ShutdownWithContext`) instead of waiting indefinitely for connections to go idle, and a second Ctrl+C (or a hard deadline) force-quits a hung shutdown. The config watcher also watches the actual `--config` file rather than only the default path.

## [v0.1.22-beta] - 2026-06-06

An agentic-scan and traffic-capture release: attack-vector skills wired into autopilot and swarm with planner-driven selection, an HTTPS-intercepting ingest proxy, sturdier olium stream recovery, a static-root traversal file-read oracle, and cleaner parallel-scan output.

### Added

- **Attack-vector skills for agentic scan** — confirmation/escalation playbooks the agent loads to confirm and escalate findings (new `xss-browser-confirm`, upgraded `idor-blast-radius`). Built-in skills are materialized to `~/.vigolium/skills` (override `VIGOLIUM_SKILLS_DIR`) on `vigolium init` as editable copies, which the loader prefers over the embedded fallback.
- **Planner-driven skill selection** — the swarm planner picks skills matching the target's attack surface (`RECOMMENDED_SKILLS`) and the triage phase loads just that subset; autopilot runs an equivalent best-effort pre-flight pick before its run. `--skill`, `--skill-tag`, and `--no-skill-filter` (on `agent autopilot` / `agent swarm`) override the selection per run, and `agent.olium.always_on_skills` (default `triage-finding`, `write-jsext`) pins general-purpose playbooks that stay available regardless of filtering.
- **HTTPS-intercepting ingest proxy** — `vigolium server --ingest-proxy-port N --proxy-mitm` terminates TLS with a generated CA so HTTPS traffic is recorded (and scanned with `-S`); trust the CA printed at startup or write it out with `--export-ca <path>`, and use `--proxy-insecure` to skip upstream TLS verification. Plain HTTP and un-intercepted CONNECT tunnels still pass through untouched.

### Changed

- **Active module improvements** — additional detection coverage and false-positive hardening across the active modules (including a new static-root file-read oracle in `path-normalization`).
- **Sturdier olium stream recovery** — transient upstream stream failures (HTTP/2 `INTERNAL_ERROR`/`GOAWAY`/idle reset and content-less codex `error` frames) now retry even mid-tool-call instead of tearing down the run, recovering exactly the in-flight-tool-call blips that previously killed autopilot/swarm runs.
- **Parallel scan output** — each `-P`/`--parallel` child now writes a self-contained `<output>.console.log` that captures the live finding stream (even with deferred JSONL and no `console` format) and drops the repetitive `[status]` progress ticker, so per-target logs read like a normal console scan.

## [v0.1.21-beta] - 2026-06-05

A false-positive-reduction and observability release: broad confirmation-hardening across the active and passive modules, full secret disclosure in findings, and Pi-compatible JSONL transcripts for every olium agent mode.

### Added

- **Olium session transcripts** — every olium run (`olium`/`ol` TUI, `-p` headless, `agent autopilot`, and `agent swarm`/`query` per phase) writes a Pi-compatible JSONL conversation transcript to its session dir for debugging.
- **Shared confirmation primitives** — static-asset Content-Type gate, WAF/CDN challenge-page detection (catching 200/202 Cloudflare/Incapsula interstitials), a genuine WebSocket-handshake check, and body-similarity / raw-replay helpers, reused across the hardening below.

### Changed

- **Active false-positive hardening** — ~20 High/Critical modules now drop findings that fail strict confirmation (soft-404 / wildcard / reflection / content-shape gates), and ones that confirmed on HTTP status alone now require a content/body gate, so catch-all and SPA 200s no longer trip findings.
- **Error/marker matching** (`sqli-error-based`, `graphql-scan`, `ssrf-detection`, `ldap-injection`, `xxe-generic`, `nosqli-*`, …) skips WAF/CDN challenge, auth-gate, and rate-limit pages before matching, closing the SSO/Cloudflare-challenge false-positive class.
- **Passive false-positive hardening** — ~12 detectors (env-secret, info-disclosure, error-message, MCP-endpoint, jackson/joomla, …) skip static-asset and binary bodies, so a token baked into a minified bundle is no longer flagged.
- **Secrets shown in full** — target-discovered secrets are now reported unredacted (`secret-detect`, `env-secret-exposure`, `jwt-weak-secret`, `jwt-claims-detect`); only operator BYOK credentials in logs/config stay masked.
- **vigolium-audit harness** — restructured output layout with pre-merge and artifact-redaction passes, so `agent audit` runs land cleaner, deduplicated, secret-safe output.

## [v0.1.20-beta] - 2026-06-02

A detection-expansion and false-positive-reduction release: OS command-injection detection, a `-P/--parallel` multi-target fan-out, finding evidence in output, and a broad hardening pass across the active modules and shared diffscan engine.

### Added

- **OS command-injection detection** — three new active modules covering results-based (in-band), out-of-band (OAST callback), and time-based blind techniques, each confirming execution across multiple rounds against a baseline to avoid false positives.
- **`-P`/`--parallel` flag** (`scan`, default `1`): scan up to N targets concurrently via isolated child processes. Pair with `-S -T --split-by-host` for per-host output files, or `--db-isolate -T` to merge every target into one shared `--db` and export a single unified result. Single target / `-P 1` is unchanged.
- **Finding evidence** — findings now carry the supporting request/response pairs (baselines, confirmation rounds, control fetches) behind each decision, surfaced in console output and stored in the database.

### Changed

- **Broad false-positive hardening** across the active modules: findings now have to reproduce and show real content-level changes, so they survive WAF/rate-limit pages, dynamic-content jitter, transient flaps, and reflection artifacts instead of misreading them as vulnerabilities. Confirmation replays also bypass the response cache so each sample is genuinely fresh.
- **diffscan engine** — excludes reflection-prone and volatile attributes from comparisons, gates out responses where the payload couldn't have been evaluated (redirects, empty bodies, 404s), and surfaces which attributes actually differed across confirmation rounds.
- **Severity recalibration** — server-side template injection lowered to Info (a human-confirmation lead) and HTTP method tampering to Suspect (frequently non-exploitable alone).
- **Passive checks** — missing-security-header detection now also flags weak `Referrer-Policy` values and cacheable sensitive HTTPS responses; CSRF detection filters out requests that aren't actually CSRF-reachable (JSON bodies, header-based auth, no session cookie).
- **OAST service** — command-injection callbacks are now classified as confirmed OS command injection rather than generic SSRF/XXE.
- **Olium autopilot** — project custom skills now load from `.agents/skills/`, with a startup summary of available skills by source.

### Removed

- Folded the standalone cacheable-HTTPS and Referrer-Policy passive checks into the missing-security-header module.

## [v0.1.19-beta] - 2026-06-01

### Added

- Five new active modules: `ssrf-filter-bypass`, `ssrf-protocol-smuggling`, `open-redirect-confusion`, `reverse-proxy-path-confusion` (High), and `cache-poisoned-dos` / CPDoS (Medium).
- `--db-isolate` flag (`scan`, `agent autopilot`, `agent swarm`): scan into a private temp SQLite DB and merge into `--db` at the end, so parallel scans can share one `--db` without write contention.
- `--soft-fail` global flag: always exit 0 even on error (error still printed to stderr) for CI/scripts.

### Changed

- `response-header-injection`: confirmed injections served over a keep-alive connection are now flagged as likely to let an attacker poison the shared connection's response queue and deliver their responses to other users, and are raised to High.

## [v0.1.18-beta] - 2026-05-30

A false-positive reduction release: high/critical active modules now re-confirm findings (replay payload vs. clean baseline) before reporting, plus discovery and crawler robustness fixes.

### Re-confirmation safety net

- Executor-level net (`modkit.ConfirmBodyDifferential` + opt-in `BodyDifferentialConfirmable`) replays a finding's payload vs. a clean baseline and drops it without a reproducible difference, fails *open* on anything inconclusive. Opted in by `host-header-injection`, `reflected-ssti`, `struts-ognl-injection`, `web-cache-poisoning`.
- Dropped findings counted and surfaced via `SuppressedFindings()`.

### SQL & NoSQL injection

- **`sqli-boolean-blind`** — single-shot comparison replaced by a multi-round, multi-factor logic battery (operator probing, alternating comparisons, per-branch stability, invalid-syntax probe) + WAF payload mutation.
- **`sqli-time-blind`** — multi-round, delay-scaling confirmation to separate injection from network jitter.
- **`nosqli-operator-injection`, `nosqli-error-based`** — size-change hits re-confirmed against per-request variance; now require a captured baseline.
- New `pkg/modules/infra` SQLi helpers: `sqldbms.go`, `sqlvalue.go`, `sqlwaf.go`.

### Active module confirmation

- **`crlf-injection`, `response-header-injection`** — replay with fresh canaries across rounds.
- **`open-redirect`** — require the redirect to track a fresh injected domain across rounds.
- **`ssrf-detection`** — verify matched markers are payload-introduced, not ambient.
- **`idor-detection`, `idor-guid`** — determinism gate vs. per-request variance (skips analytics/beacon endpoints).
- **`mass-assignment`** — canary field detects endpoints that echo arbitrary keys.
- **`http-method-tampering`** — catch-all guard drops endpoints that accept *any* method.

### Discovery & spidering

- Built-in wordlists materialized to disk and used as defaults (`internal/resources/wordlists`).
- `dedup_cluster_cap` (default 10) collapses near-identical responses so catch-all/SPA targets don't flood the scan; `auto_fuzz_low_yield` (default on) enables `FUZZ` brute-forcing on low-yield/SSO-walled spidering.
- Initial navigation retries on transient transport errors; proxied scans force Chrome to HTTP/1.1 (fixes `net::ERR_HTTP2_PROTOCOL_ERROR` through Burp/ZAP); off-host start redirects classified as SSO wall vs. relocated app (host adopted into scope).

## [v0.1.17-beta] - 2026-05-29

Expand XSS detection with additive modules that sit alongside the existing scanners rather than changing them. The WAF-aware evasion and encoding-payload work takes inspiration from [dalfox](https://github.com/hahwul/dalfox).

### XSS

- **Stored XSS (`xss-stored`)** — browser-confirmed persistent XSS: writes a unique canary, re-fetches the page with a clean request, and only reports when the canary both persists and executes, distinguishing stored from reflected.
- **DOM-XSS taint (`dom-xss-taint`)** — passive AST taint analysis that raises a finding only when a DOM-controlled source (`location.hash`, `document.cookie`, …) provably flows into a dangerous sink (`innerHTML`, `eval`, …), complementing the pattern-based `dom-xss-detect`.
- **Pre-encoded injection (`xss-light-encoded`)** — targets filters that decode a parameter (base64 / double-URL) before reflecting it.
- **WAF-aware evasion** — a per-host `WAFRegistry` lets modules publish the detected WAF/CDN so later insertion points reuse it, and a package-level `waf.ClassifyParts` helper classifies blocks from raw response primitives. Inspired by dalfox's WAF handling.
- **Encoding payloads** — `pkg/modules/infra/xssencode` supplies execution-preserving payload mutators and an encoding ladder for bypassing filters. Inspired by dalfox's evasion payloads.

### jstangle

- Add axios and custom-protocol request-pattern extraction.
- Surface DOM-XSS source→sink taint flows (`dom_flows`) in scanner output.
- Add `linux/arm64` / `darwin/amd64` correlation testdata.

### Audit

- vigolium-audit no longer forces a hardcoded per-platform model and reasoning effort; it now inherits the agent runtime's own configured default unless `--model` or `VIGOLIUM_AUDIT_MODEL` is set explicitly.

## [v0.1.16-beta] - 2026-05-28

Fix cross-platform release packaging for embedded helper binaries: GoReleaser, snapshot, release, public-release, and Docker builds now stage the matching `vigolium-audit` blob per target, run cross-builds sequentially where the shared go:embed path would otherwise race, and restore the host blob afterward so local builds do not inherit the last release target. Add runtime and npm packaging guards that detect wrong-platform embedded audit blobs before users hit opaque exec-format failures. Also add missing `jstangle` embeds for `linux/arm64` and `darwin/amd64`, with coverage tests to ensure every shipped release target has a real scanner binary instead of the unsupported stub.

## [v0.1.15-beta] - 2026-05-28

Make `--format jsonl` emit the same post-scan, project-scoped `{"type":...,"data":...}` envelope as `vigolium export` (instead of the live nuclei-style stream) across scan, scan-url phase mode, and stateless runs; default stateless multi-target scans (`-S -T file`) to a single unified output file with new `--split-by-host` to opt into per-host files; surface timed-out modules in the scan status line (`X/Y (A active, P passive, T timed out)`); make failed scans exit non-zero and skip the "completed" banner instead of logging at INFO; accept `--session`/`--session-file` as aliases for `--auth`/`--auth-file`; and fold phases, intensities, and agent modes into `vigolium strategy` (dropping the `ls` subcommand).

## [v0.1.14-beta] - 2026-05-25

Publish multi-arch Docker images: `make docker-publish` now builds and pushes both `linux/amd64` and `linux/arm64` (override via `DOCKER_PLATFORMS`) as a single manifest using `docker buildx`.

## [v0.1.13-beta] - 2026-05-24

Make `--scanning-max-duration` cap total scan wall-clock time (all phases combined), widen severities to all levels for single-phase known-issue-scan runs, and add `cve`/`kis`/`known-issues` phase aliases.

## [v0.1.12-beta] - 2026-05-24

Bound the known-issue-scan phase to its `max_duration` and default it to critical+high severities.

## [v0.1.11-beta] - 2026-05-24

Initial release of Vigolium open source.
