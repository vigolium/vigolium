# Configuration Reference

Vigolium uses a layered configuration system that merges settings from multiple sources. This document covers the config file format, environment variables, and every configurable section.

## Config File Location

The main config file is `~/.vigolium/vigolium-configs.yaml`. It is created automatically on first run with sensible defaults.

Vigolium searches for configuration in this order:

1. Path specified via the `--config` flag (error if not found)
2. `~/.vigolium/vigolium-configs.yaml`
3. `./vigolium-configs.yaml` (current working directory)

If no config file is found, built-in defaults are used.

### When a config file cannot be read

The two cases are deliberately different:

- **A file you named with `--config`** is load-bearing. If it is missing,
  unreadable or unparseable, the command **fails** (exit 1) naming the file.
  Commands used to fall back to built-in defaults here, so a typo in `--config`
  ran the scan against the *default* database with the *default* scope and
  exited 0 — a failure that looks exactly like success.
- **A file found by discovery** is a convenience. An unreadable one prints one
  stderr warning and the command continues on built-in defaults.

`vigolium db clean --reset` is stricter still: it refuses on *any* config error,
including a discovered one, because the config is what names the database it
would delete.

`vigolium doctor` never fails on a broken config — reporting it is its job. The
config appears as its own check under **Core**, and every other check in that
report then reflects built-in defaults rather than your settings. A broken
config makes the verdict `degraded`, which exits 0 unless you pass `--strict`
(doctor exits 1 only on `not_ready`, or on `degraded` under `--strict`).

### Diagnostics

Two non-fatal warnings print to stderr (once per process, and never under
`--silent`):

- **Unknown keys.** A key that matches no setting — a typo like
  `default_stratgy`, or a key from a different vigolium version — is applied by
  nobody and silently has no effect. The warning names the key and the file. The
  rest of the file still loads.
- **A shadowed `./vigolium-configs.yaml`.** Discovery is first-match-wins, so a
  config dropped in a project directory does nothing whenever
  `~/.vigolium/vigolium-configs.yaml` exists. Pass `--config
  ./vigolium-configs.yaml` to use it.

### Awkward database paths

A SQLite path containing a space, a `#`, a `%` or non-ASCII characters now
reaches the file it names, on both the read-write and the read-only open and on
an `import` merge. A `#` used to truncate the path at the driver's URI parser,
so vigolium opened — and created — a *different*, empty database beside the real
one and reported success.

A path containing a literal `?` is **rejected** with a clear error. The bundled
SQLite driver cannot address one in any spelling; the previous behaviour was a
silently empty database.

## Config Precedence

Settings are resolved from highest to lowest precedence:

1. **CLI flags** -- e.g. `--concurrency 100`, `--rate-limit 50`
2. **Environment variables** -- e.g. `VIGOLIUM_API_KEY`, `VIGOLIUM_PROJECT_UUID`
3. **Scanning profile** -- loaded via `--scanning-profile <name>` (from `~/.vigolium/profiles/`)
4. **Project-level config** -- per-project overlay at `~/.vigolium/projects/<uuid>/config.yaml`
5. **Main config file** -- `~/.vigolium/vigolium-configs.yaml`
6. **Built-in defaults** -- hardcoded in the Go source

Higher-precedence sources override lower ones. Within the config file, environment variables can be referenced using `${VAR}` or `$VAR` syntax and are expanded at load time.

## Environment Variables

| Variable | Purpose |
|---|---|
| `VIGOLIUM_API_KEY` | API key for the REST server and ingestor client authentication |
| `VIGOLIUM_DB` | `--db` from the environment: the database path when `--db` is not set, with project scoping kept (wins over `VIGOLIUM_DB_PATH`). An agent run exports it to the `vigolium` commands its bash tool runs |
| `VIGOLIUM_DB_PATH` | Default SQLite database path when `--db` is not set — pins a shell to one session database (see [Session database](#session-database)) |
| `VIGOLIUM_CONFIG` | `--config` from the environment: the config file when `--config` is not set (an agent run exports it to its bash tool's commands) |
| `VIGOLIUM_BIN` | Set (not read) by an agent run for its bash tool: the absolute path of the running `vigolium`, which is also first on that shell's `PATH` |
| `VIGOLIUM_PROJECT_UUID` | Active project UUID when no project flag is supplied |
| `VIGOLIUM_PROJECT_NAME` | Active project name when no project flag is supplied (looked up in the database; `VIGOLIUM_PROJECT_UUID` wins if both are set) |
| `VIGOLIUM_PROXY` | HTTP/SOCKS proxy URL, used when `--proxy` is not set |
| `VIGOLIUM_DEFAULT_UA` | Override the configured outbound User-Agent selector or value |
| `VIGOLIUM_BURP_BRIDGE_URL` | Default loopback Burp bridge URL for bridge-aware commands |
| `VIGOLIUM_HOME` | Base directory for Vigolium data (used by the installer; defaults to `~/.vigolium`) |
| `VIGOLIUM_DISABLE_UPDATE_CHECK` | Set truthy to disable the periodic "new version available" check entirely |
| `VIGOLIUM_AUTO_UPDATE` | Set truthy to update the binary in place and re-exec it when a newer release is detected (interactive terminals only; see [Update check](#update-check)) |
| `VIGOLIUM_UPDATE_BASE_URL` | Release prefix `vigolium update` reads `metadata.json`, `checksums.txt` and its `.minisig` from (default `https://cdn.vigolium.com/vigolium-release`; https only). Signatures are still required |

### Session database

`VIGOLIUM_DB_PATH` supplies a default for the global `--db` flag, so a shell can be pinned to one database for a whole engagement instead of repeating `--db` on every command:

```bash
export VIGOLIUM_DB_PATH=~/engagements/acme.sqlite

cat requests.txt | vigolium ingest      # writes into acme.sqlite
vigolium scan -t https://acme.example   # scans into acme.sqlite
vigolium finding                        # reads acme.sqlite
```

The value goes through the same expansion as the config file's `database.sqlite.path`, so `~` and nested `${VAR}` references resolve. Each command prints a one-line notice naming the resolved database (suppressed under `--silent`, `-j/--json`, and `--ci-output-format`).

**Reads** additionally treat the file as a standalone source with project scoping off — the same thing `-S/--stateless` does — so every row in it is visible regardless of which project UUID wrote it. This applies to every command that reads through the shared query path (`finding`, `traffic`, `replay`, `export`, and record lookups like `fuzz -u <uuid>`), and is skipped until the file exists, so the first read on a fresh session prints an empty table instead of failing. **Writes are unaffected**: `scan` and `ingest` write to the pinned database normally, and the variable never sets the `--stateless` flag itself — on `scan`/`scan-url`/`scan-request`/`run` that flag means "scan into a throwaway temp database and discard it" (and is mutually exclusive with `--db`), while on `ingest` `-S` is `--scan-on-receive`.

Because reads are unscoped, `--project-uuid` / `--project-name` / `VIGOLIUM_PROJECT_UUID` / `VIGOLIUM_PROJECT_NAME` become inert on `finding` and `traffic` while a session database is pinned — the file's own contents are the scope.

Precedence and opt-outs:

- An explicit `--db` always wins; the notice says so when the two paths differ.
- An explicit `-S` on `scan`/`scan-url`/`scan-request`/`run`/`audit` — where it means a throwaway database — makes the variable a no-op for that run.
- `--glob-db` keeps driving the merge; the variable does not displace it.

### Update check

On startup Vigolium compares the running version against the latest `@vigolium/vigolium` release on the npm registry (cached to at most once per 24 h in `~/.vigolium/update-check.json`). When a newer version exists it prints a one-line notice at the end of the run:

```
▼ A new vigolium version is available: v0.3.1 → v0.3.2
  Run `vigolium update` to upgrade.
```

The check is automatically skipped for `--json`, CI (`--ci-output-format`), and non-interactive (piped) output, and for the `version`, `update`, and `init` commands. Set `VIGOLIUM_DISABLE_UPDATE_CHECK=1` to turn it off, or `VIGOLIUM_AUTO_UPDATE=1` to have Vigolium update the running binary in place (the same signed, verified path as `vigolium update`) and re-exec it to continue the current command.

Auto-update never acts when the caller is not a person at a terminal: it is off under `-j`, `--events` and `--ci-output-format`, when stdout or stderr is not a TTY, for `vigolium server`, when any of `CI`, `CONTINUOUS_INTEGRATION`, `GITHUB_ACTIONS`, `GITLAB_CI`, `BUILDKITE`, `JENKINS_URL`, `VIGOLIUM_AGENT`, `CLAUDECODE`, `CLAUDE_CODE_ENTRYPOINT`, `CODEX_SANDBOX`, `CURSOR_AGENT` or `GEMINI_CLI` is set (to anything but `0`/`false`), and for binaries run by the npm package or Homebrew. In those cases the notice flow applies instead.

Any environment variable can also be interpolated inside `vigolium-configs.yaml`:

```yaml
database:
  postgres:
    password: ${VIGOLIUM_DB_PASSWORD}
```

## CLI Config Overrides

Use `vigolium config set` to update individual config values using dot-notation keys:

```bash
vigolium config set scanning_pace.concurrency 100
vigolium config set database.driver postgres
vigolium config set notify.enabled true
vigolium config set notify.severities high,critical
vigolium config set server.service_port 8080
vigolium config set scanning_strategy.http.user_agent "Mozilla/5.0 (compatible; Vigolium/{version}; +https://github.com/vigolium/vigolium)"
```

These commands modify the main config file directly (an atomic rewrite). For one-off overrides during a scan, use CLI flags instead.

### Lists and maps

List and map settings take JSON or YAML flow syntax, decoded against the
setting's declared type. The comma form still works for lists:

```bash
vigolium config set scope.host.include '["*.example.com","example.com"]'   # JSON
vigolium config set scope.host.include '[*.example.com, example.com]'      # YAML flow
vigolium config set scope.host.include '*.example.com,example.com'         # comma form
vigolium config set scope.host.exclude.add admin.example.com               # append one
vigolium config set scope.host.exclude.add '["a.example.com","b.example.com"]'  # append several
vigolium config set scope.host.exclude.clear ''                            # empty the list
vigolium config set known_issue_scan.severity_overrides '{"tech-detect":"info"}'  # replace a map
```

A value is refused with exit 2 (`error.code: usage_error`) and the file is left
unchanged when it does not parse (`'["a",'`), has the wrong element type (`[1,2]`
into a list of strings), has an empty element (`a,,b`), carries JSON residue
(`"a","b"` in the comma form), or introduces an error-level validation issue at
that key (see below), such as a host pattern with a scheme. `vigolium scope set`
goes through the same parser and checks; it also refuses to write when the
config failed to load, and `--project <uuid>` writes only that key into the
project's overlay (`~/.vigolium/projects/<uuid>/config.yaml`).

### Validating the config

`vigolium config validate` checks the effective settings with the same rules
`config set` enforces and doctor's **Scope** check reports:

```bash
vigolium config validate                       # global config
vigolium config validate --project <uuid>      # global + that project's overlay
vigolium config validate -j --strict           # items[] of {key, severity, code, message, fix}
```

| Code | Severity | Meaning |
|---|---|---|
| `scope_pattern_invalid` | error | Empty pattern, leading/trailing whitespace, quote or bracket residue, or a malformed glob |
| `scope_host_has_scheme_or_path` | error | A host pattern containing `://` or `/` (hosts match the hostname only) |
| `scope_host_has_port` | warning | A host pattern ending in `:port`, which never matches |
| `scope_include_restrictive` | warning | `scope.host.include` with no wildcard: subdomains are dropped |
| `scope_include_matches_no_recent_target` | warning | That include admits none of the last `--recent` (default 5) scans' targets; skipped when no database exists |
| `scope_path_no_slash` | warning | A path pattern starting with neither `/` nor `*` |
| `scope_status_invalid` | error | A `status_code` pattern that is not a code, class (`2xx`, `30*`) or range (`400-499`) |
| `scope_origin_mode_invalid` | error | `scope.cli_origin_mode` not in `all`, `relaxed`, `balanced`, `strict` |
| `scope_body_action_invalid` | error | `scope.body_size_exceeded_action` not in `truncate`, `drop`, `skip-scan`, `passive-only` |
| `oast_server_missing` / `oast_server_url_invalid` / `oast_interval_invalid` | error | OAST enabled without a server, a malformed `server_url`, or a negative interval |
| `config_value_invalid` | error | A section's own validation failed (database, spidering, storage, ...) |
| `config_unknown_key` | warning | A key in the file that matches no setting |
| `config_load_failed` | error | The file does not load at all |

Every issue carries a `fix`, usually the exact `config set` to run. The command
exits 1 with `error.code: config_invalid` when any error-level issue is found;
`--strict` also fails on warnings. Under `-j` the envelope carries `valid` (the verdict, `--strict` included),
`errors`, `warnings` and `config_path`.

## Config Sections

### `scanning_strategy`

Controls which scan phases run for each strategy preset.

```yaml
scanning_strategy:
  default_strategy: balanced    # lite | balanced | deep
  heuristics_check: basic
  scanning_profile: ""          # name of a profile to auto-load
  profiles_dir: ~/.vigolium/profiles/

  session:
    session_dir: ~/.vigolium/sessions/
    use_in_discovery: true       # apply session headers during discovery/spidering
    compare_enabled: true        # cross-session IDOR/BOLA replay in dynamic-assessment
    reauth_interval: ""          # default check.interval for sessions (e.g. "2m")
    reauth_on_status: []         # default check.logged_out.status (e.g. [401, 440])
    validate_url: ""             # default check.url; `auth check` probes it without --url

  http:
    user_agent: preset           # preset | random | literal value; blank behaves like random
    host_errors:                 # dead-host breaker; the trip threshold is --max-host-error
      cooldown: 30s              # quarantine before the first re-probe
      max_cooldown: 5m           # cap for the doubling cooldown after failed probes
      max_trips: 5               # failed probes before the host is dead for the scan (<0 = never)

  # Phase toggles per strategy:
  balanced:
    discovery: true
    spidering: true
    known_issue_scan: true
    dynamic-assessment: true
    external_harvesting: false
```

Available strategies and their default phases:

| Phase | lite | balanced | deep |
|---|---|---|---|
| external_harvesting | - | - | yes |
| discovery | - | yes | yes |
| spidering | - | yes | yes |
| known_issue_scan | - | yes | yes |
| dynamic-assessment | yes | yes | yes |

**`http.user_agent`** — controls the `User-Agent` header on outgoing scanner
requests across HTTP phases. The default selector, `preset`, emits the
self-identifying Vigolium string. `random` rotates realistic browser strings;
blank behaves like `random`; any other value is used literally. The literal
`{version}` is replaced with the running binary version:

```bash
vigolium config set scanning_strategy.http.user_agent "Mozilla/5.0 (compatible; Vigolium/{version}; +https://github.com/vigolium/vigolium)"
```

Precedence: an explicit `-H 'User-Agent: ...'` CLI flag still overrides this for
the dynamic-assessment phase. The browser-driven spidering phase (`--spider`)
uses its native Chromium User-Agent and is not affected by this setting.

### `scanning_pace`

Centralized speed control. Common values serve as baselines; per-phase subsections override them.

```yaml
scanning_pace:
  concurrency: 25          # global worker count
  rate_limit: 100          # max requests/sec across all hosts
  max_per_host: 40         # max concurrent requests per host
  max_duration: 45m        # per-phase base duration (each phase scales it by its duration_factor)
  max_requests: 0          # stop the scan after N requests to the targets (0 = unlimited; --max-requests)
  max_requests_per_host: 0 # at most N requests to any one host (0 = unlimited; --max-requests-per-host)

  # Per-phase overrides (zero = inherit from common):
  discovery:
    concurrency: 0
    rate_limit: 0
    concurrency_factor: 0  # multiplier on common concurrency
    duration_factor: 0     # multiplier on common max_duration
  spidering:
    duration_factor: 0.1
  known_issue_scan:
    duration_factor: 0.5
  external_harvester:
    duration_factor: 0.1
  dynamic-assessment:
    duration_factor: 1.0
    parallel_passive: true         # run passive modules in parallel
    feedback_drain_timeout: 500ms  # wait for feedback loop items
```

> **Total scan cap (CLI):** `max_duration` above is only the per-phase base — on its
> own it does not bound total scan time, so back-to-back phases can sum well past it.
> The `--scanning-max-duration` CLI flag additionally caps the **total** wall-clock
> time of the whole scan at the value you pass: the per-phase `duration_factor`s then
> distribute that budget across phases (and remaining phases are skipped once it
> elapses) instead of each phase getting the full value sequentially. A single-phase
> run (e.g. `vigolium run known-issue-scan`) therefore matches the value exactly.

#### Unset, zero, and negative

A duration setting reads differently depending on whether it is absent, zero, or
negative. The three are not interchangeable:

| Value | Meaning |
|---|---|
| unset / `""` | Use the default for that setting |
| `0s` — `spidering.max_duration`, `--spider-max-time` | Use the 30m default. There is no "crawl forever": each target runs under a per-target deadline, so zero would mean *crawl nothing* |
| `0s` — `scanning_pace.discovery.max_duration`, `--discover-max-time` | Use the 1h default, for the same reason |
| `0s` — per-phase `max_duration` for dynamic-assessment / known-issue-scan | No phase deadline (unlimited); these phases are bounded by the total scan cap instead |
| negative | **Rejected** at config validation and at flag parse (exit 2). A negative duration is an already-expired deadline, so the phase would silently do nothing |

#### Rate limit precedence

`rate_limit` is resolved once and both enforced and reported from the same value:
**typed `--rate-limit` flag → scanning profile → `scanning_pace.rate_limit` →
unlimited.** A rate limit set through the REST API (`rate_limit` in the scan
request) applies to the native scan as well as to known-issue-scan.

The banner's `Speed:` line and the scan's config snapshot both report this
resolved value. `rate_limit_known_issue_scan` in the snapshot reports
`scanning_pace.known-issue-scan.rate_limit`, the one phase that can legitimately
run at a different rate.

#### Which phase enforces which dial

A pace section accepts all three dials for every phase, but each phase only
applies the ones its transport has. A dial a phase cannot apply is **warned about
on stderr** when you set it, and is **omitted** from the `scan.started` pace table
and from the phase's own `Speed:` line — so nothing presents an unenforced number
as effective.

| Phase | `concurrency` | `rate_limit` | `max_per_host` |
|---|---|---|---|
| `discovery` | yes (engine threads) | yes, **explicit only** (see below) | no (the scan's shared host slots apply) |
| `spidering` | no | no | no |
| `probe` | yes | yes | yes |
| `dynamic-assessment` | yes (workers) | no (scan-wide limiter) | no (scan-wide semaphore) |
| `known-issue-scan` | yes | yes | no |
| `external-harvest` | no | no | no |

`spidering` applies none of them: it drives one browser, with a per-target
`max_duration` as its only bound. Its entry is therefore absent from the
`scan.started` pace table rather than reported as zeros. `external-harvest`
applies none either: it only queries third-party archives and stores what they
return as request-only records, so it never sends a request to the target.

`discovery` is the one dial that does **not** inherit the global value. It is
paced only when a rate is set explicitly — `scanning_pace.discovery.rate_limit`
(equivalently `--rate-limit discovery=N`), or a typed `--rate-limit N` — because
the global `rate_limit` carries a 100 rps default and adopting it would slow down
every scan that merely loaded a config file. Unset means unpaced, and
`concurrency` remains the throttle. The section value wins over the global flag.
Discovery runs up to `discovery.target_concurrency` targets at once (never two on
the same host:port): `concurrency` is the phase's thread budget, split across the
targets in flight (`max(5, concurrency / active)`), and `rate_limit` is one
bucket shared by every target in flight, so it is the rate of the whole phase.
Discovery requests also take the scan's per-host slots and honour its dead-host
quarantine (see the egress gate below).

#### The egress gate

Every request a native scan sends to a target goes through one gate, in this
order: the dead-host quarantine check, a global `rate_limit` token, a per-host
slot (`max_per_host`), then one counted wire attempt.

- **Retries** (`--retries`, default 1) are separate attempts: each takes a
  token, and the backoff before it (1s, doubling, capped at 10s) is slept
  without holding the host slot. Only transport errors are retried; raw
  requests (smuggling and request-line probes) are never retried.
- **Redirect hops** that are followed take a token each; the original request's
  host slot is held through the hops.
- `requests_sent` (events, `scan status`, `scans.total_requests`) counts wire
  attempts, retries and hops included.
- **Discovery** uses its own token bucket (above) with the shared host slots and
  quarantine. **Session logins** go through the gate on a priority lane that may
  use one reserved slot per host, so a login never waits behind the module
  requests that are waiting for it. The **port-sweep** HTTP confirm step is
  gated; its TCP connect pre-filter is counted but not paced. The
  `tls_cert_recon` and `tls_protocol_cipher_audit` handshakes take a gated
  attempt each.

- **Request budgets** (`max_requests`, `max_requests_per_host`) are checked in
  the gate too, before the rate token: a request over budget is refused and
  never dialed. Running out of `max_requests` stops the scan (partial,
  `stop_reason: request_budget`); running out of `max_requests_per_host` stops
  traffic to that host only (the `host_request_budget` limit). The browser
  crawl's in-scope requests count toward `max_requests` within 500ms; nuclei
  and the own-dialer paths below are not counted. See
  [request budgets](guides/native-scan-phases.md#request-budgets).

Some paths bypass the gate. `scan.started` lists them, for the phases the scan
runs, as `egress: {gated: [...], exempt: [{path, reason}]}`:

| Exempt path | Why |
|---|---|
| `known-issue-scan` | nuclei's own HTTP stack; its pace section's rate and concurrency apply |
| `spidering` | the Chrome crawl; requests are counted, not gated |
| `browser-confirmations` | Chrome used by confirmation modules; low volume |
| `http_request_smuggling.cl0` | own raw-socket dialer; also bypasses `--proxy` |
| `probe-tls`, `scheme-detection` | one TLS handshake / TCP connect per host:port in the probe phase |
| `external-harvest`, `oast`, `npm-registry` | not target traffic |

### `discovery`

Content discovery (directory/file brute-forcing).

```yaml
discovery:
  mode: files_and_dirs         # files_and_dirs | files_only | dirs_only
  scope_mode: subdomain        # any | subdomain | exact
  save_response_body: true
  enable_malformed_path_probe: false
  enrich_targets: false        # feed paths from spidering/harvest into discovery
  extract_words:               # harvest response-body words into the observed wordlist; unset = on at --intensity deep only
  target_concurrency: 0        # targets at once; 0 = min(targets, 3); same host:port never overlaps
  flush_interval: 15s          # stream records every interval (and per 500 nodes); "0" = at target end
  stream_fuzz: true            # stream wordlist/fuzz results too (keep-first dedup, first-N cluster cap); false = at target end

  recursion:
    enabled: true
    max_depth: 5

  wordlists:
    tier: auto                 # embedded dir/file lists: auto | short | long | large (auto: deep → large, else short)
    short_file_path: ""        # custom wordlist paths (win over the tier)
    long_file_path: ""
    short_dir_path: ""
    long_dir_path: ""
    fuzz_wordlist_path: ""     # --discovery-wordlist (repeatable) replaces it
    use_observed_names: true
    use_observed_paths: true
    use_observed_files: true
    enable_numeric_fuzzing: false

  extensions:
    test_custom: true
    custom_list: []
    test_observed: true
    test_backup_extensions: true
    backup_extensions: []
    test_no_extension: true

  engine:
    case_sensitivity: auto_detect  # auto_detect | sensitive | insensitive
    timeout: 10s                   # per-request timeout (1s-300s)
    custom_headers: {}
    enable_cookie_jar: false
    max_consecutive_errors: 0
    max_consecutive_waf_blocks: 0
    observed_max_items: 4000
    disable_secret_scan: false  # disable the in-process secret scanner

  jstangle:
    enabled: true
    replay_mode: exact           # exact | conservative | off (confidence gate)
    replay_safety: read-only     # metadata-only | read-only | safe-baseline | state-changing
    source_maps: true
    asset_graph: true
    protocol_handshake: false    # bounded WebSocket/SSE GET handshake
    worker_count: 0              # 0 = clamp(CPUs/2, 2, memory_budget_mb/384), max 8; one pool per process, grown (never shrunk) when a later discovery asks for more
    memory_budget_mb: 0          # 0 = min(2048, max(768, RAM/8)) MiB
    cache_mb: 128
    worker_max_jobs: 100
    worker_max_rss_mb: 1024
    job_timeout: 60s
    normal_input_mb: 1           # above this, discovery drops costly stages
    max_ast_input_mb: 4          # above this, use bounded lexical fallback
    max_unpack_input_mb: 16      # beautify/unpack without an AST up to here; <= hard_input_mb (0 = hard)
    hard_input_mb: 16            # larger scripts are skipped and counted (js_input_over_hard_limit)
    max_requests_per_file: 500
    max_ast_nodes: 500000
    max_asset_depth: 4
    max_assets_per_parent: 64
    max_assets_per_host: 512
    max_assets_total: 2048
    max_chunks_per_runtime: 512  # webpack/Vite chunks one bundle's loader may add (replaces max_assets_per_parent for them)
    persist_unreplayed: true     # also store JS templates never sent (withheld/deduped) as source=jstangle rows
    persist_not_found_emit_statuses: [400, 405, 415, 422]  # not-found replays handed to later phases
    max_persisted_js_templates: 2000  # per-target cap (js_template_persist_cap limit)
  sitemap:                     # robots-named sitemaps, else /sitemap.xml + /sitemap_index.xml
    enabled: true
    max_urls: 2000               # sampled URLs spidered per target (sitemap_cap limit when hit)
    per_shape: 3                 # sampled URLs per host + path shape
    follow_index: true           # follow <sitemapindex> children (depth <= 2, <= 16 each)
```

`exact` is the safe default: only high-confidence templates produce traffic.
`conservative` additionally permits bounded medium-confidence completion. `off`
stores JavaScript intelligence without replaying extracted requests. Source-map
and asset fetching still obey the ordinary discovery scope, rate, and HTTP
session policy. Full generated/beautified code is stored as a verified artifact,
not in the typed JSON result.

### `spidering`

Browser-based crawling.

```yaml
spidering:
  max_depth: 6               # 0 = unlimited
  max_states: 1500           # 0 = unlimited
  max_duration: 30m
  max_consecutive_fails: 100
  headless: true
  browser_count: 1           # >1 is clamped to 1 (parallelism comes from tabs)
  tabs: 1                    # tabs of that browser crawling one shared state graph (max 16); 1 at every intensity for now
  tab_isolation: shared      # shared (one cookie jar) | context (each extra tab gets its own)
  strategy: adaptive         # normal | random | oldest_first | shallow_first | adaptive
  include_response_body: true
  browser_engine: chromium   # chromium | ungoogled | fingerprint
  no_cdp: false              # disable CDP event listener detection
  max_listener_probe_nodes: 2000  # click-listener nodes turned into candidates per state; 0 = 2000, -1 = no cap
  no_forms: false            # legacy: interaction.edit_fields + submit_forms = false
  self_register: false       # legacy: interaction.register_account = true
  identity_email_domain: ""  # domain of generated emails; "" = example.com
  require_auth: false        # fail a target whose configured auth cannot be applied
  max_capture_body_bytes: 0  # dynamic body ceiling; 0 = 16 MiB, -1 = none
  graph_output_dir: ""       # write crawl graphs here (one file per crawl)
  graph_include_values: false  # keep credential-bearing values in graphs
  route_seeds: true          # browse client routes found in the JS (initial crawl + re-spider)
  max_extra_seeds: 50        # route seeds browsed per target crawl (0 = 50)
  interaction:               # what the browser may change; every key optional
    edit_fields: true        # type into / toggle / select controls
    submit_forms: true       # dispatch a form submit by any mechanism
    upload_files: true       # attach the generated benign fixture to file inputs
    download_files: false    # let the browser save downloads
    register_account: false  # complete a signup form (never on by intensity)
    login_attempts:          # unset: on at balanced/deep, off at quick/lite
    dialogs: record-dismiss  # record-dismiss | accept-all
  browser_compat:            # browser security exceptions; every key optional
    no_sandbox: false        # sandbox on unless the host cannot provide one
    ignore_tls_errors: true  # like the scanner's HTTP transport
    allow_insecure_content: false
    disable_web_security: false
```

**Interaction policy.** (Full contract: [Browser policy](guides/browser-policy.md).)
`spidering.interaction` is the one table of what a browser crawl is permitted
to change. An omitted key keeps its default and
survives a profile or project overlay that does not name it; an explicit key
always wins — over the legacy `no_forms` / `self_register` keys (a conflict is
logged once) and over the intensity. The resolved policy is printed under the
Spidering phase header as a `Policy:` line, with the source of every value that
is not the default (`config`, `no_forms`, `self_register`, `intensity`).
Intensity only picks the default for `login_attempts` and sizes its credential
list; it never authorizes an account to be created.

What each switch enforces:

- `submit_forms: false` (or `--no-forms`) is a no-submission guarantee for the
  native crawl: submit controls and Enter actions are refused at dispatch
  (counted as "prevented by policy" in the Spidering summary), GET/POST form
  synthesis does not run, and every page gets a guard that stops native and
  script-driven form submission (`form.submit()`, `requestSubmit()`, submit
  events). It also withdraws the intensity default for `login_attempts`.
  It cannot stop a page script that sends its own `fetch`/XHR from an ordinary
  click handler — no browser crawl can promise a read-only website.
- `login_attempts` / `register_account` are their own authorization: when set,
  those submissions go through even with `submit_forms: false`.
- `upload_files: true` (default) attaches a benign generated fixture (or the
  configured value) to file inputs, so the upload surface is exercised.
  `false` attaches no file and generates no fixture; the input is reported as
  unsupported by policy. Uploads are field edits, so `edit_fields: false` (or
  `--no-forms`) withdraws them too.
- `download_files: false` (default) makes the browser deny downloads; when
  allowed, files land in the run's own browser profile, never `~/Downloads`.
- `edit_fields: false` leaves every control untouched.

A click fills only the controls of the form it would submit (the clicked
element's own form, honoring the `form=` attribute); a click outside any form
— a link, or an SPA "form" made of loose inputs and a scripted button — still
fills the page's inputs. Generated email addresses (signup, login, email
fields) use `identity_email_domain`, `example.com` by default — reserved, with
a null MX, so nothing is ever delivered — and never the target's own domain.
A page-provided example address is still preferred.

**Capture.** A dynamic (HTML/JS/JSON/API) response whose encoded body is
larger than `max_capture_body_bytes` (16 MiB by default — above the API-spec
ingest window, so spec parsing is unaffected) is still recorded, without its
body; the capture counts these and logs how many at the end. Stored response
times (`duration_ms`) measure request → response headers; the time spent
pulling a body out of the browser is no longer included, so values are lower
than in earlier versions for body-bearing responses.

`max_depth` and `max_states` bound how the crawl spends its clock. With both
unlimited, a link-dense site can sink the whole `max_duration` into one deep
branch, and a template that mints a state per row (a paginated table, a
calendar) can consume the budget on near-identical pages. Set either to `0` to
lift the bound.

**Browser security.** The crawler launches Chromium with its ordinary
boundaries — process sandbox on, mixed content blocked, same-origin policy
intact — and relaxes one only when `spidering.browser_compat` asks.
Certificate errors are ignored by default, matching the scanner's HTTP
transport (which does not verify either), so a self-signed target the rest of
the scan reaches is crawlable too; set `ignore_tls_errors: false` to verify.
The sandbox is dropped automatically, with one named warning, where the host
cannot provide it (running as root, in a container, or with user namespaces
disabled), and on Linux when a sandboxed launch fails and an unsandboxed retry
works (Ubuntu 23.10+'s AppArmor user-namespace restriction is the usual cause).
`--browser-insecure` turns all four exceptions on — for local test apps only.
The effective posture is printed under the Spidering header as a
`Browser security:` line.

**Authentication in the browser.** The session cookies and auth headers the
HTTP phases use (`--auth`, `--auth-file`, `-H`) are bridged into the crawl.
Cookies keep their own `Domain`/`Path`, so the browser's jar decides where they
go. Auth headers are page-wide in the browser (they ride on every request a
page makes), so they are installed only while the crawl is on a host the
operator scope admits — with no custom scope, the target host and its
subdomains. When the start URL redirects to a host outside that (a relocated
app the crawl adopts, or a login wall), the headers are cleared and not
reinstalled; the host is logged and counted (never the header values). The
browser cannot hold a header back from the redirect hop itself, nor from a
third-party subresource on an in-scope page — that needs request
interception, which the crawler does not do. The outcome is reported per
target as `auth_state`: `not-requested`, `configured`, `applied` or `failed`
— never "verified", because applying credentials does not prove the
application accepted them. By default a `failed` target is still crawled
(unauthenticated) and the Spidering summary says so; `require_auth: true` (or
`--require-auth`) fails that target instead.

**Reaching what nothing links to.** An interaction crawl can only find what a
click leads to. Three sources run alongside it and are on by default:

- **Route declarations.** `robots.txt` and `sitemap.xml` are fetched from the
  seed page and everything they name in scope is recorded. `Disallow` entries
  are the valuable half — they enumerate what the owner kept out of search
  indexes, which is routinely the admin and internal-tooling surface. Up to 25
  of the declared locations are also browsed into the crawl, chosen to spread
  across distinct path shapes so a sitemap dominated by one template does not
  consume the whole allowance.
- **Speculative strings.** URL-like strings in HTML comments and inline script
  are scraped from the *rendered* document and fetched. A single-page app writes
  its API base paths and route table into inline script that only exists after
  the framework runs, so these are invisible to anything reading the served HTML.
- **Self-registration** (`self_register`, off by default). Completes a public
  signup form and continues as the account it creates, turning the authenticated
  surface from unreachable into ordinary crawlable content. Runs at most once
  per host, only submits to an in-scope host, and reuses the identity it creates
  at any later login form. It is a write, so it stays opt-in at every intensity:
  set `interaction.register_account: true` (or the legacy `self_register: true`).
  Before this policy existed `--intensity deep` turned it on implicitly; it no
  longer does.

**Extra sweeps.** After the action queue drains with budget left, the crawler
re-visits known locations and re-extracts. Actions unlock state out of order — a
menu that only appears once logged in, a section revealed by an earlier form —
and every location captured before that point was extracted against the old
view. A second sweep then re-attempts the actions that failed on transient page
conditions (an overlay, a node detached mid-render) instead of dropping whatever
they guarded. Both stop immediately if the crawl ended on its budget or on a
failure streak.

**`graph_output_dir`** writes the finished crawl graph as JSON, one file per
crawl: `crawl-graph-<host>-<run>-<seq>.json`, where `<run>` is the scan UUID
and `<seq>` numbers the crawls of the process, so same-host seeds and repeat
runs never overwrite each other. Captured traffic records *what* was
requested; the graph records *how* the crawler got there — the source and target
state of every transition, the selector for the element that was actioned, and
the form values it carried. That is the difference between a list of URLs and a
reproducible route. Each file also carries the run's manifest: the interaction
policy and browser security posture in force, and the capture receipt.

Graphs are written owner-only (`0600`) and atomically, and are **redacted by
default**: password and hidden field values, fields and URL parameters whose
names read as credentials (`token`, `secret`, `code`, `session`, …), URL
userinfo, and element `value`/`data-*` attributes are replaced with
`<redacted>`; the file says `"redacted": true`. `graph_include_values: true`
keeps them and marks the file `"redacted": false`. Graph files written by
earlier versions (`version` 1) were not redacted and should be treated as
sensitive.

### `dynamic-assessment`

Controls which scanner modules run and JavaScript extension settings.

```yaml
dynamic-assessment:
  enabled_modules:
    active_modules: ["all"]    # ["all"] or list of module IDs
    passive_modules: ["all"]

  # hygiene_modules: true     # unset = follow intensity (see below)
  # allow_risky_payloads: true # risk:high payloads/modules below deep (see below)

  param_mining:                 # hidden-parameter mining (deep or --param-mining)
    max_endpoints_per_host: 50  # 0 = default 50
    max_requests_per_endpoint: 60
    # wordlist: ~/params.txt    # extra names, tried before the built-in list

  extensions:
    enabled: false
    extension_dir: ~/.vigolium/extensions/
    custom_dir: []              # additional script paths
    variables: {}               # key-value pairs passed to scripts
    allow_exec: false           # enable exec() and setEnv() in scripts
    sandbox_dir: ""             # base path for file ops (empty = cwd)
    yaml_strict: false          # unknown .vgm.yaml key = load failure, not a warning (default true next minor)
    allow_load_failures: false  # keep scanning when an --ext/custom_dir file fails to load (--ext-allow-failures)
    limits:
      timeout: 30s
      max_memory_mb: 128
```

An extension named with `--ext` or listed in `custom_dir` that fails to load
stops the scan before any request (exit 2, `error.code`
`extension_load_failed`) unless `allow_load_failures` is set; one found in
`extension_dir` is skipped with a warning. Every failure is reported as an
`extension.failed` event and in `scan.finished.extensions_failed`. See
[writing extensions](customization/writing-extensions.md#when-an-extension-fails-to-load).

**Hardening advisories (`hygiene_modules`).** Fourteen modules report a *missing
best-practice control* rather than an exploitable condition — absent security
headers, weak TLS protocol/cipher policy, cookie and session-cookie attributes,
and the CSP/HSTS/SRI/Permissions-Policy/COOP audits. They are cheap to run and
fire on nearly every response, so on a crawl of any size they contribute one
near-identical Info/Low row per URL and bury the findings worth triaging.

Below `--intensity deep` they do not run. The gated set is every module tagged
`hygiene`:

| | |
|---|---|
| Info | `security-headers-missing`, `permissions-policy-detect`, `cross-origin-isolation-audit`, `subresource-integrity-detect`, `password-autocomplete-detect` |
| Low | `tls-protocol-cipher-audit`, `hsts-preload-audit`, `csp-weakness-audit`, `cors-vary-origin-missing`, `cookie-security-detect`, `mixed-content-detect`, `reverse-tabnabbing-detect`, `content-type-mismatch`, `express-session-audit` |

The Info-tier fingerprints, endpoint/param observers, and `surface-scoring` are
*not* in this set — their output feeds tech tags, scoring, and active-module
targeting, so they still run at every intensity. Neither is
`clickjacking-detect`, which stays on at Medium.

To get the advisories back:

```bash
vigolium scan -t https://example.com --intensity deep          # per scan
vigolium scan -t https://example.com --module-tag hygiene      # just this family
vigolium scan -t https://example.com --module-id security-headers-missing
vigolium config set dynamic-assessment.hygiene_modules true    # every scan
```

`hygiene_modules` sets the default for a broad (`["all"]`) selection: `true`
runs them at every intensity, `false` suppresses them even at deep. Naming them
explicitly with `--module-tag` or `--module-id` always wins, the same way an
explicit selection already bypasses the intensity tier ceiling.

**Risky payloads (`allow_risky_payloads`).** `OR`-per-row and stacked time-blind
SQLi payloads, and whole modules tagged `risk:high`, run only at `--intensity
deep` by default (MSSQL time-blind is therefore deep-only). Set
`allow_risky_payloads: true` to allow them at every intensity. The
`--allow-risky-payloads` flag on `scan`, `run`, `scan-url` and `scan-request`
overrides this value in either direction; deep always allows them. See
[Risky Payloads](native-scan/modules-reference.md#risky-payloads-riskhigh).

**Param mining (`param_mining`).** Bounds the `param-mining` phase, which runs
before the assessment at `--intensity deep` or with `--param-mining` and stores
every hidden parameter it confirms as a `source: param-mining` record. These keys
shape it only (`max_endpoints_per_host`, `max_requests_per_endpoint`, `max_words`,
`wordlist`, `concurrency`); `--param-mining=false` or `--skip param-mining` turns
it off. See [Param Mining](guides/native-scan-phases.md#param-mining).

### `scope`

Defines what is in scope for scanning. Exclude rules take priority over include rules.

```yaml
scope:
  applied_on_ingest: false       # enforce scope during ingestion (not just scanning)
  cli_origin_mode: balanced      # balanced (default) | all | relaxed | strict
  ignore_static_file: true       # skip images, fonts, video, audio, etc.
  max_request_body_size: 1048576     # 1 MB
  max_response_body_size: 524288000  # 500 MB
  body_size_exceeded_action: truncate  # truncate | drop | skip-scan

  host:
    include: ["*"]
    exclude: []
  path:
    include: ["*"]
    exclude: []
  status_code:
    include: ["*"]
    exclude: []
  request_content_type:
    include: ["*"]
    exclude: []
  response_content_type:
    include: ["*"]
    exclude: []
  request_string:
    include: []
    exclude: []
  response_string:
    include: []
    exclude: []
```

### `server`

REST API server settings.

```yaml
server:
  auth_api_key: ""                 # auto-generated if empty; also set via VIGOLIUM_API_KEY
  users_file: ~/.vigolium/users.json
  service_port: 9002
  ingest_proxy_port: 0             # 0 = disabled
  ingest_proxy_host: ""            # empty = 127.0.0.1; --ingest-proxy-host wins
  ingest_proxy_token: ""           # Proxy-Authorization secret; --proxy-token wins
  ingest_proxy_allow: []           # client CIDRs/IPs; --proxy-allow replaces
  cors_allowed_origins: reflect-origin
  enable_metrics: true
  enable_burp_bridge: false        # opt in to merging live Burp Proxy history into /api/http-records
  burp_bridge_url: 'http://127.0.0.1:9009'
  api_version_default: 1           # REST body shape for requests that don't negotiate one (1 or 2)
  auto_create_projects: false      # true = an unknown X-Project-UUID is created instead of 404
```

`api_version_default` picks the REST response version for a client that does
not ask for one (`Accept: application/vnd.vigolium.v2+json`,
`Vigolium-Api-Version: 2` or `?api_version=2`). v1 is the historical shape;
v2 is the CLI's envelope (`items`, and an `error` object with a string `code`).
See [API overview](api-references/overview.md#response-versions).

`auto_create_projects` restores the old behaviour of creating any unknown
`X-Project-UUID` on first use. Without it the API answers
`404 project_not_found`, and a client that means to create the project sends
`X-Project-Create: 1` (or `?create=1`) with the request.

`enable_burp_bridge` is the gate, not `burp_bridge_url`. The URL ships with a
default address, so the bool is what decides whether the bridge is contacted —
otherwise every config would silently enable it. Precedence is
`-B/--burp-bridge-url` → `$VIGOLIUM_BURP_BRIDGE_URL` → config (only when
`enable_burp_bridge: true`). Passing the flag works regardless of the bool.
`--caido-bridge-url` is an alias of the same flag (a Caido plugin exposing the
same loopback bridge); both spellings set the same value and read the same env
var and config key.

The REST API binds `127.0.0.1` unless `--host` or `$VIGOLIUM_SERVER_HOST` says
otherwise. The ingest proxy binds `ingest_proxy_host` (default `127.0.0.1`); a
non-loopback proxy bind needs `ingest_proxy_token` and/or `ingest_proxy_allow`
(or the `--proxy-token` / `--proxy-allow` flags), otherwise `vigolium server`
exits 2 before listening.

### `agent`

AI agent integration. Agent commands dispatch through the in-process **olium**
engine; individual provider drivers may call an API, a compatible local
endpoint, Vertex AI, the Claude CLI, or the Claude SDK bridge.

```yaml
agent:
  default_agent: olium
  templates_dir: ~/.vigolium/prompts/
  sessions_dir: ~/.vigolium/agent-sessions/
  stream: true

  browser:
    enable: true
    binary_path: ""               # empty = agent-browser on PATH

  olium:
    provider: openai-compatible    # shipped default: local Ollama
    model: ""                       # empty = provider/custom-provider default
    oauth_cred_path: ~/.codex/auth.json
    oauth_token: ""
    llm_api_key: ""                # prefer ${ENV_VAR}
    reasoning_effort: medium
    system_prompt: ""
    max_tokens: 1000000
    temperature: 0.0
    max_turns: 32
    cache_size: 1024
    max_concurrent: 4              # 0 = default 4; negative = unbounded
    call_timeout_sec: 600          # negative = no added provider deadline
    preflight_timeout: ""          # preflight ping deadline; "" = 15s (60s for a loopback endpoint)
    autopilot_mode: legacy         # legacy | shadow | enforced
    custom_provider:
      base_url: http://localhost:11434/v1
      model_id: gemma4:latest
      api_key: ""
      extra_headers: []

  context_limits:
    max_findings: 50
    max_endpoints: 100
    max_high_risk: 20
    min_risk_score: 50

  guardrails:
    log_commands: false
    max_turns: 0
    disallowed_tools: []

  audit:
    enable: false
    mode: balanced
    sync_interval: 30
    default_agent: ""              # empty = infer claude/codex from provider
```

Supported providers are `openai-compatible`, `openai-codex-oauth`,
`openai-api-key`, `openai-responses`, `anthropic-api-key`, `anthropic-oauth`,
`anthropic-cli`, `anthropic-claude-sdk-bridge`, `anthropic-vertex`,
`google-vertex`, and `anthropic-compatible`. Most agent commands accept
`--provider` and `--model` overrides.

`autopilot_mode: shadow` records and verifies durable candidates without
promoting them through the enforced path; `enforced` enables durable candidate
promotion and `--resume`; `legacy` retains the earlier operator behavior.

The deprecated `agent.llm` block is accepted only for backward compatibility;
new configuration belongs under `agent.olium`.

### `database`

Storage backend. SQLite is the default; PostgreSQL is supported for multi-user deployments.

```yaml
database:
  enabled: true
  driver: sqlite                   # sqlite | postgres

  sqlite:
    path: ~/.vigolium/database-vgnm.sqlite
    busy_timeout: 15000
    journal_mode: WAL              # DELETE | TRUNCATE | PERSIST | MEMORY | WAL | OFF
    synchronous: NORMAL            # OFF | NORMAL | FULL | EXTRA
    cache_size: 10000

  postgres:
    host: localhost
    port: 5432
    user: vigolium
    password: ""
    database: vigolium
    sslmode: disable
    max_open_conns: 25
    max_idle_conns: 5
    conn_max_lifetime: 5m
```

### `known_issue_scan`

Known-issue scanning powered by the Nuclei template engine.

```yaml
known_issue_scan:
  tags: []                         # nuclei template tags (empty = all)
  exclude_tags: [dos]
  severities: []                   # filter: critical, high, medium, low, info
  templates_dir: ""                # custom templates path
  enrich_targets: true             # feed discovered paths into known-issue scan
  severity_overrides:              # remap recorded severity by template ID (case-insensitive)
    config-json-exposure-fuzz: medium
```

> **Right-sizing template severities:** `severity_overrides` remaps the severity a
> finding is recorded with, keyed by nuclei template ID, applied before output and
> persistence so the stored finding, console output, and severity counts all agree.
> Use it for noisy or context-dependent templates (an exposed `config.json` often
> ships only public base URLs / feature flags) instead of forking the upstream
> template, which reverts on `nuclei -update-templates`. Set an entry back to the
> template's own severity to undo a default remap.

> **Single-phase runs sweep all severities:** the balanced default narrows
> `severities` to `critical,high`. When known-issue-scan is the **only** phase
> requested (`vigolium run known-issue-scan` or `--only known-issue-scan`), Vigolium
> treats it as a focused full scan and widens `severities` to all levels for that
> run, printing a one-line notice. Pass `--known-issue-scan-severities` to override.

### `mutation_strategy`

Controls how parameter values are mutated during active scanning.

```yaml
mutation_strategy:
  default_modes: [append]

  value_aware:
    enabled: true
    max_per_intent: 5
    default_intents: [neighbor, boundary, escalation]
    enum_mappings: {}              # custom enum escalation pairs
    param_synonyms: {}             # custom param name synonyms

  field_type_defaults:
    email: ["test@example.com", "user@test.org"]
    uuid: ["550e8400-e29b-41d4-a716-446655440000"]
    integer: ["1", "100", "999"]
    # ... (all standard types have built-in defaults)
```

### `external_harvester`

Pre-scan intelligence gathering from public data sources.

```yaml
external_harvester:
  sources: [wayback, commoncrawl, alienvault, arquivo]
  # Additional sources: urlscan, virustotal (require API keys)

  api_keys:
    urlscan: ""
    virustotal: ""

  per_shape: 3          # URLs kept per shape (host + path template + query names); -1 = no cap
  max_urls: 5000        # URLs kept per harvested domain after shaping; -1 = no cap
  cdx:
    page_size: 10000    # Wayback CDX rows per resumeKey page
    max_rows: 200000    # CDX rows read per domain; hitting it reports limit cdx_max_rows; -1 = no cap
  probe: true           # harvest-probe: check harvested URLs on the live target before later phases scan them
```

Every harvested URL is normalized before dedup: scheme and host lowercased,
default port and fragment dropped, query pairs sorted by key, and tracking
parameters (`utm_*`, `fbclid`, `gclid`, `_ga`, `mc_*`, …) removed. Static assets
(images, fonts, CSS, audio/video, PDFs, archives) are dropped; `.js` and `.map`
are kept because JS analysis reads them. The survivors are grouped by shape —
host, `pathshape` template (`/users/42` → `/users/{int}`) and sorted query
parameter names — and at most `per_shape` URLs per shape and `max_urls` per
domain are stored. The phase prints raw versus kept counts with the reason for
each drop.

The Wayback index query keeps `collapse=urlkey`, filters out 404 rows and
image/font/video/audio MIME types on the server (301/302/401/403 rows are kept:
they are real endpoints), and pages with `showResumeKey`/`resumeKey`. A server
that returns a full first page without a resume key is re-read once unpaged.
Reaching `cdx.max_rows` stops the query and is reported as the `cdx_max_rows`
limit on the `external-harvest` phase outcome.

`wayback` and `commoncrawl` do more than read their index. Both also mine the
archived response bodies the index points at — the robots.txt history of the
main hosts, the sitemaps those files name, and a bounded sample of captured
HTML/JavaScript — and emit the in-scope URLs found inside. That recovers
endpoints no CDX index holds: a path that was only ever named in a script
bundle, or one a site owner listed in robots.txt precisely so no crawler would
record it. Mining is on by default, is capped by fixed per-domain budgets rather
than flags, and is skipped entirely if the index query returns nothing.

The harvest never contacts the target; URLs are stored as request-only records
(`source=harvest`). With `probe: true` (the default) and a later phase that
reaches the target, the `harvest-probe` step runs right after the harvest: one
liveness request per origin, then one GET per harvested URL on a live origin
(redirects recorded, not followed). Dead origins, `404`/`410` and soft-404 answers
are dropped and their stubs deleted; survivors keep `source=harvest` with their
response filled in. The counts land on the step's phase outcome. `probe: false`
(or `--skip harvest-probe` for one run) leaves every stub for the later phases to
fetch themselves. See [native scan phases](guides/native-scan-phases.md#external-harvest).

### `oast`

Out-of-Band Application Security Testing via interactsh callbacks.

```yaml
oast:
  enabled: true
  server_url: oast.pro
  token: ""                        # optional auth token
  poll_interval: 5                 # seconds
  grace_period: 10                 # seconds after scan for late callbacks
  oast_url: ""                     # fixed callback URL (empty = auto-generate)
  blind_xss_src: ""                # JS script src for blind XSS payloads
  enabled_blind_xss: false
```

A `server_url` without a scheme registers over https only. If that fails, OAST
is unavailable for the scan; it is never retried over cleartext http. Write
`http://…` explicitly to use a cleartext interactsh server.

Registration runs in the background from the start of a scan whose plan includes
`dynamic-assessment`, so earlier phases hide its latency. The registration
request is bounded at 3s with no retry, and dynamic assessment waits at most 3s
more for it. When OAST is unavailable the scan prints one line
(`OAST unavailable (oast.pro: dial timeout) — blind/out-of-band checks skipped`),
emits an `oast.unavailable` event, records the non-stopping reason
`oast_unavailable` (the scan is `partial`), and runs without out-of-band checks.
`grace_period` is only waited out when a round actually planted a callback URL.

#### Your own callback endpoint (`oast_url`)

`oast_url` (or `--oast-url`) replaces interactsh with an endpoint you run and
log. Put `{nonce}` in it so every probe gets its own callback:

```yaml
oast:
  oast_url: "https://{nonce}.cb.example.com"   # nonce in the host (DNS + HTTP)
  # oast_url: "https://cb.example.com/{nonce}" # nonce in the path (HTTP only)
```

Each probe mints a nonce locally (an xid: 20 characters of `[0-9a-v]`) and
plants the template with it, without the scheme (`<nonce>.cb.example.com`, the
same bare shape interactsh URLs have). The nonce's context (project, scan,
class, module, target, parameter, request hash, planted payload) is stored in
the `oast_payloads` table. Nothing polls your endpoint: when its log holds the
callbacks, attribute them with

```bash
vigolium oast ingest cb.log --format raw-log            # access / DNS query log, one callback per line
vigolium oast ingest out.jsonl --format interactsh-json # interactsh-client -json
vigolium oast ingest poll.json --format collaborator-json -j
```

`oast ingest` looks for stored nonces in each callback's host or path (case-
insensitively), rates the callback as a live interactsh callback would, and
saves the finding to the scan that planted the probe. Callbacks without a
stored nonce are ignored (`unmatched`); ingesting the same log again adds
nothing (`duplicates`). The lookup is scoped to the current project. For
`raw-log` the protocol is guessed per line (an HTTP request line is `http`,
SMTP verbs `smtp`, anything else `dns`, the weakest claim); `--protocol`
sets it for every line.

An `oast_url` without `{nonce}` keeps the old behaviour: every probe plants the
same URL, so a callback cannot be traced to the probe that caused it. The scan
says so once at the start of dynamic assessment (`oast.mode:
fixed-uncorrelated` on stderr and as an `error` event); the scan is not marked
partial. `doctor` shows the mode on its OAST line.

### `notify`

Vigolium ships three notification channels:

| Channel  | Lifecycle                | Severity-filtered? | Best for |
|----------|--------------------------|--------------------|----------|
| telegram | Per-finding              | Yes                | Live alerts on critical/high findings |
| discord  | Per-finding              | Yes                | Live alerts on critical/high findings |
| webhook  | One POST per scan        | No                 | Programmatic integrations, CI/CD, dashboards |

The **`provider`** field picks which channel is active:

| `provider` value | Effect |
|------------------|--------|
| `webhook`        | Only the scan-completion webhook fires |
| `telegram`       | Only per-finding telegram messages fire |
| `discord`        | Only per-finding discord messages fire |
| `""` (empty)     | All configured channels fire (legacy default) |

```yaml
notify:
  enabled: false
  provider: ""        # webhook | telegram | discord | "" for all
  severities: [high, critical, medium]

  telegram:
    bot_token: ""
    chat_id: ""

  discord:
    webhook_url: ""

  webhook:
    url: ""
    authorization: ""
    timeout_sec: 10
    events: [completed, failed, cancelled]   # default: every outcome
```

#### Webhook on scan completion

Fires a single `POST` once when a native or agentic scan reaches a terminal
state: `scan.completed`, `scan.failed` or `scan.cancelled`. One request per
scan, JSON body, retried up to 5 times on 5xx and network errors with
exponential backoff (1s, 2s, 4s, 8s, 16s). 4xx responses are not retried.

It fires on every exit of `scan`, `run`, `scan-url`, `scan-request` (the
direct path included, when results are persisted), `-S`, `--db-isolate`,
`ingest` and the REST server, after the scan row's terminal status is
written: a failed run, a scope that refused every target, and a Ctrl-C all
report. The scan does not wait for the POST, but the CLI process waits up to
10s for pending deliveries before it exits and prints a warning on stderr
for any it gives up on. A second Ctrl-C exits at once, so a webhook still in
flight then is lost. The server is long-lived and delivers in the background.

`events` limits which outcomes POST (`completed`, `failed`, `cancelled`; the
`scan.` prefix is accepted). Unset means all three. `config validate`
rejects an unknown value.

The webhook is best configured **per project** so each project can post to
its own endpoint. Run `vigolium project config [uuid]` to print the overlay
path, then edit `~/.vigolium/projects/<project-uuid>/config.yaml` directly:

```yaml
notify:
  enabled: true
  provider: webhook
  webhook:
    url: https://my-endpoint.example/scan-complete
    authorization: "Bearer ${MY_WEBHOOK_TOKEN}"
    timeout_sec: 10
```

**Headers:** `Content-Type: application/json` and (when set)
`Authorization: <raw value from config>` — vigolium passes the value through
verbatim, so any scheme works (Bearer, Basic, custom).

**Payload (`application/json`):**

```json
{
  "event": "scan.completed",
  "project_uuid": "8f2a...",
  "scan_uuid": "ab12...",
  "scan_type": "native",
  "target": "https://example.com",
  "status": "completed",
  "started_at": "2026-05-10T10:00:00Z",
  "finished_at": "2026-05-10T10:15:30Z",
  "findings": {
    "total": 12,
    "by_severity": { "critical": 1, "high": 3, "medium": 5, "low": 3, "info": 0 }
  },
  "result_url": "gs://8f2a.../native-scans/ab12.../results.tar.gz"
}
```

Additive fields: `completeness` (`complete`/`partial`, omitted when
unknown), `stop_reason` (why a partial run stopped short, e.g. `scan_budget`,
`cancelled`, `no_targets_in_scope`) and `error` (the failure message on
`scan.failed`).

Field notes:

| Outcome | `event` | `status` |
|---|---|---|
| Ran to its end, including a curtailed run (`completeness: "partial"`) | `scan.completed` | `completed` |
| Failed (an error, no target in scope, no target answered) | `scan.failed` | `failed` |
| Interrupted (Ctrl-C, SIGTERM, a REST stop) | `scan.cancelled` | `cancelled` |
| Agentic run stopped at `timeout` / `budget_exhausted` | `scan.completed` | the run status, `completeness: "partial"` |

- A receiver that filters on `event == "scan.completed"` gets exactly the
  runs it got before; the other two events are new. A cancelled native scan
  is stored as `failed` with error `cancelled`, and is reported as
  `scan.cancelled` / `cancelled`.
- A run that failed before its scan row was created (for example a session
  login failure) still reports `scan.failed` with the scan UUID it would have
  used, its target and an empty findings count.
- `scan_type` is `"native"` for module-driven scans; for agentic scans it is
  the run mode (`autopilot`, `swarm`, `audit`, `piolium`, or `query`).
- `result_url` is the [storage](storage.md) `gs://` URL for the result
  bundle. Empty when storage is disabled or the run did not request
  `--upload-results`.

## Scanning Profiles

Scanning profiles are YAML files stored in `~/.vigolium/profiles/` that override subsets of the main config. They can tune any combination of: `scanning_strategy`, `scanning_pace`, `discovery`, `spidering`, `known_issue_scan`, `dynamic-assessment`, `external_harvester`, `mutation_strategy`, `scope`, and `agent`.

Apply a profile with:

```bash
vigolium scan -t https://example.com --scanning-profile aggressive
```

This loads `~/.vigolium/profiles/aggressive.yaml` and overlays it onto the active config. Only non-zero fields in the profile override the base config; unspecified fields are left unchanged.

Built-in profiles are bundled in `public/presets/profiles/`. See [native-scan/scanning-modes-overview.md](native-scan/scanning-modes-overview.md) for details.

## Project-Level Config

Each project can have its own config overlay at `~/.vigolium/projects/<uuid>/config.yaml`. This uses the same format as scanning profiles and is automatically applied when the project is active.

Print the active or named project's overlay path with:

```bash
vigolium project config
vigolium project config <project-uuid>
```

Create or edit the returned `config.yaml` file; `project config` does not have
`set` or `show` subcommands.

See [projects.md](projects.md) for full project management documentation.
