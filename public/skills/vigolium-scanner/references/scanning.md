# Scanning Commands Reference

> **Related:** [agent-loop.md](agent-loop.md) for triage · [flags.generated.md](flags.generated.md) for any flag · `vigolium scan -h`

Complete flag reference for `scan`, `scan-url`, `scan-request`, and `run` commands.

## Choosing a scan command

- **`scan -t <url>`** — broad. Give it a bare host or root URL and it expands the
  surface itself (discovery, spidering, the full phase pipeline per `--strategy`).
- **`scan-url` / `scan-request`** — precision. Use these only when you're testing
  **one specific request**: it already has full query params, a deep multi-segment
  path, or custom headers/method/body that must be sent verbatim. They scan that
  single request (phases are opt-in via `--discover`/`--spider`).
- **`run probe -T hosts.txt`** — triage at scale. One request per target, no
  discovery or fuzzing, JSONL on stdout. This is the httpx replacement: use it to
  pick which of a thousand hosts deserve a real `scan`.

A full `scan` can exceed 30 min per target — discovery defaults to
`--discover-max-time 1h`, spidering to `--spider-max-time 30m`, and
`--scanning-max-duration` defaults to `0s` (**no total cap**). **Run a full scan
in the background**, or bound it explicitly:

```bash
vigolium scan -t https://target.example --scanning-max-duration 30m
```

To iterate on one part of the pipeline instead of the whole thing, run a phase
directly with `vigolium run <phase>` (see [run](#run)) — e.g. `run spidering` or
`run discovery`.

## Table of Contents

- [scan](#scan)
- [scan-url](#scan-url)
- [scan-request](#scan-request)
- [run](#run)
- [fingerprint](#fingerprint)
- [dns](#dns)
- [Strategy and Phase Interaction](#strategy-and-phase-interaction)
- [Replacing standalone recon tools](#replacing-standalone-recon-tools)

---

## scan

**Usage:** `vigolium scan [flags]`

Run a full vulnerability scan pipeline. Supports multiple targets, input formats, phase control, and strategy presets.

### Output flags (scan & run)

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--output` | `-o` | string | — | Write findings to specified output file |
| `--stats` | — | bool | `false` | Show live progress stats during scanning |
| `--include-response` | — | bool | `false` | Include full HTTP response body in output |
| `--omit-response` | — | bool | `false` | Omit raw request/response bytes (smaller files; drops the `.resp.*` files under `--format fs`) |
| `--fail-on` | — | string | — | Exit non-zero when a finding at/above this severity is present (`info`,`suspect`,`low`,`medium`,`high`,`critical`); output written first, `--soft-fail` overrides |
| `--split-by-host` | — | bool | `false` | Stateless multi-target (`-S -T file`): write per-host output files (`base-<host>.<ext>`); required for `-P > 1` **in this mode** (the `--db-isolate -T` fan-out needs no per-host files); no-op for `--format fs` |
| `--stateless` | — | bool | `false` | Use a temporary database, export results to `--output`, then discard |
| `--keep-db-on-error` | — | bool | `false` | On a **failed** `-S` run, move the throwaway database to `~/.vigolium/recovered/` instead of deleting it, so partial results survive (requires `-S`) |
| `--upload-results` | — | bool | `false` | Upload scan results to cloud storage after completion (requires storage config) |

Stateless mode creates a temp SQLite file, runs the full scan against it, writes
the export/report to `--output`, then deletes the DB (including WAL/SHM
sidecars). Mutually exclusive with `--db`. Combine with `--format jsonl`,
`--format html`, `--format fs`, or `--format sqlite` for shareable artifacts
(`sqlite` requires `-S`).

`-o` is **optional, not required**: without it the run warns that results will be
discarded with the temp DB and continues. The warning is suppressed under
`--silent`, `--split-by-host`, `-j`, and `--ci-output` — the last two stream
every record to stdout as it is written, so nothing is actually lost.

**A failed stateless run normally takes its findings with it.** `--keep-db-on-error`
moves the working database to `~/.vigolium/recovered/` instead (mode `0600`),
names the path in the error, and exits non-zero. Read it back with
`vigolium finding -S --db <path>`. A failed `--db-isolate` merge lands there too,
printing the exact `vigolium import --db <dest> <path>` command to recover it.

**Reach for `-S` for isolation, not just for CI.** The other half of what it buys
you is an empty database. A scan against the persisted DB resolves its work set
from every origin already in the project that passes the scope matcher (see the
**Host scope** section below), so repeated scans into the default store silently
grow what each run touches, and records from earlier scans sort *ahead* of the
target you just named. `-S`
removes that variable entirely, which is what makes it the right default for a
measurement run, a coverage comparison, or any scan whose result set you intend
to read as "what this target looks like".

`--format` accepts `console` (default), `jsonl`, `html`, `sqlite`, and `fs` (comma-separated for multiple):
- **`fs`** — a flat, browsable tree (`<base>-traffic/` + `<base>-findings/`) with per-host `.req` / `.resp.headers` / `.resp.body` / `.md` files and a jq-friendly `index.json`. No `-o` → `vigolium-traffic/` + `vigolium-findings/`. Works with or without `-S`. `--omit-response` drops the `.resp.*` files.
- **`sqlite`** (aliases `sqlite3`, `db`) — dumps the standalone per-run DB to `<output>.sqlite` via `VACUUM INTO`. Requires `-S/--stateless` + `-o`. Reopen with `vigolium finding/traffic -S --db <file>.sqlite`.

### Request flags (scan & run)

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--header` | `-H` | []string | — | Add custom HTTP header (repeatable, e.g. -H 'Auth: Bearer token') |
| `--advanced-options` | `-a` | map | — | Module-specific options as key=value (e.g. -a xss.dom=true) |
| `--retries` | — | int | `1` | Retry attempts for failed requests |
| `--stream` | — | bool | `false` | Process targets as a stream without buffering or deduplication |

### Input Format flags (scan & run)

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--target` | `-t` | []string | — | Target URL. **Repeat the flag** for several targets - commas are *literal*, so a query like `?ids=1,2,3` stays one target instead of splitting into three |
| `--target-file` | `-T` | []string | — | File of target URLs, one per line. Repeatable for several files; commas in the path are literal too |
| `--all-records` | — | bool | `false` | Rescan every HTTP record already in the active project. **Required** for a no-target run: bare `scan` / `run <phase>` is exit `2` (the message names the DB and project). Not combinable with `-t`/`-T`/`-i`/`-S` |
| `--input` | `-i` | string | `-` (stdin) | Spec / export to expand into requests (see `-i` vs `-T` below). A **single** value on `scan`/`run` - repeating it overwrites. Only `vigolium ingest` accumulates repeated `-i` |
| `--input-mode` | `-I` | string | `urls` | Input format. Canonical names: `urls`, `nuclei`, `openapi`, `wsdl`, `postman`, `curl`, `burpraw`, `burpxml`, `burpscope`, `har`, `deparos`. Old spellings still work as aliases (`swagger`→`openapi`, `burp`→`burpxml`, `raw`→`burpraw`). `vigolium --list-input-mode` prints the table with aliases and examples |
| `--input-read-timeout` | — | duration | `3m` | Deadline for reading input from stdin; `0` disables it, a negative value is exit `2`. Also on `scan-url`/`scan-request`. Raise it when piping a very large export through stdin. Implicit stdin (nothing else given) gives up after **2s with no first byte** (exit `2`); a typed `-i -` waits the full deadline |
| `--required-only` | — | bool | `false` | Parse only required fields from input format (ignore optional) |
| `--skip-format-validation` | — | bool | `false` | Skip validation of input file format |

### Other flags (scan & run)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--auth-file` | []string | — | Path to auth file (YAML/JSON, single session or `sessions:` bundle), or bare name resolved against session_dir. Repeatable. |
| `--auth` | []string | — | Inline session in `name:Header:value` format. Repeatable. |
| `--oast-url` | string | — | Fixed out-of-band callback URL instead of interactsh. Put `{nonce}` in it (`https://{nonce}.cb.example.com` or `https://cb.example.com/{nonce}`) so each probe gets its own nonce; then `vigolium oast ingest <log> --format raw-log\|interactsh-json\|collaborator-json` turns the callbacks your endpoint logged into findings of the planting scan. Without `{nonce}` callbacks cannot be attributed (`oast.mode: fixed-uncorrelated`) |
| `--max-findings-per-module` | int | `50` | Stop reporting after N distinct findings **per module** (`0` = unlimited) |
| `--max-host-error` | int | `30` | Skip a host after this many consecutive errors |
| `--no-clustering` | bool | `false` | Disable deduplication of identical concurrent HTTP requests |

**`--max-findings-per-module` is a reporting cap that is on by default.** A module
that fires on 400 URLs reports 50 - which is what you want during triage, and is
*not* what you want when you are measuring coverage or exporting a full corpus.
Drops are reported: `findings_capped` (per module) on `scan.finished` and the
phase outcome, plus the `findings_per_module` limit. `--max-findings-per-module 0`
lifts it.

`--max-host-error 30` is why a host that goes down mid-scan does not burn the
rest of the budget. Lower it for a wide `-T` sweep where a dead host should be
abandoned fast; raise it for a flaky target you still want scanned.
`--no-clustering` costs real requests - reach for it only when the dedup is
collapsing requests that the app actually treats as distinct.

### Host scope: `--scope-origin` (and what a non-empty database does)

| Mode | A host is in scope when… | `-t https://app.example.com` also admits |
|------|--------------------------|------------------------------------------|
| `strict` | hostname matches the target exactly | nothing else |
| `balanced` **(default)** | hostname shares the target's eTLD+1 | `sub.example.com`, `www.example.com`, … |
| `relaxed` | the candidate's registrable *label* contains the target's | `example.io`, `examplegroup.com`, … |
| `all` | always | every host in the project |

Resolution is `--scope-origin` → `scope.cli_origin_mode` in config → `balanced`.
IP targets always match exactly, whatever the mode.

**This is not only a filter on new traffic - it decides which *stored* records a
scan picks up.** Every assessment phase resolves its work set from the database:
distinct origins in the project, minus those the scope matcher rejects, minus
those whose (scheme, port) does not match a target's. There is no "this scan
only" filter, because `http_records` carries no scan id. So on a database that
already holds traffic from earlier scans:

```bash
# Target is ONE host, but at the default balanced mode this also (re)scans every
# https:443 *.example.com host already in the project - live requests, not replay.
vigolium scan -t https://app.example.com --only dynamic-assessment
```

Worse, it scans them *first*: the work set is ordered `risk_score DESC,
created_at ASC`, so older records outrank the one the seed phase just wrote for
your actual target. Under a tight `--scanning-max-duration` the named host can
go untouched.

Pick deliberately:

| Want | Use |
|------|-----|
| Exactly the host named, but keep its stored history | `--scope-origin strict` |
| Nothing pre-existing at all | `-S/--stateless` (throwaway DB) |
| Keep state, but separate from other work | `--db <file>` or a distinct `--project` |
| Deliberate brand-wide recon | `--scope-origin relaxed` |

The resolved mode is echoed in the `Scope:` line of the scan banner (stderr) and
recorded as `scope_origin_mode` on the `scan` object - visible in `--format
jsonl`, `vigolium export`, and the REST scan endpoints.

### Parallel, DB & module flags (scan & run)

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--parallel` | `-P` | int | `1` | Scan up to N targets concurrently as isolated child processes (requires `-S -T --split-by-host`, OR `--db-isolate -T`: one shape or the other, never both) |
| `--db-isolate` | — | bool | `false` | Scan into a private temp DB, then merge into `--db` at the end (SQLite only; ignored with a warning under `--stateless`, which keeps no database to merge) |
| `--resume` | — | bool | `false` | Resume a prior `-S -T --split-by-host -P` run from its `<output>.progress.json` manifest |
| `--follow-subdomains` | — | bool | `false` | Pull in-scope subdomains found in responses into the scan (auto-on at `--intensity deep`) |
| `--module-id` | — | []string | — | Run exactly these module IDs (exact match against **both** active + passive registries; unlike `-m`, also selects passive) — **scan/scan-url/scan-request only, not `run`** |
| `--passive-only` | — | bool | `false` | Run only passive modules (no active scan traffic) — **scan/scan-url/scan-request only, not `run`** |
| `--print-finding` / `--print-traffic` / `--print-traffic-tree` | — | bool | `false` | After the scan, print findings / raw traffic / traffic tree to stdout (pairs with `-S`/`--silent`) |
| `--report-url` | — | string | — | URL for the "Raw Report URL" button in HTML reports |
| `--no-waf-pacing` | — | bool | `false` | Disable proactive CDN/WAF-edge pacing |
| `--no-tech-filter` | — | bool | `false` | Disable tech-stack fingerprint gating of modules |

### Content Discovery flags (scan & run)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--discover` | bool | `false` | Enable content discovery phase before scanning |
| `--discover-max-time` | duration | `1h` | Max time for content discovery per target |
| `--discovery-wordlist` | stringArray | — | Custom wordlist file seeding the discovery phase's `/FUZZ` task (enables fuzzing on the fly). Repeatable: files are streamed in order and each word is tried once; a comma-joined value is split only when every part exists. A missing file exits 2. Formerly `--fuzz-wordlist`, still accepted as a deprecated alias. **Not** the same knob as `vigolium fuzz -w`. |
| `--no-discovery-fuzz` | bool | `false` | Disable discovery's `/FUZZ` brute-force (alias `--no-fuzz`). See the note below - it beats *every* reason the brute-force would turn itself on |
| `--no-prefix-breaker` | bool | `false` | Disable per-prefix circuit breaker that stops trap-directory recursion |
| `--port-sweep-ports` | string | — | Override the alternate HTTP(S) ports swept on CLI target hosts (comma-separated; the sweep runs at `--intensity deep` or with `--follow-subdomains`) |

**`--no-discovery-fuzz` is the off switch, not a default-setter.** Discovery's
`/FUZZ` brute-force auto-enables for three independent reasons - `--intensity
deep`, a discovery-only run (`vigolium run discover`), and the low-yield
auto-enable when passive extraction turns up little - so "I didn't pass
`--discovery-wordlist`" is not a guarantee it stayed off. This flag overrides all
three. It only stops the **brute-force**: link extraction, JS parsing,
response-word harvesting, and the short dir/file wordlists still run, so
discovery still finds what the app tells it about. Reach for it when the target
is rate-limited, metered, or behind a WAF you do not want to trip.

### Probe / host-sweep flags (scan & run)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--probe` | bool | `false` | Enable the host-sweep phase (same as `vigolium run probe`) |
| `--tls-probe` | bool | `false` | Handshake each HTTPS target; record negotiated version/cipher and the leaf certificate per host:port (read back with `vigolium hosts -j`, and as `tls` on `traffic -j` rows) |
| `--favicon` | bool | `false` | After the sweep, one icon read per answering origin (the page's `<link rel="icon">`, else `/favicon.ico`; not followed, not stored as a record), hashed like `fingerprint` does. Stored per host:port: `favicon_mmh3` and `favicon` in `vigolium hosts -j`, and `favicon` `{url, mmh3, md5, sha256, size}` on every `traffic -j` row and jsonl `http_record` line of the host. A redirecting target stores the icon of the origin it lands on |
| `--depth` | string | auto | `fingerprint` only: `light` (~9 reads/origin), `standard` (~60), `full` (adds sensitive paths, OPTIONS on answered paths, source maps). Default standard, light past 50 targets |
| `--redirect-mode` | string | `in-scope` | `off` \| `same-host` \| `same-apex` \| `in-scope` \| `any`. `in-scope` follows only to hosts the scan scope admits; a hop to another host never carries session or `-H` headers. `same-apex` follows within the registrable domain (`www.example.com` → `example.com` yes, `example.com` → `tracker.example.net` no). Applies to **every** phase, not just probe |
| `--record-redirect-chain` | bool | `false` | Each followed hop becomes its own `http_records` row, chained by `parent_uuid`. Read by the probe phase |
| `--no-response` | bool | `false` | Drop raw request/response bytes from output, keep every derived field (alias of `--omit-response`) |

A **probe-only** run (`run probe`, `scan --only probe`) flips its own defaults:
`--record-redirect-chain` on, `--redirect-mode same-apex`, the many-hosts
connection profile, and proactive WAF-edge pacing **off**. Each yields to an
explicit flag. `--tls-probe` / `--record-redirect-chain` on a run without the
probe phase warn that they are inert rather than doing nothing silently.

### Browser Spidering flags (scan & run)

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--spider` | — | bool | `false` | Enable browser-based spidering phase before scanning |
| `--spider-max-time` | — | duration | `30m` | Max time for spidering per target |
| `--browser-engine` | `-E` | string | `chromium` | Browser engine: chromium, ungoogled, fingerprint |
| `--browsers` | `-b` | int | `1` | Browser instances to launch for spidering (currently clamped to 1 — the crawler is single-threaded) |
| `--headless` | — | bool | `true` | Run browser in headless mode |
| `--no-cdp` | — | bool | `false` | Disable Chrome DevTools Protocol event listener detection |
| `--no-forms` | — | bool | `false` | Disable form filling and submission during spidering (sets `spidering.interaction` `edit_fields` and `submit_forms` off; an explicit interaction key wins) |
| `--browser-insecure` | — | bool | `false` | Spider with every browser security exception on: no sandbox, TLS errors ignored, mixed content allowed, same-origin policy off. For local test apps only |
| `--require-auth` | — | bool | `false` | Fail a target's spidering instead of crawling anonymously when configured authentication (session cookies/auth headers) cannot be applied to the browser (sets spidering.require_auth) |
| `--headed` | — | bool | `false` | Show the browser window during spidering (sugar for `--headless=false`; wins when both are set) |
| `--no-carry-browser-session` | — | bool | `false` | Do not carry the spidering browser's cleared session (cookies + UA) into discovery/scanning (on by default when `--spider` runs; scoped to the same host, respects `-H`) |

### External Harvest flags (scan & run)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--external-harvest` | bool | `false` | Enable external intelligence gathering phase (Wayback, CT logs, etc.) |

### KnownIssueScan flags (scan & run)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--known-issue-scan-tags` | []string | — | Nuclei template tags to include |
| `--known-issue-scan-exclude-tags` | []string | — | Nuclei template tags to exclude |
| `--known-issue-scan-severities` | []string | — | Filter Nuclei templates by severity (critical,high,medium,low,info) |
| `--known-issue-scan-templates-dir` | string | — | Custom Nuclei templates directory |

> **Source-aware / SAST scanning is an agent feature**, not a native `scan`/`run` phase.
> Use `vigolium agent audit --source <path-or-git-url>` (security code audit) or
> `vigolium agent query --source <path> --prompt-template security-code-review`. See `references/agent-modes.md`.

### Examples

```bash
# Basic scan
vigolium scan -t https://example.com

# Multiple targets
vigolium scan -t https://example.com -t https://api.example.com

# Targets from file
vigolium scan -T targets.txt

# Deep strategy with discovery
vigolium scan -t https://example.com --strategy deep

# Phase isolation
vigolium scan -t https://example.com --only dynamic-assessment
vigolium scan -t https://example.com --only ext --ext ./custom-check.js
vigolium scan -t https://example.com --skip discovery,spidering

# Specific modules
vigolium scan -t https://example.com -m xss-reflected,sqli-error

# Custom scanning profile
vigolium scan -t https://example.com --scanning-profile aggressive

# JSONL output
vigolium scan -t https://example.com --format jsonl -o results.jsonl

# HTML report
vigolium scan -t https://example.com --format html -o report.html

# Filesystem tree (run-traffic/ + run-findings/) — browsable with ls/grep/jq
vigolium scan -t https://example.com --format fs -o run

# Standalone per-run SQLite DB (requires -S)
vigolium scan -t https://example.com -S --format sqlite -o run.sqlite

# Fail the pipeline on any high/critical finding
vigolium scan -t https://example.com --fail-on high

# With proxy
vigolium scan -t https://example.com --proxy http://127.0.0.1:8080

# Speed tuning (bare form applies to the whole invocation)
vigolium scan -t https://example.com -c 100 --rate-limit 200

# Per-phase speed: cap the nuclei phase only
vigolium scan -t https://example.com --rate-limit known-issue-scan=20

# Watch it run from a program (human console stays on stderr)
vigolium scan -t https://example.com --events ndjson 2>/dev/null | jq -c .

# Source-aware / whitebox scanning is an agent feature (see agent-modes.md)
vigolium agent autopilot -t https://example.com --source ./src

# Source-aware via git clone (--source accepts a git URL)
vigolium agent swarm -t https://example.com --source https://github.com/org/repo

# OpenAPI scan
vigolium scan -I openapi -i openapi.yaml -t https://api.example.com

# WSDL / SOAP scan (one SOAP POST per operation; a .svc/.asmx URL auto-fetches the WSDL)
vigolium scan -I wsdl -i service.wsdl -t https://api.example.com
vigolium scan -i https://api.example.com/Service.svc

# Burp import scan
vigolium scan -I burp -i burp-export.xml -t https://example.com

# Pipe from stdin
cat urls.txt | vigolium scan -i -

# Filter modules by tag
vigolium scan -t https://example.com --module-tag spring --module-tag injection

# Run extension during scan
vigolium scan -t https://example.com --ext custom-check.js

# Extensions-only scan
vigolium scan -t https://example.com --only extension --ext custom-check.js
```

---

## scan-url

**Usage:** `vigolium scan-url <url> [flags]`

Scan a single URL for vulnerabilities. Designed for quick, targeted scans and AI agent integration. Returns JSON output with findings.

> Precision command — for one specific request; for broad surface expansion use `scan -t` (see [Choosing a scan command](#choosing-a-scan-command)).

### scan-url specific flags

**Spidering:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--spider` | bool | `false` | Run browser-based spidering before scanning |

**Discovery:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--discover` | bool | `false` | Run content discovery before scanning |

**Harvest:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--external-harvest` | bool | `false` | Run external intelligence harvesting before scanning |

**Request:**

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--header` | `-H` | []string | — | Custom header (repeatable) |

**Other:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--method` | string | `GET` | HTTP method |
| `--body` | string | — | Request body |
| `--known-issue-scan` | bool | `false` | Run known issue scan (Nuclei/Kingfisher) |
| `--no-passive` | bool | `false` | Skip passive modules |

### Scan tuning (shared with `scan`)

`scan-url` and `scan-request` register these with the same definitions and help text as `scan`:

| Flag | Path | Effect |
|------|------|--------|
| `--auth <name:Header:value>` / `--auth-file <path>` (aliases `--session` / `--session-file`) | Runner | Authenticated scan with session hydration, refresh and re-login, as on `scan`. See [auth.md](auth.md) |
| `--intensity quick\|balanced\|deep` | Runner | Applies the intensity's scanning profile, its `scanning_pace`, and its module-tier ceiling (`quick` stops at the moderate tier). It does not apply the profile's strategy (no phases switch on; use `--discover`/`--spider`/...), and `deep` does not port-sweep the host |
| `--scanning-max-duration <d>` | either | Caps the run. A run it ends is `partial` with `scan_budget` |
| `--oast-url <url>` | either | Fixed out-of-band callback URL instead of interactsh (ready at once) |
| `--scope-origin <mode>` | either | Host scope strictness for admission and the executor's scope filter |

"Runner" means the flag routes the request through the full native-scan runner, like `-o`, `-S` or a phase flag do. The scan document (`-j`) has the same shape on both paths.

On the direct path, out-of-band checks follow `oast.enabled` as on `scan`: with no `--oast-url`, interactsh registration starts before the request goes out and gets up to 3s. When it cannot register, stderr says `OAST unavailable (...) — blind/out-of-band checks skipped` once, and the scan row is `partial` with `oast_unavailable`. `vigolium config set oast.enabled false` turns OAST off.

### Examples

```bash
# Simple GET scan
vigolium scan-url https://example.com/api/users

# POST with body
vigolium scan-url https://example.com/login \
  --method POST --body '{"user":"admin","pass":"test"}' \
  -H "Content-Type: application/json"

# With discovery phase
vigolium scan-url https://example.com --discover

# Specific modules, no passive
vigolium scan-url https://example.com/api -m xss-reflected --no-passive

# Authenticated, quick intensity, capped at 10 minutes
vigolium scan-url https://example.com/api/me --auth-file admin.yaml --intensity quick --scanning-max-duration 10m
```

---

## scan-request

**Usage:** `vigolium scan-request [flags]`

Read a raw HTTP request from file or stdin and run scanner modules against it. Designed for pipeline integration and AI agent workflows.

> Precision command — for one specific request; for broad surface expansion use `scan -t` (see [Choosing a scan command](#choosing-a-scan-command)).

### scan-request specific flags

**Spidering:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--spider` | bool | `false` | Run browser-based spidering before scanning |

**Discovery:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--discover` | bool | `false` | Run content discovery before scanning |

**Harvest:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--external-harvest` | bool | `false` | Run external intelligence harvesting before scanning |

**Other:**

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--input` | `-i` | string | `-` (stdin) | Input file or stdin |
| `--target` | `-t` | string | — | Override target URL (scheme://host) |
| `--header` | `-H` | []string | — | Set a header on the captured request (repeatable). **`-H` overrides the capture**: it replaces every captured header of the same name (case-insensitive), or is appended when the capture has none. With two `-H` of one name, the last wins |
| `--known-issue-scan` | — | bool | `false` | Run known issue scan |
| `--no-passive` | — | bool | `false` | Skip passive modules |

The [scan tuning flags](#scan-tuning-shared-with-scan) (`--auth`, `--auth-file`, `--intensity`, `--scanning-max-duration`, `--oast-url`, `--scope-origin`) work as on `scan-url`.

### Examples

```bash
# From file
vigolium scan-request -i raw-request.txt

# From stdin
echo -e "GET /api/users HTTP/1.1\r\nHost: example.com\r\n" | vigolium scan-request

# With target override
vigolium scan-request -i request.txt --target https://staging.example.com

# With discovery
vigolium scan-request -i request.txt --discover

# Swap the captured (stale) session cookie for a fresh one
vigolium scan-request -i request.txt -H 'Cookie: session=fresh'
```

---

## run

**Usage:** `vigolium run <phase> [flags]`

**Aliases:** `r`

Run a single scan phase directly. Equivalent to `vigolium scan --only <phase>`.

### Valid phases

Phase names and aliases come from the binary, not from this file:
`vigolium strategy -j` lists every phase in `phases[]` with `canonical`,
`aliases`, `skippable` and `only_accepted` (`internal` phases such as
`param-mining` can be skipped but not run alone). `targeted-respider` is
accepted by `--only` beside spidering and discovery:
`--only discovery,spidering,targeted-respider` re-crawls the SPA routes
discovery found and stores the records with no assessment.
`vigolium run -h` and the `--only`/`--skip` help list the same names.

The one alias with a catch: `audit` means `dynamic-assessment` on `--only` and
`--skip`, but `vigolium run audit` is refused as ambiguous with the AI source
audit (`vigolium agent audit`). Type `vigolium run dast` for the native module
scan.

The `run` command accepts the same flag groups as `scan` (Spidering, Discovery, Harvest, KnownIssueScan, Input Format, Request, Output, and `--oast-url`), **except** the module-selection flags `--module-id` / `--passive-only`, which are only on `scan` / `scan-url` / `scan-request`.

### Examples

```bash
vigolium run probe -T hosts.txt --format jsonl --no-response        # host sweep, httpx-style
vigolium run probe -T hosts.txt --format jsonl --tls-probe -c 50    # + TLS certificates
vigolium run discover -t https://example.com
vigolium run spidering -t https://example.com
vigolium run dast -t https://example.com
vigolium run dast -t https://example.com --module-tag spring
vigolium run external-harvest -t https://example.com
vigolium run known-issue-scan -t https://example.com
vigolium run known-issue-scan -t https://example.com --known-issue-scan-tags cve --known-issue-scan-severities critical,high
vigolium run extension -t https://example.com --ext custom-check.js
vigolium run ext -t https://example.com --ext ./my-scanner.js
vigolium run deparos -t https://example.com
vigolium run dynamic-assessment -t https://example.com
```

---

## fingerprint

**Usage:** `vigolium fingerprint [url ...] [flags]` (same as `vigolium run fingerprint`)

Per origin, a bounded set of reads whose conclusions are stored as host facts:
the base page (title, `Server`, `X-Powered-By`, HTTP version, `Alt-Svc`, security
headers, JS framework signals, login forms, stack rules), the favicon the page
links (mmh3 + MD5 + SHA-256), well-known paths, API-definition paths, GraphQL
introspection, OPTIONS, a CORS preflight from a foreign Origin, Host-header
variants, three random paths for the **not-found baseline**, and — at `--depth
full` — sensitive-file paths, OPTIONS on every path that answered, and source maps.

- Every request goes through the scan engine: scope, `--rate-limit`,
  `--max-per-host`, `--max-requests[-per-host]`, WAF pacing; each is stored as an
  `http_record` with `source fingerprint`.
- Only reads (GET, OPTIONS, one introspection POST). Redirects are not followed —
  a 301 from `/robots.txt` to `/login` is the answer. A WAF block page is kept
  (remark `blocked:<reason>`): which edge answers is part of the fingerprint.
- The TLS handshake always runs for HTTPS origins.
- A path counts as reachable only when it does not look like the origin's
  not-found answer, so a host that serves 200 for everything does not "have"
  `/actuator` and `/wp-login.php`.
- A read that fails in transport is retried once after a short backoff at low
  concurrency. Reads still unanswered are listed in `fingerprint.errors[]`
  (`path`, `kind`: `network` | `budget` | `scope` | `blocked` | `cancelled` |
  `skipped`, `error`; plus `method`, `probe`, and `host` for a vhost read) and
  counted in `probe_errors`. A listed path was **not read** — do not treat it as
  absent.

`-j` is the scan document with the fingerprinted origins as `items` (the `hosts`
view: `title`, `server`, `status_code`, `technology`, `favicon_mmh3`,
`soft_not_found`, `tls_version`, `sans`, plus the full `fingerprint`, `not_found`
and `tls` documents, which `--compact` drops).

```bash
vigolium fingerprint https://app.example -j
vigolium fingerprint -T hosts.txt --depth light -j --compact
vigolium hosts --soft-404 -j --fields hostname,port,not_found
```

The stored baseline then answers "is this record the not-found page?" for any
later record from that origin: `vigolium traffic -j --fields url,matches_not_found`,
or drop them with `--exclude-not-found`. For responses vigolium did not record,
pipe them to `vigolium match-not-found -j` (see `data.md`).

## dns

**Usage:** `vigolium dns [name|url ...] [flags]`

Resolves A, AAAA, CNAME, MX, NS, TXT, SOA and CAA (`--type` to narrow) against
the system resolver or `--resolver host[:port]`, and stores the answers on the
host's port-0 row (`vigolium hosts --has dns`). The A/AAAA/CNAME also appear on
`traffic -j` rows for that host. Names outside the configured host scope are
refused unless `--ignore-scope`; `--no-store` prints without storing.

```bash
vigolium dns example.com api.example.com -j
vigolium dns -T hosts.txt --type mx,txt --format tsv     # name, type, ttl, value per record
```

## Strategy and Phase Interaction

### Strategy matrix

Strategies control which phases run. Select with `--strategy <name>`; print the
table with `vigolium strategy` (no `ls` subcommand). Default lives in
`scanning_strategy.default_strategy`.

| Strategy | ExtHarvest | Discovery | Spidering | KnownIssueScan | Assessment |
|----------|:---------:|:---------:|:---------:|:--------------:|:----------:|
| `lite` | no | no | no | no | yes |
| `balanced` *(default)* | no | yes | yes | yes | yes |
| `deep` | yes | yes | yes | yes | yes |

Source-aware / whitebox scanning is **not** a strategy — it is an agent feature
(`agent audit`/`autopilot`/`swarm` `--source`; see the SAST note below).

### Precedence

1. `--only <phase>` overrides everything — only that phase runs, heuristics disabled
2. `--skip <phase>` disables specific phases while keeping all others (`--skip preflight` drops the per-target reachability GET; scope admission still applies)
3. `--strategy <name>` sets baseline phase configuration
4. Individual phase flags (`--discover`, `--spider`, etc.) override strategy settings
5. Config file `scanning_strategy.default_strategy` provides the lowest-precedence default

### Heuristics

- Default: `--heuristics-check basic`
- Levels: `none`, `basic`, `advanced`
- `basic` probes target root pages to detect content type (HTML / JSON / blank) and skips spidering for non-HTML targets
- `advanced` adds deep HTML analysis to detect SPA frameworks and optimize phase selection
- `none` runs all enabled phases unconditionally
- `--skip-heuristics` is shorthand for `--heuristics-check=none`
- `--only` automatically disables heuristics
- Precedence: `--skip-heuristics` > `--heuristics-check` > config > `basic`

### Intensity Presets

`--intensity quick|balanced|deep` is a cross-cutting preset that maps to a scanning profile + strategy. It is also honored by `agent autopilot` and `agent swarm` with backend-specific defaults. Explicit flags always override the preset — e.g. `--intensity deep --scanning-profile foo` applies `deep`'s strategy but your custom profile.

### Scanning Pace

Speed settings have a layered precedence:

1. A **phase-qualified** CLI flag (`--rate-limit known-issue-scan=20`) — highest
2. A bare CLI flag (`-c`, `--rate-limit`, `--max-per-host`)
3. `--scanning-max-duration` — overrides `scanning_pace.max_duration`
4. Config `scanning_pace` section — per-phase max_duration and duration_factor
5. The strategy's own pace ceiling (`lite` only — see below)
6. Built-in defaults — lowest

**The pace flags apply whether or not you type them.** `--rate-limit` is
enforced at its documented default when unset; pass `--rate-limit 0` for
genuinely no cap. A negative value is a usage error (exit 2), not
"unlimited".

**Each of the three dials takes an optional phase qualifier, repeatable and
mixable with the bare form:**

```bash
# Cap nuclei without capping the ~200 native modules, which pace themselves.
vigolium scan -t https://target.example \
  --only known-issue-scan,dynamic-assessment \
  --rate-limit known-issue-scan=20

# Bare form, unchanged.
vigolium scan -t https://target.example --rate-limit 50

# Mixed: 50 rps everywhere, 20 for the nuclei phase.
vigolium scan -t https://target.example --rate-limit 50 --rate-limit kis=20
```

Qualifiers accept the same phase aliases as `--only`/`--skip` (`kis`, `cve`,
`deparos`, `dast`, …). A qualifier naming a phase this run does not execute
warns rather than failing. Resolution per phase is phase-scoped → global →
strategy/config default, and `scan.started` (under `--events`) reports the
resolved `pace` plus a `phase_pace` table for any phase that differs — assert
what applied instead of inferring it from the flags you passed.

**`--strategy lite` carries a pace ceiling** (concurrency 10 / rate 20 /
max-per-host 10) on top of selecting fewer phases. Previously `lite` and
`balanced` opened a crawl identically, so a name every operator reads as
"gentler on the target" was gentler in module count alone. The ceiling only ever
*narrows*: an explicit `--concurrency` overrules it, and a config already gentler
than `lite` is not dragged up to it. `balanced` is the baseline and `deep` ships
no ceiling.

**`known-issue-scan` opens conservatively when unattended.** It runs nuclei,
which owns its own HTTP stack and does not pace itself, so its no-flags defaults
are 20 rps / 10 host-concurrency. Before its phase starts, vigolium probes each
target host through the shared requester: a host whose edge is already filtering
is **dropped from the target list** (and reported as a `waf.block` event) rather
than scanned, and the per-host limiter's verdict narrows nuclei's own knobs. A
sentinel re-probes during the run and curtails the phase if a majority of hosts
start filtering.

### CI Output

- `--ci-output-format` was removed (exit 2): use `-j` for one scan document, or `--format jsonl -o <file>`
- `--silent` prints one plain line per finding on stdout and nothing else
- `-o` with no `--format` infers it from the extension (`.jsonl`, `.html`, `.sarif`, `.junit.xml`, …); `-j -o doc.json` writes the document to the file and a receipt to stdout

### Valid `--only` Phases

Every phase in `vigolium strategy -j` with `only_accepted: true`; `--skip`
takes every phase with `skippable: true`. Aliases are accepted on both.

### HTML Format Constraints

- `--format html` requires `-o/--output`
- In `scan` mode with `--only`, HTML is only supported for `discovery` and `spidering` phases
- The `export` command supports HTML for all data

### Filesystem & SQLite Format Constraints

- `--format fs` writes two sibling dirs off the `-o` base (`<base>-traffic/` + `<base>-findings/`); with no `-o` it defaults to `vigolium-traffic/` + `vigolium-findings/` in the cwd. Available on `scan` / `scan-url` / `scan-request` / `run`, `export`, and `db export`. `--split-by-host` is a no-op (fs already splits per host). For `scan-url` / `scan-request`, pass `-o`, `-S`, or a phase flag so the request routes through the runner that writes the tree
- `--format sqlite` requires `-S/--stateless` **and** `-o/--output`; aliases `sqlite3` / `db`. Under `--split-by-host` each file is `<base>-<host>.sqlite`. Reopen with `vigolium finding/traffic -S --db <file>.sqlite`

---

## Input formats

`-I <format>` selects the input type. Without `-I`, an `-i` file is detected from
its content (HAR, Postman, OpenAPI/Swagger, WSDL, Burp XML/raw/scope, curl,
nuclei, deparos, URL list); a file that is mostly not URLs and matches nothing
fails with `input_unparsed`. An explicit `-I` (including `-I urls`) turns
detection off for `scan`, `run` and `ingest`: the file is read as that format.

| Format | Flag | Example |
|--------|------|---------|
| URLs *(default)* | `-I urls` | `-t https://target.example` or `-T targets.txt` |
| OpenAPI 3.x | `-I openapi` | `-I openapi -i spec.yaml -t https://api.target.example` |
| Swagger 2.0 | `-I swagger` | `-I swagger -i swagger.json` |
| WSDL / SOAP | `-I wsdl` | `-I wsdl -i service.wsdl -t https://soap.target.example` — one SOAP POST per operation; a `.svc`/`.asmx` URL auto-fetches its WSDL |
| Burp XML | `-I burp` | `-I burp -i burp-export.xml` |
| cURL commands | `-I curl` | `-I curl -i requests.txt` |
| Nuclei templates | `-I nuclei` | `-I nuclei -i templates/` |
| HAR archive | `-I har` | `-I har -i traffic.har` |
| Postman collection | `-I postman` | `-I postman -i collection.json` |
| Burp scope export | `-I burpscope` | `-I burpscope -i burp-scope.json` — expands a program's scope into seed URLs (content-sniffed on `-T` too) |
| stdin | — | `cat urls.txt \| vigolium scan -i -` |

**`-i` vs `-T`:** `-i` reads a *spec / export* and expands it into requests; `-T`
reads a *list of target URLs*, one per line. Pointing `-T` at a YAML spec makes
every line of that file a target. The only genuine target-list formats are
`urls` and `burpscope`.

OpenAPI extras: `--spec-url` (use servers from the spec), `--spec-header`
(auth), `--spec-var` (parameter values), `--spec-default` (fallback). WSDL
reuses `--spec-header` (auth) and `--spec-var` (override a body element by its
local name); `-t` overrides only the endpoint host, keeping the WSDL path.
Postman: `-t` fills `{{baseUrl}}` / `{{url}}` and `--spec-var` fills other
`{{variables}}`.

## Output formats

| Format | Flag | Notes |
|--------|------|-------|
| Console *(default)* | `--format console` | human-readable tables to stderr |
| JSONL | `--format jsonl` | bulk `{"type":…,"data":{…}}` stream |
| HTML | `--format html -o report.html` | interactive ag-grid report; requires `-o` |
| Document / PDF | `--format report -o r.html` / `--format pdf -o r.pdf` | PDF via headless Chrome; `--pdf-timeout` bounds it (exit 1 `pdf_failed`) |
| Markdown | `--format markdown -o r.md` (alias `md`) | per-finding sections with finding_hash/scan_uuid/record_uuids; `--max-body-bytes` caps bodies |
| SARIF | `--format sarif -o out.sarif` | SARIF 2.1.0 for GitHub code scanning / DefectDojo |
| CSV | `--format csv -o f.csv` | one row per finding; formula-injection guarded |
| JUnit | `--format junit -o f.junit.xml` | suite per module, failure per finding at/above `--fail-on` (default `low`) |
| GitHub annotations | `--format github` | `::error`/`::warning`/`::notice` on stdout (or `-o FILE`); not with `-j`; appends to `$GITHUB_STEP_SUMMARY` |
| SQLite | `--format sqlite -S -o run.sqlite` | standalone per-run DB via `VACUUM INTO`; requires `-S` + `-o`; aliases `sqlite3`, `db` |
| Filesystem tree | `--format fs -o run` | browsable `run-traffic/` + `run-findings/`; see [agent-loop.md](agent-loop.md) |

Combine with commas: `--format jsonl,html -o report.html`.

### Exit-Code Gating

- `--fail-on <sev>` (`scan` / `run` / `scan-url` / `scan-request`) makes the command exit non-zero when a finding at/above `<sev>` was produced. Accepted (ascending): `info`, `suspect`, `low`, `medium`, `high`, `critical`
- Output is always written first; the gate fires afterward
- `--soft-fail` (global) forces exit 0 even when the gate (or any other error) trips
- Under `-P` / `--split-by-host` the gate is evaluated per child; the parent batch exits non-zero only when every target fails

### Source-Aware / SAST

Static analysis and source-aware scanning are **agent** features, not native `scan`/`run`
phases. Use `vigolium agent audit --source <path-or-git-url>` (security code audit) or
`vigolium agent query --source <path> --prompt-template security-code-review`. `--source` accepts a local
directory, a git URL (cloned automatically), a `.zip`/`.tar.gz`, or a `gs://` archive.

---

## Replacing standalone recon tools

A coding agent will instinctively reach for `nuclei`, `ffuf`, `katana`, `httpx`,
`gau`. Each maps to a vigolium phase (`run <phase>`) or a `kit` primitive - and
the win is that instead of piping four uninstalled binaries together, one binary
runs the phases into one DB you query with `-j/--json`.

**Do not go hunting the host for those binaries.** You will often *find* them,
and then the run's whole mapping happens outside the pinned traffic DB, outside
the phase model, with flags nobody scoped - invisible to every later `finding`,
`traffic` and `replay` call.

### Tool shims: type the argv you already know

You do not have to remember the native spelling. Vigolium accepts each tool's
own command line and routes it:

```bash
$ vigolium ffuf -u https://target.example/FUZZ -w words.txt
◆ routed to: vigolium run discovery -t https://target.example --discovery-wordlist words.txt
```

| Instead of | Shim | Native |
|---|---|---|
| `ffuf` / `feroxbuster` | `vigolium ffuf …` | `run discovery --discovery-wordlist` (FUZZ as the last path segment), else `fuzz <url-with-FUZZ> -w <list>` with matchers mapped |
| `nuclei` | `vigolium nuclei …` | `run known-issue-scan -t <url>` |
| `katana` / `gospider` | `vigolium katana …` | `run spidering -t <url>` |
| `gau` / `waybackurls` | `vigolium gau <domain>` | `run external-harvest -t <url>` (into the DB), or `kit harvest <domain>` (stdout, no DB) |
| `arjun` | `vigolium arjun -u <url>` | `fuzz --fuzz new-param -w params --anomaly <url>`, or `kit param-mine -t <url>` (batched) |
| `httpx` | none | `run probe -T hosts.txt --format jsonl` (aliases: `run httpx`/`alive`/`sweep`) |
| `subfinder` / `amass` | none | **not covered**: pass a host list with `-T` |

How each shim routes its argv:

| Shim | Routes to |
|---|---|
| `vigolium ffuf -u <url>/FUZZ -w <list>` (FUZZ is the whole last path segment, no matchers) | `run discovery --discovery-wordlist` |
| `vigolium ffuf -u <url>/api/FUZZ.php …`, FUZZ in a query/`-H`/`-d`, or any `-mc/-ms/-mw/-ml/-mr/-fc/-fs/-fw/-fl/-fr` | `fuzz <url> -w <list>` (FUZZ kept, matchers mapped) |
| `vigolium nuclei -u <url> -severity high -tags cve` | `run known-issue-scan --known-issue-scan-*` |
| `vigolium katana -u <url>` | `run spidering` |
| `vigolium gau <domain>` | `run external-harvest` |
| `vigolium arjun -u <url>` | `fuzz --fuzz new-param:query -w params --anomaly` |

Notable mappings (the full table is in each shim's `--help`):

| Tool flag | Native |
|---|---|
| ffuf `-t` / `-rate` / `-p` (s) / `-timeout` | `--concurrency` / `--rate-limit` / fuzz `--delay` (ms) / `--timeout Ns` |
| ffuf `-mc -ms -mw -ml -mr` / `-fc -fs -fw -fl -fr` | fuzz `--match-*` / `--exclude-*` |
| ffuf `-e .php,.bak` | discovery `--discovery-extensions php,bak`; fuzz `--suffix .php,.bak` |
| ffuf `-recursion` / `-recursion-depth N` | no-op note (discovery recurses by default) / `--discovery-max-depth N` |
| ffuf `-w list:KEY` | fuzz `-w list --keyword KEY` |
| ffuf `-ac` / `-of` | no-op notes (both routes calibrate; vigolium picks the file format) |
| katana `-list FILE` / `-ct 60` / `-jc` | `-T FILE` / `--spider-max-time 60s` / no-op note |
| nuclei `-l FILE` / `-t DIR` / `-t FILE-or-ID` | `-T FILE` / `--known-issue-scan-templates-dir DIR` (repeatable) / `--known-issue-scan-templates T` |
| arjun `-m GET/POST/JSON` / `-d` (s) / `--stable` / `-oJ` | `new-param:query` / `-X POST new-param:body` / JSON Content-Type `new-param:json`; `--delay` (ms); `--concurrency=1`; `-o` |
| gau `--subs` | `--scope-origin=relaxed` (keeps the subdomain URLs; does **not** widen the scan like `--follow-subdomains`) |

Both `-u X` and `-u=X` parse. Vigolium's own globals (`--db`, `--proxy`, `-j`,
`--project-name`, …) go **before** the tool's argv, or before an explicit `--`
when a spelling collides with the tool's own (nuclei/katana `-j` is JSONL):

```bash
vigolium ffuf --db scan.sqlite -u https://t/FUZZ -w words.txt
vigolium nuclei -j -- -u https://t -severity high
vigolium ffuf --dry-run -u https://t/api/FUZZ.php -w words.txt   # print, run nothing
vigolium -j arjun --dry-run -u https://t/api   # envelope: tool, argv, translated, native_command, notes
```

Behaviours to expect:

- **Every approximation is a printed note** under the `routed to:` line (and in
  `notes` of the `--dry-run -j` envelope): the ffuf route reason, `-ac`/`-jc`
  no-ops, gau `--subs`, arjun's one-candidate-per-request.
- **An unmapped argument is a hard error naming the native command**, never a
  silent drop - a dropped flag is a scan that ran with a scope nobody chose.
  An ffuf `-json` flag is refused with a pointer to `vigolium run discovery --help`
  and `vigolium fuzz --help`.
- **Where a concept does not exist, the shim says so rather than approximating.**
  `katana -d 3` errors: vigolium's spider is a state machine over DOM snapshots,
  not a depth-limited link follower, so bound it with `--spider-max-time`
  instead. Likewise arjun `-m XML`, ffuf `-p` on the discovery route, ffuf
  `-recursion` on the fuzz route, and nuclei without `-u`/`-l` (no stdin
  fallback).
- arjun maps to `fuzz --fuzz new-param` (one candidate per request). For
  batched, budgeted parameter mining use `vigolium kit param-mine -t <url>`, or
  `--param-mining` on a scan.

The shims are a redirect for muscle memory, not a full port. Once you know the
native form, prefer it - it takes every vigolium flag, the shims only a subset.

### The pattern

```bash
# One phase, throwaway DB, portable output - the direct tool substitute.
vigolium run <phase> -t https://target.example -S --format jsonl,fs -o out

# Or the full pipeline, which chains them (harvest -> discover -> spider ->
# known-issue-scan -> dynamic-assessment) per --strategy.
vigolium scan -t https://target.example --strategy deep
```

### nuclei -> known-issue-scan

`run known-issue-scan` *is* the nuclei engine plus native CVE modules and
Kingfisher secret scanning. Templates filter the same way:

```bash
vigolium run known-issue-scan -t https://target.example \
  --known-issue-scan-tags cve,exposure \
  --known-issue-scan-severities critical,high \
  --known-issue-scan-templates-dir ./my-templates
```

`--known-issue-scan-templates-dir` is repeatable; `--known-issue-scan-templates`
(repeatable) runs only the named template files or paths relative to the
templates directory, like nuclei's `-t file.yaml`.

`-I nuclei -i templates/` instead *ingests* a template's request definitions as
scan traffic (it does not run the templates as nuclei would).

### ffuf / feroxbuster -> fuzz (or discovery)

`vigolium fuzz` is the deliberate ffuf-style primitive - see [fuzzing.md](fuzzing.md).

```bash
vigolium fuzz https://target.example/FUZZ -w file-long --match-status-code 200,301
```

For dir/content discovery folded into a scan, use the discovery phase with a
wordlist: `vigolium run discovery --discovery-wordlist words.txt -t <url>`
(`--discovery-extensions php,bak` and `--discovery-max-depth N` are ffuf's `-e`
and `-recursion-depth`).

Or just type ffuf's own argv — `vigolium ffuf -u https://t/FUZZ -w words.txt`
translates to exactly that and prints what it ran (see "Tool shims" below).

### katana / gospider / hakrawler -> spidering

`run spidering` is a headless-browser, JS-aware crawl (state machine, not a
link-follower), so it reaches SPA routes a static crawler misses:

```bash
vigolium run spidering -t https://target.example -S --format fs -o crawl
```

### gau / waybackurls -> kit harvest (or external-harvest)

```bash
vigolium kit harvest target.example                      # stateless, prints URLs
vigolium run external-harvest -t https://target.example   # into the scan DB
```

Sources: Wayback, Common Crawl, AlienVault OTX, Arquivo by default; urlscan and
VirusTotal join when their keys are set under `external_harvester`.

### httpx -> `run probe`

`vigolium run probe` is the native prober. One request per target, passive tech
fingerprinting and attack-surface scoring, no content discovery and no fuzzing —
built for host lists in the thousands.

```bash
vigolium run probe -T hosts.txt --format jsonl --no-response   # stdout = JSONL
vigolium run probe -T hosts.txt --format jsonl --tls-probe -c 50   # + certificates
vigolium run probe -T hosts.txt -S --format sqlite -o sweep   # keep the DB
```

**`--format jsonl` makes stdout pure JSONL; progress goes to stderr.** Pipe with
`2>/dev/null`, or add `--silent` for a fully quiet run. (`-j` prints the one
scan document instead, without the per-record DNS/TLS fields.) Each line is
`{"type":"http_record","data":{…}}`, where `data` is:

```json
{"url":"https://www.example.com/","status_code":200,"response_time_ms":601,
 "ip":"104.16.123.96","a":["104.16.123.96","104.16.124.96"],
 "aaaa":["2606:4700::6810:7b60"],"cname":["origin.example.net"],
 "response_title":"Example","response_content_type":"text/html",
 "response_words":118,"surface_score":43,"technology":["cloudflare","nextjs"],
 "source":"probe",
 "tls":{"tls_version":"tls13","cipher":"TLS_AES_128_GCM_SHA256",
        "subject_cn":"www.example.com","subject_an":["www.example.com"],
        "issuer_cn":"YE2","not_after":"2026-12-02T07:35:03Z",
        "fingerprint_hash":{"sha256":"cf80…"},"self_signed":false}}
```

Field names match httpx's (`a`/`aaaa`/`cname`/`tls`), so a consumer written
against that output reads these unmodified.

| Flag | Effect |
|---|---|
| `--format jsonl` | JSONL on stdout (human progress stays on stderr) |
| `--no-response` | Drop raw request/response bytes; keep every derived field (alias of `--omit-response`) |
| `--tls-probe` | Handshake each HTTPS target; record version/cipher + leaf certificate per host:port |
| `--redirect-mode` | `off` \| `same-host` \| `same-apex` \| `in-scope` \| `any` — default `in-scope`; probe defaults to `same-apex` |
| `--record-redirect-chain` | Each followed hop becomes its own record, chained by `parent_uuid` (on by default here) |
| `-c/--concurrency` | Request workers; DNS prefetch runs at `min(c*4, 128)` |
| `-S/--stateless` | Throwaway DB; combine with `--format sqlite -o <base>` to keep it |
| `--export-only` | Record types in the JSONL envelope (`http`, `findings`, …); probe-only runs default to `http` |

**Probe-only defaults.** A standalone probe run (`run probe`, `scan --only
probe`, REST `{"only":"probe"}`) turns on: `--record-redirect-chain`,
`--redirect-mode same-apex`, the many-hosts connection profile (keep-alives off,
short header timeout), and **proactive WAF-edge pacing off** — one request per
host has no burst to pre-empt, and the pacing notice is noise across thousands of
targets. Reactive back-off after a real WAF block still applies. It also narrows
the JSONL envelope to `http_record` objects only: every finding a sweep produces
is a "Technology Detected" one, and that verdict is already on the record's
`technology` field, so emitting both says the same thing twice. Each yields to an
explicit flag (`--no-waf-pacing=false` re-enables pacing, `--export-only
http,findings` restores the findings). These defaults do NOT apply when the probe
rides along inside a wider scan.

**Two columns, no findings.** A sweep's output is record metadata, not findings,
so a "0 findings" summary is expected. `surface_score` is 0-100: the percentage
of the attack-surface signals present on that exchange (input surface,
method, session and login surface, non-standard port, response shape, and origin
posture — dynamic vs edge-cached, permissive CORS, leaked internals, API
markers). `technology` carries the host's detected stack, written once every
fingerprint module has settled.

**Stored per host, not per record.** `a`/`aaaa`/`cname`/`tls` describe the host,
so they are kept once per host:port and run (`host_observations`), not copied onto
every record; the record keeps a single `ip` column. `traffic -j` merges them back
onto each row, and `vigolium hosts -j` reads them without a record (`--sans` prints
the certificate names, a ready `-T` list). `surface_score`, `technology`,
`response_time_ms` and `parent_uuid` are record columns.

Rank a finished sweep:

```bash
vigolium traffic --source probe --sort surface_score -n 50
vigolium traffic --source probe -j --fields url,status_code,surface_score,ip
```

### curl -I / favicon hashing / OPTIONS / Host-header curls -> `fingerprint`

The per-host curl work — headers, the favicon hash, `robots.txt` and
`.well-known/*`, OPTIONS, a foreign-Origin preflight, Host-header variants, "does
this host answer 200 for everything?" — is one command whose requests are scoped,
paced and stored, and whose conclusions are re-readable:

```bash
vigolium fingerprint -T hosts.txt -j --compact
vigolium hosts --format tsv --fields hostname,port,title,server,favicon_mmh3,soft_not_found
```

`favicon_mmh3` is the Shodan `http.favicon.hash` / FOFA `icon_hash` key; the MD5
(Censys) is in `fingerprint.favicon.md5`. See [fingerprint](#fingerprint).

### dig / host / nslookup -> `dns`

The dig and host shims accept their usual argv and route to `vigolium dns`, which
stores every answer for `vigolium hosts` to read back:

```bash
vigolium dig +short MX example.com @1.1.1.1      # → vigolium dns example.com --type mx --resolver 1.1.1.1
vigolium dns -T hosts.txt --type a,cname,txt -j
```

Resolution only: `dig AXFR` and reverse lookups are refused.

### openssl s_client -> `hosts`

The negotiated version, cipher and leaf certificate (subject, SANs, issuer,
validity, fingerprints) are stored by `fingerprint` (always) and `run probe
--tls-probe`:

```bash
vigolium hosts '*.example.com' -j --fields hostname,port,tls_version,cert_not_after,sans
vigolium hosts --has tls --sans > more-hosts.txt
```

### subfinder / amass -> not covered

Vigolium does **not** do external passive subdomain enumeration. Bring your own
subdomain list via `-T`. `--follow-subdomains` only pulls in-scope hosts already
observed in responses (auto-on at `--intensity deep`); it is not a substitute.
