# Native Scan: Running Phases Independently

## Overview

Vigolium's native scan pipeline consists of multiple phases that run sequentially. You can run the full pipeline, isolate a single phase with `--only`, or skip specific phases with `--skip`. This guide walks through each phase and how to run them independently.

## The Full Pipeline

When you run a scan, the enabled phases execute in this order (the source of
truth is `BuildNativeScanPlan` in `internal/runner/native_plan.go`):

1. **Heuristics check** (`heuristics-check`) - fetch each target's root page and classify it (blank vs content, JSON/XML API; with `scanning_strategy.heuristics_check: advanced` also SPA detection and link counting) to decide whether spidering that target is worthwhile. It does not fingerprint technologies. On by default (`basic`); turned off by `--skip heuristics-check` and by any `--only` that does not list it
2. **Port Sweep** (`port-sweep`) - find extra web services on alternate ports of the CLI target hosts and add them to the target set. Only with `--intensity deep`, `--follow-subdomains`, or `--only port-sweep`; turned off by `--skip port-sweep` and by any `--only` that does not list it. Its HTTP confirm requests go through `--proxy`; the TCP connect that finds open ports cannot and always dials the host directly
3. **External Harvest** (`external-harvest`) - gather URLs about the target from third-party archives (Wayback Machine, CT logs); never contacts the target
4. **Harvest probe** (`harvest-probe`) - check the harvested URLs against the live target so later phases scan only the ones that still answer (see [External Harvest](#external-harvest)). Runs only when external-harvest ran AND a later enabled phase reaches the target anyway; `vigolium run external-harvest` alone never schedules it
5. **Spidering** (`spidering`) - browser-based crawling to discover dynamic content
6. **Probe** (`probe`) - one request per target, passive modules only, no content discovery (an httpx-style host sweep). Opt-in: runs only with `--only probe` / `vigolium run probe`
7. **Fingerprint** (`fingerprint`) - per origin, a bounded set of reads (well-known paths, favicon, CORS preflight, OPTIONS, Host-header variants, a not-found baseline) whose conclusions are stored as host facts (see [Fingerprint](#fingerprint)). Opt-in: `vigolium fingerprint` / `vigolium run fingerprint` / `--only fingerprint`
8. **Discovery / Ingestion** (`discovery`) - parse inputs and perform content discovery
9. **Targeted re-spider** (`targeted-respider`) - re-crawl the rich/SPA routes discovery surfaced after the first browser crawl, including client routes found only in the JavaScript (`spidering.route_seeds`). Needs spidering and discovery (and `discovery.respider` allowing it); a full scan runs it when dynamic assessment is enabled too. `--only discovery,spidering,targeted-respider` runs it without an assessment, storing the re-crawled records for a later `--only dynamic-assessment` run; `--only` naming it without spidering and discovery (or ingestion) is a usage error
10. **Seed** (`seed`) - when discovery/ingestion is skipped (for example `--only dynamic-assessment`), store the CLI targets as records so the assessment phases have something to scan. Not run under scan-on-receive
11. **Param mining** (`param-mining`) - discover hidden parameters (Arjun-style) on this scan's dynamic endpoints and store each one as a record, so the assessment tests it too (see [Param Mining](#param-mining)). On at `--intensity deep` or with `--param-mining`; never without dynamic assessment
12. **DynamicAssessment** (`dynamic-assessment`) - run active, passive, and extension modules
13. **Known Issue Scan** (`known-issue-scan`) - run Nuclei plus native in-process secret detection

Every step above is a name in the phase vocabulary, so each `phase.started` /
`phase.finished` id can be looked up in `vigolium strategy -j` (`phases[]`).
`harvest-probe`, `param-mining` and `seed` are **internal**: the plan schedules them on its
own gates, so `--only` rejects them. `--skip harvest-probe`, `--skip targeted-respider` and `--skip param-mining` are accepted
(external-harvest, spidering and the assessment still run); `seed` cannot be skipped. `targeted-respider` is
scheduled on its own gate too, but `--only` may name it beside spidering and discovery (see step 9).

**Preflight** (`preflight`, internal, `--skip` only) runs before step 1 whenever the CLI targets are the
scan's input (`-t`, positional URLs, `-T`, a piped URL list, `scan-url -S`): scope admission, then one GET
to each admitted target URL through the shared requester. No admitted target answering stops the scan
with exit `1` (`error.code: no_targets_reachable`) before any phase runs; some not answering keeps them
all in the plan and marks the scan `partial` (`targets_unreachable`). The heuristics check reuses the
root page preflight fetched, so with heuristics on the GET costs nothing extra for a root target.
`--skip preflight` turns the GET off (scope admission still applies). It is skipped for `run probe`,
plans that never reach the target (`run external-harvest`), scan-on-receive and `-i`/`--all-records`
input. See [Reachability](../coding-agent.md#reachability).

### When a phase fails

Every phase follows the same rule (`executeNativePhase`, `internal/runner/phase_errors.go`):

- **A phase error does not end the scan.** The phase is recorded `failed` with reason `phase_error`
  and its first error as the message, an `error` event is emitted, and the next phase runs on
  whatever the earlier phases stored. The scan finishes `completed` with completeness `partial`
  (`scan.finished` `curtailed`, `stop_reason: phase_error` unless something earlier stopped it).
  Discovery and seed are included: they used to abort the scan. A scan whose targets never got
  in is still loud, through the preflight's `no_targets_in_scope` / `no_targets_reachable` stop.
- **An infrastructure error stops the scan.** The database or a record store is closed or cannot
  be written (closed LevelDB, closed record writer, `sql: database is closed`, disk full,
  read-only database), the output writer is closed, or a session is lost under
  `reauth.on_failure: abort`. The phase is recorded `failed`, the phases after it `skipped` with
  reason `error`, and the error (`<phase> phase failed: …`) is the scan row's `error_message`
  and the `scan.finished{status: "failed"}` message (exit `1`). An explicit `--auth-file` login
  failure stops the scan before the first phase.
- **A phase cut short by the scan itself is not a failure.** When Ctrl-C,
  `--scanning-max-duration`, `--max-requests` or an auth abort ends the scan's context, the
  running phase is `partial` (`curtailed`) with that reason and the phases that never started are
  `skipped` with it.

A full scan with all phases enabled:

```bash
vigolium scan -t https://example.com --strategy deep
```

## Running a Single Phase

Use `vigolium run <phase>` or `vigolium scan --only <phase>` to execute one phase in isolation.

### Discovery

Discovers new endpoints through wordlist-based fuzzing and content probing:

```bash
vigolium run discovery -t https://example.com
```

Equivalent to:

```bash
vigolium scan -t https://example.com --only discovery
```

Tune discovery with additional flags:

```bash
vigolium run discovery -t https://example.com \
  --discover-max-time 30m \
  -c 100 \
  --rate-limit 200
```

#### Wire protocol and brute-force width

Discovery traffic is multiplexed where the origin allows it. Each origin is
pinned to one protocol before its first request: HTTP/3 when a direct QUIC
handshake proves it (never through `--proxy`), else HTTP/2 when TLS ALPN selects
it, else HTTP/1.1. Every discovery request to that origin then uses the same
protocol, including the soft-404 learner, so fingerprints are always compared
against responses of the same protocol. An origin whose HTTP/3 connections stop
working moves to TCP for the rest of the run and logs a warning. The module
scanner is unaffected and always sends HTTP/1.1.

Only the wordlist brute-force runs wider. Built-in file and directory lists and
the `/FUZZ` template get their own pool of `brute_force_concurrency` workers per
target. That defaults to the per-host slot cap (`scanning_pace.max_per_host`,
40), or to `-c` when `-c` is given explicitly. The spider, observed-word and
extension variants, JS fetches and validation probes keep the phase
concurrency. Every request still passes the scan's egress gate: host slots, rate
limit and dead-host breaker. Discovery responses also feed the per-host limiter,
so a host answering 429 or WAF block pages slows discovery down too. The
Discovery phase header prints the resolved values:

```
◆ Speed: threads=25, brute-force=40, rate-limit=unlimited, protocol=auto
```

```yaml
discovery:
  engine:
    protocol: auto              # auto | http1 | http2 | http3
    brute_force_concurrency: 0  # 0 = scanning_pace.max_per_host (or -c when given)
```

### Spidering

Crawls the target using a headless browser to discover pages, forms, and JavaScript-rendered content:

```bash
vigolium run spidering -t https://example.com
```

Control the browser engine, time budget and what the crawl may change:

```bash
vigolium run spidering -t https://example.com \
  -E chromium \
  --spider-max-time 20m \
  --no-forms
```

The crawler drives one browser (`-b`/`--browsers` above 1 is clamped to 1).
Under the phase header it prints the resolved interaction `Policy:` and the
`Browser security:` posture (see [Browser policy](browser-policy.md)). Its
completion line is built from capture receipts: when records were lost it says
`run incomplete` instead of reporting the stored count as the whole crawl, and
per-target notes call out authentication that could not be applied, credential
headers withheld from out-of-scope hosts, and readiness conditions that never
met.

The alias `spitolas` also works:

```bash
vigolium run spitolas -t https://example.com
```

### External Harvest

Pulls endpoints from external intelligence sources (Wayback Machine, certificate transparency logs).
It never contacts the target: each harvested URL is stored as a request-only record
(`source=harvest`, no response).
URLs are normalized (tracking params and static assets dropped, `.js`/`.map` kept) and sampled by
path shape before they are stored — see `external_harvester.per_shape`, `max_urls` and `cdx` in
[configuration](../configuration.md#external_harvester). A Wayback index that hits `cdx.max_rows`
is reported as the `cdx_max_rows` phase limit:

```bash
vigolium run external-harvest -t https://example.com
```

When a later phase will reach the target (`--external-harvest` on a normal scan,
`--only harvest,dast`, …), the **harvest probe** step runs right after the harvest,
so archive history is not fuzzed:

1. One liveness request per origin (`scheme://host:port`), to a random path. An
   origin with no HTTP answer has all of its harvested URLs dropped unfetched.
2. One GET per harvested URL on a live origin, through the shared requester (scan
   session, rate limit, per-host limiter). Redirects are recorded on the record,
   not followed.
3. `404`/`410` answers are dropped, as are soft-404s: on an origin that answers
   unknown paths with a `2xx` page or a `3xx` redirect, a response with the same
   status, media type and size (or redirect destination) as the random path's is
   treated as "not found". Origins that answer unknown paths with `404` are judged
   by status alone; `401`/`403`/`5xx` are always kept.

Survivors keep `source=harvest` and get their response filled in. Dropped URLs'
request-only stubs are deleted, so no later phase scans them (a record another
phase already fetched is never touched). The tallies land on the phase outcome
(`scan.phase_outcomes[].counts`): `stubs`, `hosts`, `hosts_dead`, `probed`, `kept`,
`dropped_dead_host`, `dropped_not_found`, `dropped_soft_404`, `dropped_failed`,
`unprobed`, `deleted`, `write_failed`. Turn the step off with `--skip harvest-probe`
for one run, or `external_harvester.probe: false` in the config, to let the later
phases fetch every harvested URL themselves.

### Known Issue Scan

Runs template-based scanning (Nuclei templates) against ingested endpoints:

```bash
vigolium run known-issue-scan -t https://example.com
```

Filter templates by severity or tags:

```bash
vigolium run known-issue-scan -t https://example.com \
  --known-issue-scan-severities critical,high \
  --known-issue-scan-tags cve,rce
```

### Param Mining

Finds parameters an endpoint reads although no recorded request carries them
(`debug=`, `callback=`, `admin=`) and hands them to dynamic assessment. It is
internal (no `--only`), and runs right before the assessment when either:

- `--intensity deep` (and no `--only`), or
- `--param-mining` (any intensity, also with `--only dast`).

`--param-mining=false` or `--skip param-mining` (aliases `params`, `arjun`,
`param-miner`) turns it off, and it never runs without dynamic assessment.

```bash
vigolium scan -t https://example.com --intensity deep        # mining included
vigolium scan -t https://example.com --param-mining          # balanced scan + mining
vigolium run dast -t https://example.com --param-mining      # rescan stored records with mining first
```

Endpoints come from the records the assessment will read: 2xx, GET or POST,
dynamic content (HTML, JSON, XML, text; no static assets), one per method and
path, the top `max_endpoints_per_host` (50) per origin by `risk_score`. Each is
mined by the same engine as `vigolium kit param-mine`: two baselines with a random
parameter (an endpoint whose baselines disagree is skipped as `unstable`), names
in chunks sized to the transport, bisection to single names, and two fresh-value
confirmations. The wordlist puts the host's own names first (from jstangle facts
and the host's recorded traffic), then `dynamic-assessment.param_mining.wordlist`,
then the built-in list (`vigolium kit wordlist params`). Every request goes
through the scan's requester (session, rate limit, host limiter);
`max_requests_per_endpoint` (60) bounds each endpoint, and a burst of 403/429/WAF
answers stops it.

Each confirmed parameter becomes an `http_records` row with `source:
param-mining`, a remark `param-mining:name=<n>;signal=<reflect|status|header|length|body>`,
and `hidden: true` on that parameter. `phase.finished` counts: `candidates`,
`endpoints`, `mined`, `unstable`, `blocked`, `budget_exhausted`, `failed`,
`names_tested`, `params_found`, `records_written`, `write_failed`.

```yaml
dynamic-assessment:
  param_mining:
    max_endpoints_per_host: 50
    max_requests_per_endpoint: 60
    max_words: 0          # 0 = no cap on the merged wordlist
    wordlist: ""          # extra names file, tried before the built-in list
    concurrency: 0        # endpoints at once; 0 = min(-c, 10)
```

### Fingerprint

```bash
vigolium fingerprint -T hosts.txt -j --compact          # same as: vigolium run fingerprint -T hosts.txt
vigolium fingerprint https://app.example --depth full
```

Per origin it sends a planned set of reads — the base page, the icon it links,
well-known and API-definition paths, a GraphQL introspection query, OPTIONS, a
CORS preflight from a foreign Origin, Host-header variants, and three random paths
— through the scan executor, so scope admission, `--rate-limit`, `--max-per-host`,
`--max-requests[-per-host]` and WAF pacing all apply, and every request is stored
as an `http_record` (`source fingerprint`). Redirects are not followed and only
reads are sent. HTTPS origins always get the TLS handshake.

A read that fails in transport (no response, a reset, a quarantined host) is
asked once more after a short backoff, at two workers per failing origin, so a
host that drops connections under the pass's concurrency still gets read. Every
read still unanswered is listed in the report's `errors` —
`{path, method, host, probe, kind, error}`, `kind` one of `network`, `budget`
(`--max-requests[-per-host]` refused it), `scope`, `blocked`, `cancelled` or
`skipped`, classified from the executor's reason rather than its message — and
counted in `probe_errors`. A path missing from the report with no `errors` entry
was read and not found.

The conclusions are stored once per origin and run in `host_observations`: the
report (stack, title, server, HTTP version, security headers, CORS verdict,
allowed methods, well-known and API-definition hits, login forms, favicon mmh3/MD5)
and the **not-found baseline** (status, size, title and a response signature for a
path no application serves). Read them with `vigolium hosts`; compare any later
record against the baseline with `vigolium traffic --fields url,matches_not_found`
or `--exclude-not-found`.

`--depth light` is about nine reads per origin, `standard` about sixty, `full` adds
sensitive-file paths, OPTIONS on every path that answered and source maps. The
default is standard for up to 50 targets and light beyond. A path counts as found
only when it does not look like the origin's not-found answer.

### DynamicAssessment

Runs active and passive vulnerability scanning modules. This is the core scanning phase. CLI aliases: `audit`, `dast`, `assessment`.

```bash
vigolium run dynamic-assessment -t https://example.com
```

Select specific modules or tags:

```bash
vigolium run dynamic-assessment -t https://example.com -m xss -m sqli
vigolium run dast -t https://example.com --module-tag injection
```

### Extension

Runs only custom JavaScript or YAML extensions:

```bash
vigolium run extension -t https://example.com --ext ./my-checks.js
```

## Skipping Phases

Use `--skip` to disable specific phases while keeping the rest of the pipeline:

```bash
# Run everything except spidering
vigolium scan -t https://example.com --discover --skip spidering

# Skip both spidering and known-issue-scan
vigolium scan -t https://example.com --discover --skip spidering --skip known-issue-scan
```

Note: `--only` and `--skip` cannot be used together.

## Phase Aliases

Every phase answers to several spellings. They work identically with `--only`, `--skip`, the `vigolium run <phase>` argument, the per-phase pace qualifiers (`--rate-limit crawl=20`) and the REST API's `only`/`skip` fields. Names are trimmed and lowercased first, so `--skip Spider` and `--skip ' spider'` both resolve.

| Phase | Also accepts |
|-------|--------------|
| `ingestion` | `ingest`, `ingesting` |
| `probe` | `probing`, `httpx`, `alive`, `sweep` |
| `fingerprint` | `fp`, `tech`, `recon` |
| `discovery` | `discover`, `discovering`, `deparos` |
| `external-harvest` | `harvest`, `harvesting`, `external-harvester`, `external_harvester` |
| `spidering` | `spider`, `spitolas`, `crawl`, `crawling`, `crawler` |
| `known-issue-scan` | `cve`, `kis`, `known-issue`, `known-issues` |
| `dynamic-assessment` | `dast`, `audit`, `assessment`, `assess` |
| `extension` | `ext`, `extensions` |
| `heuristics-check` | `heuristics`, `heuristic` |
| `port-sweep` | `ports`, `portsweep`, `port-scan` |
| `harvest-probe` (internal: `--skip` only) | `harvest-check` |
| `targeted-respider` (`--only` with spidering and discovery) | `respider`, `re-spider` |
| `param-mining` (internal: `--skip` only) | `params`, `arjun`, `param-miner` |
| `seed` (internal: neither) | |
| `preflight` (internal: `--skip` only) | |

`--skip extension` turns extensions off for the run, even when the config or `--ext` enabled them; the built-in modules still run. `--skip heuristics-check` is the same as `--skip-heuristics`.

`strategy -j` reports each phase with `skippable`, `internal` and `only_accepted`, so a caller can tell which list a name belongs to without parsing help text.

One exception applies to the positional form only: `vigolium run audit` is rejected as ambiguous, because it reads as `vigolium agent audit` (the AI source-code audit) rather than the native module-scanning phase. Use `vigolium run dynamic-assessment` (or `dast`). `--only audit` and `--skip audit` are unaffected.

### `run <phase>` and `scan --only <phase>` are the same thing

`vigolium run discover` is not a lighter variant of `vigolium scan --only discovery` — it is literally the same code path, so the two behave identically in every respect.

What *does* differ is running a phase on its own versus running it inside a full pipeline. The clearest case is discovery's FUZZ brute-force: it is enabled whenever the active `--only` set contains `discovery`, and disabled when discovery runs as one phase of a balanced or lite full scan. The Discovery phase header prints which applies:

```
◆ Fuzzing: enabled — fuzz.txt (5369) (embedded default), appends /FUZZ [discovery-only run]
◆ Fuzzing: disabled — off on balanced/lite full scans (enable via `run discover`, --intensity deep, or --discovery-wordlist)
```

### Turning discovery fuzzing off

`--no-discovery-fuzz` (alias `--no-fuzz`) disables the `/FUZZ` brute-force outright. It is checked before every rule that would switch fuzzing on, so it wins over `--intensity deep`, over a discovery-only run, and over the low-yield auto-enable:

```bash
vigolium run discover -T hosts.txt --no-fuzz            # content discovery without the 5369-word brute
vigolium scan -t https://example.com --intensity deep --no-fuzz
```

The rest of discovery is untouched — link extraction, robots.txt, JS parsing (jstangle, Next.js/Angular/CRA manifests, source maps), observed path/file names, form submission, response-word harvesting when it is on (`discovery.extract_words`; by default only at `--intensity deep`), and the short `dir-short.txt`/`file-short.txt` dictionaries all still run. `--intensity deep` still loads the large dictionaries (`discovery.wordlists.tier`); only the `/FUZZ` task is removed.

Passing `--no-discovery-fuzz` together with `--discovery-wordlist` is an error rather than a precedence rule — the two state opposite intents, and the outcomes differ by thousands of requests per host.

## Chaining Phases Manually

You can chain independent phase runs to build a custom pipeline. Each phase stores its results in the database, so subsequent phases pick up where the previous one left off:

```bash
# Step 1: Discover endpoints
vigolium run discovery -t https://example.com

# Step 2: Dynamic-assessment against the discovered endpoints
vigolium run dynamic-assessment -t https://example.com

# Step 3: Run custom extensions against results
vigolium run extension -t https://example.com --ext ./custom-check.js
```

## Tuning Per-Phase Performance

Override concurrency and rate limits for individual phases using the config file (`vigolium-configs.yaml`):

```yaml
scanning_pace:
  concurrency: 50
  rate_limit: 100

  discovery:
    concurrency: 100
    duration_factor: 1.0

  spidering:
    max_duration: 20m

  dynamic-assessment:
    parallel_passive: true
```

CLI flags (`-c`, `--rate-limit`) always take precedence over config values.

### What `max_duration` bounds in each phase

`scanning_pace.<phase>.max_duration` (or the common `max_duration` × the phase's
`duration_factor`) does **not** mean the same thing in every phase. Until the
semantics are unified (planned: phase wall clock plus an explicit
`max_duration_per_target`), this is what each value bounds:

| Phase | `max_duration` bounds | Notes |
|---|---|---|
| `discovery` | each **target** (`--discover-max-time`, default 1h) | Up to 3 targets run at once; there is **no phase ceiling**, so the phase can run for about targets ÷ 3 × the budget. |
| `spidering` | each **target** (`--spider-max-time`) | Phase ceiling = per-target budget × min(targets, 8); targets past it are skipped (`targets_skipped`). A factor-derived budget gets a floor (below). The crawler stops scheduling new states `min(10s, 10%)` before a target's deadline so in-flight pages and capture drain inside the budget. |
| `known-issue-scan` | each **leg**: nuclei and the secret scan each get the full value | The two legs run one after the other, so the phase can take twice the value. |
| `dynamic-assessment` | the **whole phase**, every feedback round included | |
| `probe` | the **whole phase**, prefetch included | |
| `external-harvest` | each archive **query** (per-call timeout) | |
| `heuristics-check`, `port-sweep`, `harvest-probe`, `targeted-respider`, `param-mining` | not governed by `scanning_pace` | `targeted-respider` and `param-mining` have their own budgets in config. |

`--scanning-max-duration` is different from all of these: it is the wall clock
of the **whole scan**. Every phase deadline above is cut short by it, and once
it elapses the remaining phases are skipped (`scan_budget`).

**Spidering floor.** When the spidering per-target budget is *derived* —
`max_duration × duration_factor`, including the `max_duration` that
`--scanning-max-duration` seeds — it is raised to at least **60s**, capped at
half of `--scanning-max-duration`. Without it a 4m scan gave each crawl 24s,
too little to log in and settle a single-page app. An explicit value
(`--spider-max-time`, `scanning_pace.spidering.max_duration`,
`spidering.max_duration`) is never adjusted. The banner shows the budget the
phase will actually use.

### Request budgets

`--max-requests N` stops the scan after N requests to the targets, and
`--max-requests-per-host N` sends at most N to any one host (config:
`scanning_pace.max_requests` / `max_requests_per_host`; 0 = unlimited, the
default). Both are enforced in the egress gate, before a request is dialed:

- When the scan-wide budget runs out, the running phase is stopped and the
  remaining phases are skipped. The scan is **partial** with
  `stop_reason: request_budget`.
- When one host's budget runs out, further requests to that host fail at once;
  the scan carries on with the other hosts. The phase records the
  `host_request_budget` **limit** (not a reason), and `scan.finished` lists the
  hosts in `budget_exhausted_hosts`.
- Gated traffic is held to the number exactly. The browser crawl bypasses the
  gate, so its in-scope requests are counted and checked every 500ms (the
  scan can overshoot by what the crawl sends in that time). nuclei and the
  own-dialer probes are not counted. `scan.started` reports `budgets` and, when
  a budget is set, `request_cap_enforcement` per phase: `hard`, `soft` or
  `partial`.

## Controlling Scope

Scope filtering applies across all phases. Use `--scope-origin` to control host matching:

```bash
# Strict: exact host match only
vigolium run discovery -t https://api.example.com --scope-origin strict

# Balanced: same eTLD+1 (*.example.com)
vigolium run discovery -t https://api.example.com --scope-origin balanced

# Relaxed (default): host contains target keyword
vigolium run discovery -t https://api.example.com --scope-origin relaxed
```

## Adding Authentication

All phases respect authentication headers. Pass them with `-H`:

```bash
vigolium run dynamic-assessment -t https://api.example.com \
  -H 'Authorization: Bearer eyJhbGciOi...' \
  -H 'Cookie: session=abc123'
```

For multi-session testing (e.g., IDOR detection), use session configs:

```bash
vigolium run dynamic-assessment -t https://api.example.com \
  --auth-file sessions.yaml
```
