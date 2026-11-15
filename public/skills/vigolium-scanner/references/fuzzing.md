# Fuzzing (`vigolium fuzz`)

> **Related:** [agent-loop.md](agent-loop.md) · [burp.md](burp.md) · [scanning.md](scanning.md) · [flags.generated.md](flags.generated.md)

`vigolium fuzz` injects a payload set **you supply** into positions **you pick**
in ONE HTTP request, sends each variant, and streams per-payload response
signals with match/exclude gating and auto-calibration.

## Table of Contents

- [Mental model — primitive, not scanner](#mental-model--primitive-not-scanner)
- [Source: where the request comes from](#source-where-the-request-comes-from)
- [Request builder (curl parity)](#request-builder-curl-parity)
- [Positions: what gets fuzzed](#positions-what-gets-fuzzed)
- [Attack modes: several markers at once](#attack-modes-several-markers-at-once)
- [Payloads](#payloads)
- [Anomaly detection (`-a`)](#anomaly-detection--a)
- [Matchers and excludes](#matchers-and-excludes)
- [Calibration and baseline](#calibration-and-baseline)
- [Output](#output)
- [Operational flags](#operational-flags)
- [Sending through Burp](#sending-through-burp)
- [Recipes](#recipes)
- [Gotchas](#gotchas)

---

## Mental model — primitive, not scanner

`fuzz` makes **no** vulnerability decision and emits **no** findings. It sends
exactly what you tell it and shows exactly what came back. The intelligence
lives in the caller — you, or the agent driving it.

> The native scan **decides what to test and judges the result.** `fuzz` does
> neither.

| Goal | Use |
|------|-----|
| Find **known** classes (XSS/SQLi/LFI/SSRF/…) with confirmation + low FPs | `vigolium scan-request -i req.txt -m xss,sqli -j` |
| Re-send one request and diff it against a stored baseline | `vigolium replay …` |
| Send **custom payloads** at an **exact position** and read raw signals | `vigolium fuzz …` |
| Wordlist-scale content / parameter discovery | `vigolium fuzz … -w dir-short` |

`fuzz` will happily show you 500s and size deltas that aren't bugs; interpreting
them is your job. That is the deliberate trade for control and transparency.
Every `-j` summary hands back a `query` field with a ready `scan-request`
confirmation command — run that rather than reasoning from signals alone.

## Source: where the request comes from

Exactly one source. Everything else (positions, payloads, matchers) applies on
top of whatever it resolves to.

```bash
vigolium fuzz 'https://acme.test/item?id=FUZZ'          # positional URL
vigolium fuzz -i req.txt                                 # curl / raw HTTP / Burp XML / base64 / URL — text, or a path to a file holding it
vigolium fuzz --input-file ./req.txt                     # same, read from a file
vigolium fuzz -u <record-uuid>                           # a stored HTTP record
cat req.txt | vigolium fuzz --target https://acme.test   # stdin (scheme-less raw → needs --target)
```

`-t/--target` overrides scheme/host/port **without touching the request bytes** —
the way to fuzz a staging host with production's captured request.

## Request builder (curl parity)

These reshape the request *before* position analysis, so a marker introduced by
`-H 'X-Forwarded-For: FUZZ'` is discovered as a position. They apply to **every**
source, not just a positional URL.

| Flag | Notes |
|------|-------|
| `-X/--request` | method override |
| `-H/--header` | `Name: value`, added or replaced (repeatable) |
| `-d/--data` | body override, refreshes `Content-Length` |
| `--data-raw` / `--data-binary` / `--data-urlencode` | curl's variants; `@file` handling matches curl |
| `--form` / `--form-string` | multipart, built with `mime/multipart` |
| `--get` | send accumulated data as query params (curl's `-G`) |
| `--head` | HEAD (curl's `-I`) |
| `--cookie` / `--user` / `--user-agent` / `--referer` | curl's `-b` / `-u` / `-A` / `-e` |
| `--compressed` / `--location` / `--insecure` / `--path-as-is` | accepted for compatibility; already the behavior |
| `--http1.1` / `--http2` / `--http-version` | force a wire protocol |
| `--resolve host:port:addr` | pin a host to an address |
| `--cacert` / `--cert` / `--key` / `--verify-tls` | TLS material |
| `--connect-timeout` / `--max-time` | curl's timeouts (`--max-time` aliases `--timeout`) |

**Long forms only.** curl's short flags are already taken by vigolium meanings:
`-u` is the record UUID, `-i` the input, `-w` a wordlist, `-c` concurrency.

## Positions: what gets fuzzed

Pick positions **one way** — the run is refused (exit 2) otherwise:

1. **A literal `FUZZ` marker** anywhere in the request (request line, path,
   header name/value, body). Occurrences in the request line are auto-encoded,
   so a payload with spaces (`' OR '1'='1`) stays well-formed. Rename it with
   `--keyword`. A marker plus `--point`/`--fuzz`/`--fuzz-header` is a usage error.
2. No marker: `--point TYPE:name` (one exact insertion point, repeatable),
   `--fuzz-header NAME` (repeatable), or `--fuzz method|path|params|headers|cookies|all`.
3. Neither → usage error naming the nearest marker-like token (`FUZ`, `fuzz`).
   `--fuzz all` is the old "every discovered insertion point".

Headers the request does not carry (`X-Forwarded-For`, `Referer`, …) are left
out of `headers`/`all` unless `--fuzz headers:synthetic`.

Three opt-in kinds are never in the default set; ask for them by selector:

| Selector | Does | Position type |
|---|---|---|
| `--fuzz param-name` | **renames** an existing query/form parameter: `?id=1` → `?PAYLOAD=1` | `PARAM_NAME_URL` / `PARAM_NAME_BODY` |
| `--fuzz new-param[:query\|body\|json]` (alias `param-add`) | **adds** a parameter named PAYLOAD with a fixed canary value — parameter discovery. Location inferred from the request when omitted (JSON body → json, form body → body, else query) | `NEW_PARAM_QUERY` / `_BODY` / `_JSON` (name `<new>`) |
| `--fuzz body` | replaces the **entire** body, Content-Length refreshed (needs a body: `-d`) | `ENTIRE_BODY` |

Parameter discovery is `--fuzz new-param -w params --anomaly`: one candidate per
request, scored against the calibrated baseline. For batched, budgeted mining use
`vigolium kit param-mine` instead.

`--point` TYPE values are the `httpmsg` insertion-point names:

```
URL_PARAM  BODY_PARAM  COOKIE  JSON_PARAM  XML_PARAM  XML_ATTR  MULTIPART_ATTR
AMF_PARAM  HEADER  PATH_FOLDER  PATH_FILENAME  PARAM_NAME_URL  PARAM_NAME_BODY
ENTIRE_BODY
```

A wrong `--point` is a hard error that **lists what was actually available** —
cheaper than guessing:

```
--point "URL_PARAM:page" not found; available: URL_PARAM:id, HEADER:User-Agent, …
```

`--fuzz-header` **injects** a header the request doesn't carry instead of
erroring. That is the point: `X-Forwarded-For` is interesting *precisely*
because the client never sends it.

## Attack modes: several markers at once

Numbered markers (`FUZZ`, `FUZZ2`, `FUZZ3`, …) become separate positions.

| `--mode` | Behavior | Use for |
|----------|----------|---------|
| `sniper` *(default)* | one position at a time, others left alone | most fuzzing |
| `batteringram` | the same payload in every marker | the value must match in two places |
| `pitchfork` | lists advanced in lockstep (i-th with i-th) | credential **pairs** — bounded by the shortest list |
| `clusterbomb` | every combination | small lists only |

Multi-position modes are **marker-only** and error otherwise: an `httpmsg`
insertion point is built against the request it was analyzed on, so applying a
second would discard the first's edit. Clusterbomb expansion is bounded — a
runaway product is a clear error, not an OOM.

`FUZZ` never eats the prefix of `FUZZ2` (a marker followed by a digit doesn't
match), so substitution order is irrelevant.

### Binding a list to one marker

`pitchfork` and `clusterbomb` need to know *which* list belongs to *which*
marker — a flat payload set can't say that. Append `:KEYWORD` to a `-w` or
`--class` value:

```bash
-w users.txt:FUZZ  -w passwords.txt:FUZZ2      # one list per marker
--class sqli:FUZZ  --class xss:FUZZ2           # classes bind the same way
```

The suffix only counts when `KEYWORD` names a **resolved marker** — a wordlist
path containing a colon is far likelier than a stray marker name, so unmatched
suffixes are treated as part of the path. Unbound lists stay in the shared pool
(single-marker runs are unaffected), and inline `-p` payloads are **always**
shared: there's no sensible place to hang a keyword off a literal.

## Shaping `-j`

`fuzz -j` items are the top-ranked matched results. `--fields` projects them
(aliases work: `--fields payload,status_code,length` comes back under those
names), and `--compact` drops each result's `anomaly_reasons`, the top-level
`anomalies` list and the baseline's raw timing samples. `vigolium schema command
fuzz` is the shape.

## Payloads

Combine freely; duplicates are dropped in first-seen order.

```bash
--class sqli,xss                # built-in vulnerability classes
-w/--wordlist <file|NAME>       # repeatable; NAME: dir-short, dir-long, file-short, file-long, fuzz, params
                                # ('builtin'/'default' = fuzz; 'builtin:<name>' wins over a file of that name)
-p/--payload '<literal>'        # inline, repeatable
--suffix .php,.bak              # also each payload + each suffix, appended literally (ffuf -e)
```

**Classes** (`pkg/payloads`, the same catalog behind the JS `vigolium.payloads()`
API): `cmdi`, `crlf`, `lfi`, `open_redirect`, `path_traversal`, `sqli`, `ssrf`,
`ssti`, `xss`, `xxe`. Aliases resolve: `traversal`/`path` → `path_traversal`,
`cmd`/`command`/`rce` → `cmdi`, `redirect`/`openredirect` → `open_redirect`,
`sql` → `sqli`, `template` → `ssti`.

**Builtin wordlists** (embedded in the binary, no files needed): `fuzz`,
`dir-short`, `dir-long`, `file-short`, `file-long`, `params` (candidate parameter
names, for `--fuzz new-param`). Anything else is read as a file path; blank lines
and `#` comments are skipped.

## Anomaly detection (`-a`)

**Reach for this before writing matchers.** A matcher requires knowing the
interesting size or status *up front*. `-a/--anomaly` instead scores every
response against two references:

- the **baseline** — the un-fuzzed request's own response, and
- the **population** — every other response in this same run.

The population reference is what makes it work on an unknown target. A status
change that *every* payload triggers is the endpoint's normal behavior, not a
signal; only rarity tells those apart.

### Signals and weights

**Baseline-relative** (always active):

| Signal | Weight | Fires when |
|--------|-------:|------------|
| `error_signature` | 45 | a stack trace / driver error / template error the baseline lacked (SQL errors go through `modkit`, the repo's single source of truth) |
| `server_error` | 40 | status changed to 5xx |
| `status_now_ok` | 40 | baseline 4xx+ → 2xx — the shape of an auth/access-control bypass |
| `transport_error` | 35 | connection error where the baseline succeeded (short-circuits: no other signal is scored) |
| `header_changed` | 25 | `Location` or `WWW-Authenticate` changed |
| `status_changed` / `status_redirect` / `reflected_unencoded` | 20 | status differs / became 3xx / payload appears **verbatim** |
| `header_changed` | 15 | `Set-Cookie`, `Content-Type`, `Server`, `X-Powered-By`, `Content-Disposition` changed |
| `reflected_encoded` | 5 | payload appears escaped — the app handled it |

**Population-relative** (silent below `--anomaly-min-population`, default 12):

| Signal | Weight | Fires when |
|--------|-------:|------------|
| `unique_body` | 30 | no other payload produced this body, on a run where bodies otherwise repeat |
| `size_outlier` | 30 | length ≥6 MADs from the run's median (or the only length that differs at all) |
| `rare_status` | 25 | this status is ≤5% of the population |
| `time_outlier` | 25 | time >500 ms **and** ≥6 MADs above the run's median |

Outliers use **median-absolute-deviation**, not standard deviation: a fuzz
population is full of outliers by construction, and they would inflate a stddev
enough to hide themselves.

### Thresholds

`--anomaly-threshold low|medium|high` or a bare number.

| Level | Score | Meaning |
|-------|------:|---------|
| `low` | 25 | one weak signal is enough |
| `medium` *(default)* | 45 | one strong signal (error signature, 5xx, auth-shape) clears it alone; weak ones must stack |
| `high` | 70 | several strong signals |

Each kept result carries `anomaly_score` and `anomaly_reasons` (`[{signal,
detail, weight}]`) so the score is auditable, never a black box.

With `-a` and **no explicit matchers**, "interesting" replaces "keep
everything". Add matchers on top and both apply.

It reports **where to look, never a verdict.** Confirm with the module scanner.

## Matchers and excludes

Matchers **keep** a response; excludes **drop** it. Every `--match-*` has an
`--exclude-*` twin, so any signal you can match on is one you can exclude on.

**Predicate grammar** for numeric flags — exact equality alone is near-useless
for sizes, since a page carrying a timestamp or CSRF token is never
byte-identical twice:

```
N        exact          N-M      range
>N  >=N  <N  <=N        !N       not
```

Comma-separated for alternatives. A bare `--match-time 500` means `>=500`.

```bash
--match-status-code 200,301     --exclude-status-code 404
--match-size '>1000'            --exclude-size 0
--match-words 50-80             --exclude-words 0
--match-lines '!0'              --exclude-lines '<5'
--match-regex 'root:.*:0:0'     --exclude-regex 'Not Found'
--match-time '>500'             --exclude-time '<50'
--match-time-z '>3'             --exclude-time-z '>4'   # need --baseline-samples > 1
--match-header 'Location: /admin'          # regex on the value
--match-header Location                    # presence only
--exclude-header 'Server: nginx'           # same grammar, inverted
--match-mode all                           # require every category (default: any)
```

The full twin set is `--exclude-status-code`, `--exclude-size`,
`--exclude-words`, `--exclude-lines`, `--exclude-regex`, `--exclude-time`,
`--exclude-time-z` and `--exclude-header` — each takes exactly the grammar its
`--match-*` counterpart does.

`--match-status-code all` keeps every status. `--exclude-mode` is the twin of
`--match-mode` (`any` = OR, the default; `all` = AND).

Reflection is reported in three parts, because conflating them hides the
difference between "this might execute" and "the app escaped it":

| Field | Meaning |
|-------|---------|
| `reflected` | the payload appears somewhere |
| `reflected_raw` | it appears **verbatim** (unencoded) |
| `reflected_in` | *where* — `body`, `header:Location`, … |

Header reflection is the whole signal for open redirect and response splitting.

## Calibration and baseline

**Auto-calibration is on by default.** `fuzz` sends a few improbable values
first, learns the target's wildcard/catch-all `(status,length)` signature, and
suppresses matching results — surfaced as `"calibrated": true`, never silently
hidden. `--no-calibrate` turns it off.

**`--baseline-samples N`** re-sends the un-fuzzed request N times to measure
timing jitter (default 1; **3** under `-a`). With N > 1 each result gets a
`time_z` — the way to express a time-based signal without guessing a per-target
millisecond threshold.

## Output

**Default:** a human table on stdout, one line per send, matched-only unless
`--all-results`. `--format jsonl` prints the per-payload stream instead, one
object per send; `-o file` writes that stream to a file (stdout keeps the table,
or the `-j` envelope).

```json
{"position":"id","position_type":"URL_PARAM","payload":"' OR '1'='1",
 "status":500,"length":73,"words":15,"lines":0,"time_ms":112,
 "content_hash":"…","reflected":true,"reflected_raw":true,"reflected_in":["body"],
 "status_changed":true,"length_delta":48,"time_z":0.4,
 "anomaly_score":65,"anomaly_reasons":[{"signal":"server_error","weight":40}],
 "matched":true,"calibrated":false}
```

**Under `-j/--json`** ONE envelope goes to **stdout** — the agent handle, so you
never parse the stream. The ranked top results are `items`; the run summary sits
beside them, and `total` is the full matched count:

```json
{ "schema_version":2, "command":"fuzz", "kind":"read", "ok":true,
  "sends_traffic":true, "target":"https://acme.test", "positions":1,
  "payloads":13, "sent":13, "sent_total":19, "matched":1, "calibrated":8,
  "errors":0, "baseline":{"status":200,"length":25,"words":4,"lines":0,…},
  "pace":{"rate_limit":100,"concurrency":10,"delay_ms":0,"protocol":"http/1.1"},
  "total":1, "items":[…], "anomalies":[…],
  "next":[{"argv":["vigolium","scan-url","-t","…","-m","sqli","-j"],
           "why":"confirm the anomalies with the hardened modules",
           "sends_traffic":true}] }
```

The per-payload stream is not written under `-j` unless `-o` names a file
(`-j --format jsonl` without `-o` is a usage error: two documents on one stdout).

`items` are ranked most-interesting first (status-changed → reflected →
largest size delta → slowest) and capped by `-n` (default 20, `0` = all).
`sent` counts payload sends; `sent_total` every request on the wire (baseline
samples and calibration probes included). The confirmation command against the
hardened module scanner is `next[0].argv`: it **sends traffic**
(`sends_traffic: true`), so it is not the read-only `query`.

`--fail-on-match` exits **3** when any result matched, for CI/agent gating.

## Operational flags

| Flag | Why you want it |
|------|-----------------|
| `--dry-run` | resolve positions + payloads and print the exact bytes each would send, with **zero** network traffic — the pre-flight before committing to a big run |
| `-c/--concurrency` | concurrent requests (default 10); lower it through a proxy |
| `-r/--rate-limit <req/s>` | cap the whole run across all workers, counting baseline and calibration sends (fractions allowed; default 100, `0` = unlimited). Smooth, no burst. Not taken from `scanning.rate_limit` — fuzz is a primitive. The effective pace is echoed on stderr and as `pace` in `-j`/`--dry-run` |
| `--delay <ms>` | per-worker delay before each request — the polite knob for rate-limited targets |
| `--max-requests <n>` | refuse a plan that expands to more payload sends (default 10000, `0` = no cap); baseline and calibration sends are not counted |
| `--timeout` | per-request (default 25s); `--max-time` is the curl alias |
| `--no-redirects` | stop following 30x (following is the default) |
| `--max-redirs` | cap the chain instead of severing it (`0` = Go's default of 10). The curl spelling; use it when a target loops redirects and a wordlist run would otherwise spend its budget in the loop |
| `--auth-session <name>` | merge headers from a stored session (`vigolium auth list`) |
| `--session-id <id>` | persist cookies across runs, same jar as `replay` (`~/.vigolium/replay-jars/`) |
| `--no-cookies` | opt out of the jar |
| `--ignore-scope` | fuzz a host outside the project's configured scope (otherwise a hard error) |
| `--verify-tls` | **not** the default — verification is off unless you ask |

Always `--dry-run` a wordlist-scale run first. It costs one command and catches
the two failures that waste a whole run: the marker landed somewhere you didn't
mean, or the payload set is empty.

## Sending through Burp

`--send-via-burp` routes every payload through Burp's own HTTP stack so the
**exact bytes** hit the wire, and `--matches-to-organizer` hands each match to
Burp's Organizer for manual triage. Both need `-B/--burp-bridge-url`.

```bash
vigolium fuzz -u <uuid> --fuzz params --class sqli -a \
  --send-via-burp --http-mode http1 --matches-to-organizer -B http://127.0.0.1:9009
```

Full setup, limits, and the rest of the Burp surface: **[burp.md](burp.md)**.

## Recipes

### 1. Unknown endpoint — let anomalies find the shape

```bash
vigolium fuzz -u <record-uuid> --point URL_PARAM:id --class sqli -a -j
```

No matchers. Read `anomalies` in the summary, then run its `query` to confirm.

### 2. Content discovery at a path segment

```bash
vigolium fuzz 'https://acme.test/FUZZ' -w dir-short --match-status-code 200,301,403
```

Calibration already suppresses the catch-all, so the matches are real hits.

### 3. Credential pairs from two lists

```bash
vigolium fuzz -i login.txt --mode pitchfork \
  -w users.txt:FUZZ -w passwords.txt:FUZZ2 --exclude-size 0 -a
```

`pitchfork` pairs list entries in lockstep; `clusterbomb` would try every
combination instead.

### 4. Header injection the client never sends

```bash
vigolium fuzz -u <uuid> --fuzz-header X-Forwarded-For \
  -p 127.0.0.1 -p localhost -p 'http://169.254.169.254/' --match-status-code all -a
```

The header isn't on the request — `--fuzz-header` injects it.

### 5. Blind timing signal without guessing a threshold

```bash
vigolium fuzz -u <uuid> --point BODY_PARAM:q --class sqli \
  --baseline-samples 5 --match-time-z '>4'
```

`time_z` is standard deviations above the *measured* baseline mean, so the
threshold travels between targets.

### 6. Agent gate in CI

```bash
vigolium fuzz -i req.txt --fuzz-header X-Api-Version --class lfi \
  --match-regex 'root:.*:0:0' --fail-on-match -j
```

Exit 3 on a hit; the summary object lands on stdout either way.

## Gotchas

- **`fuzz` emits no findings and makes no verdict.** Nothing is written to the
  database. Confirm with `scan-request -m <module>`.
- A literal `FUZZ` in the request **overrides** `--fuzz`/`--point` silently —
  `--dry-run` shows which positions actually resolved.
- Multi-position `--mode` values require markers; insertion points error.
- `--verify-tls` is off by default (the inverse of curl).
- Only long-form curl flags are accepted; the short ones mean vigolium things.
- Population signals stay silent under `--anomaly-min-population` (default 12) —
  a 5-payload run gets baseline signals only.
- `--ignore-scope` is required for a host outside the project scope; the guard
  is deliberate.
- Exit **3** means `--fail-on-match` matched. Exit **1** is an error and exit
  **2** is a usage error (bad flag or value) — three distinct outcomes, not one.
  Full table: [invariants.md → Exit codes](invariants.md#exit-codes).
