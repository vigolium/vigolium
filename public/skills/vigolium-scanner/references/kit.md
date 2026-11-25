# Utility toolbox (`vigolium kit`)

> **Related:** [agent-loop.md](agent-loop.md) · [fuzzing.md](fuzzing.md) · [flags.generated.md](flags.generated.md)

`vigolium kit` is a family of small, **stateless** primitives carved out of the
scanner's own engine — no database, no project scope, no scan pipeline. Each is
a one-shot transform or probe built to be shelled out to by an agent: it reads
files/stdin, honours `-j/--json` for machine output, and gates via exit codes.

## Table of Contents

- [Mental model](#mental-model)
- [cookies](#cookies)
- [secret-scan](#secret-scan)
- [js-beautify](#js-beautify)
- [oast (new / poll)](#oast-new--poll)
- [harvest](#harvest)
- [param-mine](#param-mine)
- [jwt-crack](#jwt-crack)
- [viewstate-crack](#viewstate-crack)
- [unlock-walk](#unlock-walk)
- [wordlist](#wordlist)
- [payload](#payload)
- [tmp-clean](#tmp-clean)
- [Gotchas](#gotchas)

---

## Mental model

These are **primitives**: they do one job and report raw output, never a
vulnerability verdict. They touch no project DB, so nothing is persisted — pipe
the output where you need it. Every command reads `-` (or no argument) as stdin
and takes `-j/--json` for one envelope document on stdout (human notes go
to stderr, so a pipe stays clean).

Under `-j` every kit command prints the standard envelope (`schema_version`,
`command`, `kind`, `ok`, `total`, `items`, …; see `invariants.md`). The rows
are always in `items`; every other field the command reports (`count`,
`files_scanned`, `server`, …) stays at the top level under its old name. A
single-object result (`js-beautify`, `jwt-crack`, `tmp-clean`) is
`items:[object]` — read `.items[0]`. `--json-legacy-keys` re-adds the
pre-envelope row name (`matches`, `urls`, …) or flattens the object back to
the top level, for one release.

| I need to… | Use |
|---|---|
| Reuse a login the operator's browser already holds (cookies + localStorage) | `vigolium kit cookies <domain…>` |
| Scan files/dirs/stdin for leaked credentials | `vigolium kit secret-scan <files\|dirs\|->` |
| Unminify / unpack a JS bundle | `vigolium kit js-beautify <file\|url\|->` |
| Mint OOB callback URLs and drain hits | `vigolium kit oast new` → `vigolium kit oast poll` |
| Collect known URLs for a domain | `vigolium kit harvest <domain…>` |
| Find hidden parameters an endpoint accepts | `vigolium kit param-mine -t <url>` |
| Recover a JWT's HMAC secret | `vigolium kit jwt-crack <token>` |
| Check an ASP.NET ViewState MAC against published machineKeys | `vigolium kit viewstate-crack -g <generator> <viewstate>` |
| Render an SPA's client-gated views on forged client state | `vigolium kit unlock-walk --profile <file>` |
| List / print the built-in wordlists | `vigolium kit wordlist [name]` |
| Emit built-in payloads by class | `vigolium kit payload --class <c>` |
| Remove leftover vigolium temp scratch | `vigolium kit tmp-clean` |

---

## cookies

Reading the local browser's own session — cookies, local and session storage,
or a scoped profile clone — has its own reference: **[cookies.md](cookies.md)**.

---

## secret-scan

Scan bytes for leaked secrets with the embedded detection catalog (~12k
kingfisher + vigolium rules, pure Go, no network). Positional args are files or
directories (walked recursively); `-`/no arg reads stdin.

```bash
vigolium kit secret-scan config.env .github/            # files + dirs
cat bundle.js | vigolium kit secret-scan -              # stdin
vigolium kit secret-scan -j --min-confidence high src/  # high-confidence JSON
```

| Flag | Effect |
|------|--------|
| `--min-confidence low\|medium\|high` | threshold (default `low`) |
| `--rule` / `--exclude-rule` | allow/deny by rule ID (comma-separated) |
| `--redact` | mask the value (prefix/suffix kept); **full value shown by default** |
| `--fail-on-match` | exit **3** when any secret is found (CI/agent gate) |
| `--max-file-size` | skip files larger than N bytes (default 16 MiB) |

JSON: envelope with `items` = matches `[{rule_id, rule_name, confidence, secret, entropy, file, line, start, end}]`, plus top-level `files_scanned`, `count`.
Reports *where* a secret is, never exploitability. Obvious placeholders
(`…EXAMPLE`, `123456…` sequences) are safelisted away.

## js-beautify

Unminify + unpack minified/bundled JavaScript with the embedded jstangle tool
(webcrack — no eval-based deobfuscation). Argument is a local file, an
`http(s)://` URL (fetched), or `-`/no arg for stdin.

```bash
vigolium kit js-beautify app.min.js                     # local file
vigolium kit js-beautify https://target.example/main.abc.js
cat bundle.js | vigolium kit js-beautify -              # stdin
vigolium kit js-beautify -j --extract app.min.js        # + every extracted fact
vigolium kit js-beautify -j --kinds routes,paths app.js # only these fact kinds
vigolium kit js-beautify -j --secrets app.min.js        # + leaked credentials (redacted)
vigolium kit js-beautify --modules ./out app.min.js     # one file per module
```

Default: beautified source to stdout (input emitted unchanged if it is neither
minified nor bundled). `--extract` also runs a full analysis and reports every
fact kind; without `-j` a per-kind summary (counts plus the first 20 of each)
goes to stderr and stdout stays the source.

| Flag | Effect |
|------|--------|
| `--extract` | also extract every fact kind (a full analysis pass); listed in `-j` output, summarized on stderr otherwise |
| `--kinds <list>` | only report these kinds: `endpoints`, `routes`, `assets`, `graphql`, `realtime`, `dom_flows`, `paths` (implies `--extract`) |
| `--secrets` | run the built-in secret catalog over the beautified source; values **redacted** by default |
| `--show-secrets` | with `--secrets`, print values in full |
| `--modules <dir>` | write each recovered module to its own file under `<dir>`, at its recovered path |
| `-o, --output <file>` | write the beautified source to a file instead of stdout (`-` means stdout) |
| `--profile <p>` | `beautify` \| `endpoints` \| `discovery` \| `discovery-lite` \| `full` \| `inspect` \| `dom-security` \| `legacy`; default depends on `--extract` |
| `--unpack-modules` | unpack a bundle and re-scan each module for endpoints (implies `--extract`) |
| `--max-ast-nodes` | AST node budget before the analysis degrades to a per-module scan (0 = engine default, 500k) |
| `--max-input-mb` | **lowers** the input ceiling only; it cannot raise it above the service limit |
| `--deadline` | analysis deadline (0 = engine default, 60s) |
| `--timeout` | fetch timeout for a URL argument (default 30s) |

JSON: envelope with `items:[result]`, where `result` (read `.items[0]`) is
`{source, status, changed, format, module_count, module_paths?, bytes_in,
bytes_out, content, endpoints?, routes?, assets?, graphql?, realtime?,
dom_flows?, paths?, secrets?, counts, truncated?, diagnostics?, output_path?,
modules_dir?, modules_written?}`.

Every fact item carries flattened provenance: `id?`, `confidence`, `extractor`,
`line?`, `column?`, `module_path?`. Per kind:

| Kind | Item fields (besides provenance) |
|------|-------------------------------|
| `endpoints` | `url, method, params, body, headers, cookies` (legacy flat strings) plus typed `client?, query?[{name,value,static}], header_fields?[{name,value,static,sensitive?}], body_template?{kind,value,static,content_type?}, auth?{kind,header?,query?,scheme?,source,source_kind}` |
| `routes` | `path, full_path?, type, guards?, lazy_asset?, parent_id?, meta?, loader?` (`parent_id` is another route's `id`; `guards` names every gate — `canActivate`, `canActivateChild`, `canMatch`, `canLoad`, `beforeEnter` — as an identifier, a call such as `hasRole("admin")` or `inject(AuthService).isLoggedIn()`, or `<inline>`; `meta` is the route record's literal Vue `meta` / Angular `data` object, e.g. `{requiresAuth: true, roles: ["admin"]}`, with a runtime-computed value as `null`; `loader` names a React Router data route's loader) |
| `assets` | `url, type, loader?, eager, inline?, parent_source_url?` |
| `graphql` | `operation_type, operation_name?, endpoint?, transport?, persisted_query_hash?, variables?[{name,type?,required?}], document?` |
| `realtime` | `protocol` (`websocket`\|`sse`), `url, library?, subprotocols?, event_names?, with_credentials?` |
| `dom_flows` | `flow_class` (`dom`\|`browser_security`), `flow_type?, source, sink, evidence?` |
| `paths` | `path, source` (`jstangle`\|`linkfinder`\|`both`), `reason?, key?` |
| `secrets` | the `secret-scan` match: `rule_id, rule_name, confidence, secret, entropy, file, line, start, end` |

`counts` has one entry per kind that was looked for, zero included, so a kind
missing from `counts` was filtered out by `--kinds`, not empty. `truncated`
maps a jstangle record kind (`httpRequest`, `pathLiteral`, ...) to how many
records the analyzer dropped at a cap; any entry means the lists are incomplete.

**`paths` is what a scan would seed.** It merges the jstangle path-literal pass
with the same Go linkfinder discovery runs over every fetched script
(`source: "both"` when they agree). Linkfinder hits are always `confidence:
"low"` and have no line: wordlist hints, not requests.

**`auth` names where a credential comes from, never the credential.**
`source: "localStorage:jwt"` tells you which storage key to fill from a logged-in
browser. A hard-coded token shows up under `--secrets` instead.

**`--secrets` scans the beautified text**, per recovered module when the bundle
splits (so `file` is the module path and `line` is within it), else the whole
document (which is the raw input when nothing changed). One entry per
rule+value: a key repeated across modules is reported once, at its first hit.

**Read `status` before trusting `endpoints`.** `complete` is a clean AST pass.
`partial` means some stages did not run, and the `diagnostics` codes say which.
`failed` means the analysis produced nothing of its own.

**A big bundle returns `partial`, and that is the good outcome.** A script dense
enough to blow the AST budget cannot be parsed whole, so the engine unpacks it
and analyzes each module separately (`ast_budget_recovered_by_module_scan`).
Those endpoints carry `extractor: "bundle-module"` and a `module_path`, with real
methods, headers and body templates. A `partial` from that path is far better
data than a `complete` from a small file.

**An empty `method` means unresolved, not GET.** The `large-input-string-fallback`
extractor is a regex sweep over source that no analyzer could parse; it recovers
URLs only. Treat `confidence: "low"` plus an empty method as a lead to confirm,
never as a request to replay.

For a bundle of any size, prefer `--modules <dir>` over reading `content`: a
400-module document is one 5 MB blob, and the directory is greppable.

## oast (new / poll)

Generate interactsh out-of-band callback URLs and later poll for the
DNS/HTTP/SMTP interactions they received — the primitive behind blind
SSRF/XXE/RCE/log4shell confirmation. State lives in a **session file**, so
minting and polling are separate fire-and-forget invocations (no long-running
process).

```bash
vigolium kit oast new -n 2 --session run.yaml          # mint 2 URLs, save session
# ...inject the URL(s) somewhere, wait...
vigolium kit oast poll --session run.yaml --wait 30s -j   # drain interactions as JSON
vigolium kit oast poll --session run.yaml --deregister    # final drain + tear down
```

| Flag | Command | Effect |
|------|---------|--------|
| `-o/--session` | both | session file path (default `oast-session.yaml`) |
| `--server` / `--token` | `new` | interactsh server (default `oast.pro`) + auth for a self-hosted one |
| `-n/--count` | `new` | number of URLs to mint |
| `--wait` / `--interval` | `poll` | how long to poll / cadence (auto-shrunk below `--wait`) |
| `--deregister` | `poll` | after draining, destroy the session server-side and delete the file |

`new` JSON: envelope, `items` = the minted URLs, top-level `server`, `session`, `count`.
`poll` JSON: envelope, `items` = interactions `[{protocol, unique_id, full_id, remote_address, timestamp, raw_request, raw_response}]`, top-level `server`, `session`, `count`.
Point `--server`/`--token` at a self-hosted interactsh to keep callbacks
private. Keep the session file until you are done polling.

## harvest

Collect historically-known URLs for one or more domains from public archives and
indexes (Wayback, Common Crawl, AlienVault OTX, Arquivo by default; urlscan and
VirusTotal join when their key is configured under `external_harvester`). A URL
argument is reduced to its host; `-` reads domains one per line from stdin.

```bash
vigolium kit harvest target.example                     # one domain
vigolium kit harvest target.example shop.target.example -j
cat domains.txt | vigolium kit harvest -                # stdin
vigolium kit harvest --source wayback,commoncrawl target.example
```

Plain mode streams deduped URLs one per line; `-j` yields the envelope with
`items` = the URLs (sorted) and top-level `domains`, `sources`, `count`,
`stats` (`raw`, `kept`, and why the rest were dropped: `invalid`, `static`,
`duplicate`, `over_shape`, `over_domain_cap`; `source_errors`) and `limits`
(limit codes the run hit, such as `cdx_max_rows`; non-empty means the archive
held more than was read). stdin is read with the shared bounded reader, so a
producer that never closes it fails at `--input-read-timeout` instead of
hanging. Same source set and shaping as the scan's
`external-harvest` phase: URLs come back normalized (tracking params, fragments
and static assets dropped; `.js`/`.map` kept) and sampled to
`external_harvester.per_shape` URLs per path shape and `max_urls` per domain.

## param-mine

Discover parameters an endpoint reads although no request carries them
(`debug=`, `callback=`, `admin=`): Arjun-style mining that **sends requests to the
target** (unlike most kit tools). Two baselines with a random parameter profile
the endpoint; names go out in chunks sized to the transport (6 KiB request
target for the query string, 32 KiB for a form/JSON body), each with a random
value; a chunk whose answer differs is bisected to single names, and every
candidate must reproduce on two fresh-value re-sends.

```bash
vigolium kit param-mine -t 'https://target.example/search?q=x'
vigolium kit param-mine -t https://target.example/login -X POST -d 'user=a' -j
vigolium kit param-mine -t https://target.example/api -X POST \
    -H 'Content-Type: application/json' -d '{"id":1}'
vigolium kit param-mine -t https://target.example/ -w names.txt --max-requests 200
vigolium kit param-mine -t https://target.example/admin --location header -j
vigolium kit param-mine -t https://target.example/admin --location cookie -H 'Cookie: session=abc' -j
```

| Flag | Default | Effect |
|------|---------|--------|
| `-t/--target` | — | endpoint URL (or the positional argument) |
| `-X/--method`, `-d/--data`, `-H/--header` | `GET` | the base request; names are added to it |
| `--location` | `auto` | `query`, `form`, `json`, `header`, `cookie`; auto = query for GET/HEAD/DELETE, else the body's encoding. `header` mines request header names (built-in list `kit wordlist headers`; framing, routing and session headers never mined); `cookie` mines cookie names, each joined to the request's `Cookie` header beside the cookies it already sends (a session cookie is never replaced; the whole header stays under 6 KiB). Neither is ever chosen by `auto` |
| `-w/--wordlist` | — | names file(s) tried before the built-in list (`kit wordlist params`, ~1.8k); `--no-builtin` drops it |
| `--max-requests` | `60` | per-run budget, baselines and confirmations included |
| `--rate-limit` / `--timeout` | `20` rps / `15s` | pacing; the global `--proxy` applies |

Each hit has a signal: `reflect` (its value came back), `status`, `header`
(the header-name set changed), `length` (substantial body-length change) or
`body` (content change at a similar length). `-j` is a read envelope: items
`{name, signal, location, detail, url, status}` plus top-level `url`, `method`,
`location`, `names_tested`, `requests`, `aborted`. `aborted` is empty for a full
run, else `unstable` (the baselines disagree: dynamic page, nothing can be
pinned on a parameter), `blocked` (3 consecutive 403/429/WAF answers), `budget`,
`baseline_failed` or `errors`. A full scan runs the same miner per endpoint in
its `param-mining` phase (`--intensity deep` or `--param-mining`).

## jwt-crack

Brute-force a JWT's HMAC signing secret (HS256/384/512) against a wordlist. A
token declaring an asymmetric alg (RS*/ES*/PS*) is tried under every HMAC
variant — the algorithm-confusion attack — and the match is labelled. Token is a
positional arg or `-`/stdin; a leading `Bearer ` is stripped.

```bash
vigolium kit jwt-crack eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ...
echo "$TOKEN" | vigolium kit jwt-crack -
vigolium kit jwt-crack -w /path/rockyou.txt -p s3cr3t eyJ...
vigolium kit jwt-crack -j --fail-on-crack eyJ...
```

| Flag | Effect |
|------|--------|
| `-w/--wordlist` | built-in name (see `kit wordlist`) or a file path (default: embedded `jwt.secrets.list`, ~104k) |
| `-p/--secret` | inline candidate secret (repeatable) |
| `--fail-on-crack` | exit **3** when the secret is recovered |

JSON: envelope with `items:[{alg, cracked, secret, matched_alg, candidates_tried, wordlist, header, payload}]`.
The recovered secret is printed in full (that is the point).

## viewstate-crack

Recompute an ASP.NET `__VIEWSTATE` MAC, offline, under every published
machineKey validation key (embedded `aspnet.machinekeys.list`, plus any
`--validation-key`) with each legacy validation algorithm (SHA1 — also what AES
and 3DES validation use — and HMACSHA256/384/512). `-g` is the page's
`__VIEWSTATEGENERATOR`, the modifier the MAC covers. The passive
`aspnet-viewstate-detect` module runs the same check on every page it sees.

```bash
vigolium kit viewstate-crack -g CA0B0334 /wEPDwUKLTEyMzQ1Njc4...
echo "$VS" | vigolium kit viewstate-crack -g CA0B0334 -
vigolium kit viewstate-crack -g CA0B0334 --validation-key D61B3C89... -j --fail-on-crack /wEPDwUK...
```

| Flag | Effect |
|------|--------|
| `-g/--generator` | the page's `__VIEWSTATEGENERATOR` (eight hex digits); required |
| `--validation-key` | extra validationKey to try, as hex (repeatable) |
| `--fail-on-crack` | exit **3** when a key reproduces the MAC |

JSON: envelope with `items:[{cracked, serialized, generator, algorithm?, validation_key?, key_source?, keys_tried, mac_mode}]`.
Only the legacy (pre-4.5) MAC is checked (`mac_mode: "legacy"`): a 4.5+
purpose-based MAC, MD5 validation, a page with a `ViewStateUserKey` and an
encrypted ViewState (`serialized: false`) are not, so `cracked: false` never
proves the key is private.

## unlock-walk

Open a single-page app in a headless browser with **forged client state** and
visit its routes, so views a client-side gate hides from an anonymous visitor
render and send their real API calls. You decide how the gate works (read the
bundle: `kit js-beautify`, the route table, the guards) and write the profile;
the walk only applies it. Unlike most kit tools it **sends requests to the
target and stores what it sees**.

```bash
vigolium kit unlock-walk --profile unlock.json -j
vigolium kit unlock-walk --profile unlock.json --origin https://app.target.example -j
```

```json
{"origin": "https://app.target.example",
 "localStorage": {"token": "x"}, "sessionStorage": {}, "cookies": [{"name": "s", "value": "1"}],
 "stubs": [{"method": "GET", "path": "/api/me", "status": 200,
            "contentType": "application/json", "body": "{\"role\":\"admin\"}"}],
 "rewrites": [{"method": "GET", "path": "/api/menu", "status": 200,
               "set": [{"pointer": "/data/isAdmin", "value": true}]}],
 "routes": ["/admin", "/admin/users"], "maxRoutes": 40, "settleMs": 2500, "maxClicksPerRoute": 6}
```

The profile's JSON Schema is the `unlock-profile` document in `vigolium schema all -j`. A stub path is exact or a
template (`/api/users/:id`, `/api/{tenant}/x`; one segment per parameter, the
query is not matched), status 2xx/4xx/5xx, body ≤ 64 KiB. A rewrite matches the
same way (a stub wins) and changes the REAL answer: `status` (absent keeps it)
and/or ≤ 20 `set` entries, an RFC 6901 `pointer` (never `""`) and a JSON
`value` (≤ 64 KiB together; replace or add a member, `-` appends). All or none:
an answer not JSON, over 4 MiB or missing a container passes unchanged.
`maxRoutes` 40 (cap 200), `settleMs` 2500 (cap 10000), `maxClicksPerRoute` 6
(cap 30, 0 off). Stub a bootstrap answer (who am I, role, permission tree);
rewrite a data answer the view renders from real content with one field changed
(a menu missing its admin entry). Never fabricate data a report would read.

| Flag | Effect |
|------|--------|
| `--profile` | the profile file, or `-` for stdin (required) |
| `--origin` | refuse the profile unless its origin is exactly this one |
| `--allow-writes` | let in-scope POST/PUT/PATCH/DELETE reach the target (default: failed in the browser) |
| `--ignore-scope` / `--require-scope` | as on the other senders |

What it guarantees:

- **Seeds are data.** Storage seeds reach the page as a JSON literal a fixed
  script parses; routes are call arguments. Nothing from the profile becomes script source.
- **Stubs are confined.** Only requests on the profile's origin can match; a
  stub off the origin refuses the profile (exit 2, nothing launched). A stubbed
  response is answered in the browser, never stored, never listed as a request.
- **Rewritten answers are never evidence.** The request is sent (same method
  gate), never stored nor listed as a request; `rewrites_hit` reports it
  (`upstream_status`, `status`, `applied`, `error`), `rewrites_never_hit` the rest.
- **Writes are recorded, not sent.** Every non-GET/HEAD/OPTIONS request is
  failed in the browser and listed in `aborted_writes` by shape (method, URL,
  header names, body clipped to 8 KiB).
- **Clicks are bounded.** Per rendered route: the first search, filter, view,
  edit and export control, then tabs and links, never one the destructive-label
  guard refuses (delete, logout, approve, …: `clicks_skipped_destructive`,
  `skipped_controls`). Click requests pass the same gate (`via: "click"`). Under
  `--allow-writes` nothing is clicked (`clicks_refused: "writes_allowed"`).
- **Real exchanges are stored** as traffic, source `unlock-walk`, remark
  `client-unlocked` on a new row (the request is real, the page state was
  forged). Off-origin exchanges are stored only when the configured scope names
  their host.

`-j`: `items:[{origin, landing, routes, routes_skipped, stubs_never_hit,
rewrites_never_hit, clicks_refused, skipped_controls, writes_allowed, totals,
stored, store_skip}]`; each route (and `landing`) has `route, url, navigation
(load|client|full), final_url, redirected, title, text_sample,
requests[{method,url,type,status,record_uuid,via}], aborted_writes, stubs_hit,
rewrites_hit, clicks[{kind,label,requests,left_route,error}],
clicks_skipped_destructive`. `redirected: true` means the guard still sent you away — read
`stubs_never_hit` and the requests before changing the profile. A reached
endpoint is **not** a finding: confirm it with an anonymous request
(`vigolium replay`) and let the access-control checks decide.

## wordlist

List the embedded wordlists, or print one to stdout so it can be piped into
another tool (or `kit jwt-crack -w <name>`).

```bash
vigolium kit wordlist               # list available lists with entry/byte counts
vigolium kit wordlist -j            # the same, as JSON
vigolium kit wordlist fuzz          # print the fuzz list to stdout
vigolium kit wordlist jwt > jwt.txt # materialize (alias: jwt → jwt.secrets.list)
```

`-j` without a name: `items` = `[{name, entries, bytes}]`. With a name: `items`
= the entries, top-level `name` and `count`.

A name matches the embedded filename, its basename without extension, or the
`jwt` alias. Built-ins: `dir-short`, `dir-long`, `dir-large`, `file-short`,
`file-long`, `file-large`, `fuzz`, `params` (parameter names for
`kit param-mine` and the param-mining phase), `jwt.secrets.list` (the large
lists are stored gzip-compressed and printed decompressed).

## payload

Print the built-in fuzzing payloads for one or more classes, one per line — the
same catalog behind `vigolium fuzz --class`.

```bash
vigolium kit payload --list              # list classes
vigolium kit payload --class sqli        # SQLi payloads
vigolium kit payload --class sqli,xss -j # two classes, as JSON
```

Classes: `cmdi`, `crlf`, `lfi`, `open_redirect`, `path_traversal`, `sqli`,
`ssrf`, `ssti`, `xss`, `xxe` (aliases like `sql`→`sqli`, `traversal`→
`path_traversal`). JSON: envelope with `items` = the payloads and top-level
`classes`, `count`; `--list -j` has the class names as `items`.

---

## tmp-clean

Remove scratch vigolium left in the system temp directory. Every scan allocates
its scratch under one root and removes it on exit, so a run that finishes — or
is interrupted — cleans up after itself; this is for what a hard kill left
behind.

```bash
vigolium kit tmp-clean                  # anything untouched for 6h+
vigolium kit tmp-clean --max-age 1h     # narrower window
vigolium kit tmp-clean --max-age 0      # everything not held by a running scan
vigolium kit tmp-clean -j               # machine-readable receipt
```

`-j` is a mutation envelope: `changed` (anything removed), `action: "delete"`,
`items:[{temp_dir, scratch_root, abandoned_removed, legacy_removed, total_removed, duration}]`.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--max-age` | duration | `6h` | Only remove scratch untouched for at least this long (`0` removes everything not held by a running scan) |

A directory held by a **live** scan is never collected, whatever `--max-age`
says: on Unix the sweeper asks the kernel through a flocked `.lease` file rather
than guessing from mtime (elsewhere it falls back to a pid check, then age), so
a long-running scan is safe even at `--max-age 0`.

---

## Gotchas

- **Stateless by design.** Nothing lands in the project DB — pipe or redirect
  the output yourself. For findings that persist, use `scan`/`agent` instead.
- **`oast new` does not tear down the session.** Closing an interactsh client
  deregisters it server-side, so `new` mints + saves and exits without closing;
  the session stays alive for `poll`. Use `poll --deregister` to explicitly
  destroy it when done.
- **`oast --interval` is auto-shrunk** below `--wait` (the poll ticker fires
  only after one interval), so a short `--wait` still polls at least twice.
- **secret-scan safelists placeholders.** `AKIA…EXAMPLE` and `123456`-sequence
  tokens are treated as benign — use real-looking values to test.
- **`js-beautify` never exits non-zero for a degraded analysis.** A bundle that
  only half-analyzed still exits 0; `status` and `diagnostics` are the only
  signal. Check them, not the exit code.
- **`js-beautify --max-input-mb` cannot raise the ceiling.** The service takes
  the lower of this and its own limit (16 MiB by default), so a larger value is
  silently ignored. Raise `jstangle.hard_input_mb` in config instead.
- **Exit 3 gates.** `secret-scan --fail-on-match`, `jwt-crack --fail-on-crack`,
  `viewstate-crack --fail-on-crack` and `cookies --require-match` exit 3 on a hit (or, for `cookies`, a miss).
  Otherwise 0 success, 1 error, 2 usage error — see
  [invariants.md → Exit codes](invariants.md#exit-codes).
