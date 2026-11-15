# Fuzzing (`vigolium fuzz`)

`vigolium fuzz` is a low-level, agent-driven fuzzing **primitive**. It injects a
payload set **you supply** into positions **you pick** in a single HTTP request,
sends each variant, and reports per-payload response signals with match/filter
gating and auto-calibration.

## Mental model — primitive, not scanner

`fuzz` makes **no** vulnerability decision and emits **no** findings. It sends
exactly what you tell it and shows you exactly what came back. The intelligence
lives in the caller (you, or a coding agent).

> The native scan **decides what to test and judges the result.** `fuzz` does
> neither — it sends what you say and shows you what came back.

Use the right tool:

| Goal | Use |
|------|-----|
| Find **known** vuln classes (XSS/SQLi/LFI/SSRF…) with confirmation + low FPs | `vigolium scan-request -i req.txt -m xss,sqli -j` |
| Send **custom payloads** at an **exact position** and read raw anomalies | `vigolium fuzz …` |
| Wordlist-scale **content/param discovery** | `vigolium fuzz … -w dir-short` |

`fuzz` will happily show you 500s and size deltas that aren't bugs — interpreting
them is your job. That is the deliberate trade for control and transparency.

## Sources

Provide the request one of these ways (or pipe it on stdin):

```bash
vigolium fuzz 'https://acme.test/item?id=FUZZ'        # positional URL (+ -X/-H/-d)
vigolium fuzz -i req.txt                               # curl / raw HTTP / Burp / base64 / URL
vigolium fuzz -u <record-uuid>                         # a stored HTTP record
cat req.txt | vigolium fuzz --target http://acme.test  # stdin (scheme-less raw → use --target)
```

## Positions — what to fuzz

Positions are picked **one way**; a request with no marker and no position
flag is refused (exit 2) with the nearest marker-like token it found, and so
is a marker combined with a position flag.

- A literal **`FUZZ` marker** anywhere in the request (request line, path,
  header, body). Occurrences in the request line are auto-encoded, so a
  payload with spaces (`' OR '1'='1`) stays well-formed. Rename the keyword
  with `--keyword`.
- Otherwise `--fuzz method|path|params|headers|cookies|all` (`all` is every
  discovered insertion point). Headers the request does not carry are left out
  unless `--fuzz headers:synthetic`.
- Or target one point: `--point URL_PARAM:id`, or `--fuzz-header X-Forwarded-For`.
- Three kinds the default set never includes, each its own selector:
  - `--fuzz param-name` **renames** an existing query or form parameter
    (`?id=1` → `?PAYLOAD=1`); positions are `PARAM_NAME_URL` / `PARAM_NAME_BODY`.
  - `--fuzz new-param[:query|body|json]` (alias `param-add`) **adds** a
    parameter named by each payload, carrying a fixed canary value
    (`?id=1` → `?id=1&PAYLOAD=vigolium7c4n4ry`). This is parameter discovery: pair
    it with `-w params` and `--anomaly`. The location is inferred from the
    request (JSON body → `json`, form body → `body`, otherwise `query`) unless
    given; positions read `NEW_PARAM_QUERY` / `_BODY` / `_JSON`, and a body
    location supplies a Content-Type when the request has none.
  - `--fuzz body` replaces the **entire** request body (Content-Length
    refreshed); it needs a body (`-d`).

## Payloads — combine freely

```bash
--class sqli,xss,lfi,ssrf,cmdi,ssti,xxe,open_redirect,crlf,path_traversal
-w/--wordlist <builtin|file>     # builtins: fuzz, dir-short, dir-long, file-short, file-long, params
-p/--payload '<literal>'          # inline, repeatable
--suffix .php,.bak               # also send each payload with each suffix appended (ffuf -e)
```

`params` is the candidate parameter-name list the param-mining phase and
`kit param-mine` use. `--suffix` appends literally (pass the dot), so
`-w dir-short --suffix .php,.bak` sends `admin`, `admin.php`, `admin.bak`, ….

## Pace

`-c/--concurrency` (default 10; 50 on HTTP/2 or HTTP/3, see [Protocol](#protocol)) bounds parallel sends, `--delay <ms>` waits
before each send per worker, and `-r/--rate-limit <req/s>` caps the whole run
across every worker (default 100, fractions allowed, `0` = unlimited). `--max-requests`
(default 10000, `0` = no cap) refuses a plan that expands to more payload sends. The rate limit counts
**every** send — baseline samples and calibration probes as well as payloads —
and is smooth (no burst). `fuzz` is a primitive, so `scanning.rate_limit` and the
scan pace config never apply to it. The effective pace is printed on the
`fuzzing …` stderr line and returned as `pace` in the `-j` envelope and the
`--dry-run` report:

```json
"pace": {"rate_limit": 20, "concurrency": 10, "delay_ms": 0, "protocol": "h2"}
```

### Protocol

By default a run picks the fastest protocol the target supports and keeps it
for the baseline, calibration and every case. It tries HTTP/3 first, which
needs a direct QUIC handshake and is never used through `--proxy`. Next is
HTTP/2, used when TLS ALPN selects it. Otherwise the run uses HTTP/1.1. The
choice is made with handshakes only, before the baseline is sent. When the
target is pinned to HTTP/2 or HTTP/3 and `-c` is not given, the run uses **50**
workers instead of 10, because they share one or two connections rather than
holding one each.

A job stays on HTTP/1.1 when its meaning only exists there, and `pace` gets a
`protocol_note` saying why. That happens when:

- a position rewrites the Host header;
- a position lands in a header name or the HTTP version;
- a payload contains CR, LF or NUL;
- the request carries `Upgrade`, `Transfer-Encoding`, a `TE` other than `trailers`,
  or a `Connection` header naming other headers.

`Connection: keep-alive`/`close` from a captured request does not count.

```bash
--http1.1        # HTTP/1.1 only (the old default)
--http2          # TCP only; HTTP/2 where the target negotiates it
--http3          # prefer HTTP/3 (same as the default)
--http3-only     # require HTTP/3; fail if the target does not speak it
--http-version auto|1.1|2|3|3-only
```

`--send-via-burp` sends through Burp's engine, so these flags don't apply and
Burp's `--http-mode` decides the protocol.

Classes come from the shared `pkg/payloads` catalog (the same set behind the JS
`vigolium.payloads()` API); aliases like `traversal`, `rce`, `redirect` resolve.

## Anomaly gating

Matchers **keep** a response (OR across categories; empty = keep all); excludes
**drop** it (OR):

```
--match-status-code 200,301   --match-size N    --match-words N    --match-lines N
--match-regex <re>            --match-time <ms>
--exclude-status-code 404     --exclude-size N  --exclude-words N  --exclude-lines N
--exclude-regex <re>          --exclude-time <ms>
```

`--match-status-code all` keeps every status. **Auto-calibration** is on by default: `fuzz`
sends a few improbable values first, learns the target's wildcard/catch-all
`(status,length)` signature, and suppresses matching results (surfaced as
`"calibrated": true`, never silently hidden). Disable with `--no-calibrate`.

## Output

Default: a human table, one line per send, to stdout — matched results only
unless `--all-results`. `--format jsonl` prints the per-payload stream instead,
one self-describing object per send:

```json
{"position":"id","position_type":"URL_PARAM","payload":"' OR '1'='1","status":500,
 "length":73,"words":15,"lines":0,"reflected":true,"status_changed":true,
 "length_delta":48,"matched":true}
```

`-o file` writes that stream to a file; stdout keeps the table (or the `-j`
envelope).

### Agent JSON contract (`-j/--json`)

With the global `-j`, `fuzz` prints **one envelope** on **stdout** — a usable
handle so you don't parse the stream. The ranked top results are `items`, the
run summary sits beside them, and `total` is the full matched count:

```json
{
  "schema_version": 1, "command": "fuzz", "kind": "read", "ok": true,
  "target": "https://acme.test",
  "positions": 1, "payloads": 13,
  "sent": 13, "matched": 1, "calibrated": 8, "errors": 0,
  "baseline": {"status": 200, "length": 25, "words": 4, "lines": 0},
  "pace": {"rate_limit": 0, "concurrency": 10, "delay_ms": 0},
  "total": 1, "offset": 0, "limit": 1,
  "items": [ { "payload": "' OR '1'='1", "status": 500, "reflected": true, "matched": true } ],
  "query": "vigolium scan-request -i 'https://acme.test/item?id=FUZZ' -m xss,sqli,lfi,ssrf,cmdi -j",
  "query_argv": ["vigolium", "scan-request", "-i", "https://acme.test/item?id=FUZZ", "-m", "xss,sqli,lfi,ssrf,cmdi", "-j"]
}
```

The per-payload stream is not written under `-j` unless `-o` names a file;
`-j --format jsonl` without `-o` is a usage error (exit 2), since both would
claim stdout. The old local `--pretty` is a deprecated no-op (the table is the
default); `--pretty` now means the global "indent -j output".

`items` are ranked most-interesting first (status-changed → reflected →
largest size delta → slowest). `query` (or `query_argv`, ready for exec) is a
confirmation command against the hardened module scanner.

`--fail-on-match` exits non-zero (**3**) when any result matches — for CI/agent
gating. Network policy honors `--proxy`, `VIGOLIUM_PROXY` and the
environment proxies (`HTTPS_PROXY` for https targets, `HTTP_PROXY` for http,
`ALL_PROXY` as the fallback, minus `NO_PROXY`) to route through Burp. Through an `http://` proxy the
request line names the target's host and non-default port, and a fuzzed `Host`
header is sent as the payload, not replaced by the target hostname.

## Recipes

```bash
# SQLi class at a URL param, keep 500s
vigolium fuzz 'https://acme.test/item?id=FUZZ' --class sqli --match-status-code 500

# One exact point, custom wordlist, drop 404s (auto-calibrated)
vigolium fuzz -i req.txt --point URL_PARAM:id -w /list/sqli.txt --exclude-status-code 404

# Content discovery on a path segment
vigolium fuzz 'https://acme.test/FUZZ' -w dir-short --match-status-code 200,301,403

# Parameter discovery (Arjun-style): add each candidate name, keep the anomalies
vigolium fuzz 'https://acme.test/search?q=x' --fuzz new-param -w params --anomaly -r 20

# Method (verb) fuzzing
vigolium fuzz 'https://acme.test/admin' --fuzz method -p PUT -p DELETE --match-status-code all

# Agent gate: LFI via header, regex-match /etc/passwd, non-zero on hit
vigolium fuzz -i req.txt --fuzz-header X-Api-Version --class lfi --match-regex 'root:.*:0:0' --fail-on-match

# Agent summary
vigolium fuzz 'https://acme.test/item?id=FUZZ' --class sqli,xss --match-status-code 500 -j
```

## Relationship to `replay`

`replay` re-sends a request and diffs baseline vs replay (including bulk
pattern-search re-send of stored traffic, and exact-byte `--raw-request`
overrides); `fuzz` is payload/wordlist-scale fuzzing with anomaly gating. All
payload / insertion-point fuzzing lives in `fuzz` — `replay` has no `--mutate`
flag. Both share the same `pkg/replay` send library; the agent's in-process
`replay_request` tool still supports mutations and is unchanged.
