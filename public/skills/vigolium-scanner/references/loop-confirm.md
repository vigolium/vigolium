# The agent loop: Confirm, record, diff

> **Related:** [agent-loop.md](agent-loop.md) (start here) · [invariants.md](invariants.md) (the `-j` envelope, exit codes) · [flags.generated.md](flags.generated.md)

Step 4: re-check a finding, record the verdict, compare scans, re-send stored requests and fuzz one position.

## Step 4 — Confirm a finding

Two tools, for two questions:

- **Does the module still find it?** `vigolium finding verify <id|hash>...`
  re-runs the finding's own module against the request it scanned, on the one
  insertion point it was found on, and records a verdict. Use it first: it
  needs no reasoning about the payload and it writes the answer back.
- **What exactly does the target answer?** `vigolium replay` re-sends one
  request and diffs it against the stored baseline, for manual confirmation.

```bash
vigolium finding verify 42 -j                         # one finding
vigolium finding verify --scan-uuid <uuid> --mark -j  # every finding of a scan, status set
vigolium finding verify 42 --dry-run                  # what would run; sends nothing
```

Verdicts: `confirmed` (the module reported it again), `not_reproduced` (the
module ran against a responding target and did not), `inconclusive` (target
unreachable, module timed out, or no baseline could be rebuilt — the `reason`
says which), `unsupported` (agent, audit, OAST and known-issue-scan findings,
or an `ext-*` module not loaded with `--ext`). The verdict lands in the
finding's `verification` field (`finding -j` shows it with `verified_at`); the
status is untouched unless `--mark` moves `not_reproduced` → `false_positive`
and `confirmed` → `confirmed`, with the same audit trail as `finding mark`.
Passive findings are re-analyzed on the stored record without a request
(`--refetch` fetches a fresh one). `--fail-if not_reproduced` exits 4 when any
finding matches, after the envelope is written. Full reference:
[data.md → finding verify](data.md#finding-verify).

`vigolium replay` re-sends **one** request and diffs it against the stored
baseline. It is the CLI surface of the in-process `replay_request` tool, and it
is the way to inspect a finding's evidence by hand before reporting it.

```bash
# Re-send the request behind a stored record.
vigolium replay --record-uuid <uuid>

# Re-confirm a finding's evidence. When the finding came from an imported
# source (audit, JSONL) with no linked record, this falls back to the
# finding's stored request/response bytes.
vigolium replay --finding-id 42

# Any input shape: curl, raw HTTP, Burp XML, base64, URL, or stdin.
vigolium replay -i "curl -X POST https://target.example/api -d '{\"id\":1}'"

# Send exact bytes verbatim (no reframing).
vigolium replay --raw-request-file ./request.txt
```

Output is a human summary by default. Under `-j` it is one envelope whose
`items[0]` is the result: `result.baseline`, `result.replay`, `result.diff`
(status delta, length delta, content hash, interpretation). A supplied request
(`-i`, `--raw-request`) is sent **once**, with `baseline` and `diff` null; add
`--baseline` to send it a second time as a baseline and diff the two. `--format jsonl`
prints the same object bare, on one line; `-o <file>` writes that line to a file.

**Persist auth across calls.** Multi-step flows (login → CSRF → action) need
cookies between requests:

```bash
vigolium replay --session-id login -i curl-login.sh        # sets cookies
vigolium replay --session-id login --record-uuid <action>  # reuses them
```

The jar lives at `~/.vigolium/replay-jars/<session-id>.json`; `--no-cookies`
opts out.

**Confirm against another environment** — `--target` rewrites the destination
while keeping the baseline request bytes intact:

```bash
vigolium replay --record-uuid <prod-uuid> --target https://staging.example.com
```

**Update the stored baseline** with `--in-replace` (only when the source is a
stored HTTPRecord):

```bash
vigolium replay --record-uuid <uuid> --in-replace
```

## Recording a verdict

Once a finding is confirmed or refuted, write the verdict back so later gates
and diffs stop re-asking:

```bash
vigolium finding mark 42 --as confirmed --note "replayed: 500 + SQL error on id=1'"
vigolium finding mark 3f9a0c2b71de --as false_positive --note "static asset" -j
```

Verdicts: `false_positive`, `accepted_risk` (both **dismissed**), `confirmed`
(reproduced), `triaged` (believed real, not reproduced), `fixed`. Name findings
by id or by `finding_hash` (≥12-char prefix) — the hash survives merges and
exports, the id does not. Dismissed findings drop out of `--fail-on`, `scan diff`
and `finding --new-since`; `finding --verdict <list>` filters on the status and
the `-j` item carries `status`, `status_note`, `status_actor`. An id or hash that
matches nothing **exits 1** (listed in the envelope's `not_found`). Refused under
`--glob-db`, a `.jsonl` `--db`, and `--read-only`. Full reference:
[data.md → finding mark](data.md#finding-mark).

## What changed since the last scan

A re-run overwrites `findings.scan_uuid` with the newest observer, so
`--scan-uuid` cannot answer "what is new". Use the per-scan observation history:

```bash
vigolium scan diff previous latest -j            # keywords, UUIDs or 8+ char prefixes
vigolium scan diff --target https://app.example --last 2 --fail-on-new high
vigolium finding --new-since <base-scan> -j      # composes with every finding filter
vigolium finding --new-since 24h -j              # or a time: stored after it
```

Each `scan diff` item is the finding view plus `change` and `first_seen_scan`:

| `change` | Meaning |
|---|---|
| `new` | head saw it, base did not |
| `unchanged` | both saw it |
| `fixed` | base saw it, a **comparable** head did not |
| `not_reobserved` | base saw it, a head that cannot vouch for its absence did not — **not** evidence of a fix |

The envelope adds `base`/`head` (uuid, status, completeness, target),
`comparable` + `comparability_reasons` (`head_partial`, `head_not_finished`,
`head_targets_not_superset`, `head_phases_not_superset`, `*_unknown`), `counts`,
and `history`: `"partial"` when a scan predates the store's observation history,
so an older re-detection may be missing. Dismissed findings are left out unless
`--include-dismissed`. `--fail-on-new <sev>` exits `4` after the result is written.

`scan <uuid>` is refused (exit 2) — a UUID in the target position is a mistyped
subcommand (`scan staus <uuid>`), and the error points at the `scan` subcommands.

## Bulk replay

There is **one** bulk replay implementation: `vigolium replay`.
`vigolium traffic --replay` is a shortcut for it that keeps traffic's flag
spellings, defaults to the human comparison table, and does not follow
redirects. Reach for `replay` directly whenever you need to *change* the
request — the shortcut has no override flags.

Bulk `replay` still streams JSONL (one object per record) by default, with a
stderr notice; the default becomes the per-record tables in the next release.
Say what you want: `--format jsonl` for the stream, `-j` for one envelope.

```bash
# Re-send ALL stored traffic through Burp, 5 at a time.
vigolium replay --all --proxy http://127.0.0.1:8080 -c 5

# Fuzzy-search stored traffic and re-send just the matches (--all-matches is
# required once more than one record matches; a URL-shaped term is refused:
# send a URL with -i).
vigolium replay admin --all-matches --proxy http://127.0.0.1:8080 -c 5

# Pattern-search like `traffic`: POSTs to an API host, drop logout.
vigolium replay --host api.example.com --method POST --search token --all-matches \
  --exclude-search logout --proxy http://127.0.0.1:8080 -c 5

# From a standalone export (project scoping off).
vigolium replay -S --db scan.sqlite --all --proxy http://127.0.0.1:8080 -c 5

# Per-record tables instead of the JSONL stream.
vigolium replay login --all-matches --format console

# One envelope, every replayed record a row in items (failed ones carry error).
vigolium replay login --all-matches -j
```

Bulk selection mirrors `vigolium traffic`: `--host`, `--method`, `--status`,
`--path`, `--source`, repeatable AND-combined `--search`, `--header-search`,
`--body`, `--exclude-search`/`--exclude-header-search`/`--exclude-body`,
`--from`/`--to`, `--sort`/`--asc`/`--offset`. Throttle with `-c/--concurrency`
(default 10), cap with `-n/--limit` (default 100; `--all` lifts it). Bulk
selection is mutually exclusive with `--record-uuid` / `--finding-id` /
`--input`. With `-B/--burp-bridge-url`, live Burp Proxy history is merged into
the selection just as it is for `traffic`.

### Replaying with different headers / cookies

`--header-search` **filters** which records are selected; `-H/--header`
**rewrites** headers on what gets sent. (They are separate flags because
`traffic`'s `--header` is a search filter.) `-H` replaces the whole header
value, so pass the complete cookie string — it is not additive per-cookie.

```bash
# Same request, another user's session — the diff IS the IDOR/BFLA check.
vigolium replay -u <uuid> -H 'Cookie: session=victim; csrf=xyz'

# Merge a stored auth session, then override one header on top (-H wins).
vigolium replay -u <uuid> --auth-session staging -H 'X-Forwarded-For: 127.0.0.1'

# Re-send everything that carried a header, under a different session.
vigolium replay --header-search 'X-Api-Key' -H 'Cookie: session=other' -c 5
```

### Browser-driven replay

`--with-browser` loads each matched URL in a real browser routed through
`--proxy`, so the proxy sees genuine browser traffic — real TLS fingerprint, JS
execution, subresource loads. It is **navigation-only**: a browser exposes no
status code or response body, so these runs report final URL, title, and fired
JS dialogs and carry **no diff** (`result` is null; a `browser` object is
emitted instead). A navigation is a GET, so a non-GET record's method and body
are not reproduced — the JSON says so in `browser.method_note`.

```bash
vigolium replay --all --with-browser --proxy http://127.0.0.1:8080
vigolium traffic --replay --with-browser --proxy http://127.0.0.1:8080
```

`validateReplayFlags` rejects it alongside every flag downstream of the send
(`--in-replace`, `--raw-request`, and the Burp send/stage targets), and warns
when `--proxy` is absent — a browser run with nothing intercepting it captures
nothing.

## Payload fuzzing

`vigolium fuzz` is a low-level **primitive**, not a scanner. It injects a
caller-supplied payload set into chosen positions of ONE request and streams
per-payload signals (status / size / words / lines / time / reflection /
baseline-delta) with match/filter gating and auto-calibration against the
target's catch-all. It makes **no** vulnerability decision and emits **no**
findings — you bring the intelligence.

For confirmation-backed detection of known classes, use the module scanner
(`scan-request -m …`) instead. `fuzz` fills only the gap modules can't express:
custom payloads, an exact position, wordlist-scale discovery.

```bash
# Start here: let anomaly detection find what's interesting — no matchers needed.
vigolium fuzz -u <record-uuid> --point URL_PARAM:id --class sqli -a

# A literal FUZZ marker anywhere in the request is the position (no --fuzz/--point with it).
echo -e "GET /api/FUZZ HTTP/1.1\r\nHost: target.example\r\n" | vigolium fuzz -w dir-short

# Wordlist discovery + matcher gating (keep 200/301, drop the calibrated catch-all).
vigolium fuzz https://target.example/FUZZ -w file-long --match-status-code 200,301

# Build the request curl-style from a positional URL.
vigolium fuzz https://target.example/login -X POST \
  -d 'user=admin&pass=FUZZ' -H 'X-Api-Key: k' -w file-short

# Inline payloads across a specific header, with excludes.
vigolium fuzz -u <uuid> --fuzz-header X-Forwarded-For \
  -p "127.0.0.1" -p "localhost" --exclude-size 0

# Two markers in lockstep (user/pass pairs from two lists).
vigolium fuzz -i login.txt --mode pitchfork -w users.txt -w passwords.txt

# Agent handle: ONE envelope on stdout, exit 3 on match.
vigolium fuzz -u <uuid> --fuzz params --class xss,sqli -a -j --fail-on-match
```

**Source** (one of): a positional URL, `-i/--input` (curl / raw HTTP / Burp XML /
base64 / URL / `-`), `--input-file`, `-u/--record-uuid`, or a piped request on
stdin. `-t/--target` overrides scheme/host/port without touching the bytes.

**Positions** (exactly one way, required): a literal `FUZZ` marker anywhere, or
`--point TYPE:name`, `--fuzz-header Name`, or
`--fuzz method|path|params|param-name|headers|cookies|all`. A request with
neither is exit 2, and so is a marker combined with a position flag. Headers the
request does not carry are skipped unless `--fuzz headers:synthetic`.

**Payloads** combine `--class` (`cmdi,crlf,lfi,open_redirect,path_traversal,sqli,
ssrf,ssti,xss,xxe`) + `-w/--wordlist` (builtin `dir-long`, `dir-short`,
`file-long`, `file-short`, `fuzz`, or a file path) + `-p/--payload` (inline,
repeatable).

**Prefer `-a/--anomaly` over hand-written matchers.** A matcher requires knowing
the interesting size or status up front; `-a` instead scores every response
against the baseline *and* the run's own population and keeps what stands out,
with `anomaly_score` + `anomaly_reasons` on each result. It reports where to
look, never a verdict.

**Output** (matched only unless `--all-results`): a human table by default;
`--format jsonl` for the per-payload stream on stdout; `-o` writes that stream to
a file. Under `-j`, ONE envelope goes to stdout — the ranked top results in
`items`, plus `target, sent, matched, calibrated, baseline, anomalies` at the top
level. `query`/`query_argv` is a read; the confirmation command (a
`scan-request`/`scan-url` that sends traffic) is in `next[]` with
`sends_traffic: true`. `--fail-on-match` exits 3 for CI/agent gating (`ok`
stays true). Defaults: `--rate-limit 100`, `--max-requests 10000` (a bigger
plan is exit 2; `0` lifts either); `--save` stores the matched exchanges.

Always `--dry-run` a large run first: it resolves positions and payloads and
prints the exact bytes each would send, with **zero** network traffic.

Attack modes, the full signal/weight table, matcher grammar, curl-parity flags,
and operational knobs: **[fuzzing.md](fuzzing.md)**.
