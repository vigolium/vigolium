# Burp Suite integration

> **Related:** [agent-loop.md](agent-loop.md) · [fuzzing.md](fuzzing.md) · [data.md](data.md) · [server.md](server.md) · [ingest.md](ingest.md) · [flags.generated.md](flags.generated.md)

Vigolium and Burp are complementary: vigolium scans at scale and stores
everything in a queryable database; Burp is where a human does manual work.
The integration exists so traffic and evidence move **both ways** without
copy-pasting requests.

## Table of Contents

- [Three independent channels](#three-independent-channels)
- [Setup: the bridge listener](#setup-the-bridge-listener)
- [Channel 1 — route vigolium's traffic through Burp](#channel-1--route-vigoliums-traffic-through-burp)
- [Channel 2 — the bridge (live, both directions)](#channel-2--the-bridge-live-both-directions)
  - [Burp → vigolium: read live Proxy history](#burp--vigolium-read-live-proxy-history)
  - [vigolium → Burp: hand off for manual work](#vigolium--burp-hand-off-for-manual-work)
  - [Send through Burp's engine](#send-through-burps-engine)
- [Channel 3 — files (offline)](#channel-3--files-offline)
- [Server mode](#server-mode)
- [Limits, errors, and safety rails](#limits-errors-and-safety-rails)
- [Recipes](#recipes)
- [Gotchas](#gotchas)

---

## Three independent channels

Pick by what you actually need — they don't depend on each other.

| Channel | Direction | Mechanism | Use when |
|---------|-----------|-----------|----------|
| **Proxy** | vigolium → Burp | `--proxy http://127.0.0.1:8080` | you want Burp to *observe* what vigolium sends |
| **Bridge** | both ways, live | the extension's loopback listener, `-B` | you want to read Burp's history or push evidence into Burp's tools |
| **Files** | Burp → vigolium | `-I burp -i export.xml` | Burp isn't running / an offline export |

The **proxy** channel needs no extension. The **bridge** channel does.

## Setup: the bridge listener

The bridge is a loopback HTTP listener hosted by the
[burp-vigolium](https://github.com/vigolium/burp-vigolium) extension. Install the
extension in Burp, enable the Bridge listener in its settings, then point
vigolium at it.

```bash
export VIGOLIUM_BURP_BRIDGE_URL=http://127.0.0.1:9009   # or pass -B every time
vigolium traffic -B http://127.0.0.1:9009 --host acme.test
```

- `-B/--burp-bridge-url` defaults to `$VIGOLIUM_BURP_BRIDGE_URL`, **not** to
  `http://127.0.0.1:9009`. With neither set, every bridge feature is simply off.
- `--caido-bridge-url` is an alias of the same flag, for pointing at a Caido
  plugin exposing the same loopback bridge. It is one flag with two spellings
  (a flag-name alias, so it renders no line of its own in `--help`), not two
  flags — either name sets the same value, and the env var is
  `$VIGOLIUM_BURP_BRIDGE_URL` under both.
- **Everything in this file works identically against Caido.** Burp and Caido
  serve the *same* bridge protocol on the same loopback URL (default port 9009),
  so which vendor is listening is auto-detected per reply — no flag declares it.
  Records are then labelled `source: "burp"` or `source: "caido"` accordingly,
  and `--source caido` filters to Caido's. Read every `-B http://127.0.0.1:9009`
  below as "your Burp or Caido bridge."
- The URL is validated: `http://` only, a **loopback host** (`127.0.0.1`, `::1`,
  or `localhost`), an explicit **port**, and **no path**. Anything else is a hard
  error before a request is made.
- Commands carrying `-B`: `traffic`, `replay`, `fuzz`, `finding`, `import`,
  `server`, `agent autopilot`. Not `scan` — route scans through the proxy channel
  instead.

**Failure behavior differs by intent, deliberately:**

| Situation | Behavior |
|-----------|----------|
| *Reading* (`traffic`, `replay` bulk selection) and Burp is closed | warn, fall back to database-only results |
| *Writing/sending* (`--send-via-burp`, `--push-to-burp`, `--to-repeater`, `--to-organizer`, `--save-to-burp`) | preflight `/health` and **fail up front** with a clear error |

A read is an optional enrichment; a write you asked for must not silently
no-op.

## Channel 1 — route vigolium's traffic through Burp

`--proxy` is a **global** flag, so it works on every command that sends
requests. Without it, `VIGOLIUM_PROXY` is used (it proxies everything, like
the flag), then the environment by target scheme: `HTTPS_PROXY` for https,
`HTTP_PROXY` for http, `ALL_PROXY` for either, minus hosts in `NO_PROXY`.
Loopback is not bypassed on its own: `HTTPS_PROXY=<Burp>` still shows a
`localhost` target in Burp. The banner's `Proxy:` line, the plan's `proxy`
section and an unreachable error name the proxy and the variable it came
from. Both `http://` (Burp's listener) and `socks5://` proxy URLs work.

```bash
vigolium scan -t https://acme.test --proxy http://127.0.0.1:8080
vigolium replay -u <uuid> --proxy http://127.0.0.1:8080
vigolium fuzz -u <uuid> --fuzz params --class sqli -a --proxy http://127.0.0.1:8080 -c 3
vigolium fuzz 'http://127.0.0.1:3000/FUZZ' -w words.txt --proxy http://127.0.0.1:8080
```

Through an `http://` proxy, a plain-HTTP request names its destination in the
request line (`GET http://127.0.0.1:3000/x HTTP/1.1`), and that line always
carries the target's real host and non-default port. The `Host` header is sent
as the request has it, so a Host-header probe, a fuzzed `Host`, or
`replay --target` against another environment still reaches the target you
aimed at. Burp forwards that `Host` unchanged; a strict RFC 9112 proxy replaces
it with the request-line authority, so Host-header tests need Burp, SOCKS, or
no proxy. `https://` targets are tunnelled with `CONNECT host:port` and are
unaffected.

Keep `-c/--concurrency` low through an intercepting proxy — Burp is the
bottleneck, not the target.

**Browser-driven traffic**: `traffic --replay --with-browser --proxy …` loads
each matched URL in a real browser routed through the proxy, so Burp sees a
genuine TLS fingerprint, JS execution, and subresource loads. It is
navigation-only — no status code or body, therefore **no diff**; those runs emit
a `browser` object instead of a comparison.

## Channel 2 — the bridge (live, both directions)

### Burp → vigolium: read live Proxy history

| Command | Effect |
|---------|--------|
| `vigolium traffic -B <url>` | merges live Proxy history **with** database records — one global sort/page over both sources |
| `vigolium traffic -B <url> --save-to-vigolium-db` | persists the live records matching the active filters into the database |
| `vigolium import -B <url> --host <h>` | imports the **filtered** subset of Proxy history (a filter, or `--all-hosts`, is required) |
| `vigolium replay <filters> -B <url>` | bulk selection includes live Burp records alongside stored ones |
| `vigolium agent autopilot -t <url> -B <url>` | pulls live Burp history into the project DB **before** the run, so the pre-scan and operator can mine it |
| `vigolium server -B <url>` | merges live Burp traffic into `/api/http-records` |

Live records carry `"source": "burp"` (or `"caido"` when a Caido bridge answered
— the vendor is detected per reply) and a `burp:`-prefixed UUID. They have no
database row, which is why `replay --in-replace` refuses them.

The bridge query is **skipped** (database-only) when the filter set can't be
expressed over the live history: `--source` set to anything other than the
listening vendor (`burp`/`caido`), or any min-risk-score / remark filter.

`import -B` is idempotent — changed responses are refreshed, unchanged requests
are not duplicated — so re-running it during an engagement is safe.

**It refuses an unfiltered pull.** Without a narrowing filter it errors (exit 2)
rather than running, because an unfiltered import copies **every host the
operator has ever browsed — carrying those hosts' cookies and tokens** — into
your database. Where that database is shared with an autonomous agent, that is a
cross-engagement leak: banking sessions, internal tools, an unrelated client's
work.

It accepts the same filters `traffic -B` does, spelled the same way:
`--host` (wildcards), `--path`, `--method`, `--status`, `--search`,
`--exclude-search`, `--from`/`--to`, `-n/--limit`. `--all-hosts` opts into the
unfiltered form on purpose; `--yes` skips the pre-flight confirmation (which
prints how many records are about to cross, before anything is written).

```bash
# Correct: name what you want.
vigolium import -B http://127.0.0.1:9009 --host acme.test

# Refused (exit 2) — the error names the filters and the opt-in.
vigolium import -B http://127.0.0.1:9009

# Deliberate whole-history import, unattended.
vigolium import -B http://127.0.0.1:9009 --all-hosts --yes

# Survey what Burp has seen, without importing anything.
vigolium traffic -B http://127.0.0.1:9009 --host acme.test --compact -j

# Keep the subset worth scanning. The WRITE is not bounded by -n's listing
# default: an untyped -n does not truncate the import at 100 records.
vigolium traffic -B http://127.0.0.1:9009 --host acme.test --method POST \
  --save-to-vigolium-db

# Then scan only what's stored.
vigolium scan --only dynamic-assessment -t https://acme.test
```

### vigolium → Burp: hand off for manual work

Three destinations, each answering a different question.

| Destination | What it's for | Flag |
|-------------|---------------|------|
| **Organizer** | a batch to triage later, with notes + colour | `--push-to-burp` (finding), `--to-organizer` (replay), `--matches-to-organizer` (fuzz) |
| **Repeater** | one request you're about to hand-edit | `--to-repeater` |
| **Site map** | populate Burp's Target tree with what vigolium found | `--save-to-burp` (replay, traffic) |

On `finding`, `--push-to-burp` and `--to-repeater` are **independent** and
compose — one invocation can file a finding in the Organizer *and* open it in
Repeater, exactly as `replay --to-organizer --to-repeater` does. `--to-repeater`
on its own still means Repeater only.

```bash
# A finding's evidence → Organizer (default) or a Repeater tab
vigolium finding --id 42 --push-to-burp -B http://127.0.0.1:9009
vigolium finding --min-severity high --to-repeater -B http://127.0.0.1:9009

# Both at once: file it and open it.
vigolium finding --id 42 --push-to-burp --to-repeater -B http://127.0.0.1:9009

# A replayed request → Repeater / Organizer / Site map
vigolium replay -u <uuid> --to-repeater --repeater-tab idor -B http://127.0.0.1:9009
vigolium replay -u <uuid> --to-organizer --notes "IDOR candidate" --highlight orange -B …
vigolium replay -u <uuid> --save-to-burp -B http://127.0.0.1:9009

# Fuzz matches → Organizer (Burp re-issues each one)
vigolium fuzz -u <uuid> --fuzz params --class sqli -a --matches-to-organizer -B http://127.0.0.1:9009

# Copy the database records matching the active filters into Burp's Site map
vigolium traffic --host acme.test --status 200 --save-to-burp -B http://127.0.0.1:9009
```

**What gets attached automatically:**

- `finding --push-to-burp` writes a note `"<module> [<severity>] finding #<id>"`
  and colours the Organizer item by severity — critical/high → red, medium →
  orange, low → yellow, suspect → cyan, else gray. A pushed batch is triageable
  at a glance.
- `finding --to-repeater` names each tab `finding-<id>`; `replay --repeater-tab`
  defaults to `vigolium`.
- `replay --notes` longer than 200 chars is **truncated with an ellipsis and
  warned about**, never rejected — losing a note's tail beats losing the
  evidence. `--highlight` accepts
  `none|red|orange|yellow|green|cyan|blue|pink|magenta|gray`.
- `finding` falls back to the finding's **inline** evidence bytes when its linked
  HTTP record is missing (imported audit findings, filtered exports). Findings
  with no request bytes at all are counted as skipped, not failed.

### Send through Burp's engine

`--send-via-burp` replaces Go's HTTP client with Burp's own stack for the actual
send, so the **exact bytes** reach the wire — a deliberate `Content-Length`, a
smuggling prefix, an unusual method, malformed framing. Available on `replay`,
`fuzz`, and `finding` (where it re-issues the pushed request so the stored item
carries a fresh response).

```bash
vigolium replay --raw-request-file ./desync.txt \
  --send-via-burp --http-mode http1 -B http://127.0.0.1:9009

vigolium fuzz -u <uuid> --fuzz params --class crlf --send-via-burp --http-mode http1 -B …
```

| Flag | Notes |
|------|-------|
| `--http-mode` | `auto` *(default)* \| `http1` \| `http2` \| `http2_ignore_alpn` |
| `--send-timeout` | per-request response timeout, ≤ 2m (bridge default 30s) |

**Pair smuggling/desync work with `--http-mode http1`.** `auto` may negotiate
HTTP/2 and reframe the request, which destroys exactly the property you were
testing.

Without these flags the send path is byte-for-byte unchanged — the bridge is
additive, never a silent reroute.

## Channel 3 — files (offline)

No extension, no running Burp.

```bash
vigolium scan -I burp -i burp-export.xml -t https://acme.test   # Burp XML export
vigolium ingest -I burp -i burp-export.xml                       # ingest without scanning
vigolium replay -i ./copied-request.txt                          # "Copy as raw" single item
vigolium fuzz -i ./copied-request.txt --fuzz params --class sqli -a
```

Auto-detection covers Burp XML, a raw request, and a Burp-style
request/response pair separated by `***` — so `-i` usually needs no `-I`.
Base64-encoded requests are accepted too.

## Server mode

```bash
vigolium server --burp-bridge-url http://127.0.0.1:9009
```

`/api/http-records` then returns the merged database + live Burp result set; no
separate bridge route is needed. Config equivalent:

```yaml
server:
  enable_burp_bridge: true                  # the gate
  burp_bridge_url: 'http://127.0.0.1:9009'  # ships with a default value
```

`enable_burp_bridge` is the gate, **not** the URL — the URL carries a default, so
without the bool every config would silently enable the bridge. `-B` and
`$VIGOLIUM_BURP_BRIDGE_URL` take precedence and work regardless of the bool.

The extension can also push a Site map snapshot **into** a running server at
`POST /api/burp/sitemap/snapshot` (≤200 records per chunk, upserted and deduped
with `source=burp-sitemap`) — the bulk companion to the live `-B` merge.

Pair with `--mirror-fs` when an agent should read ingested Burp traffic as files:

```bash
vigolium server -B http://127.0.0.1:9009 --mirror-fs ./mirror
```

## Limits, errors, and safety rails

| Condition | Result |
|-----------|--------|
| Burp's "In-scope items only" is on and the target isn't in scope | HTTP 403 → typed scope error (warned about up front at preflight) |
| Repeater tab-creation rate limit hit | HTTP 429 → typed rate-limit error; `finding --to-repeater` warns above 20 selected findings (Burp caps ~30 tabs/min) |
| `fuzz --matches-to-organizer` on a huge run | capped at 200 items; the overflow count is printed, never silently dropped |
| Import message > 4 MiB | that record is skipped and reported as oversized |
| Site map message > 8 MiB | rejected with an explicit error |
| Bridge send response > 4 MiB | truncated; the true length is still reported |
| Target-side failure (connection refused, timeout) under `--send-via-burp` | a normal per-request result with an error, **not** an aborted run |

Mutually exclusive / rejected combinations:

- `traffic --save-to-burp` + `--save-to-vigolium-db`
- either of those + `--replay`
- `--save-to-vigolium-db` + `-S/--stateless` or `--glob-db`
- `replay --with-browser` + any of `--send-via-burp` / `--save-to-burp` /
  `--to-repeater` / `--to-organizer` / `--in-replace` / `--raw-request` (a
  navigation produces no request or response bytes to send, save, or store)
- `replay --in-replace` on a `burp:` UUID (live bridge records have no DB row)
- `import -B` + positional paths or `--glob-db` (the bridge is an alternative
  source, not an additional one)
- `import -B` with **no filter and no `--all-hosts`** — refused (exit 2) rather
  than copying the operator's whole browsing history into the database

## Recipes

### 1. Manual browsing in Burp, scanning in vigolium

```bash
# 1. Browse the app through Burp as usual, then pull what it captured.
#    Name the host — an unfiltered pull is refused, and would drag in every
#    other site you have browsed this session.
vigolium import -B http://127.0.0.1:9009 --host acme.test

# 2. Scan only the captured traffic — no crawling.
vigolium scan --only dynamic-assessment -t https://acme.test --fail-on high

# 3. Push what it found back for manual confirmation.
vigolium finding --min-severity high --push-to-burp -B http://127.0.0.1:9009
```

The round trip: Burp's session (auth, workflow state) reaches vigolium's
modules, and vigolium's findings land back in Burp's Organizer.

### 2. Triage a finding without leaving the terminal, then escalate

```bash
vigolium finding -j --id 42 --with-records          # read it
vigolium replay --finding-id 42                     # confirm it re-triggers
vigolium finding --id 42 --to-repeater -B http://127.0.0.1:9009   # hand to a human
```

### 3. Fuzz through Burp's engine, triage the hits in Burp

```bash
vigolium fuzz -u <uuid> --point URL_PARAM:id --class sqli -a \
  --send-via-burp --http-mode http1 --matches-to-organizer \
  -B http://127.0.0.1:9009 -c 3 -j
```

Exact bytes on the wire, anomalies chosen by score, every match waiting in the
Organizer with a colour and a note.

### 4. Give Burp a Site map from a vigolium scan

```bash
vigolium scan -t https://acme.test
vigolium traffic --host acme.test --save-to-burp -B http://127.0.0.1:9009
```

vigolium's discovery/spidering finds routes a manual browse missed; this puts
them in Burp's Target tree without replaying anything.

### 5. Cross-session testing (IDOR / BFLA) using Burp's cookies

```bash
# Re-send Burp-captured requests under a different user's session.
vigolium replay --host acme.test --method GET -B http://127.0.0.1:9009 \
  -H 'Cookie: session=victim' --format console -c 3
```

The diff between the two responses **is** the access-control check.

## Gotchas

- `-B` has **no default** — set `$VIGOLIUM_BURP_BRIDGE_URL` or pass it. Only
  `vigolium server` falls back to `http://127.0.0.1:9009`, and only when
  `server.enable_burp_bridge` is true.
- **`--burp` ≠ the bridge.** `finding --burp` / `traffic --burp` only *display*
  records in Burp-style colored request/response format.
- `traffic --header` is a search filter; `replay -H/--header` rewrites a header
  on the request being sent. On `replay` the filter is `--header-search`.
- `--send-via-burp` changes *how* the request is sent; `--proxy` only lets Burp
  *watch*. They are different channels — use the bridge when the bytes matter.
- On `finding`, `--push-to-burp` and `--to-repeater` **compose**, the same rule
  as on `replay`.
- `--http-mode` without `--send-via-burp` is ignored (with a warning).
- Live bridge records aren't in the database: they can't be updated
  (`--in-replace`) and vanish when Burp's history is cleared. `import -B` or
  `traffic --save-to-vigolium-db` is how you keep them.
- Reading degrades quietly when Burp is closed; writing fails loudly. If a
  `traffic -B` listing looks short, check that Burp is actually running.
