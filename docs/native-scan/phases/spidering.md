# Spitolas — Browser-Based Web Crawler

Spitolas is a state-machine-driven web crawler that drives a real Chromium browser to discover application states through user-like interactions (clicking, form filling, iframe traversal). All resulting HTTP traffic is captured at the CDP level and fed into vigolium's scanning pipeline.

## How It Works

```
RunSpider(config, recordSaver)
  │
  ▼
┌─────────────────────────────────────────────────┐
│  Browser Pool (Chromium via rod)                │
│  ├── CDP Network Capture (all tabs/iframes)     │
│  └── Auto dialog handler (alert/confirm/prompt) │
└────────────────────┬────────────────────────────┘
                     │ navigate to target URL
                     ▼
┌─────────────────────────────────────────────────┐
│  Capture Index State (DOM snapshot + SHA256 ID) │
└────────────────────┬────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────┐
│  Crawl Loop                                     │
│  1. Pick next state (candidates + priority)     │
│  2. Reset browser → navigate to index           │
│  3. Replay shortest path to target state        │
│  4. Fire unfired actions (click/hover/submit)   │
│  5. Capture new DOM → compare → add state/edge  │
│  6. Repeat until termination condition met       │
└────────────────────┬────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────┐
│  Network Writer                                 │
│  CDP events → httpmsg.HttpRequestResponse       │
│  → RecordSaver (database) → scanning pipeline   │
└─────────────────────────────────────────────────┘
```

## Core Concepts

### States and the State Graph

A **State** is a DOM snapshot identified by `SHA256(strippedDOM)[:16]`. The **State Graph** is a directed graph where nodes are states and edges are actions that caused transitions. Navigation between states uses Dijkstra's shortest path (with Yen's K-shortest as fallback).

**Near-duplicate detection** is structural: each state carries a `StructID`, a 64-bit SimHash over its DOM's tag-path shingles. A newly captured state on the same URL template (id-like path segments collapsed, query dropped) whose SimHash is within 3 bits of an existing state's is treated as that state — a counter, a timestamp or one changed list item no longer makes a new state to explore. States are otherwise identified exactly by their stripped-DOM hash.

### Actions and Candidate Elements

Candidate clickable elements are discovered via CSS selectors (`a`, `button`, `[onclick]`, `[role=button]`, `input[type=submit]`, framework-specific bindings like `[ng-click]`, `[v-on:click]`, etc.). Each candidate becomes an **Eventable** (graph edge) once fired, linking a source state to a target state with an event type (click, hover, enter).

### Fragments (Visual Page Segmentation)

Pages are decomposed into **Fragments** — DOM regions identified by XPath, bounding box, subtree size, and content hash. Two modes:

- **Landmark** (default): fast DOM-based extraction
- **VIPS**: vision-based page segmentation with multi-pass decreasing thresholds

Fragment comparison uses the **APTED** tree edit distance algorithm. The Fragment Manager tracks exploration status across duplicate/equivalent fragments and uses **candidate influence** scoring to prioritize which states to explore next.

### Form Handling

The Form Handler detects and fills forms with smart value generation:

- Field-name-aware values (email, password, phone, URL, etc.)
- Constraint-aware generation (respects `pattern`, `min`/`max`, `minlength`/`maxlength`)
- Pairwise fallback when filling all inputs at once fails
- File upload support with type-aware file selection (a benign generated
  fixture, created in the run's scratch directory)
- A click fills only the controls of the form it would submit
- Each control's fill is reported as verified, attempted, rejected, skipped or
  unsupported — a value that did not stick is not counted as filled

What the crawl may change — field edits, submissions, uploads, downloads,
account creation, credential attempts, dialog answers — is one explicit policy
(`spidering.interaction`), printed under the Spidering header. See
[Browser policy](../../guides/browser-policy.md).

### Exploration Strategies

| Strategy | Description |
|----------|-------------|
| `adaptive` (default) | **Exp3.1** multi-armed bandit — balances exploitation (known-good actions) with exploration (untried actions) via importance-weighted probability sampling. Rewards are based on new-state discovery. |
| `normal` | BFS state selection with FIFO action selection. |
| `random` | Random state selection with FIFO action selection. |
| `oldest_first` | DFS-like state selection with FIFO action selection. |
| `shallow_first` | Prioritizes states with the lowest crawl depth. |

## Browser Management

- **Browser engines**: select `chromium`, `ungoogled`, or `fingerprint` with
  `--browser-engine`; availability of the latter two depends on the platform and
  build. Embedded browser archives are extracted on first use and cached by
  version. An explicit `spidering.browser_path` overrides automatic resolution.
- **Stealth** (`spidering.stealth`: `auto` | `on` | `off`, default `auto`):
  drops the trivial automation markers — the `enable-automation` switch,
  `navigator.webdriver`, an empty plugin list, the `HeadlessChrome` brand in
  `Sec-CH-UA` / `navigator.userAgentData`, mismatched languages, a SwiftShader
  WebGL renderer under headless. It reduces false negatives where a simple bot
  wall serves the crawler a challenge page instead of the application; it is
  not bot-detection evasion. `auto` is on for the `chromium` engine and off for
  `ungoogled` / `fingerprint`, which carry their own fingerprint flags. Module
  browser confirmations (`ProbeURL`, e.g. XSS dialog checks) follow the
  configured mode — the scan installs it, with `--proxy`, as their default on
  the runner, the direct `scan-url` / `scan-request` path and the REST server.
- **Display mode**: headless is the default. Use `--headed` to show browser
  windows, or set `spidering.headless: false` in configuration.
- **Security posture**: sandbox on (dropped, with a named warning, only where
  the host cannot provide one), same-origin policy and mixed-content blocking
  intact, certificate errors ignored like the scanner's HTTP transport. Each
  exception is configurable (`spidering.browser_compat`, `--browser-insecure`)
  and the effective set is printed as `Browser security:`.
- **One browser, N tabs**: `--browsers N` above 1 is clamped to 1 with a
  warning that points at `spidering.tabs`. With `tabs: N` (default 1, max 16)
  the crawl runs N consumers of one state graph and candidate queue: a tab
  claims a state, resets to the start URL, follows the shortest known path to
  it and fires its actions. It stops when the queue is empty and no tab is
  crawling, or when any tab hits a budget, the state cap or the (crawl-wide)
  failure streak. Seeding, the follow-up pass and the retry sweep run on the
  first tab. Each extra tab has its own window, so it keeps rendering.
  `tab_isolation: context` gives each extra tab its own cookie jar (seeded with
  the configured auth and the first tab's cookies); the default `shared` means
  a logout in one tab logs all of them out. Several targets crawl in parallel
  only as separate processes.
- **Cancellation**: a cancelled scan stops browser provisioning (including a
  Chrome for Testing download) and tab creation, not just the crawl loop.

## Network Capture

Traffic is captured at the **browser level** (not page level) via CDP events, covering all tabs, popups, and iframes:

1. `NetworkRequestWillBeSent` → record request
2. `NetworkRequestWillBeSentExtraInfo` → merge the headers Chrome actually sent
3. `NetworkResponseReceived` → record response headers
4. `NetworkLoadingFinished` → fetch response body (and, when needed, the request body)

Crawler records carry the **wire** request headers: `Cookie`, `Host`, `Origin`
and `Referer` come from `requestWillBeSentExtraInfo`, which is where Chrome
reports what its network stack added (the page's own cookies included). So
`http_records` from spidering now hold the session cookies the browser sent, as
records from `scan` already do. ExtraInfo can arrive before or after its
request, and a redirect chain reuses one request id; out-of-order ExtraInfo is
held (up to 4096 requests, 30s) until its request shows up.

A request body Chrome leaves out of `requestWillBeSent` (large or file-backed
multipart, for example) is fetched with `Network.getRequestPostData` after the
request finishes, off the event loop, for in-scope non-static requests only. It
is best-effort: two workers with a short queue, and a fetch that is dropped or
fails leaves the record with the body Chrome reported. A fetched body over
`spidering.max_capture_body_bytes` is not stored.

The phase's `requests_sent` on `phase.progress` and `phase.finished` counts
every request the browser sent, third-party and out-of-scope included (each
redirect hop separately), which is the crawl's network cost; `requests_in_scope`
is the share the operator scope admits. Both apply to `spidering` and
`targeted-respider`. Before, these phases reported the shared requester's
delta, which a browser never touches, so a crawl read about zero.

Hash-based deduplication prevents duplicate records. A cleanup loop removes stale pending requests (>15s). Captured traffic is converted to `httpmsg.HttpRequestResponse` and saved via the `RecordSaver` interface with source `"spidering"`.

Stored `duration_ms` is request → response headers; the body fetch over CDP is
timed separately. A dynamic response whose encoded body is over
`spidering.max_capture_body_bytes` (16 MiB) is recorded without its body.

### Capture receipt

Every crawl (and every browser probe that captures) ends with a **capture
receipt** read from the writer after it has drained: records accepted,
persisted, refused after close, failed, and whether the final drain completed.
A phase or tool reports what was persisted, never merely that capture was
configured. The Spidering completion line sums the receipts of every crawl; when
any record was lost it reads `N records (M failed — run incomplete)` (or notes
that the capture did not finish draining), and the low-yield decision that
triggers extra discovery treats lost records as found rather than reading a
lossy run as an empty site. "Incomplete" means the stored traffic is a lower
bound: the browser saw more than the database holds.

### Carried session

Unless `--no-carry-browser-session` is given, the browser's cookie jar at the
end of a crawl is carried forward into Discovery and DynamicAssessment, so those
phases inherit the WAF/bot clearance and the logged-in session the real browser
earned. A harvested bearer token is carried too, scoped to the exact origin
(scheme + host + port) it was minted for.

Cookies are carried **with their attributes** — Domain, Path, Secure, expiry,
and whether the cookie is host-only — and the HTTP path evaluates them per
request the way a browser does (RFC 6265 §5.4): a host-only cookie is not sent
to a subdomain, a `/admin` cookie is not sent to `/` or to `/administrator`, a
`Secure` cookie is not sent over plain http, and an expired cookie is not sent
at all. Content discovery configures one static `Cookie` header per target, so
it evaluates the same jar for the target's **origin** with the path ignored, and
still drops `Secure` cookies on an http target.

Where a browser would send two same-name cookies at different paths, the carried
session sends the more specific one: it leaves as a single flat header, and the
duplicate would be dropped downstream regardless.

An operator `-H Cookie` always wins over the carried session; the carried
cookies are merged into a request's own `Cookie` header only for names it does
not already have.

## Route Seeds

Before the crawl loop starts, the crawler browses a bounded list of seed
locations into the state graph, so their clickables join the frontier:

- **Declared seeds**: the `Allow`/`Disallow` paths of `robots.txt` and the
  `<loc>` entries of the sitemap, fetched in-page. All are recorded; up to 25
  are browsed, spread over distinct path shapes.
- **Extra seeds** (`SpiderConfig.ExtraSeeds`): caller-supplied entry points,
  in the product the client routes discovery found in the target's JavaScript
  (the `jstangle-facts` artifacts). Nothing on the page links to such a route,
  so an interaction crawl cannot reach it on its own.

Extra seeds are resolved, scope-filtered, deduplicated by route shape (against
the landing page, the declared seeds and each other; `/users/1` and
`/users/2` are one seed) and taken highest priority first, up to
`spidering.max_extra_seeds` (default 50). The navigation rule is shared with
discovery:

| Route | Navigated to |
| --- | --- |
| history (default) | origin + path: `/admin/reports/:id` → `https://app/admin/reports/1` |
| hash (`#/x`, `#!/x`, or a hash-routed landing page) | start page + fragment: `https://app/#/admin/reports/1` |

Route parameters (`:id`, `[id]`, `[...slug]`, `{id}`, `${id}`) become `1`, the
substitution discovery uses (`pkg/deparos/jstangle/clientroute`); wildcard
routes are skipped. A seed whose mode is unset follows the landing page: when
its URL carries a fragment route (`/#/home`) the app is hash-routed.

The runner feeds client routes in two places, both gated by
`spidering.route_seeds` (default true):

- **Initial spidering** passes the routes earlier runs of the project stored
  for the in-scope origins, so `vigolium run spidering` after `run discovery`
  browses them. A shared host session browses them on its first target only.
- **Targeted re-spider** adds the routes this scan's discovery stored as
  candidates (source `jstangle-route`) beside the record-derived ones. They
  skip the app-shell dedup (every route of one SPA serves the same shell) but
  share the route-template dedup, the login screen check and the
  `discovery.respider` per-host and total caps; the selection line reports how
  many were chosen. A route discovery found only in the JavaScript becomes a
  browser navigation in the same scan.

Redirect entries, low-confidence routes, API routes and nested routes whose
parent lives in another module (a templated `fullPath`) are not seeded. A route
is attributed to the origin of the record its `jstangle-facts` artifact hangs
on, normally the JS asset's own origin; a bundle served from an out-of-scope
CDN contributes no seeds.

## Termination Conditions

The crawl stops when any of these are met:

- Maximum states discovered
- Maximum duration elapsed
- Maximum crawl depth reached
- Maximum consecutive failures
- No more candidate actions to explore
- Context cancellation

## Entry Point

```go
result, err := spitolas.RunSpider(ctx, spitolas.SpiderConfig{
    TargetURL:    "https://example.com",
    MaxStates:    100,
    MaxDuration:  10 * time.Minute,
    MaxDepth:     5,
    BrowserCount: 1,
    Strategy:     "adaptive",
}, recordSaver)
```

Returns `SpiderResult` with: states discovered, actions executed/failed, forms
submitted / prevented by policy / uncertain, duration, records saved, the
capture receipt (`Capture`), the authentication outcome (`AuthState`:
`not-requested`, `configured`, `applied` or `failed` — never "verified"), hosts
credential headers were withheld from, auxiliary fetches denied by scope, and
readiness conditions that never met, and how many extra seeds were accepted
and browsed (`ExtraSeedsAccepted`, `ExtraSeedsCrawled`). A crawl that fails after starting returns a
partial result (records saved, capture receipt, auth state) alongside the error.
