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

**Near-duplicate detection** uses normalized Levenshtein distance (threshold: 10%). For large DOMs (>10K chars), a sampling-based distance is used for performance.

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
- File upload support with type-aware file selection

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
- **Display mode**: headless is the default. Use `--headed` to show browser
  windows, or set `spidering.headless: false` in configuration.
- **Security flags disabled** for crawling: `--disable-web-security`, `--ignore-certificate-errors`, `--allow-running-insecure-content`.
- **Pool**: use `--browsers N` to run multiple browser instances with
  round-robin selection.

## Network Capture

Traffic is captured at the **browser level** (not page level) via CDP events, covering all tabs, popups, and iframes:

1. `NetworkRequestWillBeSent` → record request
2. `NetworkResponseReceived` → record response headers
3. `NetworkLoadingFinished` → fetch response body

Hash-based deduplication prevents duplicate records. A cleanup loop removes stale pending requests (>15s). Captured traffic is converted to `httpmsg.HttpRequestResponse` and saved via the `RecordSaver` interface with source `"spidering"`.

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
    CrawlStrategy: "adaptive",
}, recordSaver)
```

Returns `SpiderResult` with: states discovered, actions executed/failed, forms submitted, duration, and records saved.
